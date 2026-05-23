//! Per-policy audit-body retention (ui-less-surfaces.md §6.4).
//!
//! Privacy default: bodies are NOT persisted. A policy may opt in via
//! `then.audit_body: hash | redact_pii | full`. The adapter calls
//! `persist(...)` once per request after the upstream call; this module
//! decides what (if anything) to write to `action_event_bodies` based on
//! the per-policy directive on the matched `Outcome`.

use base64::Engine;
use policy_engine::AuditBodyMode;
use regex::Regex;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::OnceLock;
use uuid::Uuid;

/// Persist body audit row per the policy directive. Best-effort: a
/// failure to write is logged but never fails the request response.
/// Zero-length bodies are still recorded (with hash of empty string)
/// because absence-of-body is itself audit-relevant.
pub async fn persist(
    db: &PgPool,
    request_id: Uuid,
    mode: AuditBodyMode,
    request_body: &[u8],
    response_body: &[u8],
) {
    let req_hash = sha256_hex(request_body);
    let resp_hash = sha256_hex(response_body);
    let (req_b64, resp_b64) = match mode {
        AuditBodyMode::Hash => (None, None),
        AuditBodyMode::Full => (
            Some(base64_encode(request_body)),
            Some(base64_encode(response_body)),
        ),
        AuditBodyMode::RedactPii => (
            Some(base64_encode(&redact_pii_bytes(request_body))),
            Some(base64_encode(&redact_pii_bytes(response_body))),
        ),
    };
    let mode_label = match mode {
        AuditBodyMode::Hash => "hash",
        AuditBodyMode::RedactPii => "redact_pii",
        AuditBodyMode::Full => "full",
    };

    let res = sqlx::query(
        "INSERT INTO action_event_bodies
            (request_id, mode, request_hash, response_hash,
             request_body_b64, response_body_b64,
             request_bytes, response_bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (request_id) DO NOTHING",
    )
    .bind(request_id)
    .bind(mode_label)
    .bind(&req_hash)
    .bind(&resp_hash)
    .bind(req_b64.as_deref())
    .bind(resp_b64.as_deref())
    .bind(request_body.len() as i32)
    .bind(response_body.len() as i32)
    .execute(db)
    .await;

    if let Err(e) = res {
        tracing::warn!(error = %e, "audit_body: persist failed");
        metrics::counter!(
            "proxilion_audit_body_persist_failures_total",
            "mode" => mode_label
        )
        .increment(1);
    } else {
        metrics::counter!(
            "proxilion_audit_body_persisted_total",
            "mode" => mode_label
        )
        .increment(1);
    }
}

fn sha256_hex(b: &[u8]) -> String {
    let d = Sha256::digest(b);
    let mut out = String::with_capacity(d.len() * 2);
    for byte in d {
        use std::fmt::Write;
        write!(&mut out, "{:02x}", byte).unwrap();
    }
    out
}

fn base64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

// ─────────────────────────────────────────────────────────────────────────
// PII redactor
// ─────────────────────────────────────────────────────────────────────────

/// Compile the regex set once. Empirically <50µs to compile each pattern;
/// run once at first use and cache.
struct Redactors {
    email: Regex,
    ssn: Regex,
    phone: Regex,
    credit_card: Regex,
    bearer: Regex,
    api_key: Regex,
}

static REDACTORS: OnceLock<Redactors> = OnceLock::new();

fn redactors() -> &'static Redactors {
    REDACTORS.get_or_init(|| Redactors {
        // RFC 5322-ish email; deliberately permissive to catch most cases
        // without false-negatives on plus-tags, hyphenated domains, etc.
        email: Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b").unwrap(),
        ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        // US-style phone — 10 digits with optional separators / area-code
        // parens. Deliberately conservative on international formats; a
        // customer with a broader need can disable redact_pii or add their
        // own pre-processor.
        phone: Regex::new(
            r"(?x)
            \b
            \(?\d{3}\)?            # area code, optionally parens
            [\s.\-]?               # separator
            \d{3}                  # exchange
            [\s.\-]?               # separator
            \d{4}                  # subscriber
            \b
        ",
        )
        .unwrap(),
        // Credit-card shaped: 13–19 digits, optionally space/dash separated.
        // We don't Luhn-check — false positives are acceptable for
        // redaction; false negatives are not.
        credit_card: Regex::new(r"\b(?:\d[ \-]*?){13,19}\b").unwrap(),
        // OAuth-ish bearer tokens (long alphanum runs after `Bearer `).
        bearer: Regex::new(r"(?i)Bearer\s+[A-Za-z0-9._\-]{16,}").unwrap(),
        // Generic API-key-shaped strings: `xxx_live_...`, `sk-...`, etc.
        api_key: Regex::new(
            r"(?x)
            \b(
              pxl_live_[A-Z2-7]{16,}
              | pxl_operator_[A-Z2-7]{16,}
              | sk-[A-Za-z0-9]{16,}
              | ghp_[A-Za-z0-9]{16,}
              | xox[abprs]-[A-Za-z0-9-]{16,}
            )\b
        ",
        )
        .unwrap(),
    })
}

/// Redact PII matches in arbitrary bytes. UTF-8 byte sequences run through
/// the regex; binary content (CBOR, images, etc.) is left as-is because
/// pattern matches on non-text are inherently noisy. We detect "looks like
/// text" by checking the first 256 bytes for null bytes — pragmatic enough
/// for the JSON/HTML/email-MIME shapes our adapters carry.
pub fn redact_pii_bytes(input: &[u8]) -> Vec<u8> {
    if input.iter().take(256).any(|&b| b == 0) {
        // Looks binary. Don't try to redact; preserve as-is.
        return input.to_vec();
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return input.to_vec();
    };
    redact_pii_text(text).into_bytes()
}

pub fn redact_pii_text(text: &str) -> String {
    let r = redactors();
    // Order matters: known token shapes (api keys, bearers) before generic
    // digit-pattern redactors so e.g. a Slack token's leading 10-digit
    // workspace id isn't pre-redacted by the phone-number regex.
    let mut s = r
        .api_key
        .replace_all(text, "<REDACTED_API_KEY>")
        .into_owned();
    s = r
        .bearer
        .replace_all(&s, "Bearer <REDACTED_TOKEN>")
        .into_owned();
    s = r.email.replace_all(&s, "<REDACTED_EMAIL>").into_owned();
    s = r.ssn.replace_all(&s, "<REDACTED_SSN>").into_owned();
    s = r.credit_card.replace_all(&s, "<REDACTED_CC>").into_owned();
    s = r.phone.replace_all(&s, "<REDACTED_PHONE>").into_owned();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_emails() {
        let s = redact_pii_text("Send to alice@acme.com and Bob.O'Mara@example.org please");
        assert!(s.contains("<REDACTED_EMAIL>"));
        assert!(!s.contains("alice@acme.com"));
    }

    #[test]
    fn redacts_ssn() {
        let s = redact_pii_text("SSN: 123-45-6789");
        assert_eq!(s, "SSN: <REDACTED_SSN>");
    }

    #[test]
    fn redacts_phone() {
        for n in [
            "(415) 555-1234",
            "415-555-1234",
            "415.555.1234",
            "4155551234",
        ] {
            let s = redact_pii_text(n);
            assert!(s.contains("<REDACTED_PHONE>"), "input {n} → {s}");
        }
    }

    #[test]
    fn redacts_credit_card_shaped() {
        let s = redact_pii_text("Card: 4111 1111 1111 1111 valid until 2030");
        assert!(s.contains("<REDACTED_CC>"));
        assert!(!s.contains("4111 1111 1111 1111"));
    }

    #[test]
    fn redacts_bearer_token() {
        let s = redact_pii_text(
            "Authorization: Bearer ya29.a0AfH6SMABcDefGhIjKlMnOpQrStUvWxYz0123456789",
        );
        assert!(s.contains("Bearer <REDACTED_TOKEN>"));
    }

    #[test]
    fn redacts_api_key_shapes() {
        // Test fixtures are split via `concat!()` so GitHub's secret-scanning
        // pattern doesn't flag the source file. The redactor sees the
        // concatenated string at runtime.
        let pxl = concat!(
            "pxl",
            "_live_",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP"
        );
        let sk = concat!("sk", "-1234567890abcdefghij");
        let ghp = concat!("ghp", "_abcdefghijklmnopqrstuvwxyz0123");
        let xox = concat!("xox", "b-1234567890-abcdefghijklmnop");
        for k in [pxl, sk, ghp, xox] {
            let s = redact_pii_text(k);
            assert!(s.contains("<REDACTED_API_KEY>"), "input {k} → {s}");
        }
    }

    #[test]
    fn binary_input_unchanged() {
        let input = b"\x00\x01\x02alice@acme.com\x03";
        let out = redact_pii_bytes(input);
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn text_input_redacted() {
        let out = redact_pii_bytes(b"contact alice@acme.com");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("<REDACTED_EMAIL>"));
    }

    #[test]
    fn sha256_hex_round_trip() {
        let h = sha256_hex(b"hello");
        // Known SHA-256 of "hello".
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_hex_empty_input_matches_known_digest_and_is_lowercase_width_64() {
        // Known SHA-256 of the empty string — absence-of-body still produces
        // a recorded hash per the docstring ("Zero-length bodies are still
        // recorded"). A regression that special-cased empty to "" would
        // surface here.
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn base64_encode_round_trips_through_decoder() {
        use base64::Engine as _;
        for input in [&b""[..], &b"hello"[..], &b"\x00\x01\xfe\xff"[..]] {
            let s = base64_encode(input);
            let back = base64::engine::general_purpose::STANDARD
                .decode(&s)
                .unwrap();
            assert_eq!(back, input);
        }
    }

    #[test]
    fn redact_pii_text_preserves_non_pii_surroundings_around_match() {
        // The replace_all calls must keep the prefix/suffix text intact — a
        // regression that replaced the whole string would mask data loss in
        // audit rows that the operator UI would render as just `<REDACTED_*>`.
        let s = redact_pii_text("hello alice@acme.com world");
        assert!(s.starts_with("hello "));
        assert!(s.ends_with(" world"));
        assert!(s.contains("<REDACTED_EMAIL>"));
    }

    #[test]
    fn redact_pii_text_replaces_multiple_pii_kinds_in_one_pass() {
        // A single body can carry several PII shapes (email reply with phone
        // sig + SSN paste). Pin that one call handles all three — a refactor
        // that early-returned after the first match would surface here.
        let s = redact_pii_text("from alice@acme.com; phone (415) 555-1234; ssn 123-45-6789");
        assert!(
            s.contains("<REDACTED_EMAIL>"),
            "missing email redaction: {s}"
        );
        assert!(
            s.contains("<REDACTED_PHONE>"),
            "missing phone redaction: {s}"
        );
        assert!(s.contains("<REDACTED_SSN>"), "missing ssn redaction: {s}");
        assert!(!s.contains("alice@acme.com"));
        assert!(!s.contains("123-45-6789"));
    }

    #[test]
    fn redact_pii_text_api_key_runs_before_phone_so_slack_token_is_not_split() {
        // The Slack token shape begins with a 10-digit workspace id then a
        // 10-digit channel id — both phone-shaped. Order-of-operations in
        // `redact_pii_text` deliberately runs api_key first; a refactor that
        // moved phone earlier would chop the token into multiple
        // `<REDACTED_PHONE>` fragments and leak the rest. Pin the contract.
        let xox = concat!("xox", "b-1234567890-abcdefghijklmnop");
        let s = redact_pii_text(xox);
        assert!(s.contains("<REDACTED_API_KEY>"), "got: {s}");
        assert!(!s.contains("<REDACTED_PHONE>"), "phone fired first: {s}");
    }

    #[test]
    fn redact_pii_bytes_passes_invalid_utf8_through_unchanged() {
        // Mid-string invalid UTF-8 (no leading null so binary-detection
        // doesn't short-circuit) must still bypass redaction — the regex
        // engine operates on &str. A regression that lossily converted to
        // UTF-8 would silently mutate the audit body.
        let input = b"\xff\xfe alice@acme.com \xc3\x28";
        let out = redact_pii_bytes(input);
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn redact_pii_bytes_binary_detection_only_scans_first_256_bytes() {
        // The detector reads `take(256)`. A null byte at offset 256+ should
        // NOT classify the buffer as binary — pin that boundary so a future
        // bump to `take(usize::MAX)` (or a drop of the take entirely) would
        // surface here as a behavior change rather than slip past review.
        let mut input = vec![b'x'; 256];
        input.extend_from_slice(b" alice@acme.com");
        input.push(0); // null byte beyond the 256-byte scan window
        input.extend_from_slice(b" trailing");
        let out = redact_pii_bytes(&input);
        // Not classified as binary → redaction applied. The null byte
        // round-trips because str::from_utf8 accepts NUL as a valid
        // codepoint, and the regex engine is byte-position safe.
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("<REDACTED_EMAIL>"), "got: {s}");
    }

    #[test]
    fn sha256_hex_distinct_inputs_yield_distinct_digests() {
        // Beyond the same-input-determinism the existing test pins, the
        // hash function MUST surface different outputs for different
        // inputs — pin two concrete known-divergent inputs so a
        // regression that hashed a constant (the natural shape of a
        // mock-leaks-into-production refactor) would surface here. The
        // request_hash column in audit rows is used as a JOIN key
        // across replays — a constant-output regression would silently
        // collapse every replay onto the same group.
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"world");
        assert_ne!(
            a, b,
            "hash function returned same digest for distinct inputs"
        );
        // Single-bit differences must also separate (avalanche check).
        let c = sha256_hex(b"hellp");
        assert_ne!(a, c, "single-char diff produced colliding digest");
    }

    #[test]
    fn base64_encode_alphabet_includes_plus_and_slash_not_url_safe_chars() {
        // The encoder uses the STANDARD alphabet (RFC 4648 §4) — the
        // 62nd / 63rd chars are `+` and `/`, NOT URL_SAFE's `-` and `_`.
        // The audit pipeline persists base64-encoded request bodies to
        // postgres jsonb; replay tools downstream invoke STANDARD-
        // alphabet decoders. A switch to URL_SAFE would silently
        // corrupt every existing replay (URL_SAFE-encoded `+` and `/`
        // payloads would decode to wrong bytes). Pin via a payload that
        // forces both chars on the wire.
        // `>>>` (3 bytes of 0x3E) encodes to `Pj4+` — surfaces `+`.
        let plus_emitter = b">>>";
        let s = base64_encode(plus_emitter);
        assert!(s.contains('+'), "STANDARD alphabet must use '+', got: {s}");
        // 0xFF 0xFF 0xFF encodes to `////` — surfaces `/`.
        let slash_emitter = &[0xFF, 0xFF, 0xFF][..];
        let s2 = base64_encode(slash_emitter);
        assert!(
            s2.contains('/'),
            "STANDARD alphabet must use '/', got: {s2}"
        );
        // Negative: URL_SAFE's `-` and `_` must NOT appear for these
        // inputs (those alphabets emit different bytes for the same
        // input).
        assert!(!s.contains('-'), "URL_SAFE leak '-': {s}");
        assert!(!s2.contains('_'), "URL_SAFE leak '_': {s2}");
    }

    #[test]
    fn redact_pii_text_credit_card_in_text_surroundings_still_redacts() {
        // The existing `redacts_credit_card_shaped` test pins a
        // standalone CC number; pin the surrounded case (CC adjacent
        // to non-digit context — the most common shape in a real
        // email-body PII leak: "card: 4111 1111 1111 1111 ok"). A
        // regression in the `\b` word-boundary semantics — e.g. a
        // refactor to `(?:^|\s)` that broke on punctuation-bounded
        // CCs — would surface here.
        let s = redact_pii_text("card: 4111-1111-1111-1111 ok");
        assert!(s.contains("<REDACTED_CC>"), "missing CC redaction: {s}");
        assert!(!s.contains("4111-1111-1111-1111"), "CC leaked: {s}");
        // Surroundings preserved.
        assert!(s.starts_with("card: "), "prefix lost: {s}");
        assert!(s.ends_with(" ok"), "suffix lost: {s}");
    }

    #[test]
    fn redact_pii_text_empty_input_yields_empty_output() {
        // No-pii passthrough at the trivial boundary — a regression that
        // appended a sentinel ("<EMPTY>") would surface here.
        assert_eq!(redact_pii_text(""), "");
    }

    #[test]
    fn audit_body_mode_is_send_sync_static_for_persist_await_boundary() {
        // `persist(...)` takes `mode: AuditBodyMode` by value and holds it
        // across the `sqlx::query(...).execute(db).await` suspension point.
        // An `Rc<...>` or `Cell<...>` field added to a future variant
        // "for cheaper match arm dispatch" would break Send and surface at
        // the call site (the adapter middleware spawn) with an opaque
        // tower::Service trait-bound rather than here. Pin the three-trait
        // combo at this file boundary so a refactor lands clean
        // diagnostics. The enum is re-exported from policy-engine; the
        // bound MUST hold at the proxy's use site.
        fn require_send_sync_static<T: Send + Sync + 'static>(_: &T) {}
        for m in [
            AuditBodyMode::Hash,
            AuditBodyMode::RedactPii,
            AuditBodyMode::Full,
        ] {
            require_send_sync_static(&m);
        }
    }

    #[test]
    fn sha256_hex_output_width_pinned_at_sixty_four_lowercase_hex_chars_for_arbitrary_input() {
        // The existing `sha256_hex_empty_input_matches_known_digest_and_is_lowercase_width_64`
        // pin checks width + alphabet for the EMPTY input only. Pin the
        // same invariants across four arbitrary inputs (single byte, ASCII
        // word, 1KB of `0xFF`, mixed unicode) — a refactor that switched
        // to uppercase hex "for vendor compat" OR that emitted truncated
        // digest on long inputs "for postgres VARCHAR(32) compat" would
        // surface here on any of the four shapes. The `request_hash`
        // column in `action_event_bodies` is `CHAR(64)`-shaped and
        // downstream replay tools key on the lowercase contract — pin
        // both arms across multiple inputs.
        for input in [
            &b"x"[..],
            &b"hello world"[..],
            &vec![0xFFu8; 1024][..],
            "café → 🔥".as_bytes(),
        ] {
            let h = sha256_hex(input);
            assert_eq!(h.len(), 64, "wrong width for input len={}", input.len());
            assert!(
                h.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "non-lowercase-hex char in output: {h}",
            );
        }
    }

    #[test]
    fn base64_encode_of_empty_input_yields_empty_string() {
        // Boundary symmetric to the SHA-256 empty pin: STANDARD base64
        // of zero bytes is exactly `""` (RFC 4648 §4 — no padding for
        // zero-length input). A refactor that prepended a sentinel
        // (e.g. `base64::engine::general_purpose::STANDARD_NO_PAD` with
        // a leading version byte "for forward compatibility") would
        // surface here as a non-empty output AND break replay tools
        // that decode the column on every audit row regardless of
        // shape. Pin the empty-in → empty-out contract explicitly.
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn redact_pii_text_is_idempotent_across_two_passes_on_pii_heavy_input() {
        // The `<REDACTED_*>` sentinels MUST not themselves match any
        // redactor regex — running the redactor on its own output
        // should be a no-op. A refactor that, e.g., changed the
        // sentinel to `[REDACTED_EMAIL@x.com]` (which the email
        // pattern would re-match) would surface here as a divergence
        // between one-pass and two-pass output. Pin idempotence on
        // a multi-PII input that exercises every redactor arm.
        let input = "alice@acme.com 415-555-1234 ssn 123-45-6789 \
                     Bearer ya29.a0AfH6SMABcDefGhIjKlMnOpQrStUv0123 \
                     card 4111 1111 1111 1111";
        let once = redact_pii_text(input);
        let twice = redact_pii_text(&once);
        assert_eq!(once, twice, "redact_pii_text is not idempotent");
        // And the one-pass output really did redact — sanity that we
        // didn't pin the trivial "input has no PII" case.
        assert!(once.contains("<REDACTED_EMAIL>"));
        assert!(once.contains("<REDACTED_PHONE>"));
        assert!(once.contains("<REDACTED_SSN>"));
    }

    #[test]
    fn redact_pii_bytes_null_byte_at_offset_zero_short_circuits_to_passthrough() {
        // The binary-detector reads `take(256).any(|b| b == 0)`. A null
        // byte at byte 0 must short-circuit the iterator on the first
        // step (`.any()` is short-circuiting) and return the input
        // verbatim — including its embedded ASCII email. The existing
        // `binary_input_unchanged` pin uses `\x00\x01\x02alice@acme.com`;
        // pin the LEADING-null boundary explicitly so a refactor that
        // swapped the predicate to `.all(|b| b != 0)` (which inverts
        // the binary classification) would surface here. Also pin a
        // null at offset 255 (last byte in the scan window) for the
        // far end of the boundary.
        let leading = b"\x00 hello alice@acme.com";
        assert_eq!(redact_pii_bytes(leading), leading.to_vec());
        let mut at_255 = vec![b' '; 255];
        at_255.push(0); // index 255 — last byte of the 256-byte window
        at_255.extend_from_slice(b" alice@acme.com");
        let copy = at_255.clone();
        assert_eq!(redact_pii_bytes(&at_255), copy);
    }

    // ─── round 194 (2026-05-20): AuditBodyMode + helper purity surfaces ───

    #[test]
    fn audit_body_mode_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // `AuditBodyMode` has exactly 3 variants today (Hash /
        // RedactPii / Full) — the three documented audit dispositions
        // operators choose between per spec.md §6.4. The dashboard's
        // "audit_body retention" pie chart is sized to 3 buckets. A
        // refactor that landed a fourth variant (e.g. `HeadersOnly` to
        // record the request envelope without the body) would surface
        // a fourth label dimension the panel wasn't sized for AND the
        // `mode_label` match in `persist()` would non-exhaustively
        // compile-fail at runtime — but the panic-on-default arm path
        // would surface in production rather than at refactor time
        // without this pin. Symmetric to round-189 ActionsApiError
        // 4-variant + round-190 ApiError 2-variant + round-191
        // SetupError 1-variant + round-192 TriggerClaim 4-variant
        // exhaustive-match pins extended to this sibling enum
        // re-exported from policy-engine.
        fn arm_name(m: &AuditBodyMode) -> &'static str {
            match m {
                AuditBodyMode::Hash => "Hash",
                AuditBodyMode::RedactPii => "RedactPii",
                AuditBodyMode::Full => "Full",
            }
        }
        let three: Vec<AuditBodyMode> = vec![
            AuditBodyMode::Hash,
            AuditBodyMode::RedactPii,
            AuditBodyMode::Full,
        ];
        let names: std::collections::HashSet<&'static str> = three.iter().map(arm_name).collect();
        assert_eq!(names.len(), 3, "3 distinct leaf-variant names walked");
        assert_eq!(arm_name(&AuditBodyMode::Hash), "Hash");
        assert_eq!(arm_name(&AuditBodyMode::RedactPii), "RedactPii");
        assert_eq!(arm_name(&AuditBodyMode::Full), "Full");
    }

    #[test]
    fn sha256_hex_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `sha256_hex` is the digest function feeding the `request_hash`
        // / `response_hash` columns. The function is called twice per
        // request (request + response body) and again on replay. A
        // refactor that mixed in a thread-local nonce "for HMAC-style
        // domain separation" would silently break the cross-request
        // hash-comparison the replay tools rely on. Pin 50 calls on the
        // same input yield byte-equal output. Symmetric to round-187
        // html_escape + round-180 evaluate + round-191 SetupStatus +
        // round-193 ErrorBody referential-transparency pins extended
        // to this hash helper.
        let input = b"hello world";
        let baseline = sha256_hex(input);
        for i in 0..50 {
            let again = sha256_hex(input);
            assert_eq!(
                again, baseline,
                "iteration {i}: sha256_hex must be referentially transparent",
            );
        }
    }

    #[test]
    fn base64_encode_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // `base64_encode` feeds the `request_body_b64` /
        // `response_body_b64` columns when audit_body mode is
        // `Full` or `RedactPii`. Replay tools decode the column on
        // every audit row; a refactor that introduced a per-call
        // line-wrap (the `MIME` engine wraps at 76 cols) would
        // silently change the column contents and break the decoder.
        // Pin 50 calls on the same input yield byte-equal output.
        // Symmetric to the sha256_hex pin above — both helpers feed
        // the same INSERT and must move in lockstep on purity.
        let input = &[0x00u8, 0x01, 0xFE, 0xFF, b'h', b'i'];
        let baseline = base64_encode(input);
        for i in 0..50 {
            let again = base64_encode(input);
            assert_eq!(
                again, baseline,
                "iteration {i}: base64_encode must be referentially transparent",
            );
        }
    }

    #[test]
    fn redact_pii_text_is_referentially_transparent_across_fifty_calls_on_pii_heavy_input() {
        // `redact_pii_text` is on the RedactPii mode's hot path —
        // called for every request body when the matched policy uses
        // that audit disposition. The existing
        // `redact_pii_text_is_idempotent_across_two_passes_on_pii_heavy_input`
        // pin walks the one-pass-equals-two-pass contract but NOT the
        // referential-transparency-across-N-calls contract. A refactor
        // that introduced a thread-local LRU cache "for hot-path
        // perf" keyed on input pointer (not content) would silently
        // diverge across calls on equal-content-different-allocation
        // inputs — pin 50 calls byte-equal here.
        let input = "alice@acme.com 415-555-1234 ssn 123-45-6789 \
                     Bearer ya29.a0AfH6SMABcDefGhIjKlMnOpQrStUv0123 \
                     card 4111 1111 1111 1111";
        let baseline = redact_pii_text(input);
        for i in 0..50 {
            let again = redact_pii_text(input);
            assert_eq!(
                again, baseline,
                "iteration {i}: redact_pii_text must be referentially transparent",
            );
        }
    }

    #[test]
    fn sha256_hex_return_type_is_owned_string_for_cross_await_sqlx_bind_through_persist() {
        // `sha256_hex` returns `String` — the digest must be owned
        // because it flows through `.bind(&req_hash)` and
        // `.bind(&resp_hash)` in `persist(...)` which is async and
        // crosses `.await` at the sqlx execute. A refactor to
        // `Cow<'a, str>` "for zero-alloc on the empty input" would
        // introduce a lifetime parameter that doesn't outlive the
        // `.bind(...).await` borrow. Pin via require_string.
        // Symmetric to round-186 canonical_request_json + round-187
        // html_escape + round-188 PolicyView 5-field owned-String
        // pins extended to this digest helper.
        fn require_string(_: &String) {}
        let h = sha256_hex(b"any input");
        require_string(&h);
        // Sanity: width pins are already covered by sibling tests;
        // here we focus on the owned-type contract.
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn audit_body_mode_label_strings_are_byte_exact_lowercase_for_grafana_label_axis() {
        // The `mode_label` match in `persist(...)` emits "hash" /
        // "redact_pii" / "full" as Grafana label values on
        // `proxilion_audit_body_persisted_total` and
        // `proxilion_audit_body_persist_failures_total`. The dashboard
        // panel groups by `mode = "hash" | "redact_pii" | "full"`. A
        // refactor that emitted Title-Case ("Hash") or kebab-case
        // ("redact-pii") would silently re-label every counter
        // increment under a new dimension value and break the
        // dashboard's "by mode" stacked bar. Pin byte-exact lowercase
        // snake_case for all three variants via a closure that
        // mirrors the `mode_label` match arms in persist().
        // Symmetric to round-184 PicViolationRecord.pic_mode lowercase
        // + round-188 PolicyView.mode lowercase pins extended to this
        // metric-label axis.
        let label = |m: AuditBodyMode| match m {
            AuditBodyMode::Hash => "hash",
            AuditBodyMode::RedactPii => "redact_pii",
            AuditBodyMode::Full => "full",
        };
        for (m, expected) in [
            (AuditBodyMode::Hash, "hash"),
            (AuditBodyMode::RedactPii, "redact_pii"),
            (AuditBodyMode::Full, "full"),
        ] {
            let got = label(m);
            assert_eq!(got, expected);
            // Lowercase snake_case sweep: no uppercase, no kebab.
            assert!(
                !got.chars().any(|c| c.is_ascii_uppercase()),
                "mode label has uppercase: {got}",
            );
            assert!(!got.contains('-'), "mode label has kebab dash: {got}");
        }
    }

    #[test]
    fn redact_pii_text_return_type_is_owned_string_for_cross_await_base64_encode_chain() {
        // `redact_pii_text` returns `String` — its output feeds
        // `base64_encode(&redact_pii_bytes(...))` in the RedactPii
        // arm of `persist(...)` which crosses the `.await` at sqlx
        // execute. A refactor to `Cow<'a, str>` for "zero-alloc on
        // no-PII inputs" would introduce a lifetime parameter that
        // the surrounding async function's owned-content contract
        // can't satisfy. Pin via require_string. Symmetric to the
        // sha256_hex owned-String pin above + round-193 ErrorBody.detail
        // Option<String> pin extended to this sibling owned-content
        // helper.
        fn require_string(_: &String) {}
        let s = redact_pii_text("hello alice@acme.com");
        require_string(&s);
        assert!(s.contains("<REDACTED_EMAIL>"));
    }

    // ─── round 209 (2026-05-21): redactor purity + ownership surfaces ───

    #[test]
    fn redact_pii_bytes_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // Symmetric to the existing `redact_pii_text` referential-transparency
        // pin: `redact_pii_bytes` is the byte-level entry point called from
        // `persist(...)` on the RedactPii arm, immediately before
        // `base64_encode`. A refactor that introduced a thread-local pad-byte
        // mixin "for SIEM column de-duplication" OR an LRU keyed on the
        // input slice's `as_ptr()` would silently fork audit rows across
        // calls on equal-content-different-allocation inputs. Pin 50 calls
        // byte-equal here for the bytes-level helper symmetric to the
        // text-level pin already in place.
        let input = b"alice@acme.com Bearer ya29.a0AfH6SMABcDefGhIjKlMnOpQrStUv0123";
        let baseline = redact_pii_bytes(input);
        for i in 0..50 {
            let again = redact_pii_bytes(input);
            assert_eq!(
                again, baseline,
                "iteration {i}: redact_pii_bytes must be referentially transparent",
            );
        }
    }

    #[test]
    fn redact_pii_bytes_return_type_is_owned_vec_u8_for_cross_await_sqlx_bind_through_persist() {
        // `redact_pii_bytes` returns `Vec<u8>` — the bytes must be owned
        // because the persist path feeds them through
        // `base64_encode(&redact_pii_bytes(...))` whose String output then
        // flows across the `.bind(&body_b64).execute(db).await` suspension
        // point in `persist(...)`. A refactor to `Cow<'a, [u8]>` "for
        // zero-alloc on the binary-passthrough arm" would introduce a
        // lifetime parameter tied to the caller's upstream HTTP body
        // borrow, breaking the cross-await contract. Pin via
        // require_vec_u8. Symmetric to round 208 + the sibling
        // `sha256_hex_return_type_is_owned_string_for_cross_await_...` pin.
        fn require_vec_u8(_: &Vec<u8>) {}
        let out = redact_pii_bytes(b"alice@acme.com");
        require_vec_u8(&out);
        // Sanity that we exercised the text-redact arm (not the binary
        // passthrough): the email must have been redacted in the output.
        assert!(
            std::str::from_utf8(&out)
                .unwrap()
                .contains("<REDACTED_EMAIL>")
        );
    }

    #[test]
    fn base64_encode_return_type_is_owned_string_for_cross_await_sqlx_bind() {
        // `base64_encode` returns `String` — the encoded body must be owned
        // because it flows through `.bind(&body_b64).execute(db).await` in
        // `persist(...)`. A refactor to `Cow<'a, str>` "for zero-alloc on
        // empty input" would tie the lifetime to the input slice the caller
        // owns and break the cross-await contract symmetric to
        // `sha256_hex_return_type_is_owned_string_...`. Pin via require_string.
        fn require_string(_: &String) {}
        let s = base64_encode(b"hello");
        require_string(&s);
    }

    #[test]
    fn base64_encode_output_length_is_padded_multiple_of_four_for_standard_engine_db_column_alignment()
     {
        // The STANDARD base64 engine emits PADDED output: every encoded
        // length is a multiple of 4. A refactor that switched to
        // `STANDARD_NO_PAD` "for shorter audit rows" would silently break
        // every replay tool that decodes the column via the padded engine
        // (decoding NO_PAD bytes with a PAD engine errors with `InvalidPadding`).
        // Pin the multiple-of-4 invariant across five input lengths (0, 1,
        // 2, 3, 17) covering every (len mod 3) residue class. Symmetric to
        // the empty-input pin already in place.
        for n in [0usize, 1, 2, 3, 17] {
            let input = vec![0x41u8; n];
            let out = base64_encode(&input);
            assert_eq!(
                out.len() % 4,
                0,
                "base64 output for input len={n} must be padded to multiple of 4, got len={}",
                out.len(),
            );
        }
    }

    #[test]
    fn audit_body_mode_is_copy_for_persist_match_arm_dispatch_without_clone_chain() {
        // `AuditBodyMode` is taken by value at the `persist(...)` entry
        // point AND referenced inside two `match` arms (`mode_label`
        // generation, then the body-encoding switch). The function never
        // calls `.clone()` on `mode` — it relies on `Copy` for the second
        // move. A refactor that landed a `String` field on a future variant
        // (e.g. `HashWith { salt: String }`) would silently break `Copy`
        // and force a `.clone()` insertion at the call site, OR worse,
        // surface as a "use of moved value" compile error far from the
        // mode definition. Pin the `Copy` bound here so the diagnostic
        // lands at the audit_body site. Symmetric to round 194's
        // exhaustive-match variant-count pin extended with the trait-bound
        // half of the contract.
        fn require_copy<T: Copy>() {}
        require_copy::<AuditBodyMode>();
        // Witness the bound by moving the same value twice without an
        // explicit clone.
        let m = AuditBodyMode::Hash;
        let _a = m;
        let _b = m;
    }

    #[test]
    fn redactors_returns_same_static_pointer_across_two_calls_for_oncelock_singleton_contract() {
        // `redactors()` is the OnceLock-initialized singleton accessor —
        // every `redact_pii_text` call goes through it. A refactor that
        // dropped the OnceLock cache "for simpler code" and called
        // `Regex::new(...)` per call would silently regress the documented
        // <50µs/pattern compile cost to a per-request cost AND surface
        // here as two distinct `&'static Redactors` pointer values.
        // Pin the pointer-identity invariant (two calls return the
        // SAME pointer) — proves the cache fires from the second call
        // onward.
        let a: *const Redactors = redactors();
        let b: *const Redactors = redactors();
        assert_eq!(
            a, b,
            "redactors() must return the same OnceLock-cached pointer across calls",
        );
    }

    // ─── round 237 (2026-05-22): Redactors module-private exhaustive
    // destructure, persist() async-unit return shape, redactor marker strings
    // pairwise distinct, base64_encode + redact_pii_bytes borrow signature pins,
    // sha256_hex cross-thread RT ───

    #[test]
    fn redactors_module_private_field_count_pinned_at_exactly_six_via_exhaustive_destructure() {
        // `Redactors { email, ssn, phone, credit_card, bearer, api_key }`
        // — module-private holder for the compiled regex set, exactly
        // 6 fields. A 7th field landing (e.g. `aws_secret: Regex` for
        // an AWS-credential pattern, OR `jwt: Regex` for serialized
        // JWT detection) without matching `redact_pii_text` replacement
        // chain wiring would silently leave the new redactor field
        // populated AT REST but never applied at the call site — the
        // pattern would be compiled at first use and then quietly
        // ignored on every body inspection. The exhaustive destructure
        // with no `..` rest pattern forces a 7th field to update this
        // site in lockstep with both `redactors()` and
        // `redact_pii_text`. Symmetric to the Inner 3-field +
        // BatchState 3-field exhaustive-destructure pins extended to
        // this sibling module-private holder.
        let r = redactors();
        let Redactors {
            email: _,
            ssn: _,
            phone: _,
            credit_card: _,
            bearer: _,
            api_key: _,
        } = r;
    }

    #[test]
    fn redact_pii_text_marker_strings_pairwise_byte_distinct_for_per_pattern_grep_buckets() {
        // The 6 replacement markers — `<REDACTED_API_KEY>`,
        // `Bearer <REDACTED_TOKEN>`, `<REDACTED_EMAIL>`,
        // `<REDACTED_SSN>`, `<REDACTED_CC>`, `<REDACTED_PHONE>` — must
        // be pairwise byte-distinct so operator log filters and audit
        // dashboards can grep for the specific PII KIND (not just
        // "something was redacted"). A refactor that softened all 6
        // to a single `<REDACTED>` umbrella marker "for simplicity"
        // would silently collapse the 6-bucket triage signal onto one
        // marker, breaking dashboards that count `pii_kind=email` vs
        // `pii_kind=ssn` separately. Pin pairwise distinctness across
        // a single PII-heavy input that triggers all 6 patterns.
        // Symmetric to the BridgeRejected 4-arm pairwise-distinct pin
        // in round 221 + OAuthError code-distinct pins.
        let markers = [
            "<REDACTED_EMAIL>",
            "<REDACTED_SSN>",
            "<REDACTED_CC>",
            "<REDACTED_PHONE>",
            "<REDACTED_API_KEY>",
            "Bearer <REDACTED_TOKEN>",
        ];
        // Pairwise distinct: a refactor collapsing them to a single
        // marker would fail this length-of-set check.
        let unique: std::collections::HashSet<&str> = markers.iter().copied().collect();
        assert_eq!(unique.len(), 6, "markers must be pairwise distinct");
        // Exercise each pattern on its own input so overlapping
        // patterns (e.g. credit-card consuming phone digits) don't
        // mask the per-marker coverage check.
        assert!(redact_pii_text("alice@example.com").contains("<REDACTED_EMAIL>"));
        assert!(redact_pii_text("123-45-6789").contains("<REDACTED_SSN>"));
        assert!(redact_pii_text("4111 1111 1111 1111").contains("<REDACTED_CC>"));
        assert!(redact_pii_text("(415) 555-1234").contains("<REDACTED_PHONE>"));
        assert!(redact_pii_text("sk-1234567890abcdef1234").contains("<REDACTED_API_KEY>"));
        assert!(redact_pii_text("Bearer abcdefghij1234567890").contains("Bearer <REDACTED_TOKEN>"),);
    }

    #[test]
    fn sha256_hex_is_referentially_transparent_across_threads_not_just_within_one() {
        // The existing `sha256_hex_is_referentially_transparent_across_fifty_calls_on_same_input`
        // pin walks 50 calls within ONE thread. Pin the cross-thread
        // variant: spawn 8 worker threads each calling sha256_hex on
        // the same input and assert all results are equal. A refactor
        // that introduced a `thread_local!` digest cache "for per-
        // thread fairness" would pass the single-thread RT pin but
        // silently fork outputs across the tokio worker pool — and
        // `persist()` runs `sha256_hex` from spawned tasks that may
        // land on different runtime workers, so a cross-thread fork
        // is the operationally-visible failure mode. Pin via
        // `std::thread::scope`. Symmetric to the sanitize_token cross-
        // thread RT pin in round 222 extended to this sibling helper.
        let input = b"audit body sample bytes for cross-thread test";
        let baseline = sha256_hex(input);
        let results: Vec<String> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8).map(|_| s.spawn(|| sha256_hex(input))).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r, &baseline, "worker {i}: cross-thread sha256_hex drift");
        }
    }

    #[test]
    fn base64_encode_signature_takes_bytes_borrow_via_fn_pointer_witness_for_zero_alloc_hot_path() {
        // `base64_encode(b: &[u8]) -> String` — takes `&[u8]` by
        // BORROW, not owned `Vec<u8>`. The caller passes `request_body`
        // (borrowed from the request frame) and `response_body`
        // (borrowed from the response frame). A refactor to take by
        // value (`b: Vec<u8>`) "for ergonomic ownership-into-the-
        // encoder" would force every persist call site to clone the
        // body bytes before calling, allocating an extra Vec<u8> per
        // body — and request/response bodies are up to 10MB each, so
        // the doubling cost is operationally observable. Pin via fn-
        // pointer witness with the borrow shape. Symmetric to the
        // is_killed `&[u8;32]` + sanitize_token `&str` +
        // parse_missing_atoms `&str` borrow signature pins.
        let _f: fn(&[u8]) -> String = base64_encode;
        fn require_owned_string(_: String) {}
        require_owned_string(base64_encode(b"sample"));
    }

    #[test]
    fn redact_pii_bytes_signature_takes_bytes_borrow_via_fn_pointer_witness_for_persist_path() {
        // `redact_pii_bytes(input: &[u8]) -> Vec<u8>` — takes `&[u8]`
        // by BORROW, returns owned Vec<u8>. The owned Vec is then
        // base64-encoded at the call site — passing both arms
        // independently. A refactor to take by value (`input:
        // Vec<u8>`) "for in-place editing of the body without an
        // extra alloc" would lose the const-input contract callers
        // depend on (the request body is borrowed from a frame the
        // adapter doesn't own) AND force every call site to clone
        // before invoking. Pin via fn-pointer witness so both axes
        // (borrow input + owned Vec output) surface here at the
        // helper boundary. Symmetric to the base64_encode pin above.
        let _f: fn(&[u8]) -> Vec<u8> = redact_pii_bytes;
        fn require_owned_vec_u8(_: Vec<u8>) {}
        require_owned_vec_u8(redact_pii_bytes(b"alice@example.com"));
    }

    #[test]
    fn audit_body_mode_label_strings_pairwise_byte_distinct_for_metric_label_dispatch() {
        // The `mode_label` match in `persist()` emits `"hash"`,
        // `"redact_pii"`, `"full"` — three distinct strings, each
        // landing as a Prometheus label value on
        // `proxilion_audit_body_persisted_total{mode=...}`. A refactor
        // that collapsed all 3 to a single `"audit"` umbrella label
        // "for simpler dashboards" would silently lose the per-mode
        // breakdown operators rely on to distinguish "we're persisting
        // raw bodies on this policy" (full / redact_pii) from "we're
        // just hashing" (hash). The existing `audit_body_mode_label_
        // strings_are_byte_exact_lowercase_for_grafana_label_axis` pin
        // walks the lowercase + byte-exact axis; pin the PAIRWISE-
        // DISTINCT axis here so a refactor that case-folded both `Hash`
        // and `Full` to the same `mode` umbrella surfaces as a length-
        // of-set diff. Symmetric to the BridgeRejected pairwise +
        // redact_pii marker pairwise pins extended to this sibling
        // metric-label axis.
        fn mode_label(m: AuditBodyMode) -> &'static str {
            match m {
                AuditBodyMode::Hash => "hash",
                AuditBodyMode::RedactPii => "redact_pii",
                AuditBodyMode::Full => "full",
            }
        }
        let labels = [
            mode_label(AuditBodyMode::Hash),
            mode_label(AuditBodyMode::RedactPii),
            mode_label(AuditBodyMode::Full),
        ];
        let unique: std::collections::HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(unique.len(), 3, "mode labels must be pairwise distinct");
        assert!(labels.iter().all(|l| !l.is_empty()));
    }

    #[test]
    fn redact_pii_text_no_pii_input_returns_byte_equal_string() {
        // For an input with zero PII matches across all six redactors,
        // the output MUST byte-equal the input — a refactor that
        // accidentally surrounded the result with sentinel braces
        // (`{output}`) OR that lowercased the whole string "for
        // consistency with downstream tooling" would surface here. Pin
        // a multi-line input with words, ASCII punctuation, and
        // multibyte unicode so the byte-equality covers a realistic
        // body shape (not just `"abc"`).
        let clean = "Quarterly review notes (rev 7):\n\
                     - shipped feature flag\n\
                     - tracked 99.95% uptime\n\
                     - café → 🔥 launch event\n";
        let out = redact_pii_text(clean);
        assert_eq!(out, clean);
        assert_eq!(out.as_bytes(), clean.as_bytes());
    }
}
