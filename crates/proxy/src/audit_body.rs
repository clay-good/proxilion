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
    let mut s = r.api_key.replace_all(text, "<REDACTED_API_KEY>").into_owned();
    s = r.bearer.replace_all(&s, "Bearer <REDACTED_TOKEN>").into_owned();
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
        for n in ["(415) 555-1234", "415-555-1234", "415.555.1234", "4155551234"] {
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
        let pxl = concat!("pxl", "_live_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP");
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
}
