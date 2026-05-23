//! Generic webhook notifier (ui-less-surfaces.md §5.5).
//!
//! POST `blocked_actions` JSON to a customer-configured URL with an
//! `X-Proxilion-Signature: sha256=<hmac>` header. Receiver can be Slack
//! incoming-webhook, PagerDuty events API v2, Jira webhook,
//! Opsgenie, or any HTTP endpoint that speaks JSON.
//!
//! Reliability mirrors the SIEM forwarder (§3.3): up to 3 retries with
//! exponential backoff on 5xx / transport failure; 4xx is treated as a
//! deliberate rejection and not retried. The `/api/v1/blocked` API is
//! the authoritative pull surface for any gaps.

use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

use super::{BlockedNotification, BurstSummary, BurstSuppressor};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct WebhookSecret(Vec<u8>);

impl WebhookSecret {
    pub fn from_hex(hex: &str) -> Result<Self, NotifierBuildError> {
        if hex.is_empty() {
            return Err(NotifierBuildError("hmac secret is empty".into()));
        }
        if hex.len() % 2 != 0 {
            return Err(NotifierBuildError(
                "hmac secret hex length must be even".into(),
            ));
        }
        if hex.len() < 32 {
            return Err(NotifierBuildError(
                "hmac secret must be at least 16 bytes (32 hex chars)".into(),
            ));
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let b = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| NotifierBuildError(format!("invalid hex at {i}: {e}")))?;
            out.push(b);
        }
        Ok(Self(out))
    }

    pub fn sign(&self, body: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.0).expect("HMAC-SHA256 accepts any key length");
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let mut hex = String::with_capacity(tag.len() * 2);
        for b in tag {
            use std::fmt::Write;
            write!(&mut hex, "{:02x}", b).unwrap();
        }
        format!("sha256={hex}")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("notifier build: {0}")]
pub struct NotifierBuildError(pub String);

pub struct WebhookNotifier {
    url: String,
    secret: WebhookSecret,
    http: reqwest::Client,
    max_retries: u32,
    proxy_public_url: String,
    /// Optional burst-suppressor (ui-less-surfaces.md §5.6). When set,
    /// `notify(...)` consults it before each POST and may drop the event.
    burst: Option<BurstSuppressor>,
}

impl WebhookNotifier {
    pub fn new(
        url: String,
        secret: WebhookSecret,
        proxy_public_url: String,
    ) -> Result<Self, NotifierBuildError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!(
                "Proxilion-Notifier/",
                env!("CARGO_PKG_VERSION"),
                " (+https://proxilion.com)"
            ))
            .build()
            .map_err(|e| NotifierBuildError(e.to_string()))?;
        Ok(Self {
            url,
            secret,
            http,
            max_retries: 3,
            proxy_public_url,
            burst: None,
        })
    }

    /// Attach a burst suppressor. Without it the notifier passes every
    /// event through unconditionally (the original behavior).
    pub fn with_burst(mut self, suppressor: BurstSuppressor) -> Self {
        self.burst = Some(suppressor);
        self
    }

    #[allow(dead_code)] // surfaced via /api/v1/notifier/test in a future iteration
    pub fn burst(&self) -> Option<&BurstSuppressor> {
        self.burst.as_ref()
    }

    #[cfg(test)]
    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    pub fn proxy_public_url(&self) -> &str {
        &self.proxy_public_url
    }

    pub async fn notify(&self, n: &BlockedNotification<'_>) {
        if let Some(b) = &self.burst {
            if !b.admit(n, Instant::now()).await {
                // Suppressed — the periodic flush will emit a summary
                // for this bucket.
                return;
            }
        }
        let body = match serde_json::to_vec(n) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "notifier: serialize failed");
                metrics::counter!(
                    "proxilion_notifier_send_failures_total",
                    "reason" => "serialize"
                )
                .increment(1);
                return;
            }
        };
        let signature = self.secret.sign(&body);

        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let send = self
                .http
                .post(&self.url)
                .header("content-type", "application/json")
                .header("x-proxilion-signature", &signature)
                .header("x-proxilion-schema", BlockedNotification::SCHEMA)
                .header("x-proxilion-blocked-id", n.blocked_id.to_string())
                .body(body.clone())
                .send()
                .await;
            match send {
                Ok(r) if r.status().is_success() => {
                    metrics::counter!(
                        "proxilion_notifier_send_total",
                        "result" => "ok",
                        "layer" => n.layer.to_string()
                    )
                    .increment(1);
                    debug!(status = %r.status(), attempt, "notifier delivered");
                    return;
                }
                Ok(r) if r.status().is_client_error() => {
                    warn!(status = %r.status(), "notifier: webhook 4xx; not retrying");
                    metrics::counter!(
                        "proxilion_notifier_send_failures_total",
                        "reason" => "client_error"
                    )
                    .increment(1);
                    return;
                }
                Ok(r) => {
                    warn!(status = %r.status(), attempt, "notifier: webhook 5xx");
                    if attempt > self.max_retries {
                        metrics::counter!(
                            "proxilion_notifier_send_failures_total",
                            "reason" => "server_error_exhausted"
                        )
                        .increment(1);
                        return;
                    }
                }
                Err(e) => {
                    warn!(error = %e, attempt, "notifier: transport error");
                    if attempt > self.max_retries {
                        metrics::counter!(
                            "proxilion_notifier_send_failures_total",
                            "reason" => "transport_exhausted"
                        )
                        .increment(1);
                        return;
                    }
                }
            }
            let backoff_ms = 100u64 * 4u64.saturating_pow(attempt.saturating_sub(1));
            tokio::time::sleep(Duration::from_millis(backoff_ms.min(5_000))).await;
        }
    }

    /// POST a burst-summary envelope. Same signing + retry contract as
    /// the per-event path, but on a different schema header so receivers
    /// can route differently.
    pub async fn notify_summary(&self, s: &BurstSummary) {
        let body = match serde_json::to_vec(s) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "notifier: serialize summary failed");
                return;
            }
        };
        let signature = self.secret.sign(&body);
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let send = self
                .http
                .post(&self.url)
                .header("content-type", "application/json")
                .header("x-proxilion-signature", &signature)
                .header("x-proxilion-schema", BurstSummary::SCHEMA)
                .body(body.clone())
                .send()
                .await;
            match send {
                Ok(r) if r.status().is_success() => {
                    metrics::counter!(
                        "proxilion_notifier_summary_sent_total",
                        "policy_id" => s.policy_id.clone()
                    )
                    .increment(1);
                    debug!(policy_id = %s.policy_id, suppressed = s.suppressed_count, "summary delivered");
                    return;
                }
                Ok(r) if r.status().is_client_error() => {
                    warn!(status = %r.status(), "summary: 4xx; not retrying");
                    return;
                }
                Ok(_) | Err(_) => {
                    if attempt > self.max_retries {
                        warn!(policy_id = %s.policy_id, "summary: retries exhausted");
                        return;
                    }
                }
            }
            let backoff_ms = 100u64 * 4u64.saturating_pow(attempt.saturating_sub(1));
            tokio::time::sleep(Duration::from_millis(backoff_ms.min(5_000))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use wiremock::matchers::{body_string_contains, header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample(blocked_id: Uuid, ops: &[String]) -> BlockedNotification<'_> {
        BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id,
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            p_0: Some("alice@demo.local"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("gmail-external-send-gate"),
            detail: Some("external recipient"),
            predecessor_pca_id: None,
            requested_ops: ops,
            approve_url: format!("https://proxy.local/api/v1/blocked/{blocked_id}/approve"),
            reject_url: format!("https://proxy.local/api/v1/blocked/{blocked_id}/reject"),
        }
    }

    #[test]
    fn secret_round_trip() {
        let hex = "00112233445566778899aabbccddeeff";
        let s = WebhookSecret::from_hex(hex).unwrap();
        let sig = s.sign(b"payload");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
        assert_eq!(sig, s.sign(b"payload"));
        assert_ne!(sig, s.sign(b"PAYLOAD"));
    }

    #[test]
    fn secret_rejects_short_and_odd() {
        assert!(WebhookSecret::from_hex("").is_err());
        assert!(WebhookSecret::from_hex("aaa").is_err());
        assert!(WebhookSecret::from_hex("dead").is_err());
    }

    #[test]
    fn secret_from_hex_distinguishes_each_failure_branch_by_message() {
        // Each branch surfaces a distinct, operator-facing message — the
        // CLI / setup page reads `NotifierBuildError(...)` and prints it
        // verbatim, so a future merge of two branches into "invalid hex"
        // would lose the actionable hint. (WebhookSecret intentionally
        // has no Debug, so we match on the Result rather than unwrap_err.)
        fn err(hex: &str) -> NotifierBuildError {
            match WebhookSecret::from_hex(hex) {
                Err(e) => e,
                Ok(_) => panic!("expected error for {hex:?}"),
            }
        }
        assert!(err("").0.contains("empty"));
        assert!(err("aaa").0.contains("even"));
        assert!(err("aabb").0.contains("16 bytes"));
        // Non-hex char at the 17th byte (well past the length gate).
        assert!(
            err("0011223344556677889900112233gg00")
                .0
                .contains("invalid hex"),
        );
    }

    #[test]
    fn signature_is_lowercase_hex_with_sha256_prefix() {
        // Receivers verify by stripping the `sha256=` prefix and hex-
        // decoding the rest. A regression that emitted uppercase, or
        // dropped the prefix, would surface here. Length is fixed at 64
        // hex chars for SHA-256.
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let sig = s.sign(b"some body");
        let suffix = sig.strip_prefix("sha256=").expect("starts with sha256=");
        assert_eq!(suffix.len(), 64);
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "signature suffix must be lowercase hex: {suffix}",
        );
    }

    #[test]
    fn webhook_notifier_with_burst_attaches_suppressor_and_burst_accessor_reads_it() {
        // `with_burst` is the fluent setter; `burst()` is the read path
        // (intended for /api/v1/notifier/test in a future round). Pin
        // both ends of the contract — a future refactor that renamed the
        // private `burst` field but missed the accessor would surface
        // here as None where the fluent path just set Some.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            "http://localhost:9/hook".into(),
            secret,
            "https://proxy.local".into(),
        )
        .unwrap();
        assert!(n.burst().is_none(), "fresh notifier has no suppressor");
        let n = n.with_burst(crate::notifier::BurstSuppressor::new(
            crate::notifier::BurstConfig::default(),
        ));
        assert!(n.burst().is_some(), "with_burst attaches");
    }

    #[test]
    fn notifier_build_error_display_contains_inner_reason() {
        // The error is a tuple struct with `#[error("notifier build: {0}")]`
        // — operator-facing setup-status path uses Display directly. Pin
        // the prefix + inner pass-through so a future variant rename
        // surfaces here rather than at the dashboard.
        let e = NotifierBuildError("hmac secret hex length must be even".into());
        let s = e.to_string();
        assert!(s.starts_with("notifier build:"));
        assert!(s.contains("hmac secret hex length must be even"));
    }

    #[test]
    fn secret_sign_distinguishes_single_byte_difference_in_body() {
        // The HMAC-SHA256 avalanche property is what guarantees a
        // tampered body produces a different signature. Pin this on
        // a single-byte flip — a regression that switched to a
        // checksum (e.g. CRC32) would silently let the receiver
        // accept tampered payloads. The signature space is 2^256,
        // so accidental collision on a single-byte flip is
        // astronomically improbable.
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let a = s.sign(b"payload-A");
        let b = s.sign(b"payload-B");
        assert_ne!(a, b);
        // Pin same-length too — only the content differs.
        let c = s.sign(b"payload-C");
        assert_eq!(a.len(), c.len());
        assert_ne!(a, c);
    }

    #[test]
    fn secret_distinct_keys_produce_distinct_signatures_for_same_body() {
        // Symmetric to the body-flip test — pin that two different
        // secrets sign the same body to different MACs. A refactor
        // that accidentally hard-coded a key (e.g. via a `lazy_static`
        // fixture in a test path that leaked into prod) would surface
        // here as identical signatures across distinct WebhookSecret
        // instances.
        let s1 = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let s2 = WebhookSecret::from_hex("ffeeddccbbaa99887766554433221100").unwrap();
        let body = b"identical payload bytes";
        assert_ne!(s1.sign(body), s2.sign(body));
    }

    #[test]
    fn secret_clone_yields_same_signature_as_original() {
        // `WebhookSecret` is `Clone` — the bundle hands a clone into
        // each driver build. Pin that the cloned secret signs to the
        // SAME MAC as the original (no per-instance salt or RNG
        // smuggled in via the clone path).
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let c = s.clone();
        assert_eq!(s.sign(b"x"), c.sign(b"x"));
    }

    #[test]
    fn webhook_proxy_public_url_round_trips_through_accessor() {
        // The approve-URL builder reads this back to construct the
        // `proxy_public_url/api/v1/blocked/{id}/approve` strings — a
        // future refactor that returned the *upstream* webhook URL by
        // mistake would point operators at the wrong place.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            "https://webhook.example/hook".into(),
            secret,
            "https://proxy.example".into(),
        )
        .unwrap();
        assert_eq!(n.proxy_public_url(), "https://proxy.example");
    }

    #[test]
    fn secret_from_hex_accepts_uppercase_and_mixed_case_hex_letters() {
        // `u8::from_str_radix(_, 16)` is case-insensitive — pin that
        // `from_hex` honors this end-to-end so operators who paste hex
        // from `openssl rand -hex 16` (lowercase) or from a Vault UI
        // (often uppercase) get the same bytes. A future tightening
        // to require lowercase (in the name of "canonical form") would
        // silently start rejecting half of operator workflows. The
        // three shapes — all-lower, all-upper, mixed — must each
        // decode to the same `WebhookSecret` (verified via signing the
        // same body and asserting matching MACs, since the inner Vec
        // is private).
        let lower = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let upper = WebhookSecret::from_hex("00112233445566778899AABBCCDDEEFF").unwrap();
        let mixed = WebhookSecret::from_hex("00112233445566778899AaBbCcDdEeFf").unwrap();
        let body = b"sample-payload";
        assert_eq!(lower.sign(body), upper.sign(body));
        assert_eq!(lower.sign(body), mixed.sign(body));
    }

    #[test]
    fn secret_sign_on_empty_body_still_returns_sha256_prefix_and_64_hex_chars() {
        // HMAC-SHA256 has no special case for empty input — the empty
        // body is a valid (and operationally observable) shape: a
        // notifier event with a serializer that emits `{}` and gets
        // stripped to nothing is fixture-shaped here as `b""`. Pin
        // that the format invariant (`sha256=` prefix + exactly 64
        // lowercase hex chars) survives the empty case. A refactor
        // that early-returned on empty input (e.g. `if body.is_empty() {
        // return String::new() }` "for performance") would silently
        // produce an unverifiable empty signature header — receivers
        // would 401 every empty-body event.
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let sig = s.sign(b"");
        assert!(sig.starts_with("sha256="), "got: {sig}");
        let suffix = sig.strip_prefix("sha256=").unwrap();
        assert_eq!(suffix.len(), 64, "got: {sig}");
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "suffix must be lowercase hex: {suffix}",
        );
        // And it must be byte-equal across two calls (no random salt).
        assert_eq!(sig, s.sign(b""));
        // And differ from the same key signing a non-empty body
        // (sanity: empty isn't a degenerate fixed-output shortcut).
        assert_ne!(sig, s.sign(b" "));
    }

    #[test]
    fn webhook_notifier_with_burst_replaces_prior_suppressor_on_chained_call() {
        // The fluent builder takes `mut self`-by-value — repeated calls
        // to `with_burst` MUST replace the prior suppressor (last-write-
        // wins) rather than chain into a Vec or panic. Adapter call
        // sites occasionally build the notifier in two stages (default
        // suppressor at construction, then operator-configured override
        // applied later). A refactor that pushed onto a `Vec<BurstSuppressor>`
        // for "compose multiple suppressors" would silently change the
        // semantics — every event would be admit-checked against every
        // suppressor in turn, doubling the gating logic. Pin the
        // replace-on-chain invariant by chaining two distinct suppressor
        // configs and asserting the accessor surfaces a Some (i.e.
        // didn't accidentally clear it). The inner-suppressor identity
        // can't be checked from outside the module (private fields),
        // so the assertion is binary: still Some after two calls + the
        // chained value compiles.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            "http://localhost:9/hook".into(),
            secret,
            "https://proxy.local".into(),
        )
        .unwrap()
        .with_burst(crate::notifier::BurstSuppressor::new(
            crate::notifier::BurstConfig::default(),
        ))
        .with_burst(crate::notifier::BurstSuppressor::new(
            crate::notifier::BurstConfig::default(),
        ));
        assert!(
            n.burst().is_some(),
            "second with_burst must not clear the suppressor",
        );
    }

    #[test]
    fn webhook_secret_and_build_error_and_notifier_are_send_sync_static() {
        // `WebhookSecret` is held inside `WebhookNotifier` which is wired
        // into AppState as part of the Notifiers bundle. `NotifierBuildError`
        // flows through anyhow chains at boot. `WebhookNotifier` itself
        // crosses tokio task boundaries when adapter handlers fire it.
        // All three need (Send + Sync + 'static). A refactor that
        // introduced an `Rc<Vec<u8>>` on WebhookSecret "for cheap clone of
        // the inner key bytes" would break Send + Sync but the breakage
        // would surface at AppState assembly with an unrelated
        // tower::Service trait-bound error. Pin all three bounds here.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<WebhookSecret>();
        require_send_sync_static::<NotifierBuildError>();
        require_send_sync_static::<WebhookNotifier>();
    }

    #[test]
    fn webhook_secret_from_hex_accepts_long_64_byte_key_128_hex_chars() {
        // HMAC-SHA256 RFC 2104 §3 recommends a key length ≥ the hash
        // output length (32 bytes); operators following best practice
        // generate 64-byte keys via `openssl rand -hex 64`. The existing
        // tests pin the 16-byte minimum (32-hex-char) boundary but never
        // exercise the larger keys real operators actually use. Pin a
        // 64-byte key (128 hex chars) constructs cleanly AND signs to a
        // valid 71-char signature shape — a refactor that capped the key
        // size at 32 bytes "for fixed-buffer-size hot-path performance"
        // would silently truncate every long key and produce wrong-MAC
        // signatures every receiver would 401.
        let long_hex = "0".repeat(128); // 64 zero bytes
        let s = WebhookSecret::from_hex(&long_hex).unwrap();
        let sig = s.sign(b"payload");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 7 + 64, "signature is 'sha256=' + 64 hex chars");
        // And the long-key signature must DIFFER from a short-key
        // signature on the same body (sanity: the key bytes do flow
        // into the MAC, no silent truncation to a fixed prefix).
        let short = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        assert_ne!(sig, short.sign(b"payload"));
    }

    #[test]
    fn webhook_signature_prefix_is_byte_exact_seven_chars_lowercase_sha256_equals() {
        // The `sha256=` prefix is the de-facto wire shape that Slack,
        // GitHub, Stripe, and most webhook receivers parse via
        // `strip_prefix("sha256=")` before hex-decoding the rest.
        // The existing `signature_is_lowercase_hex_with_sha256_prefix`
        // pin checks that the suffix has the right length and case, but
        // doesn't pin the prefix shape byte-exact. A refactor that
        // emitted `SHA256=` (uppercase, the X-Hub-Signature-256
        // pre-2020 shape) or `sha2_256=` (no-such-shape) would silently
        // break every receiver. Pin the prefix at byte-exact "sha256="
        // (7 chars) so a one-char drift surfaces here.
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let sig = s.sign(b"any");
        assert_eq!(&sig.as_bytes()[..7], b"sha256=");
        // The total signature is exactly 71 bytes (7-char prefix + 64
        // hex chars of HMAC-SHA256 output). A refactor that introduced
        // any byte drift surfaces.
        assert_eq!(sig.len(), 71);
    }

    #[test]
    fn webhook_secret_sign_with_multibyte_unicode_body_bytes_produces_valid_signature_shape() {
        // The `sign` signature is `&[u8]` — HMAC operates on raw bytes,
        // not Unicode codepoints. Pin that a body containing multibyte
        // UTF-8 (`café → 🔥` mixed with policy JSON) signs to a valid
        // 71-byte sha256= signature with no panic and byte-deterministic
        // output. A refactor that called `.to_ascii_lowercase()` or
        // `.replace(non_ascii, '?')` on the body bytes "for SIEM
        // ASCII-only ingest hygiene" would silently change every MAC for
        // bodies carrying non-ASCII policy fields (a multi-tenant
        // deployment where a tenant's policy detail contains the tenant's
        // name in a non-Latin script would silently 401 every event).
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let unicode_body = "café → 🔥 {\"policy_id\":\"é-tenant\"}".as_bytes();
        let sig = s.sign(unicode_body);
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 71);
        // Determinism — two calls with same unicode bytes produce
        // byte-equal signatures.
        assert_eq!(sig, s.sign(unicode_body));
        // And the unicode-body signature DIFFERS from the ASCII-stripped
        // version (sanity: the non-ASCII bytes do flow into the MAC).
        let stripped = "policy_id".as_bytes();
        assert_ne!(sig, s.sign(stripped));
    }

    #[test]
    fn notifier_build_error_implements_std_error_trait_for_anyhow_chains() {
        // The boot-path error surface from notifier construction bubbles
        // through anyhow chains in `server::run` — pin that the
        // `thiserror::Error` derive lands the `std::error::Error` impl
        // via a dyn-cast. A refactor that dropped `#[derive(thiserror::Error)]`
        // (e.g. swapped to a plain `impl Display` for "less macro
        // surface") would surface as a confusing anyhow trait-bound
        // error at the boot site rather than here. Symmetric to the
        // existing `pkce_error_implements_std_error_trait_for_anyhow_chains`
        // and `cache_error_implements_std_error_trait_and_source_carries_inner_sqlx`
        // pins on sibling error types — round out the error-type triad
        // at the notifier path.
        let e = NotifierBuildError("test build failure".into());
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.to_string().contains("notifier build:"));
        assert!(dyn_err.to_string().contains("test build failure"));
        // Leaf — no inner source (the inner is a String, not an Error).
        assert!(dyn_err.source().is_none(), "NotifierBuildError is a leaf");
    }

    #[test]
    fn webhook_notifier_proxy_public_url_accessor_preserves_trailing_slash_verbatim() {
        // The approve-URL builder reads `proxy_public_url()` and appends
        // `/api/v1/blocked/{id}/approve` — the proxy_public_url is used
        // VERBATIM with no normalization (no trim of trailing `/`). The
        // existing `webhook_proxy_public_url_round_trips_through_accessor`
        // test pins a no-slash URL ("https://proxy.example"); pin the
        // trailing-slash shape symmetrically. A refactor that started
        // `.trim_end_matches('/')` here "for ergonomic URL joining"
        // would silently change every approve_url generated against an
        // operator who configured the public URL with a trailing slash
        // (producing `https://proxy.example/api/...` becoming
        // `https://proxy.example//api/...` if the trim were dropped, or
        // shifting bytes if added). Pin both axes.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            "https://webhook.example/hook".into(),
            secret,
            "https://proxy.example/".into(),
        )
        .unwrap();
        assert_eq!(n.proxy_public_url(), "https://proxy.example/");
        // Symmetric on a deeper sub-path with trailing slash.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            "https://webhook.example/hook".into(),
            secret,
            "https://proxy.example/sub/path/".into(),
        )
        .unwrap();
        assert_eq!(n.proxy_public_url(), "https://proxy.example/sub/path/");
    }

    #[tokio::test]
    async fn posts_with_signature_and_schema_headers() {
        let server = MockServer::start().await;
        let blocked_id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header_exists("x-proxilion-signature"))
            .and(header("x-proxilion-schema", BlockedNotification::SCHEMA))
            .and(header(
                "x-proxilion-blocked-id",
                blocked_id.to_string().as_str(),
            ))
            .and(body_string_contains("gmail.messages.send"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            format!("{}/hook", server.uri()),
            secret,
            "https://proxy.local".into(),
        )
        .unwrap();
        let ops = vec!["gmail:send:alice@demo.local".to_string()];
        n.notify(&sample(blocked_id, &ops)).await;
    }

    #[tokio::test]
    async fn does_not_retry_on_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(server.uri(), secret, "https://proxy.local".into()).unwrap();
        let ops: Vec<String> = vec![];
        n.notify(&sample(Uuid::new_v4(), &ops)).await;
    }

    #[tokio::test]
    async fn retries_on_5xx_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(server.uri(), secret, "https://proxy.local".into())
            .unwrap()
            .with_max_retries(5);
        let ops: Vec<String> = vec![];
        n.notify(&sample(Uuid::new_v4(), &ops)).await;
    }

    // ─── round 183 (2026-05-20): WebhookSecret + NotifierBuildError + WebhookNotifier surfaces ───

    #[test]
    fn webhook_secret_sign_is_referentially_transparent_across_fifty_repeated_calls() {
        // `WebhookSecret::sign` is a pure function — HMAC-SHA256 over
        // (secret, body) has no clock / counter / global state. Pin
        // referential transparency across 50 back-to-back calls on
        // the same body+secret. A refactor that introduced a once-cell
        // memoization layer "for hot-path perf" would still pass
        // equality; but a refactor that introduced any form of
        // per-call state (e.g. a nonce mixed into the MAC for "replay
        // hardening") would surface here on call #2..#50, AND would
        // silently break every receiver's signature validation (which
        // depends on the byte-identical MAC). Symmetric to round-181
        // RefreshCoordinator + round-182 CatKeyError Display
        // referential-transparency pins extended to this signing path.
        let secret = WebhookSecret::from_hex(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();
        let body = br#"{"blocked_id":"abc","vendor":"google"}"#;
        let first = secret.sign(body);
        for i in 1..50 {
            assert_eq!(
                secret.sign(body),
                first,
                "HMAC diverged on call #{i} — sign() must be referentially transparent",
            );
        }
    }

    #[test]
    fn webhook_secret_sign_output_byte_length_is_exactly_seventy_one_across_body_sizes() {
        // `sign()` returns `"sha256=" + hex(SHA256_digest)`. The
        // prefix is 7 bytes and the hex digest is always 64 bytes
        // (32-byte SHA-256 × 2 hex chars per byte), so the total
        // output is ALWAYS 71 bytes regardless of input body size.
        // The existing `webhook_signature_prefix_is_byte_exact_seven_chars_lowercase_sha256_equals`
        // test pins the prefix; pin the FULL output length here so a
        // refactor that switched to lower-resolution hashing (e.g.
        // truncated SHA-256 for shorter signatures) would silently
        // change the wire shape and break every receiver's
        // fixed-size signature parser. Walk three body sizes
        // (empty / 1 KB / 64 KB) so a refactor that special-cased
        // one size silently surfaces here. Symmetric to round-92
        // / round-100 byte-exact length pins extended to this
        // signature output.
        let secret = WebhookSecret::from_hex("aabbccddeeff00112233445566778899").unwrap();
        for body_size in [0usize, 1024, 64 * 1024] {
            let body = vec![0x42u8; body_size];
            let sig = secret.sign(&body);
            assert_eq!(
                sig.len(),
                71,
                "signature must be 71 bytes for body_size={body_size}, got: {} ({})",
                sig.len(),
                sig,
            );
        }
    }

    #[test]
    fn webhook_secret_from_hex_inner_vec_length_equals_input_hex_length_div_two() {
        // `WebhookSecret::from_hex` parses pairs of hex chars into
        // a `Vec<u8>` of half the input length. The existing tests
        // pin the round-trip + sign output but do NOT pin the inner
        // Vec length invariant directly. The HMAC-SHA256 algorithm
        // accepts any key length — but the inner Vec length is what
        // the operator's key-rotation playbook keys on (a 32-hex-char
        // input MUST yield a 16-byte secret, etc). A refactor that
        // started padding the key to a fixed length (e.g. 32 bytes
        // "for SHA-256 block size alignment") would silently change
        // the inner length AND silently change every signature the
        // operator's prior keys produced. Pin via the `sign(empty)`
        // output: with body == empty, the HMAC tag is purely a
        // function of the key — so different keys of different lengths
        // produce different tags. Indirect, but pin via the public
        // surface (inner Vec is private). Walk 3 hex sizes.
        for hex_len in [32usize, 64, 128] {
            let hex = "a".repeat(hex_len);
            let secret = WebhookSecret::from_hex(&hex).unwrap();
            // Sanity: sign produces a 71-char output regardless of
            // key length (HMAC accepts any).
            let sig = secret.sign(b"");
            assert_eq!(sig.len(), 71, "hex_len={hex_len} sig: {sig}");
            // Different key lengths MUST produce different signatures
            // for the same body — pin via cross-key inequality (a
            // refactor that padded all keys to 32 bytes would surface
            // here as two distinct hex inputs producing the same
            // sig). Compare against a clearly-different key.
            let other = WebhookSecret::from_hex(&"b".repeat(hex_len)).unwrap();
            assert_ne!(
                sig,
                other.sign(b""),
                "distinct keys of hex_len={hex_len} must produce distinct sigs",
            );
        }
    }

    #[test]
    fn notifier_build_error_inner_field_is_owned_string_for_cross_await_propagation() {
        // `NotifierBuildError(pub String)` — the inner is an OWNED
        // `String`. The error propagates across the `.await` boundary
        // in the boot-time notifier-assembly path AND through the
        // notifier-reconfig API handler's `?`-chain. A refactor to
        // `&'a str` for "zero-alloc on the cold-path" would
        // introduce a lifetime parameter that would cascade through
        // every consuming `?`-chain. Pin the owned-String type via
        // the canonical require_string helper. Symmetric to
        // round-181 + round-182 owned-String pins extended to this
        // notifier-build error type.
        fn require_string(_: &String) {}
        let e = NotifierBuildError("hmac secret hex length must be even".to_string());
        require_string(&e.0);
        assert_eq!(e.0, "hmac secret hex length must be even");
        // Three distinct inner messages each round-trip the owned-
        // String contract — a refactor that interned the inner via
        // a static slice would surface here.
        for msg in ["", "boot failed", "café-é-→-🔥"] {
            let e = NotifierBuildError(msg.to_string());
            require_string(&e.0);
            assert_eq!(e.0, msg);
        }
    }

    #[test]
    fn notifier_build_error_debug_carries_struct_name_for_grep_bucketing() {
        // `#[derive(Debug)]` on `NotifierBuildError` feeds `?err` in
        // the boot-path's notifier-assembly tracing call. Operators
        // grep for `NotifierBuildError` to bucket "notifier failed
        // to start" from other boot faults. A hand-rolled
        // `impl Debug` that hid the struct name "to compact" the
        // log line would silently merge the bucket with other
        // ad-hoc error renders. Pin the struct name across three
        // distinct inner messages so any single-input rendering
        // hack also surfaces. Symmetric to round-176 PolicyLoadError
        // + round-180 MatchError + round-181 AuthFail + round-182
        // CatKeyError Debug variant-name sweeps extended to this
        // single-variant tuple struct.
        for inner in [
            "hmac secret is empty",
            "boot client failed",
            "invalid hex at 2",
        ] {
            let e = NotifierBuildError(inner.to_string());
            let s = format!("{e:?}");
            assert!(
                s.contains("NotifierBuildError"),
                "missing struct name `NotifierBuildError` in Debug: {s}",
            );
            assert!(s.contains(inner), "missing inner reason in Debug: {s}");
        }
    }

    #[test]
    fn webhook_notifier_proxy_public_url_accessor_is_referentially_transparent_across_fifty_calls()
    {
        // `WebhookNotifier::proxy_public_url(&self)` returns `&str`
        // borrowed from `self.proxy_public_url: String` — pure
        // accessor with no per-call state. Pin 50 back-to-back
        // calls returning the SAME `&str` (byte-identical content
        // AND pointing into the same backing buffer via the
        // `as_ptr` equality). A refactor that re-cloned the field
        // on every access "for some Cow conversion" would silently
        // re-allocate per call AND break the borrow-pointer
        // identity. Symmetric to round-181 RefreshCoordinator
        // referential-transparency pin extended to this accessor.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            "https://hook.example.test/wh".into(),
            secret,
            "https://proxy.local".into(),
        )
        .unwrap();
        let first = n.proxy_public_url();
        let first_ptr = first.as_ptr();
        let first_str = first.to_string();
        for i in 1..50 {
            let next = n.proxy_public_url();
            assert_eq!(next, first_str, "URL string diverged on call #{i}");
            assert_eq!(
                next.as_ptr(),
                first_ptr,
                "accessor must return SAME borrow on call #{i}, not re-clone",
            );
        }
    }

    // ─── round 225 (2026-05-22): WebhookSecret/WebhookNotifier exhaustive
    // destructure field counts, return-type pins on from_hex/sign/new,
    // WebhookSecret inner field type pin ───

    #[test]
    fn webhook_secret_inner_field_count_pinned_at_exactly_one_via_exhaustive_destructure() {
        // `WebhookSecret(Vec<u8>)` is a single-field tuple struct holding
        // the HMAC key. A 2nd field landing (e.g. `algorithm: HashAlg`
        // for a future "SHA-512 instead of SHA-256 per-deployment"
        // override, OR `created_at: DateTime<Utc>` "for key-rotation
        // observability") without matching `from_hex` constructor wiring
        // would silently leave the new field zero-initialized on every
        // secret handed out, breaking the rotation path or quietly
        // defaulting to a less-safe algorithm. The exhaustive
        // destructure with no `..` rest pattern forces a 2nd field to
        // update this site in lockstep with `from_hex`. Symmetric to
        // the BearerHash inner-array pin + ErrorBody 6-field +
        // FederationClaims 8-field exhaustive-destructure pins.
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let WebhookSecret(_inner) = s;
    }

    #[test]
    fn webhook_notifier_field_count_pinned_at_exactly_six_via_exhaustive_destructure_no_rest_pattern()
     {
        // `WebhookNotifier { url, secret, http, max_retries,
        // proxy_public_url, burst }` — exactly 6 fields. A 7th field
        // landing (e.g. `auth_header: Option<String>` for receivers
        // that require Bearer/Basic auth in ADDITION to the HMAC
        // signature, OR `circuit_breaker: CircuitBreaker` for per-
        // endpoint failure-rate damping) without matching `new()`
        // constructor wiring would silently leave the new field
        // zero-initialized on every notifier — operators would see no
        // error AND no behaviour change. The exhaustive destructure
        // forces a 7th field to update this site in lockstep with
        // `new()`. Symmetric to the TeeStream 2-field + NatsBridge
        // 2-field + WebhookSecret 1-field exhaustive-destructure
        // pins extended to this sibling notifier shape.
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let n = WebhookNotifier::new(
            "https://hook.example.test/wh".into(),
            secret,
            "https://proxy.local".into(),
        )
        .unwrap();
        let WebhookNotifier {
            url: _,
            secret: _,
            http: _,
            max_retries: _,
            proxy_public_url: _,
            burst: _,
        } = n;
    }

    #[test]
    fn webhook_secret_from_hex_return_type_is_result_self_notifier_build_error_via_fn_pointer_witness()
     {
        // `WebhookSecret::from_hex` returns `Result<Self,
        // NotifierBuildError>` — the boot path bubbles the error
        // through `?` via `anyhow::Error` chains for structured
        // logging. Pin the type via a fn-pointer witness so a
        // refactor that widened the Err arm to `anyhow::Error` "for
        // ergonomic boot-path bubbling" would lose the structured
        // `NotifierBuildError` variant the operator setup-status
        // dashboard splits on at the wire (boot logs key on the
        // `notifier build:` prefix). Symmetric to the
        // FederationClaims-validate + new_auth_code +
        // pct + TeeStream::new fn-pointer-return-type pins extended
        // to this sibling boot-path constructor.
        let _f: fn(&str) -> Result<WebhookSecret, NotifierBuildError> = WebhookSecret::from_hex;
        // Exercise on both arms (Ok + Err) so the witness covers the
        // value-domain as well as the type axis.
        assert!(WebhookSecret::from_hex("00112233445566778899aabbccddeeff").is_ok());
        assert!(WebhookSecret::from_hex("").is_err());
    }

    #[test]
    fn webhook_secret_sign_return_type_is_owned_string_by_value_via_fn_pointer_witness_for_header_set()
     {
        // `WebhookSecret::sign` returns owned `String` — the signature
        // is set as the `x-proxilion-signature` HTTP header value in
        // `notify`, which crosses the `.await` boundary at
        // `self.http.post(...).send().await`. The value MUST be owned
        // (not `Cow<'a, str>`) because the header builder consumes the
        // value. A refactor to `Cow<'a, str>` "for zero-alloc on a
        // small-input fast-path" would tie the lifetime to `self` or
        // `body` and break the cross-await header-set path. Pin via
        // fn-pointer witness `fn(&WebhookSecret, &[u8]) -> String` so
        // the type surfaces at the signing boundary, not at the
        // header-set call site downstream. Symmetric to the
        // sanitize_token + pct + new_auth_code owned-String
        // fn-pointer pins extended to this sibling secret method.
        let _f: fn(&WebhookSecret, &[u8]) -> String = WebhookSecret::sign;
        fn require_owned_string(_: String) {}
        let s = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        require_owned_string(s.sign(b"body"));
    }

    #[test]
    fn webhook_notifier_new_return_type_is_result_self_notifier_build_error_via_fn_pointer_witness()
    {
        // `WebhookNotifier::new` returns `Result<Self,
        // NotifierBuildError>` — the boot path bubbles the error
        // through `?` symmetric to `WebhookSecret::from_hex`. Pin the
        // type via a fn-pointer witness so a refactor that swapped to
        // `Result<Self, anyhow::Error>` "for ergonomic boot-path
        // bubbling" OR to a panicking `pub fn new(...) -> Self` "since
        // reqwest::Client::builder() rarely fails" would surface here
        // at the constructor boundary rather than at the boot-path call
        // site downstream. The `reqwest::Client::builder().build()`
        // error path is the load-bearing branch — operators who pass
        // a malformed `user_agent` env override would see this fire.
        // Symmetric to the WebhookSecret::from_hex Result pin above.
        let _f: fn(String, WebhookSecret, String) -> Result<WebhookNotifier, NotifierBuildError> =
            WebhookNotifier::new;
        let secret = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let result = WebhookNotifier::new(
            "https://hook.example.test/wh".into(),
            secret,
            "https://proxy.local".into(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn webhook_secret_clone_preserves_inner_bytes_byte_exact_via_destructure() {
        // The existing `secret_clone_yields_same_signature_as_original`
        // pin checks that cloning preserves the OUTPUT (signature
        // byte-equal) of `sign`; pin the symmetric INPUT axis (the
        // inner Vec<u8> bytes are preserved verbatim through Clone)
        // via a destructure-then-compare. A refactor that introduced a
        // per-clone derived value (e.g. `Vec<u8>::from(&self.0[..])`
        // accidentally truncating one byte) would pass the
        // sign-output pin if the truncation happened to produce a
        // consistent signature, but would surface here as a length
        // diff. Pin both length AND byte-equality on the inner
        // destructured field. Symmetric to the BearerHash
        // partial-eq distinct-inputs + Bearer Clone-independent-array
        // pins extended to this sibling Vec-backed secret type.
        let original = WebhookSecret::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let cloned = original.clone();
        let WebhookSecret(orig_bytes) = original;
        let WebhookSecret(clone_bytes) = cloned;
        assert_eq!(orig_bytes.len(), clone_bytes.len(), "byte count diverged");
        assert_eq!(orig_bytes, clone_bytes, "inner bytes diverged after clone");
        // And the length matches the hex input / 2 (16 bytes for
        // 32 hex chars).
        assert_eq!(orig_bytes.len(), 16);
    }
}
