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
}
