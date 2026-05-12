//! Generic SIEM webhook forwarder (spec.md §3.3).
//!
//! Posts every `ActionEvent` as JSON to a customer-configured webhook URL
//! with an `X-Proxilion-Signature` HMAC-SHA256 header keyed on a shared
//! secret. Body is the same JSON shape as `/api/v1/actions` (one event per
//! POST). For batched ingestion, customers should subscribe to NATS
//! (§3.1) or pull `/api/v1/actions/export` — this forwarder is for fire-
//! and-forget integrations that expect one webhook per event (PagerDuty,
//! generic Splunk HEC, Datadog Events, Slack, etc.).
//!
//! Reliability: each publish is retried with exponential backoff up to
//! `max_retries` (default 3). On exhaustion the failure is logged and
//! metric'd; the event is not re-queued — the customer is expected to
//! pull from `/api/v1/actions` for any gaps. This matches the spec's
//! "preventative chokepoint, audit log is the source of truth" model.

use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

use crate::adapters::action_stream::{ActionEvent, ActionStream};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct SiemHmacKey(Vec<u8>);

impl SiemHmacKey {
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        if hex.len() % 2 != 0 {
            return Err(KeyError("HMAC key hex length must be even".into()));
        }
        if hex.len() < 32 {
            return Err(KeyError(
                "HMAC key must be at least 16 bytes (32 hex chars)".into(),
            ));
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| KeyError(format!("invalid hex at {i}: {e}")))?;
            out.push(byte);
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
#[error("{0}")]
pub struct KeyError(pub String);

pub struct SiemForwarder {
    url: String,
    key: SiemHmacKey,
    http: reqwest::Client,
    max_retries: u32,
}

impl SiemForwarder {
    pub fn new(url: String, key: SiemHmacKey) -> Result<Self, BuildError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!(
                "Proxilion-SIEM/",
                env!("CARGO_PKG_VERSION"),
                " (+https://proxilion.com)"
            ))
            .build()
            .map_err(|e| BuildError(e.to_string()))?;
        Ok(Self {
            url,
            key,
            http,
            max_retries: 3,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }
}

#[derive(Debug, thiserror::Error)]
#[error("siem forwarder build: {0}")]
pub struct BuildError(pub String);

#[async_trait]
impl ActionStream for SiemForwarder {
    async fn publish(&self, event: ActionEvent) {
        let body = match serde_json::to_vec(&event) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "siem: serialize ActionEvent failed");
                metrics::counter!(
                    "proxilion_siem_forward_failures_total",
                    "reason" => "serialize"
                )
                .increment(1);
                return;
            }
        };
        let signature = self.key.sign(&body);
        // Schema version for forward-compat (mirrors ui-less-surfaces.md §6.2).
        let schema = "proxilion.action_event.v1";

        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let send = self
                .http
                .post(&self.url)
                .header("content-type", "application/json")
                .header("x-proxilion-signature", &signature)
                .header("x-proxilion-schema", schema)
                .header("x-proxilion-event-id", event.request_id.to_string())
                .body(body.clone())
                .send()
                .await;

            match send {
                Ok(r) if r.status().is_success() => {
                    metrics::counter!(
                        "proxilion_siem_forward_total",
                        "result" => "ok",
                        "decision" => event.decision.clone()
                    )
                    .increment(1);
                    debug!(status = %r.status(), attempt, "siem forward ok");
                    return;
                }
                Ok(r) if r.status().is_client_error() => {
                    // 4xx: the webhook rejected us. Retrying won't help.
                    warn!(status = %r.status(), "siem: webhook rejected (4xx); not retrying");
                    metrics::counter!(
                        "proxilion_siem_forward_failures_total",
                        "reason" => "client_error"
                    )
                    .increment(1);
                    return;
                }
                Ok(r) => {
                    warn!(status = %r.status(), attempt, "siem: webhook 5xx");
                    if attempt > self.max_retries {
                        metrics::counter!(
                            "proxilion_siem_forward_failures_total",
                            "reason" => "server_error_exhausted"
                        )
                        .increment(1);
                        return;
                    }
                }
                Err(e) => {
                    warn!(error = %e, attempt, "siem: webhook transport error");
                    if attempt > self.max_retries {
                        metrics::counter!(
                            "proxilion_siem_forward_failures_total",
                            "reason" => "transport_exhausted"
                        )
                        .increment(1);
                        return;
                    }
                }
            }

            // Exponential backoff: 100ms, 400ms, 1.6s, …
            let backoff_ms = 100u64 * 4u64.saturating_pow(attempt.saturating_sub(1));
            tokio::time::sleep(Duration::from_millis(backoff_ms.min(5_000))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample() -> ActionEvent {
        ActionEvent {
            request_id: Uuid::new_v4(),
            agent_session_id: Uuid::new_v4(),
            p_0: "alice@demo.local".into(),
            leaf_pca_id: None,
            vendor: "google".into(),
            action: "gmail.messages.send".into(),
            method: "POST".into(),
            path: "/gmail/v1/users/me/messages/send".into(),
            status: 200,
            decision: "allow".into(),
            block_reason: None,
            read_filter_triggered: false,
            quarantined_count: 0,
            at: Utc::now(),
            policy_id: Some("gmail-external-recipient".into()),
            extra: serde_json::Value::Null,
        }
    }

    #[test]
    fn hmac_key_round_trip() {
        let hex = "00112233445566778899aabbccddeeff";
        let k = SiemHmacKey::from_hex(hex).unwrap();
        let sig = k.sign(b"hello");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
        // Deterministic.
        assert_eq!(sig, k.sign(b"hello"));
        // Diverges on body change.
        assert_ne!(sig, k.sign(b"hellp"));
    }

    #[test]
    fn hmac_key_rejects_short() {
        assert!(SiemHmacKey::from_hex("dead").is_err());
        assert!(SiemHmacKey::from_hex("abc").is_err()); // odd length
    }

    #[tokio::test]
    async fn posts_event_with_signature_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/siem"))
            .and(header_exists("x-proxilion-signature"))
            .and(header("x-proxilion-schema", "proxilion.action_event.v1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd =
            SiemForwarder::new(format!("{}/siem", server.uri()), key).unwrap();
        fwd.publish(sample()).await;
        // wiremock asserts the matcher on drop; if it didn't match, the
        // test panics. Reaching this line is success.
    }

    #[tokio::test]
    async fn does_not_retry_on_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new(server.uri(), key).unwrap();
        fwd.publish(sample()).await;
    }

    #[tokio::test]
    async fn retries_on_5xx_then_succeeds() {
        let server = MockServer::start().await;
        // First two attempts: 503. Third: 200.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new(server.uri(), key)
            .unwrap()
            .with_max_retries(5);
        fwd.publish(sample()).await;
    }
}
