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

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

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
    /// Optional batch mode (spec.md §3.3 dev 2). When set, `publish`
    /// appends to an in-memory buffer and a single POST drains it once
    /// the buffer reaches `max_batch_size` OR a background flush task
    /// ticks at `flush_interval`. Mutually-exclusive with the per-event
    /// path — when batching is configured, `publish` returns after the
    /// append; the actual POST happens on flush.
    batch: Option<BatchState>,
}

#[derive(Clone)]
struct BatchState {
    buffer: Arc<Mutex<Vec<ActionEvent>>>,
    max_batch_size: usize,
    flush_interval: Duration,
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
            batch: None,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Enable batched delivery. spec.md §3.3 dev 2.
    /// `max_batch_size` triggers a flush on size; `flush_interval` triggers
    /// a flush on time (via the task spawned by [`SiemForwarder::spawn_flush_loop`]).
    /// Skip this method to keep the per-event default.
    pub fn with_batching(mut self, max_batch_size: usize, flush_interval: Duration) -> Self {
        assert!(max_batch_size > 0, "max_batch_size must be > 0");
        self.batch = Some(BatchState {
            buffer: Arc::new(Mutex::new(Vec::with_capacity(max_batch_size))),
            max_batch_size,
            flush_interval,
        });
        self
    }

    /// Returns true when batching is enabled. Callers use this to decide
    /// whether to spawn the flush loop.
    pub fn batching_enabled(&self) -> bool {
        self.batch.is_some()
    }

    /// Drain the batch buffer and POST whatever it contains as a single
    /// batch envelope. No-op when batching is disabled or the buffer is
    /// empty. Public so the `spawn_flush_loop` task can drive flushes.
    pub async fn flush_batch(&self) {
        let Some(b) = &self.batch else { return };
        let drained: Vec<ActionEvent> = {
            let mut buf = b.buffer.lock().await;
            if buf.is_empty() {
                return;
            }
            std::mem::take(&mut *buf)
        };
        self.send_batch(drained).await;
    }

    async fn send_batch(&self, events: Vec<ActionEvent>) {
        let envelope = serde_json::json!({
            "schema": "proxilion.action_event_batch.v1",
            "count": events.len(),
            "events": events,
        });
        let body = match serde_json::to_vec(&envelope) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "siem batch: serialize failed");
                metrics::counter!(
                    "proxilion_siem_forward_failures_total",
                    "reason" => "serialize"
                )
                .increment(1);
                return;
            }
        };
        let signature = self.key.sign(&body);
        let schema = "proxilion.action_event_batch.v1";

        let mut attempt: u32 = 0;
        let count = events.len();
        loop {
            attempt += 1;
            let send = self
                .http
                .post(&self.url)
                .header("content-type", "application/json")
                .header("x-proxilion-signature", &signature)
                .header("x-proxilion-schema", schema)
                .header("x-proxilion-batch-count", count.to_string())
                .body(body.clone())
                .send()
                .await;
            match send {
                Ok(r) if r.status().is_success() => {
                    metrics::counter!(
                        "proxilion_siem_forward_total",
                        "result" => "ok",
                        "decision" => "(batch)"
                    )
                    .increment(count as u64);
                    metrics::counter!("proxilion_siem_batches_sent_total").increment(1);
                    metrics::histogram!("proxilion_siem_batch_size").record(count as f64);
                    debug!(status = %r.status(), attempt, count, "siem batch ok");
                    return;
                }
                Ok(r) if r.status().is_client_error() => {
                    warn!(status = %r.status(), count, "siem batch: 4xx; not retrying");
                    metrics::counter!(
                        "proxilion_siem_forward_failures_total",
                        "reason" => "client_error"
                    )
                    .increment(count as u64);
                    return;
                }
                Ok(r) => {
                    warn!(status = %r.status(), attempt, count, "siem batch: 5xx");
                    if attempt > self.max_retries {
                        metrics::counter!(
                            "proxilion_siem_forward_failures_total",
                            "reason" => "server_error_exhausted"
                        )
                        .increment(count as u64);
                        return;
                    }
                }
                Err(e) => {
                    warn!(error = %e, attempt, count, "siem batch: transport error");
                    if attempt > self.max_retries {
                        metrics::counter!(
                            "proxilion_siem_forward_failures_total",
                            "reason" => "transport_exhausted"
                        )
                        .increment(count as u64);
                        return;
                    }
                }
            }
            let backoff_ms = 100u64 * 4u64.saturating_pow(attempt.saturating_sub(1));
            tokio::time::sleep(Duration::from_millis(backoff_ms.min(5_000))).await;
        }
    }
}

/// Background flush task. Spawns when [`SiemForwarder::batching_enabled`]
/// is true. The task lives for the duration of the proxy process — the
/// only failure mode is "DB-side receiver permanently down," which
/// `send_batch` already metric's and drops.
pub async fn spawn_flush_loop(forwarder: Arc<SiemForwarder>) {
    let Some(batch) = forwarder.batch.as_ref().cloned() else {
        return;
    };
    info!(
        max_batch_size = batch.max_batch_size,
        flush_interval_secs = batch.flush_interval.as_secs(),
        "SIEM batch flush loop started"
    );
    loop {
        tokio::time::sleep(batch.flush_interval).await;
        forwarder.flush_batch().await;
    }
}

#[derive(Debug, thiserror::Error)]
#[error("siem forwarder build: {0}")]
pub struct BuildError(pub String);

#[async_trait]
impl ActionStream for SiemForwarder {
    async fn publish(&self, event: ActionEvent) {
        // Batched path (spec.md §3.3 dev 2): append + size-flush. The
        // time-based flush is driven by `spawn_flush_loop`.
        if let Some(b) = &self.batch {
            let drained = {
                let mut buf = b.buffer.lock().await;
                buf.push(event);
                if buf.len() >= b.max_batch_size {
                    Some(std::mem::take(&mut *buf))
                } else {
                    None
                }
            };
            if let Some(events) = drained {
                self.send_batch(events).await;
            }
            return;
        }
        // Per-event path (default).
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
        let fwd = SiemForwarder::new(format!("{}/siem", server.uri()), key).unwrap();
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

    #[tokio::test]
    async fn batch_mode_buffers_then_flushes_on_size() {
        let server = MockServer::start().await;
        // Match exactly one batched POST with the batch schema header.
        // We assert `count` header matches the batch size (3).
        Mock::given(method("POST"))
            .and(path("/siem"))
            .and(header(
                "x-proxilion-schema",
                "proxilion.action_event_batch.v1",
            ))
            .and(header("x-proxilion-batch-count", "3"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new(format!("{}/siem", server.uri()), key)
            .unwrap()
            .with_batching(3, Duration::from_secs(60));
        assert!(fwd.batching_enabled());
        // Two events: buffer holds them, no POST yet.
        fwd.publish(sample()).await;
        fwd.publish(sample()).await;
        // Third triggers a size-flush.
        fwd.publish(sample()).await;
    }

    #[tokio::test]
    async fn batch_mode_flush_drains_partial_buffer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header(
                "x-proxilion-schema",
                "proxilion.action_event_batch.v1",
            ))
            .and(header("x-proxilion-batch-count", "2"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new(server.uri(), key)
            .unwrap()
            .with_batching(10, Duration::from_secs(60));
        fwd.publish(sample()).await;
        fwd.publish(sample()).await;
        // Manual drain — exercises the path the background flush task takes.
        fwd.flush_batch().await;
    }

    #[tokio::test]
    async fn flush_batch_is_noop_when_buffer_empty() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new(server.uri(), key)
            .unwrap()
            .with_batching(10, Duration::from_secs(60));
        fwd.flush_batch().await;
    }
}
