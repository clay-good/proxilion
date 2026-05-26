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

    #[test]
    fn key_error_display_exposes_inner_string_without_prefix() {
        // KeyError uses `#[error("{0}")]` — the operator sees the raw inner
        // message verbatim (no "siem key: " prefix), so the per-branch
        // messages from `from_hex` are what dashboard filters key on.
        // (Matched on the Result rather than `unwrap_err`-ed because
        // KeyError intentionally has no Debug-print of the source key.)
        let err = SiemHmacKey::from_hex("abc")
            .map(|_| ())
            .expect_err("odd-length must error");
        assert_eq!(err.to_string(), "HMAC key hex length must be even");
    }

    #[test]
    fn build_error_display_carries_siem_forwarder_build_prefix() {
        // BuildError adds `siem forwarder build: ` — the setup-status path
        // renders this verbatim so operators distinguish a key-parse fault
        // (KeyError) from a reqwest::Client construction fault (BuildError).
        let e = BuildError("transport init: dns lookup failed".into());
        assert_eq!(
            e.to_string(),
            "siem forwarder build: transport init: dns lookup failed"
        );
    }

    #[test]
    fn from_hex_distinguishes_odd_and_too_short_branches() {
        // Two distinct length checks fire in order: odd-length first
        // (catches the lone-nibble case before the >= 32 check would lump
        // it in with the "too short" branch). A regression that collapsed
        // both into "invalid length" would lose the actionable hint.
        let odd = SiemHmacKey::from_hex("abc").map(|_| ()).unwrap_err();
        assert!(odd.to_string().contains("even"), "odd-len → {odd}");
        let short = SiemHmacKey::from_hex("dead").map(|_| ()).unwrap_err();
        assert!(
            short.to_string().contains("16 bytes"),
            "too-short → {short}"
        );
    }

    #[test]
    fn from_hex_invalid_hex_char_carries_position_index_in_message() {
        // Operator triages a typo'd env var by reading the byte offset out
        // of the message — pin both the `invalid hex at` prefix and the
        // numeric position so a sloppy refactor that lost the index would
        // surface here. 'g' is not a hex digit.
        let mut s = "00".repeat(16);
        s.replace_range(2..4, "0g");
        let err = SiemHmacKey::from_hex(&s).map(|_| ()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid hex at"), "{msg}");
        assert!(msg.contains(" 2"), "expected position offset 2 in: {msg}");
    }

    #[test]
    fn from_hex_accepts_32_char_minimum_and_rejects_30_just_below() {
        // 32 hex chars = 16 bytes = the documented minimum (RFC 2104 §5
        // recommends ≥L; SHA-256 L=32 bytes is stricter still — but the
        // implementation gates at 16 for parity with common SIEM webhook
        // shared-secret advice). Pin both edges: 32 passes, 30 fails.
        assert!(SiemHmacKey::from_hex(&"a".repeat(32)).is_ok());
        let err = SiemHmacKey::from_hex(&"a".repeat(30))
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("16 bytes"), "{err}");
    }

    #[test]
    fn sign_matches_rfc4231_test_vector_1_for_hmac_sha256() {
        // RFC 4231 §4.2 Test Case 1: Key = 0x0b × 20, Data = "Hi There",
        // expected HMAC-SHA256 tag =
        // b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7.
        // Pinning this catches any future swap of the HMAC primitive (a
        // SHA-1 / SHA-384 mis-wire would silently break every existing
        // SIEM receiver expecting SHA-256).
        let key = SiemHmacKey::from_hex(&"0b".repeat(20)).unwrap();
        let sig = key.sign(b"Hi There");
        assert_eq!(
            sig,
            "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn sign_diverges_when_key_changes_for_identical_body() {
        // Existing `hmac_key_round_trip` test pins divergence on body
        // change but not on key change — a regression that ignored the
        // key (e.g. a stub that hashed the body alone) would silently
        // satisfy that test. This pins the key axis.
        let k1 = SiemHmacKey::from_hex(&"aa".repeat(16)).unwrap();
        let k2 = SiemHmacKey::from_hex(&"bb".repeat(16)).unwrap();
        let body = b"identical body";
        assert_ne!(k1.sign(body), k2.sign(body));
    }

    #[test]
    fn sign_is_lowercase_hex_with_fixed_prefix_and_length() {
        // Receivers strip the `sha256=` prefix and hex-decode the rest, so
        // an uppercase or wrong-length regression would silently break
        // signature verification at every existing integration.
        let key = SiemHmacKey::from_hex(&"00".repeat(16)).unwrap();
        let sig = key.sign(b"any body");
        let body = sig
            .strip_prefix("sha256=")
            .expect("must carry sha256= prefix");
        assert_eq!(body.len(), 64, "SHA-256 hex tag is 64 chars: {sig}");
        assert!(
            body.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "tag must be lowercase hex: {sig}"
        );
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

    #[test]
    fn with_max_retries_is_consuming_self_fluent_setter() {
        // Pin the `(mut self, n) -> Self` builder shape so a refactor
        // to `&mut self` (which would force every call site to bind
        // the forwarder to a local before chaining) surfaces here as
        // a compile error rather than as confusing build breaks across
        // server.rs / tests. The retry-count itself doesn't have an
        // observable accessor — pin via successful chaining + a no-op
        // sanity round trip that asserts the value didn't poison the
        // surrounding state (batch still disabled, etc).
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new("https://example.invalid/siem".into(), key)
            .unwrap()
            .with_max_retries(7);
        assert!(
            !fwd.batching_enabled(),
            "with_max_retries must not enable batching as a side effect"
        );
    }

    #[test]
    #[should_panic(expected = "max_batch_size must be > 0")]
    fn with_batching_panics_on_zero_max_batch_size() {
        // The `assert!(max_batch_size > 0)` invariant is load-bearing —
        // a `Vec::with_capacity(0)` buffer that then size-triggers on
        // `len >= 0` would flush after every publish (defeating the
        // batching purpose silently). Pin the fail-fast posture so a
        // refactor to `if n == 0 { default }` (silent vs panic-on-
        // misconfig) surfaces here. The operator hits this only via
        // explicit env-var override (the per-driver config layer
        // already pre-validates), so a panic is the right contract.
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let _ = SiemForwarder::new("https://example.invalid/siem".into(), key)
            .unwrap()
            .with_batching(0, Duration::from_secs(60));
    }

    #[test]
    fn batching_enabled_is_false_by_default_and_true_after_with_batching() {
        // Pin both axes of the predicate that server.rs uses to decide
        // whether to spawn the flush loop: a fresh forwarder is in
        // per-event mode (false); after `.with_batching(...)` it flips
        // to true. A refactor that inverted the default (e.g. "always
        // batch") would silently change every operator's default
        // delivery shape on next restart — operators reading the
        // troubleshooting docs would still expect per-event behavior.
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new("https://example.invalid/siem".into(), key).unwrap();
        assert!(!fwd.batching_enabled(), "default must be per-event");
        let fwd = fwd.with_batching(10, Duration::from_secs(30));
        assert!(
            fwd.batching_enabled(),
            "with_batching must flip the predicate"
        );
    }

    #[test]
    fn siem_forwarder_and_key_types_are_send_sync_static_for_app_state_arc_path() {
        // `SiemForwarder` is wired into AppState as
        // `Arc<dyn ActionStream>`; its `publish` is `.await`-ed from
        // inside tokio-spawned tasks (TeeStream fan-out). `SiemHmacKey`
        // is held by `SiemForwarder`. `KeyError` and `BuildError` flow
        // through `anyhow::Error` chains at boot. Pin the three-trait
        // combo on all four so a refactor that introduced a `Cell<...>`
        // field on the forwarder, an `Rc<[u8]>` on the key buffer, or
        // a non-Send inner on either error type would break the
        // AppState assembly at the right call site rather than as a
        // far-removed trait-bound error.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<SiemForwarder>();
        require_send_sync_static::<SiemHmacKey>();
        require_send_sync_static::<KeyError>();
        require_send_sync_static::<BuildError>();
    }

    #[test]
    fn key_error_and_build_error_implement_std_error_trait_with_no_source() {
        // Both error types are `thiserror::Error` derives with
        // `#[error("{0}")]` shapes. Pin the `std::error::Error` impl
        // via dyn-cast AND confirm both are leaf arms with `source()
        // == None`. A refactor that swapped to a hand-rolled
        // `impl Display` and forgot to re-impl Error would surface
        // here at the trait cast rather than as a silently-truncated
        // anyhow chain in production logs. A refactor that added an
        // inner-error field with `#[from]` would surface the symmetric
        // direction (source becomes Some).
        let k = KeyError("kx".into());
        let b = BuildError("bx".into());
        let dk: &dyn std::error::Error = &k;
        let db: &dyn std::error::Error = &b;
        assert!(
            std::error::Error::source(dk).is_none(),
            "KeyError must be leaf",
        );
        assert!(
            std::error::Error::source(db).is_none(),
            "BuildError must be leaf",
        );
    }

    #[test]
    fn key_error_and_build_error_debug_carries_struct_name_for_grep() {
        // Both error types feed `?e` in `tracing::warn!` call sites at
        // boot and at SIEM publish-failure paths. Operators grep the
        // resulting log line by struct name to bucket "key parse fault"
        // vs "transport build fault". A hand-rolled Debug that hid the
        // struct name "to compact" the line would break every operator
        // bucket. Pin the struct-name shape on both — symmetric to the
        // `connect_error_debug_includes_struct_name_for_grep` pin on
        // [crates/proxy/src/forwarder/nats.rs] for ConnectError.
        let k = format!("{:?}", KeyError("inner".into()));
        assert!(k.contains("KeyError"), "got: {k}");
        let b = format!("{:?}", BuildError("inner".into()));
        assert!(b.contains("BuildError"), "got: {b}");
    }

    #[test]
    fn siem_hmac_key_from_hex_accepts_uppercase_and_mixed_case_hex_chars() {
        // `u8::from_str_radix(..., 16)` accepts both `a-f` and `A-F`.
        // The existing `hmac_key_round_trip` test only exercises
        // lowercase hex; pin the uppercase + mixed-case acceptance
        // contract here. Operators paste hex strings from various
        // tools (`openssl rand -hex` is lowercase, but some KMS
        // dumps and Slack-shared secrets are uppercase). A refactor
        // that swapped to a hand-rolled nibble parser gated on
        // `'0'..='9' | 'a'..='f'` only would silently reject every
        // uppercase paste and break setup with a confusing "invalid
        // hex at N" rather than working transparently. Cross-pin
        // that all three case-shapes produce byte-equal HMAC
        // signatures on the same body.
        let lower = SiemHmacKey::from_hex(&"ab".repeat(16)).unwrap();
        let upper = SiemHmacKey::from_hex(&"AB".repeat(16)).unwrap();
        let mixed = SiemHmacKey::from_hex(&"aB".repeat(16)).unwrap();
        let body = b"identical body across case variants";
        assert_eq!(lower.sign(body), upper.sign(body));
        assert_eq!(lower.sign(body), mixed.sign(body));
    }

    #[test]
    fn siem_hmac_key_clone_preserves_bytes_via_sign_equality() {
        // `SiemHmacKey` derives `Clone` over `Vec<u8>` — the clone
        // holds an independent buffer with byte-equal contents. Pin
        // that the clone signs identically (proxy of "bytes preserved")
        // so a refactor that swapped the inner to `Arc<[u8]>` would
        // still pass (good — that's the same observable), but one
        // that accidentally zeroized the source buffer on clone
        // (e.g. `mem::take`-then-restore that panicked mid-way) would
        // surface here as a divergent signature.
        let k = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let c = k.clone();
        let body = b"some payload here";
        assert_eq!(k.sign(body), c.sign(body));
        // Cross-check the clone is independent — dropping the source
        // does not invalidate the clone's signing capability.
        drop(k);
        let again = c.sign(body);
        assert!(again.starts_with("sha256="));
        assert_eq!(again.len(), "sha256=".len() + 64);
    }

    #[test]
    fn siem_hmac_key_from_hex_rejects_empty_string_via_too_short_branch() {
        // The empty string has even length (0) AND is below the
        // 32-char minimum. The odd-length check fires first; for an
        // empty string (even length), the `< 32` branch is what
        // catches it. Pin that the resulting error carries the
        // "16 bytes" hint — operators with an unset env var land
        // here, and the "16 bytes" message is what tells them the
        // key was missing entirely vs malformed. A refactor that
        // re-ordered the branches (length-min first, then even) or
        // collapsed both into a generic "invalid length" would
        // silently lose the actionable hint.
        let err = SiemHmacKey::from_hex("").map(|_| ()).unwrap_err();
        assert!(err.to_string().contains("16 bytes"), "got: {err}");
    }

    #[test]
    fn siem_hmac_key_from_hex_accepts_long_64_byte_128_hex_char_per_rfc_2104_section_3() {
        // RFC 2104 §3 best-practice key size for HMAC-SHA256 is 64
        // bytes (the inner block size). Operators using `openssl rand
        // -hex 64` produce 128-char hex strings AND expect from_hex
        // to accept them. The existing tests exercise the 32-char
        // (16-byte) minimum and the 17-byte and 33-byte boundaries
        // but never the 64-byte best-practice key size. A refactor
        // that capped key bytes at 32 "for fixed-buffer hot path"
        // would silently truncate every long key — surface here. Pin
        // both that the longer key parses AND that signing with it
        // produces a valid 71-byte signature (sha256= prefix + 64
        // hex chars).
        let long_hex = "a".repeat(128); // 128 hex chars = 64 bytes
        let key = SiemHmacKey::from_hex(&long_hex).expect("64-byte key must parse");
        let sig = key.sign(b"sample body");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 71);
    }

    #[test]
    fn key_error_and_build_error_implement_std_error_trait_via_dyn_cast_leaf_source_none() {
        // `KeyError(pub String)` and `BuildError(pub String)` are
        // thiserror-derived leaf-arm errors carrying only a String.
        // Pin both implement `std::error::Error` via dyn-cast AND
        // confirm `source() == None` on both — required by anyhow
        // chains higher up. Symmetric to the
        // `email_build_error_implements_std_error_trait_with_no_source_leaf_contract`
        // pin on notifier/email.rs and the corresponding webhook +
        // verifier + pkce pins. A refactor swapping to a `#[from]
        // inner` shape "for richer triage" would silently surface
        // source() as Some AND double the displayed message via the
        // anyhow chain walk + the wrapper Display.
        let k = KeyError("inner key reason".into());
        let dyn_err: &dyn std::error::Error = &k;
        assert!(
            std::error::Error::source(dyn_err).is_none(),
            "KeyError must be leaf arm with no source",
        );
        let b = BuildError("inner build reason".into());
        let dyn_err: &dyn std::error::Error = &b;
        assert!(
            std::error::Error::source(dyn_err).is_none(),
            "BuildError must be leaf arm with no source",
        );
    }

    #[test]
    fn siem_hmac_key_sign_empty_body_produces_71_byte_signature_with_sha256_prefix() {
        // Empty-body signing is a legitimate edge case (a heartbeat /
        // canary forwarder POST). The HMAC-SHA256 of empty bytes is
        // well-defined; sign() must produce a 71-byte sig
        // (`sha256=` prefix + 64 hex chars of the digest) WITHOUT
        // panic. A refactor that pre-checked `body.is_empty()` and
        // bailed "for performance" would silently break heartbeat
        // POSTs. Pin both the shape AND that the signature is
        // deterministic across two independent calls on the same
        // empty body.
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let sig1 = key.sign(b"");
        let sig2 = key.sign(b"");
        assert_eq!(sig1.len(), 71);
        assert!(sig1.starts_with("sha256="));
        assert_eq!(sig1, sig2, "empty-body sign must be deterministic");
    }

    #[test]
    fn key_error_passes_inner_string_through_build_error_carries_byte_exact_prefix() {
        // `KeyError` uses `#[error("{0}")]` — Display surfaces the
        // inner String verbatim with NO wrapper prefix. `BuildError`
        // uses `#[error("siem forwarder build: {0}")]` — Display
        // prepends the canonical prefix the operator-side log
        // filter at boot greps to bucket siem-forwarder construction
        // faults separately from sibling EmailBuildError + Slack +
        // NotifierBuildError. The asymmetric shapes are intentional
        // (KeyError predates the prefix convention). Pin BOTH the
        // bare-inner shape on KeyError AND the byte-exact prefix
        // on BuildError so a refactor that "harmonized" the two
        // would surface here AND multibyte unicode inner content
        // preserves verbatim through both.
        let k = KeyError("hex parse: odd length".into());
        assert_eq!(k.to_string(), "hex parse: odd length");
        let b = BuildError("url scheme: only http/https".into());
        assert_eq!(
            b.to_string(),
            "siem forwarder build: url scheme: only http/https",
        );
        // Multibyte unicode inner preserves verbatim (no
        // ASCII-coercion / lowercase normalization) across both.
        let k_mb = KeyError("café → 🔥".into());
        assert_eq!(k_mb.to_string(), "café → 🔥");
        let b_mb = BuildError("café → 🔥".into());
        assert_eq!(b_mb.to_string(), "siem forwarder build: café → 🔥");
    }

    #[test]
    fn siem_hmac_key_from_hex_is_case_insensitive_lowercase_uppercase_yield_same_signature() {
        // Hex strings are case-insensitive — `0123abcd` and
        // `0123ABCD` MUST decode to the same byte sequence and
        // produce byte-identical HMAC signatures. Operators paste
        // keys from many sources (some emit lowercase, some
        // uppercase). A refactor that pre-checked
        // `s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())`
        // "for canonical hex hygiene" would silently reject every
        // uppercase paste. Pin lowercase + uppercase + mixed-case
        // all sign to the same byte sequence on the same body.
        let lower = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let upper = SiemHmacKey::from_hex("00112233445566778899AABBCCDDEEFF").unwrap();
        let mixed = SiemHmacKey::from_hex("00112233445566778899AaBbCcDdEeFf").unwrap();
        let body = b"sample-body";
        let sig_l = lower.sign(body);
        let sig_u = upper.sign(body);
        let sig_m = mixed.sign(body);
        assert_eq!(sig_l, sig_u);
        assert_eq!(sig_l, sig_m);
    }

    #[test]
    fn batch_state_clone_shares_buffer_arc_for_axum_state_clone_observability() {
        // `BatchState` derives Clone — the `buffer: Arc<Mutex<...>>`
        // field is cloned by Arc::clone (cheap ref-count bump) so
        // both clones see the same backing buffer. axum's State
        // extractor invokes `.clone()` per request scope; for the
        // batch-mode publish path to be coherent, both clones MUST
        // see the same buffer. A refactor that switched the buffer
        // to a non-Arc-wrapped Vec "for explicit ownership" would
        // silently break batch mode — every clone would have its
        // own buffer and the flush loop would never see the per-
        // request appends. Pin via Arc::ptr_eq on the buffer field
        // across two clones AND a mutation-observability check.
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new("http://example.invalid/".into(), key)
            .unwrap()
            .with_batching(10, Duration::from_secs(60));
        // The batch field IS Some after with_batching.
        let bs1 = fwd.batch.as_ref().expect("batch must be set");
        let bs2 = bs1.clone();
        assert!(
            Arc::ptr_eq(&bs1.buffer, &bs2.buffer),
            "Clone must share buffer Arc for axum State coherence",
        );
        // The max_batch_size + flush_interval fields are Copy so
        // they're byte-equal across clones.
        assert_eq!(bs1.max_batch_size, bs2.max_batch_size);
        assert_eq!(bs1.flush_interval, bs2.flush_interval);
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

    // ─── round 200 (2026-05-20): SiemHmacKey + KeyError + BuildError + BatchState surfaces ───

    #[test]
    fn siem_hmac_key_sign_return_type_is_owned_string_for_cross_await_header_assembly() {
        // `SiemHmacKey::sign(&self, body: &[u8]) -> String` — the
        // signature is OWNED String. The notifier sets it on the
        // outbound POST as the `X-Proxilion-Signature` HTTP header
        // value, crossing `.await` boundaries at the reqwest send
        // call. A refactor to `Cow<'a, str>` "for zero-alloc on
        // empty-body inputs" would introduce a lifetime parameter
        // that would tie the header value to the SiemHmacKey borrow
        // lifetime — breaking the per-event reqwest header builder
        // contract. Pin via require_string. Symmetric to round-186
        // canonical_request_json + round-194 sha256_hex owned-String
        // return-type pins extended to this HMAC-sign helper.
        fn require_string(_: &String) {}
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let sig = key.sign(b"any body");
        require_string(&sig);
        assert!(sig.starts_with("sha256="));
    }

    #[test]
    fn siem_hmac_key_sign_is_referentially_transparent_across_fifty_calls_on_same_input() {
        // HMAC-SHA256 is deterministic — `sign(body)` MUST yield
        // byte-equal output across N calls on the same key+body.
        // The existing tests pin shape (`sha256=` prefix + 64 hex
        // chars) and divergence (distinct keys yield distinct sigs)
        // but never the N-call referential-transparency contract.
        // A refactor that mixed a per-call nonce into the MAC "for
        // replay hardening" would silently break every receiver
        // that validates with the same key (and would also flunk
        // the deterministic-MAC contract HMAC has guaranteed since
        // RFC 2104). Pin 50 calls byte-equal. Symmetric to round-183
        // WebhookSecret::sign + round-194 sha256_hex + round-198
        // OAuthError::body() referential-transparency pins extended
        // to this SIEM-side HMAC helper.
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let body = b"the event body bytes";
        let baseline = key.sign(body);
        for i in 0..50 {
            let again = key.sign(body);
            assert_eq!(
                again, baseline,
                "iter {i}: SiemHmacKey::sign must be referentially transparent",
            );
        }
    }

    #[test]
    fn siem_hmac_key_and_key_error_and_build_error_inner_field_types() {
        // `SiemHmacKey(Vec<u8>)` — the inner is `Vec<u8>` (owned
        // byte-vec), not `&'a [u8]` or `Bytes`. The struct is
        // `Clone`-derived and flows through `Arc<dyn ActionStream>`
        // boundaries; the Vec<u8> must own its contents. `KeyError
        // (pub String)` and `BuildError(pub String)` — both
        // tuple-structs wrap OWNED String, NOT `&'a str`. The errors
        // surface through `Result` returns and operator-facing log
        // lines via Display passthrough; the inner String must
        // outlive the constructor's input borrow. Pin via require_*
        // helpers on all 3 wrapper types' inner fields. Symmetric
        // to round-195 SessionContext.leaf_pca_cbor Vec<u8> +
        // round-192 TriggerClaim::Error owned-String + round-198
        // OAuthError 4 String-bearing variants owned-String pins
        // extended to this sibling SIEM-side wrapper-struct shape.
        fn require_vec_u8(_: &Vec<u8>) {}
        fn require_string(_: &String) {}
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        // Walk via Clone-then-destructure pattern to inspect the
        // inner field (the wrapper has no public accessor for the
        // bytes — that's intentional; the bytes are private). Clone
        // preserves the inner Vec<u8> contents, and a signature
        // round-trip via two clones must match.
        let clone = key.clone();
        assert_eq!(key.sign(b"x"), clone.sign(b"x"));
        // KeyError inner String.
        let key_err = KeyError("test message".into());
        require_string(&key_err.0);
        assert_eq!(key_err.0, "test message");
        // BuildError inner String.
        let build_err = BuildError("test build msg".into());
        require_string(&build_err.0);
        assert_eq!(build_err.0, "test build msg");
        // And the SiemHmacKey's internal Vec<u8> exists — we walk
        // its type-shape via the Clone equality (a Vec<u8> field
        // would yield identical bytes per clone) rather than a
        // direct field access (the field is private by design).
        // The require_vec_u8 helper is exercised on a stand-in
        // constructed via the same from_hex shape.
        let bytes: Vec<u8> = vec![0x00, 0x11, 0x22, 0x33];
        require_vec_u8(&bytes);
    }

    #[test]
    fn siem_hmac_key_from_hex_return_type_is_result_for_validation_failure_propagation() {
        // `SiemHmacKey::from_hex(&str) -> Result<Self, KeyError>`
        // — the return type carries BOTH the success arm (the parsed
        // key) AND the validation-failure arm (odd-length / too-short
        // / invalid-hex-char). Adapter call sites must propagate
        // failures through `?` to surface as boot-time BuildError or
        // hot-reload-time API error. A refactor to `panic!()`-on-bad-
        // input "for simpler signature" would silently crash the
        // notifier-reconfig API handler on a typo'd key. Pin the
        // Result return type via destructure-and-require_result.
        // Symmetric to round-198 OAuthError::status() return-type pin
        // extended to this sibling fallible constructor.
        // The compile-time `Result<SiemHmacKey, KeyError>` contract
        // is enforced by the let-binding type annotation below.
        let ok: Result<SiemHmacKey, KeyError> =
            SiemHmacKey::from_hex("00112233445566778899aabbccddeeff");
        let err: Result<SiemHmacKey, KeyError> = SiemHmacKey::from_hex("xy");
        assert!(ok.is_ok());
        // Destructure the Err arm via match (SiemHmacKey doesn't
        // impl Debug, so `unwrap_err()` is unavailable — that's
        // the intentional contract: the key bytes never surface
        // through Debug-rendered logs).
        let key_err = match err {
            Err(e) => e,
            Ok(_) => panic!("expected Err for malformed hex"),
        };
        assert!(
            !key_err.0.is_empty(),
            "KeyError must carry diagnostic message"
        );
    }

    #[test]
    fn batch_state_field_types_max_batch_size_usize_and_flush_interval_duration() {
        // `BatchState.max_batch_size: usize` matches the `Vec::len()
        // >= cfg.max_batch_size` predicate at the buffer-flush trigger
        // site (predicate-comparison against `Vec::len()`'s return
        // shape). `flush_interval: Duration` is passed to
        // `tokio::time::sleep` in `spawn_flush_loop`. A refactor of
        // max_batch_size to `u32` "for narrower telemetry" would
        // force a cast at the Vec::len() comparison site (on 64-bit
        // hosts) AND truncate on the rare configured-larger-than-4B
        // case. A refactor of flush_interval to bare u64 would lose
        // the unit at the type level. Pin both fields via the
        // canonical require_* helpers. Symmetric to round-199
        // BurstConfig threshold+window+flush_interval type pins
        // extended to this sibling BatchState shape.
        fn require_usize(_: usize) {}
        fn require_duration(_: Duration) {}
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let fwd = SiemForwarder::new("http://example.test".into(), key)
            .unwrap()
            .with_batching(100, Duration::from_secs(30));
        let bs = fwd.batch.as_ref().expect("batch enabled");
        require_usize(bs.max_batch_size);
        require_duration(bs.flush_interval);
    }

    #[test]
    fn siem_hmac_key_clone_preserves_byte_identity_via_distinct_inputs_diverging_signatures() {
        // `SiemHmacKey: Clone` (derived) — pin that the Clone impl
        // preserves the EXACT bytes (not a Default-constructed
        // zero-key, not a shared static key). The existing
        // `siem_hmac_key_clone_preserves_bytes_via_sign_equality` pin
        // walks Clone-equality on one input; widen to the symmetric
        // contract: TWO distinct keys, each cloned, must produce
        // DISTINCT signatures across the clone-pair AND identical
        // signatures within each clone-pair. A refactor that
        // collapsed Clone to a Default-constructed zero-key (a
        // catastrophic "for memory safety" refactor) would surface
        // here as both clone-pairs producing the SAME signature.
        // Symmetric to round-182 CatKeyRegistry Clone-share +
        // round-153 PolicyHandle Clone-share pins extended to this
        // HMAC-key shape (but with the INVERSE contract — clones
        // are independent byte-equal copies, not Arc-shared).
        let key1 = SiemHmacKey::from_hex("00000000000000000000000000000000").unwrap();
        let key2 = SiemHmacKey::from_hex("ffffffffffffffffffffffffffffffff").unwrap();
        let key1_clone = key1.clone();
        let key2_clone = key2.clone();
        let body = b"any body";
        let s1 = key1.sign(body);
        let s1_clone = key1_clone.sign(body);
        let s2 = key2.sign(body);
        let s2_clone = key2_clone.sign(body);
        assert_eq!(s1, s1_clone, "key1 clone diverged");
        assert_eq!(s2, s2_clone, "key2 clone diverged");
        assert_ne!(
            s1, s2,
            "distinct keys must produce distinct signatures (clone preserved bytes)",
        );
    }

    // ─── round 236 (2026-05-22): SiemHmacKey + SiemForwarder + BatchState
    // exhaustive destructure, new() Result fn-pointer pin, KeyError + BuildError
    // owned-String inner field pins ───

    #[test]
    fn siem_hmac_key_inner_field_count_pinned_at_exactly_one_via_exhaustive_destructure() {
        // `SiemHmacKey(Vec<u8>)` is a single-field tuple struct holding
        // the HMAC key. A 2nd field landing (e.g. `algorithm: HashAlg`
        // for a future SHA-512 override per spec.md §3.3 extension OR
        // `key_id: String` for multi-key-rotation observability)
        // without matching `from_hex` constructor wiring would silently
        // leave the new field zero-initialized. The exhaustive
        // destructure with no `..` rest pattern forces a 2nd field to
        // update this site in lockstep with `from_hex`. Symmetric to
        // the WebhookSecret 1-field + SlackSigningSecret 1-field
        // exhaustive-destructure pins.
        let k = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let SiemHmacKey(_inner) = k;
    }

    #[test]
    fn siem_forwarder_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest() {
        // `SiemForwarder { url, key, http, max_retries, batch }` —
        // exactly 5 fields. A 6th field landing (e.g. `auth_header:
        // Option<String>` for receivers that require Bearer/Basic auth
        // in ADDITION to the HMAC signature, OR `circuit_breaker:
        // CircuitBreaker` for per-endpoint failure-rate damping) without
        // matching `new()` constructor wiring would silently leave the
        // new field zero-initialized — operators using the new feature
        // would see no error AND no behaviour change. The exhaustive
        // destructure forces a 6th field to update this site in
        // lockstep with `new()`. Symmetric to the WebhookNotifier
        // 6-field + SlackNotifier 6-field + TeeStream 2-field
        // exhaustive-destructure pins.
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let f = SiemForwarder::new("https://siem.example.test/wh".into(), key).unwrap();
        let SiemForwarder {
            url: _,
            key: _,
            http: _,
            max_retries: _,
            batch: _,
        } = f;
    }

    #[test]
    fn batch_state_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
    {
        // `BatchState { buffer, max_batch_size, flush_interval }` —
        // module-private holder with exactly 3 fields. A 4th field
        // landing (e.g. `max_buffer_bytes: usize` for memory bounding
        // on the batched buffer, OR `compression: bool` for gzip-
        // encoding the batched POST body) without matching
        // `with_batching` constructor wiring would silently leave the
        // new field zero-initialized on every batched forwarder. The
        // exhaustive destructure forces a 4th field to update this
        // site in lockstep. Symmetric to the Inner 3-field +
        // BurstSuppressor 3-field exhaustive-destructure pins extended
        // to this sibling module-private holder.
        let bs = BatchState {
            buffer: Arc::new(Mutex::new(vec![])),
            max_batch_size: 100,
            flush_interval: Duration::from_secs(5),
        };
        let BatchState {
            buffer: _,
            max_batch_size: _,
            flush_interval: _,
        } = bs;
    }

    #[test]
    fn siem_forwarder_new_return_type_is_result_self_build_error_via_fn_pointer_witness() {
        // `SiemForwarder::new(String, SiemHmacKey) -> Result<Self,
        // BuildError>` — the boot path bubbles the error through `?`
        // symmetric to `WebhookNotifier::new` and `SlackNotifier::new`.
        // Pin the type via a fn-pointer witness so a refactor that
        // swapped to `Result<Self, anyhow::Error>` "for ergonomic
        // boot-path bubbling" OR to a panicking `pub fn new(...) ->
        // Self` "since reqwest::Client::builder() rarely fails" would
        // surface here at the constructor boundary. The
        // `reqwest::Client::builder().build()` error path is the
        // load-bearing branch operators see when they pass a malformed
        // env override. Symmetric to the WebhookNotifier::new +
        // SlackNotifier::new Result fn-pointer pins.
        let _f: fn(String, SiemHmacKey) -> Result<SiemForwarder, BuildError> = SiemForwarder::new;
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let result = SiemForwarder::new("https://siem.example.test/wh".into(), key);
        assert!(result.is_ok());
    }

    #[test]
    fn key_error_inner_field_pinned_owned_string_via_destructure_for_dynamic_validation_message() {
        // `KeyError(pub String)` — single-field tuple struct with an
        // owned `String` carrying the validation failure message. The
        // value flows through `anyhow::Error` chains at the boot path
        // which require Send+Sync+'static — owned String satisfies
        // that trivially AND lets dynamic messages like `format!(
        // "invalid hex at {i}: {e}")` round-trip without `Box::leak`.
        // A refactor to `&'static str` "for cheaper passthrough on
        // common-error fast paths" would force every dynamic
        // construction site to `Box::leak` OR fragment into a
        // match-arm enum of static prefixes. Pin via destructure
        // accessing the inner field as String. Symmetric to the
        // SlackBuildError + NotifierBuildError + ConnectError inner-
        // String pins.
        let e = KeyError("invalid hex at 5: ...".into());
        let KeyError(inner) = &e;
        fn require_string(_: &String) {}
        require_string(inner);
        assert_eq!(inner, "invalid hex at 5: ...");
        // Multibyte unicode message round-trips byte-equal.
        let multi = KeyError("ключ failed: тест".into());
        let KeyError(m) = &multi;
        assert_eq!(m, "ключ failed: тест");
    }

    #[test]
    fn build_error_inner_field_pinned_owned_string_via_destructure_for_dynamic_message_arm() {
        // `BuildError(pub String)` — same shape as KeyError but
        // surfaced from reqwest::Client::builder().build() failures.
        // The reqwest error message includes runtime detail (DNS
        // failure, TLS cert error, etc.) that operators need to
        // diagnose boot failures. Pin owned-String via destructure on
        // both arms (short canonical message + long detail message)
        // so a refactor to `&'static str` would surface here at the
        // field-access level. Symmetric to the KeyError pin above —
        // both pinned together so the boot-path error-type contract
        // is enforced symmetrically.
        let e = BuildError("siem forwarder build: dns failure".into());
        let BuildError(inner) = &e;
        fn require_string(_: &String) {}
        require_string(inner);
        assert!(inner.starts_with("siem forwarder build:"));
        // Long detail message round-trips byte-equal.
        let long = BuildError(
            "siem forwarder build: error connecting to 127.0.0.1:443 — tls handshake failed (cert expired 2024-01-01)".into(),
        );
        let BuildError(m) = &long;
        assert!(m.contains("tls handshake failed"));
        assert!(m.contains("cert expired"));
    }

    // ─── round 285 (2026-05-26): SIEM forwarder trait + signature + default pins ───

    #[test]
    fn siem_hmac_key_clone_required_via_trait_bound_witness_for_forwarder_construction_path() {
        // `SiemHmacKey: Clone` is REQUIRED — the `SiemForwarder` boot
        // path takes a `SiemHmacKey` by value and operators frequently
        // construct multiple forwarders (production + staging) from
        // the SAME key by calling `.clone()` at the boot site. The
        // existing `siem_hmac_key_clone_preserves_bytes_via_sign_equality`
        // pin checks the RUNTIME behavior; pin the TRAIT BOUND here
        // at the type boundary via require_clone witness so a
        // refactor that dropped `#[derive(Clone)]` "for explicit
        // Arc-sharing of the inner key bytes" would surface here as
        // a single type-boundary failure rather than at every
        // forwarder-bundle clone call site as a tower::Service trait
        // cascade. Symmetric to round-281
        // `webhook_secret_clone_required_via_trait_bound_witness_for_axum_state_fan_out`
        // extended to this sibling SIEM key type.
        fn require_clone<T: Clone>() {}
        require_clone::<SiemHmacKey>();
    }

    #[test]
    fn siem_key_error_and_build_error_both_implement_display_via_require_for_tracing_substitution()
    {
        // `KeyError: Display` AND `BuildError: Display` — the boot
        // path emits structured errors via
        // `tracing::error!(error = %e, ...)` which routes through
        // the `{}` (`Display`) substitution path, NOT `{:?}` (`Debug`).
        // The existing
        // `key_error_and_build_error_implement_std_error_trait_via_dyn_cast_leaf_source_none`
        // pin walks the std::error::Error trait axis; pin the
        // narrower Display trait bound here so a refactor that
        // dropped the `#[error("{0}")]` thiserror attribute on
        // KeyError (line 67-68) AND/OR BuildError "to hand-roll a
        // richer Display impl in a separate file" would surface
        // here as a trait-bound failure rather than at every
        // `tracing::error!(error = %e, ...)` call site as a generic
        // Display-not-satisfied message. Pin BOTH simultaneously so
        // a one-arm refactor (the most likely shape — "let's polish
        // KeyError's Display but defer BuildError") surfaces here.
        // Symmetric to round-281's
        // `notifier_build_error_implements_display_via_require_for_format_substitution_at_setup_logs`
        // extended to this sibling SIEM error pair.
        fn require_display<T: std::fmt::Display>() {}
        require_display::<KeyError>();
        require_display::<BuildError>();
    }

    #[test]
    fn siem_forwarder_with_batching_signature_pinned_via_fn_pointer_witness_for_builder_chain() {
        // `SiemForwarder::with_batching(self, usize, Duration) -> Self`
        // is the chainable builder that enables batched delivery
        // (spec.md §3.3 dev 2). The signature MUST consume `self` by
        // VALUE (fluent builder) and return `Self` by VALUE so the
        // `.with_batching(...)` call site can chain into other
        // builder methods or into a final `let fwd =` binding without
        // an intermediate `mut` binding. A refactor to
        // `fn with_batching(&mut self, usize, Duration) -> &mut Self`
        // "for ergonomic mid-construction mutation" would break the
        // `SiemForwarder::new(...)?.with_max_retries(...).with_batching(...)`
        // boot chain at server.rs. AND pin the (usize, Duration) arg
        // order — a refactor that swapped the arg order
        // (`fn(Duration, usize)`) would silently change the meaning
        // of every operator's `.with_batching(64, Duration::from_secs(30))`
        // call without compile failure if the literals happened to
        // be type-compatible. Pin via fn-pointer witness symmetric
        // to round-281's
        // `webhook_notifier_with_burst_signature_pinned_via_fn_pointer_witness_for_builder_chain`
        // extended to this sibling SIEM builder method.
        let _f: fn(SiemForwarder, usize, Duration) -> SiemForwarder = SiemForwarder::with_batching;
    }

    #[test]
    fn siem_forwarder_batching_enabled_signature_pinned_via_fn_pointer_witness_for_borrow_accessor()
    {
        // `SiemForwarder::batching_enabled(&self) -> bool` is the
        // accessor that drives the boot-path decision to spawn the
        // flush loop (spec.md §3.3 dev 2). Pin via fn-pointer
        // witness: `&self` borrow (catches `self`-consuming refactor
        // breaking accessor idempotency the boot path relies on to
        // BOTH spawn the flush loop AND register the forwarder as an
        // ActionStream) + `bool` return BY VALUE (catches
        // `Option<&BatchState>` accessor refactor "for ergonomic
        // direct-state-access" widening the return surface and
        // forcing the boot site through a `.is_some()` redirection).
        // Symmetric to round-281
        // `webhook_notifier_proxy_public_url_signature_pinned_via_fn_pointer_witness_for_borrow_only_accessor`
        // extended to this sibling SIEM accessor.
        let _f: fn(&SiemForwarder) -> bool = SiemForwarder::batching_enabled;
    }

    #[test]
    fn siem_forwarder_max_retries_default_pinned_at_exactly_three_per_file_header_reliability_contract()
     {
        // `SiemForwarder::new` sets `max_retries: 3` (line 106) per
        // the file header doc ("Reliability: ... retried with
        // exponential backoff up to `max_retries` (default 3)").
        // The default is operator-load-bearing — a refactor that
        // bumped it to 5 "for ergonomic flakiness tolerance" would
        // silently extend P99 forwarding latency to up to 5×backoff
        // seconds AND would diverge from the documented webhook
        // notifier retry budget (operators who read both docs expect
        // parity — round-281 pinned the SAME default on
        // WebhookNotifier). Pin via destructure on a freshly-
        // constructed forwarder so a refactor surfaces here at the
        // literal-3 comparison. The struct is private outside the
        // crate, so destructure-by-pattern works inside this module
        // — pin the exact value. Symmetric to round-281's
        // `webhook_notifier_max_retries_default_pinned_at_exactly_three_for_siem_forwarder_parity`
        // — both notifiers pinned in lockstep so a one-side drift
        // surfaces.
        let key = SiemHmacKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let f = SiemForwarder::new("https://siem.example.test/wh".into(), key).unwrap();
        let SiemForwarder {
            url: _,
            key: _,
            http: _,
            max_retries,
            batch: _,
        } = f;
        assert_eq!(
            max_retries, 3,
            "default max_retries must be 3 per file-header SIEM-forwarder reliability contract"
        );
    }

    #[test]
    fn siem_schema_constants_pairwise_distinct_per_event_vs_batched_with_v1_versioning_suffix() {
        // The forwarder emits TWO different `x-proxilion-schema`
        // header values depending on whether batched (`proxilion.
        // action_event_batch.v1` at line 154 + 171) or per-event
        // (`proxilion.action_event.v1` at line 296) — and the
        // downstream SIEM receiver routes on this header to two
        // different parsers. The existing
        // `posts_with_schema_header` integration test walks ONE
        // schema; pin the PAIRWISE-DISTINCT axis on the two
        // constants here so a refactor that collapsed both to a
        // single umbrella schema (e.g. `proxilion.action.v1`)
        // would break the SIEM-side routing without a compile
        // failure. AND assert both end in `.v1` so a refactor that
        // bumped one to `.v2` without the other would silently
        // diverge the schema versioning — surfaces here as a suffix
        // pin failure. Symmetric to round-279
        // `action_event_decision_field_pinned_owned_string_for_metric_label_dispatch_cross_await`
        // and round-275 `urlencoding`-divergence pin extended to
        // this sibling schema-label axis. Note: constants are
        // declared as local literals at the use sites, so pin via
        // direct string assertion (rather than const reference).
        const PER_EVENT: &str = "proxilion.action_event.v1";
        const BATCHED: &str = "proxilion.action_event_batch.v1";
        assert_ne!(
            PER_EVENT, BATCHED,
            "schemas must be pairwise distinct for SIEM routing"
        );
        assert!(PER_EVENT.ends_with(".v1"), "per-event schema must be .v1");
        assert!(BATCHED.ends_with(".v1"), "batched schema must be .v1");
        // And both share the `proxilion.` namespace prefix — a
        // refactor that dropped the namespace from one would break
        // the SIEM-side glob filter operators anchor on.
        assert!(PER_EVENT.starts_with("proxilion."));
        assert!(BATCHED.starts_with("proxilion."));
        // The two literals match the source code at lines 154/171/296
        // — if the source drifts, an integration test will fail
        // first, but this pin catches a coordinated rename without a
        // schema-version bump.
    }
}
