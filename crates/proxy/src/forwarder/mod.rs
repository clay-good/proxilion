//! Action-stream sinks (spec.md §3.1 NATS bridge, §3.3 SIEM webhook).
//!
//! Composable: the adapter publishes to one `ActionStream`; in production
//! that stream is a `TeeStream` fanning out to a primary
//! `BroadcastingActionStream` (DB + SSE), plus any optional NATS / SIEM
//! sinks. Each sink is best-effort and isolated — one sink's failure does
//! not affect the others, and the durable record (in `action_events`) is
//! already persisted by the primary before fan-out runs.

pub mod nats;
pub mod siem;
pub mod tee;

pub use nats::NatsBridge;
pub use siem::{SiemForwarder, SiemHmacKey};
pub use tee::TeeStream;

/// Whether a 4xx upstream status is *retryable* rather than permanent
/// (surface-delight-and-correctness.md §6.5). Most 4xx are permanent — the
/// request is malformed or unauthorized and replaying won't help. But
/// `429 Too Many Requests` (Slack, PagerDuty, Datadog, Splunk HEC all
/// rate-limit with it) and `408 Request Timeout` are transient: under load,
/// treating them as permanent silently drops deliverable audit / notification
/// events exactly when volume is highest. Callers fold a `true` here into their
/// 5xx retry branch. Shared by the SIEM forwarder and the webhook notifier so
/// both honor the same retry contract.
pub(crate) fn is_retryable_4xx(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429)
}
