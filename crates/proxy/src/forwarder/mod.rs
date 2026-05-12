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
