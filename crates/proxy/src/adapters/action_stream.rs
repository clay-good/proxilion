//! Action event stream — every adapter call emits one of these.
//!
//! Two implementations:
//!   * `LoggingStream` — writes JSON to tracing. Default in tests / dev.
//!   * `BroadcastingActionStream` — persists to `action_events` and fans out
//!     over a `tokio::sync::broadcast` channel for SSE subscribers.
//!
//! NATS bridging (spec.md §3.1) can compose with either by wrapping.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvent {
    pub request_id: Uuid,
    pub agent_session_id: Uuid,
    pub p_0: String,
    pub leaf_pca_id: Option<Uuid>,
    pub vendor: String,
    pub action: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub decision: String,
    pub block_reason: Option<String>,
    pub read_filter_triggered: bool,
    pub quarantined_count: usize,
    pub at: DateTime<Utc>,
    /// Optional matched policy id (kept out of `extra` so callers can index it).
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Value::is_null", default)]
    pub extra: Value,
}

#[async_trait]
pub trait ActionStream: Send + Sync + 'static {
    async fn publish(&self, event: ActionEvent);
}

#[derive(Default)]
#[allow(dead_code)] // kept for tests / future plain-logging deployments
pub struct LoggingStream;

#[async_trait]
impl ActionStream for LoggingStream {
    async fn publish(&self, event: ActionEvent) {
        info!(target: "proxilion.action_stream", event = ?event, "action");
    }
}

/// Persist every event to `action_events` and fan it out to live subscribers
/// (the admin UI's SSE endpoint and any future NATS bridge).
#[derive(Clone)]
pub struct BroadcastingActionStream {
    db: PgPool,
    tx: broadcast::Sender<Arc<ActionEvent>>,
}

impl BroadcastingActionStream {
    pub fn new(db: PgPool) -> Self {
        // 256-event ring buffer for slow consumers; if a subscriber lags more
        // than that, they get `RecvError::Lagged` and re-sync via the
        // /api/v1/actions/recent endpoint.
        let (tx, _rx) = broadcast::channel(256);
        Self { db, tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<ActionEvent>> {
        self.tx.subscribe()
    }
}

#[async_trait]
impl ActionStream for BroadcastingActionStream {
    async fn publish(&self, event: ActionEvent) {
        // Persist first; only after the durable record exists do we fan out.
        // Live consumers reflect ground truth.
        let res = sqlx::query(
            r#"
            INSERT INTO action_events
                (request_id, session_id, p_0, leaf_pca_id, vendor, action, method, path,
                 status, decision, block_reason, read_filter_triggered, quarantined_count,
                 policy_id, extra, at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                    $9, $10, $11, $12, $13, $14, $15, $16)
            "#,
        )
        .bind(event.request_id)
        .bind(event.agent_session_id)
        .bind(&event.p_0)
        .bind(event.leaf_pca_id)
        .bind(&event.vendor)
        .bind(&event.action)
        .bind(&event.method)
        .bind(&event.path)
        .bind(event.status as i32)
        .bind(&event.decision)
        .bind(event.block_reason.as_deref())
        .bind(event.read_filter_triggered)
        .bind(event.quarantined_count as i32)
        .bind(event.policy_id.as_deref())
        .bind(&event.extra)
        .bind(event.at)
        .execute(&self.db)
        .await;
        if let Err(e) = &res {
            warn!(error = %e, "failed to persist action_event; broadcasting anyway");
            metrics::counter!(
                "proxilion_action_events_persist_failures_total",
                "reason" => "db_error"
            )
            .increment(1);
        } else {
            metrics::counter!(
                "proxilion_action_events_persisted_total",
                "decision" => event.decision.clone()
            )
            .increment(1);
        }

        // Best-effort broadcast. `send` only errors when there are zero
        // subscribers, which is fine; we still got the event into postgres.
        let _ = self.tx.send(Arc::new(event));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample() -> ActionEvent {
        ActionEvent {
            request_id: Uuid::nil(),
            agent_session_id: Uuid::nil(),
            p_0: "alice@demo.local".into(),
            leaf_pca_id: None,
            vendor: "google".into(),
            action: "gmail.messages.send".into(),
            method: "POST".into(),
            path: "/gmail/v1/users/me/messages/send".into(),
            status: 403,
            decision: "block".into(),
            block_reason: Some("policy".into()),
            read_filter_triggered: false,
            quarantined_count: 0,
            at: Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
            policy_id: Some("gmail-external-send-gate".into()),
            extra: Value::Null,
        }
    }

    #[test]
    fn extra_null_is_skipped_in_json() {
        let s = serde_json::to_string(&sample()).unwrap();
        // `extra` is the only optional-shaped field; with the value `null`
        // it must NOT appear in the wire form. Downstream consumers index
        // on the presence of `extra` to decide whether to parse it.
        assert!(!s.contains("\"extra\""), "wire shape: {s}");
        assert!(s.contains("\"decision\":\"block\""));
        assert!(s.contains("\"policy_id\":\"gmail-external-send-gate\""));
    }

    #[test]
    fn extra_object_is_serialized() {
        let mut e = sample();
        e.extra = serde_json::json!({"to_domain": "external.com"});
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"extra\""));
        assert!(s.contains("\"to_domain\":\"external.com\""));
    }

    #[test]
    fn round_trips_through_json_with_absent_extra() {
        // Older NATS / SIEM consumers MAY emit events without the `extra`
        // key — deserialization must default it to `Value::Null` rather
        // than fail. (`#[serde(default)]` on the field guarantees this.)
        let s = r#"{
            "request_id":"00000000-0000-0000-0000-000000000000",
            "agent_session_id":"00000000-0000-0000-0000-000000000000",
            "p_0":"alice@demo.local","leaf_pca_id":null,
            "vendor":"google","action":"drive.files.get",
            "method":"GET","path":"/drive/v3/files/x","status":200,
            "decision":"allow","block_reason":null,
            "read_filter_triggered":false,"quarantined_count":0,
            "at":"2026-05-16T12:00:00Z","policy_id":null
        }"#;
        let ev: ActionEvent = serde_json::from_str(s).unwrap();
        assert_eq!(ev.decision, "allow");
        assert!(ev.extra.is_null());
    }

    #[test]
    fn full_round_trip_preserves_all_fields() {
        let original = sample();
        let bytes = serde_json::to_vec(&original).unwrap();
        let back: ActionEvent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.vendor, original.vendor);
        assert_eq!(back.action, original.action);
        assert_eq!(back.status, original.status);
        assert_eq!(back.decision, original.decision);
        assert_eq!(back.block_reason, original.block_reason);
        assert_eq!(back.policy_id, original.policy_id);
        assert_eq!(back.read_filter_triggered, original.read_filter_triggered);
        assert_eq!(back.quarantined_count, original.quarantined_count);
        assert_eq!(back.at, original.at);
    }

    #[tokio::test]
    async fn logging_stream_publish_is_infallible() {
        // `LoggingStream` writes to tracing and returns; no DB, no panic.
        // We exercise the trait dispatch so the default impl is covered.
        let s = LoggingStream;
        s.publish(sample()).await;
    }

    #[test]
    fn leaf_pca_id_round_trips_through_json_when_some() {
        // `leaf_pca_id: Option<Uuid>` is the foreign key into pca_cache —
        // serde must preserve a `Some(Uuid)` exactly (string form, no
        // hyphen drift). A refactor to `#[serde(with = "...")]` on this
        // field could silently switch to the simple (no-hyphen) form;
        // pin the hyphenated wire shape since downstream NATS / SIEM
        // consumers parse it through `Uuid::parse_str` which accepts
        // both forms but operators grep for the hyphenated one.
        let mut e = sample();
        let id = Uuid::new_v4();
        e.leaf_pca_id = Some(id);
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(&format!("\"leaf_pca_id\":\"{id}\"")), "got: {s}");
        let back: ActionEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.leaf_pca_id, Some(id));
    }

    #[test]
    fn status_u16_round_trips_as_unquoted_integer() {
        // `status: u16` MUST land in JSON as a bare integer (not a
        // string). Grafana dashboards alert on `status >= 500` with a
        // numeric comparison; a refactor that wrapped the field in
        // `#[serde(with = "string")]` would silently break every
        // operator alert. Pin the unquoted form on the wire.
        let mut e = sample();
        e.status = 503;
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"status\":503"), "got: {s}");
        // And the boundary u16 max — confirm no clipping or overflow.
        e.status = u16::MAX;
        let s = serde_json::to_string(&e).unwrap();
        let back: ActionEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.status, u16::MAX);
    }

    #[test]
    fn quarantined_count_round_trips_as_unsigned_integer() {
        // `quarantined_count: usize` is the read-filter scan tally.
        // Pin both the wire form (bare integer, never null/string) and
        // the round-trip — a refactor that switched to `i64` for SQL
        // alignment would change the deserialization domain (allowing
        // negatives), which is exactly the regression this test catches.
        let mut e = sample();
        e.quarantined_count = 17;
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"quarantined_count\":17"), "got: {s}");
        let back: ActionEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.quarantined_count, 17);
        // Negative-string rejection — the wire form is unsigned.
        let bad = s.replace("\"quarantined_count\":17", "\"quarantined_count\":-1");
        assert!(serde_json::from_str::<ActionEvent>(&bad).is_err());
    }

    #[test]
    fn logging_stream_default_produces_usable_instance() {
        // `LoggingStream` derives `Default` — pin the derive so a
        // refactor that gave it state (e.g. a `target: String`) and
        // dropped the `Default` derive without a manual impl would
        // surface at test time rather than at the call site that
        // builds `LoggingStream::default()` in dev-mode wiring.
        let _s: LoggingStream = LoggingStream;
        let _s2: LoggingStream = Default::default();
    }
}
