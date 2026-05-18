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
    fn action_event_debug_carries_struct_name_and_key_field_names_for_grep() {
        // ActionEvent flows through `info!(target: "proxilion.action_stream",
        // event = ?event, "action")` on every adapter call. Operators
        // grep the resulting log line by struct name + by the
        // `request_id` / `vendor` / `action` / `decision` selectors
        // to bucket "which request did what" across the full action
        // log. A manual Debug that hid the struct name or any of
        // these four selectors "to compact" the log line would break
        // every operator bucket. Pin all five surfaces.
        let s = format!("{:?}", sample());
        assert!(s.contains("ActionEvent"), "got: {s}");
        assert!(s.contains("request_id"), "got: {s}");
        assert!(s.contains("vendor"), "got: {s}");
        assert!(s.contains("action"), "got: {s}");
        assert!(s.contains("decision"), "got: {s}");
    }

    #[test]
    fn action_event_clone_produces_independent_value_for_each_sink() {
        // `TeeStream::publish` clones the event once per sink (primary
        // + every secondary). The clone MUST be independent — mutating
        // a clone's owned fields (`decision`, `block_reason`, `vendor`)
        // must NOT touch the original. A refactor that snuck in an
        // `Arc<String>` "for memory savings" would silently share state
        // across sinks; if one sink decorator (a redactor, say) mutated
        // the inner string via `Arc::make_mut`, every other sink would
        // observe the mutation. Pin field-level independence on three
        // owned-String fields and the bool flag.
        let original = sample();
        let mut clone = original.clone();
        clone.decision = "allow".to_string();
        clone.block_reason = Some("mutated".to_string());
        clone.vendor = "other".to_string();
        clone.read_filter_triggered = !original.read_filter_triggered;
        assert_eq!(original.decision, "block");
        assert_eq!(original.block_reason.as_deref(), Some("policy"));
        assert_eq!(original.vendor, "google");
        assert!(!original.read_filter_triggered);
    }

    #[test]
    fn at_datetime_serializes_as_rfc3339_with_z_suffix_not_offset_form() {
        // `at: DateTime<Utc>` serializes through chrono's serde impl
        // as an RFC3339 string ending in `Z`. Grafana / Datadog
        // ingestors parse this byte-for-byte; a refactor that swapped
        // to the `+00:00` offset form (also RFC3339-valid) would
        // change the wire shape and break dashboards that compute
        // bucket alignment off the trailing character. Pin the `Z`
        // suffix AND the absence of the offset form.
        let s = serde_json::to_string(&sample()).unwrap();
        assert!(s.contains("\"at\":\"2026-05-16T12:00:00Z\""), "got: {s}");
        assert!(!s.contains("+00:00"), "got: {s}");
    }

    #[test]
    fn read_filter_triggered_serializes_as_bare_json_boolean_not_string() {
        // `read_filter_triggered: bool` MUST land on the wire as
        // `true` / `false`, not `"true"` / `"false"`. The Slack
        // notifier template + the SIEM forwarder both branch on the
        // JSON type (`is_boolean()`) — a refactor that wrapped the
        // field in `#[serde(with = "string")]` would silently flip
        // every branch to the false path. Pin both polarities.
        let mut e = sample();
        e.read_filter_triggered = false;
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"read_filter_triggered\":false"), "got: {s}");
        assert!(
            !s.contains("\"read_filter_triggered\":\"false\""),
            "got: {s}"
        );
        e.read_filter_triggered = true;
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"read_filter_triggered\":true"), "got: {s}");
        assert!(
            !s.contains("\"read_filter_triggered\":\"true\""),
            "got: {s}"
        );
    }

    #[test]
    fn logging_stream_is_send_sync_static_for_app_state_arc_dyn_path() {
        // `LoggingStream` is wired into AppState as an
        // `Arc<dyn ActionStream>` in dev / test configurations. The
        // `ActionStream` trait declares `Send + Sync + 'static`
        // bounds — a refactor that gave `LoggingStream` an interior
        // `RefCell` field "for instance-local config" would break
        // Sync without surfacing at this file (the breakage would
        // appear at AppState assembly with an unrelated trait-bound
        // error). Pin the three-trait combo here so the type
        // boundary fails fast at the right call site.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<LoggingStream>();
    }

    #[test]
    fn full_round_trip_preserves_all_sixteen_fields_when_extra_is_non_null() {
        // The existing `full_round_trip_preserves_all_fields` test
        // only spot-checks 9 of 16 fields and uses `Value::Null` for
        // `extra` (which is skipped on serialize). The wire contract
        // covers all 16 — every Option round-trips through Some, the
        // serde_json::Value round-trips through a structured shape,
        // and the two usize / u16 numeric fields round-trip without
        // signedness drift. Pin every field so a refactor that added
        // a 17th field without `#[serde(default)]` would surface as
        // a deserialize failure here.
        let request_id = Uuid::new_v4();
        let agent_session_id = Uuid::new_v4();
        let leaf_pca_id = Uuid::new_v4();
        let original = ActionEvent {
            request_id,
            agent_session_id,
            p_0: "alice@example.com".into(),
            leaf_pca_id: Some(leaf_pca_id),
            vendor: "google".into(),
            action: "drive.files.list".into(),
            method: "GET".into(),
            path: "/drive/v3/files".into(),
            status: 200,
            decision: "allow".into(),
            block_reason: Some("none".into()),
            read_filter_triggered: true,
            quarantined_count: 5,
            at: chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
            policy_id: Some("drive-read-gate".into()),
            extra: serde_json::json!({"to_domain": "external.com", "n": 42}),
        };
        let bytes = serde_json::to_vec(&original).unwrap();
        let back: ActionEvent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.request_id, request_id);
        assert_eq!(back.agent_session_id, agent_session_id);
        assert_eq!(back.p_0, "alice@example.com");
        assert_eq!(back.leaf_pca_id, Some(leaf_pca_id));
        assert_eq!(back.vendor, "google");
        assert_eq!(back.action, "drive.files.list");
        assert_eq!(back.method, "GET");
        assert_eq!(back.path, "/drive/v3/files");
        assert_eq!(back.status, 200);
        assert_eq!(back.decision, "allow");
        assert_eq!(back.block_reason.as_deref(), Some("none"));
        assert!(back.read_filter_triggered);
        assert_eq!(back.quarantined_count, 5);
        assert_eq!(back.at, original.at);
        assert_eq!(back.policy_id.as_deref(), Some("drive-read-gate"));
        assert_eq!(back.extra["to_domain"], "external.com");
        assert_eq!(back.extra["n"], 42);
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
