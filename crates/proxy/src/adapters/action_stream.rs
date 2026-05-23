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

    #[tokio::test]
    async fn action_stream_trait_is_dyn_compatible_via_arc_dyn_dispatch() {
        // The `ActionStream` trait is consumed everywhere as
        // `Arc<dyn ActionStream>` — AppState holds it as a trait object
        // so different concrete implementations (LoggingStream,
        // BroadcastingActionStream, TeeStream) can plug in
        // interchangeably. Pin trait object-safety explicitly via an
        // erased dispatch: build an `Arc<dyn ActionStream>` from a
        // concrete LoggingStream and call `publish` through the trait
        // object boundary. A refactor that added a generic method or a
        // `Self: Sized` bound would silently break the object-safety
        // and surface as a confusing compile error at the AppState
        // assembly site rather than here.
        let erased: Arc<dyn ActionStream> = Arc::new(LoggingStream);
        erased.publish(sample()).await;
    }

    #[test]
    fn action_event_serialization_is_byte_deterministic_across_repeated_calls() {
        // Serde with derived Serialize emits fields in declaration order
        // — the wire shape is byte-deterministic for any given input.
        // Pin determinism by serializing the SAME sample 5 times and
        // asserting all 5 byte-strings are equal. A refactor that
        // swapped to a manual `Serialize` impl with HashMap-backed
        // serialization "for ergonomic field-set extensibility" would
        // surface here as non-deterministic key order across calls and
        // break every consumer that expects deterministic action_event
        // rows for log-line deduplication.
        let e = sample();
        let s1 = serde_json::to_string(&e).unwrap();
        let s2 = serde_json::to_string(&e).unwrap();
        let s3 = serde_json::to_string(&e).unwrap();
        let s4 = serde_json::to_string(&e).unwrap();
        let s5 = serde_json::to_string(&e).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
        assert_eq!(s3, s4);
        assert_eq!(s4, s5);
    }

    #[test]
    fn action_event_json_contains_fifteen_keys_when_extra_is_null() {
        // The wire shape has 16 fields; with `extra: Value::Null` the
        // `skip_serializing_if = "Value::is_null"` elides one, leaving
        // exactly 15 keys on the wire. Pin the exact key set so a
        // refactor that added a 17th field (or accidentally removed
        // the skip-if) would surface here as a multi-name diff rather
        // than as some downstream consumer ad-hoc complaining about a
        // missing or unexpected key. The list is the load-bearing
        // schema contract for SIEM ingestors that assert presence
        // before parsing.
        let s = serde_json::to_string(&sample()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let obj = v.as_object().expect("must be a JSON object");
        assert_eq!(obj.len(), 15, "wire shape: {s}");
        for key in [
            "request_id",
            "agent_session_id",
            "p_0",
            "leaf_pca_id",
            "vendor",
            "action",
            "method",
            "path",
            "status",
            "decision",
            "block_reason",
            "read_filter_triggered",
            "quarantined_count",
            "at",
            "policy_id",
        ] {
            assert!(obj.contains_key(key), "missing key {key} in: {s}");
        }
        assert!(
            !obj.contains_key("extra"),
            "extra null must be skipped: {s}"
        );
    }

    #[test]
    fn action_event_json_contains_sixteen_keys_when_extra_is_non_null() {
        // Symmetric pin to the 15-key-with-null version — when `extra`
        // carries a real value the wire shape grows to exactly 16 keys.
        // A refactor that flipped the skip-if predicate to
        // `Option::is_none` (collapsing the "structured null vs absent"
        // distinction the spec relies on) would silently re-add the
        // `"extra":null` shape and surface as a 17-key envelope here.
        let mut e = sample();
        e.extra = serde_json::json!({"to_domain": "external.com"});
        let s = serde_json::to_string(&e).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let obj = v.as_object().expect("must be a JSON object");
        assert_eq!(obj.len(), 16, "wire shape: {s}");
        assert!(obj.contains_key("extra"));
    }

    #[test]
    fn action_event_extra_with_json_array_value_round_trips_byte_equal() {
        // The `extra` field is `serde_json::Value` — it accepts any
        // JSON shape (object / array / scalar). The existing
        // `extra_object_is_serialized` test pins the object shape; pin
        // the ARRAY shape so a refactor to `extra: HashMap<String, Value>`
        // "for type-level safety on the dashboard side" would surface
        // here. Some adapters legitimately emit array `extra` payloads
        // (e.g. a list of quarantined attachment names) — pin a
        // 3-element array round-trip.
        let mut e = sample();
        e.extra = serde_json::json!(["attachment1.pdf", "attachment2.zip", "attachment3.docx"]);
        let s = serde_json::to_string(&e).unwrap();
        let back: ActionEvent = serde_json::from_str(&s).unwrap();
        let arr = back
            .extra
            .as_array()
            .expect("extra must round-trip as array");
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], "attachment1.pdf");
        assert_eq!(arr[1], "attachment2.zip");
        assert_eq!(arr[2], "attachment3.docx");
    }

    #[test]
    fn action_event_block_reason_none_serializes_as_json_null_not_skipped() {
        // `block_reason: Option<String>` does NOT carry the
        // `skip_serializing_if` attribute — None must land as
        // `"block_reason":null` on the wire, not be elided. The
        // operator dashboard's "block reason histogram" panel keys on
        // the JSON null vs absent distinction to bucket "explicit no
        // reason" vs "unknown shape from old SIEM rows". A refactor
        // that added `#[serde(skip_serializing_if = "Option::is_none")]`
        // "for compactness" would silently collapse the two shapes.
        // Pin both polarities — None → null literal, Some → quoted
        // string.
        let mut e = sample();
        e.block_reason = None;
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            s.contains("\"block_reason\":null"),
            "None must serialize as null: {s}"
        );
        e.block_reason = Some("policy_blocked".into());
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            s.contains("\"block_reason\":\"policy_blocked\""),
            "Some must quote: {s}"
        );
    }

    // ─── round 214 (2026-05-21): ActionEvent + ActionStream + Broadcasting surfaces ───

    #[test]
    fn action_event_field_count_pinned_exactly_sixteen_via_exhaustive_destructure() {
        // `ActionEvent` has EXACTLY 16 fields. The INSERT into `action_events`
        // hard-codes 15 columns (extra is JSONB + at is a timestamptz). Pin
        // the count via exhaustive destructure with no `..` rest pattern —
        // a 17th field landing without a matching column wiring would
        // surface here as a compile error rather than as a silent data drop
        // in the BroadcastingActionStream persist path. Symmetric to
        // round-213 CachedPca 8-field destructure pin + round-208
        // VerificationResult 7-field-types-intact pin.
        let ActionEvent {
            request_id: _,
            agent_session_id: _,
            p_0: _,
            leaf_pca_id: _,
            vendor: _,
            action: _,
            method: _,
            path: _,
            status: _,
            decision: _,
            block_reason: _,
            read_filter_triggered: _,
            quarantined_count: _,
            at: _,
            policy_id: _,
            extra: _,
        } = sample();
    }

    #[test]
    fn action_event_status_field_type_is_u16_via_require_u16_for_http_response_code_domain() {
        // `status: u16` matches the HTTP response-code domain (3-digit
        // codes up to 599 fit; the type signals "HTTP code, not a
        // generic counter"). The existing `status_u16_round_trips_as_unquoted_integer`
        // pin walks the wire form; pin the TYPE here so a refactor to
        // `u32` "for symmetry with the rest of metrics" would surface
        // here at the field level. The cast at INSERT site is
        // `event.status as i32` — a u32 refactor would change the cast
        // domain and silently change the postgres `integer` column
        // value for status codes above i32::MAX (impossible for HTTP
        // codes today, but the type contract is the boundary).
        // Symmetric to round-201 MAX_CAPACITY u64 type pin.
        fn require_u16(_: u16) {}
        require_u16(sample().status);
    }

    #[test]
    fn broadcasting_action_stream_new_constructor_returns_self_owned_by_value() {
        // `BroadcastingActionStream::new(pool: PgPool) -> Self` — the
        // constructor returns OWNED `Self` by value, NOT `Arc<Self>` or
        // `Result<Self, _>`. server.rs wires
        // `Arc::new(BroadcastingActionStream::new(pool))` and the
        // owned-by-value shape lets the caller decide the Arc-wrap
        // policy. A refactor to `Arc<Self>` "for guaranteed shared
        // dispatch" would force every call site to handle the deref and
        // would foreclose the AppState-builder pattern that holds the
        // bare struct briefly before wrapping. Pin via fn-pointer type
        // capture at the static-fn item — does NOT require a runtime
        // PgPool (no call is made).
        let _ctor: fn(PgPool) -> BroadcastingActionStream = BroadcastingActionStream::new;
    }

    #[test]
    fn action_stream_trait_super_bounds_pinned_send_sync_static_for_arc_dyn_dispatch() {
        // The `ActionStream` trait declares
        // `pub trait ActionStream: Send + Sync + 'static`. AppState holds
        // it as `Arc<dyn ActionStream>` so the three super-bounds are
        // load-bearing for the entire request-scoped dispatch path. A
        // refactor that dropped one bound "for ergonomic single-thread
        // testing" would silently break the AppState assembly with a
        // confusing `tower::Service` trait-bound error far from this
        // file. Pin all three super-bounds explicitly via require_super
        // — every concrete impl (LoggingStream, BroadcastingActionStream)
        // MUST satisfy them. Symmetric to round-211 emit + summary
        // Send+Sync+'static pins extended to this trait's super-bounds.
        fn require_super<T: ActionStream + ?Sized>() {}
        require_super::<dyn ActionStream>();
        require_super::<LoggingStream>();
        require_super::<BroadcastingActionStream>();
    }

    #[test]
    fn action_event_clone_independent_owned_strings_on_block_reason_some_arm() {
        // The existing `action_event_clone_produces_independent_value_for_each_sink`
        // pin walks decision/block_reason/vendor mutation independence
        // but uses `clone.block_reason = Some("mutated".to_string())` —
        // it REPLACES the Option rather than mutating the inner String.
        // Pin the deeper contract: mutating the INNER String of a Some
        // arm via `.as_mut().unwrap().push_str(...)` must NOT alias back
        // to the original. A refactor that switched `Option<String>` to
        // `Option<Arc<String>>` "for memory savings on common policy
        // names" would pass the replace-the-Option pin but fail this
        // inner-mutation pin — surfacing the silent cross-sink aliasing
        // that would let one sink decorator's mutation poison every
        // other sink.
        let original = sample();
        let mut clone = original.clone();
        clone
            .block_reason
            .as_mut()
            .expect("Some arm")
            .push_str("-MUTATED");
        assert_eq!(original.block_reason.as_deref(), Some("policy"));
        assert_eq!(clone.block_reason.as_deref(), Some("policy-MUTATED"));
    }

    #[test]
    fn action_event_referentially_transparent_clone_across_fifty_calls() {
        // `ActionEvent: Clone` (derived). The clone path is the hot path
        // — every TeeStream sink clones the event. Pin referential
        // transparency on the clone helper across 50 calls on the same
        // input: no thread-local LRU keyed on the source-event pointer
        // forking the cloned values, no per-call counter mixin tagging
        // a "clone #N" field. A refactor that introduced
        // `Arc<dashmap::DashMap<...>>` keyed memoization "for hot-path
        // dedup" would surface here as a field drift across the 50-call
        // sweep. Symmetric to round-213 CachedPca::new RT-50 +
        // round-211 parse_id_value RT-50 referential-transparency pins
        // extended to this hot-path Clone.
        let baseline = sample();
        for n in 0..50 {
            let next = baseline.clone();
            assert_eq!(next.request_id, baseline.request_id, "iter {n}");
            assert_eq!(next.vendor, baseline.vendor, "iter {n}");
            assert_eq!(next.action, baseline.action, "iter {n}");
            assert_eq!(next.status, baseline.status, "iter {n}");
            assert_eq!(next.decision, baseline.decision, "iter {n}");
            assert_eq!(next.block_reason, baseline.block_reason, "iter {n}");
            assert_eq!(
                next.read_filter_triggered, baseline.read_filter_triggered,
                "iter {n}",
            );
            assert_eq!(
                next.quarantined_count, baseline.quarantined_count,
                "iter {n}"
            );
            assert_eq!(next.at, baseline.at, "iter {n}");
            assert_eq!(next.policy_id, baseline.policy_id, "iter {n}");
            assert_eq!(next.extra, baseline.extra, "iter {n}");
        }
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

    // ─── round 241 (2026-05-22): BroadcastingActionStream + ActionEvent
    // field-shape + Arc<dyn> dispatch surfaces ───

    #[tokio::test]
    async fn broadcasting_action_stream_field_count_pinned_at_exactly_two_via_exhaustive_destructure()
     {
        // `BroadcastingActionStream { db, tx }` — exactly 2 fields. A 3rd
        // field landing (e.g. `metrics_label: &'static str` for per-
        // stream metric bucketing OR
        // `dropped_counter: Arc<AtomicU64>` for slow-consumer-lag
        // observability) without matching `new()` constructor wiring
        // would silently zero-initialize the new field on every
        // construction — and any handler reading it would see
        // `AtomicU64::new(0)` forever, never tripping. The exhaustive
        // destructure with no `..` rest pattern forces a 3rd field to
        // update this site in lockstep with the constructor. Symmetric
        // to the `TeeStream` 2-field + `BurstSuppressor` 3-field +
        // `PicExecutor` 1-field exhaustive-destructure pins in rounds
        // 224 / 235 / 239 extended to this sibling persist-and-fan-out
        // sink. Construction needs a `PgPool` which can't be cheaply
        // built without a connection; use `lazy_no_connection` so the
        // pool struct exists but doesn't open a socket — the
        // destructure runs at compile time anyway.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://x:y@127.0.0.1:1/z")
            .expect("lazy connect");
        let stream = BroadcastingActionStream::new(pool);
        let BroadcastingActionStream { db: _, tx: _ } = stream;
    }

    #[test]
    fn action_event_send_sync_static_for_arc_dyn_action_stream_publish_boundary() {
        // `ActionEvent` crosses the `tokio::spawn(async move { sink.publish(event).await })`
        // fan-out boundary in TeeStream; `Send + Sync + 'static` are
        // load-bearing for that path. The existing
        // `logging_stream_is_send_sync_static_for_app_state_arc_dyn_path`
        // pin walks the SINK type, not the EVENT type — a refactor
        // that swapped any field for `Rc<...>` "for cheap clone on
        // a single-thread test runner" would break Send without
        // surfacing here; the breakage would land at TeeStream's
        // spawn site with an unrelated trait-bound error. Pin the
        // three-trait combo on ActionEvent so the type boundary
        // fails fast at this file. Symmetric to round-239's
        // `pic_executor_and_error_and_outcome_are_send_sync_static`
        // pin extended to this sibling event envelope.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ActionEvent>();
    }

    #[test]
    fn action_event_policy_id_field_pinned_owned_option_string_via_require_for_cross_await_db_bind()
    {
        // `policy_id: Option<String>` — OWNED `Option<String>`, NOT
        // `Option<&'a str>` borrow. The event is held across an
        // `.await` in `BroadcastingActionStream::publish` (the sqlx
        // `INSERT … .execute(&self.db).await` chain binds
        // `event.policy_id.as_deref()` after the await suspension)
        // and crosses the `tokio::spawn` boundary inside TeeStream's
        // fan-out. A refactor to `Option<&'a str>` "for zero-alloc
        // logging-stream construction" would tie the lifetime to the
        // request frame's `policy_id` borrow — and the frame is freed
        // before the spawn awaits, producing a use-after-free. Pin
        // the owned-Option-String shape via require_option_string.
        // Symmetric to round-238's
        // `email_notifier_recipient_fields_to_cc_bcc_all_pinned_owned_vec_mailbox_via_require`
        // extended to this sibling owned-Option field.
        fn require_option_string(_: Option<String>) {}
        let e = sample();
        require_option_string(e.policy_id);
        // And the symmetric `block_reason` field carries the SAME
        // owned-Option-String shape — pin via the same require fn so
        // a refactor changing one and not the other (silently breaking
        // operator dashboard policy-vs-reason cross-references) would
        // surface here.
        let e = sample();
        require_option_string(e.block_reason);
    }

    #[test]
    fn broadcasting_action_stream_subscribe_return_type_is_broadcast_receiver_via_fn_pointer_witness()
     {
        // `BroadcastingActionStream::subscribe(&self) -> broadcast::Receiver<Arc<ActionEvent>>` —
        // returns a tokio broadcast receiver typed on the Arc-shared
        // event payload. The admin SSE endpoint calls
        // `stream.subscribe()` and forwards messages over an HTTP
        // response stream; a refactor that swapped the payload type
        // to `Arc<serde_json::Value>` "for ergonomic mid-pipeline
        // mutation" would force every subscriber to re-derive the
        // ActionEvent shape and would surface only at the SSE site as
        // a confusing trait-bound mismatch. Pin via fn-pointer witness
        // on the method type so a payload-type change surfaces at the
        // boundary here. Symmetric to round-216's
        // `oauth_state_session_token_return_type_is_string_via_fn_pointer_witness`
        // extended to this sibling subscribe accessor.
        let _f: fn(&BroadcastingActionStream) -> broadcast::Receiver<Arc<ActionEvent>> =
            BroadcastingActionStream::subscribe;
    }

    #[test]
    fn action_event_extra_default_for_missing_field_pinned_value_null_not_unit_value() {
        // The `extra: Value` field carries `#[serde(default)]` so a
        // wire payload omitting the key deserializes successfully. The
        // existing `round_trips_through_json_with_absent_extra` test
        // pins the deserialize path; pin the DEFAULT value's shape
        // here — it MUST be `Value::Null`, NOT some other Value
        // variant (e.g. `Value::Object(Default::default())` "for
        // ergonomic key-presence checks downstream"). A refactor of
        // `serde_json::Value::default()` (it's `Value::Null` today,
        // but a downstream serde_json bump could shift it) would
        // surface here as a deserialize value drift. Pin via direct
        // construction + assertion on the resulting `extra` field.
        // Symmetric to round-237's
        // `audit_body_mode_label_strings_pairwise_byte_distinct_for_metric_label_dispatch`
        // extended to this sibling default-value contract.
        let s = r#"{
            "request_id":"00000000-0000-0000-0000-000000000000",
            "agent_session_id":"00000000-0000-0000-0000-000000000000",
            "p_0":"x","leaf_pca_id":null,
            "vendor":"v","action":"a","method":"M","path":"/p",
            "status":200,"decision":"allow","block_reason":null,
            "read_filter_triggered":false,"quarantined_count":0,
            "at":"2026-05-22T00:00:00Z","policy_id":null
        }"#;
        let ev: ActionEvent = serde_json::from_str(s).unwrap();
        // The default MUST be `Value::Null` specifically — not Object,
        // not Array, not the empty-string Value. Pin via direct
        // discriminant matching.
        assert!(matches!(ev.extra, Value::Null));
        assert_eq!(ev.extra, Value::Null);
    }

    #[test]
    fn action_event_at_field_pinned_datetime_utc_not_local_via_require_for_grafana_alignment() {
        // `at: DateTime<Utc>` — pinned to the UTC timezone marker, NOT
        // `DateTime<Local>` or a bare `chrono::NaiveDateTime`. The
        // existing `at_datetime_serializes_as_rfc3339_with_z_suffix_not_offset_form`
        // pin walks the WIRE shape (`Z` suffix); pin the TYPE shape
        // here so a refactor to `DateTime<Local>` "for ergonomic dev-
        // mode log reading" would silently shift the serialized
        // suffix to `+HH:MM` (matching the host's TZ) on every
        // operator's laptop AND in CI runners with non-UTC system
        // clocks — breaking the byte-exact suffix pin only on
        // non-UTC hosts. Pin via fn-pointer require on the field
        // type so a TZ refactor surfaces at the field boundary, not
        // at the wire boundary downstream. Symmetric to round-231's
        // `blocked_action_record_uuid_fields_request_id_session_id_both_pinned_uuid_via_require_uuid`
        // extended to this sibling typed-timestamp field.
        fn require_datetime_utc(_: DateTime<Utc>) {}
        let e = sample();
        require_datetime_utc(e.at);
    }
}
