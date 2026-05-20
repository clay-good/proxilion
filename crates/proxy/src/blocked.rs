//! Block-record persistence — adapters call into this when an action is
//! denied or shunted into the human-approval queue.
//!
//! Authority: spec.md §2.3, ui-less-surfaces.md §5/§8.

use sqlx::PgPool;
use uuid::Uuid;

use crate::notifier::{BlockedNotification, Notifiers};

/// Everything the adapter knows at the moment of denial. The API in
/// `crate::api::blocked` joins this with `pca_cache` to load the
/// predecessor CBOR when an operator approves.
#[derive(Debug, Clone)]
pub struct BlockedActionRecord<'a> {
    pub request_id: Uuid,
    pub session_id: Uuid,
    pub p_0: Option<&'a str>,
    pub vendor: &'a str,
    pub action: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    /// `policy`, `pic_invariant`, `read_filter`.
    pub layer: &'a str,
    pub policy_id: Option<&'a str>,
    pub detail: Option<&'a str>,
    /// The PCA the override flow will use as predecessor when minting an
    /// attested branch. None for `read_filter` blocks (the action already
    /// crossed the wire) — those are audit-only.
    pub predecessor_pca_id: Option<Uuid>,
    /// Ops the policy / adapter wanted to express as the next link's
    /// authority. Override re-uses this so the approved action is bound to
    /// the exact same authority the original attempt declared.
    pub requested_ops: &'a [String],
    /// Per-policy escalation deadline in minutes (ui-less-surfaces.md
    /// §5.7 dev 2). When set, persist writes
    /// `escalation_at = now() + N min`; the sweeper re-fires the email
    /// notifier with a REMINDER: subject prefix when the deadline lapses.
    /// `None` → no escalation.
    pub escalation_after_minutes: Option<u32>,
    /// Canonical JSON snapshot of the request the agent tried to make
    /// (spec.md §2.1 dev 3 — resolved 2026-05-12). Truncated to 4 KB by
    /// `canonical_request_json`; `None` is tolerated for back-compat
    /// with paths that haven't been migrated yet, in which case the
    /// approver surfaces fall back to the `(method, path, action)`
    /// triple. Use [`canonical_request_json`] to build this consistently
    /// across adapters.
    pub request_canonical_json: Option<String>,
}

/// Build a deterministic, 4 KB-bounded JSON snapshot of the request as
/// the policy engine saw it. Keys are emitted in a fixed order so the
/// rendered output is stable; nested maps go through `serde_json` which
/// sorts alphabetically. The body and path-params maps reflect *what
/// the adapter opted into exposing to the policy engine* — spec.md §5.4
/// default-deny semantics, so a Drive list response can't accidentally
/// leak file content into the approver view.
///
/// Truncation: if the rendered JSON exceeds `CANONICAL_REQUEST_MAX_LEN`
/// (4 KB), the value is replaced with a small envelope
/// `{"truncated":true,"original_len":N}` so downstream consumers know
/// what happened. The metric `proxilion_blocked_canonical_truncated_total`
/// ticks on truncation.
pub const CANONICAL_REQUEST_MAX_LEN: usize = 4096;

pub fn canonical_request_json(
    method: &str,
    upstream_path: &str,
    vendor: &str,
    action: &str,
    path_params: &std::collections::HashMap<String, String>,
    body_for_policy: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    // Manual key ordering — top-level fields appear in a stable shape
    // so operators reading raw rows or NDJSON exports get the same
    // layout every time. Nested maps go through `serde_json::Value`
    // which sorts keys alphabetically.
    let payload = serde_json::json!({
        "method": method,
        "path": upstream_path,
        "vendor": vendor,
        "action": action,
        "path_params": path_params,
        "body": body_for_policy,
    });
    let s = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
    if s.len() <= CANONICAL_REQUEST_MAX_LEN {
        s
    } else {
        let len = s.len();
        metrics::counter!(
            "proxilion_blocked_canonical_truncated_total",
            "vendor" => vendor.to_string(),
            "action" => action.to_string(),
        )
        .increment(1);
        serde_json::json!({
            "truncated": true,
            "original_len": len,
            "method": method,
            "path": upstream_path,
            "vendor": vendor,
            "action": action,
        })
        .to_string()
    }
}

#[allow(dead_code)]
pub async fn persist(db: &PgPool, r: BlockedActionRecord<'_>) {
    let _ = persist_returning_id(db, &r).await;
}

/// Persist + optionally notify (ui-less-surfaces.md §10.3). Adapters use
/// this variant so the human-approval channel fires as soon as the row
/// commits. Notification is fire-and-forget — the request response and
/// the durable row never wait on the webhook receiver.
pub async fn persist_and_notify(db: &PgPool, notifiers: &Notifiers, r: BlockedActionRecord<'_>) {
    let id = match persist_returning_id(db, &r).await {
        Some(id) => id,
        None => return,
    };
    // Build the canonical notification once. proxy_public_url defaults to
    // whichever driver is configured first; all drivers use the same
    // approve/reject URLs.
    let proxy_url = notifiers
        .webhook
        .current()
        .map(|n| n.proxy_public_url().to_string())
        .or_else(|| {
            notifiers
                .slack
                .current()
                .map(|n| n.proxy_public_url().to_string())
        })
        .or_else(|| {
            notifiers
                .email
                .current()
                .map(|n| n.proxy_public_url().to_string())
        });
    let Some(proxy_url) = proxy_url else { return };
    let payload = BlockedNotification::from_record(id, &r, &proxy_url);
    let owned = OwnedBlockedNotification::from(&payload);

    // Webhook fan-out.
    if let Some(n) = notifiers.webhook.current() {
        let owned = owned.clone();
        tokio::spawn(async move {
            n.notify(&owned.as_borrowed()).await;
        });
    }
    // Slack fan-out.
    if let Some(s) = notifiers.slack.current() {
        let owned = owned.clone();
        tokio::spawn(async move {
            s.notify(&owned.as_borrowed()).await;
        });
    }
    // Email fan-out.
    if let Some(e) = notifiers.email.current() {
        let owned = owned.clone();
        tokio::spawn(async move {
            e.notify(&owned.as_borrowed()).await;
        });
    }
}

async fn persist_returning_id(db: &PgPool, r: &BlockedActionRecord<'_>) -> Option<Uuid> {
    // `escalation_at` is computed in SQL so it shares the same `now()`
    // clock as the row's `blocked_at` default — important for the
    // sweeper's `escalation_at < now()` comparison to be self-consistent.
    let escalation_minutes_sql = r.escalation_after_minutes.map(|m| m as i64);
    let res: Result<(Uuid,), _> = sqlx::query_as(
        "INSERT INTO blocked_actions
            (request_id, session_id, p_0, vendor, action, method, path,
             layer, policy_id, detail, predecessor_pca_id, requested_ops,
             escalation_at, request_canonical_json)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                 CASE WHEN $13::bigint IS NULL THEN NULL
                      ELSE now() + ($13::bigint * interval '1 minute')
                 END,
                 $14)
         RETURNING id",
    )
    .bind(r.request_id)
    .bind(r.session_id)
    .bind(r.p_0)
    .bind(r.vendor)
    .bind(r.action)
    .bind(r.method)
    .bind(r.path)
    .bind(r.layer)
    .bind(r.policy_id)
    .bind(r.detail)
    .bind(r.predecessor_pca_id)
    .bind(r.requested_ops)
    .bind(escalation_minutes_sql)
    .bind(r.request_canonical_json.as_deref())
    .fetch_one(db)
    .await;
    match res {
        Ok((id,)) => {
            // spec.md §3.2 — `proxilion_blocks_total{policy_id,reason}`.
            // `reason` is the layer that produced the block (policy /
            // pic_invariant / read_filter); the `policy_id` label degrades
            // gracefully to `(none)` for Layer-A invariant breaks that
            // never matched a Layer-B policy. Cardinality is bounded by
            // the customer's YAML — see §3.3.
            metrics::counter!(
                "proxilion_blocks_total",
                "policy_id" => r.policy_id.map(String::from).unwrap_or_else(|| "(none)".into()),
                "reason" => r.layer.to_string(),
            )
            .increment(1);
            Some(id)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to persist blocked_action");
            None
        }
    }
}

/// `BlockedNotification` borrows from the adapter's `BlockedActionRecord`.
/// To send it on a `tokio::spawn` we need owned strings. This struct is
/// the materialized snapshot; `as_borrowed()` reconstructs the borrowed
/// view the notifier expects.
#[derive(Clone)]
struct OwnedBlockedNotification {
    blocked_id: Uuid,
    request_id: Uuid,
    session_id: Uuid,
    p_0: Option<String>,
    vendor: String,
    action: String,
    method: String,
    path: String,
    layer: String,
    policy_id: Option<String>,
    detail: Option<String>,
    predecessor_pca_id: Option<Uuid>,
    requested_ops: Vec<String>,
    approve_url: String,
    reject_url: String,
}

impl OwnedBlockedNotification {
    fn from(n: &BlockedNotification<'_>) -> Self {
        Self {
            blocked_id: n.blocked_id,
            request_id: n.request_id,
            session_id: n.session_id,
            p_0: n.p_0.map(|s| s.to_string()),
            vendor: n.vendor.to_string(),
            action: n.action.to_string(),
            method: n.method.to_string(),
            path: n.path.to_string(),
            layer: n.layer.to_string(),
            policy_id: n.policy_id.map(|s| s.to_string()),
            detail: n.detail.map(|s| s.to_string()),
            predecessor_pca_id: n.predecessor_pca_id,
            requested_ops: n.requested_ops.to_vec(),
            approve_url: n.approve_url.clone(),
            reject_url: n.reject_url.clone(),
        }
    }

    fn as_borrowed(&self) -> BlockedNotification<'_> {
        BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: self.blocked_id,
            request_id: self.request_id,
            session_id: self.session_id,
            p_0: self.p_0.as_deref(),
            vendor: &self.vendor,
            action: &self.action,
            method: &self.method,
            path: &self.path,
            layer: &self.layer,
            policy_id: self.policy_id.as_deref(),
            detail: self.detail.as_deref(),
            predecessor_pca_id: self.predecessor_pca_id,
            requested_ops: &self.requested_ops,
            approve_url: self.approve_url.clone(),
            reject_url: self.reject_url.clone(),
        }
    }
}

#[cfg(test)]
mod canonical_request_json_tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_maps() -> (HashMap<String, String>, HashMap<String, serde_json::Value>) {
        (HashMap::new(), HashMap::new())
    }

    /// The output is valid JSON and carries the top-level identification
    /// triple the approver surfaces rely on (method, path, action).
    #[test]
    fn shapes_a_well_formed_object() {
        let (path_params, body) = empty_maps();
        let s = canonical_request_json(
            "GET",
            "/drive/v3/files/abc",
            "google",
            "drive.files.get",
            &path_params,
            &body,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["method"], "GET");
        assert_eq!(v["path"], "/drive/v3/files/abc");
        assert_eq!(v["vendor"], "google");
        assert_eq!(v["action"], "drive.files.get");
        assert!(v["truncated"].is_null());
    }

    /// Body fields the adapter exposed land under `body.*`. Reads with
    /// empty `body_for_policy` produce an empty object (no surprise
    /// leakage from response bodies).
    #[test]
    fn body_is_only_what_adapter_exposed() {
        let path_params = HashMap::new();
        let mut body = HashMap::new();
        body.insert("external_recipient".into(), serde_json::Value::Bool(true));
        body.insert(
            "to_domains".into(),
            serde_json::json!(["evil.example", "spam.example"]),
        );
        let s = canonical_request_json(
            "POST",
            "/gmail/v1/users/me/messages/send",
            "google",
            "gmail.messages.send",
            &path_params,
            &body,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["body"]["external_recipient"], true);
        assert_eq!(v["body"]["to_domains"][0], "evil.example");
        // No fields the adapter didn't opt into.
        assert!(v["body"]["subject"].is_null());
    }

    /// At the 4 KB cap the function emits a stub instead of the full
    /// JSON, and the `proxilion_blocked_canonical_truncated_total`
    /// counter ticks (asserted indirectly via the response shape).
    #[test]
    fn truncates_oversize_bodies() {
        let path_params = HashMap::new();
        let mut body = HashMap::new();
        body.insert("blob".into(), serde_json::Value::String("x".repeat(8192)));
        let s = canonical_request_json(
            "POST",
            "/gmail/v1/users/me/messages/send",
            "google",
            "gmail.messages.send",
            &path_params,
            &body,
        );
        assert!(s.len() <= CANONICAL_REQUEST_MAX_LEN + 256, "{}", s.len());
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["truncated"], true);
        assert!(v["original_len"].as_u64().unwrap() > CANONICAL_REQUEST_MAX_LEN as u64);
        // Identification fields survive the truncation envelope so the
        // approver still knows what the request was.
        assert_eq!(v["method"], "POST");
        assert_eq!(v["action"], "gmail.messages.send");
    }

    /// OwnedBlockedNotification round-trips a borrowed
    /// `BlockedNotification` through owned strings and back, preserving
    /// every field. The `spawn`'d notifier path depends on this so
    /// adapters that go out of scope before the notifier finishes don't
    /// dangle borrowed pointers.
    #[test]
    fn owned_notification_round_trips_through_borrowed() {
        let ops = vec!["gmail:send:bob@external.com".to_string()];
        let approve_url = "https://proxy.example/api/v1/blocked/abc/approve".to_string();
        let reject_url = "https://proxy.example/api/v1/blocked/abc/reject".to_string();
        let id = Uuid::new_v4();
        let req = Uuid::new_v4();
        let session = Uuid::new_v4();
        let pred = Uuid::new_v4();
        let original = BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: id,
            request_id: req,
            session_id: session,
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("gmail-external-send-gate"),
            detail: Some("external recipient"),
            predecessor_pca_id: Some(pred),
            requested_ops: &ops,
            approve_url: approve_url.clone(),
            reject_url: reject_url.clone(),
        };
        let owned = OwnedBlockedNotification::from(&original);
        let borrowed = owned.as_borrowed();
        assert_eq!(borrowed.schema, BlockedNotification::SCHEMA);
        assert_eq!(borrowed.blocked_id, id);
        assert_eq!(borrowed.request_id, req);
        assert_eq!(borrowed.session_id, session);
        assert_eq!(borrowed.p_0, Some("alice@acme.com"));
        assert_eq!(borrowed.vendor, "google");
        assert_eq!(borrowed.action, "gmail.messages.send");
        assert_eq!(borrowed.method, "POST");
        assert_eq!(borrowed.layer, "policy");
        assert_eq!(borrowed.policy_id, Some("gmail-external-send-gate"));
        assert_eq!(borrowed.detail, Some("external recipient"));
        assert_eq!(borrowed.predecessor_pca_id, Some(pred));
        assert_eq!(borrowed.requested_ops.len(), 1);
        assert_eq!(borrowed.approve_url, approve_url);
        assert_eq!(borrowed.reject_url, reject_url);
    }

    #[test]
    fn owned_notification_clone_yields_independent_views() {
        let ops: Vec<String> = vec![];
        let n = BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: None,
            vendor: "v",
            action: "a",
            method: "m",
            path: "/p",
            layer: "policy",
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: &ops,
            approve_url: "u/approve".into(),
            reject_url: "u/reject".into(),
        };
        let a = OwnedBlockedNotification::from(&n);
        let b = a.clone();
        assert_eq!(a.approve_url, b.approve_url);
        assert_eq!(a.as_borrowed().vendor, b.as_borrowed().vendor);
    }

    /// Path params land under `path_params` exactly as the adapter
    /// surfaced them (no transformation). Two calls with the same
    /// inputs produce byte-equal output — the `request_canonical_json`
    /// audit row is reproducible.
    #[test]
    fn is_deterministic_across_calls() {
        let mut path_params = HashMap::new();
        path_params.insert("id".into(), "file-123".into());
        let body = HashMap::new();
        let a = canonical_request_json(
            "GET",
            "/x",
            "google",
            "drive.files.get",
            &path_params,
            &body,
        );
        let b = canonical_request_json(
            "GET",
            "/x",
            "google",
            "drive.files.get",
            &path_params,
            &body,
        );
        assert_eq!(a, b);
        let v: serde_json::Value = serde_json::from_str(&a).unwrap();
        assert_eq!(v["path_params"]["id"], "file-123");
    }

    /// Truncation envelope MUST NOT carry `body` or `path_params` — those
    /// are the fields that caused the bloat, and re-serializing them
    /// inside the truncation envelope would defeat the whole point. The
    /// approver still gets the (method, path, vendor, action) triple.
    #[test]
    fn truncation_envelope_elides_body_and_path_params() {
        let mut path_params = HashMap::new();
        path_params.insert("id".into(), "file-123".into());
        let mut body = HashMap::new();
        body.insert("blob".into(), serde_json::Value::String("y".repeat(8192)));
        let s = canonical_request_json(
            "POST",
            "/drive/v3/files/abc",
            "google",
            "drive.files.create",
            &path_params,
            &body,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["truncated"], true);
        // Identification fields survive.
        assert_eq!(v["method"], "POST");
        assert_eq!(v["path"], "/drive/v3/files/abc");
        assert_eq!(v["vendor"], "google");
        assert_eq!(v["action"], "drive.files.create");
        // The bloat sources are absent — a regression that re-included
        // body/path_params would inflate every truncated row in the audit
        // log and reintroduce the size-cap problem this envelope solves.
        assert!(
            v["body"].is_null(),
            "body must be absent in truncation envelope: {s}"
        );
        assert!(
            v["path_params"].is_null(),
            "path_params must be absent in truncation envelope: {s}"
        );
    }

    /// Just-below the cap: a body that renders to ~4090 bytes passes
    /// through unmodified (no truncation envelope). The boundary check
    /// is `s.len() <= MAX`, so a regression to `<` would silently start
    /// truncating exact-at-limit rows that fit fine today.
    #[test]
    fn just_below_cap_passes_through_unchanged() {
        let path_params = HashMap::new();
        let mut body = HashMap::new();
        // Conservatively undersized so envelope overhead + alphabetic
        // key sort don't push it over without us noticing.
        body.insert("blob".into(), serde_json::Value::String("a".repeat(3900)));
        let s = canonical_request_json("POST", "/x", "google", "a", &path_params, &body);
        assert!(
            s.len() <= CANONICAL_REQUEST_MAX_LEN,
            "{} > {}",
            s.len(),
            CANONICAL_REQUEST_MAX_LEN
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            v["truncated"].is_null(),
            "must not be a truncation envelope"
        );
        // The body field survives unsummarized — operators can read it.
        assert_eq!(v["body"]["blob"].as_str().unwrap().len(), 3900);
    }

    /// Nested keys are sorted alphabetically by serde_json — the audit
    /// log is reproducible across map orderings (Rust's HashMap iteration
    /// order is randomized per process, so without sort the same logical
    /// request would render differently across restarts and break
    /// deterministic-diff workflows the approver UI depends on).
    #[test]
    fn nested_body_keys_render_in_alphabetical_order() {
        let path_params = HashMap::new();
        // Insert in non-alphabetical order to exercise the sort.
        let mut body = HashMap::new();
        body.insert("zebra".into(), serde_json::Value::String("z".into()));
        body.insert("alpha".into(), serde_json::Value::String("a".into()));
        body.insert("mango".into(), serde_json::Value::String("m".into()));
        let s = canonical_request_json("GET", "/x", "v", "a", &path_params, &body);
        // Locate each key's position in the rendered string — they MUST
        // appear in `alpha < mango < zebra` order regardless of insertion.
        let a = s.find("\"alpha\"").expect("alpha key present");
        let m = s.find("\"mango\"").expect("mango key present");
        let z = s.find("\"zebra\"").expect("zebra key present");
        assert!(
            a < m && m < z,
            "keys must be sorted: alpha={a} mango={m} zebra={z}"
        );
    }

    /// The empty-maps case is the most common shape (read endpoints with
    /// no path params and no exposed body fields). It must produce
    /// `body: {}` + `path_params: {}` (not `null`), so the approver UI
    /// can distinguish "adapter opted into 0 fields" from "field absent
    /// because schema is older."
    #[test]
    fn empty_maps_render_as_empty_objects_not_null() {
        let (path_params, body) = empty_maps();
        let s = canonical_request_json("GET", "/x", "v", "a", &path_params, &body);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            v["body"].is_object(),
            "body must be an object, got {:?}",
            v["body"]
        );
        assert_eq!(v["body"].as_object().unwrap().len(), 0);
        assert!(v["path_params"].is_object());
        assert_eq!(v["path_params"].as_object().unwrap().len(), 0);
    }

    /// `BlockedActionRecord` is `Clone` so adapters can hand a snapshot
    /// to the spawned notifier task without giving up ownership of the
    /// original. Pin both that the derive exists and that lifetime'd
    /// references survive cloning (a future refactor to `Cow<'a, str>`
    /// would surface here).
    #[test]
    fn canonical_request_json_renders_nested_object_body_field() {
        // Adapters sometimes surface a parsed sub-object (e.g. the
        // gmail message's `headers` map) to the policy engine. Pin
        // that a nested JSON object lands intact in the canonical
        // form — a regression that stringified nested values would
        // break the audit-log shape operators key on for forensic
        // detail.
        let path_params = HashMap::new();
        let mut body = HashMap::new();
        body.insert(
            "headers".into(),
            serde_json::json!({"from": "alice@acme.com", "to": "bob@external"}),
        );
        let s = canonical_request_json("POST", "/x", "google", "a", &path_params, &body);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["body"]["headers"].is_object());
        assert_eq!(v["body"]["headers"]["from"], "alice@acme.com");
        assert_eq!(v["body"]["headers"]["to"], "bob@external");
    }

    #[test]
    fn canonical_request_json_with_empty_method_and_path_still_serializes() {
        // Defensive: an adapter that accidentally passed empty strings
        // for method/path (a refactor mid-flight) must not panic and
        // must still produce valid JSON with the four identification
        // fields present (as empty strings) so the audit row is parseable.
        let path_params = HashMap::new();
        let body = HashMap::new();
        let s = canonical_request_json("", "", "", "", &path_params, &body);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["method"], "");
        assert_eq!(v["path"], "");
        assert_eq!(v["vendor"], "");
        assert_eq!(v["action"], "");
        assert!(v["truncated"].is_null());
    }

    #[test]
    fn canonical_request_max_len_constant_pinned_at_4_kib() {
        // The 4 KiB cap is the spec.md §2.1 dev 3 wire contract — the
        // truncation envelope kicks in above this. A refactor that
        // bumped the constant (in the name of "give operators more
        // context") would silently widen audit-row sizes across every
        // existing deployment and could break downstream SIEM
        // ingestors keyed on the bounded shape. Pin the literal value.
        assert_eq!(CANONICAL_REQUEST_MAX_LEN, 4096);
    }

    #[test]
    fn blocked_action_record_debug_carries_struct_name_and_key_field_names() {
        // `BlockedActionRecord` derives `Debug` — the persist failure
        // path `tracing::warn!(error = %e, "failed to persist blocked_action")`
        // does NOT render the record itself today, but the type is
        // also passed to spawned notifier tasks via `OwnedBlockedNotification`
        // and operator-actionable debug spans in tests and ad-hoc traces
        // render the record via `?r`. Pin the struct name + four
        // operator-essential field names (request_id / session_id /
        // vendor / action) so a hand-rolled `impl Debug` that hid them
        // "to compact" the line would break every operator grep target.
        let ops: Vec<String> = vec![];
        let r = BlockedActionRecord {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "drive.files.get",
            method: "GET",
            path: "/drive/v3/files/x",
            layer: "policy",
            policy_id: Some("p1"),
            detail: Some("d"),
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        };
        let s = format!("{r:?}");
        assert!(s.contains("BlockedActionRecord"), "got: {s}");
        assert!(s.contains("request_id"), "got: {s}");
        assert!(s.contains("session_id"), "got: {s}");
        assert!(s.contains("vendor"), "got: {s}");
        assert!(s.contains("action"), "got: {s}");
    }

    #[test]
    fn owned_blocked_notification_is_send_sync_static_for_tokio_spawn_boundary() {
        // `OwnedBlockedNotification` is the materialized snapshot that
        // the persist_and_notify path clones into each `tokio::spawn`
        // future (one per webhook / slack / email driver fan-out). The
        // spawn boundary requires `Send + 'static`; the clone-into-
        // multiple-tasks design also relies on `Sync` for safety. A
        // refactor that introduced a !Send field (e.g. swapped
        // `String` for `Rc<str>` "for cheap clone") would break the
        // spawn site with a far-removed trait-bound error. Pin all
        // three traits here so the failure surfaces at the right
        // module — symmetric to the `tee.rs` Send+Sync+'static pins.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<OwnedBlockedNotification>();
    }

    #[test]
    fn canonical_request_json_non_truncated_carries_exactly_six_top_level_keys() {
        // The non-truncated envelope has SIX top-level keys: method +
        // path + vendor + action + path_params + body. Operator audit
        // queries iterate the keys to render a deterministic table.
        // Pin the exact key set so a refactor that added a seventh
        // (e.g. `timestamp` "for ergonomic ordering") would silently
        // widen every audit row — a wire-shape change SIEM ingestors
        // would need to acknowledge. The existing tests pin individual
        // key presence (method, path, vendor, action, body) but never
        // pin the exhaustive set.
        let (path_params, body) = empty_maps();
        let s = canonical_request_json(
            "GET",
            "/x",
            "google",
            "drive.files.get",
            &path_params,
            &body,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let obj = v.as_object().expect("top-level must be object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(String::as_str).collect();
        let expected: std::collections::HashSet<&str> =
            ["method", "path", "vendor", "action", "path_params", "body"]
                .into_iter()
                .collect();
        assert_eq!(keys, expected, "got: {keys:?}");
    }

    #[test]
    fn canonical_request_json_truncation_envelope_carries_exactly_six_expected_keys() {
        // The truncation envelope has SIX keys: truncated + original_len
        // + method + path + vendor + action — NO body, NO path_params
        // (the existing `truncation_envelope_elides_body_and_path_params`
        // pin covers the elision). Pin the exhaustive key set so a
        // refactor that added a seventh (e.g. `policy_id` "for
        // forensic context") would silently re-inflate truncated rows
        // and defeat the size-cap. Operators auto-expand truncated
        // rows in the UI and depend on the fixed-shape envelope.
        let path_params = std::collections::HashMap::new();
        let mut body = std::collections::HashMap::new();
        body.insert("blob".into(), serde_json::Value::String("z".repeat(8192)));
        let s = canonical_request_json(
            "POST",
            "/drive/v3/files",
            "google",
            "drive.files.create",
            &path_params,
            &body,
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let obj = v.as_object().expect("top-level must be object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(String::as_str).collect();
        let expected: std::collections::HashSet<&str> = [
            "truncated",
            "original_len",
            "method",
            "path",
            "vendor",
            "action",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, expected, "got: {keys:?}");
    }

    #[test]
    fn blocked_action_record_with_all_none_optionals_constructs_cleanly() {
        // All four `Option<_>` fields (p_0, policy_id, detail,
        // predecessor_pca_id, escalation_after_minutes,
        // request_canonical_json) AND policy_id / detail simultaneously
        // None — the unauthenticated-probe / pic_invariant-only shape
        // that the read_filter layer produces. Pin that the type
        // constructs cleanly with no required-field gap. A refactor
        // that removed `Option<>` on `detail` "since the policy layer
        // always emits one" would surface here rather than at the
        // read_filter call site that builds the record without a
        // policy-supplied detail. Symmetric to the
        // `pic_violation_record_with_all_none_optionals_constructs_and_clones`
        // pin on [crates/proxy/src/pic/violations.rs].
        let ops: Vec<String> = vec![];
        let r = BlockedActionRecord {
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: None,
            vendor: "google",
            action: "drive.files.get",
            method: "GET",
            path: "/x",
            layer: "read_filter",
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        };
        assert!(r.p_0.is_none());
        assert!(r.policy_id.is_none());
        assert!(r.detail.is_none());
        assert!(r.predecessor_pca_id.is_none());
        assert!(r.escalation_after_minutes.is_none());
        assert!(r.request_canonical_json.is_none());
        // Clone preserves all None polarities.
        let c = r.clone();
        assert!(c.p_0.is_none());
        assert!(c.escalation_after_minutes.is_none());
    }

    #[test]
    fn canonical_request_json_preserves_multibyte_unicode_in_body_string_value() {
        // The canonical-request snapshot is operator-visible in the
        // approver UI; non-ASCII content in policy-exposed body fields
        // (e.g. a localized email subject "café reminder →") must
        // survive the JSON round-trip byte-for-byte. The existing
        // tests cover ASCII bodies; pin multibyte passthrough across
        // 2-byte / 3-byte / 4-byte codepoints. A refactor that called
        // `.replace(non_ascii, "?")` "for SIEM ASCII-only ingest" would
        // silently mangle every non-English audit row.
        let path_params = std::collections::HashMap::new();
        let mut body = std::collections::HashMap::new();
        body.insert(
            "subject".into(),
            serde_json::Value::String("café reminder → 🔥".into()),
        );
        let s = canonical_request_json("POST", "/x", "google", "a", &path_params, &body);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["body"]["subject"], "café reminder → 🔥");
        // And the snapshot must not be the truncation envelope (the
        // 2-byte / 3-byte / 4-byte chars together are < 32 bytes, well
        // under the 4 KB cap).
        assert!(
            v["truncated"].is_null(),
            "small unicode body must not truncate"
        );
    }

    #[test]
    fn blocked_action_record_clone_preserves_borrowed_fields() {
        let ops = vec!["gmail:send:bob@external.com".to_string()];
        let r = BlockedActionRecord {
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("p1"),
            detail: Some("d"),
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: Some(15),
            request_canonical_json: Some("{}".into()),
        };
        let c = r.clone();
        assert_eq!(c.vendor, "google");
        assert_eq!(c.p_0, Some("alice@acme.com"));
        assert_eq!(c.requested_ops.len(), 1);
        assert_eq!(c.escalation_after_minutes, Some(15));
        assert_eq!(c.request_canonical_json.as_deref(), Some("{}"));
    }

    #[test]
    fn canonical_request_max_len_is_power_of_two_for_memory_budget_alignment() {
        // The existing `canonical_request_max_len_constant_pinned_at_4_kib`
        // pin asserts the literal value (4096). Pin the structural
        // invariant that earns the literal: 4096 = 2^12 is a power
        // of two, which matters because the SIEM ingestors and
        // postgres TOAST page boundaries align cleanly to power-of-
        // two byte budgets (a refactor that bumped to 5000 "for round
        // number" would silently misalign every audit row across the
        // TOAST 8KB page boundary and could change the storage cost
        // of every row by triggering a TOAST chunk-split). Symmetric
        // pin to `default_tick_interval_is_strictly_positive_and_bounded_for_loop_safety`
        // on [crates/proxy/src/blocked_expiry.rs] — both pin a
        // structural invariant on top of the literal constant.
        const {
            assert!(
                CANONICAL_REQUEST_MAX_LEN.is_power_of_two(),
                "CANONICAL_REQUEST_MAX_LEN must be a power of two",
            );
            // And it must be > 0 (a zero cap would silently truncate
            // every audit row to the envelope) AND ≤ 1 MiB (a
            // refactor that bumped to 16 MB "for verbose debug"
            // would silently inflate every audit row beyond the SIEM
            // ingestor's per-event payload bound and the per-row
            // postgres TOAST budget).
            assert!(
                CANONICAL_REQUEST_MAX_LEN > 0,
                "must be positive to avoid truncating every row",
            );
            assert!(
                CANONICAL_REQUEST_MAX_LEN <= 1024 * 1024,
                "must be ≤ 1 MiB to keep SIEM + postgres budgets aligned",
            );
        }
    }

    #[test]
    fn canonical_request_json_is_referentially_transparent_across_fifty_repeated_calls() {
        // The function is pure (no clock, no env, no global state —
        // the `metrics::counter!` on the truncation path mutates a
        // global counter but does NOT vary the returned bytes). Pin
        // referential transparency by calling 50 times with the
        // same args and asserting every call yields byte-equal
        // output, across BOTH the non-truncated AND the truncation
        // envelope branches. The existing `is_deterministic_across_calls`
        // pin checks two calls on the non-truncated branch only; widen
        // to 50 iterations × 2 branches so a refactor that introduced
        // a once-cell-backed cache "for hot-path performance" OR a
        // counter-tagged trace id would surface here. Symmetric to
        // `verify_pkce_s256_is_referentially_transparent_across_repeated_calls`
        // on [crates/proxy/src/crypto/pkce.rs] and the round-161
        // `parse_listing_is_referentially_transparent_across_fifty_repeated_calls`
        // pin on [crates/proxy/src/api/policy.rs].
        let path_params = std::collections::HashMap::new();
        let body = std::collections::HashMap::new();
        let first_small = canonical_request_json(
            "POST",
            "/x",
            "google",
            "drive.files.get",
            &path_params,
            &body,
        );
        let mut big_body = std::collections::HashMap::new();
        big_body.insert("blob".into(), serde_json::Value::String("z".repeat(8192)));
        let first_big = canonical_request_json(
            "POST",
            "/drive/v3/files",
            "google",
            "drive.files.create",
            &path_params,
            &big_body,
        );
        for i in 0..50 {
            let again_small = canonical_request_json(
                "POST",
                "/x",
                "google",
                "drive.files.get",
                &path_params,
                &body,
            );
            assert_eq!(again_small, first_small, "call {i} small-branch drift");
            let again_big = canonical_request_json(
                "POST",
                "/drive/v3/files",
                "google",
                "drive.files.create",
                &path_params,
                &big_body,
            );
            assert_eq!(again_big, first_big, "call {i} truncation-branch drift");
        }
    }

    #[test]
    fn canonical_request_json_top_level_result_is_json_object_across_both_truncated_and_normal_branches()
     {
        // The existing tests pin individual top-level keys via
        // `v["method"]`, `v["truncated"]`, etc., implicitly relying
        // on the top-level shape being a JSON object — but never
        // pin the object-shape contract directly. A refactor that
        // wrapped the envelope in an array `[{...}]` "for batch
        // ingest compat" OR returned a top-level JSON string
        // (a `serde_json::to_string(&payload).unwrap()` accidentally
        // double-serialized once) would still parse via
        // `serde_json::from_str` but break every downstream consumer
        // that walks via `v["method"]`. Pin `is_object()` on BOTH
        // branches so the structural contract is explicit.
        let path_params = std::collections::HashMap::new();
        let body = std::collections::HashMap::new();
        let small = canonical_request_json(
            "GET",
            "/x",
            "google",
            "drive.files.get",
            &path_params,
            &body,
        );
        let v_small: serde_json::Value = serde_json::from_str(&small).unwrap();
        assert!(
            v_small.is_object(),
            "non-truncated branch must be JSON object, got: {v_small:?}",
        );
        assert!(!v_small.is_array());
        assert!(!v_small.is_string());
        // Truncation branch.
        let mut big_body = std::collections::HashMap::new();
        big_body.insert("blob".into(), serde_json::Value::String("y".repeat(8192)));
        let big = canonical_request_json(
            "POST",
            "/drive/v3/files",
            "google",
            "drive.files.create",
            &path_params,
            &big_body,
        );
        let v_big: serde_json::Value = serde_json::from_str(&big).unwrap();
        assert!(
            v_big.is_object(),
            "truncation envelope must be JSON object, got: {v_big:?}",
        );
        assert!(!v_big.is_array());
        assert!(!v_big.is_string());
    }

    #[test]
    fn canonical_request_json_multibyte_unicode_in_vendor_and_action_passes_through_truncation_envelope_verbatim()
     {
        // The existing `canonical_request_json_preserves_multibyte_unicode_in_body_string_value`
        // pin walks multibyte content in the BODY field on the non-
        // truncated branch only. Pin the symmetric contract on the
        // TRUNCATION envelope's identification fields (vendor +
        // action), which the operator-facing approver UI renders
        // verbatim even when the body was elided. A refactor that
        // `.to_ascii_lowercase()`-ed the vendor/action labels "for
        // SIEM ingest hygiene" or `.replace(non_ascii, "?")`-ed them
        // would silently mangle the truncation envelope's id triple
        // and break per-tenant audit-row triage for non-ASCII
        // vendor/action labels (a future multi-tenant deployment
        // with localized vendor slugs). Force the truncation branch
        // with a bloat body, then assert the multibyte vendor + action
        // labels survive byte-for-byte.
        let path_params = std::collections::HashMap::new();
        let mut body = std::collections::HashMap::new();
        body.insert("blob".into(), serde_json::Value::String("x".repeat(8192)));
        let vendor = "googlé→🔥";
        let action = "drive.files.café";
        let s = canonical_request_json("POST", "/x", vendor, action, &path_params, &body);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["truncated"], true);
        assert_eq!(v["vendor"], vendor);
        assert_eq!(v["action"], action);
    }

    #[test]
    fn owned_blocked_notification_as_borrowed_sets_schema_to_constant_blocked_notification_schema_verbatim()
     {
        // The `as_borrowed()` builder unconditionally stamps the
        // `schema` field to `BlockedNotification::SCHEMA` (the
        // wire-versioned schema string downstream consumers route
        // on). A refactor that started persisting the schema in
        // `OwnedBlockedNotification` itself (to round-trip a
        // historical wire version "for replay across schema bumps")
        // would silently let stale schema strings leak back onto
        // the notifier wire — every webhook receiver verifying the
        // schema header would 4xx events from any pre-bump persist.
        // Pin that `as_borrowed()` ALWAYS emits the current
        // `BlockedNotification::SCHEMA` constant verbatim,
        // regardless of what was in the original BlockedNotification
        // (today's `OwnedBlockedNotification::from` doesn't even
        // store the schema, but pin the invariant so a future
        // refactor surfaces here rather than at the notifier wire).
        let ops: Vec<String> = vec![];
        let n = BlockedNotification {
            schema: "obsolete-schema-string-from-past",
            blocked_id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: None,
            vendor: "v",
            action: "a",
            method: "m",
            path: "/p",
            layer: "policy",
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: &ops,
            approve_url: "u/approve".into(),
            reject_url: "u/reject".into(),
        };
        let owned = OwnedBlockedNotification::from(&n);
        let borrowed = owned.as_borrowed();
        // schema must be the current SCHEMA constant, NOT the
        // obsolete string from the input.
        assert_eq!(borrowed.schema, BlockedNotification::SCHEMA);
        assert_ne!(borrowed.schema, "obsolete-schema-string-from-past");
    }

    #[test]
    fn owned_blocked_notification_as_borrowed_is_repeatable_yields_byte_equal_fields_across_two_calls()
     {
        // `as_borrowed()` is called once per spawned notifier task
        // (webhook + slack + email fan-out — up to three calls
        // against the same OwnedBlockedNotification instance). Pin
        // that two consecutive calls on the same instance produce
        // byte-equal borrowed views — a refactor that mutated any
        // internal state on the first call (e.g. lazily computed a
        // signature and cached it back into the owned struct "for
        // performance") OR a refactor that introduced any once-
        // cell-backed tagging would surface here as a divergence
        // between the webhook and slack fan-out arms. Symmetric to
        // the `verify_pkce_s256_is_referentially_transparent` and
        // round-161 `parse_listing_is_referentially_transparent`
        // pins — pure-helper repeatability invariants.
        let ops = vec!["gmail:send:bob@external.com".to_string()];
        let id = Uuid::new_v4();
        let req = Uuid::new_v4();
        let session = Uuid::new_v4();
        let n = BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: id,
            request_id: req,
            session_id: session,
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("p1"),
            detail: Some("external recipient"),
            predecessor_pca_id: None,
            requested_ops: &ops,
            approve_url: "u/approve".into(),
            reject_url: "u/reject".into(),
        };
        let owned = OwnedBlockedNotification::from(&n);
        let a = owned.as_borrowed();
        let b = owned.as_borrowed();
        assert_eq!(a.schema, b.schema);
        assert_eq!(a.blocked_id, b.blocked_id);
        assert_eq!(a.request_id, b.request_id);
        assert_eq!(a.session_id, b.session_id);
        assert_eq!(a.p_0, b.p_0);
        assert_eq!(a.vendor, b.vendor);
        assert_eq!(a.action, b.action);
        assert_eq!(a.method, b.method);
        assert_eq!(a.path, b.path);
        assert_eq!(a.layer, b.layer);
        assert_eq!(a.policy_id, b.policy_id);
        assert_eq!(a.detail, b.detail);
        assert_eq!(a.predecessor_pca_id, b.predecessor_pca_id);
        assert_eq!(a.requested_ops, b.requested_ops);
        assert_eq!(a.approve_url, b.approve_url);
        assert_eq!(a.reject_url, b.reject_url);
    }

    // ─── round 186 (2026-05-20): canonical_request_json + BlockedActionRecord type-level surfaces ───

    #[test]
    fn canonical_request_max_len_constant_field_is_usize_type_for_slice_len_compat() {
        // `CANONICAL_REQUEST_MAX_LEN: usize` — the constant's type is
        // `usize`, NOT `u32` / `i64`. Pin the underlying TYPE via the
        // canonical require_usize helper so a refactor that switched
        // to `i32` (or any signed/non-platform-pointer type) "for
        // explicit byte-size clarity" would force every call site
        // (the `s.len() <= CANONICAL_REQUEST_MAX_LEN` comparison) to
        // add casts — and would silently introduce an i32/i64 overflow
        // hazard on long bodies if the comparison swap weren't done
        // in lockstep. The existing `canonical_request_max_len_constant_pinned_at_4_kib`
        // pins the VALUE; this pins the TYPE. Symmetric to round-177
        // u32 + round-182 u16 type pins extended to this usize
        // constant.
        fn require_usize(_: usize) {}
        require_usize(CANONICAL_REQUEST_MAX_LEN);
        // Sanity: still equals the documented 4096 (4 KiB) value.
        assert_eq!(CANONICAL_REQUEST_MAX_LEN, 4096);
    }

    #[test]
    fn canonical_request_json_return_type_is_owned_string_for_cross_await_ownership() {
        // `canonical_request_json(...) -> String` — the return is an
        // OWNED `String`, NOT a borrowed `&str` or `Cow<'_, str>`.
        // The persist() bind path captures the value across an
        // `.await` boundary in the sqlx INSERT call AND across the
        // tokio::spawn'd notifier fan-out. A refactor to `&'a str`
        // "for zero-alloc on the trim path" would introduce a
        // lifetime parameter that cascades through every consuming
        // `?`-chain. Pin the owned-String type via the canonical
        // require_string helper. Symmetric to round-181 + round-183
        // owned-String type pins extended to this canonical-JSON
        // builder's return type.
        let (path_params, body) = empty_maps();
        let s = canonical_request_json(
            "POST",
            "/gmail/v1/users/me/messages/send",
            "google",
            "gmail.messages.send",
            &path_params,
            &body,
        );
        fn require_string(_: &String) {}
        require_string(&s);
        // Sanity: also a non-empty owned String value.
        assert!(!s.is_empty());
    }

    #[test]
    fn blocked_action_record_static_borrow_is_send_sync_static_for_router_state_path() {
        // `BlockedActionRecord<'static>` flows through the adapter's
        // record-building call site that constructs the record from
        // 'static lifetime sources (test fixtures, const labels). The
        // existing `owned_blocked_notification_is_send_sync_static_for_tokio_spawn_boundary`
        // pins the Owned variant; pin the BORROWED 'static variant
        // here so a refactor that introduced a !Sync field on
        // BlockedActionRecord (e.g. `Cell<u32>` "for a per-row
        // counter") would surface at this file rather than at
        // hundreds of call sites. Symmetric to round-184 +
        // PicViolationRecord<'static> Send+Sync pin extended to
        // this sibling borrowed-Record type.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<BlockedActionRecord<'static>>();
    }

    #[test]
    fn blocked_action_record_requested_ops_field_is_borrowed_string_slice_type() {
        // `BlockedActionRecord.requested_ops: &'a [String]` —
        // borrowed slice, not owned Vec. The persist() bind path
        // calls `.bind(r.requested_ops)` which accepts `&[String]`
        // directly for the `text[]` Postgres column. A refactor to
        // `Vec<String>` "for ownership clarity" would force every
        // call site to clone the upstream Vec into the record.
        // Symmetric to round-184 PicViolationRecord borrowed-slice
        // pin extended to this sibling Record's requested_ops slice.
        fn require_slice_string(_: &[String]) {}
        let ops: Vec<String> = vec![
            "gmail:send:bob@external.com".into(),
            "gmail:send:eve@evil.example".into(),
        ];
        let r = BlockedActionRecord {
            request_id: Uuid::nil(),
            session_id: Uuid::nil(),
            p_0: None,
            vendor: "v",
            action: "a",
            method: "POST",
            path: "/x",
            layer: "policy",
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: &ops,
            escalation_after_minutes: None,
            request_canonical_json: None,
        };
        require_slice_string(r.requested_ops);
        // Zero-copy borrow — slice ptr equals the original Vec's
        // slice ptr.
        assert_eq!(r.requested_ops.as_ptr(), ops.as_ptr());
        assert_eq!(r.requested_ops.len(), 2);
    }

    #[test]
    fn owned_blocked_notification_as_borrowed_schema_field_is_static_str_lifetime() {
        // `OwnedBlockedNotification::as_borrowed()` sets
        // `schema: BlockedNotification::SCHEMA` — a `&'static str`
        // constant from notifier/mod.rs. Pin the static lifetime via
        // require_static_str so a refactor that swapped the schema
        // assignment to `self.schema.clone()` "for symmetry with the
        // other String fields" would silently promote the field to
        // an owned String AND drop the 'static lifetime contract
        // every webhook header propagation depends on. Symmetric to
        // round-172 + round-173 + round-174 static-str lifetime
        // pins extended to this as_borrowed schema field.
        fn require_static_str(_: &'static str) {}
        let ops = vec!["gmail:send:bob@external.com".to_string()];
        let n = BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("p1"),
            detail: Some("external recipient"),
            predecessor_pca_id: None,
            requested_ops: &ops,
            approve_url: "u/approve".into(),
            reject_url: "u/reject".into(),
        };
        let owned = OwnedBlockedNotification::from(&n);
        let borrowed = owned.as_borrowed();
        require_static_str(borrowed.schema);
        // Sanity: the schema string matches the canonical constant.
        assert_eq!(borrowed.schema, BlockedNotification::SCHEMA);
        assert_eq!(borrowed.schema, "proxilion.blocked_action.v1");
    }

    #[test]
    fn owned_blocked_notification_from_is_referentially_transparent_across_fifty_repeated_calls() {
        // `OwnedBlockedNotification::from(&n)` is a pure
        // borrowed-to-owned converter — no clock, no env, no global
        // state. Pin referential transparency across 50 back-to-back
        // calls on the same `BlockedNotification` source. A refactor
        // that introduced a per-call tag (e.g. an Instant-stamped
        // suffix added to the URL "for log correlation") would
        // silently make two calls diverge AND break webhook /
        // slack / email fan-out idempotency (each fan-out arm calls
        // from() independently). Symmetric to round-181 +
        // round-183 + round-185 referential-transparency pins
        // extended to this borrowed-to-owned converter.
        let ops = vec!["gmail:send:bob@external.com".to_string()];
        let id = Uuid::new_v4();
        let req = Uuid::new_v4();
        let session = Uuid::new_v4();
        let n = BlockedNotification {
            schema: BlockedNotification::SCHEMA,
            blocked_id: id,
            request_id: req,
            session_id: session,
            p_0: Some("alice@acme.com"),
            vendor: "google",
            action: "gmail.messages.send",
            method: "POST",
            path: "/gmail/v1/users/me/messages/send",
            layer: "policy",
            policy_id: Some("p1"),
            detail: Some("external recipient"),
            predecessor_pca_id: None,
            requested_ops: &ops,
            approve_url: "u/approve".into(),
            reject_url: "u/reject".into(),
        };
        let first = OwnedBlockedNotification::from(&n);
        for i in 1..50 {
            let next = OwnedBlockedNotification::from(&n);
            assert_eq!(
                next.blocked_id, first.blocked_id,
                "blocked_id diverged on call #{i}",
            );
            assert_eq!(next.vendor, first.vendor, "vendor diverged on call #{i}");
            assert_eq!(next.action, first.action, "action diverged on call #{i}");
            assert_eq!(next.method, first.method, "method diverged on call #{i}");
            assert_eq!(next.path, first.path, "path diverged on call #{i}");
            assert_eq!(next.layer, first.layer, "layer diverged on call #{i}");
            assert_eq!(
                next.approve_url, first.approve_url,
                "approve_url diverged on call #{i}",
            );
            assert_eq!(
                next.reject_url, first.reject_url,
                "reject_url diverged on call #{i}",
            );
            assert_eq!(
                next.requested_ops, first.requested_ops,
                "requested_ops diverged on call #{i}",
            );
        }
    }
}
