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
}
