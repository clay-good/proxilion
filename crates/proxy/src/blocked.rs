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
}

#[allow(dead_code)]
pub async fn persist(db: &PgPool, r: BlockedActionRecord<'_>) {
    let _ = persist_returning_id(db, &r).await;
}

/// Persist + optionally notify (ui-less-surfaces.md §10.3). Adapters use
/// this variant so the human-approval channel fires as soon as the row
/// commits. Notification is fire-and-forget — the request response and
/// the durable row never wait on the webhook receiver.
pub async fn persist_and_notify(
    db: &PgPool,
    notifiers: &Notifiers,
    r: BlockedActionRecord<'_>,
) {
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
             escalation_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                 CASE WHEN $13::bigint IS NULL THEN NULL
                      ELSE now() + ($13::bigint * interval '1 minute')
                 END)
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
