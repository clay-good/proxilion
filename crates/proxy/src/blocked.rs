//! Block-record persistence — adapters call into this when an action is
//! denied or shunted into the human-approval queue.
//!
//! Authority: spec.md §2.3, ui-less-surfaces.md §5/§8.

use sqlx::PgPool;
use uuid::Uuid;

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
}

pub async fn persist(db: &PgPool, r: BlockedActionRecord<'_>) {
    let res = sqlx::query(
        "INSERT INTO blocked_actions
            (request_id, session_id, p_0, vendor, action, method, path,
             layer, policy_id, detail, predecessor_pca_id, requested_ops)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
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
    .execute(db)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "failed to persist blocked_action");
    }
}
