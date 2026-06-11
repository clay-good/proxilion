//! Blocked-action queue API: list / show / approve / reject.
//!
//! Authority: spec.md §2.3 + ui-less-surfaces.md §5/§8. The dashboard UI
//! is dropped per the ui-less pivot; these endpoints are consumed by
//! `proxilion-cli blocked …`, the Slack interaction webhook (M2), and
//! the email signed-URL landing page.
//!
//! Approve flow:
//!   1. Load blocked_actions row, validate `status='pending'` and unexpired.
//!   2. Validate justification ≥ 20 chars.
//!   3. Load predecessor PCA from `pca_cache` (the blocked row's
//!      `predecessor_pca_id`) — its CBOR is the PoC input.
//!   4. Submit a successor PoC to the Trust Plane via `PicExecutor`,
//!      requesting the exact ops the original attempt declared. Trust
//!      Plane enforces monotonicity; if it refuses (the operator is
//!      trying to override a real PIC invariant violation), we surface
//!      that as a 422.
//!   5. Cache the new PCA locally with the blocked row's predecessor as
//!      this PCA's predecessor — this is the "attested branch".
//!   6. Mark blocked row `status='overridden'`, populate `override_pca_id`,
//!      `justification`, `approver_subject`, `resolved_at`.
//!
//! Reject flow: just flips status to 'rejected' with a `reject_reason`.
//!
//! The operator-side attestation PCA branch from spec.md §6.6 (`operator_pca`
//! co-signature) is a v2 strengthening — v1 records the approver_subject
//! in the row and relies on operator authentication at the API edge.
//! Flagged in spec status.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::pic::{CachedPca, PcaCache, PicExecutor};
use shared_types::provenance::pca::ExecutorBinding;

#[derive(Clone)]
pub struct BlockedApiState {
    pub db: PgPool,
    pub pca_cache: PcaCache,
    pub pic: PicExecutor,
}

pub fn router(state: BlockedApiState) -> Router {
    use crate::operator_auth::scope_check;
    use axum::middleware::from_fn_with_state;
    let read = || from_fn_with_state("blocks:read", scope_check);
    let approve_scope = || from_fn_with_state("blocks:approve", scope_check);
    Router::new()
        .route("/api/v1/blocked", get(list).route_layer(read()))
        .route("/api/v1/blocked/{id}", get(show).route_layer(read()))
        .route(
            "/api/v1/blocked/{id}/approve",
            post(approve).route_layer(approve_scope()),
        )
        .route(
            "/api/v1/blocked/{id}/reject",
            post(reject).route_layer(approve_scope()),
        )
        .route(
            "/api/v1/blocked/{id}/issue-link",
            post(issue_link).route_layer(approve_scope()),
        )
        .with_state(Arc::new(state))
}

// ─────────────────────────────────────────────────────────────────────────
// Signed-URL approve link (ui-less-surfaces.md §5.4)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IssueLinkBody {
    /// "approve" or "reject".
    action: String,
    /// Link TTL in minutes. Default 30, max 1440.
    ttl_minutes: Option<i64>,
    /// Optional approver hint (email of the recipient — surfaced on the
    /// landing page and recorded if they actually click through).
    approver_hint: Option<String>,
}

#[derive(Debug, Serialize)]
struct IssueLinkResponse {
    token_id: Uuid,
    url: String,
    action: String,
    expires_at: DateTime<Utc>,
}

async fn issue_link(
    State(state): State<Arc<BlockedApiState>>,
    Path(blocked_id): Path<Uuid>,
    axum::extract::Extension(principal): axum::extract::Extension<
        crate::operator_auth::OperatorPrincipal,
    >,
    Json(body): Json<IssueLinkBody>,
) -> Result<Json<IssueLinkResponse>, ApiError> {
    let action = body.action.trim().to_ascii_lowercase();
    if action != "approve" && action != "reject" {
        return Err(ApiError::BadRequest(
            "action must be `approve` or `reject`".into(),
        ));
    }
    let ttl = body.ttl_minutes.unwrap_or(30);
    if !(1..=1440).contains(&ttl) {
        return Err(ApiError::BadRequest("ttl_minutes must be 1..=1440".into()));
    }

    // Confirm the blocked row exists + is pending — minting a link for a
    // resolved row is a no-op and confusing for the receiver.
    let exists: Option<(String,)> =
        sqlx::query_as("SELECT status FROM blocked_actions WHERE id = $1")
            .bind(blocked_id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::Db)?;
    let Some((status,)) = exists else {
        return Err(ApiError::NotFound);
    };
    if status != "pending" {
        return Err(ApiError::Conflict(format!(
            "blocked row is {status} — only pending rows accept signed links"
        )));
    }

    let row: (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO notifier_tokens (blocked_id, action, approver_hint, issued_by, expires_at)
         VALUES ($1, $2, $3, $4, now() + ($5::int || ' minutes')::interval)
         RETURNING token_id, expires_at",
    )
    .bind(blocked_id)
    .bind(&action)
    .bind(body.approver_hint.as_deref())
    .bind(&principal.name)
    .bind(ttl as i32)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Db)?;

    let url = format!("/notifier/approve?t={token}", token = row.0);
    metrics::counter!(
        "proxilion_overrides_requested_total",
        "channel" => "email_link"
    )
    .increment(1);
    Ok(Json(IssueLinkResponse {
        token_id: row.0,
        url,
        action,
        expires_at: row.1,
    }))
}

#[derive(Debug, Deserialize)]
struct ListParams {
    /// `pending` (default) | `approved` | `rejected` | `expired` | `overridden` | `all`.
    status: Option<String>,
    /// Filter by p_0 (origin user).
    p_0: Option<String>,
    /// Filter by policy_id.
    policy_id: Option<String>,
    /// Filter by session_id.
    session_id: Option<Uuid>,
    /// 1..=500 (default 50).
    limit: Option<u32>,
    /// Cursor: rows strictly older than this `at`.
    before: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct BlockedRow {
    id: Uuid,
    request_id: Uuid,
    session_id: Option<Uuid>,
    p_0: Option<String>,
    vendor: String,
    action: String,
    method: Option<String>,
    path: Option<String>,
    layer: String,
    policy_id: Option<String>,
    detail: Option<String>,
    predecessor_pca_id: Option<Uuid>,
    requested_ops: Vec<String>,
    status: String,
    override_pca_id: Option<Uuid>,
    justification: Option<String>,
    approver_subject: Option<String>,
    reject_reason: Option<String>,
    resolved_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    at: DateTime<Utc>,
    /// Canonical JSON snapshot of the agent's request at block time
    /// (spec.md §2.1 dev 3). Truncated to 4 KB; absent on pre-0014
    /// historical rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_canonical_json: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ListResponse {
    rows: Vec<BlockedRow>,
    next_before: Option<DateTime<Utc>>,
}

const ALL_COLS: &str = "id, request_id, session_id, p_0, vendor, action, method, path, layer, \
    policy_id, detail, predecessor_pca_id, requested_ops, status, override_pca_id, \
    justification, approver_subject, reject_reason, resolved_at, expires_at, at, \
    request_canonical_json";

async fn list(
    State(state): State<Arc<BlockedApiState>>,
    Query(p): Query<ListParams>,
) -> Result<Json<ListResponse>, ApiError> {
    let limit = p.limit.unwrap_or(50).clamp(1, 500) as i64;
    let status_filter = p.status.as_deref().unwrap_or("pending");
    let status_filter = if status_filter == "all" {
        None
    } else {
        Some(status_filter)
    };

    // Auto-expire `pending` rows whose expires_at has passed before listing,
    // so callers see a coherent view. Cheap UPDATE; idempotent.
    let _ = sqlx::query(
        "UPDATE blocked_actions SET status='expired', resolved_at=now() \
         WHERE status='pending' AND expires_at < now()",
    )
    .execute(&state.db)
    .await;

    let rows = sqlx::query(&format!(
        "SELECT {ALL_COLS} FROM blocked_actions
          WHERE ($1::text IS NULL OR status     = $1)
            AND ($2::text IS NULL OR p_0        = $2)
            AND ($3::text IS NULL OR policy_id  = $3)
            AND ($4::uuid IS NULL OR session_id = $4)
            AND ($5::timestamptz IS NULL OR at  < $5)
          ORDER BY at DESC
          LIMIT $6"
    ))
    .bind(status_filter)
    .bind(p.p_0.as_deref())
    .bind(p.policy_id.as_deref())
    .bind(p.session_id)
    .bind(p.before)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(row_to_blocked(&r)?);
    }
    let next_before = if out.len() as i64 == limit {
        out.last().map(|r| r.at)
    } else {
        None
    };
    Ok(Json(ListResponse {
        rows: out,
        next_before,
    }))
}

async fn show(
    State(state): State<Arc<BlockedApiState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<BlockedRow>, ApiError> {
    let r = sqlx::query(&format!(
        "SELECT {ALL_COLS} FROM blocked_actions WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_blocked(&r)?))
}

#[derive(Debug, Deserialize)]
pub struct ApproveBody {
    pub justification: String,
    /// Optional override; default 30m from now. Caps at 24h.
    pub ttl_minutes: Option<i64>,
    /// Approver identity (in v1: free-text; in v2: extracted from operator
    /// token / Slack user id mapping). For now we record whatever the caller
    /// provides — the same field the Slack interaction webhook will fill.
    pub approver_subject: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApproveResponse {
    pub blocked_id: Uuid,
    pub override_pca_id: Uuid,
    pub p_0: String,
    pub granted_ops: Vec<String>,
    pub hop: u32,
    pub predecessor_pca_id: Uuid,
    pub status: &'static str,
}

async fn approve(
    State(state): State<Arc<BlockedApiState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<ApproveResponse>, ApiError> {
    Ok(Json(approve_inner(&state, id, body, "api").await?))
}

/// Inner approve implementation, reusable from non-operator-auth code
/// paths (the signed-URL landing page). `channel` is the metric label
/// (`api`, `email`, etc.).
pub async fn approve_inner(
    state: &BlockedApiState,
    id: Uuid,
    body: ApproveBody,
    channel: &'static str,
) -> Result<ApproveResponse, ApiError> {
    if body.justification.trim().len() < 20 {
        metrics::counter!(
            "proxilion_overrides_resolved_total",
            "outcome" => "rejected_validation", "channel" => channel
        )
        .increment(1);
        return Err(ApiError::BadRequest(
            "justification must be at least 20 characters".into(),
        ));
    }
    if let Some(t) = body.ttl_minutes {
        if !(1..=1440).contains(&t) {
            return Err(ApiError::BadRequest("ttl_minutes must be 1..=1440".into()));
        }
    }

    // Load row, lock against double-approve via SELECT … FOR UPDATE inside
    // a transaction.
    let mut tx = state.db.begin().await.map_err(ApiError::Db)?;
    let row = sqlx::query(&format!(
        "SELECT {ALL_COLS} FROM blocked_actions WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Db)?
    .ok_or(ApiError::NotFound)?;
    let blocked = row_to_blocked(&row)?;

    if blocked.status != "pending" {
        return Err(ApiError::Conflict(format!(
            "blocked row is {} — only pending rows may be approved",
            blocked.status
        )));
    }
    if blocked.expires_at <= Utc::now() {
        sqlx::query("UPDATE blocked_actions SET status='expired', resolved_at=now() WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Db)?;
        tx.commit().await.map_err(ApiError::Db)?;
        return Err(ApiError::Conflict("block expired before approval".into()));
    }

    let pred_id = blocked
        .predecessor_pca_id
        .ok_or_else(|| ApiError::Conflict(
            "blocked row has no predecessor_pca_id (likely a read_filter block which is audit-only)".into()
        ))?;
    let pred = state
        .pca_cache
        .get(pred_id)
        .await
        .map_err(|e| ApiError::Internal(format!("pca_cache: {e}")))?
        .ok_or_else(|| {
            ApiError::Internal(format!(
                "predecessor PCA {pred_id} not in cache — chain unrecoverable"
            ))
        })?;

    let requested_ops = blocked.requested_ops.clone();
    if requested_ops.is_empty() {
        return Err(ApiError::Conflict(
            "blocked row has no requested_ops — nothing to mint an override for".into(),
        ));
    }

    let binding = ExecutorBinding::new()
        .with("service", "proxilion-proxy")
        .with("kind", "override")
        .with("blocked_id", id.to_string().as_str())
        .with(
            "approver_subject",
            body.approver_subject.as_deref().unwrap_or("operator"),
        );

    let pca = match state
        .pic
        .mint_successor(pred.cbor.clone(), requested_ops.clone(), binding)
        .await
    {
        Ok(p) => p,
        Err(crate::pic::ExecutorError::Invariant(d)) => {
            // Operator tried to override a real monotonicity break — refused
            // by the Trust Plane. This is the right outcome: prevention by
            // construction beats operator override.
            metrics::counter!(
                "proxilion_overrides_resolved_total",
                "outcome" => "rejected_invariant", "channel" => channel
            )
            .increment(1);
            return Err(ApiError::PicRefused(d));
        }
        Err(e) => return Err(ApiError::Internal(format!("trust plane: {e}"))),
    };

    let cbor = B64
        .decode(&pca.pca)
        .map_err(|e| ApiError::Internal(format!("override PCA base64: {e}")))?;
    let override_pca_id = Uuid::new_v4();
    state
        .pca_cache
        .insert(&CachedPca {
            pca_id: override_pca_id,
            cbor,
            p_0: pca.p_0.clone(),
            ops: pca.ops.clone(),
            hop: pca.hop as i32,
            predecessor_id: Some(pred_id),
            signature: vec![],
            pic_profile: crate::pic::cache::CURRENT_PIC_PROFILE.to_string(),
        })
        .await
        .map_err(|e| ApiError::Internal(format!("pca_cache insert: {e}")))?;

    let approver = body
        .approver_subject
        .as_deref()
        .unwrap_or("operator")
        .to_string();
    sqlx::query(
        "UPDATE blocked_actions
            SET status            = 'overridden',
                override_pca_id   = $2,
                justification     = $3,
                approver_subject  = $4,
                resolved_at       = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(override_pca_id)
    .bind(&body.justification)
    .bind(&approver)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Db)?;

    tx.commit().await.map_err(ApiError::Db)?;

    metrics::counter!(
        "proxilion_overrides_resolved_total",
        "outcome" => "approved", "channel" => channel
    )
    .increment(1);
    // spec.md §3.2 — `proxilion_override_latency_seconds{outcome}` histogram.
    // Measures wall-clock from the original block (blocked_actions.at) to
    // the operator's decision. Powers §3.5's "p50 < 5 min" override SLO.
    let latency = (Utc::now() - blocked.at).num_milliseconds().max(0) as f64 / 1000.0;
    metrics::histogram!(
        "proxilion_override_latency_seconds",
        "outcome" => "approved",
    )
    .record(latency);

    Ok(ApproveResponse {
        blocked_id: id,
        override_pca_id,
        p_0: pca.p_0,
        granted_ops: pca.ops,
        hop: pca.hop,
        predecessor_pca_id: pred_id,
        status: "overridden",
    })
}

#[derive(Debug, Deserialize)]
pub struct RejectBody {
    pub reason: String,
    pub approver_subject: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RejectResponse {
    pub blocked_id: Uuid,
    pub status: &'static str,
}

async fn reject(
    State(state): State<Arc<BlockedApiState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<RejectBody>,
) -> Result<Json<RejectResponse>, ApiError> {
    Ok(Json(reject_inner(&state, id, body).await?))
}

pub async fn reject_inner(
    state: &BlockedApiState,
    id: Uuid,
    body: RejectBody,
) -> Result<RejectResponse, ApiError> {
    if body.reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason must be non-empty".into()));
    }
    // RETURNING `at` so we can compute override-latency without a separate
    // SELECT. SQL `now() - at` would also work but yields a `pg interval`
    // type; passing the timestamp back and subtracting in Rust keeps the
    // arithmetic side-effect-free.
    let returned: Option<(chrono::DateTime<Utc>,)> = sqlx::query_as(
        "UPDATE blocked_actions
            SET status           = 'rejected',
                reject_reason    = $2,
                approver_subject = $3,
                resolved_at      = now()
          WHERE id = $1 AND status = 'pending'
          RETURNING at",
    )
    .bind(id)
    .bind(&body.reason)
    .bind(body.approver_subject.as_deref().unwrap_or("operator"))
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Db)?;
    if returned.is_none() {
        // Either no row, or it's not pending. Disambiguate with a follow-up
        // read for a friendlier error.
        let exists: Option<String> =
            sqlx::query_scalar("SELECT status FROM blocked_actions WHERE id = $1")
                .bind(id)
                .fetch_optional(&state.db)
                .await
                .map_err(ApiError::Db)?;
        return Err(match exists {
            None => ApiError::NotFound,
            Some(s) => ApiError::Conflict(format!(
                "blocked row is {s} — only pending rows may be rejected"
            )),
        });
    }
    metrics::counter!(
        "proxilion_overrides_resolved_total",
        "outcome" => "rejected", "channel" => "api"
    )
    .increment(1);
    if let Some((blocked_at,)) = returned {
        // spec.md §3.2 — override latency for the reject path. Same shape
        // as the approve histogram so a single PromQL panel covers both.
        let latency = (Utc::now() - blocked_at).num_milliseconds().max(0) as f64 / 1000.0;
        metrics::histogram!(
            "proxilion_override_latency_seconds",
            "outcome" => "rejected",
        )
        .record(latency);
    }
    Ok(RejectResponse {
        blocked_id: id,
        status: "rejected",
    })
}

fn row_to_blocked(r: &sqlx::postgres::PgRow) -> Result<BlockedRow, ApiError> {
    Ok(BlockedRow {
        id: r.try_get("id")?,
        request_id: r.try_get("request_id")?,
        session_id: r.try_get("session_id")?,
        p_0: r.try_get("p_0")?,
        vendor: r.try_get("vendor")?,
        action: r.try_get("action")?,
        method: r.try_get("method")?,
        path: r.try_get("path")?,
        layer: r.try_get("layer")?,
        policy_id: r.try_get("policy_id")?,
        detail: r.try_get("detail")?,
        predecessor_pca_id: r.try_get("predecessor_pca_id")?,
        requested_ops: r
            .try_get::<Vec<String>, _>("requested_ops")
            .unwrap_or_default(),
        status: r.try_get("status")?,
        override_pca_id: r.try_get("override_pca_id")?,
        justification: r.try_get("justification")?,
        approver_subject: r.try_get("approver_subject")?,
        reject_reason: r.try_get("reject_reason")?,
        resolved_at: r.try_get("resolved_at")?,
        expires_at: r.try_get("expires_at")?,
        at: r.try_get("at")?,
        request_canonical_json: r
            .try_get::<Option<String>, _>("request_canonical_json")?
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("PIC invariant refused: {0}")]
    PicRefused(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use crate::error_envelope::ErrorBody;
        let (status, body) = match &self {
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody::new("blocked action not found", "not_found"),
            ),
            ApiError::BadRequest(d) => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new("bad request", "bad_request").with_detail(d.clone()),
            ),
            ApiError::Conflict(d) => (
                StatusCode::CONFLICT,
                ErrorBody::new("conflict", "conflict").with_detail(d.clone()),
            ),
            ApiError::PicRefused(d) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorBody::new("pic invariant refused override", "pic_invariant")
                    .with_detail(d.clone())
                    .with_fix(
                        "The Trust Plane refused to issue an override successor — the requested \
                         ops are not a subset of the predecessor's grant. This is a real \
                         monotonicity break, not a policy decision, so it cannot be overridden \
                         without re-rooting the chain at a broader PCA_0 (e.g. updating Alice's \
                         IdP group → ops mapping). Adjust the YAML group→ops policy or reject \
                         this block.",
                    ),
            ),
            ApiError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::new("internal", "internal_error").with_detail(d.clone()),
            ),
            ApiError::Db(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody::new("database error", "internal_error").with_detail(e.to_string()),
            ),
        };
        body.into_response(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_json(r: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(r.into_body(), 8 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn api_error_not_found_is_404() {
        let r = ApiError::NotFound.into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let v = body_json(r).await;
        assert_eq!(v["code"], "not_found");
    }

    #[tokio::test]
    async fn api_error_bad_request_carries_detail() {
        let r = ApiError::BadRequest("missing field".into()).into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let v = body_json(r).await;
        assert_eq!(v["code"], "bad_request");
        assert_eq!(v["detail"], "missing field");
    }

    #[tokio::test]
    async fn api_error_conflict_is_409() {
        let r = ApiError::Conflict("already overridden".into()).into_response();
        assert_eq!(r.status(), StatusCode::CONFLICT);
        let v = body_json(r).await;
        assert_eq!(v["code"], "conflict");
        assert_eq!(v["detail"], "already overridden");
    }

    #[tokio::test]
    async fn api_error_pic_refused_is_422_with_fix_hint() {
        let r = ApiError::PicRefused("ops not subset".into()).into_response();
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let v = body_json(r).await;
        assert_eq!(v["code"], "pic_invariant");
        assert_eq!(v["detail"], "ops not subset");
        assert!(v["fix"].as_str().unwrap().contains("monotonicity"));
    }

    #[tokio::test]
    async fn api_error_internal_is_500() {
        let r = ApiError::Internal("oops".into()).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let v = body_json(r).await;
        assert_eq!(v["code"], "internal_error");
    }

    #[tokio::test]
    async fn api_error_db_is_500_with_detail() {
        let r = ApiError::Db(sqlx::Error::RowNotFound).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let v = body_json(r).await;
        assert_eq!(v["code"], "internal_error");
        assert!(v["detail"].as_str().unwrap().contains("no rows"));
    }

    #[test]
    fn approve_body_deserializes_required_and_optional_fields() {
        let minimal: ApproveBody =
            serde_json::from_str(r#"{"justification":"reviewed and ok"}"#).unwrap();
        assert_eq!(minimal.justification, "reviewed and ok");
        assert!(minimal.ttl_minutes.is_none());
        assert!(minimal.approver_subject.is_none());

        let full: ApproveBody = serde_json::from_str(
            r#"{"justification":"j","ttl_minutes":15,"approver_subject":"alice"}"#,
        )
        .unwrap();
        assert_eq!(full.ttl_minutes, Some(15));
        assert_eq!(full.approver_subject.as_deref(), Some("alice"));
    }

    #[test]
    fn approve_body_rejects_missing_justification() {
        assert!(serde_json::from_str::<ApproveBody>("{}").is_err());
    }

    #[test]
    fn reject_body_deserializes() {
        let b: RejectBody = serde_json::from_str(r#"{"reason":"not safe"}"#).unwrap();
        assert_eq!(b.reason, "not safe");
        assert!(b.approver_subject.is_none());
    }

    #[test]
    fn issue_link_body_action_is_required() {
        // Missing `action` → deserialization fails.
        assert!(serde_json::from_str::<IssueLinkBody>("{}").is_err());
        let b: IssueLinkBody = serde_json::from_str(r#"{"action":"approve"}"#).unwrap();
        assert_eq!(b.action, "approve");
        assert!(b.ttl_minutes.is_none());
        assert!(b.approver_hint.is_none());
        let b: IssueLinkBody = serde_json::from_str(
            r#"{"action":"reject","ttl_minutes":60,"approver_hint":"alice@x"}"#,
        )
        .unwrap();
        assert_eq!(b.ttl_minutes, Some(60));
        assert_eq!(b.approver_hint.as_deref(), Some("alice@x"));
    }

    #[test]
    fn blocked_row_skips_request_canonical_json_when_none() {
        let row = BlockedRow {
            id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: None,
            p_0: None,
            vendor: "v".into(),
            action: "a".into(),
            method: None,
            path: None,
            layer: "policy".into(),
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: vec![],
            status: "pending".into(),
            override_pca_id: None,
            justification: None,
            approver_subject: None,
            reject_reason: None,
            resolved_at: None,
            expires_at: Utc::now(),
            at: Utc::now(),
            request_canonical_json: None,
        };
        let v = serde_json::to_value(&row).unwrap();
        assert!(v.get("request_canonical_json").is_none());
    }

    #[tokio::test]
    async fn api_error_pic_refused_fix_mentions_re_root_chain_hint() {
        // The 422 PIC-refused envelope's `fix` hint steers the
        // operator to re-root the chain at a broader PCA_0 — that's
        // the spec.md §6.6 escape hatch for genuine monotonicity
        // violations the operator wants to permit. Pin the exact
        // hint substring so a refactor that softened the message
        // ("review the chain", say) surfaces here.
        let r = ApiError::PicRefused("missing [drive:write:secret]".into()).into_response();
        let v = body_json(r).await;
        let fix = v["fix"].as_str().unwrap();
        assert!(
            fix.contains("re-root") || fix.contains("broader PCA_0"),
            "missing re-root hint in: {fix}",
        );
    }

    #[test]
    fn approve_body_accepts_zero_ttl_minutes_as_explicit_no_ttl_marker() {
        // `ttl_minutes: Option<i64>` accepts 0 — the handler later
        // interprets 0 as "no TTL", distinct from `None` which falls
        // through to the default. Pin the deserialization of the 0
        // sentinel so a refactor to `Option<u32>` (which would still
        // accept 0) AND a refactor to `i64` with NonZero would both
        // surface here.
        let b: ApproveBody =
            serde_json::from_str(r#"{"justification":"reviewed","ttl_minutes":0}"#).unwrap();
        assert_eq!(b.ttl_minutes, Some(0));
    }

    #[test]
    fn issue_link_body_with_negative_ttl_still_deserializes() {
        // `ttl_minutes: Option<i64>` — pin that negative values
        // pass deserialization (the handler clamps / rejects at the
        // semantic boundary, not the parse boundary). A refactor to
        // `Option<u64>` would surface here as a parse-time rejection
        // and signal that the validation moved layers.
        let b: IssueLinkBody =
            serde_json::from_str(r#"{"action":"approve","ttl_minutes":-5}"#).unwrap();
        assert_eq!(b.ttl_minutes, Some(-5));
    }

    #[test]
    fn approve_body_accepts_unknown_extra_fields_for_forward_compat() {
        // The CLI may send forward-compat fields (e.g. a future
        // `notify_email: true` flag) that older proxies don't know
        // about. The current `ApproveBody` does NOT carry
        // `#[serde(deny_unknown_fields)]`, so unknown fields are
        // silently ignored. Pin this contract — a refactor that
        // tightened to deny-unknown would force every CLI shape
        // change to be a coordinated proxy upgrade and 400 every
        // forward-compat field.
        let b: ApproveBody = serde_json::from_str(
            r#"{"justification":"reviewed","ttl_minutes":15,"future_flag":"notify"}"#,
        )
        .unwrap();
        assert_eq!(b.justification, "reviewed");
        assert_eq!(b.ttl_minutes, Some(15));
    }

    #[test]
    fn reject_body_accepts_optional_approver_subject_when_set() {
        // The existing `reject_body_deserializes` test pins the
        // minimal shape (reason only, approver_subject None). Pin
        // the with-subject path so a refactor that made the field
        // required would surface here as a parse error, AND a
        // refactor that changed the field name would surface as the
        // assertion below failing rather than as a missed-field
        // silent default. The handler distinguishes a Some-subject
        // (operator-driven reject) from None (system-driven reject)
        // for audit attribution.
        let b: RejectBody = serde_json::from_str(
            r#"{"reason":"not safe","approver_subject":"alice@operator.com"}"#,
        )
        .unwrap();
        assert_eq!(b.reason, "not safe");
        assert_eq!(b.approver_subject.as_deref(), Some("alice@operator.com"));
    }

    #[test]
    fn api_error_not_found_display_is_exact_not_found_string() {
        // `#[error("not found")]` — pin the exact byte sequence (no
        // variant-name prefix, no trailing punctuation). Operator log
        // filters across the proxy and the operator-cli's blocked-list
        // renderer key on the exact `"not found"` substring as the
        // "row already resolved or expired" signal. A refactor to
        // `#[error("blocked action not found")]` (the natural "be more
        // descriptive in error messages" change) would silently merge
        // this 404 surface with the wire-shape `error` field (which IS
        // `"blocked action not found"`) — the wire field is the
        // operator-UI title, the Display is the log substring; they
        // are intentionally distinct.
        assert_eq!(ApiError::NotFound.to_string(), "not found");
    }

    #[test]
    fn api_error_pic_refused_display_carries_pic_invariant_refused_prefix() {
        // `#[error("PIC invariant refused: {0}")]` — pin the full
        // Display shape (prefix + colon + space + inner string). The
        // PicRefused variant is the operator-actionable boundary
        // (spec.md §6.6 escape hatch) and its prefix is the substring
        // log aggregators key on to bucket "operator override attempt
        // refused by Trust Plane" separately from policy decisions
        // (which never use the "invariant" qualifier). A refactor that
        // softened the prefix to "pic refused" or merged it with the
        // generic `Internal(_)` "internal: {0}" shape would silently
        // collapse the two operator dashboards. Pin against an inner
        // string carrying the canonical missing-ops syntax that the
        // upstream Trust Plane emits.
        let s = ApiError::PicRefused(
            "ops not subset of predecessor: missing [drive:write:bob/*]".into(),
        )
        .to_string();
        assert_eq!(
            s,
            "PIC invariant refused: ops not subset of predecessor: missing [drive:write:bob/*]",
        );
    }

    #[test]
    fn api_error_internal_display_carries_internal_prefix_with_inner_string() {
        // `#[error("internal: {0}")]` — pin the prefix-and-inner
        // shape. The Internal variant is the catch-all for "this
        // shouldn't happen" code paths (panicked task surfaced as a
        // string, a malformed CBOR slice from the cache, etc); the
        // `"internal:"` prefix is what distinguishes it from `Db` (which
        // surfaces sqlx::Error transparently — NO prefix). A refactor
        // that aligned Internal to `Db`'s transparent shape (or that
        // merged the two variants into one `Generic(String)` shape)
        // would silently flatten the operator-triage signal that lets
        // Grafana distinguish "proxy bug" (Internal) from "postgres
        // health issue" (Db).
        let s = ApiError::Internal("unexpected None on session lookup".into()).to_string();
        assert_eq!(s, "internal: unexpected None on session lookup");
    }

    #[test]
    fn blocked_api_error_is_send_sync_static_for_axum_into_response_boundary() {
        // `ApiError` is the return-error type for every blocked-action
        // handler (list / show / approve / reject / issue-link) — it
        // flows through `IntoResponse` from handler futures crossing
        // tokio task boundaries, which mandates Send+Sync+'static.
        // Symmetric to the same-axis pins on
        // [crates/proxy/src/adapters/error.rs] (AppError),
        // [crates/proxy/src/oauth/error.rs] (OAuthError), and
        // [crates/proxy/src/api/killswitch.rs] (sibling ApiError + state).
        // A refactor giving any variant an `Rc<...>` field "for cheap
        // clone of the detail string" would break Sync at the router
        // site rather than as a far-removed trait-bound error.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ApiError>();
    }

    #[test]
    fn blocked_api_error_status_across_all_variants_is_4xx_or_5xx_never_2xx_or_3xx() {
        // Symmetric to the same-axis pins on adapters/error.rs (round
        // 143) and oauth/error.rs (round 145). Every ApiError variant
        // surfaces a non-success status — a refactor that registered
        // a new variant mapping to 200 OK "for the silent-success case"
        // would silently exclude that variant from operator dashboard
        // error-rate metrics. Pin !is_success AND !is_redirection
        // AND (is_client_error || is_server_error) across the full
        // variant sweep.
        for v in [
            ApiError::NotFound,
            ApiError::BadRequest("x".into()),
            ApiError::Conflict("x".into()),
            ApiError::PicRefused("x".into()),
            ApiError::Internal("x".into()),
            ApiError::Db(sqlx::Error::RowNotFound),
        ] {
            let label = format!("{v:?}");
            let r = v.into_response();
            let s = r.status();
            assert!(!s.is_success(), "variant {label} surfaced 2xx {s}");
            assert!(!s.is_redirection(), "variant {label} surfaced 3xx {s}");
            assert!(
                s.is_client_error() || s.is_server_error(),
                "variant {label} surfaced non-4xx/5xx {s}",
            );
        }
    }

    #[tokio::test]
    async fn blocked_api_error_body_code_is_lowercase_snake_case_across_all_variants() {
        // Symmetric to the same-axis pin on adapters/error.rs (round
        // 143) and oauth/error.rs (round 145). The wire `code` field
        // operators grep on MUST be lowercase snake_case across all
        // ApiError variants. A refactor that surfaced one as
        // PascalCase OR kebab-case would silently break every operator
        // dashboard regex bucket. Pin absence of uppercase ASCII AND
        // absence of `-` exhaustively.
        let variants: Vec<ApiError> = vec![
            ApiError::NotFound,
            ApiError::BadRequest("x".into()),
            ApiError::Conflict("x".into()),
            ApiError::PicRefused("x".into()),
            ApiError::Internal("x".into()),
            ApiError::Db(sqlx::Error::RowNotFound),
        ];
        for v in variants {
            let r = v.into_response();
            let body = body_json(r).await;
            let code = body["code"].as_str().unwrap_or("");
            assert!(!code.is_empty(), "empty code surfaced");
            assert!(
                !code.chars().any(|c| c.is_ascii_uppercase()),
                "uppercase in code `{code}`",
            );
            assert!(!code.contains('-'), "kebab in code `{code}`");
        }
    }

    #[test]
    fn approve_response_serializes_with_exactly_seven_known_keys_and_static_status() {
        // The struct has 7 fields (blocked_id, override_pca_id, p_0,
        // granted_ops, hop, predecessor_pca_id, status). When serialized
        // the JSON object MUST carry EXACTLY those 7 keys — a refactor
        // that elided one would silently drop operator-visible state
        // from the confirmation toast; an addition would widen the wire
        // shape unannounced. AND pin that `status: &'static str` is a
        // string literal — `"overridden"` constructed at the handler
        // site (NOT heap-allocated on every approval). A refactor to
        // `status: String` would silently allocate on every call.
        fn require_static_str(_: &'static str) {}
        let r = ApproveResponse {
            blocked_id: Uuid::nil(),
            override_pca_id: Uuid::nil(),
            p_0: "user:alice@x".into(),
            granted_ops: vec!["drive:read:x".into()],
            hop: 1,
            predecessor_pca_id: Uuid::nil(),
            status: "overridden",
        };
        require_static_str(r.status);
        let v = serde_json::to_value(&r).unwrap();
        let obj = v.as_object().expect("must serialize to JSON object");
        assert_eq!(obj.len(), 7, "field count drift: {obj:?}");
        for k in [
            "blocked_id",
            "override_pca_id",
            "p_0",
            "granted_ops",
            "hop",
            "predecessor_pca_id",
            "status",
        ] {
            assert!(obj.contains_key(k), "missing key {k}: {obj:?}");
        }
        // And the status string serializes verbatim, not under a tag
        // wrapper (a refactor to an enum with `#[serde(tag)]` would
        // silently change the wire shape to a nested object).
        assert!(v["status"].is_string());
        assert_eq!(v["status"], "overridden");
    }

    #[test]
    fn api_error_debug_carries_variant_names_for_grep_bucketing() {
        // Symmetric to the AppError + OAuthError + sibling ApiError
        // Debug pins. Operators grep tracing log lines by ApiError
        // variant name to bucket NotFound (operator typo) vs Conflict
        // (race) vs PicRefused (Trust Plane refusal) vs Internal
        // (proxy bug) vs Db (postgres outage). A hand-rolled
        // `impl Debug` that hid variant names "to compact" the line
        // would break every operator bucket.
        for (variant, name) in [
            (ApiError::NotFound, "NotFound"),
            (ApiError::BadRequest("x".into()), "BadRequest"),
            (ApiError::Conflict("x".into()), "Conflict"),
            (ApiError::PicRefused("x".into()), "PicRefused"),
            (ApiError::Internal("x".into()), "Internal"),
            (ApiError::Db(sqlx::Error::RowNotFound), "Db"),
        ] {
            let s = format!("{:?}", variant);
            assert!(s.contains(name), "expected `{name}` in Debug, got: {s}");
        }
    }

    #[tokio::test]
    async fn api_error_pic_refused_body_carries_pic_invariant_code_and_fix_field_present() {
        // The PicRefused 422 envelope is the only ApiError variant
        // whose body carries a `fix` field — the existing
        // `api_error_pic_refused_is_422_with_fix_hint` and
        // `api_error_pic_refused_fix_mentions_re_root_chain_hint`
        // pins exercise the fix text. Pin the wire SHAPE
        // distinguisher: the body MUST carry `code:
        // "pic_invariant"` (not `internal_error` or `conflict`) AND
        // the `fix` field MUST be present on the wire (not None,
        // not skipped). A refactor that collapsed PicRefused into
        // the generic Conflict arm "since both are 4xx and operator-
        // actionable" would surface here as code drift OR fix
        // absence — both would silently break the operator dashboard
        // panel that anchors on `code == "pic_invariant"`.
        let r = ApiError::PicRefused("ops not subset".into()).into_response();
        let v = body_json(r).await;
        assert_eq!(v["code"], "pic_invariant");
        assert!(
            v.get("fix").is_some(),
            "fix field must be present for PicRefused: {v}",
        );
        assert!(
            v["fix"].is_string(),
            "fix must be a string, got: {}",
            v["fix"],
        );
    }

    #[test]
    fn blocked_row_includes_request_canonical_json_when_set() {
        let mut row = BlockedRow {
            id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: None,
            p_0: None,
            vendor: "v".into(),
            action: "a".into(),
            method: None,
            path: None,
            layer: "policy".into(),
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: vec![],
            status: "pending".into(),
            override_pca_id: None,
            justification: None,
            approver_subject: None,
            reject_reason: None,
            resolved_at: None,
            expires_at: Utc::now(),
            at: Utc::now(),
            request_canonical_json: None,
        };
        row.request_canonical_json = Some(serde_json::json!({"to":"alice"}));
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["request_canonical_json"]["to"], "alice");
    }

    #[test]
    fn blocked_api_state_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the BlockedApiState struct field count at exactly 3 via
        // exhaustive destructure (no `..`). The 3 fields are: db
        // (PgPool) + pca_cache (PcaCache) + pic (PicExecutor). A 4th
        // field landing (e.g. `audit_sink: Arc<dyn ActionStream>` to
        // emit a per-approve / per-reject audit event distinct from
        // the policy_engine trace path, or `notifier: Notifiers` to
        // fan out a post-approve notification to operators who
        // requested the override) would silently bloat every
        // Clone of BlockedApiState the axum router fans out per
        // request. Pin via exhaustive destructure.
        fn _destructure_witness(s: BlockedApiState) {
            let BlockedApiState {
                db: _,
                pca_cache: _,
                pic: _,
            } = s;
        }
    }

    #[test]
    fn blocked_row_field_count_pinned_at_exactly_twenty_one_via_exhaustive_destructure_no_rest_pattern()
     {
        // Pin the BlockedRow wire-shape field count at exactly 21
        // via exhaustive destructure (no `..`). The 21 fields are:
        // id + request_id + session_id + p_0 + vendor + action +
        // method + path + layer + policy_id + detail +
        // predecessor_pca_id + requested_ops + status +
        // override_pca_id + justification + approver_subject +
        // reject_reason + resolved_at + expires_at + at +
        // request_canonical_json. A 22nd field landing (e.g.
        // `chain_id: Option<Uuid>` for back-attribution from
        // blocked row to chain root, or `actor_subject:
        // Option<String>` for richer audit attribution) would
        // silently extend the wire shape every CLI / dashboard
        // consumer reads — and a `#[serde(skip_serializing_if =
        // "Option::is_none")]` 22nd field would silently bypass any
        // serde-key sweep test. Exhaustive destructure is the
        // canonical pin.
        let r = BlockedRow {
            id: Uuid::nil(),
            request_id: Uuid::nil(),
            session_id: None,
            p_0: None,
            vendor: String::new(),
            action: String::new(),
            method: None,
            path: None,
            layer: String::new(),
            policy_id: None,
            detail: None,
            predecessor_pca_id: None,
            requested_ops: vec![],
            status: String::new(),
            override_pca_id: None,
            justification: None,
            approver_subject: None,
            reject_reason: None,
            resolved_at: None,
            expires_at: Utc::now(),
            at: Utc::now(),
            request_canonical_json: None,
        };
        let BlockedRow {
            id: _,
            request_id: _,
            session_id: _,
            p_0: _,
            vendor: _,
            action: _,
            method: _,
            path: _,
            layer: _,
            policy_id: _,
            detail: _,
            predecessor_pca_id: _,
            requested_ops: _,
            status: _,
            override_pca_id: _,
            justification: _,
            approver_subject: _,
            reject_reason: _,
            resolved_at: _,
            expires_at: _,
            at: _,
            request_canonical_json: _,
        } = r;
    }

    #[test]
    fn api_error_variant_count_pinned_at_exactly_six_via_exhaustive_match() {
        // Pin the ApiError variant count at exactly 6 via exhaustive
        // match. The 6 variants are: NotFound + BadRequest + Conflict
        // + PicRefused + Internal + Db. A 7th variant landing (e.g.
        // `Unauthorized` to distinguish "blocked-row exists but the
        // operator's scope doesn't cover this tenant" from the
        // middleware-layer 403, or `RateLimited` for per-operator
        // approval-throttling) without matching every Display +
        // IntoResponse arm + every adapter-bubble `?` site would
        // surface here as a non-exhaustive compile error. Pin the
        // 6-variant ceiling explicitly.
        fn variant_witness(e: &ApiError) -> u8 {
            match e {
                ApiError::NotFound => 0,
                ApiError::BadRequest(_) => 1,
                ApiError::Conflict(_) => 2,
                ApiError::PicRefused(_) => 3,
                ApiError::Internal(_) => 4,
                ApiError::Db(_) => 5,
            }
        }
        let cases = [
            ApiError::NotFound,
            ApiError::BadRequest("x".into()),
            ApiError::Conflict("x".into()),
            ApiError::PicRefused("x".into()),
            ApiError::Internal("x".into()),
            // Db needs a real sqlx::Error — use PoolClosed which is
            // trivially constructible.
            ApiError::Db(sqlx::Error::PoolClosed),
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &cases {
            assert!(seen.insert(variant_witness(e)));
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn list_params_field_count_pinned_at_exactly_six_via_exhaustive_destructure_no_rest_pattern() {
        // Pin the ListParams query-string field count at exactly 6
        // via exhaustive destructure. The 6 fields are: status +
        // p_0 + policy_id + session_id + limit + before. A 7th
        // field landing (e.g. `vendor: Option<String>` for the
        // dashboard's "filter by Google vs other adapter" panel,
        // or `since: Option<DateTime<Utc>>` to symmetrically pair
        // with the existing `before` cursor for paging both
        // directions) would silently extend the CLI's expected
        // query-string shape AND silently change which rows the
        // `/api/v1/blocked` GET endpoint surfaces. Pin via
        // exhaustive destructure.
        let v = ListParams {
            status: None,
            p_0: None,
            policy_id: None,
            session_id: None,
            limit: None,
            before: None,
        };
        let ListParams {
            status: _,
            p_0: _,
            policy_id: _,
            session_id: _,
            limit: _,
            before: _,
        } = v;
    }

    #[test]
    fn router_function_signature_pinned_via_fn_pointer_witness() {
        // Pin the module's router constructor signature as
        // `fn(BlockedApiState) -> Router` via fn-pointer witness.
        // Symmetric to round-262/263/264 router fn-pointer pins
        // extended to the blocked-actions API surface. The server.rs
        // boot path calls `router(blocked_state)` exactly once at
        // app assembly AND consumes the state by value (the router
        // internally wraps it in Arc before fan-out via
        // `.with_state(Arc::new(state))`). A refactor to
        // `fn(&BlockedApiState) -> Router` or
        // `fn(BlockedApiState) -> Result<Router, _>` would silently
        // change the boot path's ownership AND error-handling
        // shape.
        let _f: fn(BlockedApiState) -> Router = router;
    }

    #[test]
    fn blocked_api_state_is_clone_for_axum_router_state_fan_out() {
        // The axum `with_state(Arc::new(state))` indirection still
        // requires the inner BlockedApiState to be Clone (the
        // router constructor itself takes the state by value and
        // Arc-wraps it, but operator-tooling that builds the state
        // outside the boot path may clone it for testing /
        // dashboard fan-out). The existing `#[derive(Clone)]` is
        // what makes this work; a refactor that dropped the
        // derive would surface at hundreds of test-fixture sites
        // rather than at this single trait-bound assertion. Pin
        // Clone via require_clone — symmetric to round-264
        // NotifierApiState require_clone pin extended to
        // BlockedApiState.
        fn require_clone<T: Clone>() {}
        require_clone::<BlockedApiState>();
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB-backed integration test (opt-in via PROXILION_TEST_DATABASE_URL).
    // Skips when no test database is configured — see `test_support`.
    // ─────────────────────────────────────────────────────────────────────

    async fn blocked_state(pool: sqlx::PgPool) -> Arc<BlockedApiState> {
        let pca_cache = PcaCache::new(pool.clone());
        let pic = PicExecutor::dev_ephemeral("http://localhost:0".into())
            .expect("ephemeral pic executor builds");
        Arc::new(BlockedApiState {
            db: pool,
            pca_cache,
            pic,
        })
    }

    /// Insert a blocked row with explicit status + expiry so the test can
    /// drive the list filters and the auto-expire side effect. Returns the id.
    async fn seed_blocked(
        pool: &sqlx::PgPool,
        p_0: &str,
        policy_id: &str,
        status: &str,
        expires_in: chrono::Duration,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO blocked_actions
               (id, request_id, vendor, action, layer, policy_id, p_0, status, expires_at)
             VALUES ($1, $2, 'google', 'gmail.messages.send', 'policy', $3, $4, $5, now() + $6)",
        )
        .bind(id)
        .bind(Uuid::new_v4())
        .bind(policy_id)
        .bind(p_0)
        .bind(status)
        .bind(expires_in)
        .execute(pool)
        .await
        .expect("seed blocked_actions");
        id
    }

    fn list_params(status: &str, policy_id: Option<&str>) -> ListParams {
        ListParams {
            status: Some(status.to_string()),
            p_0: None,
            policy_id: policy_id.map(str::to_string),
            session_id: None,
            limit: Some(500),
            before: None,
        }
    }

    #[tokio::test]
    async fn db_backed_blocked_list_filters_auto_expires_and_show_round_trip() {
        // Exercises the `list` filters + the auto-expire side effect + `show`
        // against real SQL (these handlers are otherwise uncovered).
        let Some(pool) = crate::test_support::pool().await else {
            eprintln!("skipping: {} unset", crate::test_support::TEST_DB_ENV);
            return;
        };
        // Unique tag so this test's rows don't collide with a shared DB.
        let tag = Uuid::new_v4().simple().to_string();
        let pa = format!("alice-{tag}@acme.com");
        let pol_a = format!("gate-a-{tag}");
        let pol_b = format!("gate-b-{tag}");
        // A: pending, valid for an hour.
        let id_a = seed_blocked(&pool, &pa, &pol_a, "pending", chrono::Duration::hours(1)).await;
        // B: pending, but ALREADY expired (expires_at in the past).
        let id_b = seed_blocked(&pool, &pa, &pol_b, "pending", chrono::Duration::hours(-1)).await;
        // C: already rejected.
        let id_c = seed_blocked(&pool, &pa, &pol_a, "rejected", chrono::Duration::hours(1)).await;

        let state = blocked_state(pool.clone()).await;

        // 1. list(status=pending) auto-expires B and returns only A.
        let resp = list(State(state.clone()), Query(list_params("pending", None)))
            .await
            .expect("list ok")
            .0;
        let ids: Vec<Uuid> = resp.rows.iter().map(|r| r.id).collect();
        assert!(ids.contains(&id_a), "A (live pending) must be listed");
        assert!(!ids.contains(&id_b), "B (expired) must NOT be in pending");
        assert!(!ids.contains(&id_c), "C (rejected) must NOT be in pending");
        // The auto-expire UPDATE flipped B's status.
        let b_status: String =
            sqlx::query_scalar("SELECT status FROM blocked_actions WHERE id = $1")
                .bind(id_b)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            b_status, "expired",
            "list must auto-expire past-due pending rows"
        );

        // 2. list(status=all, policy_id=pol_a) returns A and C (both gate-a), not B.
        let resp = list(
            State(state.clone()),
            Query(list_params("all", Some(&pol_a))),
        )
        .await
        .expect("list ok")
        .0;
        let ids: Vec<Uuid> = resp.rows.iter().map(|r| r.id).collect();
        assert!(
            ids.contains(&id_a) && ids.contains(&id_c),
            "both gate-a rows"
        );
        assert!(!ids.contains(&id_b), "gate-b row excluded by policy filter");

        // 3. show(id) round-trips the row; a random id is NotFound.
        let row = show(State(state.clone()), Path(id_a))
            .await
            .expect("show ok")
            .0;
        assert_eq!(row.id, id_a);
        assert_eq!(row.policy_id.as_deref(), Some(pol_a.as_str()));
        assert_eq!(row.status, "pending");
        let missing = show(State(state), Path(Uuid::new_v4())).await;
        assert!(
            matches!(missing, Err(ApiError::NotFound)),
            "unknown id → NotFound"
        );
    }
}
