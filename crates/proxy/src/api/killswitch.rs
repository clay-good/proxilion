//! Killswitch API.
//!
//! Authority: spec.md §3.2, ui-less-surfaces.md §4.1.
//!
//! Three scopes:
//!   * `session` — revoke a single bearer (= one OAuth session).
//!   * `user`    — revoke every bearer rooted at the given p_0.
//!   * `all`     — global stop. Revokes every non-revoked bearer.
//!
//! Each call marks rows in `agent_bearers` with `revoked_at = now()` so the
//! auth middleware rejects subsequent bearers (it already checks this
//! column at every request). Trust Plane `/revoke` is upstream-deferred —
//! the chain itself is not yet revoked, but the proxy refuses to act on
//! revoked bearers, which is the operator-meaningful guarantee for v1.
//!
//! Drain: in-flight requests are NOT actively aborted — they finish or
//! time out naturally (10s upstream timeout). The next request the same
//! bearer makes is rejected. This is the §3.2 v1 simplification (the
//! AbortHandle registry is a v2 hardening).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct KillswitchApiState {
    pub db: PgPool,
    /// In-process cache populated by every killswitch invocation so the
    /// bearer middleware can short-circuit subsequent reads without
    /// hitting the DB. spec.md §3.2 dev 2.
    pub kill_cache: crate::kill_cache::KillCache,
}

pub fn router(state: KillswitchApiState) -> Router {
    use crate::operator_auth::scope_check;
    use axum::middleware::from_fn_with_state;
    let kill = || from_fn_with_state("killswitch:revoke", scope_check);
    Router::new()
        .route(
            "/api/v1/killswitch/session/{id}",
            post(kill_session).route_layer(kill()),
        )
        .route(
            "/api/v1/killswitch/user/{p0}",
            post(kill_user).route_layer(kill()),
        )
        .route("/api/v1/killswitch/all", post(kill_all).route_layer(kill()))
        .with_state(Arc::new(state))
}

#[derive(Debug, Deserialize, Default)]
struct KillBody {
    reason: Option<String>,
    operator_subject: Option<String>,
    /// Required only by `/killswitch/all`; must equal "yes".
    confirm: Option<String>,
}

#[derive(Debug, Serialize)]
struct KillResponse {
    record_id: Uuid,
    scope: &'static str,
    target: String,
    bearers_revoked: i64,
    at: DateTime<Utc>,
}

async fn kill_session(
    State(state): State<Arc<KillswitchApiState>>,
    Path(id): Path<Uuid>,
    body: Option<Json<KillBody>>,
) -> Result<Json<KillResponse>, ApiError> {
    let body = body.map(|j| j.0).unwrap_or_default();
    let reason = body.reason.clone().unwrap_or_else(|| "killswitch".into());
    let hashes: Vec<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE agent_bearers
            SET revoked_at      = now(),
                revoked_reason  = $2
          WHERE session_id      = $1
            AND revoked_at IS NULL
        RETURNING bearer_sha256",
    )
    .bind(id)
    .bind(&reason)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = hashes.len() as i64;
    populate_kill_cache(&state.kill_cache, &hashes).await;
    Ok(Json(
        persist(
            &state.db,
            "session",
            &id.to_string(),
            &reason,
            body.operator_subject.as_deref(),
            n,
        )
        .await?,
    ))
}

async fn kill_user(
    State(state): State<Arc<KillswitchApiState>>,
    Path(p0): Path<String>,
    body: Option<Json<KillBody>>,
) -> Result<Json<KillResponse>, ApiError> {
    let body = body.map(|j| j.0).unwrap_or_default();
    let reason = body.reason.clone().unwrap_or_else(|| "killswitch".into());
    let hashes: Vec<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE agent_bearers ab
            SET revoked_at      = now(),
                revoked_reason  = $2
          FROM oauth_sessions os
         WHERE ab.session_id = os.id
           AND os.p_0        = $1
           AND ab.revoked_at IS NULL
        RETURNING ab.bearer_sha256",
    )
    .bind(&p0)
    .bind(&reason)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = hashes.len() as i64;
    populate_kill_cache(&state.kill_cache, &hashes).await;
    Ok(Json(
        persist(
            &state.db,
            "user",
            &p0,
            &reason,
            body.operator_subject.as_deref(),
            n,
        )
        .await?,
    ))
}

async fn kill_all(
    State(state): State<Arc<KillswitchApiState>>,
    body: Option<Json<KillBody>>,
) -> Result<Json<KillResponse>, ApiError> {
    let body = body.map(|j| j.0).unwrap_or_default();
    if body.confirm.as_deref() != Some("yes") {
        return Err(ApiError::BadRequest(
            "/killswitch/all requires { confirm: \"yes\" } in the body".into(),
        ));
    }
    let reason = body
        .reason
        .clone()
        .unwrap_or_else(|| "killswitch:all".into());
    let hashes: Vec<(Vec<u8>,)> = sqlx::query_as(
        "UPDATE agent_bearers
            SET revoked_at      = now(),
                revoked_reason  = $1
          WHERE revoked_at IS NULL
        RETURNING bearer_sha256",
    )
    .bind(&reason)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = hashes.len() as i64;
    populate_kill_cache(&state.kill_cache, &hashes).await;
    Ok(Json(
        persist(
            &state.db,
            "all",
            "*",
            &reason,
            body.operator_subject.as_deref(),
            n,
        )
        .await?,
    ))
}

/// Push `bearer_sha256` BYTEA values from a RETURNING result into the
/// in-process kill cache. Skips rows with the wrong length so a schema
/// drift can't poison the cache.
async fn populate_kill_cache(kc: &crate::kill_cache::KillCache, rows: &[(Vec<u8>,)]) {
    let mut buf: [u8; 32] = [0; 32];
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(rows.len());
    for (h,) in rows {
        if h.len() == 32 {
            buf.copy_from_slice(h);
            out.push(buf);
        }
    }
    kc.mark_many(out).await;
}

async fn persist(
    db: &PgPool,
    scope: &'static str,
    target: &str,
    reason: &str,
    operator: Option<&str>,
    bearers_revoked: i64,
) -> Result<KillResponse, ApiError> {
    let record_id: Uuid = sqlx::query_scalar(
        "INSERT INTO kill_records (scope, target, reason, operator_subject, bearers_revoked)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id",
    )
    .bind(scope)
    .bind(target)
    .bind(reason)
    .bind(operator)
    .bind(bearers_revoked as i32)
    .fetch_one(db)
    .await
    .map_err(ApiError::Db)?;
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT at FROM kill_records WHERE id = $1")
        .bind(record_id)
        .fetch_one(db)
        .await
        .map_err(ApiError::Db)?;
    metrics::counter!(
        "proxilion_killswitch_invocations_total",
        "scope" => scope.to_string()
    )
    .increment(1);
    metrics::counter!("proxilion_killswitch_revoked_capabilities_total")
        .increment(bearers_revoked as u64);
    Ok(KillResponse {
        record_id,
        scope,
        target: target.to_string(),
        bearers_revoked,
        at,
    })
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use crate::error_envelope::ErrorBody;
        let (status, body) = match &self {
            ApiError::BadRequest(d) => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new("bad request", "bad_request").with_detail(d.clone()),
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
    use crate::kill_cache::KillCache;

    #[tokio::test]
    async fn populate_kill_cache_marks_correctly_sized_rows() {
        let kc = KillCache::new();
        let rows = vec![([1u8; 32].to_vec(),), ([2u8; 32].to_vec(),)];
        populate_kill_cache(&kc, &rows).await;
        assert!(kc.is_killed(&[1u8; 32]).await);
        assert!(kc.is_killed(&[2u8; 32]).await);
        assert!(!kc.is_killed(&[3u8; 32]).await);
    }

    #[tokio::test]
    async fn populate_kill_cache_skips_wrong_length_rows() {
        let kc = KillCache::new();
        // 31 bytes (too short) + 33 bytes (too long) + 32 bytes (valid).
        let rows = vec![(vec![9u8; 31],), (vec![8u8; 33],), ([7u8; 32].to_vec(),)];
        populate_kill_cache(&kc, &rows).await;
        assert!(kc.is_killed(&[7u8; 32]).await);
        // The short/long rows can't be queried as [u8; 32]; their absence is
        // demonstrated by a different 32-byte probe returning false.
        assert!(!kc.is_killed(&[9u8; 32]).await);
        assert!(!kc.is_killed(&[8u8; 32]).await);
    }

    #[tokio::test]
    async fn populate_kill_cache_empty_input_is_no_op() {
        let kc = KillCache::new();
        populate_kill_cache(&kc, &[]).await;
        assert!(!kc.is_killed(&[0u8; 32]).await);
    }

    #[tokio::test]
    async fn api_error_bad_request_is_400_with_detail() {
        let r = ApiError::BadRequest("missing field".into()).into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "bad_request");
        assert_eq!(v["detail"], "missing field");
    }
}
