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
}

pub fn router(state: KillswitchApiState) -> Router {
    Router::new()
        .route("/api/v1/killswitch/session/{id}", post(kill_session))
        .route("/api/v1/killswitch/user/{p0}", post(kill_user))
        .route("/api/v1/killswitch/all", post(kill_all))
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
    let res = sqlx::query(
        "UPDATE agent_bearers
            SET revoked_at      = now(),
                revoked_reason  = $2
          WHERE session_id      = $1
            AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(&reason)
    .execute(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = res.rows_affected() as i64;
    Ok(Json(persist(&state.db, "session", &id.to_string(), &reason, body.operator_subject.as_deref(), n).await?))
}

async fn kill_user(
    State(state): State<Arc<KillswitchApiState>>,
    Path(p0): Path<String>,
    body: Option<Json<KillBody>>,
) -> Result<Json<KillResponse>, ApiError> {
    let body = body.map(|j| j.0).unwrap_or_default();
    let reason = body.reason.clone().unwrap_or_else(|| "killswitch".into());
    let res = sqlx::query(
        "UPDATE agent_bearers ab
            SET revoked_at      = now(),
                revoked_reason  = $2
          FROM oauth_sessions os
         WHERE ab.session_id = os.id
           AND os.p_0        = $1
           AND ab.revoked_at IS NULL",
    )
    .bind(&p0)
    .bind(&reason)
    .execute(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = res.rows_affected() as i64;
    Ok(Json(persist(&state.db, "user", &p0, &reason, body.operator_subject.as_deref(), n).await?))
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
    let reason = body.reason.clone().unwrap_or_else(|| "killswitch:all".into());
    let res = sqlx::query(
        "UPDATE agent_bearers
            SET revoked_at      = now(),
                revoked_reason  = $1
          WHERE revoked_at IS NULL",
    )
    .bind(&reason)
    .execute(&state.db)
    .await
    .map_err(ApiError::Db)?;
    let n = res.rows_affected() as i64;
    Ok(Json(persist(&state.db, "all", "*", &reason, body.operator_subject.as_deref(), n).await?))
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
    let at: DateTime<Utc> =
        sqlx::query_scalar("SELECT at FROM kill_records WHERE id = $1")
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
