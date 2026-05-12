//! Operator-token middleware (ui-less-surfaces.md §4.4).
//!
//! Tokens are `pxl_operator_<52 base32 chars>` (mirrors the bearer
//! layout). Only `sha256(token)` is persisted. The plaintext is shown
//! to the operator exactly once at issue time via `proxilion-cli tokens
//! issue` and stored hashed in `operator_tokens`.
//!
//! Scopes are a curated string set:
//!   * `policy:read`           — `GET /api/v1/policy`
//!   * `policy:write`          — `POST /api/v1/policy/reload`, `…/mode`
//!   * `blocks:read`           — `GET /api/v1/blocked` + `GET /…/{id}`
//!   * `blocks:approve`        — `POST /api/v1/blocked/{id}/approve|reject`
//!   * `killswitch:revoke`     — `POST /api/v1/killswitch/*`
//!   * `actions:read`          — `GET /api/v1/actions*`
//!   * `actions:export`        — `GET /api/v1/actions/export`
//!   * `pca:read`              — `GET /api/v1/pca/*`
//!   * `tokens:admin`          — manage other tokens (future)
//!
//! Wildcard `*` matches every scope; useful for a single bootstrap admin
//! token. Otherwise scopes are exact-match.
//!
//! Default posture: **enforced**. To bypass for local dev, set
//! `PROXILION_DISABLE_OPERATOR_AUTH=1`. The escape hatch logs a `WARN`
//! once at startup so it's loud in CI / prod logs.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderName, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

const PREFIX: &str = "pxl_operator_";
const BODY_LEN: usize = 52;
const TOKEN_LEN: usize = PREFIX.len() + BODY_LEN;

/// Wildcard scope — grants any scope check. Use exactly one bootstrap
/// token with this; everything else should be least-privilege.
pub const WILDCARD: &str = "*";

// The canonical catalogue lives in `shared_types::operator_scopes` so
// the CLI + tests + future SCIM sync depend on the same source of truth.
// The proxy itself doesn't render the catalogue (that's the CLI's job),
// but tests can pull it from `shared_types::operator_scopes::SCOPE_CATALOGUE`.

#[derive(Clone)]
pub struct OperatorAuthState {
    pub db: PgPool,
    /// When `false`, the middleware short-circuits with 200/extension-set
    /// to None — endpoints can still gate on the principal but unauthed
    /// access works. Enabled by default; set
    /// `PROXILION_DISABLE_OPERATOR_AUTH=1` to flip off.
    pub enforced: bool,
}

/// Authenticated principal, inserted into request extensions when the
/// middleware succeeds. Endpoint handlers can pull it from extensions
/// and call `principal.require_scope(...)` per route.
#[derive(Debug, Clone)]
pub struct OperatorPrincipal {
    pub token_id: Uuid,
    #[allow(dead_code)] // surfaced on audit rows in a future iteration
    pub name: String,
    pub scopes: Arc<Vec<String>>,
    #[allow(dead_code)]
    pub last_used_at: Option<DateTime<Utc>>,
}

impl OperatorPrincipal {
    /// Returns `Ok(())` if the principal carries the wildcard scope or
    /// the exact scope requested.
    pub fn require_scope(&self, scope: &str) -> Result<(), ScopeError> {
        if self.scopes.iter().any(|s| s == WILDCARD || s == scope) {
            Ok(())
        } else {
            Err(ScopeError {
                required: scope.to_string(),
                have: self.scopes.as_ref().clone(),
            })
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("insufficient scope: need `{required}`")]
pub struct ScopeError {
    pub required: String,
    pub have: Vec<String>,
}

/// `pxl_operator_*` parsing — same shape as `Bearer`.
pub fn parse_token(input: &str) -> Option<&str> {
    if input.len() != TOKEN_LEN || !input.starts_with(PREFIX) {
        return None;
    }
    let body = &input[PREFIX.len()..];
    if !body.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7')) {
        return None;
    }
    Some(input)
}

pub fn hash(token: &str) -> [u8; 32] {
    let d = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Generate a fresh `pxl_operator_*` token. Used by tests; the CLI has
/// its own copy of the same logic (no shared types crate needed for one
/// 10-line helper). Kept here so the format is single-sourced in tests.
#[allow(dead_code)]
pub fn generate() -> String {
    use rand::RngCore;
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = [0u8; BODY_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body: String = bytes.iter().map(|b| ALPH[(*b as usize) % ALPH.len()] as char).collect();
    format!("{PREFIX}{body}")
}

/// Middleware. Looks up the token, validates `revoked_at IS NULL`, attaches
/// `OperatorPrincipal` to request extensions, updates `last_used_at`.
/// 401 on missing/bad/revoked token (when enforced).
pub async fn middleware(
    State(state): State<OperatorAuthState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if !state.enforced {
        // Insert a synthetic wildcard principal so per-route `scope_layer`
        // checks pass uniformly. This is the load-bearing trick: scope
        // enforcement lives on the route, the middleware decides whether
        // it's gated at all.
        req.extensions_mut().insert(OperatorPrincipal {
            token_id: Uuid::nil(),
            name: "anonymous-disabled".into(),
            scopes: Arc::new(vec![WILDCARD.to_string()]),
            last_used_at: None,
        });
        return next.run(req).await;
    }
    // Extract Authorization: Bearer pxl_operator_<...>
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let token = match header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) => t,
        None => return unauthorized("missing"),
    };
    if parse_token(token).is_none() {
        return unauthorized("malformed");
    }
    let hash = hash(token);
    let row: Result<Option<(Uuid, String, Vec<String>, Option<DateTime<Utc>>)>, _> =
        sqlx::query_as(
            "SELECT id, name, scopes, last_used_at
             FROM operator_tokens
             WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(&hash[..])
        .fetch_optional(&state.db)
        .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return unauthorized("unknown_or_revoked"),
        Err(e) => {
            warn!(error = %e, "operator_auth: db error");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let principal = OperatorPrincipal {
        token_id: row.0,
        name: row.1,
        scopes: Arc::new(row.2),
        last_used_at: row.3,
    };
    // Best-effort touch; failure must not fail the request. Clone the
    // pool so the spawned future doesn't borrow from `state`.
    let db = state.db.clone();
    let token_id = principal.token_id;
    tokio::spawn(async move {
        let r = sqlx::query("UPDATE operator_tokens SET last_used_at = now() WHERE id = $1")
            .bind(token_id)
            .execute(&db)
            .await;
        if let Err(e) = r {
            tracing::warn!(error = %e, "operator_auth: last_used_at update failed");
        }
    });
    req.extensions_mut().insert(principal);
    metrics::counter!(
        "proxilion_operator_auth_total",
        "result" => "ok"
    )
    .increment(1);
    next.run(req).await
}

fn unauthorized(reason: &'static str) -> Response {
    metrics::counter!(
        "proxilion_operator_auth_total",
        "result" => "rejected",
        "reason" => reason
    )
    .increment(1);
    // Fixed body — same posture as the bearer middleware.
    (
        StatusCode::UNAUTHORIZED,
        [(HeaderName::from_static("content-type"), "text/plain")],
        "unauthorized",
    )
        .into_response()
}

/// Per-route scope-check middleware. Use via:
///
/// ```ignore
/// Router::new().route("/api/v1/policy", get(handler))
///     .route_layer(axum::middleware::from_fn_with_state(
///         "policy:read",
///         operator_auth::scope_check,
///     ))
/// ```
///
/// Relies on `middleware()` having already attached an `OperatorPrincipal`
/// to request extensions. In disabled-auth mode the middleware attaches a
/// synthetic wildcard principal so this check is a no-op; in enforced
/// mode an absent principal means the outer middleware would have
/// already 401'd, so the `None` arm here is genuinely unreachable.
pub async fn scope_check(
    State(scope): State<&'static str>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let principal = req.extensions().get::<OperatorPrincipal>().cloned();
    match principal {
        Some(p) if p.scopes.iter().any(|s| s == WILDCARD || s == scope) => next.run(req).await,
        Some(p) => {
            metrics::counter!(
                "proxilion_operator_auth_total",
                "result" => "rejected",
                "reason" => "scope_denied"
            )
            .increment(1);
            let have = p.scopes.as_ref().clone();
            (
                StatusCode::FORBIDDEN,
                [(HeaderName::from_static("content-type"), "application/json")],
                serde_json::json!({
                    "error": "insufficient scope",
                    "code": "scope_denied",
                    "required": scope,
                    "have": have,
                })
                .to_string(),
            )
                .into_response()
        }
        None => unauthorized("no_principal"),
    }
}

/// Helper for handlers: load the principal from request extensions and
/// run a scope check. Returns the principal on success, a 401/403 Response
/// on failure. Handlers that don't need a principal can omit this entirely
/// — the middleware already enforces *presence* of any valid token when
/// `enforced=true`.
#[allow(dead_code)] // wired in §future when per-endpoint scopes are added
pub fn require_scope(
    req: &Request<Body>,
    scope: &str,
) -> Result<OperatorPrincipal, Response> {
    let principal = req
        .extensions()
        .get::<OperatorPrincipal>()
        .cloned()
        .ok_or_else(|| unauthorized("no_principal"))?;
    principal
        .require_scope(scope)
        .map_err(|e| {
            metrics::counter!(
                "proxilion_operator_auth_total",
                "result" => "rejected",
                "reason" => "scope_denied"
            )
            .increment(1);
            (
                StatusCode::FORBIDDEN,
                [(HeaderName::from_static("content-type"), "application/json")],
                serde_json::json!({
                    "error": "insufficient scope",
                    "code": "scope_denied",
                    "required": scope,
                    "have": e.have,
                })
                .to_string(),
            )
                .into_response()
        })?;
    Ok(principal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_validates_shape() {
        let t = generate();
        assert_eq!(t.len(), TOKEN_LEN);
        assert!(t.starts_with(PREFIX));
        assert!(parse_token(&t).is_some());
    }

    #[test]
    fn parse_token_rejects_wrong_prefix() {
        let bad = format!("pxl_live_{}", "A".repeat(BODY_LEN));
        assert!(parse_token(&bad).is_none());
    }

    #[test]
    fn parse_token_rejects_lowercase_body() {
        let bad = format!("{PREFIX}{}", "a".repeat(BODY_LEN));
        assert!(parse_token(&bad).is_none());
    }

    #[test]
    fn parse_token_rejects_wrong_length() {
        let bad = format!("{PREFIX}{}", "A".repeat(BODY_LEN - 1));
        assert!(parse_token(&bad).is_none());
    }

    #[test]
    fn require_scope_accepts_wildcard() {
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "admin".into(),
            scopes: Arc::new(vec!["*".into()]),
            last_used_at: None,
        };
        assert!(p.require_scope("policy:write").is_ok());
        assert!(p.require_scope("anything:at:all").is_ok());
    }

    #[test]
    fn require_scope_accepts_exact() {
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "ci-bot".into(),
            scopes: Arc::new(vec!["policy:read".into(), "actions:read".into()]),
            last_used_at: None,
        };
        assert!(p.require_scope("policy:read").is_ok());
        assert!(p.require_scope("actions:read").is_ok());
        let err = p.require_scope("policy:write").unwrap_err();
        assert_eq!(err.required, "policy:write");
    }

    #[test]
    fn hash_is_stable() {
        let t = "pxl_operator_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(hash(t), hash(t));
        // 32 bytes.
        assert_eq!(hash(t).len(), 32);
    }
}
