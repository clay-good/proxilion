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
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderName, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use moka::future::Cache;
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

/// `last_used_at` debounce window (ui-less-surfaces.md §4.4 dev 4). When
/// the same token authenticates within this window, we skip the DB
/// `UPDATE` — the timestamp it would have written is at most this stale.
/// Tradeoff: write amplification reduced to 1 / token / minute at most;
/// observability loss is bounded.
const LAST_USED_DEBOUNCE: Duration = Duration::from_secs(60);

/// Per-process moka cache mapping `token_id -> Instant of last DB touch`.
/// Capacity matches the bearer kill-cache — bounded RAM, no leak.
const TOUCH_CACHE_CAPACITY: u64 = 100_000;

#[derive(Clone)]
pub struct OperatorAuthState {
    pub db: PgPool,
    /// When `false`, the middleware short-circuits with 200/extension-set
    /// to None — endpoints can still gate on the principal but unauthed
    /// access works. Enabled by default; set
    /// `PROXILION_DISABLE_OPERATOR_AUTH=1` to flip off.
    pub enforced: bool,
    /// Per-process debounce of `last_used_at` writes (ui-less-surfaces.md
    /// §4.4 dev 4). A token's `Instant` lands here on every successful
    /// auth; subsequent auths within `LAST_USED_DEBOUNCE` skip the DB
    /// update.
    touch_cache: Cache<Uuid, Instant>,
}

impl OperatorAuthState {
    pub fn new(db: PgPool, enforced: bool) -> Self {
        Self {
            db,
            enforced,
            touch_cache: Cache::builder()
                .max_capacity(TOUCH_CACHE_CAPACITY)
                // Idle eviction matches the debounce window — once a
                // token hasn't touched in 2×debounce we drop its entry.
                .time_to_idle(LAST_USED_DEBOUNCE * 2)
                .build(),
        }
    }
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
    let body: String = bytes
        .iter()
        .map(|b| ALPH[(*b as usize) % ALPH.len()] as char)
        .collect();
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
    // Best-effort touch; failure must not fail the request. Debounced
    // per ui-less-surfaces.md §4.4 dev 4 — skip the DB UPDATE if this
    // token was already touched within `LAST_USED_DEBOUNCE`. Drops
    // sustained-load write amplification from one UPDATE per request
    // to at most one UPDATE per token per minute.
    let token_id = principal.token_id;
    let now = Instant::now();
    let should_write = match state.touch_cache.get(&token_id).await {
        Some(prev) if now.duration_since(prev) < LAST_USED_DEBOUNCE => {
            metrics::counter!(
                "proxilion_operator_last_used_writes_total",
                "result" => "debounced"
            )
            .increment(1);
            false
        }
        _ => true,
    };
    if should_write {
        state.touch_cache.insert(token_id, now).await;
        let db = state.db.clone();
        tokio::spawn(async move {
            let r = sqlx::query("UPDATE operator_tokens SET last_used_at = now() WHERE id = $1")
                .bind(token_id)
                .execute(&db)
                .await;
            match r {
                Ok(_) => metrics::counter!(
                    "proxilion_operator_last_used_writes_total",
                    "result" => "ok"
                )
                .increment(1),
                Err(e) => {
                    tracing::warn!(error = %e, "operator_auth: last_used_at update failed");
                    metrics::counter!(
                        "proxilion_operator_last_used_writes_total",
                        "result" => "error"
                    )
                    .increment(1);
                }
            }
        });
    }
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
pub fn require_scope(req: &Request<Body>, scope: &str) -> Result<OperatorPrincipal, Response> {
    let principal = req
        .extensions()
        .get::<OperatorPrincipal>()
        .cloned()
        .ok_or_else(|| unauthorized("no_principal"))?;
    principal.require_scope(scope).map_err(|e| {
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

    #[tokio::test]
    async fn touch_cache_debounces_within_window() {
        // ui-less-surfaces.md §4.4 dev 4 — first auth seeds the cache,
        // subsequent auths within `LAST_USED_DEBOUNCE` see the prior
        // Instant and skip the UPDATE. We exercise the cache directly
        // (full middleware needs a live PgPool).
        let cache: Cache<Uuid, Instant> = Cache::builder()
            .max_capacity(TOUCH_CACHE_CAPACITY)
            .time_to_idle(LAST_USED_DEBOUNCE * 2)
            .build();
        let token_id = Uuid::new_v4();
        let t0 = Instant::now();

        // First request: cache miss → would write.
        assert!(cache.get(&token_id).await.is_none());
        cache.insert(token_id, t0).await;

        // Second request immediately after: cache hit AND within window
        // → debounced.
        let prev = cache.get(&token_id).await.expect("cache hit");
        let elapsed = Instant::now().duration_since(prev);
        assert!(
            elapsed < LAST_USED_DEBOUNCE,
            "elapsed should be below the debounce window"
        );

        // A different token doesn't share the entry.
        let other = Uuid::new_v4();
        assert!(cache.get(&other).await.is_none());
    }

    #[test]
    fn hash_is_stable() {
        let t = "pxl_operator_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(hash(t), hash(t));
        // 32 bytes.
        assert_eq!(hash(t).len(), 32);
    }

    #[test]
    fn hash_differs_across_tokens() {
        let a = "pxl_operator_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let b = "pxl_operator_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert_ne!(hash(a), hash(b));
    }

    #[test]
    fn generate_returns_distinct_well_formed_tokens() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
        assert!(parse_token(&a).is_some());
        assert!(parse_token(&b).is_some());
    }

    #[test]
    fn scope_error_message_carries_required() {
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "n".into(),
            scopes: Arc::new(vec!["policy:read".into()]),
            last_used_at: None,
        };
        let err = p.require_scope("killswitch:revoke").unwrap_err();
        assert_eq!(err.required, "killswitch:revoke");
        assert_eq!(err.have, vec!["policy:read".to_string()]);
        let msg = err.to_string();
        assert!(msg.contains("killswitch:revoke"));
    }

    #[tokio::test]
    async fn unauthorized_response_is_401_with_plain_body() {
        let r = unauthorized("missing");
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(r.into_body(), 256).await.unwrap();
        assert_eq!(&bytes[..], b"unauthorized");
    }

    #[tokio::test]
    async fn require_scope_helper_returns_principal_on_match() {
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "n".into(),
            scopes: Arc::new(vec!["policy:read".into()]),
            last_used_at: None,
        };
        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(p.clone());
        let out = require_scope(&req, "policy:read").expect("principal returned");
        assert_eq!(out.token_id, p.token_id);
    }

    #[tokio::test]
    async fn require_scope_helper_403_with_required_and_have_on_miss() {
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "n".into(),
            scopes: Arc::new(vec!["actions:read".into()]),
            last_used_at: None,
        };
        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(p);
        let r = require_scope(&req, "policy:write").expect_err("must deny");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "scope_denied");
        assert_eq!(v["required"], "policy:write");
        assert!(
            v["have"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x == "actions:read")
        );
    }

    #[tokio::test]
    async fn require_scope_helper_401_when_no_principal() {
        let req = Request::new(Body::empty());
        let r = require_scope(&req, "policy:read").expect_err("no principal");
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn token_layout_constants_pinned_per_module_docstring() {
        // The module docstring commits to `pxl_operator_<52 base32 chars>`
        // as the operator-token shape, and the proxy CLI's `tokens issue`
        // command renders that exact format to the operator on screen.
        // PREFIX, BODY_LEN, and TOKEN_LEN are all `const` (no public
        // accessor), so a tightening / loosening regression on any of
        // the three would silently produce tokens that the CLI's own
        // round-trip (issue → SHA-256 hash → DB lookup) accepts but
        // that no operator-facing documentation describes. Pin all three.
        assert_eq!(PREFIX, "pxl_operator_");
        assert_eq!(BODY_LEN, 52);
        assert_eq!(TOKEN_LEN, PREFIX.len() + BODY_LEN);
        assert_eq!(TOKEN_LEN, 65);
    }

    #[tokio::test]
    async fn unauthorized_response_content_type_is_text_plain() {
        // Operator log parsers split "operator auth lost" 401s from the
        // structured-401s that handlers emit on the `application/json`
        // content type. The bearer middleware uses the same shape per
        // the docstring's "fixed body — same posture as the bearer
        // middleware" — a refactor that swapped to a JSON envelope
        // "for consistency with handler 401s" would silently merge the
        // two buckets on every operator dashboard.
        let r = unauthorized("malformed");
        let ct = r
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content-type set")
            .to_str()
            .unwrap();
        assert_eq!(ct, "text/plain");
    }

    #[tokio::test]
    async fn require_scope_helper_403_response_is_application_json() {
        // Symmetric to the unauthorized() text/plain pin above — the
        // 403 path serializes the structured `{code, required, have}`
        // envelope and MUST carry `application/json`. The CLI's renderer
        // parses the body and fails loudly on a content-type mismatch
        // (better to surface a confusing message than to silently render
        // raw bytes), so a regression here would break operator
        // dashboards on every scope-denied request.
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "ci-bot".into(),
            scopes: Arc::new(vec!["actions:read".into()]),
            last_used_at: None,
        };
        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(p);
        let r = require_scope(&req, "policy:write").expect_err("must deny");
        let ct = r
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content-type set")
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn operator_principal_scopes_cloned_through_arc_share() {
        // `scopes: Arc<Vec<String>>` is intentional — every successful
        // auth clones the principal into request extensions, and on a
        // hot route the per-handler `principal.clone()` would otherwise
        // allocate one Vec<String> per scope every request. Pin via
        // `Arc::ptr_eq` that the cloned principal shares the SAME
        // backing Vec — a refactor to `scopes: Vec<String>` "for
        // simplicity" would silently regress every request's allocation
        // count without surfacing as a wire-shape change.
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "ci-bot".into(),
            scopes: Arc::new(vec!["policy:read".into(), "actions:read".into()]),
            last_used_at: None,
        };
        let c = p.clone();
        assert!(Arc::ptr_eq(&p.scopes, &c.scopes));
        // Sanity: both views see the same contents.
        assert_eq!(c.scopes.len(), 2);
        assert_eq!(c.scopes[0], "policy:read");
    }

    #[test]
    fn operator_auth_state_is_clone_for_axum_state_propagation() {
        // axum's `State<OperatorAuthState>` extractor requires Clone on
        // every middleware invocation — a `!Clone` field landing on the
        // state struct (e.g. a `tokio::sync::Mutex` for some new
        // per-state counter) would surface here as a compile error
        // rather than at the hundreds of router-build sites in
        // `server.rs`. Compile-time trait bound; no instantiation
        // required.
        fn require_clone<T: Clone>() {}
        require_clone::<OperatorAuthState>();
    }
}
