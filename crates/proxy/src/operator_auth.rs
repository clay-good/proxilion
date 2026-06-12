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
    fn operator_principal_and_scope_error_and_state_are_send_sync_static_for_axum_bounds() {
        // `OperatorPrincipal` is held in axum request extensions
        // (Send+Sync+'static-bound bag) and cloned across spawned
        // metrics/audit tasks; `ScopeError` flows through `thiserror`'s
        // `std::error::Error` impl and into anyhow chains in the
        // require_scope path; `OperatorAuthState` is the `State<...>`
        // extractor's stored value on every middleware invocation. The
        // existing `operator_auth_state_is_clone_for_axum_state_propagation`
        // pin only checks the Clone bound; widen the same boundary to
        // include Send+Sync+'static across all three types. A refactor
        // that gave any one an `Rc<...>` field "for cheap clone on the
        // hot path" would break Send and surface at the router assembly
        // site with an opaque tower::Service trait-bound rather than at
        // this file. Pin all three at compile time.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<OperatorPrincipal>();
        require_send_sync_static::<ScopeError>();
        require_send_sync_static::<OperatorAuthState>();
    }

    #[test]
    fn wildcard_constant_is_byte_exact_single_asterisk_one_char() {
        // The `WILDCARD` constant is the load-bearing comparison in
        // `require_scope` (`if scopes.iter().any(|s| s == WILDCARD || s ==
        // scope)`) — a refactor that drifted it to `"**"` (npm-glob
        // double-star "for ergonomic match-everything") OR to `"any"`
        // (English-word "for operator-friendliness") would silently
        // either narrow every wildcard token to deny-by-default OR
        // collide with a literal scope name `any:*`. Pin the byte-exact
        // `"*"` literal AND the length=1 AND that the constant is
        // `&'static str` not String. The existing tests exercise WILDCARD
        // behaviorally; pin the LITERAL here so a one-byte drift surfaces
        // at this file, not as a cascading deny on every wildcard token.
        fn require_static_str(_: &'static str) {}
        require_static_str(WILDCARD);
        assert_eq!(WILDCARD, "*");
        assert_eq!(WILDCARD.len(), 1);
        assert_eq!(WILDCARD.as_bytes(), b"*");
    }

    #[test]
    fn generate_emits_prefix_exactly_once_at_offset_zero_across_burst() {
        // The generator concats PREFIX + 52-char base32 body — across a
        // burst of 100 generations the prefix MUST appear exactly once
        // at offset 0 in every token, with no internal duplication. A
        // refactor that, e.g., changed `format!("{PREFIX}{body}")` to
        // `format!("{PREFIX}{PREFIX}{body}")` (a copy-paste mistake when
        // splitting the helper between proxy + CLI) would surface here
        // on iteration 1. Pin both invariants (count == 1 + offset == 0)
        // across the burst so a stateful regression — e.g. a once-cell
        // that wrapped after N calls — surfaces too.
        for i in 0..100 {
            let t = generate();
            let count = t.matches(PREFIX).count();
            assert_eq!(count, 1, "iter {i}: PREFIX count drift, got {count}");
            assert_eq!(
                &t[..PREFIX.len()],
                PREFIX,
                "iter {i}: PREFIX not at offset 0"
            );
            assert_eq!(t.len(), TOKEN_LEN);
        }
    }

    #[test]
    fn parse_token_rejects_body_length_plus_one_off_by_one_boundary() {
        // The existing `parse_token_rejects_wrong_length` pin only checks
        // BODY_LEN-1 (52-1 = 51 char body). Pin the symmetric BODY_LEN+1
        // (53-char body) boundary so a refactor that loosened the
        // length check to `>= TOKEN_LEN` (the natural shape of a "tolerate
        // operator-typed trailing whitespace" change) would surface here.
        // Both boundaries fail-closed via the `input.len() != TOKEN_LEN`
        // fast-path. The CLI's `tokens issue` rendering depends on the
        // exact 65-byte total — a one-byte off-by-one in either direction
        // would silently produce a token the CLI accepts but the proxy
        // rejects.
        let too_long = format!("{PREFIX}{}", "A".repeat(BODY_LEN + 1));
        assert_eq!(too_long.len(), TOKEN_LEN + 1);
        assert!(parse_token(&too_long).is_none(), "53-char body must reject");
        let way_too_long = format!("{PREFIX}{}", "A".repeat(BODY_LEN + 100));
        assert!(
            parse_token(&way_too_long).is_none(),
            "152-char body must reject"
        );
        // Also pin the trailing-whitespace shape — a 52-char valid body
        // with one trailing space (53 chars total). The CLI's HTTP
        // header parsing strips trailing whitespace at the
        // axum/header layer, so the proxy receives the canonical 52-char
        // body — but pin the validator's behavior on raw +1-with-trailing
        // -space input as a defense-in-depth check.
        let with_trailing_space = format!("{PREFIX}{} ", "A".repeat(BODY_LEN));
        assert_eq!(with_trailing_space.len(), TOKEN_LEN + 1);
        assert!(parse_token(&with_trailing_space).is_none());
    }

    #[test]
    fn require_scope_error_have_preserves_input_scope_order() {
        // `ScopeError::have` is rendered into the 403 response body's
        // `have` array — operator dashboards parse the array and
        // re-render it in the order the token's scope catalog defined.
        // A refactor that, e.g., sorted the array "for stable JSON
        // output" OR that deduplicated "for compactness" would surface
        // here on a known order-preserving input. Pin both axes: order
        // preserved across a 5-scope input AND duplicates retained (the
        // catalog may legitimately list a scope twice if it spans two
        // logical buckets in the operator's mental model). The existing
        // `scope_error_message_carries_required` pin walks ONE scope;
        // widen to N=5 with deliberate ordering + a deliberate duplicate.
        let scopes = vec![
            "policy:read".to_string(),
            "actions:read".to_string(),
            "blocks:read".to_string(),
            "actions:read".to_string(), // intentional duplicate
            "pca:read".to_string(),
        ];
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "multi-scope-bot".into(),
            scopes: Arc::new(scopes.clone()),
            last_used_at: None,
        };
        let err = p.require_scope("policy:write").unwrap_err();
        // Element-wise byte-equal — order preserved AND duplicate
        // retained.
        assert_eq!(err.have, scopes);
        assert_eq!(err.have.len(), 5);
        assert_eq!(err.have[3], "actions:read", "duplicate dropped");
    }

    #[test]
    fn hash_byte_exact_for_canonical_operator_token_via_well_known_sha256_vector_abc() {
        // `hash()` is `sha256(token.as_bytes())` — pin against the
        // canonical FIPS 180-4 §B.1 / RFC 6234 §A.5 vector for input
        // "abc" so the operator-token SHA-256 is verified against a
        // published cross-checked digest (NOT just a self-consistency
        // pin of `hash(t) == hash(t)`, which the existing
        // `hash_is_stable` pin covers). A refactor that swapped to
        // BLAKE3 "for speed" OR that prepended a per-process salt "for
        // cache-key uniqueness" would silently invalidate every
        // operator token already in the `operator_tokens` table — pin
        // the deterministic mapping against an outside reference.
        let h = hash("abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(h, expected);
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

    #[test]
    fn last_used_debounce_constant_type_is_duration_for_instant_duration_since_signature_compat() {
        // The `LAST_USED_DEBOUNCE` constant is fed to two distinct
        // signatures: `Instant::duration_since(prev)` returns Duration
        // and is compared against this constant via the `<` operator;
        // `Cache::builder().time_to_idle(LAST_USED_DEBOUNCE * 2)` passes
        // the doubled value to moka. Both call sites require the
        // constant be typed `Duration` — a refactor to `u64` "for
        // ergonomic config-file embedding" would silently strip the
        // unit-info at the type level, force every call site through
        // ad-hoc `Duration::from_secs(LAST_USED_DEBOUNCE)` wrappers,
        // AND open a paper cut where a future change to `_MILLIS` vs
        // `_SECS` would silently widen the debounce window 1000x. Pin
        // the type at the constant boundary via a let-binding type
        // annotation; the existing tests exercise the constant
        // behaviorally but never pin its TYPE.
        fn require_duration(_: Duration) {}
        let v: Duration = LAST_USED_DEBOUNCE;
        require_duration(v);
        // Also pin the numeric value contract — the docstring commits
        // to "at most one UPDATE per token per minute", which is
        // 60-second debounce. A refactor that tightened to e.g. 30s
        // "for fresher observability" would silently double write
        // amplification under sustained load.
        assert_eq!(LAST_USED_DEBOUNCE, Duration::from_secs(60));
    }

    #[test]
    fn touch_cache_capacity_constant_type_is_u64_for_moka_max_capacity_signature_compat() {
        // The `TOUCH_CACHE_CAPACITY` constant is fed directly to
        // `Cache::builder().max_capacity(TOUCH_CACHE_CAPACITY)`, which
        // takes `u64`. Symmetric to `kill_cache::MAX_CAPACITY`'s u64
        // pin (rounds 201) — a refactor to `usize` "for parity with
        // Vec::len()" would diverge between 32-bit and 64-bit hosts
        // AND would silently force an `as u64` cast at the moka call
        // site that could truncate on hypothetical 16-bit embedded
        // hosts. Pin the type at the constant boundary via require_u64.
        fn require_u64(_: u64) {}
        let v: u64 = TOUCH_CACHE_CAPACITY;
        require_u64(v);
        assert_eq!(TOUCH_CACHE_CAPACITY, 100_000);
    }

    #[test]
    fn operator_principal_field_types_pinned_for_axum_extension_storage_contract() {
        // `OperatorPrincipal` is stored in axum request extensions and
        // cloned into spawned `last_used_at` UPDATE tasks AND scope-
        // check middleware. Pin all 4 field types at the struct
        // boundary so a refactor that, e.g., switched `scopes` to
        // `Arc<[String]>` "for borrowed-slice ergonomics" (which
        // breaks the `.iter().any(|s| s == ...)` call site's `&&str`
        // -vs-`&String` comparison) OR switched `last_used_at` to
        // bare `DateTime<Utc>` (which would lose nullable-column
        // shape from the postgres `last_used_at TIMESTAMPTZ` column
        // and force every fixture through a sentinel "never used"
        // value) would surface here at the struct boundary, not as a
        // cascading row-fetch error at the sqlx call site.
        fn require_uuid(_: Uuid) {}
        fn require_string(_: String) {}
        fn require_arc_vec_string(_: Arc<Vec<String>>) {}
        fn require_opt_datetime(_: Option<DateTime<Utc>>) {}
        let p = OperatorPrincipal {
            token_id: Uuid::new_v4(),
            name: "n".into(),
            scopes: Arc::new(vec!["policy:read".into()]),
            last_used_at: Some(Utc::now()),
        };
        require_uuid(p.token_id);
        require_string(p.name.clone());
        require_arc_vec_string(p.scopes.clone());
        require_opt_datetime(p.last_used_at);
    }

    #[test]
    fn parse_token_return_type_is_borrowed_str_slice_for_zero_alloc_validate_then_use_contract() {
        // `parse_token` returns `Option<&str>` borrowed from its input
        // — the docstring's wording "`pxl_operator_*` parsing — same
        // shape as `Bearer`" commits to the zero-allocation
        // validate-then-use idiom: the middleware validates the token
        // shape with `parse_token(token).is_none()` and on success
        // continues to use the ORIGINAL `token: &str` (not the
        // parsed return value) for `hash(token)`. A refactor to
        // `Option<String>` "for ergonomic owned-output" would silently
        // start heap-allocating one String per operator-API request
        // AND break the `is_none()` check's `if-let-else-return`
        // shape. Pin the lifetime by binding the input to a local +
        // checking the return value's pointer equals the input's.
        let t = "pxl_operator_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let out: Option<&str> = parse_token(t);
        let out = out.expect("valid token");
        // Pointer equality — `out` is a borrow into `t`, not a
        // freshly-allocated String.
        assert_eq!(out.as_ptr(), t.as_ptr());
        assert_eq!(out.len(), t.len());
    }

    #[test]
    fn hash_return_type_is_fixed_size_32_byte_array_for_postgres_bytea_bind_shape() {
        // `hash` returns `[u8; 32]` (fixed-size stack array) — the
        // middleware binds `&hash[..]` (a slice view of the array)
        // into sqlx's `BIND $1` for the `token_hash = $1` lookup
        // against the `operator_tokens.token_hash BYTEA` column. A
        // refactor that switched to `Vec<u8>` "for symmetry with
        // bearer::hash" would heap-allocate one Vec per request AND
        // would tolerate variable-length values at the type system
        // boundary (a future-bug where a caller passed `truncate(16)`
        // would silently produce a 16-byte hash that the DB lookup
        // would never match — but with `[u8; 32]` the compiler
        // forbids that at the type level). Pin the array length AND
        // type at the return boundary.
        fn require_array_u8_32(_: [u8; 32]) {}
        let h = hash("pxl_operator_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        require_array_u8_32(h);
        // The const `TOKEN_LEN` is 65; the hash output is ALWAYS 32
        // bytes regardless of input length — sanity-pin with a
        // distinct-length input.
        let h2 = hash("");
        require_array_u8_32(h2);
        assert_eq!(h2.len(), 32);
    }

    #[test]
    fn scope_error_inner_field_types_pinned_for_thiserror_display_substitution_contract() {
        // `ScopeError` has two fields: `required: String` (interpolated
        // into the `#[error("insufficient scope: need `{required}`")]`
        // Display impl) and `have: Vec<String>` (rendered into the
        // JSON 403 response body's `have` array). Pin both: a
        // refactor that switched `required` to `&'static str` "for
        // zero-alloc constant scope names" would break the runtime-
        // dynamic scope-string call sites (handlers pass owned
        // strings from request paths); a refactor that switched
        // `have` to `Arc<Vec<String>>` "for cheap clone" would force
        // the JSON serializer through one extra `Arc::deref` per 403
        // response AND would break the operator-facing dashboard
        // parser's array-shape expectation. Both shapes are
        // load-bearing — pin at the field boundary.
        fn require_string(_: String) {}
        fn require_vec_string(_: Vec<String>) {}
        let e = ScopeError {
            required: "policy:write".to_string(),
            have: vec!["policy:read".to_string()],
        };
        require_string(e.required.clone());
        require_vec_string(e.have.clone());
        // Also pin the Display shape — the `#[error(...)]` derive
        // wires `to_string()` to the format string with `{required}`
        // substituted byte-exact.
        assert_eq!(e.to_string(), "insufficient scope: need `policy:write`");
    }

    // ─── round 247 (2026-05-22): OperatorPrincipal + ScopeError + state field
    // counts, require_scope fn-pointer witness, scope-prefix hygiene pin ───

    #[test]
    fn operator_principal_field_count_pinned_at_exactly_four_via_exhaustive_destructure_no_rest() {
        // `OperatorPrincipal { token_id, name, scopes, last_used_at }` —
        // exactly 4 fields. A 5th field landing (e.g.
        // `tenant_id: Option<Uuid>` for multi-tenant operator scoping OR
        // `mfa_verified_at: Option<DateTime<Utc>>` for elevated-scope
        // audit) without matching middleware construction wiring would
        // silently zero-initialize the new field on every authenticated
        // request — and any handler reading it would see the default
        // forever. The exhaustive destructure with no `..` rest pattern
        // forces a 5th field to update this site in lockstep with the
        // middleware constructor. Symmetric to round-240's
        // `blocked_notification_field_count_pinned_at_exactly_sixteen_via_exhaustive_destructure_no_rest`
        // + round-243's
        // `auth_state_field_count_pinned_at_exactly_ten_via_exhaustive_destructure_no_rest_pattern`
        // extended to this sibling axum-extension wrapper.
        let p = OperatorPrincipal {
            token_id: Uuid::nil(),
            name: "op".into(),
            scopes: Arc::new(vec!["policy:read".to_string()]),
            last_used_at: None,
        };
        let OperatorPrincipal {
            token_id: _,
            name: _,
            scopes: _,
            last_used_at: _,
        } = p;
    }

    #[test]
    fn scope_error_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern() {
        // `ScopeError { required, have }` — exactly 2 fields. A 3rd field
        // landing (e.g. `granted_via: Option<String>` to track WHICH
        // upstream issued the scope set, OR `expires_at:
        // DateTime<Utc>` for per-scope expiry observability) without
        // matching the `require_scope` Err-arm constructor would
        // silently zero-initialize on every 403 — and the JSON response
        // body serializer would either drop the field (if it doesn't
        // derive Serialize) or surface a default value that confuses
        // operator dashboards keying on the field presence. The
        // exhaustive destructure with no `..` rest pattern forces a 3rd
        // field to update this site in lockstep with the
        // `require_scope` Err construction site. Symmetric to round-238's
        // `email_build_error_inner_field_count_pinned_at_exactly_one_via_exhaustive_destructure`
        // extended to this sibling 403-response-payload struct.
        let e = ScopeError {
            required: "policy:write".to_string(),
            have: vec!["policy:read".to_string()],
        };
        let ScopeError {
            required: _,
            have: _,
        } = e;
    }

    #[tokio::test]
    async fn operator_auth_state_field_count_pinned_at_exactly_three_via_exhaustive_destructure_no_rest()
     {
        // `OperatorAuthState { db, enforced, touch_cache }` — exactly 3
        // fields. A 4th field landing (e.g.
        // `rate_limiter: Arc<RateLimiter>` for per-operator request-rate
        // observability OR `audit_sink: Arc<dyn AuditSink>` for token-
        // use forwarding to SIEM) without matching `new()` constructor
        // wiring would silently zero-initialize on every middleware
        // invocation — and the per-operator audit log would
        // permanently emit zero events. The exhaustive destructure with
        // no `..` rest pattern forces a 4th field to update this site
        // in lockstep with `OperatorAuthState::new`. Symmetric to
        // round-243's
        // `auth_state_field_count_pinned_at_exactly_ten_via_exhaustive_destructure_no_rest_pattern`
        // extended to this sibling operator-side axum-state shape.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://x:y@127.0.0.1:1/z")
            .expect("lazy connect");
        let s = OperatorAuthState::new(pool, true);
        let OperatorAuthState {
            db: _,
            enforced: _,
            touch_cache: _,
        } = s;
    }

    #[test]
    fn require_scope_method_signature_self_borrow_scope_borrow_returns_result_via_fn_pointer_witness()
     {
        // `OperatorPrincipal::require_scope(&self, scope: &str) -> Result<(), ScopeError>` —
        // takes `&self` BORROW (for cross-handler shared principal access
        // via axum extensions) AND `&str` BORROW (zero-alloc on the
        // scope-string-literal hot path) and returns `Result<(),
        // ScopeError>`. The handler call sites use
        // `principal.require_scope("policy:write")?` to bubble 403s
        // into the response envelope. A refactor to `fn
        // require_scope(self, ...)` "consuming the principal at the
        // gate" would foreclose the per-request multi-gate pattern
        // (handlers sometimes check multiple scopes); a refactor that
        // returned `bool` "for ergonomic `if`-gate" would silently
        // drop the `have` operator-dashboard context. Pin via
        // fn-pointer witness. Symmetric to round-246's
        // `bearer_hash_method_signature_self_borrow_returns_owned_bearer_hash_via_fn_pointer_witness`
        // extended to this sibling scope-gate method.
        let _f: fn(&OperatorPrincipal, &str) -> Result<(), ScopeError> =
            OperatorPrincipal::require_scope;
    }

    #[test]
    fn scope_catalogue_strings_all_carry_colon_separator_for_resource_action_split() {
        // The operator-scope catalogue uses the `resource:action` shape
        // (e.g. `policy:read`, `blocks:approve`, `killswitch:revoke`).
        // The colon separator is load-bearing for: (a) the dashboard's
        // "group scopes by resource" UI rule, and (b) the CLI's
        // `tokens issue --scope policy:*` glob expansion. A refactor
        // that swapped to a dotted separator (`policy.read`) "for
        // symmetry with action_event vendor.action shape" would
        // silently break both consumers. Pin the colon separator on
        // every catalogue entry — and pin that the WILDCARD constant
        // is the lone exception (no colon, single asterisk). Symmetric
        // to round-219's
        // `scope_catalogue_carries_exactly_twelve_entries_pinning_the_documented_set_byte_exact`
        // (which pins the SHAPE of the set) extended to this hyphenated-
        // syntax contract.
        for entry in shared_types::operator_scopes::SCOPE_CATALOGUE {
            let scope = entry.0;
            // Skip the wildcard sigil — pinned separately below.
            if scope == WILDCARD {
                continue;
            }
            assert!(
                scope.contains(':'),
                "scope `{scope}` missing colon separator"
            );
            // Sanity: exactly ONE colon (no nested `resource:sub:action`
            // shapes today — a refactor adding nested scopes would
            // surface here as multi-colon entries).
            assert_eq!(
                scope.matches(':').count(),
                1,
                "scope `{scope}` carries >1 colon",
            );
            // Resource half + action half are both non-empty.
            let (res, act) = scope.split_once(':').expect("colon present");
            assert!(!res.is_empty(), "scope `{scope}` has empty resource half");
            assert!(!act.is_empty(), "scope `{scope}` has empty action half");
        }
        // WILDCARD intentionally has no colon — it's a sigil, not a
        // resource:action pair.
        assert_eq!(WILDCARD, "*");
        assert!(!WILDCARD.contains(':'));
    }

    #[test]
    fn parse_token_prefix_constant_byte_exact_pxl_operator_distinct_from_bearer_pxl_live() {
        // `PREFIX = "pxl_operator_"` — operator tokens are wire-distinct
        // from agent bearers (`pxl_live_`) so a leaked operator token
        // can't slip into the bearer-middleware accept path AND vice
        // versa. The existing `token_layout_constants_pinned_per_module_docstring`
        // pin walks the byte-length but not the byte-exact value. A
        // refactor that "consolidated" the two prefixes (e.g.
        // `pxl_token_` umbrella for both kinds) would silently break the
        // wire-distinction contract — operator tokens would parse via
        // the agent bearer middleware as malformed bearers (length
        // mismatches), but a future shape that happened to match would
        // silently authenticate operators on agent endpoints. Pin the
        // byte-exact prefix AND distinctness from the bearer prefix.
        // Symmetric to round-246's
        // `prefix_constant_is_byte_exact_pxl_underscore_live_underscore`
        // pin extended to this sibling token-family separator.
        assert_eq!(PREFIX, "pxl_operator_");
        assert_eq!(PREFIX.len(), 13);
        assert_eq!(PREFIX.as_bytes(), b"pxl_operator_");
        // Distinctness from the agent-bearer prefix on BOTH byte
        // sequences AND structural overlap (no shared SUFFIX that
        // could be exploited as a forgery path).
        assert_ne!(PREFIX, "pxl_live_");
        assert!(
            !PREFIX.starts_with("pxl_live_") && !"pxl_live_".starts_with(PREFIX),
            "operator and agent prefixes must be wire-disjoint",
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB-backed integration test (opt-in via PROXILION_TEST_DATABASE_URL).
    // Drives the real operator-auth boundary (DB token lookup → principal
    // attach → per-route scope_check) end-to-end via tower's `oneshot`.
    // Skips when no test DB — see test_support.
    // ─────────────────────────────────────────────────────────────────────

    /// Insert an `operator_tokens` row and return the matching bearer token.
    async fn seed_operator_token(pool: &PgPool, scopes: &[&str], revoked: bool) -> String {
        let token = generate();
        let h = hash(&token);
        let scopes_vec: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        sqlx::query(
            "INSERT INTO operator_tokens (token_hash, name, scopes, revoked_at)
             VALUES ($1, 'it', $2, $3)",
        )
        .bind(&h[..])
        .bind(&scopes_vec)
        .bind(if revoked { Some(Utc::now()) } else { None })
        .execute(pool)
        .await
        .expect("seed operator_tokens");
        token
    }

    #[tokio::test]
    async fn db_backed_operator_auth_boundary_enforces_token_and_scope() {
        // The auth gate for the entire operator API: every `/api/v1/*` request
        // crosses `middleware` (DB token lookup, revocation check, principal
        // attach) then a per-route `scope_check`. Pin the full decision matrix
        // against real SQL: valid+scope→200, wildcard→200, unknown→401,
        // revoked→401, wrong-scope→403, missing→401, malformed→401.
        let Some(pool) = crate::test_support::pool().await else {
            eprintln!("skipping: {} unset", crate::test_support::TEST_DB_ENV);
            return;
        };
        use axum::Router;
        use axum::body::Body;
        use axum::http::Request;
        use axum::middleware::from_fn_with_state;
        use axum::routing::get;
        use moka::future::Cache;
        use tower::ServiceExt; // oneshot

        // Seed four tokens covering the decision space.
        let tok_read = seed_operator_token(&pool, &["blocks:read"], false).await;
        let tok_wildcard = seed_operator_token(&pool, &[WILDCARD], false).await;
        let tok_revoked = seed_operator_token(&pool, &["blocks:read"], true).await;
        let tok_wrong_scope = seed_operator_token(&pool, &["policy:read"], false).await;
        // A well-formed token that was never inserted.
        let tok_unknown = generate();

        let op_state = OperatorAuthState {
            db: pool.clone(),
            enforced: true,
            touch_cache: Cache::builder().build(),
        };

        // Build the same two-layer shape `server.rs` uses: an inner handler
        // behind a `blocks:read` scope_check, wrapped by the DB middleware.
        let make_app = || {
            Router::new()
                .route("/guarded", get(|| async { "ok" }))
                .route_layer(from_fn_with_state("blocks:read", scope_check))
                .layer(from_fn_with_state(op_state.clone(), middleware))
        };

        async fn status_for(app: Router, auth: Option<&str>) -> axum::http::StatusCode {
            let mut b = Request::builder().uri("/guarded");
            if let Some(a) = auth {
                b = b.header("authorization", format!("Bearer {a}"));
            }
            let resp = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
            resp.status()
        }

        use axum::http::StatusCode;
        // Valid token with the required scope → 200.
        assert_eq!(
            status_for(make_app(), Some(&tok_read)).await,
            StatusCode::OK,
            "valid token + matching scope must pass",
        );
        // Wildcard scope → 200.
        assert_eq!(
            status_for(make_app(), Some(&tok_wildcard)).await,
            StatusCode::OK,
            "wildcard scope must pass",
        );
        // Revoked token → 401 (the DB lookup filters `revoked_at IS NULL`).
        assert_eq!(
            status_for(make_app(), Some(&tok_revoked)).await,
            StatusCode::UNAUTHORIZED,
            "revoked token must be rejected",
        );
        // Valid token, wrong scope → 403.
        assert_eq!(
            status_for(make_app(), Some(&tok_wrong_scope)).await,
            StatusCode::FORBIDDEN,
            "insufficient scope must be 403",
        );
        // Well-formed but unknown token → 401.
        assert_eq!(
            status_for(make_app(), Some(&tok_unknown)).await,
            StatusCode::UNAUTHORIZED,
            "unknown token must be rejected",
        );
        // Missing Authorization header → 401.
        assert_eq!(
            status_for(make_app(), None).await,
            StatusCode::UNAUTHORIZED,
            "missing token must be rejected",
        );
        // Malformed token (agent prefix, not operator) → 401.
        assert_eq!(
            status_for(make_app(), Some("pxl_live_not_an_operator_token")).await,
            StatusCode::UNAUTHORIZED,
            "malformed token must be rejected",
        );

        // The DB UPDATE of `last_used_at` is spawned best-effort; give it a
        // moment, then confirm the valid token's row was touched.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let touched: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT last_used_at FROM operator_tokens WHERE token_hash = $1")
                .bind(&hash(&tok_read)[..])
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            touched.is_some(),
            "a successful auth must touch last_used_at"
        );
    }
}
