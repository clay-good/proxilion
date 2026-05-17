//! `SessionContext` + `SessionCtx` extractor.
//!
//! The auth middleware (`crate::auth_middleware`) populates a
//! `SessionContext` and inserts it into request extensions; downstream
//! handlers extract it via `SessionCtx(session): SessionCtx`.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// Everything an adapter needs to act on behalf of the human user.
///
/// `google_access_token` is the *plaintext* OAuth token, decrypted into
/// process memory for the request lifetime only — never persisted, never
/// logged, never Debug-printed.
pub struct SessionContext {
    pub agent_session_id: Uuid,
    /// SHA-256 of the live bearer; used by the killswitch (§3.2) and audit.
    #[allow(dead_code)]
    pub bearer_hash: [u8; 32],
    pub p_0: String,
    pub leaf_pca_id: Uuid,
    /// Raw signed-PCA CBOR; adapters in §1.3+ pass this to the executor as
    /// the predecessor when minting per-action successors.
    #[allow(dead_code)]
    pub leaf_pca_cbor: Vec<u8>,
    pub granted_ops: Vec<String>,
    /// Plaintext Google OAuth token — handed to adapters for upstream calls.
    /// Lives in process memory for the request lifetime only.
    #[allow(dead_code)]
    pub google_access_token: String,
    pub google_token_scope: String,
}

impl std::fmt::Debug for SessionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionContext")
            .field("agent_session_id", &self.agent_session_id)
            .field("p_0", &self.p_0)
            .field("leaf_pca_id", &self.leaf_pca_id)
            .field("granted_ops", &self.granted_ops)
            .field("google_access_token", &"[redacted]")
            .field("google_token_scope", &self.google_token_scope)
            .finish()
    }
}

/// Axum extractor for handlers that require an authenticated session.
///
/// The middleware inserts an `Arc<SessionContext>` into extensions; we only
/// hand out an `Arc` so cloning across spawned tasks is cheap.
#[derive(Clone)]
pub struct SessionCtx(pub Arc<SessionContext>);

impl<S> FromRequestParts<S> for SessionCtx
where
    S: Send + Sync,
{
    type Rejection = SessionExtractError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Arc<SessionContext>>()
            .cloned()
            .map(SessionCtx)
            .ok_or(SessionExtractError)
    }
}

/// Returned when the auth middleware didn't run (or didn't populate the
/// extension) before a route that requires a session. Always 401 with a
/// generic body.
pub struct SessionExtractError;

impl IntoResponse for SessionExtractError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ctx() -> SessionContext {
        SessionContext {
            agent_session_id: Uuid::nil(),
            bearer_hash: [0u8; 32],
            p_0: "alice@acme.com".into(),
            leaf_pca_id: Uuid::nil(),
            leaf_pca_cbor: vec![1, 2, 3],
            granted_ops: vec!["drive:read:file/x".into()],
            google_access_token: "ya29.SUPER_SECRET_TOKEN_VALUE".into(),
            google_token_scope: "https://www.googleapis.com/auth/drive.readonly".into(),
        }
    }

    #[test]
    fn debug_redacts_google_access_token() {
        let ctx = sample_ctx();
        let s = format!("{ctx:?}");
        assert!(!s.contains("SUPER_SECRET_TOKEN_VALUE"));
        assert!(s.contains("[redacted]"));
        // Non-sensitive fields stay visible.
        assert!(s.contains("alice@acme.com"));
        assert!(s.contains("drive.readonly"));
    }

    #[tokio::test]
    async fn session_extract_error_into_response_is_401() {
        let r = SessionExtractError.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], b"unauthorized");
    }

    #[tokio::test]
    async fn extractor_returns_err_when_extension_missing() {
        let req = axum::http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        let result: Result<SessionCtx, SessionExtractError> =
            SessionCtx::from_request_parts(&mut parts, &()).await;
        // SessionExtractError doesn't impl Debug, so match instead of unwrap_err.
        match result {
            Err(_) => {}
            Ok(_) => panic!("expected SessionExtractError"),
        }
    }

    #[test]
    fn debug_omits_bearer_hash_and_leaf_pca_cbor_to_avoid_leaking_credential_material() {
        // bearer_hash is the SHA-256 the killswitch SQL predicate keys on
        // (knowing it lets an attacker construct a kill-row); leaf_pca_cbor
        // carries the signed PCA bytes. Both are intentionally absent from
        // the Debug impl. A future field added without updating Debug would
        // surface here.
        let ctx = sample_ctx();
        let s = format!("{ctx:?}");
        assert!(
            !s.contains("bearer_hash"),
            "bearer_hash leaked in Debug: {s}"
        );
        assert!(
            !s.contains("leaf_pca_cbor"),
            "leaf_pca_cbor leaked in Debug: {s}"
        );
    }

    #[test]
    fn session_ctx_clone_shares_arc_with_original() {
        // The #[derive(Clone)] on SessionCtx tuple-clones the inner Arc
        // rather than deep-copying the context — this is the invariant
        // every spawned task depends on (cheap clone for fan-out). A
        // refactor to `pub struct SessionCtx(pub SessionContext)` would
        // surface here as an Arc::ptr_eq failure rather than as a silent
        // performance/correctness regression at use sites.
        let ctx = Arc::new(sample_ctx());
        let a = SessionCtx(ctx.clone());
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.0, &b.0));
        assert!(Arc::ptr_eq(&a.0, &ctx));
    }

    #[tokio::test]
    async fn session_extract_error_body_is_exactly_twelve_bytes() {
        // Pin the body length so a refactor that appended a CRLF, JSON
        // wrapper, or HTML envelope would surface here. Operator alerts
        // key on the 401 rate for this fixed-body path as the "agent
        // session lost" signal — changing the body shape (even just adding
        // a trailing newline) would break log-parsing dashboards.
        let r = SessionExtractError.into_response();
        let bytes = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..], b"unauthorized");
    }

    #[tokio::test]
    async fn extractor_returns_ok_when_arc_session_context_present() {
        let ctx = Arc::new(sample_ctx());
        let req = axum::http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        parts.extensions.insert(ctx.clone());
        let extracted = SessionCtx::from_request_parts(&mut parts, &()).await;
        let SessionCtx(out) = match extracted {
            Ok(v) => v,
            Err(_) => panic!("expected Ok"),
        };
        assert!(Arc::ptr_eq(&ctx, &out));
    }
}
