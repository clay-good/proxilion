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
