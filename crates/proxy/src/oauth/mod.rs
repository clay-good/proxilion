//! OAuth interception with PIC-aware identity establishment.
//!
//! Authority: spec.md §1.1. Flow (one paragraph):
//!
//! 1. Agent → `/oauth/google/authorize` (carries `client_id`, `redirect_uri`,
//!    `state`, `code_challenge`, `scope`). We persist a session row and
//!    302 the user's browser to the federation-bridge.
//! 2. Bridge authenticates the human against the IdP, mints PCA_0 via the
//!    Trust Plane, then 302s back to `/oauth/bridge/callback` carrying a
//!    short-lived `federation_token` (JWT) whose claims point at PCA_0.
//!    We validate the JWT, persist `pca_0_id` to the session, and 302 the
//!    browser to real Google OAuth with `scope` intersected against
//!    `PCA_0.ops`.
//! 3. Google → `/oauth/google/callback?code=…`. We exchange the code,
//!    encrypt the resulting Google tokens with AES-256-GCM, build a PoC
//!    binding our executor key to PCA_0, request PCA_1 from Trust Plane
//!    (`POST /v1/poc/process`), mint a `pxl_live_*` bearer, persist a
//!    single-use authorization code, and 302 the agent's `redirect_uri`.
//! 4. Agent → `POST /oauth/google/token`. We verify PKCE, mark the code
//!    consumed, and return `{ access_token: pxl_live_…, token_type, expires_in,
//!    scope }`.
//!
//! Federation-bridge JWT validation is currently *payload-only* (matches the
//! Trust Plane stub described in §0.4 Status). Wire JWKS signature
//! verification before production — see `bridge::validate_federation_token`.

pub mod bridge;
pub mod error;
pub mod routes;
pub mod state;

#[allow(unused_imports)]
pub use error::OAuthError;
pub use routes::router;
pub use state::OAuthState;
