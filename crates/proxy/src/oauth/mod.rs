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
pub mod idp_verify;
pub mod routes;
pub mod state;

#[allow(unused_imports)]
pub use error::OAuthError;
pub use routes::router;
pub use state::OAuthState;

use chrono::{DateTime, Duration, Utc};

/// Largest access-token TTL we will trust from an OAuth token endpoint, in
/// seconds (one year). Google issues ~3600s; any value beyond a year is
/// either a misbehaving endpoint or an attacker steering an operator-overridden
/// `GOOGLE_TOKEN_URL`.
const MAX_TOKEN_TTL_SECS: i64 = 365 * 24 * 60 * 60;

/// Convert an OAuth `expires_in` (seconds, straight off untrusted upstream
/// JSON as an `i64`) into an absolute expiry timestamp.
///
/// `chrono::Duration::seconds` panics for out-of-range inputs and
/// `DateTime + Duration` panics on overflow, so a hostile or buggy token
/// endpoint returning e.g. `i64::MAX` for `expires_in` would otherwise crash
/// the OAuth callback / refresh task. Clamping into `[0, MAX_TOKEN_TTL_SECS]`
/// removes both panics; over-estimating the TTL is harmless because Google
/// rejects a truly-expired access token at use time (handled by the
/// near-expiry path in `auth_middleware`).
pub(crate) fn token_expiry(expires_in: i64) -> DateTime<Utc> {
    Utc::now() + Duration::seconds(expires_in.clamp(0, MAX_TOKEN_TTL_SECS))
}

#[cfg(test)]
mod token_expiry_tests {
    use super::*;

    #[test]
    fn token_expiry_does_not_panic_on_i64_max_and_clamps_to_one_year() {
        // i64::MAX seconds would panic both Duration::seconds and the add;
        // the clamp caps it at one year out.
        let exp = token_expiry(i64::MAX);
        let cap = Utc::now() + Duration::seconds(MAX_TOKEN_TTL_SECS);
        // Within a couple seconds of the one-year cap (wall-clock between the
        // two `Utc::now()` calls).
        assert!((exp - cap).num_seconds().abs() <= 2, "exp={exp}, cap={cap}");
    }

    #[test]
    fn token_expiry_clamps_negative_to_now() {
        let exp = token_expiry(-100);
        assert!((exp - Utc::now()).num_seconds().abs() <= 2);
    }

    #[test]
    fn token_expiry_passes_through_a_normal_ttl() {
        let exp = token_expiry(3600);
        let want = Utc::now() + Duration::seconds(3600);
        assert!((exp - want).num_seconds().abs() <= 2);
    }
}
