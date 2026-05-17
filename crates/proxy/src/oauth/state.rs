//! OAuth handler state — DB pool + Google client config + executor handle.
//!
//! Lives separate from the wider proxy AppState so the OAuth handlers can
//! be unit-tested with a mocked-up state.

use std::sync::Arc;

use sqlx::PgPool;

use crate::crypto::TokenCipher;
use crate::pic::PicExecutor;

#[derive(Clone)]
pub struct OAuthState {
    pub db: PgPool,
    pub cipher: Arc<TokenCipher>,
    pub pic: PicExecutor,
    pub google: GoogleClient,
    /// Federation-bridge user-authorize endpoint (full URL).
    pub federation_bridge_authorize_url: String,
    /// Proxy's own public base URL — used to build redirect_uris we hand
    /// to upstream OAuth servers.
    pub proxy_base_url: String,
}

#[derive(Clone, Debug)]
pub struct GoogleClient {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String, // default: https://accounts.google.com/o/oauth2/v2/auth
    pub token_url: String, // default: https://oauth2.googleapis.com/token
}

impl GoogleClient {
    #[allow(dead_code)] // convenience constructor; server.rs builds the struct inline
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            client_id: std::env::var("GOOGLE_CLIENT_ID")
                .map_err(|_| "GOOGLE_CLIENT_ID is required".to_string())?,
            client_secret: std::env::var("GOOGLE_CLIENT_SECRET")
                .map_err(|_| "GOOGLE_CLIENT_SECRET is required".to_string())?,
            auth_url: std::env::var("GOOGLE_AUTH_URL")
                .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/v2/auth".into()),
            token_url: std::env::var("GOOGLE_TOKEN_URL")
                .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env vars are process-global; the four tests below mutate the same
    // set and must run serially. Cargo runs unit tests in parallel by
    // default — guard with a single in-module mutex.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn with_clean_env<F: FnOnce()>(f: F) {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let keys = [
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_AUTH_URL",
            "GOOGLE_TOKEN_URL",
        ];
        // Save → clear → run → restore so we don't trample a real shell env.
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for k in &keys {
            // SAFETY: tests are serialized via ENV_GUARD; mutating the env
            // outside the guarded scope would race the wider test runner.
            unsafe {
                std::env::remove_var(k);
            }
        }
        f();
        for (k, v) in saved {
            // SAFETY: same as above — restoration only happens inside the
            // serialized scope.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn from_env_errors_when_client_id_missing() {
        with_clean_env(|| {
            let err = GoogleClient::from_env().unwrap_err();
            assert!(err.contains("GOOGLE_CLIENT_ID"));
        });
    }

    #[test]
    fn from_env_errors_when_secret_missing() {
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
            }
            let err = GoogleClient::from_env().unwrap_err();
            assert!(err.contains("GOOGLE_CLIENT_SECRET"));
        });
    }

    #[test]
    fn from_env_defaults_auth_and_token_urls_when_unset() {
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
            }
            let c = GoogleClient::from_env().unwrap();
            assert_eq!(c.client_id, "id");
            assert_eq!(c.client_secret, "secret");
            assert_eq!(c.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
            assert_eq!(c.token_url, "https://oauth2.googleapis.com/token");
        });
    }

    #[test]
    fn google_client_clone_preserves_every_field() {
        // `GoogleClient` derives `Clone` — the OAuth router clones it
        // into per-request handler state. Pin that all four fields
        // round-trip a clone without aliasing or truncation (a
        // refactor that switched to `Cow<str>` would silently break
        // the per-request mutation-safety the OAuthState design relies
        // on).
        let g = GoogleClient {
            client_id: "id-abc".into(),
            client_secret: "secret-xyz".into(),
            auth_url: "https://example.test/auth".into(),
            token_url: "https://example.test/token".into(),
        };
        let c = g.clone();
        assert_eq!(c.client_id, "id-abc");
        assert_eq!(c.client_secret, "secret-xyz");
        assert_eq!(c.auth_url, "https://example.test/auth");
        assert_eq!(c.token_url, "https://example.test/token");
    }

    #[test]
    fn from_env_respects_only_auth_url_override_with_token_url_default() {
        // Asymmetric override path — operator overrides AUTH_URL only
        // (e.g. to point at a regional Google endpoint) and expects
        // TOKEN_URL to keep its production default. Pin both halves so
        // a refactor that "consistently" required both URLs together
        // would surface here. Symmetric counterpart for TOKEN_URL is
        // pinned via `from_env_respects_url_overrides`.
        with_clean_env(|| {
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
                std::env::set_var("GOOGLE_AUTH_URL", "https://example.test/auth");
            }
            let c = GoogleClient::from_env().unwrap();
            assert_eq!(c.auth_url, "https://example.test/auth");
            assert_eq!(c.token_url, "https://oauth2.googleapis.com/token");
        });
    }

    #[test]
    fn google_client_debug_carries_client_id() {
        // The `Debug` derive feeds `tracing::warn!(?google, ...)` at
        // boot — pin that the (non-secret) `client_id` is visible in
        // the rendered string. A manual Debug impl that hid every
        // field (in the name of "redact secrets") would silently
        // strip the operator-facing id alongside the secret. Note:
        // `client_secret` is included by the derive — the boot path
        // does NOT log the full struct; this test pins the trait, not
        // the log line.
        let g = GoogleClient {
            client_id: "abc-client-id".into(),
            client_secret: "x".into(),
            auth_url: "u1".into(),
            token_url: "u2".into(),
        };
        let s = format!("{g:?}");
        assert!(s.contains("abc-client-id"), "got: {s}");
        assert!(s.contains("client_id"));
    }

    #[test]
    fn from_env_respects_url_overrides() {
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
                std::env::set_var("GOOGLE_AUTH_URL", "https://example.test/auth");
                std::env::set_var("GOOGLE_TOKEN_URL", "https://example.test/token");
            }
            let c = GoogleClient::from_env().unwrap();
            assert_eq!(c.auth_url, "https://example.test/auth");
            assert_eq!(c.token_url, "https://example.test/token");
        });
    }
}
