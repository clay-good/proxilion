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
    fn from_env_respects_only_token_url_override_with_auth_url_default() {
        // Symmetric counterpart to `from_env_respects_only_auth_url_override_with_token_url_default`
        // — operator overrides TOKEN_URL only (e.g. to point at a regional
        // token endpoint while leaving the user-facing auth URL on
        // production). The existing tests pin no-override AND both-override
        // AND auth-only-override; this fills the missing fourth corner so
        // a refactor that "consistently" tied the two URLs (one override
        // forces both) would surface here rather than after a regional
        // rollout.
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
                std::env::set_var("GOOGLE_TOKEN_URL", "https://example.test/token");
            }
            let c = GoogleClient::from_env().unwrap();
            assert_eq!(c.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
            assert_eq!(c.token_url, "https://example.test/token");
        });
    }

    #[test]
    fn from_env_error_strings_are_byte_exact_for_operator_grep() {
        // The boot-path error surface from `from_env` is a `String` (not a
        // structured error type) — operator boot-failure log filters key
        // on the exact `"GOOGLE_CLIENT_ID is required"` /
        // `"GOOGLE_CLIENT_SECRET is required"` strings. The existing two
        // tests only assert the env-var-name substring (`.contains(...)`)
        // — a refactor that pluralized the message (`"... are required"`)
        // or stripped the verb (`"GOOGLE_CLIENT_ID missing"`) would still
        // pass the substring check but silently break every operator
        // alert filter. Pin byte-exact equality for both arms.
        with_clean_env(|| {
            let err = GoogleClient::from_env().unwrap_err();
            assert_eq!(err, "GOOGLE_CLIENT_ID is required");
        });
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
            }
            let err = GoogleClient::from_env().unwrap_err();
            assert_eq!(err, "GOOGLE_CLIENT_SECRET is required");
        });
    }

    #[test]
    fn from_env_accepts_empty_client_id_and_secret_without_error_path() {
        // `std::env::var` returns `Err(NotPresent)` only when the variable
        // is unset (or not unicode) — an empty-string value yields
        // `Ok(String::new())`. Pin that `from_env` honors the wire-shape
        // distinction: an empty CLIENT_ID is the operator's explicit (if
        // misguided) choice, not a missing var, and `from_env` returns
        // Ok rather than the `"... is required"` Err. A refactor that
        // tightened the check to `.filter(|s| !s.is_empty())` (a tempting
        // "treat empty env var as unset" change) would surface here as
        // breaking the wire-shape distinction the boot path relies on
        // (the downstream Google client will fail-fast on the empty id
        // with its own actionable error, rather than us silently masking
        // the operator's typo at boot).
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "");
            }
            let c = GoogleClient::from_env().expect("empty-string env vars are Ok wire shape");
            assert_eq!(c.client_id, "");
            assert_eq!(c.client_secret, "");
            // URL defaults still kick in (the empty CLIENT_ID does not
            // short-circuit the URL fallback branches).
            assert_eq!(c.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
            assert_eq!(c.token_url, "https://oauth2.googleapis.com/token");
        });
    }

    #[test]
    fn google_client_debug_carries_auth_url_and_token_url_field_names() {
        // Symmetric pin to `google_client_debug_carries_client_id` — the
        // boot-time `tracing::warn!(?google, ..)` render must surface the
        // URL fields too (operators rely on the rendered URLs to confirm
        // regional overrides took effect). A manual Debug that hid the
        // URL fields "for brevity" would silently strip the operator's
        // verification handle. Pin both field names AND a representative
        // URL value.
        let g = GoogleClient {
            client_id: "id".into(),
            client_secret: "s".into(),
            auth_url: "https://regional.example.test/auth".into(),
            token_url: "https://regional.example.test/token".into(),
        };
        let s = format!("{g:?}");
        assert!(s.contains("auth_url"), "got: {s}");
        assert!(s.contains("token_url"), "got: {s}");
        assert!(s.contains("https://regional.example.test/auth"), "got: {s}");
        assert!(
            s.contains("https://regional.example.test/token"),
            "got: {s}"
        );
    }

    #[test]
    fn google_client_clone_yields_independent_owned_strings() {
        // The existing `google_client_clone_preserves_every_field` test
        // pins value-equality after clone but does NOT pin string
        // ownership independence — a refactor that swapped `String` for
        // `Arc<str>` "for cheaper clone" would still pass the
        // value-equality test while changing the per-request mutation
        // safety the OAuth state design relies on. Pin mutation
        // independence: mutating a clone's field MUST NOT alias back to
        // the original. The OAuth handler clones GoogleClient into each
        // request's per-call scope and (in principle) may mutate URL
        // fields for sub-path routing — silent aliasing would surface
        // as cross-request URL bleed.
        let mut g = GoogleClient {
            client_id: "id-original".into(),
            client_secret: "secret-original".into(),
            auth_url: "https://orig.example/auth".into(),
            token_url: "https://orig.example/token".into(),
        };
        let c = g.clone();
        g.client_id.push_str("-MUTATED");
        g.client_secret.push_str("-MUTATED");
        g.auth_url.push_str("/MUTATED");
        g.token_url.push_str("/MUTATED");
        // Clone snapshot untouched across all four String fields.
        assert_eq!(c.client_id, "id-original");
        assert_eq!(c.client_secret, "secret-original");
        assert_eq!(c.auth_url, "https://orig.example/auth");
        assert_eq!(c.token_url, "https://orig.example/token");
    }

    #[test]
    fn from_env_preserves_url_override_verbatim_including_whitespace_and_trailing_slash() {
        // `from_env` is a verbatim passthrough — `std::env::var` returns
        // the env var bytes unchanged, and the existing tests pin the
        // happy-path URL value-equality but do NOT pin the verbatim
        // contract against an override carrying surprising bytes
        // (whitespace, trailing slash). The proxy's call sites that
        // append path segments after `auth_url` / `token_url` assume the
        // operator-provided URL is used as-is — a refactor that started
        // `.trim()`-ing or stripping a trailing slash here "for
        // robustness" would silently change every constructed OAuth URL
        // by one or more bytes. Pin trailing-slash AND surrounding
        // whitespace passthrough on both URL fields.
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
                std::env::set_var("GOOGLE_AUTH_URL", "  https://override.test/auth/  ");
                std::env::set_var("GOOGLE_TOKEN_URL", "https://override.test/token/");
            }
            let c = GoogleClient::from_env().unwrap();
            // Whitespace preserved (no .trim()).
            assert_eq!(c.auth_url, "  https://override.test/auth/  ");
            // Trailing slash preserved (no .trim_end_matches('/')).
            assert_eq!(c.token_url, "https://override.test/token/");
        });
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
