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
    fn oauth_state_and_google_client_are_send_sync_static_for_axum_state_boundary() {
        // `OAuthState` is wired into the OAuth handler `Router::with_state(...)`,
        // and `GoogleClient` lives inside it. Axum's State extractor requires
        // (Clone + Send + Sync + 'static). A refactor that gave either type an
        // `Rc<...>` field "for cheap shared HTTP-client handle" would break
        // Send + Sync but the breakage would surface at router assembly with
        // an opaque `tower::Service` trait-bound error. Pin both type bounds
        // at this file so the type boundary fails fast at the right call site.
        fn require_clone_send_sync_static<T: Clone + Send + Sync + 'static>() {}
        require_clone_send_sync_static::<OAuthState>();
        require_clone_send_sync_static::<GoogleClient>();
    }

    #[test]
    fn from_env_preserves_multibyte_unicode_in_client_id_and_secret_verbatim() {
        // `std::env::var` returns the raw bytes from the env (interpreted as
        // UTF-8); a client_id or secret with multibyte unicode (rare but
        // legal — e.g. a test fixture's `tëst-client-id-é`) must round-trip
        // byte-for-byte through `from_env`. Pin three multibyte spreads:
        // 2-byte `é`, 3-byte `→`, 4-byte `🔥` in BOTH client_id AND secret.
        // A refactor that called `.replace(non_ascii, "?")` "for SIEM
        // ASCII-only env-var ingest" or a hash-and-replace "for redaction"
        // would silently mangle every UTF-8-bearing test fixture.
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "client-é-→-🔥");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret-é-→-🔥");
            }
            let c = GoogleClient::from_env().unwrap();
            assert_eq!(c.client_id, "client-é-→-🔥");
            assert_eq!(c.client_secret, "secret-é-→-🔥");
        });
    }

    #[test]
    fn from_env_accepts_non_https_auth_url_override_without_validation() {
        // `from_env` is a verbatim passthrough — no URL parsing or scheme
        // validation. An operator pointing the override at an `http://` host
        // (a wiremock fixture under TLS-termination at a sidecar, say) MUST
        // see the bytes preserved as-is so the downstream reqwest client
        // sees the operator's literal scheme. A refactor that introduced
        // `url::Url::parse(...).require_https()` "for security" would
        // silently break every test fixture using http:// and surface as a
        // downstream reqwest error rather than as a clean boot-time error.
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
                std::env::set_var(
                    "GOOGLE_AUTH_URL",
                    "http://insecure-wiremock.local:8080/auth",
                );
                std::env::set_var(
                    "GOOGLE_TOKEN_URL",
                    "http://insecure-wiremock.local:8080/token",
                );
            }
            let c = GoogleClient::from_env().unwrap();
            assert_eq!(c.auth_url, "http://insecure-wiremock.local:8080/auth");
            assert_eq!(c.token_url, "http://insecure-wiremock.local:8080/token");
        });
    }

    #[test]
    fn google_client_clone_is_reflexive_double_clone_yields_field_equal_value() {
        // The existing `google_client_clone_yields_independent_owned_strings`
        // pin checks ownership independence after ONE clone. Pin reflexivity
        // across TWO chained clones — the OAuth handler chain currently
        // clones once at router wiring and once more on per-request scoping;
        // a refactor that introduced a "first clone deep-copies, subsequent
        // clones alias" optimization (a fringe pattern but real in some
        // Cow-based libraries) would surface here as the second clone NOT
        // matching the original field-for-field. Pin all four fields
        // byte-equal across the chained clone path.
        let orig = GoogleClient {
            client_id: "id-double".into(),
            client_secret: "secret-double".into(),
            auth_url: "https://double.example/auth".into(),
            token_url: "https://double.example/token".into(),
        };
        let c1 = orig.clone();
        let c2 = c1.clone();
        assert_eq!(c2.client_id, orig.client_id);
        assert_eq!(c2.client_secret, orig.client_secret);
        assert_eq!(c2.auth_url, orig.auth_url);
        assert_eq!(c2.token_url, orig.token_url);
    }

    #[test]
    fn google_client_debug_carries_all_four_field_names_in_single_render() {
        // The existing `google_client_debug_carries_client_id` and
        // `google_client_debug_carries_auth_url_and_token_url_field_names`
        // tests pin THREE of the four field names individually. Pin all
        // FOUR in one render so a manual Debug impl that surfaced three of
        // four (e.g. omitted `client_secret` "for defense-in-depth secret
        // hygiene at the trait level") would surface here. Note: the
        // operator-facing log call sites use `?google` and rely on the
        // derive — pinning at the trait level documents the four-field
        // shape; redaction belongs at the call-site formatter, not at the
        // Debug impl.
        let g = GoogleClient {
            client_id: "id-quad".into(),
            client_secret: "secret-quad".into(),
            auth_url: "https://quad.example/auth".into(),
            token_url: "https://quad.example/token".into(),
        };
        let s = format!("{g:?}");
        for field in ["client_id", "client_secret", "auth_url", "token_url"] {
            assert!(s.contains(field), "missing field {field} in: {s}");
        }
    }

    #[test]
    fn from_env_default_urls_match_published_google_oauth_endpoints_byte_exact() {
        // The two URL defaults are the published Google OAuth 2.0 endpoints
        // from developers.google.com/identity/protocols/oauth2 — operator
        // onboarding docs link to these literals. The existing tests pin
        // both as `assert_eq!` strings but in isolation; pin BOTH literals
        // in lockstep AND assert their byte-length so a refactor that
        // introduced a typo (e.g. `oauth2/v3` instead of `v2`, a one-char
        // diff that's easy to miss in review) would surface here as a
        // multi-axis equality failure. A trailing slash or query string
        // appended "for some boot-time normalization" would surface at the
        // byte-length pin even if the substring match still held.
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
            }
            let c = GoogleClient::from_env().unwrap();
            assert_eq!(c.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
            assert_eq!(c.auth_url.len(), 44);
            assert_eq!(c.token_url, "https://oauth2.googleapis.com/token");
            assert_eq!(c.token_url.len(), 35);
        });
    }

    #[test]
    fn google_client_from_env_return_type_is_result_self_string_for_main_caller_chain() {
        // `server.rs` historically called `GoogleClient::from_env()` and
        // bubbled the `Err(String)` into the boot-time error log. Pin the
        // return type as `Result<GoogleClient, String>` via a fn-pointer
        // witness so a refactor that promoted the error to a structured
        // type (e.g. `Result<Self, anyhow::Error>` "for richer triage")
        // would surface here at the type boundary rather than as a
        // confusing call-site mismatch in the boot path far from this
        // file. The `String` body shape is load-bearing for the boot-log
        // grep contract pinned by
        // `from_env_error_strings_are_byte_exact_for_operator_grep`.
        let _f: fn() -> Result<GoogleClient, String> = GoogleClient::from_env;
    }

    #[test]
    fn oauth_state_field_count_pinned_at_exactly_six_via_exhaustive_destructure() {
        // Pin OAuthState's field count at EXACTLY 6 via an exhaustive
        // destructure with NO `..` rest pattern. A future field landing
        // (e.g. an `audit_log_url` for cross-handler trace export, or a
        // 7th `oidc_discovery_cache`) without matching wiring at the
        // OAuth router assembly site would silently start carrying a
        // zero-value field — pinning the count here forces a compile-time
        // surface at the type boundary rather than a runtime "field is
        // empty in the dashboard" bug. The `_pin` fn is never invoked;
        // its body is type-checked at compile time, which is what we want.
        #[allow(dead_code)]
        fn _pin(s: OAuthState) {
            let OAuthState {
                db: _,
                cipher: _,
                pic: _,
                google: _,
                federation_bridge_authorize_url: _,
                proxy_base_url: _,
            } = s;
        }
    }

    #[test]
    fn google_client_field_count_pinned_at_exactly_four_via_exhaustive_destructure() {
        // Symmetric to the OAuthState destructure pin: GoogleClient has
        // EXACTLY 4 fields (client_id, client_secret, auth_url, token_url).
        // A future 5th field (e.g. `scopes: Vec<String>` for per-tenant
        // scope policy) without matching `from_env` wiring would silently
        // drop the new field at boot — pinning the count here forces
        // the refactor to update both this test AND `from_env` in lockstep.
        // Pinned via destructure with no `..` rest pattern.
        let g = GoogleClient {
            client_id: "id".into(),
            client_secret: "secret".into(),
            auth_url: "u1".into(),
            token_url: "u2".into(),
        };
        let GoogleClient {
            client_id,
            client_secret,
            auth_url,
            token_url,
        } = g;
        // Reference the four bindings so the pattern isn't dead-code-elided.
        assert_eq!(client_id, "id");
        assert_eq!(client_secret, "secret");
        assert_eq!(auth_url, "u1");
        assert_eq!(token_url, "u2");
    }

    #[test]
    fn google_client_field_types_all_owned_string_for_per_request_clone_independence() {
        // All four GoogleClient fields MUST be owned `String` (not
        // `&'static str` or `Arc<str>`) so the per-request handler clone
        // gets its own buffer the OAuth callback can — in principle —
        // mutate without aliasing back to the AppState-held original.
        // The existing `google_client_clone_yields_independent_owned_strings`
        // pin checks mutation-independence at runtime; pin the
        // require_string TYPE witness explicitly so an `Arc<str>` refactor
        // would surface at the type boundary BEFORE the mutation test
        // tripped. Helper takes `String` only.
        fn require_string(_: String) {}
        let g = GoogleClient {
            client_id: "id".into(),
            client_secret: "s".into(),
            auth_url: "u1".into(),
            token_url: "u2".into(),
        };
        require_string(g.client_id);
        require_string(g.client_secret);
        require_string(g.auth_url);
        require_string(g.token_url);
    }

    #[test]
    fn from_env_is_referentially_transparent_across_repeated_calls_with_stable_env() {
        // `from_env` is a pure (env-var → struct) lookup. With the env
        // held stable across 50 sequential calls, the returned struct
        // MUST be byte-equal across all 50 calls — a refactor that
        // introduced any form of state (a once-cell-cached struct, a
        // counter, a per-call rotation for "fairness across regional
        // endpoints") would surface here. Symmetric to the
        // `verify_pkce_s256_is_referentially_transparent_across_repeated_calls`
        // pin in `pkce.rs`.
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id-rt");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret-rt");
                std::env::set_var("GOOGLE_AUTH_URL", "https://example.test/auth-rt");
                std::env::set_var("GOOGLE_TOKEN_URL", "https://example.test/token-rt");
            }
            let first = GoogleClient::from_env().unwrap();
            for _ in 0..50 {
                let c = GoogleClient::from_env().unwrap();
                assert_eq!(c.client_id, first.client_id);
                assert_eq!(c.client_secret, first.client_secret);
                assert_eq!(c.auth_url, first.auth_url);
                assert_eq!(c.token_url, first.token_url);
            }
        });
    }

    #[test]
    fn google_client_default_auth_url_contains_v2_segment_not_v1_or_v3() {
        // The default `auth_url` byte-exact equality is pinned elsewhere;
        // pin a path-segment slice of it here so a refactor that "bumped"
        // the segment to v1 or v3 (a one-char diff that's easy to miss
        // in review) surfaces as a substring-presence failure on a
        // distinct axis from the byte-length check pinned by
        // `from_env_default_urls_match_published_google_oauth_endpoints_byte_exact`.
        // The published Google OAuth 2.0 user-authorize endpoint is on
        // `/o/oauth2/v2/auth` — operator-onboarding docs anchor on the
        // `/v2/` segment.
        with_clean_env(|| {
            // SAFETY: serialized by ENV_GUARD via `with_clean_env`.
            unsafe {
                std::env::set_var("GOOGLE_CLIENT_ID", "id");
                std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
            }
            let c = GoogleClient::from_env().unwrap();
            assert!(
                c.auth_url.contains("/v2/"),
                "auth_url default missing /v2/ segment: {}",
                c.auth_url
            );
            assert!(
                !c.auth_url.contains("/v1/"),
                "auth_url default carries /v1/ — segment drift: {}",
                c.auth_url
            );
            assert!(
                !c.auth_url.contains("/v3/"),
                "auth_url default carries /v3/ — segment drift: {}",
                c.auth_url
            );
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
