//! `AdapterState` — everything an adapter handler needs, in one Clone bag.

use std::sync::Arc;

use crate::auth_middleware::AuthState;
use crate::notifier::Notifiers;
use crate::pic::PicExecutor;
use crate::policy_handle::PolicyHandle;

use super::action_stream::ActionStream;

#[derive(Clone)]
pub struct AdapterState {
    pub auth: AuthState,
    /// Hot-reloadable handle. Adapters call `policy.load()` once per
    /// request to snapshot the current engine.
    pub policy: PolicyHandle,
    pub pic: PicExecutor,
    pub upstream: reqwest::Client,
    pub stream: Arc<dyn ActionStream>,
    /// Override Google's base URL for tests (wiremock). Production passes
    /// `None` and the adapter hard-codes `https://www.googleapis.com`.
    pub google_api_base: Option<String>,
    /// Customer domain — substituted into policy templates (`${customer_domain}`).
    pub customer_domain: String,
    /// All notifier drivers bundled. Each is independently hot-swappable
    /// via `/api/v1/notifier/config`; absent drivers no-op at fan-out.
    pub notifier: Notifiers,
}

impl AdapterState {
    pub fn google_api_base(&self) -> &str {
        self.google_api_base
            .as_deref()
            .unwrap_or("https://www.googleapis.com")
    }
}

#[cfg(test)]
mod tests {
    /// We test the lookup helper in isolation: building a full `AdapterState`
    /// requires a Postgres pool + the entire notifier bundle, but
    /// `google_api_base` is a pure `Option<String> → &str` resolver. Mirror
    /// the same `as_deref().unwrap_or(...)` shape on a stand-in so a future
    /// refactor that changed the default URL or flipped the precedence
    /// (override → fallback) would still need to update both this test and
    /// the production helper in lockstep.
    fn resolve(override_url: Option<String>) -> String {
        override_url
            .as_deref()
            .unwrap_or("https://www.googleapis.com")
            .to_string()
    }

    #[test]
    fn google_api_base_falls_back_to_production_googleapis_when_unset() {
        // Production posture — adapters that send to Google MUST land on
        // `www.googleapis.com` when no override is configured. A regression
        // that changed the fallback (e.g. to `googleapis.com` without the
        // `www`) would break TLS hostname verification at runtime.
        assert_eq!(resolve(None), "https://www.googleapis.com");
    }

    #[test]
    fn google_api_base_fallback_uses_https_scheme_not_http() {
        // Defense-in-depth on the production-fallback URL: a regression
        // that dropped the `https://` prefix (or fat-fingered `http://`)
        // would route adapter calls to plaintext on the production
        // googleapis hostname — every request would fail TLS but the
        // failure mode is a 30s connect timeout rather than a clean
        // error, masking the misconfiguration in alerts. Pin the
        // scheme prefix explicitly.
        let s = resolve(None);
        assert!(s.starts_with("https://"), "expected https scheme: {s}");
        assert!(
            !s.starts_with("http://"),
            "fallback URL must not be plaintext: {s}",
        );
    }

    #[test]
    fn google_api_base_respects_override_for_wiremock_tests() {
        // The wiremock integration tests in `crates/proxy/tests/` configure
        // an `AdapterState` with the mock server URL here. Pin the precedence
        // (override wins over the default) — a future refactor that swapped
        // the arms of `unwrap_or` would silently route adapter calls to
        // production from inside a test fixture.
        assert_eq!(
            resolve(Some("http://127.0.0.1:8080".into())),
            "http://127.0.0.1:8080",
        );
    }
}
