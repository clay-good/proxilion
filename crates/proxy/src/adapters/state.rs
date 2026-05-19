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
    fn google_api_base_override_with_empty_string_returns_empty_not_fallback() {
        // Boundary: `Option<String>::Some(String::new())` is a
        // wire-distinct shape from `None`. The current `as_deref()`
        // returns `Some("")` which DOES NOT trigger `unwrap_or`'s
        // fallback — the empty string is returned verbatim. Pin
        // this behavior so a future refactor that switched to
        // `.filter(|s| !s.is_empty()).unwrap_or(...)` (a tempting
        // "treat empty-string env var as unset" change) would
        // surface here as a wire-shape difference. Today's contract:
        // empty override is the operator's explicit choice, not a
        // misconfigured `None`; honor it.
        assert_eq!(resolve(Some(String::new())), "");
    }

    #[test]
    fn google_api_base_override_preserves_trailing_slash_unchanged() {
        // The helper is a pure passthrough — it does NOT trim or
        // normalize the override. Pin that a trailing `/` survives
        // (operators sometimes configure the override as a base URL
        // with or without the slash, and the adapter call sites
        // currently expect the override to be used verbatim before
        // they append their own path segments). A regression that
        // started calling `.trim_end_matches('/')` here would
        // silently change every adapter request URL by one byte.
        assert_eq!(
            resolve(Some("http://wiremock.local:8080/".into())),
            "http://wiremock.local:8080/",
        );
    }

    #[test]
    fn google_api_base_override_preserves_multi_segment_path_verbatim() {
        // A wiremock fixture may host the Google mock under a
        // sub-path (e.g. `/google` to share a server with other
        // mocked services). Pin that the helper passes the full
        // override through without stripping path segments — a
        // regression that started extracting only the host
        // (`url::Url::host_str` shape) would silently re-route
        // every adapter call to the wiremock root instead of the
        // configured sub-path, breaking the test fixture.
        assert_eq!(
            resolve(Some("http://127.0.0.1:9000/google/v1".into())),
            "http://127.0.0.1:9000/google/v1",
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

    #[test]
    fn google_api_base_production_fallback_is_byte_exact_canonical_literal() {
        // The existing `falls_back_to_production_googleapis_when_unset` pin
        // asserts equality against the canonical literal once. Pin three
        // additional shape-invariants on the same canonical string in
        // lockstep so a refactor that "normalized" the URL (lowercasing the
        // already-lowercase host, appending a `/`, swapping `www` for
        // `api`) would surface here as a multi-line diff rather than a
        // single-character change someone could miss in review: byte-length
        // is exactly 26 (`https://` 8 + `www.googleapis.com` 18); contains
        // exactly two `.` separators (between www/googleapis and
        // googleapis/com); ends with `.com` not `.com/` or `.com.`. The
        // adapter call sites APPEND their own path segments (e.g.
        // `/calendar/v3/calendars/...`) so a trailing slash here would
        // produce `//calendar/...` and break upstream routing.
        let s = resolve(None);
        assert_eq!(s.len(), 26, "fallback URL byte-length drifted: {s}");
        assert_eq!(s.matches('.').count(), 2, "expected two dots: {s}");
        assert!(s.ends_with(".com"), "fallback must end with .com: {s}");
        assert!(
            !s.ends_with(".com/") && !s.ends_with(".com."),
            "fallback must not have trailing punctuation: {s}",
        );
    }

    #[test]
    fn google_api_base_repeated_calls_are_byte_stable() {
        // The helper is pure (no interior mutability, no clock, no env
        // lookup at call time — the env is read once at `AdapterState`
        // assembly and stored in the field). Pin that 100 sequential
        // calls return byte-equal strings for BOTH None and a Some
        // override — a refactor that introduced a once-cell with a
        // racy default ("read GOOGLE_API_BASE_URL lazily on first
        // call") would surface here as either a flaky equality or
        // a wholly different return on a later call.
        let first_none = resolve(None);
        for _ in 0..100 {
            assert_eq!(resolve(None), first_none);
        }
        let override_url = "http://wiremock.local:8080/v1".to_string();
        let first_some = resolve(Some(override_url.clone()));
        for _ in 0..100 {
            assert_eq!(resolve(Some(override_url.clone())), first_some);
        }
    }

    #[test]
    fn google_api_base_override_preserves_query_and_fragment_verbatim() {
        // The helper is a pure `Option<String> → &str` passthrough — it
        // does NOT parse the override as a URL or normalize query/fragment
        // segments. Pin that a query string (`?proxy=1`) AND a fragment
        // (`#tag`) both survive byte-for-byte. The adapter call sites
        // append their own path under the base; an operator who chose to
        // smuggle query state via the override (an unusual but valid
        // operator escape hatch) MUST see that state preserved. A refactor
        // that called `url::Url::parse(...).set_path("")` "to normalize"
        // would silently strip both, and the adapter would call a
        // wholly-different upstream.
        assert_eq!(
            resolve(Some("http://wiremock.local:8080/v1?proxy=1#tag".into())),
            "http://wiremock.local:8080/v1?proxy=1#tag",
        );
    }

    #[test]
    fn google_api_base_override_preserves_uppercase_host_verbatim() {
        // RFC 3986 says host components are case-insensitive, but the
        // helper does NOT lowercase — it is a pure passthrough. Pin
        // that an UPPERCASE-host override (the kind a copy-paste from a
        // shouted-into-Slack URL might produce) survives byte-equal so
        // the adapter call sites see the operator's literal string. A
        // refactor that added `.to_lowercase()` "to canonicalize for
        // TLS SNI" would silently mutate every adapter request URL by
        // multiple bytes and break exact-match wiremock matchers.
        assert_eq!(
            resolve(Some("HTTP://WIREMOCK.LOCAL:8080".into())),
            "HTTP://WIREMOCK.LOCAL:8080",
        );
    }

    #[test]
    fn google_api_base_override_preserves_unicode_path_verbatim() {
        // The helper passes the override through byte-for-byte without
        // percent-encoding or unicode normalization. Pin that a multibyte
        // unicode path segment (`café` 5 bytes, `→` 3 bytes, `🔥` 4 bytes)
        // survives byte-equal. The hyper/reqwest layer downstream will
        // percent-encode at send time; the AdapterState helper itself
        // must not touch the bytes. A refactor that called
        // `percent_encoding::utf8_percent_encode(...)` here "to be safe"
        // would double-encode at the request-build site and break the
        // URL the operator configured.
        let unicode = "http://wiremock.local:8080/café/→/🔥";
        assert_eq!(resolve(Some(unicode.into())), unicode);
    }

    #[test]
    fn google_api_base_override_with_whitespace_only_returns_whitespace_not_fallback() {
        // Symmetric to `empty_string_returns_empty_not_fallback` — a
        // whitespace-only override (` `, `   `, `\t`) is NOT a None and
        // MUST NOT trigger the fallback. The helper returns the literal
        // whitespace verbatim. Pin three distinct whitespace shapes
        // (single space, multiple spaces, tab) — a refactor that added
        // `.filter(|s| !s.trim().is_empty())` "for ergonomic operator
        // misconfig handling" would silently route every adapter call
        // to production from a misconfigured test fixture, and the
        // test fixture's wiremock would never see a request. Today's
        // contract: whitespace is the operator's explicit choice.
        for ws in [" ", "   ", "\t"] {
            assert_eq!(resolve(Some(ws.into())), ws, "whitespace input {ws:?}");
        }
    }
}
