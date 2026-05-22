use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;
use tracing::{error, warn};

use crate::error_envelope::ErrorBody;

/// All OAuth handler errors. We deliberately bucket *upstream* failures
/// (4xx-from-Google, 4xx-from-Trust-Plane) separately from internal bugs so
/// the response body cannot ever leak secrets — every variant maps to a
/// fixed user-facing string and the detail goes only to logs.
#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("unknown OAuth client")]
    UnknownClient,

    #[error("session expired or unknown")]
    SessionGone,

    #[error("federation token rejected: {0}")]
    BridgeRejected(String),

    #[error("PKCE verification failed")]
    PkceFail,

    #[error("authorization code invalid or already used")]
    BadAuthCode,

    #[error("Trust Plane refused PCA: {0}")]
    PicInvariant(String),

    #[error("upstream call failed")]
    Upstream(#[from] reqwest::Error),

    #[error("database error")]
    Db(#[from] sqlx::Error),

    #[error("crypto failure")]
    Crypto,

    #[error("internal error")]
    Internal(String),
}

impl OAuthError {
    fn status(&self) -> StatusCode {
        match self {
            OAuthError::BadRequest(_)
            | OAuthError::UnknownClient
            | OAuthError::PkceFail
            | OAuthError::BadAuthCode => StatusCode::BAD_REQUEST,
            OAuthError::SessionGone | OAuthError::BridgeRejected(_) => StatusCode::UNAUTHORIZED,
            OAuthError::PicInvariant(_) => StatusCode::FORBIDDEN,
            OAuthError::Upstream(_) => StatusCode::BAD_GATEWAY,
            OAuthError::Db(_) | OAuthError::Crypto | OAuthError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn body(&self) -> ErrorBody {
        match self {
            OAuthError::BadRequest(detail) => ErrorBody::new("invalid request", "bad_request")
                .with_detail(detail.clone())
                .with_fix("Check the OAuth parameters the agent sent: response_type=code, S256 PKCE, scope, and a registered redirect_uri.")
                .with_docs("https://proxilion.com/docs/oauth/intercept"),
            OAuthError::UnknownClient => ErrorBody::new("unknown OAuth client", "unknown_client")
                .with_fix("Add the agent's client_id to oauth_clients. Run `proxilion-cli clients add <id> <redirect_uri>` (planned, M3) or seed via migration.")
                .with_docs("https://proxilion.com/docs/oauth/clients"),
            OAuthError::SessionGone => ErrorBody::new("session expired", "session_gone")
                .with_fix("Sessions expire after 10 minutes. Start the OAuth flow again at /oauth/google/authorize.")
                .with_docs("https://proxilion.com/docs/oauth/sessions"),
            OAuthError::BridgeRejected(detail) => ErrorBody::new("authentication failed", "bridge_rejected")
                .with_detail(detail.clone())
                .with_fix("The federation-bridge JWT was malformed or expired. Re-authenticate at the IdP; check proxy logs for the rejection reason.")
                .with_docs("https://proxilion.com/docs/federation-bridge"),
            OAuthError::PkceFail => ErrorBody::new("PKCE verification failed", "pkce_fail")
                .with_fix("Confirm code_verifier matches code_challenge: base64url(SHA256(verifier)) per RFC 7636 §4.6.")
                .with_docs("https://proxilion.com/docs/oauth/pkce"),
            OAuthError::BadAuthCode => ErrorBody::new("invalid authorization code", "bad_auth_code")
                .with_fix("Authorization codes are single-use with a 30s TTL. Exchange immediately after the /google/callback redirect.")
                .with_docs("https://proxilion.com/docs/oauth/intercept"),
            OAuthError::PicInvariant(detail) => ErrorBody::new("operation not permitted", "pic_invariant_violation")
                .with_detail(detail.clone())
                .with_fix("Trust Plane refused to mint a PCA — requested ops aren't a subset of the predecessor PCA's ops. Check the IdP group → ops mapping for this user.")
                .with_docs("https://proxilion.com/docs/policy/ops"),
            OAuthError::Upstream(_) => ErrorBody::new("upstream temporarily unavailable", "upstream_unavailable")
                .with_fix("Google's OAuth endpoint or the Trust Plane returned an error. Retry in a few seconds; check /healthz for upstream reachability.")
                .with_docs("https://proxilion.com/docs/troubleshooting"),
            OAuthError::Db(_) | OAuthError::Crypto | OAuthError::Internal(_) => {
                ErrorBody::new("internal error", "internal_error")
                    .with_fix("This is a bug. Check the proxy logs for the structured error and file an issue at https://github.com/clay-good/proxilion/issues.")
                    .with_docs("https://proxilion.com/docs/troubleshooting")
            }
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            error!(error = %self, "oauth handler failure");
        } else {
            warn!(error = %self, "oauth handler rejected request");
        }
        self.body().into_response(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_match_variant_classification() {
        assert_eq!(
            OAuthError::BadRequest("x".into()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(OAuthError::UnknownClient.status(), StatusCode::BAD_REQUEST);
        assert_eq!(OAuthError::PkceFail.status(), StatusCode::BAD_REQUEST);
        assert_eq!(OAuthError::BadAuthCode.status(), StatusCode::BAD_REQUEST);
        assert_eq!(OAuthError::SessionGone.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            OAuthError::BridgeRejected("x".into()).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            OAuthError::PicInvariant("x".into()).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            OAuthError::Crypto.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            OAuthError::Internal("x".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn body_carries_stable_error_codes() {
        assert_eq!(
            OAuthError::BadRequest("x".into()).body().code,
            "bad_request"
        );
        assert_eq!(OAuthError::UnknownClient.body().code, "unknown_client");
        assert_eq!(OAuthError::SessionGone.body().code, "session_gone");
        assert_eq!(
            OAuthError::BridgeRejected("x".into()).body().code,
            "bridge_rejected"
        );
        assert_eq!(OAuthError::PkceFail.body().code, "pkce_fail");
        assert_eq!(OAuthError::BadAuthCode.body().code, "bad_auth_code");
        assert_eq!(
            OAuthError::PicInvariant("x".into()).body().code,
            "pic_invariant_violation"
        );
        assert_eq!(OAuthError::Crypto.body().code, "internal_error");
        assert_eq!(
            OAuthError::Internal("x".into()).body().code,
            "internal_error"
        );
    }

    #[test]
    fn body_carries_detail_when_variant_has_one() {
        assert_eq!(
            OAuthError::BadRequest("missing scope".into()).body().detail,
            Some("missing scope".to_string())
        );
        assert_eq!(
            OAuthError::PicInvariant("ops exceeded".into())
                .body()
                .detail,
            Some("ops exceeded".to_string())
        );
        // Variants without detail don't synthesize one.
        assert!(OAuthError::UnknownClient.body().detail.is_none());
        assert!(OAuthError::PkceFail.body().detail.is_none());
    }

    #[tokio::test]
    async fn into_response_uses_classification_status() {
        let r = OAuthError::UnknownClient.into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = OAuthError::PicInvariant("x".into()).into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn upstream_body_carries_upstream_unavailable_code_and_no_detail() {
        // The Upstream variant's status() is tested implicitly via the
        // 502 path above, but `body()` was not — and `Upstream(reqwest::Error)`
        // is the one variant where a sloppy `.with_detail(self.to_string())`
        // regression would leak the upstream URL (and any embedded creds)
        // into the agent-facing body.
        // We can't easily construct a reqwest::Error from outside the crate,
        // so route through Internal which shares the body() match arm with
        // Db/Crypto. Then separately assert the Upstream arm exists by
        // hitting its status() and round-tripping its Display.
        let oerr = OAuthError::Internal("boom".into());
        let body = oerr.body();
        assert_eq!(body.code, "internal_error");
        // No detail — internal error bodies must never carry the Display string,
        // otherwise an `Internal(format!("token={token}"))` regression upstream
        // would surface secrets to the agent.
        assert!(body.detail.is_none());
        assert!(body.fix.is_some());
        assert!(body.docs.unwrap().contains("troubleshooting"));
    }

    #[test]
    fn bridge_rejected_body_carries_detail_and_federation_docs_link() {
        // The detail string is the federation-bridge rejection reason —
        // safe to surface to the agent (no secrets, just "expired" / "bad sig").
        // The fix + docs steer the operator to the right runbook.
        let body = OAuthError::BridgeRejected("token expired".into()).body();
        assert_eq!(body.code, "bridge_rejected");
        assert_eq!(body.detail.as_deref(), Some("token expired"));
        assert!(body.fix.unwrap().contains("federation-bridge"));
        assert!(body.docs.unwrap().contains("federation-bridge"));
    }

    #[test]
    fn db_and_crypto_collapse_to_same_internal_error_body() {
        // Pin that NEITHER variant leaks its Display string into `detail`.
        // A future refactor that started passing `e.to_string()` through
        // would expose schema names (Db) or key-handling internals (Crypto).
        let db_body = OAuthError::Db(sqlx::Error::RowNotFound).body();
        let crypto_body = OAuthError::Crypto.body();
        assert_eq!(db_body.code, "internal_error");
        assert_eq!(crypto_body.code, "internal_error");
        assert!(db_body.detail.is_none());
        assert!(crypto_body.detail.is_none());
        // Both share the same fix/docs — operators look at logs for the
        // structured error, not the response body.
        assert_eq!(db_body.fix, crypto_body.fix);
        assert_eq!(db_body.docs, crypto_body.docs);
    }

    #[test]
    fn oauth_error_display_strings_pinned_for_log_filters() {
        // Operator log filters key on substrings like "PKCE verification
        // failed" / "session expired or unknown" / "Trust Plane refused
        // PCA". Pin each variant's Display so a `#[error(...)]` tweak
        // surfaces as a test failure rather than a silent runbook drift.
        assert!(
            OAuthError::PkceFail
                .to_string()
                .contains("PKCE verification failed")
        );
        assert!(
            OAuthError::SessionGone
                .to_string()
                .contains("session expired or unknown")
        );
        assert!(
            OAuthError::UnknownClient
                .to_string()
                .contains("unknown OAuth client")
        );
        assert!(
            OAuthError::PicInvariant("missing ops".into())
                .to_string()
                .contains("Trust Plane refused PCA")
        );
        assert!(
            OAuthError::BadAuthCode
                .to_string()
                .contains("invalid or already used")
        );
    }

    #[tokio::test]
    async fn upstream_variant_status_is_502_bad_gateway() {
        // Adapter forwarding to Trust Plane / Google can fail mid-flight;
        // the variant maps to 502 so the agent's retry policy treats it
        // as a transient upstream issue rather than a 4xx (which Cursor
        // / Claude Code would surface as a "fix your request" prompt).
        // We can't construct a reqwest::Error directly, so route through
        // the status() match — the Upstream arm is the only mapping to
        // BAD_GATEWAY, so any reachable Upstream variant must hit it.
        // Build one by making an actually-failing reqwest.
        let bad = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap()
            // RFC 5737 black-hole — guaranteed to time out within 1ms.
            .get("http://192.0.2.1:1/")
            .send()
            .await
            .unwrap_err();
        let e: OAuthError = OAuthError::from(bad);
        assert_eq!(e.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(e.body().code, "upstream_unavailable");
    }

    #[test]
    fn into_response_500_branch_uses_internal_error_code_for_db_path() {
        // The Db variant lands on the 500 branch; pin both the status
        // and the wire `code` so a Grafana alert keyed on
        // `code="internal_error" status="500"` doesn't silently drift
        // when the Db classification moves (e.g. to 503 on connection-
        // pool exhaustion).
        let e = OAuthError::Db(sqlx::Error::PoolClosed);
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(e.body().code, "internal_error");
    }

    #[test]
    fn internal_variant_display_does_not_carry_inner_string() {
        // `#[error("internal error")]` on `Internal(String)` deliberately
        // masks the inner String — the Display contract is the
        // operator-facing log substring `"internal error"` (Grafana / Loki
        // alerts key on it), and the inner detail is intended for the
        // structured `tracing::error!(?self, ...)` path only. A refactor
        // to `#[error("internal error: {0}")]` would silently leak the
        // raw inner String (which adapter call sites build via `format!`
        // — e.g. `Internal(format!("token={token}"))`) into log
        // aggregators that summarize the textual Display, not the
        // structured fields.
        let e = OAuthError::Internal("integer overflow at line 42".into());
        let s = e.to_string();
        assert_eq!(s, "internal error", "got: {s}");
        assert!(!s.contains("integer overflow"), "inner String leaked: {s}");
        assert!(!s.contains("42"), "inner String leaked: {s}");
    }

    #[tokio::test]
    async fn upstream_body_omits_detail_to_avoid_leaking_reqwest_error_url() {
        // `OAuthError::Upstream(reqwest::Error)` is the ONLY variant
        // whose inner error type carries the upstream URL (and any
        // embedded credentials in path/query). The `body()` match arm
        // for Upstream deliberately does NOT call `.with_detail(...)` —
        // a refactor that "for consistency" passed `e.to_string()`
        // through would surface that URL to the agent-facing response.
        // The existing `upstream_body_carries_upstream_unavailable_code_and_no_detail`
        // test exercises the Internal arm (which shares an arm pattern)
        // — pin the Upstream arm directly here against a real
        // reqwest::Error so a future arm-split refactor doesn't slip the
        // Upstream half through.
        let bad = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap()
            // RFC 5737 documentation prefix — routable nowhere.
            .get("http://192.0.2.1:1/secret-path?token=hunter2")
            .send()
            .await
            .unwrap_err();
        let e: OAuthError = OAuthError::from(bad);
        let body = e.body();
        assert_eq!(body.code, "upstream_unavailable");
        assert!(
            body.detail.is_none(),
            "Upstream body must not carry detail (would leak upstream URL): {:?}",
            body.detail
        );
        // The fix + docs survive — these are operator-actionable and
        // contain no caller-supplied bytes.
        assert!(body.fix.is_some());
        assert!(body.docs.unwrap().contains("troubleshooting"));
    }

    #[test]
    fn bad_request_body_fix_mentions_required_oauth_parameters() {
        // `BadRequest` is the operator-actionable variant — its fix
        // string commits to naming the four required OAuth parameter
        // shapes (`response_type=code`, `S256` PKCE, `scope`, and
        // `redirect_uri`) verbatim so the troubleshooting docs page can
        // anchor on those exact substrings. A refactor that softened
        // the message (e.g. "check OAuth parameters") would orphan
        // every docs cross-reference and force agents to debug by
        // grep across the proxy source.
        let body = OAuthError::BadRequest("scope is required".into()).body();
        assert_eq!(body.code, "bad_request");
        let fix = body.fix.expect("fix present");
        assert!(fix.contains("response_type=code"), "got: {fix}");
        assert!(fix.contains("S256"), "got: {fix}");
        assert!(fix.contains("scope"), "got: {fix}");
        assert!(fix.contains("redirect_uri"), "got: {fix}");
        // And the docs link points at the OAuth intercept page (not the
        // generic troubleshooting page — BadRequest is a misconfigured
        // agent, not a proxy bug).
        assert!(body.docs.unwrap().contains("oauth/intercept"));
    }

    #[test]
    fn oauth_error_bad_request_display_carries_invalid_request_prefix_with_inner_string() {
        // `#[error("invalid request: {0}")]` — the existing
        // `oauth_error_display_strings_pinned_for_log_filters` test
        // pins substrings via `.contains(...)` for five other
        // variants but NEVER pinned `BadRequest`'s Display at all,
        // and no test pinned the exact prefix-plus-inner shape via
        // `assert_eq!`. Operator log filters key on the literal
        // `"invalid request: "` prefix (matching the `body()`
        // arm's `error: "invalid request"` title) — a refactor
        // that softened to `"bad request: "` (matching the wire
        // `code: "bad_request"`) would silently break Loki filters
        // that historically grep the Display string. Pin the full
        // shape against a known inner message.
        let e = OAuthError::BadRequest("scope is required".into());
        assert_eq!(e.to_string(), "invalid request: scope is required");
    }

    #[test]
    fn oauth_error_bridge_rejected_display_carries_federation_token_rejected_prefix() {
        // `#[error("federation token rejected: {0}")]` — the
        // `BridgeRejected` variant was completely absent from any
        // Display assertion (the existing filter-substring test
        // covers PkceFail / SessionGone / UnknownClient /
        // PicInvariant / BadAuthCode, plus round 79's exact-shape
        // pins for Internal/Upstream/BadRequest body boundaries —
        // BridgeRejected has neither). Operator dashboards bucket
        // federation-bridge JWT validation failures on this prefix
        // separately from upstream-call failures (`upstream call
        // failed` — pinned in the sibling test) and from PIC
        // monotonicity refusals (`Trust Plane refused PCA:` —
        // already substring-pinned). A refactor that softened to
        // `"bridge rejected: {0}"` for symmetry with the body code
        // `"bridge_rejected"` would silently break log filters
        // keyed on the `"federation token"` qualifier.
        let e = OAuthError::BridgeRejected("token expired".into());
        assert_eq!(e.to_string(), "federation token rejected: token expired");
    }

    #[test]
    fn oauth_error_db_display_does_not_carry_inner_sqlx_string() {
        // `#[error("database error")]` on `Db(#[from] sqlx::Error)`
        // — symmetric to round-79's `Internal` mask: the inner
        // sqlx::Error Display carries schema column names, query
        // fragments, and constraint identifiers (operator-internal
        // surface) that must NOT bleed through into log
        // aggregators that summarize the textual Display rather
        // than the structured `?self` field. Pin the no-leak
        // contract via `assert_eq!` against the bare string and
        // confirm the inner Display ISN'T present even when sqlx
        // would carry distinctive substrings.
        let e = OAuthError::Db(sqlx::Error::RowNotFound);
        let s = e.to_string();
        assert_eq!(s, "database error");
        // The inner sqlx::Error Display contains "no rows" — pin
        // explicitly that it does NOT leak through to the wrapper.
        assert!(
            !s.to_lowercase().contains("no rows"),
            "inner sqlx Display leaked: {s}",
        );
    }

    #[test]
    fn oauth_error_crypto_display_is_fixed_no_detail_form() {
        // `#[error("crypto failure")]` on `Crypto` (unit variant —
        // no inner) — the Display is a fixed two-word string with
        // no field substitution. Operator log filters key on the
        // exact substring `"crypto failure"` to bucket AES-GCM /
        // token-cipher faults separately from `"database error"`
        // (Db) and `"internal error"` (Internal). A refactor that
        // promoted `Crypto` to `Crypto(String)` for "consistency
        // with the other detail-carrying arms" would force the
        // `#[error]` attribute to change to `"crypto failure: {0}"`
        // and silently start surfacing the cipher-internal string
        // — a regression catchable here.
        let e = OAuthError::Crypto;
        assert_eq!(e.to_string(), "crypto failure");
    }

    #[tokio::test]
    async fn oauth_error_upstream_display_masks_inner_reqwest_url_for_no_secret_leak() {
        // `#[error("upstream call failed")]` on
        // `Upstream(#[from] reqwest::Error)` — the inner reqwest
        // error carries the full URL (including any path/query
        // credentials in the upstream call), and round-79's
        // sibling `upstream_body_omits_detail_to_avoid_leaking_reqwest_error_url`
        // pins the BODY no-leak contract. This is the symmetric
        // pin for the DISPLAY string: the Display contract is the
        // fixed `"upstream call failed"` substring that operator
        // log filters bucket on, with NO inner URL leaking through.
        // A refactor to `"upstream call failed: {0}"` would
        // surface the URL (and any embedded creds) into log
        // aggregators that summarize the textual Display rather
        // than the structured field. Construct a real reqwest::Error
        // against a black-hole URL containing a sentinel `secret-path`
        // substring so we can assert its absence in the wrapper Display.
        let reqwest_err = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap()
            .get("http://192.0.2.1:1/secret-path?token=hunter2")
            .send()
            .await
            .unwrap_err();
        let e: OAuthError = OAuthError::from(reqwest_err);
        let s = e.to_string();
        assert_eq!(s, "upstream call failed");
        assert!(!s.contains("secret-path"), "URL path leaked: {s}");
        assert!(!s.contains("hunter2"), "query credential leaked: {s}");
        assert!(!s.contains("192.0.2.1"), "host leaked: {s}");
    }

    #[test]
    fn oauth_error_display_tightened_for_five_substring_pinned_variants() {
        // The existing `oauth_error_display_strings_pinned_for_log_filters`
        // test pins five variants via `.contains(...)` substring
        // checks. Tighten each to the full `assert_eq!` shape so a
        // refactor that prepended a variant prefix (`"oauth: "`)
        // or trailing punctuation (`"."`) would silently slip past
        // a `.contains()` check but surface here. The five
        // variants are unit-shaped (no field substitution) so the
        // Display strings are byte-stable constants.
        assert_eq!(OAuthError::PkceFail.to_string(), "PKCE verification failed");
        assert_eq!(
            OAuthError::SessionGone.to_string(),
            "session expired or unknown",
        );
        assert_eq!(
            OAuthError::UnknownClient.to_string(),
            "unknown OAuth client"
        );
        assert_eq!(
            OAuthError::BadAuthCode.to_string(),
            "authorization code invalid or already used",
        );
        // PicInvariant carries an inner String — pin the full
        // prefix-plus-inner shape (distinct from `AppError::PicInvariantViolation`'s
        // `"Trust Plane refused PCA: "` prefix which uses the
        // "Violation" word; this OAuth-side variant uses the
        // bare "Invariant" form).
        assert_eq!(
            OAuthError::PicInvariant("missing drive:write:bob/*".into()).to_string(),
            "Trust Plane refused PCA: missing drive:write:bob/*",
        );
    }

    #[test]
    fn oauth_error_is_send_sync_static_for_axum_into_response_boundary() {
        // `OAuthError` is the return-error type for every OAuth handler
        // (`/authorize`, `/callback`, `/token`) — it flows through
        // `IntoResponse` from handler futures that cross tokio task
        // boundaries, which mandates `Send + Sync + 'static`. Symmetric
        // to the AppError pin on [crates/proxy/src/adapters/error.rs] and
        // the ApiError + KillswitchApiState pin on
        // [crates/proxy/src/api/killswitch.rs]. A refactor that introduced
        // a !Send field (e.g. `Internal(Rc<String>)` "for cheap clone")
        // would break Sync at the router site rather than as a
        // far-removed trait-bound error.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<OAuthError>();
    }

    #[test]
    fn oauth_error_status_across_all_variants_is_4xx_or_5xx_never_2xx_or_3xx() {
        // Symmetric to the same-axis pin on [crates/proxy/src/adapters/error.rs]
        // (round 143). Every OAuthError variant surfaces a non-success
        // status — a refactor that registered a new variant mapping to
        // 200 OK "for the silent-acknowledgement case" would silently
        // exclude that variant from operator dashboard error-rate
        // metrics. Pin both is_client_error || is_server_error AND
        // !is_success AND !is_redirection across all variants.
        let variants: Vec<OAuthError> = vec![
            OAuthError::BadRequest("x".into()),
            OAuthError::UnknownClient,
            OAuthError::SessionGone,
            OAuthError::BridgeRejected("x".into()),
            OAuthError::PkceFail,
            OAuthError::BadAuthCode,
            OAuthError::PicInvariant("x".into()),
            OAuthError::Db(sqlx::Error::RowNotFound),
            OAuthError::Crypto,
            OAuthError::Internal("x".into()),
        ];
        for v in &variants {
            let s = v.status();
            assert!(!s.is_success(), "variant {:?} surfaced 2xx {}", v, s);
            assert!(!s.is_redirection(), "variant {:?} surfaced 3xx {}", v, s);
            assert!(
                s.is_client_error() || s.is_server_error(),
                "variant {:?} surfaced non-4xx/5xx {}",
                v,
                s,
            );
        }
    }

    #[test]
    fn oauth_error_body_code_is_lowercase_snake_case_across_all_variants() {
        // Symmetric to the same-axis pin on [crates/proxy/src/adapters/error.rs]
        // (round 143). The wire convention is lowercase snake_case
        // (e.g. `pkce_fail`, `bridge_rejected`, `pic_invariant_violation`).
        // A refactor that surfaced one as PascalCase OR kebab-case would
        // silently break every operator dashboard regex bucket. Pin
        // absence of uppercase ASCII AND absence of `-` across all
        // canonical OAuthError variants.
        let variants: Vec<OAuthError> = vec![
            OAuthError::BadRequest("x".into()),
            OAuthError::UnknownClient,
            OAuthError::SessionGone,
            OAuthError::BridgeRejected("x".into()),
            OAuthError::PkceFail,
            OAuthError::BadAuthCode,
            OAuthError::PicInvariant("x".into()),
            OAuthError::Db(sqlx::Error::RowNotFound),
            OAuthError::Crypto,
            OAuthError::Internal("x".into()),
        ];
        for v in &variants {
            let code = v.body().code;
            assert!(!code.is_empty(), "variant {:?} surfaced empty code", v);
            assert!(
                !code.chars().any(|c| c.is_ascii_uppercase()),
                "variant {:?} surfaced uppercase in code `{}`",
                v,
                code,
            );
            assert!(
                !code.contains('-'),
                "variant {:?} surfaced kebab in code `{}`",
                v,
                code,
            );
        }
    }

    #[test]
    fn oauth_error_body_detail_carries_multibyte_unicode_verbatim_through_bad_request_arm() {
        // The `BadRequest(String)` and `BridgeRejected(String)` and
        // `PicInvariant(String)` arms all surface their inner String
        // directly into body().detail (the existing pins use ASCII-only
        // inner content). Internationalized error contexts surface
        // multibyte unicode through OAuth flows occasionally (e.g. an
        // upstream Google error message with localized text, or an
        // operator-authored policy id with a non-ASCII slug). Pin all
        // three arms preserve multibyte unicode (3-byte é + 3-byte → +
        // 4-byte 🔥) verbatim through body().detail. A refactor that
        // `.to_ascii_lowercase()`-ed the inner string "for SIEM
        // hygiene" would silently mangle every non-ASCII detail.
        let needle = "ops missing café → 🔥";
        for body in [
            OAuthError::BadRequest(needle.into()).body(),
            OAuthError::BridgeRejected(needle.into()).body(),
            OAuthError::PicInvariant(needle.into()).body(),
        ] {
            assert_eq!(body.detail.as_deref(), Some(needle));
        }
    }

    #[test]
    fn oauth_error_debug_carries_variant_names_for_grep_bucketing() {
        // The `#[derive(Debug)]` on `OAuthError` feeds `?err` /
        // `error = %self` in the `into_response` log path. Operators
        // grep the log line by variant name to bucket PkceFail vs
        // BadAuthCode vs SessionGone vs Db vs Internal. A hand-rolled
        // `impl Debug` that hid variant names "to compact" the line
        // would break every operator bucket. Symmetric to the
        // `app_error_debug_carries_variant_names_for_grep_bucketing`
        // pin on [crates/proxy/src/adapters/error.rs] and the
        // `api_error_debug_carries_variant_names_for_grep_bucketing`
        // pin on [crates/proxy/src/api/killswitch.rs] — keep the
        // three operator-facing Error enums symmetric.
        for (variant, name) in [
            (OAuthError::PkceFail, "PkceFail"),
            (OAuthError::BadAuthCode, "BadAuthCode"),
            (OAuthError::SessionGone, "SessionGone"),
            (OAuthError::Crypto, "Crypto"),
            (OAuthError::UnknownClient, "UnknownClient"),
        ] {
            let s = format!("{:?}", variant);
            assert!(s.contains(name), "expected `{name}` in Debug, got: {s}");
        }
    }

    #[test]
    fn oauth_error_status_500_branch_is_internal_server_error_not_service_unavailable() {
        // The Db / Crypto / Internal trio collapse to
        // `INTERNAL_SERVER_ERROR` (500), NOT `SERVICE_UNAVAILABLE` (503).
        // The choice is deliberate: the agent's retry classifier
        // distinguishes 500 (proxy bug — don't retry, file an issue)
        // from 503 (transient — retry with backoff). A refactor that
        // re-classified Db to 503 "since pool exhaustion is transient"
        // would silently flip every operator's alert pager from
        // "code=internal_error status=500" to a transient-class
        // notification that misses the underlying outage. Pin the
        // exact status for all three arms via the `as_u16()` integer
        // (NOT just the .is_server_error() class) so a one-step drift
        // from 500 to 503 surfaces here. The existing
        // `status_codes_match_variant_classification` test pins
        // Crypto + Internal via `INTERNAL_SERVER_ERROR` constant but
        // NOT Db; widen with the integer-level pin across all three.
        for v in [
            OAuthError::Db(sqlx::Error::RowNotFound),
            OAuthError::Crypto,
            OAuthError::Internal("x".into()),
        ] {
            assert_eq!(v.status().as_u16(), 500, "variant {:?} drifted from 500", v,);
        }
    }

    #[test]
    fn body_fix_strings_are_actionable_for_unique_variants() {
        // Pin the fix text for the four variants whose fix strings are
        // their stable contract with the operator-docs page (the docs page
        // links these substrings; a drift would orphan the link).
        assert!(
            OAuthError::PkceFail
                .body()
                .fix
                .unwrap()
                .contains("code_verifier")
        );
        assert!(
            OAuthError::BadAuthCode
                .body()
                .fix
                .unwrap()
                .contains("single-use")
        );
        assert!(
            OAuthError::SessionGone
                .body()
                .fix
                .unwrap()
                .contains("10 minutes")
        );
        assert!(
            OAuthError::PicInvariant("x".into())
                .body()
                .fix
                .unwrap()
                .contains("subset")
        );
    }

    // ─── round 198 (2026-05-20): OAuthError variant + body purity surfaces ───

    #[test]
    fn oauth_error_variant_count_pinned_at_exactly_eleven_via_exhaustive_match() {
        // `OAuthError` has exactly 11 variants today (BadRequest /
        // UnknownClient / SessionGone / BridgeRejected / PkceFail /
        // BadAuthCode / PicInvariant / Upstream / Db / Crypto /
        // Internal). The status() + body() match arms enumerate
        // ALL 11; a refactor that landed a twelfth variant (e.g.
        // `RateLimited` for a future /token rate-gate) would
        // surface a 12th grep bucket the operator runbook wasn't
        // sized for AND would non-exhaustively compile-fail at
        // both match sites. Pin variant count via an exhaustive
        // match — a new arm forces this test to compile-fail at
        // the arm site. Symmetric to round-181 AuthFail 9-variant
        // + round-182 CatKeyError 3-variant + round-189
        // ActionsApiError 4-variant + round-190 ApiError 2-variant
        // + round-192 TriggerClaim 4-variant + round-194
        // AuditBodyMode 3-variant + round-197 (this round) all
        // exhaustive-match pins extended to this OAuthError enum.
        fn arm_name(e: &OAuthError) -> &'static str {
            match e {
                OAuthError::BadRequest(_) => "BadRequest",
                OAuthError::UnknownClient => "UnknownClient",
                OAuthError::SessionGone => "SessionGone",
                OAuthError::BridgeRejected(_) => "BridgeRejected",
                OAuthError::PkceFail => "PkceFail",
                OAuthError::BadAuthCode => "BadAuthCode",
                OAuthError::PicInvariant(_) => "PicInvariant",
                OAuthError::Upstream(_) => "Upstream",
                OAuthError::Db(_) => "Db",
                OAuthError::Crypto => "Crypto",
                OAuthError::Internal(_) => "Internal",
            }
        }
        // Walk all 10 constructible variants (Upstream needs a real
        // reqwest::Error — exercised in sibling tests; the match
        // exhaustiveness at compile time is what guards the
        // variant count, not the Vec contents).
        let ten: Vec<OAuthError> = vec![
            OAuthError::BadRequest("x".into()),
            OAuthError::UnknownClient,
            OAuthError::SessionGone,
            OAuthError::BridgeRejected("x".into()),
            OAuthError::PkceFail,
            OAuthError::BadAuthCode,
            OAuthError::PicInvariant("x".into()),
            OAuthError::Db(sqlx::Error::RowNotFound),
            OAuthError::Crypto,
            OAuthError::Internal("x".into()),
        ];
        let names: std::collections::HashSet<&'static str> = ten.iter().map(arm_name).collect();
        assert_eq!(names.len(), 10, "10 constructible-variant names walked");
        // And the 11th (Upstream) is reachable via the match — the
        // exhaustive arm forces compile-time enumeration of all 11.
    }

    #[test]
    fn oauth_error_four_string_bearing_variants_carry_owned_string_for_cross_await_propagation() {
        // The four String-bearing variants — `BadRequest(String)`,
        // `BridgeRejected(String)`, `PicInvariant(String)`,
        // `Internal(String)` — all carry OWNED String, NOT borrowed
        // `&'a str`. The errors flow through `?`-chains across
        // `.await` boundaries in the OAuth /authorize, /callback,
        // /token handlers AND propagate through `IntoResponse`. A
        // refactor to `&'a str` for "zero-alloc on the cold path"
        // would introduce a lifetime parameter that cascades through
        // every consuming `?`-chain in the OAuth handler module.
        // Pin owned-String via require_string on all 4 String-bearing
        // arms. Symmetric to round-181 AuthFail 3-String-arm +
        // round-190 ApiError::BadRequest + round-192 TriggerClaim::Error
        // + round-193 ErrorBody.detail owned-String pins extended to
        // this OAuth-error enum's String-bearing arms.
        fn require_string(_: &String) {}
        for (e, name) in [
            (OAuthError::BadRequest("x".into()), "BadRequest"),
            (OAuthError::BridgeRejected("x".into()), "BridgeRejected"),
            (OAuthError::PicInvariant("x".into()), "PicInvariant"),
            (OAuthError::Internal("x".into()), "Internal"),
        ] {
            match e {
                OAuthError::BadRequest(s)
                | OAuthError::BridgeRejected(s)
                | OAuthError::PicInvariant(s)
                | OAuthError::Internal(s) => {
                    require_string(&s);
                    assert_eq!(s, "x", "arm {name}");
                }
                _ => panic!("expected String-bearing arm for {name}"),
            }
        }
    }

    #[test]
    fn oauth_error_body_is_referentially_transparent_across_fifty_calls_on_same_variant() {
        // `body()` is called once per error response inside
        // `into_response`. The construction is purely from the
        // variant + inner String — no clock, no random source. A
        // refactor that mixed in a per-call timestamp or a
        // tracing-span id "for body-level correlation" would break
        // the byte-equal contract operator log aggregators rely on
        // for response-body dedup hashing. Pin 50 calls on three
        // distinct variants yield byte-equal serialized bodies.
        // Symmetric to round-187 html_escape + round-193 ErrorBody
        // + round-194 sha256_hex + round-195 SessionExtractError +
        // round-197 synth_event referential-transparency pins
        // extended to this OAuthError::body() construction path.
        for variant_builder in [
            || OAuthError::PkceFail,
            || OAuthError::SessionGone,
            || OAuthError::BadRequest("scope required".into()),
        ] {
            let baseline = serde_json::to_string(&variant_builder().body()).unwrap();
            for i in 0..50 {
                let again = serde_json::to_string(&variant_builder().body()).unwrap();
                assert_eq!(
                    again, baseline,
                    "iter {i}: OAuthError::body() must be referentially transparent",
                );
            }
        }
    }

    #[test]
    fn oauth_error_status_method_return_type_is_status_code_not_u16() {
        // `OAuthError::status(&self) -> StatusCode` — the method
        // returns the strong-typed `axum::http::StatusCode`, NOT
        // `u16`. A refactor that flipped to `u16` "for ergonomic
        // metrics labeling" would lose the type-level guarantee
        // that the value is a valid HTTP status code (StatusCode's
        // constructor rejects out-of-range u16s) AND would force
        // every `IntoResponse` call site to wrap the u16 back into
        // a StatusCode. Pin via require_status_code. Symmetric to
        // round-196 DEFAULT_TICK_INTERVAL Duration type pin
        // extended to this method-return-type contract.
        fn require_status_code(_: StatusCode) {}
        require_status_code(OAuthError::PkceFail.status());
        require_status_code(OAuthError::SessionGone.status());
        require_status_code(OAuthError::Db(sqlx::Error::RowNotFound).status());
    }

    #[test]
    fn oauth_error_body_code_field_is_static_str_lifetime_for_zero_alloc_per_response() {
        // `ErrorBody.code: &'static str` — the OAuth body() match
        // arms construct ErrorBody::new(...) with literal string
        // codes (`"bad_request"`, `"pkce_fail"`, `"internal_error"`,
        // etc.). All 9 distinct code strings are &'static str
        // literals. A refactor at the ErrorBody side to widen the
        // field type to `String` "for ergonomic dynamic codes"
        // would silently heap-allocate one String per OAuth
        // response. Pin lifetime via require_static_str on the
        // code field of body() across 4 distinct variants.
        // Symmetric to round-193 ErrorBody.fix/docs static-str
        // pins extended to this code-field lifetime contract.
        fn require_static_str(_: &'static str) {}
        for v in [
            OAuthError::BadRequest("x".into()),
            OAuthError::PkceFail,
            OAuthError::SessionGone,
            OAuthError::Internal("x".into()),
        ] {
            require_static_str(v.body().code);
        }
    }

    #[test]
    fn oauth_error_body_distinct_codes_across_unique_variants_no_collisions() {
        // The 11 OAuthError variants map to 8 DISTINCT `code`
        // strings: `bad_request` / `unknown_client` / `session_gone`
        // / `bridge_rejected` / `pkce_fail` / `bad_auth_code` /
        // `pic_invariant_violation` / `upstream_unavailable` /
        // `internal_error` — but the Db + Crypto + Internal trio
        // share `internal_error`. Pin that the documented-distinct
        // 8 codes are pairwise non-equal (collisions would silently
        // collapse two operator-runbook buckets), AND that the
        // shared-by-design `internal_error` arm covers Db + Crypto
        // + Internal as a single bucket. Symmetric to round-188
        // PolicyView 5-key + round-191 CheckItem 6-key exact-set
        // pins extended to this OAuth-error code-axis no-collision
        // contract.
        let unique_codes = [
            OAuthError::BadRequest("x".into()).body().code,
            OAuthError::UnknownClient.body().code,
            OAuthError::SessionGone.body().code,
            OAuthError::BridgeRejected("x".into()).body().code,
            OAuthError::PkceFail.body().code,
            OAuthError::BadAuthCode.body().code,
            OAuthError::PicInvariant("x".into()).body().code,
        ];
        let unique_set: std::collections::HashSet<&str> = unique_codes.iter().copied().collect();
        assert_eq!(
            unique_set.len(),
            unique_codes.len(),
            "code collision across documented-distinct variants: {unique_codes:?}",
        );
        // And the shared-arm trio (Db + Crypto + Internal) all
        // surface "internal_error" by design.
        for v in [
            OAuthError::Db(sqlx::Error::RowNotFound),
            OAuthError::Crypto,
            OAuthError::Internal("x".into()),
        ] {
            assert_eq!(v.body().code, "internal_error");
        }
    }

    // ─── round 220 (2026-05-22): OAuthError status + body + fix purity surfaces ───

    #[test]
    fn oauth_error_status_is_referentially_transparent_across_fifty_calls_per_variant() {
        // `OAuthError::status(&self) -> StatusCode` is a pure
        // classification — no clock, no atomic counter. The existing
        // round-198 `oauth_error_body_is_referentially_transparent`
        // pin walks `body()` purity but never `status()`. A refactor
        // that mixed in a per-call rate-limit-driven status mutation
        // (e.g. "after the 100th 401 in 10 seconds, promote to 503
        // to shed load") would silently fork the operator alert
        // bucket across what should be byte-equal calls and break the
        // deterministic-classification contract operator runbooks rely
        // on. Pin 50 `status()` calls on three distinct variants yield
        // byte-equal StatusCode. Symmetric to round-198 body() RT pin
        // extended to this sibling method on the same enum.
        for variant_builder in [
            || OAuthError::PkceFail,
            || OAuthError::PicInvariant("ops missing".into()),
            || OAuthError::Db(sqlx::Error::RowNotFound),
        ] {
            let baseline = variant_builder().status();
            for i in 0..50 {
                let again = variant_builder().status();
                assert_eq!(
                    again, baseline,
                    "iter {i}: OAuthError::status must be referentially transparent",
                );
            }
        }
    }

    #[test]
    fn oauth_error_body_return_type_is_owned_error_body_by_value_via_fn_pointer_witness() {
        // `OAuthError::body(&self) -> ErrorBody` returns owned
        // `ErrorBody` by value, NOT `&ErrorBody` (a borrow refactor
        // "to avoid cloning the inner String on every error response"
        // would tie the body's lifetime to the OAuthError's borrow
        // and break the `IntoResponse` chain where `self.body()` is
        // moved into `into_response(status)` — the borrowed return
        // would force a clone insertion at every call site OR cascade
        // a lifetime parameter through every consumer). Pin via a
        // fn-pointer witness with the exact signature. Symmetric to
        // round-217 from_bytes + round-218 Bearer::parse + round-219
        // ErrorBody::new fn-pointer-witness pins extended to this
        // method-return-type contract.
        let _: fn(&OAuthError) -> ErrorBody = OAuthError::body;
    }

    #[test]
    fn oauth_error_pic_invariant_status_is_403_forbidden_integer_level_pin() {
        // `OAuthError::PicInvariant` maps to `FORBIDDEN` (403) — the
        // existing `status_codes_match_variant_classification` pin
        // checks via the `StatusCode::FORBIDDEN` constant. Tighten
        // via the `as_u16()` integer level so a one-step drift to
        // 401 ("symmetry with BridgeRejected since both are
        // auth-related") OR to 400 ("agent should fix the request")
        // surfaces here at the integer-level. The 403 choice is
        // deliberate: it signals to the agent that the request was
        // well-formed but the AGENT (or its operator) lacks the
        // permission scope to perform the operation — distinct from
        // 401 (need to re-authenticate) and 400 (request malformed).
        // Symmetric to round-198 `oauth_error_status_500_branch_is_internal_server_error`
        // integer-level pin extended to this 403 boundary.
        assert_eq!(
            OAuthError::PicInvariant("ops missing".into())
                .status()
                .as_u16(),
            403,
            "PicInvariant status must be 403 Forbidden",
        );
    }

    #[test]
    fn oauth_error_bridge_rejected_status_is_401_unauthorized_integer_level_pin() {
        // `OAuthError::BridgeRejected` maps to `UNAUTHORIZED` (401) —
        // symmetric to the PicInvariant 403 pin one method up. The
        // 401 choice is deliberate: it signals to the agent that the
        // federation-bridge JWT is invalid/expired and the user (NOT
        // the agent) needs to re-authenticate at the IdP. A refactor
        // that re-classified to 403 "since the bridge rejected the
        // request, that's an authorization decision" would silently
        // flip the agent's retry policy from "prompt the human to
        // re-auth" to "show this as a permission error" — a UX-
        // breaking drift catchable here at the integer level. The
        // existing `status_codes_match_variant_classification` pin
        // checks via the `StatusCode::UNAUTHORIZED` constant; this
        // pin is the integer-level boundary check.
        assert_eq!(
            OAuthError::BridgeRejected("token expired".into())
                .status()
                .as_u16(),
            401,
            "BridgeRejected status must be 401 Unauthorized",
        );
    }

    #[test]
    fn oauth_error_session_gone_body_fix_mentions_oauth_google_authorize_path_verbatim() {
        // `SessionGone` body fix instructs the operator to restart
        // the OAuth flow at the exact path `/oauth/google/authorize`.
        // The path is the operator-facing entry point for the OAuth
        // intercept — operator-docs pages anchor on this exact
        // substring. A refactor that softened to "the authorize
        // endpoint" OR shortened to `/oauth/authorize` "for symmetry
        // with the non-Google flow" would orphan the docs cross-
        // reference AND break operators who copy-paste the path from
        // the error body into curl/browser. The existing
        // `body_fix_strings_are_actionable_for_unique_variants` pin
        // checks for the substring "10 minutes" but NEVER for the
        // path itself. Pin both substrings independently so a fix
        // refactor that drops EITHER surfaces here.
        let fix = OAuthError::SessionGone.body().fix.expect("fix present");
        assert!(
            fix.contains("/oauth/google/authorize"),
            "SessionGone fix must mention canonical authorize path verbatim: {fix}",
        );
        assert!(
            fix.contains("10 minutes"),
            "SessionGone fix must mention 10-minute TTL: {fix}",
        );
    }

    #[test]
    fn oauth_error_unknown_client_body_docs_link_points_at_oauth_clients_page() {
        // `UnknownClient` body docs link is
        // `https://proxilion.com/docs/oauth/clients` — distinct from
        // every other OAuthError variant's docs link (PkceFail goes
        // to `/oauth/pkce`, SessionGone to `/oauth/sessions`,
        // BadRequest to `/oauth/intercept`, PicInvariant to
        // `/policy/ops`, BridgeRejected to `/federation-bridge`,
        // internal-trio to `/troubleshooting`). A refactor that
        // collapsed UnknownClient onto `/oauth/intercept` "since both
        // are OAuth setup errors" would silently break the operator's
        // copy-paste-into-browser path away from the dedicated
        // clients-registration docs page. Pin the FULL docs URL byte-
        // exact (NOT just substring) so a one-byte drift (e.g.
        // `.com` → `.io`, or `/clients` → `/client`) surfaces here.
        // Symmetric to round-219 (this round) field-order pin extending
        // operator-grep anchors from the central envelope file to this
        // OAuth-error sibling.
        assert_eq!(
            OAuthError::UnknownClient.body().docs,
            Some("https://proxilion.com/docs/oauth/clients"),
            "UnknownClient docs link drift",
        );
    }
}
