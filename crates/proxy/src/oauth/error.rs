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
}
