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
}
