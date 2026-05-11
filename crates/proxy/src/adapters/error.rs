//! Adapter-layer errors → structured HTTP responses (shared envelope).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;
use tracing::{error, warn};

use crate::error_envelope::ErrorBody;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("policy {policy_id:?} blocked request: {reason}")]
    PolicyBlocked {
        policy_id: Option<String>,
        reason: String,
        override_allowed: bool,
    },

    #[error("requires user confirmation: {0}")]
    RequireConfirmation(String),

    #[error("rate limited")]
    RateLimit,

    #[error("Trust Plane refused PCA: {0}")]
    PicInvariantViolation(String),

    #[error("upstream returned a body larger than the 10MB cap")]
    UpstreamTooLarge,

    #[error("upstream call failed: {0}")]
    Upstream(#[from] reqwest::Error),

    #[error("policy engine: {0}")]
    Policy(#[from] policy_engine::rego::Error),

    #[error("policy ops template: {0}")]
    OpsTemplate(#[from] policy_engine::ops::OpsParseError),

    #[error("read filter blocked response body")]
    ReadFilterBlocked,

    #[error("database error")]
    Db(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::PolicyBlocked { .. } => StatusCode::FORBIDDEN,
            AppError::RequireConfirmation(_) => StatusCode::PRECONDITION_REQUIRED,
            AppError::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            AppError::PicInvariantViolation(_) => StatusCode::FORBIDDEN,
            AppError::UpstreamTooLarge | AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            AppError::ReadFilterBlocked => StatusCode::FORBIDDEN,
            AppError::Policy(_) | AppError::OpsTemplate(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Db(_) | AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn body(&self) -> ErrorBody {
        match self {
            AppError::PolicyBlocked { policy_id, reason, override_allowed } => {
                ErrorBody::new("blocked by policy", "policy_blocked")
                    .with_detail(reason.clone())
                    .with_fix("If this block is incorrect, edit the matching policy in your policy YAML or grant a one-time override via `proxilion-cli override <request_id>` (planned, M3).")
                    .with_docs("https://proxilion.com/docs/policy/layer-b")
                    .with_extras(serde_json::json!({
                        "policy_id": policy_id,
                        "override_allowed": override_allowed,
                    }))
            }
            AppError::RequireConfirmation(reason) => {
                ErrorBody::new("operation requires user confirmation", "require_confirmation")
                    .with_detail(reason.clone())
                    .with_fix("The agent must surface a confirmation prompt to the human, then resubmit with X-Proxilion-Confirmation: <token>.")
                    .with_docs("https://proxilion.com/docs/policy/confirmation")
            }
            AppError::RateLimit => ErrorBody::new("rate limit exceeded", "rate_limited")
                .with_fix("Back off and retry; the rate-limit policy and per-user burst are configurable in your policy YAML.")
                .with_docs("https://proxilion.com/docs/policy/rate-limit"),
            AppError::PicInvariantViolation(detail) => {
                ErrorBody::new("operation exceeds session authority", "pic_invariant_violation")
                    .with_detail(detail.clone())
                    .with_fix("The action requires ops the predecessor PCA doesn't grant. Either widen the user's IdP group→ops mapping or restrict the agent's action to ops the user has.")
                    .with_docs("https://proxilion.com/docs/policy/ops")
            }
            AppError::UpstreamTooLarge => ErrorBody::new("upstream response exceeded size cap", "upstream_too_large")
                .with_fix("Upstream returned >10MB. Restrict the agent's request (e.g. Drive `fields=`) or raise the cap if you have a real need — body inspection slows on large payloads.")
                .with_docs("https://proxilion.com/docs/adapters/limits"),
            AppError::Upstream(_) => ErrorBody::new("upstream temporarily unavailable", "upstream_unavailable")
                .with_fix("Retry the request. If persistent, check the vendor status page and /healthz for downstream reachability.")
                .with_docs("https://proxilion.com/docs/troubleshooting"),
            AppError::ReadFilterBlocked => ErrorBody::new("blocked by read-filter policy", "read_filter_blocked")
                .with_fix("A BlockRequest quarantine pattern matched in the response body. Open /admin/ → Live feed → click the row for the matched pattern.")
                .with_docs("https://proxilion.com/docs/policy/read-filter"),
            AppError::Policy(_) | AppError::OpsTemplate(_) => {
                ErrorBody::new("policy evaluation error", "policy_engine_error")
                    .with_fix("Policy YAML failed to evaluate. Validate it with `proxilion-cli policy check <file>` (planned, M3) or see the structured error in proxy logs.")
                    .with_docs("https://proxilion.com/docs/policy/authoring")
            }
            AppError::Db(_) | AppError::Internal(_) => {
                ErrorBody::new("internal error", "internal_error")
                    .with_fix("This is a bug. Check proxy logs and file an issue at https://github.com/clay-good/proxilion/issues.")
                    .with_docs("https://proxilion.com/docs/troubleshooting")
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            error!(error = %self, "adapter failure");
        } else {
            warn!(error = %self, "adapter rejected request");
        }
        self.body().into_response(status)
    }
}
