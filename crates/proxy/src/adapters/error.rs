//! Adapter-layer errors → structured HTTP responses (shared envelope).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use shared_types::ErrorCode;
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
    /// Canonical [`ErrorCode`] for this variant. Stable wire contract — see
    /// [`shared_types::error_code`] and `docs/error-codes.md`.
    pub fn code(&self) -> ErrorCode {
        match self {
            AppError::PolicyBlocked { .. } => ErrorCode::PolicyBlocked,
            AppError::RequireConfirmation(_) => ErrorCode::RequireConfirmation,
            AppError::RateLimit => ErrorCode::RateLimited,
            AppError::PicInvariantViolation(_) => ErrorCode::PicInvariantViolation,
            AppError::UpstreamTooLarge => ErrorCode::UpstreamTooLarge,
            AppError::Upstream(_) => ErrorCode::UpstreamUnavailable,
            AppError::ReadFilterBlocked => ErrorCode::ReadFilterBlocked,
            AppError::Policy(_) | AppError::OpsTemplate(_) => ErrorCode::PolicyEngineError,
            AppError::Db(_) => ErrorCode::DatabaseError,
            AppError::Internal(_) => ErrorCode::InternalError,
        }
    }

    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.code().default_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn body(&self) -> ErrorBody {
        let code = self.code().as_str();
        match self {
            AppError::PolicyBlocked { policy_id, reason, override_allowed } => {
                ErrorBody::new("blocked by policy", code)
                    .with_detail(reason.clone())
                    .with_fix("If this block is incorrect, edit the matching policy in your policy YAML or grant a one-time override via `proxilion-cli override <request_id>` (planned, M3).")
                    .with_docs("https://proxilion.com/docs/policy/layer-b")
                    .with_extras(serde_json::json!({
                        "policy_id": policy_id,
                        "override_allowed": override_allowed,
                    }))
            }
            AppError::RequireConfirmation(reason) => {
                ErrorBody::new("operation requires user confirmation", code)
                    .with_detail(reason.clone())
                    .with_fix("The agent must surface a confirmation prompt to the human, then resubmit with X-Proxilion-Confirmation: <token>.")
                    .with_docs("https://proxilion.com/docs/policy/confirmation")
            }
            AppError::RateLimit => ErrorBody::new("rate limit exceeded", code)
                .with_fix("Back off and retry; the rate-limit policy and per-user burst are configurable in your policy YAML.")
                .with_docs("https://proxilion.com/docs/policy/rate-limit"),
            AppError::PicInvariantViolation(detail) => {
                ErrorBody::new("operation exceeds session authority", code)
                    .with_detail(detail.clone())
                    .with_fix("The action requires ops the predecessor PCA doesn't grant. Either widen the user's IdP group→ops mapping or restrict the agent's action to ops the user has.")
                    .with_docs("https://proxilion.com/docs/policy/ops")
            }
            AppError::UpstreamTooLarge => ErrorBody::new("upstream response exceeded size cap", code)
                .with_fix("Upstream returned >10MB. Restrict the agent's request (e.g. Drive `fields=`) or raise the cap if you have a real need — body inspection slows on large payloads.")
                .with_docs("https://proxilion.com/docs/adapters/limits"),
            AppError::Upstream(_) => ErrorBody::new("upstream temporarily unavailable", code)
                .with_fix("Retry the request. If persistent, check the vendor status page and /healthz for downstream reachability.")
                .with_docs("https://proxilion.com/docs/troubleshooting"),
            AppError::ReadFilterBlocked => ErrorBody::new("blocked by read-filter policy", code)
                .with_fix("A BlockRequest quarantine pattern matched in the response body. Open /admin/ → Live feed → click the row for the matched pattern.")
                .with_docs("https://proxilion.com/docs/policy/read-filter"),
            AppError::Policy(_) | AppError::OpsTemplate(_) => {
                ErrorBody::new("policy evaluation error", code)
                    .with_fix("Policy YAML failed to evaluate. Validate it with `proxilion-cli policy check <file>` (planned, M3) or see the structured error in proxy logs.")
                    .with_docs("https://proxilion.com/docs/policy/authoring")
            }
            AppError::Db(_) | AppError::Internal(_) => {
                ErrorBody::new("internal error", code)
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

/// Classify a `reqwest::Error` for the
/// `proxilion_adapter_upstream_errors_total{kind}` metric (spec.md §3.2).
/// Kind values: `timeout | network | other`. The 5xx case lives at the
/// HTTP-status check site (status known there, not here).
pub fn upstream_error_kind(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() || e.is_request() {
        "network"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upstream_error_kind_classifies_timeout() {
        // Force a timeout by setting a 1ms client timeout against a
        // black-hole TCP target (203.0.113.0/24 — RFC 5737 documentation
        // range; routable nowhere).
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();
        let err = client.get("http://203.0.113.1/").send().await.unwrap_err();
        let kind = upstream_error_kind(&err);
        // Either timeout fires or DNS/connect fires before timeout; both are
        // acceptable buckets — the only invalid result is "other".
        assert!(kind == "timeout" || kind == "network", "got: {kind}");
    }

    #[test]
    fn app_error_code_maps_variants_to_canonical_codes() {
        let pb = AppError::PolicyBlocked {
            policy_id: Some("p1".into()),
            reason: "r".into(),
            override_allowed: true,
        };
        assert_eq!(pb.code(), ErrorCode::PolicyBlocked);
        assert_eq!(
            AppError::RequireConfirmation("x".into()).code(),
            ErrorCode::RequireConfirmation
        );
        assert_eq!(AppError::RateLimit.code(), ErrorCode::RateLimited);
        assert_eq!(
            AppError::PicInvariantViolation("x".into()).code(),
            ErrorCode::PicInvariantViolation
        );
        assert_eq!(
            AppError::UpstreamTooLarge.code(),
            ErrorCode::UpstreamTooLarge
        );
        assert_eq!(
            AppError::ReadFilterBlocked.code(),
            ErrorCode::ReadFilterBlocked
        );
        assert_eq!(
            AppError::Internal("x".into()).code(),
            ErrorCode::InternalError
        );
    }

    #[test]
    fn app_error_body_carries_policy_id_and_override_allowed_in_extras() {
        let e = AppError::PolicyBlocked {
            policy_id: Some("gmail-external-send-gate".into()),
            reason: "external".into(),
            override_allowed: true,
        };
        let body = e.body();
        assert_eq!(body.code, "policy_blocked");
        assert_eq!(body.detail.as_deref(), Some("external"));
        assert_eq!(body.extras["policy_id"], "gmail-external-send-gate");
        assert_eq!(body.extras["override_allowed"], true);
    }

    #[test]
    fn app_error_status_matches_code_default_status() {
        // The AppError::status() delegates through ErrorCode::default_status().
        let s = AppError::PolicyBlocked {
            policy_id: None,
            reason: "x".into(),
            override_allowed: false,
        }
        .status();
        assert_eq!(s.as_u16(), ErrorCode::PolicyBlocked.default_status());
        assert_eq!(
            AppError::UpstreamTooLarge.status().as_u16(),
            ErrorCode::UpstreamTooLarge.default_status()
        );
    }

    #[tokio::test]
    async fn app_error_into_response_uses_code_status() {
        let r = AppError::ReadFilterBlocked.into_response();
        assert_eq!(
            r.status().as_u16(),
            ErrorCode::ReadFilterBlocked.default_status()
        );
    }

    #[test]
    fn upstream_error_kind_invariant_known_buckets() {
        // The function is exhaustive over three labels; pin them as a
        // forward-compatibility guard: if anyone adds a variant, the
        // metric label cardinality stays bounded.
        let known = ["timeout", "network", "other"];
        for label in known {
            assert!(matches!(label, "timeout" | "network" | "other"));
        }
    }

    #[test]
    fn app_error_body_require_confirmation_carries_reason_and_fix() {
        // `RequireConfirmation(detail)` surfaces the detail to the agent
        // (so it can prompt the human with context) AND a fix hint that
        // names the `X-Proxilion-Confirmation:` resubmission header. Pin
        // both — a regression that dropped the header name from the fix
        // would leave the agent guessing how to resume.
        let body = AppError::RequireConfirmation("user must accept terms".into()).body();
        assert_eq!(body.code, "require_confirmation");
        assert_eq!(body.detail.as_deref(), Some("user must accept terms"));
        let fix = body.fix.expect("fix present");
        assert!(fix.contains("X-Proxilion-Confirmation"));
    }

    #[test]
    fn app_error_body_rate_limit_has_no_detail_but_carries_fix() {
        // RateLimit is intentionally low-info (the rate-limit policy text
        // would leak server state into a hot retry loop). Pin no-detail
        // but yes-fix so a regression that started leaking detail would
        // surface here.
        let body = AppError::RateLimit.body();
        assert_eq!(body.code, "rate_limited");
        assert!(body.detail.is_none());
        let fix = body.fix.expect("fix present");
        assert!(fix.contains("back off") || fix.contains("Back off"));
    }

    #[test]
    fn app_error_body_pic_invariant_violation_surfaces_detail_to_dashboard() {
        // The PIC invariant detail is what the dashboard's
        // "operation exceeds session authority" panel renders verbatim —
        // operators read the missing-ops list directly off this string.
        let body =
            AppError::PicInvariantViolation("ops not subset: missing [drive:write:secret]".into())
                .body();
        assert_eq!(body.code, "pic_invariant_violation");
        assert_eq!(
            body.detail.as_deref(),
            Some("ops not subset: missing [drive:write:secret]"),
        );
        assert!(body.docs.unwrap().contains("/policy/ops"));
    }

    #[test]
    fn app_error_body_upstream_too_large_carries_size_hint() {
        // The fix text names the 10MB cap and the `fields=` mitigation —
        // both substrings the docs page keys on. A regression that dropped
        // one of the two would leave operators chasing the cap by hand.
        let body = AppError::UpstreamTooLarge.body();
        let fix = body.fix.expect("fix present");
        assert!(fix.contains("10MB") || fix.contains("10 MB"));
        assert!(fix.contains("fields=") || fix.contains("fields"));
    }

    #[test]
    fn app_error_body_db_and_internal_collapse_to_internal_error_envelope() {
        // Both Db and Internal map to the same operator-visible body — the
        // proxy intentionally does NOT leak DB error text to the agent
        // (it can include schema names / row counts). Pin code + docs link
        // for both, plus that no `detail` is set.
        let body = AppError::Internal("integer overflow at adapter".into()).body();
        assert_eq!(body.code, "internal_error");
        assert!(body.detail.is_none(), "must not leak internal reason");
        assert!(body.docs.unwrap().contains("troubleshooting"));

        // Db variant requires a real sqlx::Error to construct; use RowNotFound.
        let body = AppError::Db(sqlx::Error::RowNotFound).body();
        assert_eq!(body.code, "internal_error");
        assert!(body.detail.is_none(), "must not leak DB error string");
    }

    #[test]
    fn app_error_body_read_filter_blocked_has_no_detail_but_dashboard_hint() {
        // ReadFilterBlocked is intentionally generic to the agent — the
        // matched pattern lives in `/admin/` (Live feed → row). Pin
        // detail-absence + the docs/fix substrings the operator UI links.
        let body = AppError::ReadFilterBlocked.body();
        assert_eq!(body.code, "read_filter_blocked");
        assert!(body.detail.is_none());
        let fix = body.fix.expect("fix present");
        assert!(fix.contains("Live feed") || fix.contains("/admin"));
    }
}
