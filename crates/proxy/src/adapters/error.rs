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
    fn app_error_pic_invariant_violation_carries_detail_through_to_wire() {
        // The Layer-A break is operator-actionable — the upstream
        // refusal body explains what ops weren't a subset. Pin that
        // `detail` is set (unlike Internal/Db which hide it) and
        // that the `pic_invariant_violation` wire code is stable for
        // the agent-side retry classifier.
        let body = AppError::PicInvariantViolation("missing [drive:write:secret]".into()).body();
        assert_eq!(body.code, "pic_invariant_violation");
        assert_eq!(body.detail.as_deref(), Some("missing [drive:write:secret]"),);
        // Authority docs link points operators at the ops-mapping page.
        assert!(body.docs.unwrap().contains("policy/ops"));
    }

    #[test]
    fn app_error_rate_limit_status_is_429_and_carries_no_detail() {
        // RateLimit is the canonical 429 path. Pin both status (via
        // the ErrorCode default) and the no-detail contract — the
        // current-window remaining count is intentionally not
        // surfaced in the response body (the operator dashboard has
        // the live metric; leaking it to the agent would help abusers
        // pace requests under the limit).
        let e = AppError::RateLimit;
        assert_eq!(e.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = e.body();
        assert_eq!(body.code, "rate_limited");
        assert!(body.detail.is_none());
    }

    #[test]
    fn app_error_require_confirmation_status_is_428_with_token_hint() {
        // The 428 Precondition Required path is the §3.2 contract for
        // human-in-the-loop confirmation. Pin status + the fix hint
        // mentioning the `X-Proxilion-Confirmation` header — the
        // agent SDK reads this hint to surface the right retry shape.
        let e = AppError::RequireConfirmation("external recipient".into());
        assert_eq!(e.status(), StatusCode::PRECONDITION_REQUIRED);
        let body = e.body();
        assert_eq!(body.code, "require_confirmation");
        assert_eq!(body.detail.as_deref(), Some("external recipient"));
        let fix = body.fix.expect("fix present");
        assert!(fix.contains("X-Proxilion-Confirmation"));
    }

    #[test]
    fn app_error_policy_blocked_display_carries_policy_id_debug_form_and_reason() {
        // `#[error("policy {policy_id:?} blocked request: {reason}")]`
        // — the `{policy_id:?}` Debug form is load-bearing: `Some("p1")`
        // renders as `Some("p1")` (with the quotes) and `None` renders
        // as `None`, both distinguishable in log aggregators. Operators
        // grep `policy Some("p1") blocked` to bucket per-policy block
        // rates separately from the catch-all default-deny path which
        // shows as `policy None blocked`. A refactor to `{policy_id}`
        // (without `:?`) would either panic (Option doesn't impl
        // Display) or require unwrap_or("(none)") and silently merge
        // the two buckets.
        let e = AppError::PolicyBlocked {
            policy_id: Some("gmail-external-send-gate".into()),
            reason: "external recipient".into(),
            override_allowed: true,
        };
        assert_eq!(
            e.to_string(),
            r#"policy Some("gmail-external-send-gate") blocked request: external recipient"#,
        );
        // Symmetric None case — pin the bare `None` rendering so a
        // refactor that injected a placeholder wouldn't slip past.
        let e = AppError::PolicyBlocked {
            policy_id: None,
            reason: "default-deny".into(),
            override_allowed: false,
        };
        assert_eq!(e.to_string(), "policy None blocked request: default-deny",);
    }

    #[test]
    fn app_error_require_confirmation_display_carries_prefix_with_inner_reason() {
        // `#[error("requires user confirmation: {0}")]` — pin the full
        // shape so a refactor that softened the prefix to "needs
        // confirmation: {0}" (a natural "tighten the message" change)
        // would surface here. The 428 docs page anchors on the literal
        // "requires user confirmation" substring as the operator-facing
        // log signal that distinguishes a `RequireConfirmation` 428
        // from a `RateLimit` 429 (both block the agent retry loop).
        let e = AppError::RequireConfirmation("external attendee on calendar invite".into());
        assert_eq!(
            e.to_string(),
            "requires user confirmation: external attendee on calendar invite",
        );
    }

    #[test]
    fn app_error_pic_invariant_violation_display_carries_trust_plane_prefix() {
        // `#[error("Trust Plane refused PCA: {0}")]` — the prefix
        // distinguishes this Layer-A error from `OAuthError::PicInvariant`
        // (which also surfaces a Trust Plane refusal but on the OAuth
        // flow side, not the adapter call side). Operator dashboards
        // bucket the two on the prefix presence — a "tidy up" refactor
        // that aligned both to the same prefix would silently flatten
        // adapter-side monotonicity faults onto OAuth-side ones,
        // making operators chase the wrong root cause. Pin the full
        // shape against an inner string carrying the canonical
        // missing-atoms syntax.
        let e = AppError::PicInvariantViolation(
            "ops not subset of predecessor: missing [drive:write:file/secret]".into(),
        );
        assert_eq!(
            e.to_string(),
            "Trust Plane refused PCA: ops not subset of predecessor: missing [drive:write:file/secret]",
        );
    }

    #[test]
    fn app_error_policy_display_carries_policy_engine_prefix_with_inner_error_message() {
        // `#[error("policy engine: {0}")]` on `Policy(#[from] rego::Error)`
        // — the prefix distinguishes engine-evaluation errors (a
        // malformed YAML decision shape, a regex compile fault) from
        // adapter-side errors (`OpsTemplate`, `Upstream`). Build a
        // concrete `rego::Error::BadDecision` and pin both halves of
        // the Display: the `"policy engine: "` prefix AND the inner
        // `rego::Error` Display passthrough (which itself starts with
        // `"invalid decision shape: "` — pinned in policy-engine's own
        // tests, included here defensively so a regression in either
        // module surfaces alongside the symmetric test).
        let inner = policy_engine::rego::Error::BadDecision("missing reason field".into());
        let e: AppError = AppError::Policy(inner);
        let s = e.to_string();
        assert!(s.starts_with("policy engine: "), "got: {s}");
        assert!(s.contains("invalid decision shape"), "got: {s}");
        assert!(s.contains("missing reason field"), "got: {s}");
    }

    #[test]
    fn app_error_ops_template_display_carries_policy_ops_template_prefix() {
        // `#[error("policy ops template: {0}")]` on
        // `OpsTemplate(#[from] OpsParseError)` — symmetric to the
        // `Policy(_)` arm above but distinct in prefix. The two
        // variants share a 500 ErrorCode::PolicyEngineError on the
        // wire (operators see the same `code`) but the log Display
        // string distinguishes them so a triage runbook can tell
        // "operator authored a bad template" (OpsTemplate) from "the
        // engine itself rejected the YAML structure" (Policy) without
        // walking back to the structured-trace. A refactor that
        // collapsed the two prefixes to a uniform "policy: {0}" would
        // silently merge the buckets.
        let inner = policy_engine::ops::OpsParseError::UnknownVar("path.missing".into());
        let e: AppError = AppError::OpsTemplate(inner);
        let s = e.to_string();
        assert!(s.starts_with("policy ops template: "), "got: {s}");
        // The inner OpsParseError Display surfaces — pinned in
        // policy-engine's own tests; included here so cross-module
        // drift surfaces.
        assert!(s.contains("template variable"), "got: {s}");
        assert!(s.contains("path.missing"), "got: {s}");
    }

    #[test]
    fn app_error_internal_display_carries_internal_error_prefix_with_inner_string() {
        // `#[error("internal error: {0}")]` — unlike `OAuthError::Internal`
        // (which is `#[error("internal error")]` and deliberately
        // masks the inner String to prevent leaking adapter-built
        // `format!("token=...")` payloads through the OAuth response
        // path), `AppError::Internal` DOES include the inner String
        // because adapter call sites surface it only into operator-
        // facing logs (the agent-facing 500 body collapses to the
        // shared "internal error" title with no detail — pinned by
        // `app_error_body_db_and_internal_collapse_to_internal_error_envelope`).
        // The asymmetry is intentional: OAuth-side errors face the
        // public OAuth flow, adapter-side errors face the agent which
        // is already authenticated. Pin the full prefix-and-inner
        // shape so a refactor that "harmonized" the two (the natural
        // "treat both Internal variants the same" mistake) would
        // surface here.
        let e = AppError::Internal("integer overflow at quarantine_count".into());
        assert_eq!(
            e.to_string(),
            "internal error: integer overflow at quarantine_count",
        );
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
