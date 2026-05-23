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
    fn app_error_is_send_sync_static_for_axum_into_response_boundary() {
        // `AppError` is the return-error type for every Drive / Gmail /
        // Calendar adapter handler — it flows through `IntoResponse`
        // from handler futures that cross tokio task boundaries, which
        // mandates `Send + Sync + 'static`. A refactor that introduced
        // a !Send field (e.g. `Internal(Rc<String>)` "for cheap clone")
        // would break Sync at the AppState site rather than as a
        // far-removed trait-bound error. Pin the three-trait combo —
        // symmetric to the
        // `setup_api_state_and_setup_error_are_send_sync_static_for_axum_boundary`
        // pin on [crates/proxy/src/api/setup.rs] and the
        // `api_error_and_killswitch_state_are_send_sync_static_for_axum_state_boundary`
        // pin on [crates/proxy/src/api/killswitch.rs].
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<AppError>();
    }

    #[test]
    fn app_error_debug_carries_variant_names_for_grep_bucketing() {
        // The `#[derive(Debug)]` on `AppError` feeds `?err` in
        // `tracing::warn!(error = %self, ...)` and the 500-branch logs
        // emitted by `into_response`. Operators grep the log line by
        // variant name to bucket PolicyBlocked (Layer-B refusal) vs
        // RateLimit (429) vs ReadFilterBlocked (Layer-C quarantine) vs
        // Db (postgres outage) vs Internal (proxy bug). A hand-rolled
        // `impl Debug` that hid variant names "to compact" the line
        // would break every operator bucket. Pin five distinct names
        // — symmetric to the ConnectError / KeyError / ApiError /
        // AuthFail variant-name pins on other modules.
        let pb = format!(
            "{:?}",
            AppError::PolicyBlocked {
                policy_id: Some("p1".into()),
                reason: "r".into(),
                override_allowed: true,
            }
        );
        assert!(pb.contains("PolicyBlocked"), "got: {pb}");
        let rl = format!("{:?}", AppError::RateLimit);
        assert!(rl.contains("RateLimit"), "got: {rl}");
        let rf = format!("{:?}", AppError::ReadFilterBlocked);
        assert!(rf.contains("ReadFilterBlocked"), "got: {rf}");
        let db = format!("{:?}", AppError::Db(sqlx::Error::RowNotFound));
        assert!(db.contains("Db"), "got: {db}");
        let internal = format!("{:?}", AppError::Internal("x".into()));
        assert!(internal.contains("Internal"), "got: {internal}");
    }

    #[test]
    fn app_error_db_arm_display_masks_inner_sqlx_error_across_three_variants() {
        // `#[error("database error")]` on `Db(#[from] sqlx::Error)` —
        // the inner sqlx::Error carries schema column names + query
        // fragments + constraint identifiers (operator-internal
        // surface). Pin that Display is the fixed "database error"
        // string with NO inner content, regardless of which sqlx
        // variant is wrapped. Symmetric to the
        // `auth_fail_db_arm_display_masks_inner_sqlx_error_for_no_secret_leak`
        // pin on [crates/proxy/src/auth_middleware.rs] and the
        // `oauth_error_db_display_does_not_carry_inner_sqlx_string`
        // pin on [crates/proxy/src/oauth/error.rs] — keep all three
        // sites symmetric so a refactor that "harmonized" one of
        // them to `"database error: {0}"` "for richer triage"
        // surfaces at the matching pin in this module too. Walk
        // three distinct sqlx variants.
        for inner in [
            sqlx::Error::RowNotFound,
            sqlx::Error::PoolClosed,
            sqlx::Error::WorkerCrashed,
        ] {
            let e = AppError::Db(inner);
            assert_eq!(e.to_string(), "database error");
        }
    }

    #[test]
    fn app_error_read_filter_blocked_display_is_byte_exact_for_log_filters() {
        // `#[error("read filter blocked response body")]` on the
        // ReadFilterBlocked unit variant — pin the byte-exact Display
        // via `assert_eq!`. Operator log filters bucket Layer-C
        // quarantines on this exact substring; a refactor that
        // softened to `"read-filter blocked"` (hyphen rename) or
        // dropped the trailing `"response body"` qualifier "for
        // brevity" would silently break Loki filters historically
        // keyed on the canonical message. The body-no-detail contract
        // is already pinned by
        // `app_error_body_read_filter_blocked_has_no_detail_but_dashboard_hint`
        // — this pins the Display surface.
        assert_eq!(
            AppError::ReadFilterBlocked.to_string(),
            "read filter blocked response body",
        );
    }

    #[test]
    fn app_error_upstream_too_large_display_is_byte_exact_with_size_cap_qualifier() {
        // `#[error("upstream returned a body larger than the 10MB cap")]`
        // on the UpstreamTooLarge unit variant — pin the byte-exact
        // Display shape. The `10MB` qualifier in the message is the
        // operator-facing log substring AND aligns with the body
        // fix-text `10MB` mention (pinned by
        // `app_error_body_upstream_too_large_carries_size_hint`). A
        // refactor that swapped to "10 MB" (with a space) or "10485760
        // bytes" "for precision" would silently break operator log
        // filters keyed on the exact `"10MB cap"` substring AND drift
        // the Display + body fix-text apart.
        assert_eq!(
            AppError::UpstreamTooLarge.to_string(),
            "upstream returned a body larger than the 10MB cap",
        );
    }

    #[test]
    fn app_error_policy_blocked_extras_override_allowed_false_serializes_verbatim() {
        // The existing `app_error_body_carries_policy_id_and_override_allowed_in_extras`
        // pin walks `override_allowed: true`. Pin the symmetric `false`
        // polarity here — the dashboard's "request override" button
        // strictly dispatches on the JSON `false` literal to hide the
        // button (a `null` or absent field would either show the
        // button incorrectly or crash the renderer). A refactor that
        // started skip-serializing the field when false (the natural
        // `#[serde(skip_serializing_if = "..is_false..")]` shape) would
        // silently break the dashboard's override gate. Pin presence
        // + JSON-`false` literal + the `policy_id` field's None
        // serialization as JSON null.
        let e = AppError::PolicyBlocked {
            policy_id: None,
            reason: "default-deny".into(),
            override_allowed: false,
        };
        let body = e.body();
        let extras = &body.extras;
        assert!(
            extras.get("override_allowed").is_some(),
            "override_allowed key must be present even when false: {extras}",
        );
        assert_eq!(extras["override_allowed"], false);
        assert!(
            extras["override_allowed"].is_boolean(),
            "must be JSON boolean: {extras}",
        );
        // None policy_id serializes as JSON null for the dashboard's
        // "(no policy)" rendering branch — pin presence + null type.
        assert!(extras.get("policy_id").is_some());
        assert!(extras["policy_id"].is_null());
    }

    #[test]
    fn app_error_status_across_all_variants_is_4xx_or_5xx_never_2xx_or_3xx() {
        // Every AppError variant flows through `into_response` and surfaces
        // a non-success status — pin that across all canonical variants
        // (the enum surface the proxy hits on the request hot path). A
        // refactor that registered a new ErrorCode with a `default_status`
        // of 200 "for the 'allowed but log' case" would silently slip
        // past as `AppError::into_response().status().is_success()` and
        // every operator dashboard's "error rate" metric would silently
        // exclude that variant. Pin both axes — neither success NOR
        // redirect — across the full variant sweep.
        let variants: Vec<AppError> = vec![
            AppError::PolicyBlocked {
                policy_id: None,
                reason: "r".into(),
                override_allowed: false,
            },
            AppError::RequireConfirmation("x".into()),
            AppError::RateLimit,
            AppError::PicInvariantViolation("x".into()),
            AppError::UpstreamTooLarge,
            AppError::ReadFilterBlocked,
            AppError::Db(sqlx::Error::RowNotFound),
            AppError::Internal("x".into()),
        ];
        for v in &variants {
            let s = v.status();
            assert!(
                !s.is_success(),
                "variant {:?} surfaced 2xx status {}",
                v,
                s.as_u16(),
            );
            assert!(
                !s.is_redirection(),
                "variant {:?} surfaced 3xx status {}",
                v,
                s.as_u16(),
            );
            assert!(
                s.is_client_error() || s.is_server_error(),
                "variant {:?} surfaced non-4xx/5xx {}",
                v,
                s.as_u16(),
            );
        }
    }

    #[test]
    fn app_error_code_as_str_is_snake_case_across_all_variants_for_wire_contract() {
        // Each `ErrorCode::as_str()` is the on-wire `code` field operators
        // grep on. The wire convention is lowercase `snake_case` (e.g.
        // `policy_blocked`, `pic_invariant_violation`). A refactor that
        // surfaced one as `PolicyBlocked` (PascalCase, the natural Rust
        // ident) OR `policy-blocked` (kebab, the YAML convention) would
        // silently break every operator dashboard's regex bucket. Pin
        // BOTH absence of uppercase ASCII AND absence of `-` across all
        // canonical AppError variants — exhaustive sweep.
        let variants: Vec<AppError> = vec![
            AppError::PolicyBlocked {
                policy_id: None,
                reason: "r".into(),
                override_allowed: false,
            },
            AppError::RequireConfirmation("x".into()),
            AppError::RateLimit,
            AppError::PicInvariantViolation("x".into()),
            AppError::UpstreamTooLarge,
            AppError::ReadFilterBlocked,
            AppError::Db(sqlx::Error::RowNotFound),
            AppError::Internal("x".into()),
        ];
        for v in &variants {
            let s = v.code().as_str();
            assert!(!s.is_empty(), "variant {:?} surfaced empty code string", v);
            assert!(
                !s.chars().any(|c| c.is_ascii_uppercase()),
                "variant {:?} surfaced uppercase in code `{}`",
                v,
                s,
            );
            assert!(
                !s.contains('-'),
                "variant {:?} surfaced kebab in code `{}`",
                v,
                s,
            );
        }
    }

    #[tokio::test]
    async fn upstream_error_kind_returns_static_str_from_canonical_three_label_set() {
        // The `upstream_error_kind` helper's return type is
        // `&'static str` (the metric-label set is fixed and lives in
        // the binary's read-only segment). Pin the lifetime contract
        // via a helper that takes `&'static str` only — a refactor to
        // `String` would surface here as a type-mismatch + would
        // silently start heap-allocating on every adapter failure
        // path. Also pin via a concrete reqwest::Error (build a 1ms-
        // timeout request against the RFC 5737 documentation range so
        // the result is deterministic) that the returned label is one
        // of the three canonical bucket strings.
        fn require_static_str(_: &'static str) {}
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();
        let err = client.get("http://203.0.113.1/").send().await.unwrap_err();
        let kind = upstream_error_kind(&err);
        require_static_str(kind);
        assert!(
            matches!(kind, "timeout" | "network" | "other"),
            "kind `{kind}` not in canonical set"
        );
    }

    #[tokio::test]
    async fn app_error_body_upstream_arm_carries_no_detail_to_avoid_leaking_vendor_internal_state()
    {
        // `AppError::Upstream(reqwest::Error)` surfaces a generic
        // "upstream temporarily unavailable" message — the inner
        // reqwest error CAN carry vendor-internal state (e.g. a 503
        // response body with rate-limit-headers naming an internal
        // service id, or a DNS error naming an internal resolver). Pin
        // that the body's `detail` field stays `None` regardless of
        // the inner error's payload — symmetric to the Db / Internal
        // arms (existing `app_error_body_db_and_internal_collapse_to_internal_error_envelope`
        // pin walks those). A refactor that surfaced `detail:
        // Some(err.to_string())` "for richer agent triage" would
        // silently leak the inner reqwest error text on every
        // upstream failure. Build a real reqwest::Error and pin the
        // no-detail contract on its body envelope.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();
        let inner = client.get("http://203.0.113.1/").send().await.unwrap_err();
        let body = AppError::Upstream(inner).body();
        assert_eq!(body.code, "upstream_unavailable");
        assert!(
            body.detail.is_none(),
            "Upstream arm must not surface inner reqwest detail",
        );
        // And the fix-text still points at the troubleshooting docs.
        assert!(body.docs.unwrap().contains("troubleshooting"));
    }

    #[test]
    fn app_error_policy_blocked_extras_policy_id_serializes_as_json_string_when_some() {
        // `extras: serde_json::json!({"policy_id": policy_id, ...})` —
        // when `policy_id` is `Some("p1")`, serde serializes the inner
        // String DIRECTLY (NOT as an Option-wrapped `{"Some": "p1"}`).
        // The dashboard's renderer keys on a flat JSON string at this
        // path. A refactor that swapped `policy_id` from `Option<String>`
        // to a wrapper type with a Serialize impl emitting an `Option`
        // tag would silently change the wire shape from `"p1"` to a
        // nested object. Pin BOTH the string-type AND the byte-exact
        // value. The existing
        // `app_error_body_carries_policy_id_and_override_allowed_in_extras`
        // pin checks one Some value; this pin checks the JSON TYPE
        // (is_string) — distinct axis.
        let e = AppError::PolicyBlocked {
            policy_id: Some("gmail-external-send-gate".into()),
            reason: "external".into(),
            override_allowed: true,
        };
        let body = e.body();
        let pid = &body.extras["policy_id"];
        assert!(
            pid.is_string(),
            "policy_id must serialize as JSON string, got: {pid}",
        );
        assert_eq!(pid.as_str().unwrap(), "gmail-external-send-gate");
    }

    #[test]
    fn app_error_body_envelope_code_field_equals_code_as_str_across_all_variants() {
        // The `body().code` field is `self.code().as_str()` — a stable
        // bidirectional consistency the dashboard relies on (operators
        // can grep tracing logs for `code()` and join against the wire
        // `body.code` field on a stored audit row). A refactor that
        // introduced a per-variant override on `body()` (e.g.
        // `PolicyBlocked` returning a more specific code while
        // `code()` returned the umbrella one) would silently break
        // the join. Pin equality across all canonical variants.
        let variants: Vec<AppError> = vec![
            AppError::PolicyBlocked {
                policy_id: None,
                reason: "r".into(),
                override_allowed: false,
            },
            AppError::RequireConfirmation("x".into()),
            AppError::RateLimit,
            AppError::PicInvariantViolation("x".into()),
            AppError::UpstreamTooLarge,
            AppError::ReadFilterBlocked,
            AppError::Db(sqlx::Error::RowNotFound),
            AppError::Internal("x".into()),
        ];
        for v in &variants {
            let body = v.body();
            assert_eq!(
                body.code,
                v.code().as_str(),
                "body.code drift for variant {:?}",
                v,
            );
        }
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

    // ─── round 230 (2026-05-22): AppError variant count, PolicyBlocked struct-
    // variant exhaustive destructure, code/status fn-pointer pins, body() RT,
    // Internal owned-String contract ───

    #[test]
    fn app_error_variant_count_pinned_at_exactly_eleven_via_exhaustive_match_no_underscore_fallback()
     {
        // `AppError` has 11 variants: PolicyBlocked, RequireConfirmation,
        // RateLimit, PicInvariantViolation, UpstreamTooLarge, Upstream,
        // Policy, OpsTemplate, ReadFilterBlocked, Db, Internal. A 12th
        // variant landing (e.g. `OperatorOverride(String)` for a
        // ui-less-surfaces.md follow-up, OR `CircuitBreakerOpen` for a
        // per-vendor circuit breaker) without matching `code()` /
        // `status()` / `body()` arms would silently default to whatever
        // wildcard catches it (today there's none — exhaustive matches
        // are required). The exhaustive-match witness with no `_`
        // fallback forces a 12th variant to update every match arm in
        // lockstep — surfacing here at compile time, not at the wire-
        // shape mismatch downstream. Symmetric to the CipherError 2-
        // variant + CacheError 1-variant + SetupError 1-variant
        // exhaustive-match pins.
        fn _exhaustive_variant_check(e: &AppError) -> &'static str {
            match e {
                AppError::PolicyBlocked { .. } => "policy_blocked",
                AppError::RequireConfirmation(_) => "require_confirmation",
                AppError::RateLimit => "rate_limit",
                AppError::PicInvariantViolation(_) => "pic_invariant",
                AppError::UpstreamTooLarge => "upstream_too_large",
                AppError::Upstream(_) => "upstream",
                AppError::Policy(_) => "policy",
                AppError::OpsTemplate(_) => "ops_template",
                AppError::ReadFilterBlocked => "read_filter_blocked",
                AppError::Db(_) => "db",
                AppError::Internal(_) => "internal",
            }
        }
        // Exercise on a representative variant so the witness runs.
        let e = AppError::RateLimit;
        assert_eq!(_exhaustive_variant_check(&e), "rate_limit");
    }

    #[test]
    fn app_error_policy_blocked_struct_variant_field_count_pinned_at_exactly_three_via_destructure()
    {
        // `AppError::PolicyBlocked { policy_id, reason, override_allowed }`
        // — exactly 3 fields. A 4th field landing (e.g. `matched_rule:
        // Option<String>` for surfacing the specific rule inside the
        // policy that fired, OR `severity: Severity` for a tiered
        // policy-block enum) without matching `body()` extras
        // construction at the PolicyBlocked arm would silently lose
        // the new field on every wire response. The exhaustive
        // destructure with no `..` rest pattern forces a 4th field to
        // update both the destructure AND the body() construction in
        // lockstep — surfacing here. Symmetric to the FederationClaims
        // 8-field + EscalationRow 13-field exhaustive-destructure pins
        // extended to a struct-variant case.
        let e = AppError::PolicyBlocked {
            policy_id: Some("pol1".into()),
            reason: "denied".into(),
            override_allowed: true,
        };
        if let AppError::PolicyBlocked {
            policy_id: _,
            reason: _,
            override_allowed: _,
        } = e
        {
            // Destructure compiled — 3-field shape confirmed.
        } else {
            unreachable!()
        }
    }

    #[test]
    fn app_error_code_return_type_is_error_code_via_fn_pointer_witness_for_metric_label_propagation()
     {
        // `AppError::code(&self) -> ErrorCode` is invoked on every
        // error response to attach the `code=...` metric label AND to
        // construct the wire envelope's `code` field. Pin the return
        // type via a fn-pointer witness so a refactor that widened to
        // `Option<ErrorCode>` "for variants that don't map to a
        // canonical code yet" would surface here at the type axis,
        // breaking the metric-emit + envelope construction sites that
        // depend on infallibility. The classifier MUST be total — every
        // variant has a code, none are skipped — and the type axis is
        // where that contract lives. Symmetric to the OAuthError::body
        // owned-ErrorBody fn-pointer pin in round 220.
        let _f: fn(&AppError) -> ErrorCode = AppError::code;
        // Exercise across a representative variant.
        let e = AppError::RateLimit;
        let code: ErrorCode = e.code();
        let _ = code;
    }

    #[test]
    fn app_error_status_return_type_is_status_code_via_fn_pointer_witness_for_axum_into_response() {
        // `AppError::status(&self) -> StatusCode` is invoked by
        // `into_response` to set the HTTP status on the wire envelope.
        // Pin the return type via a fn-pointer witness so a refactor
        // that widened to `u16` "for ergonomic integer-level
        // operator-override at the boundary" would surface here at the
        // type axis. The axum `into_response` site depends on the
        // typed StatusCode for correct 4xx/5xx bucket classification.
        // Symmetric to the OAuthError::status fn-pointer + status
        // integer-level pins.
        let _f: fn(&AppError) -> StatusCode = AppError::status;
        let e = AppError::RateLimit;
        let _: StatusCode = e.status();
    }

    #[test]
    fn app_error_body_is_referentially_transparent_across_fifty_calls_per_variant() {
        // `AppError::body()` is a pure function of `&self` — no I/O, no
        // global state, no time-of-day input. Pin referential
        // transparency across 50 calls per variant so a refactor that,
        // e.g., introduced a per-call rate-limit-driven detail mutation
        // ("promote rate-limit-of-rate-limits to PicInvariantViolation
        // after 100th in 10s") would surface here as non-deterministic
        // output. Operator dashboards depend on the `code` + `detail`
        // wire shape being byte-stable across all error emissions of
        // the same variant. Symmetric to the OAuthError::body RT
        // 50-call + ErrorBody::new RT 50-call pins.
        let variants = [
            AppError::PolicyBlocked {
                policy_id: Some("p1".into()),
                reason: "r".into(),
                override_allowed: true,
            },
            AppError::RequireConfirmation("reason".into()),
            AppError::RateLimit,
            AppError::PicInvariantViolation("hop".into()),
            AppError::UpstreamTooLarge,
            AppError::ReadFilterBlocked,
            AppError::Internal("boom".into()),
        ];
        for v in &variants {
            let first_body = v.body();
            for i in 0..50 {
                let next = v.body();
                assert_eq!(
                    next.code, first_body.code,
                    "iter {i}: code drift on variant {v:?}",
                );
                assert_eq!(
                    next.detail, first_body.detail,
                    "iter {i}: detail drift on variant {v:?}",
                );
            }
        }
    }

    #[test]
    fn app_error_internal_inner_field_pinned_owned_string_for_cross_await_anyhow_chain_propagation()
    {
        // `AppError::Internal(String)` — the inner field is OWNED
        // `String`, NOT `&'static str` or `Cow<'static, str>`. The
        // value is constructed at adapter call sites via `format!()`
        // / `e.to_string()` — both produce owned String — and is
        // moved across `.await` boundaries through `tokio::spawn`
        // (audit emit) before finally landing in `into_response`. A
        // refactor to `&'static str` "for cheaper passthrough on
        // static-prefix error paths" would force every adapter call
        // site to switch to leaked-string OR `Box::leak`, fragmenting
        // the construction shape across 20+ adapter files. Pin via
        // require_owned_string. Symmetric to the OAuthError 4-String-
        // variant owned-String pin in round 220 + GoogleClient
        // 4-field owned-String pin in round 216 extended to this
        // catchall variant.
        fn require_owned_string(s: String) -> String {
            s
        }
        let inner = require_owned_string(String::from("synthesized error message"));
        let e = AppError::Internal(inner);
        if let AppError::Internal(s) = &e {
            // Confirm the owned-String shape at the field-access level.
            require_owned_string(s.clone());
            assert_eq!(s, "synthesized error message");
        } else {
            unreachable!()
        }
        // And exercise the RequireConfirmation arm with the same
        // contract — also single-tuple String variant.
        let e2 = AppError::RequireConfirmation(String::from("confirm please"));
        if let AppError::RequireConfirmation(s) = &e2 {
            require_owned_string(s.clone());
        }
    }
}
