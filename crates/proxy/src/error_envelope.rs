//! Shared HTTP error envelope.
//!
//! Every 4xx/5xx body across the proxy looks the same:
//!
//! ```json
//! {
//!   "error":  "human-friendly title",
//!   "code":   "machine_code",
//!   "detail": "what specifically went wrong (optional)",
//!   "fix":    "how to fix it (optional, plain English)",
//!   "docs":   "https://proxilion.com/docs/... (optional)"
//! }
//! ```
//!
//! Optional fields are omitted when null. Each error type in the proxy uses
//! `ErrorBody::new` (with code + message) and chains `.with_detail()` /
//! `.with_fix()` / `.with_docs()` etc. The point is to make every failure
//! self-describing: an operator pasting our body into a search bar should
//! get to a fix in seconds.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[allow(dead_code)] // referenced from docs / future callers
pub const DOCS_BASE: &str = "https://proxilion.com/docs";

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// One-line human title.
    pub error: &'static str,
    /// Stable machine code (snake_case).
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Plain-English fix suggestion. Should read as an imperative ("Set
    /// PROXILION_TOKEN_ENCRYPTION_KEY to ...", "Run `proxilion-cli ...`").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<&'static str>,
    /// Link to a relevant docs page (full URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs: Option<&'static str>,
    /// Optional structured extras (policy_id, override_allowed, etc.).
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub extras: serde_json::Value,
}

impl ErrorBody {
    pub fn new(error: &'static str, code: &'static str) -> Self {
        Self {
            error,
            code,
            detail: None,
            fix: None,
            docs: None,
            extras: serde_json::Value::Null,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_fix(mut self, fix: &'static str) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn with_docs(mut self, docs: &'static str) -> Self {
        self.docs = Some(docs);
        self
    }

    pub fn with_extras(mut self, extras: serde_json::Value) -> Self {
        self.extras = extras;
        self
    }

    pub fn into_response(self, status: StatusCode) -> Response {
        (status, Json(self)).into_response()
    }
}

impl IntoResponse for ErrorBody {
    fn into_response(self) -> Response {
        // Default: 500. Callers should always specify status via
        // `into_response(status)`; we only implement IntoResponse so the
        // type can be used in test fixtures and helpers.
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_required_fields_and_leaves_optional_unset() {
        let body = ErrorBody::new("bad", "bad_request");
        assert_eq!(body.error, "bad");
        assert_eq!(body.code, "bad_request");
        assert!(body.detail.is_none());
        assert!(body.fix.is_none());
        assert!(body.docs.is_none());
        assert!(body.extras.is_null());
    }

    #[test]
    fn builders_compose_and_set_individual_fields() {
        let body = ErrorBody::new("nope", "not_found")
            .with_detail("row 42 missing")
            .with_fix("re-run the migration")
            .with_docs("https://proxilion.com/docs/x")
            .with_extras(serde_json::json!({"policy_id": "p1"}));
        assert_eq!(body.detail.as_deref(), Some("row 42 missing"));
        assert_eq!(body.fix, Some("re-run the migration"));
        assert_eq!(body.docs, Some("https://proxilion.com/docs/x"));
        assert_eq!(body.extras["policy_id"], "p1");
    }

    #[test]
    fn serializes_only_set_optional_fields() {
        let body = ErrorBody::new("title", "code1");
        let s = serde_json::to_value(&body).unwrap();
        assert_eq!(s["error"], "title");
        assert_eq!(s["code"], "code1");
        // Optional fields omitted entirely.
        assert!(s.get("detail").is_none());
        assert!(s.get("fix").is_none());
        assert!(s.get("docs").is_none());
        assert!(s.get("extras").is_none());
    }

    #[test]
    fn serializes_all_fields_when_set() {
        let body = ErrorBody::new("t", "c")
            .with_detail("d")
            .with_fix("f")
            .with_docs("https://x");
        let s = serde_json::to_value(&body).unwrap();
        assert_eq!(s["detail"], "d");
        assert_eq!(s["fix"], "f");
        assert_eq!(s["docs"], "https://x");
    }

    #[tokio::test]
    async fn into_response_with_status_uses_provided_status() {
        let r = ErrorBody::new("nope", "not_found").into_response(StatusCode::NOT_FOUND);
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn extras_null_omitted_extras_object_included_on_wire() {
        // `#[serde(skip_serializing_if = "serde_json::Value::is_null")]`
        // on the `extras` field is load-bearing: downstream operator
        // tooling indexes on the presence of `extras` to decide whether
        // to parse it. A refactor that swapped the skip-predicate for
        // `Option::is_none` (the more "consistent" choice) would land
        // an `extras: null` literal on every error body and break the
        // is_present-implies-parse contract.
        let bare = ErrorBody::new("t", "c");
        let s = serde_json::to_value(&bare).unwrap();
        assert!(s.get("extras").is_none(), "null extras must be omitted");

        let with = ErrorBody::new("t", "c")
            .with_extras(serde_json::json!({"policy_id": "p1", "override_allowed": true}));
        let s = serde_json::to_value(&with).unwrap();
        assert_eq!(s["extras"]["policy_id"], "p1");
        assert_eq!(s["extras"]["override_allowed"], true);
    }

    #[test]
    fn docs_base_constant_pinned_to_canonical_root_url() {
        // `DOCS_BASE` is referenced by future call sites and by docs
        // pages telling operators "your error body's `docs` field
        // begins with…". Pin the canonical root so a typo regression
        // (proxilion.io vs proxilion.com) doesn't slip past review.
        assert_eq!(DOCS_BASE, "https://proxilion.com/docs");
    }

    #[test]
    fn error_body_debug_includes_code_for_grep() {
        // The `Debug` derive feeds operator-facing `tracing::warn!(?body, ...)`
        // call sites — pin that the `code` field is visible in the
        // rendered string. A manual Debug impl that hid the field (in
        // the name of "don't log internal codes") would silently break
        // operator triage.
        let b = ErrorBody::new("title", "policy_blocked").with_detail("specific reason");
        let s = format!("{b:?}");
        assert!(s.contains("policy_blocked"), "got: {s}");
        assert!(s.contains("specific reason"));
    }

    #[test]
    fn with_detail_accepts_string_and_str_via_into() {
        // `with_detail(impl Into<String>)` must accept both `&str` and
        // `String` — pin both call shapes so a refactor to a stricter
        // signature (e.g. `&'static str` for symmetry with `with_fix`)
        // surfaces here. Adapter sites build dynamic detail strings
        // (`format!(...)`) and rely on the `String` path.
        let owned = ErrorBody::new("t", "c").with_detail(String::from("dynamic"));
        assert_eq!(owned.detail.as_deref(), Some("dynamic"));
        let borrowed = ErrorBody::new("t", "c").with_detail("static");
        assert_eq!(borrowed.detail.as_deref(), Some("static"));
    }

    #[tokio::test]
    async fn into_response_default_is_500() {
        // The blanket IntoResponse impl maps to 500.
        let body = ErrorBody::new("oops", "internal_error");
        let r: Response = IntoResponse::into_response(body);
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
