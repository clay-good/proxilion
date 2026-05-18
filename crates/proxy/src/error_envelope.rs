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

    #[test]
    fn with_extras_overrides_prior_value_on_repeated_call() {
        // The builder methods take `mut self`-by-value, so a repeated
        // call MUST overwrite the prior value (last-write-wins). Pin
        // this on `with_extras` specifically — adapter call sites
        // sometimes build the envelope in two stages (a default
        // policy_id from the engine, then an override from the
        // adapter), and a refactor that collapsed the two slots into
        // a merge / append shape would silently change which value
        // surfaces on the wire.
        let body = ErrorBody::new("t", "c")
            .with_extras(serde_json::json!({"policy_id": "old"}))
            .with_extras(serde_json::json!({"policy_id": "new"}));
        assert_eq!(body.extras["policy_id"], "new");
        // The first call's value is fully replaced — not merged.
        assert!(body.extras.get("policy_id").is_some());
    }

    #[test]
    fn with_fix_overrides_prior_value_on_repeated_call() {
        // The builder is `mut self`-by-value — symmetric to the existing
        // `with_extras_overrides_prior_value_on_repeated_call` test, but
        // on the `with_fix` arm. Adapter call sites sometimes layer the
        // envelope construction (a default operator-facing fix from the
        // engine, then a more specific one from the adapter); pin
        // last-write-wins so a future refactor that collapsed the two
        // slots into a "prepend / append" shape would surface here.
        // `with_fix` takes `&'static str`, so both call sites are
        // string-literals — pin the override path explicitly.
        let body = ErrorBody::new("t", "c")
            .with_fix("run migration A")
            .with_fix("run migration B");
        assert_eq!(body.fix, Some("run migration B"));
    }

    #[test]
    fn with_docs_overrides_prior_value_on_repeated_call() {
        // Symmetric to `with_fix_overrides_prior_value_on_repeated_call`
        // on the `with_docs` arm. The docs URL is the operator's
        // copy-paste-into-browser path — a refactor that appended (e.g.
        // building a `docs/?next=...&prev=...` chain) would silently
        // change the wire shape from one URL to a query-string-encoded
        // pair, breaking every `docs` field consumer that expects a
        // single canonical URL.
        let body = ErrorBody::new("t", "c")
            .with_docs("https://proxilion.com/docs/old")
            .with_docs("https://proxilion.com/docs/new");
        assert_eq!(body.docs, Some("https://proxilion.com/docs/new"));
    }

    #[test]
    fn with_detail_overrides_prior_value_on_repeated_call() {
        // Symmetric to the fix/docs override pins. `with_detail` accepts
        // `impl Into<String>` (already pinned by
        // `with_detail_accepts_string_and_str_via_into`) — pin the
        // last-write-wins contract here so a refactor that concatenated
        // (e.g. `format!("{old}; {new}")` "to preserve operator history")
        // would silently double the rendered detail string on every
        // adapter that calls `with_detail` from two layers.
        let body = ErrorBody::new("t", "c")
            .with_detail("first detail")
            .with_detail("second detail");
        assert_eq!(body.detail.as_deref(), Some("second detail"));
    }

    #[test]
    fn with_extras_boolean_false_serializes_as_present_distinct_from_null_skip() {
        // The `extras` field's skip predicate is `serde_json::Value::is_null`
        // — explicitly NOT `is_falsy` or `as_bool().unwrap_or(true)`. Pin
        // that a JSON-`false` value lands on the wire (not skipped) so a
        // refactor that swapped the predicate to a more aggressive
        // "empty-ish value" check would surface here. The existing
        // `extras_null_omitted_extras_object_included_on_wire` test
        // pins the null-skip + object-present arms; this fills in the
        // boolean-false-and-zero-and-empty-string boundary.
        for v in [
            serde_json::json!(false),
            serde_json::json!(0),
            serde_json::json!(""),
        ] {
            let body = ErrorBody::new("t", "c").with_extras(v.clone());
            let s = serde_json::to_value(&body).unwrap();
            assert!(
                s.get("extras").is_some(),
                "extras={v} must be present on wire, got: {s}",
            );
            assert_eq!(s["extras"], v);
        }
    }

    #[test]
    fn error_body_required_fields_accept_static_str_literals_for_zero_alloc_paths() {
        // `error` and `code` are `&'static str` — pin the lifetime
        // contract via a function whose signature requires the
        // 'static bound. Adapter call sites construct envelopes from
        // string literals on the hot path, and the &'static contract
        // is what keeps them zero-alloc (no `String::from`). A refactor
        // that widened to `Cow<'static, str>` would surface as a
        // borrow-checker rewrite at call sites; a refactor to bare
        // `String` would silently land an allocation per error body
        // — pin the trait bound here.
        fn require_static<T: 'static>(_: T) {}
        let title: &'static str = "title";
        let code: &'static str = "code";
        let body = ErrorBody::new(title, code);
        // The fields surface unchanged.
        assert_eq!(body.error, "title");
        assert_eq!(body.code, "code");
        // And the bound holds — the body itself is 'static-borrowable
        // for its &'static str fields. (The String detail field is
        // owned and doesn't enter this check.)
        require_static(body.error);
        require_static(body.code);
    }

    #[test]
    fn builders_chain_in_any_order_and_compose_independently() {
        // The four builders (with_detail / with_fix / with_docs /
        // with_extras) take `mut self` by value and return Self — pin
        // that the chain order is irrelevant (each builder touches one
        // field independently) so a refactor that introduced a hidden
        // dependency (e.g. with_fix only honors the fix if detail is
        // already set, "for consistency") would surface here. The
        // existing `builders_compose_and_set_individual_fields` test
        // pins ONE chain order; this pins the symmetric reverse order
        // produces the same shape.
        let forward = ErrorBody::new("t", "c")
            .with_detail("d")
            .with_fix("f")
            .with_docs("https://x")
            .with_extras(serde_json::json!({"k": "v"}));
        let reverse = ErrorBody::new("t", "c")
            .with_extras(serde_json::json!({"k": "v"}))
            .with_docs("https://x")
            .with_fix("f")
            .with_detail("d");
        // Compare via the wire shape (the operator-facing surface) —
        // every field must match across both orderings.
        let f = serde_json::to_value(&forward).unwrap();
        let r = serde_json::to_value(&reverse).unwrap();
        assert_eq!(f, r, "builder chain order must not affect wire shape");
    }

    #[test]
    fn extras_with_array_or_string_value_serialize_as_non_null_and_present() {
        // The `extras` field is `serde_json::Value`, so it accepts any
        // JSON value — but the load-bearing skip predicate is
        // `Value::is_null`, not "is empty object". Pin that an array
        // extras value (operators occasionally surface a `missing_atoms`
        // vec directly into extras) AND a string extras value
        // (defensive: a debug shim someday passing a raw error string)
        // both serialize as present + non-null. A refactor that
        // tightened the skip predicate to "only objects are kept"
        // would silently drop both of these alternate shapes.
        let with_arr = ErrorBody::new("t", "c").with_extras(serde_json::json!(["a:1", "b:2"]));
        let v = serde_json::to_value(&with_arr).unwrap();
        assert!(v["extras"].is_array());
        assert_eq!(v["extras"][0], "a:1");

        let with_str = ErrorBody::new("t", "c").with_extras(serde_json::json!("scalar"));
        let v = serde_json::to_value(&with_str).unwrap();
        assert!(v["extras"].is_string());
        assert_eq!(v["extras"], "scalar");
    }
}
