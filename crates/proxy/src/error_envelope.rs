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

    #[test]
    fn error_body_is_send_sync_for_axum_into_response_boundary() {
        // `ErrorBody` is held across `.await` points in adapter error
        // paths (the adapter builds the envelope, awaits a metrics
        // counter increment, then returns the response). The
        // `IntoResponse` trait requires `Send` because axum's response
        // future is Send-bound. An `Rc<...>` field added to a future
        // variant "for cheap clone of detail strings" would break Send
        // and surface at the adapter call site with an opaque axum
        // trait-bound. Pin both Send and Sync at this file boundary so
        // a refactor lands clean diagnostics. Note `'static` is NOT
        // pinned: the `detail: Option<String>` field is owned-not-
        // borrowed, so the type is naturally 'static — but we don't
        // need to pin that bound separately since it's tied to the
        // owned-String shape.
        fn require_send_sync<T: Send + Sync>(_: &T) {}
        let body = ErrorBody::new("t", "c")
            .with_detail("dynamic")
            .with_fix("static fix")
            .with_extras(serde_json::json!({"k": "v"}));
        require_send_sync(&body);
    }

    #[test]
    fn error_body_serialized_json_object_carries_exactly_six_known_keys_when_all_set() {
        // The struct has 6 fields (error, code, detail, fix, docs,
        // extras). When all are set, the serialized JSON object must
        // carry EXACTLY those 6 keys — not 5 (a refactor that elided
        // one field "for backwards compat" would silently drop the
        // operator-facing piece) and not 7 (a refactor that surfaced
        // an internal correlation-id field "for telemetry" would
        // silently widen the operator-facing wire shape, potentially
        // leaking session data). Pin both the count AND each key name.
        let body = ErrorBody::new("t", "c")
            .with_detail("d")
            .with_fix("f")
            .with_docs("https://x")
            .with_extras(serde_json::json!({"k": "v"}));
        let v = serde_json::to_value(&body).unwrap();
        let obj = v
            .as_object()
            .expect("ErrorBody must serialize to a JSON object");
        assert_eq!(obj.len(), 6, "field count drift: {obj:?}");
        for k in ["error", "code", "detail", "fix", "docs", "extras"] {
            assert!(obj.contains_key(k), "missing key {k}: {obj:?}");
        }
    }

    #[test]
    fn with_extras_can_reset_to_null_to_re_enable_skip_predicate() {
        // The `with_extras` builder takes `serde_json::Value` directly —
        // an operator-side refactor that wanted to CLEAR an
        // accidentally-set extras (e.g. the engine seeded it, then the
        // adapter realized the policy_id wasn't relevant to this error
        // code) MUST be able to pass `Value::Null` and have the skip
        // predicate re-engage on the wire. Pin both the field state
        // (`is_null()`) AND the wire shape (key omitted entirely) so
        // a refactor that gated the skip predicate on "was-ever-set"
        // (a once-flag refactor "for explicit absence semantics")
        // would surface here as a `"extras": null` literal on the wire.
        let body = ErrorBody::new("t", "c")
            .with_extras(serde_json::json!({"policy_id": "p1"}))
            .with_extras(serde_json::Value::Null);
        assert!(body.extras.is_null(), "extras field must be null");
        let v = serde_json::to_value(&body).unwrap();
        assert!(
            v.get("extras").is_none(),
            "null extras must be omitted by skip predicate, got: {v}",
        );
    }

    #[test]
    fn docs_base_constant_is_static_str_with_no_trailing_slash() {
        // The `DOCS_BASE` constant is the prefix that error-body `docs`
        // URLs concatenate against — pin both the `&'static str`
        // lifetime contract (a refactor to `String` would heap-allocate
        // every error build path) AND the no-trailing-slash shape (a
        // future `format!("{DOCS_BASE}/{slug}")` call site needs the
        // base WITHOUT trailing slash to avoid `//errors/...`). The
        // existing `docs_base_constant_pinned_to_canonical_root_url`
        // pin checks the literal; this pin reinforces the lifetime +
        // structural shape so a one-byte trailing-slash drift would
        // surface at this file rather than as a `//`-prefixed broken
        // link in the operator UI.
        fn require_static_str(_: &'static str) {}
        require_static_str(DOCS_BASE);
        assert!(!DOCS_BASE.ends_with('/'), "DOCS_BASE must not end with /");
        assert!(DOCS_BASE.starts_with("https://"));
    }

    #[tokio::test]
    async fn into_response_preserves_status_byte_exact_across_full_status_range() {
        // The `into_response(status)` helper passes the status through
        // unchanged — pin a SWEEP across the common 4xx/5xx codes
        // (400, 401, 403, 404, 422, 429, 500, 503) so a refactor that
        // collapsed all 4xx to 400 "for client-side simplification"
        // OR that re-mapped 503 to 500 "since both are unreachable"
        // would surface here as a status-code drift. The existing
        // `into_response_with_status_uses_provided_status` pin checks
        // ONE code (404); widen to the full sweep so any single drift
        // surfaces on the exact code that drifted, not just the one
        // covered status.
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let r = ErrorBody::new("t", "c").into_response(status);
            assert_eq!(r.status(), status, "status drifted for input {status}");
        }
    }

    #[test]
    fn error_body_serialized_json_first_two_keys_are_error_then_code_in_declaration_order() {
        // `serde_json` serializes struct fields in declaration order;
        // operator dashboards parsing the body line-by-line key on this
        // order (the first 16 bytes of every body are
        // `{"error":"...","co`...). A refactor that re-ordered the
        // struct fields "for grouping required-before-optional" would
        // silently flip the on-wire byte sequence and break any
        // streaming-parse consumer. Pin the lead-in by serializing to a
        // String and checking the byte prefix starts with `{"error":`
        // and the SECOND key is `"code":` — not just that both fields
        // are present (the existing tests cover that).
        let body = ErrorBody::new("nope", "not_found")
            .with_detail("d")
            .with_fix("f")
            .with_docs("https://x")
            .with_extras(serde_json::json!({"k": "v"}));
        let s = serde_json::to_string(&body).unwrap();
        assert!(s.starts_with("{\"error\":"), "leading key drift: {s}");
        // The second key MUST be "code" — find its position and
        // assert it's the first key after the leading `"error":"..."` pair.
        let after_error_value = s.find("\",\"").expect("error/code separator missing");
        let next_chunk = &s[after_error_value + 3..];
        assert!(
            next_chunk.starts_with("code\":"),
            "second key must be `code`, got: {next_chunk}",
        );
    }
}
