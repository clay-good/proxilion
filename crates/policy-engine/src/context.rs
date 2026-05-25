//! `RequestContext` — the input to every policy evaluation.
//!
//! Lives in the policy engine for now; will likely move to `shared-types` once
//! the proxy and adapters need to construct it.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    pub vendor: String,
    pub action: String,
    pub user: UserCtx,
    /// Path parameters extracted by the adapter (e.g. `id` for `drive.files.get`).
    pub path: HashMap<String, String>,
    /// Parsed request body fields the adapter chose to expose to policy.
    pub body: HashMap<String, serde_json::Value>,
    /// Headers exposed to policy (lowercased keys).
    pub headers: HashMap<String, String>,
    /// Customer's primary domain. Used in template interpolation.
    pub customer_domain: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserCtx {
    pub email: String,
    pub groups: Vec<String>,
}

impl RequestContext {
    /// Look up a list-valued template variable. Returns `Some(vec)` only when
    /// the bound value is genuinely a JSON array of strings — scalars and
    /// other shapes return `None` so the caller can fall back to the scalar
    /// `lookup` path. Used by `OpsExpression::resolve` (spec.md §2.2) to
    /// expand a single template into N atoms, e.g.
    /// `gmail:send:to:${body.to_domains}` over 3 recipient domains yields 3
    /// required-ops atoms.
    pub fn lookup_list(&self, dotted: &str) -> Option<Vec<String>> {
        let (head, tail) = dotted.split_once('.')?;
        let value = match head {
            "body" => self.body.get(tail)?,
            // path / headers / user are flat string maps — never list-valued.
            _ => return None,
        };
        let arr = value.as_array()?;
        let mut out = Vec::with_capacity(arr.len());
        for v in arr {
            // A list with a non-string element is not a valid expansion; fall
            // back to the scalar path by returning None.
            out.push(v.as_str()?.to_string());
        }
        Some(out)
    }

    /// Look up `dotted.path` against `path.*`, `user.*`, `body.*`, `headers.*`,
    /// and the bare `customer_domain` identifier used in YAML templates.
    pub fn lookup(&self, dotted: &str) -> Option<String> {
        if dotted == "customer_domain" {
            return Some(self.customer_domain.clone());
        }
        let (head, tail) = dotted.split_once('.')?;
        match head {
            "path" => self.path.get(tail).cloned(),
            "user" => match tail {
                "email" => Some(self.user.email.clone()),
                _ => None,
            },
            "body" => self.body.get(tail).map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| v.to_string())
            }),
            "headers" => self.headers.get(tail).cloned(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_ctx() -> RequestContext {
        let mut path = HashMap::new();
        path.insert("id".into(), "fileA".into());
        let mut headers = HashMap::new();
        headers.insert("x-trace-id".into(), "abc123".into());
        let mut body = HashMap::new();
        body.insert("subject".into(), json!("hi"));
        body.insert("to_domains".into(), json!(["example.com", "other.com"]));
        body.insert("external_recipient".into(), json!(true));
        body.insert("score".into(), json!(5));
        body.insert("mixed".into(), json!([1, "two"]));
        RequestContext {
            vendor: "google".into(),
            action: "drive.files.get".into(),
            customer_domain: "acme.com".into(),
            user: UserCtx {
                email: "alice@acme.com".into(),
                groups: vec!["eng".into(), "sec".into()],
            },
            path,
            headers,
            body,
        }
    }

    #[test]
    fn lookup_customer_domain_bare_identifier() {
        let c = sample_ctx();
        assert_eq!(c.lookup("customer_domain"), Some("acme.com".into()));
    }

    #[test]
    fn lookup_path_and_user_fields() {
        let c = sample_ctx();
        assert_eq!(c.lookup("path.id"), Some("fileA".into()));
        assert_eq!(c.lookup("user.email"), Some("alice@acme.com".into()));
        // `user.groups` is not exposed via the scalar lookup path.
        assert_eq!(c.lookup("user.groups"), None);
    }

    #[test]
    fn lookup_headers_returns_string() {
        let c = sample_ctx();
        assert_eq!(c.lookup("headers.x-trace-id"), Some("abc123".into()));
        assert_eq!(c.lookup("headers.missing"), None);
    }

    #[test]
    fn lookup_body_string_field_is_unquoted() {
        let c = sample_ctx();
        // A `Value::String` returns its inner str, not the JSON-quoted form.
        assert_eq!(c.lookup("body.subject"), Some("hi".into()));
    }

    #[test]
    fn lookup_body_non_string_falls_back_to_json_repr() {
        let c = sample_ctx();
        assert_eq!(c.lookup("body.score"), Some("5".into()));
        assert_eq!(c.lookup("body.external_recipient"), Some("true".into()));
    }

    #[test]
    fn lookup_unknown_head_returns_none() {
        let c = sample_ctx();
        assert!(c.lookup("garbage.field").is_none());
        // A dotted path with no head separator is also None.
        assert!(c.lookup("no_dot").is_none());
    }

    #[test]
    fn lookup_list_string_array_returns_vec() {
        let c = sample_ctx();
        assert_eq!(
            c.lookup_list("body.to_domains"),
            Some(vec!["example.com".into(), "other.com".into()])
        );
    }

    #[test]
    fn lookup_list_non_array_returns_none() {
        let c = sample_ctx();
        // body.score is a number → None (caller falls back to scalar lookup).
        assert!(c.lookup_list("body.score").is_none());
    }

    #[test]
    fn lookup_list_array_with_non_string_element_returns_none() {
        let c = sample_ctx();
        assert!(c.lookup_list("body.mixed").is_none());
    }

    #[test]
    fn lookup_body_missing_key_returns_none_distinct_from_null_value() {
        // Two boundaries: a missing body key returns None; a body key
        // present but valued `json!(null)` returns Some("null") via
        // the json-repr fallback. The distinction matters because
        // the OpsExpression resolver uses `None` to fall through to
        // the bare-template form (no substitution), whereas a string
        // `"null"` would produce a literal `ops:atom:null` atom on
        // the wire.
        let mut c = sample_ctx();
        assert!(c.lookup("body.absent").is_none());
        c.body.insert("nullable".into(), json!(null));
        assert_eq!(c.lookup("body.nullable"), Some("null".into()));
    }

    #[test]
    fn lookup_list_empty_string_array_returns_empty_vec_not_none() {
        // The OpsExpression substitution path treats `Some(vec)` as
        // "expand into N atoms" — an empty Vec must yield zero atoms
        // (the request has no recipients, no domains, etc.), NOT fall
        // back to the scalar path. Pin the empty-array → empty-Vec
        // contract here; a future refactor that conflated empty-array
        // with None would silently inject the bare template into
        // required_ops.
        let mut c = sample_ctx();
        c.body
            .insert("empty_list".into(), json!(Vec::<String>::new()));
        let got = c.lookup_list("body.empty_list");
        assert_eq!(got, Some(Vec::<String>::new()));
    }

    #[test]
    fn lookup_user_email_with_empty_string_returns_some_empty() {
        // `UserCtx::email` is `String` (not `Option<String>`); a
        // missing email defaults to "". Pin that `lookup("user.email")`
        // returns `Some("")` (not None) so policy authors who write
        // `user.email == ""` as a "no user" sentinel get the expected
        // match. A refactor to `Option<String>` would need to flip
        // this contract.
        let mut c = sample_ctx();
        c.user.email.clear();
        assert_eq!(c.lookup("user.email"), Some(String::new()));
    }

    #[test]
    fn lookup_customer_domain_carries_through_clone() {
        // The engine clones the context once per evaluation; pin
        // that customer_domain (the most-used template variable per
        // spec.md §9) survives a Clone. A `Cow<str>` refactor would
        // surface as a borrow-checker rewrite of the call site, not
        // a silent semantic shift, but pinning the trait still
        // catches a hand-written Clone impl that elided the field.
        let c = sample_ctx();
        let d = c.clone();
        assert_eq!(d.customer_domain, "acme.com");
        assert_eq!(d.lookup("customer_domain"), Some("acme.com".into()));
    }

    #[test]
    fn lookup_list_path_and_headers_always_none() {
        let c = sample_ctx();
        // The flat string maps are never list-valued.
        assert!(c.lookup_list("path.id").is_none());
        assert!(c.lookup_list("headers.x-trace-id").is_none());
    }

    #[test]
    fn request_context_default_yields_empty_state_for_engine_boot_path() {
        // `Default` is what `Engine::new("[]")` and embed-API test
        // fixtures call when no inbound request shape exists yet —
        // pin that every map is empty + every String is "". A
        // refactor that pre-seeded a sentinel customer_domain (e.g.
        // "example.com" "for tests") would silently bypass operator
        // template substitution checks and let a malformed policy
        // pass review.
        let c: RequestContext = RequestContext::default();
        assert_eq!(c.vendor, "");
        assert_eq!(c.action, "");
        assert_eq!(c.customer_domain, "");
        assert!(c.path.is_empty());
        assert!(c.body.is_empty());
        assert!(c.headers.is_empty());
        assert_eq!(c.user.email, "");
        assert!(c.user.groups.is_empty());
        // `lookup_list("body.anything")` on a Default context returns
        // None (no key present) — pin so the OpsExpression resolver's
        // empty-context fall-through stays deterministic.
        assert!(c.lookup_list("body.anything").is_none());
    }

    #[test]
    fn user_ctx_default_yields_empty_email_and_no_groups() {
        // Symmetric to the parent-struct Default pin — `UserCtx` is
        // also Default-constructible (operator embed tests build the
        // context piecewise). A future refactor that swapped `email`
        // to `Option<String>` would break this surface; a refactor
        // that pre-seeded a sentinel email like "anonymous@" would
        // silently route every Default-context evaluation through
        // any policy that matches that sentinel.
        let u: UserCtx = UserCtx::default();
        assert_eq!(u.email, "");
        assert!(u.groups.is_empty());
    }

    #[test]
    fn lookup_customer_domain_subfield_returns_none_not_short_circuit() {
        // The `customer_domain` bare-identifier branch lives BEFORE
        // the `split_once('.')` — pin that adding a dot disengages
        // the short-circuit (i.e. `customer_domain.foo` does NOT
        // return `acme.com`). A refactor that switched to
        // `starts_with("customer_domain")` would silently match
        // `customer_domain.org_id` and return the bare domain for
        // any sub-field path, breaking policies that rely on a
        // namespaced lookup miss.
        let c = sample_ctx();
        assert!(c.lookup("customer_domain.foo").is_none());
        // Symmetric: trailing-dot form (`customer_domain.`) also
        // disengages the short-circuit — `split_once` produces
        // `("customer_domain", "")` and the empty tail falls through
        // to the `_ => None` arm.
        assert!(c.lookup("customer_domain.").is_none());
    }

    #[test]
    fn lookup_list_body_with_missing_key_returns_none_distinct_from_non_array() {
        // Existing pins cover the non-array shape (body.score → None)
        // and the non-string-element shape (body.mixed → None), but
        // the MISSING-KEY shape (body.absent) was unpinned — the
        // distinct early-return via `self.body.get(tail)?`. A
        // refactor that swapped to `unwrap_or(&Value::Null)` for "be
        // permissive" would land on the `value.as_array()?` step
        // which would silently still return None for the same reason,
        // making the contract look unchanged — but the wire-trace
        // would drop the "missing key" log line that operator policy
        // authors rely on to debug a typo'd template. Pin the
        // missing-key path here distinctly.
        let c = sample_ctx();
        assert!(c.lookup_list("body.absent_key").is_none());
        // And a bare `body` head with no tail (no `.`) returns None
        // via the outer `split_once('.')?` — distinct from the
        // missing-key path above.
        assert!(c.lookup_list("body").is_none());
    }

    #[test]
    fn lookup_body_with_json_object_value_returns_json_repr_not_unquoted() {
        // The `body.X` arm's fallback is `value.as_str().unwrap_or_else(||
        // v.to_string())` — the `to_string()` for an Object renders
        // it as a JSON object literal (`{"k":"v"}`). Existing pins
        // cover the scalar fallback (number, boolean) but the
        // Object branch was unpinned. A refactor that switched the
        // fallback to `serde_json::to_string(&v).unwrap_or_default()`
        // would produce the same wire shape today but diverge if a
        // future value contained a non-UTF8 byte sequence (the latter
        // would error to "" instead of panic-on-render). Pin the
        // Object passthrough shape directly.
        let mut c = sample_ctx();
        c.body.insert("obj_field".into(), json!({"k": "v", "n": 7}));
        let got = c.lookup("body.obj_field").expect("present");
        // The exact JSON shape depends on serde_json's map ordering,
        // but the operator-facing contract is: contains the keys +
        // values + the braces.
        assert!(got.starts_with('{') && got.ends_with('}'), "got: {got}");
        assert!(got.contains("\"k\":\"v\""), "got: {got}");
        assert!(got.contains("\"n\":7"), "got: {got}");
    }

    #[test]
    fn request_context_serde_round_trip_preserves_every_map_and_field() {
        // `RequestContext` derives Serialize + Deserialize — the
        // embed API serializes a `RequestContext` over JSON for the
        // dashboard's "test policy" panel. Pin every field including
        // the three `HashMap` shapes (path / body / headers) and the
        // nested `UserCtx`. A refactor that switched `body` from
        // `HashMap<String, Value>` to a `BTreeMap` would change the
        // on-wire key order but preserve the round-trip semantic;
        // either is acceptable. The contract being pinned here is
        // CONTENT preservation, not order.
        let c = sample_ctx();
        let s = serde_json::to_string(&c).expect("serialize");
        let d: RequestContext = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(d.vendor, "google");
        assert_eq!(d.action, "drive.files.get");
        assert_eq!(d.customer_domain, "acme.com");
        assert_eq!(d.user.email, "alice@acme.com");
        assert_eq!(d.user.groups, vec!["eng".to_string(), "sec".to_string()]);
        assert_eq!(d.path.get("id").map(String::as_str), Some("fileA"));
        assert_eq!(
            d.headers.get("x-trace-id").map(String::as_str),
            Some("abc123"),
        );
        // Body map round-trips preserve every value shape.
        assert_eq!(d.body.get("subject"), Some(&json!("hi")));
        assert_eq!(
            d.body.get("to_domains"),
            Some(&json!(["example.com", "other.com"])),
        );
        assert_eq!(d.body.get("external_recipient"), Some(&json!(true)));
        assert_eq!(d.body.get("score"), Some(&json!(5)));
    }

    #[test]
    fn request_context_and_user_ctx_are_send_sync_static_for_axum_evaluate_with_trace_boundary() {
        // RequestContext is constructed per-adapter-request and passed
        // by reference to `Engine::evaluate_with_trace(&ctx)`; the
        // policy-engine's tokio task spawns rego evaluation across
        // .await points, requiring Send + Sync + 'static. The existing
        // module never pins these trait bounds — a refactor adding a
        // non-Send field (e.g. `Rc<HashMap<...>>` for cheap-clone path
        // dedup) would break Send and surface at a remote
        // `tower::Service` trait-bound rather than at this module.
        // Pin both struct types — symmetric to round-168 + round-169
        // + round-173 Send+Sync+'static pins extended to the policy
        // engine's input context.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<RequestContext>();
        require_send_sync_static::<UserCtx>();
    }

    #[test]
    fn request_context_body_field_is_hashmap_string_to_serde_json_value_for_template_lookup() {
        // The `body` field carries per-adapter exposed-to-policy fields
        // (default-deny per spec.md §5.4); the `lookup` + `lookup_list`
        // helpers walk it via `HashMap::get(tail)`. The existing pins
        // walk VALUES via `body.get("k") == Some(&json!(...))` but never
        // the TYPE-level contract. A refactor to `HashMap<String,
        // String>` "for stricter typing" would silently force callers
        // to allocate a Value at every body-field site AND would lose
        // the as_array branch in `lookup_list` (you can't get an array
        // from a String). Pin the exact field type via a generic fn —
        // symmetric to round-168 require_vec_string + round-172
        // require_string ownership-type pins extended to body field.
        fn require_hashmap_string_value(_: &HashMap<String, serde_json::Value>) {}
        let ctx = sample_ctx();
        require_hashmap_string_value(&ctx.body);
        // Symmetric: path + headers are HashMap<String, String> (NOT Value).
        fn require_hashmap_string_string(_: &HashMap<String, String>) {}
        require_hashmap_string_string(&ctx.path);
        require_hashmap_string_string(&ctx.headers);
    }

    #[test]
    fn lookup_list_is_referentially_transparent_across_fifty_repeated_calls_on_body_array_fixture()
    {
        // Symmetric to round-161 + round-162 + round-166 + round-168 +
        // round-169 + round-170 + round-171 + round-172 + round-173
        // referential-transparency pins extended to lookup_list. The
        // helper is invoked by `OpsExpression::resolve` per policy
        // evaluation; a refactor caching results in a once-cell keyed
        // on `&self as *const _` "for hot-path perf" would silently
        // return stale arrays on a re-evaluated context where body was
        // hot-swapped under a long-lived RequestContext (a future
        // body-rewrite middleware path the spec contemplates). Pin 50
        // calls byte-equal.
        let mut ctx = RequestContext::default();
        ctx.body
            .insert("to_domains".to_string(), json!(["a.com", "b.com", "c.com"]));
        let baseline = ctx
            .lookup_list("body.to_domains")
            .expect("fixture has 3 elems");
        assert_eq!(baseline.len(), 3);
        for i in 0..50 {
            let again = ctx.lookup_list("body.to_domains").expect("re-lookup");
            assert_eq!(
                again, baseline,
                "iteration {i}: lookup_list must be referentially transparent",
            );
        }
    }

    #[test]
    fn lookup_list_returns_owned_vec_string_type_via_require_vec_string_for_template_expansion() {
        // `OpsExpression::resolve` consumes the returned Vec by moving
        // each String into a fresh atom — the type MUST be `Vec<String>`
        // (owned per-element AND owned outer Vec). A refactor to
        // `Vec<&'a str>` "to avoid per-element allocation" would
        // surface a lifetime constraint that the resolve site
        // (which builds a transient context, calls lookup_list,
        // then drops the context before consuming the atoms in a
        // spawned eval task) couldn't satisfy. The existing pins
        // walk VALUES but never the TYPE-level contract — pin via
        // require_vec_string symmetric to round-168 parse_missing_atoms
        // + round-172 PcaView.ops owned-type pins extended to
        // lookup_list return.
        fn require_vec_string(_: &Vec<String>) {}
        let mut ctx = RequestContext::default();
        ctx.body.insert("xs".to_string(), json!(["a", "b"]));
        let v = ctx.lookup_list("body.xs").expect("fixture");
        require_vec_string(&v);
        // Per-element String (not &str).
        fn require_string(_: &String) {}
        require_string(&v[0]);
    }

    #[test]
    fn lookup_with_no_dot_separator_returns_none_except_for_bare_customer_domain_special_case() {
        // The dispatch on `dotted.split_once('.')?` early-returns None
        // for any single-token input EXCEPT the `customer_domain`
        // special case which is checked first (line 58 of the helper).
        // The existing module walks the bare-`customer_domain` path
        // but never the NEGATIVE polarity on sibling bare identifiers
        // ("vendor", "action", "path", "headers", "user"). A refactor
        // that lifted "vendor" or "action" to the bare-identifier
        // tier "for ergonomic policy templates" would silently expand
        // the special-case set and break every YAML that authors
        // `${vendor}` literally as a template key. Pin negative
        // polarity across 5 bare identifiers.
        let ctx = sample_ctx();
        // Positive control: customer_domain bare identifier IS resolved.
        assert_eq!(ctx.lookup("customer_domain").as_deref(), Some("acme.com"));
        // Negative sweep: every other bare identifier returns None.
        for bare in &["vendor", "action", "path", "headers", "user", "body"] {
            assert!(
                ctx.lookup(bare).is_none(),
                "bare identifier `{bare}` must NOT resolve (only customer_domain is bare)",
            );
        }
    }

    #[test]
    fn request_context_field_count_pinned_at_exactly_seven_via_exhaustive_destructure() {
        // Pin the RequestContext struct field count at exactly 7 via
        // exhaustive destructure with no `..` rest pattern. A 8th
        // field landing (e.g. `request_id: Uuid` for per-evaluation
        // attribution into structured logs, or `trace_id: Option<Uuid>`
        // for back-attribution from PolicyTrace to the inbound request)
        // would silently bloat every per-request adapter handoff on
        // the hot path AND silently change the existing
        // `request_context_serde_round_trip_preserves_every_map_and_field`
        // JSON wire shape. The serde test walks 7 named fields by
        // hand; exhaustive destructure catches a `#[serde(skip)]`
        // runtime-only 8th field bypass.
        let c = RequestContext::default();
        let RequestContext {
            vendor: _,
            action: _,
            user: _,
            path: _,
            body: _,
            headers: _,
            customer_domain: _,
        } = c;
    }

    #[test]
    fn user_ctx_field_count_pinned_at_exactly_two_via_exhaustive_destructure() {
        // Pin the UserCtx struct field count at exactly 2 via
        // exhaustive destructure with no `..` rest pattern. A 3rd
        // field landing (e.g. `name: String` for operator-facing
        // attribution in approver UI, or `id: Option<String>` for
        // stable user identity across email changes) would silently
        // bloat every per-request UserCtx clone AND silently change
        // the existing `user_ctx_default_yields_empty_email_and_no_groups`
        // contract surface. Pin via exhaustive destructure.
        let u = UserCtx::default();
        let UserCtx {
            email: _,
            groups: _,
        } = u;
    }

    #[test]
    fn request_context_lookup_signature_pinned_via_fn_pointer_witness() {
        // Pin RequestContext::lookup signature as
        // `fn(&RequestContext, &str) -> Option<String>` via fn-pointer
        // witness. A refactor that flipped the dotted-path arg from
        // `&str` to `String` ("for ownership clarity in cached
        // dispatch") would silently force every call site to allocate
        // a String per template variable per request, surfacing as a
        // fn-pointer type mismatch here rather than at the dozens of
        // OpsExpression resolve sites. The Option<String> return type
        // is also pinned — a refactor to `Option<Cow<'_, str>>` "to
        // avoid the clone on the bare customer_domain path" would
        // tie the return lifetime to &self and force lifetime
        // constraints at every substitute() call site.
        let _f: fn(&RequestContext, &str) -> Option<String> = RequestContext::lookup;
    }

    #[test]
    fn request_context_lookup_list_signature_pinned_via_fn_pointer_witness() {
        // Symmetric to lookup signature pin above. Pin
        // RequestContext::lookup_list as
        // `fn(&RequestContext, &str) -> Option<Vec<String>>` via
        // fn-pointer witness. The owned Vec<String> return is
        // load-bearing — `OpsExpression::resolve` consumes the Vec
        // by moving each String into a fresh atom on a tokio task
        // boundary that outlives the &self reference. A refactor to
        // `Option<&[String]>` "for zero-alloc list traversal" would
        // tie the return lifetime to &self and surface here as a
        // fn-pointer type mismatch rather than at the spawned-task
        // borrow-checker.
        let _f: fn(&RequestContext, &str) -> Option<Vec<String>> = RequestContext::lookup_list;
    }

    #[test]
    fn lookup_is_referentially_transparent_across_fifty_repeated_calls_on_body_string_fixture() {
        // Symmetric to `lookup_list_is_referentially_transparent` —
        // pin that `lookup` produces byte-equal output across 50
        // repeated calls on the same fixture. The helper is invoked
        // by `OpsExpression::substitute` once per `${var}` per
        // template per policy per request — a refactor that
        // memoized in a stale per-context cache (keyed on `&self as
        // *const _`) would silently return stale values on a
        // body-rewrite middleware path. Pin three distinct dispatch
        // paths: customer_domain (bare), path.id (path arm),
        // body.subject (body string arm).
        let c = sample_ctx();
        let baselines: Vec<(&str, Option<String>)> = vec![
            ("customer_domain", c.lookup("customer_domain")),
            ("path.id", c.lookup("path.id")),
            ("body.subject", c.lookup("body.subject")),
        ];
        for i in 0..50 {
            for (key, want) in &baselines {
                assert_eq!(
                    &c.lookup(key),
                    want,
                    "iter {i}: lookup({key}) must be referentially transparent",
                );
            }
        }
    }

    #[test]
    fn request_context_clone_is_independent_across_every_field_after_mutation() {
        // RequestContext derives Clone — the engine clones the
        // context per evaluation to avoid mutating the caller's
        // ownership. Pin that the Clone is a DEEP copy across every
        // field (a refactor to `Arc<HashMap<...>>` inner field "for
        // cheap-clone sharing" would silently alias the body Vec
        // back to the original, breaking the per-request snapshot
        // contract). Mutate every field on the clone and assert the
        // original is unchanged. The existing
        // `lookup_customer_domain_carries_through_clone` pin walks
        // ONE field; this walks all 7.
        let original = sample_ctx();
        let mut cloned = original.clone();
        cloned.vendor.push_str("-modified");
        cloned.action.push_str("-modified");
        cloned.customer_domain.push_str("-modified");
        cloned.user.email.push_str("-modified");
        cloned.user.groups.push("new-group".into());
        cloned.path.insert("new-key".into(), "new-val".into());
        cloned
            .body
            .insert("new-body-key".into(), serde_json::json!("new"));
        cloned
            .headers
            .insert("new-header".into(), "new-value".into());
        // Original unchanged across all 7 fields + nested UserCtx.
        assert_eq!(original.vendor, "google");
        assert_eq!(original.action, "drive.files.get");
        assert_eq!(original.customer_domain, "acme.com");
        assert_eq!(original.user.email, "alice@acme.com");
        assert_eq!(original.user.groups, vec!["eng".to_string(), "sec".into()]);
        assert!(!original.path.contains_key("new-key"));
        assert!(!original.body.contains_key("new-body-key"));
        assert!(!original.headers.contains_key("new-header"));
    }

    #[test]
    fn lookup_user_groups_returns_none_because_user_ctx_only_exposes_email_via_lookup_dispatch() {
        // UserCtx carries `groups: Vec<String>` but the `lookup`
        // dispatch on `user.*` only matches `email` (line 64-66 of
        // the helper). A refactor that added a `user.groups` arm "for
        // ergonomic group-based policy templates" would silently
        // change `${user.groups}` from None (current contract — the
        // template fails to resolve and the atom is dropped, per
        // spec.md §9 unresolved-template semantics) to Some(repr).
        // Pin None across `user.groups` AND any other user.* tail.
        // Operators currently work around this by using `lookup_list`
        // on `body.groups` (the adapter copies the relevant groups
        // into the body context); a silent change here would let two
        // policy paths produce different results.
        let mut ctx = sample_ctx();
        ctx.user.groups = vec!["eng".into(), "admin".into()];
        assert!(
            ctx.lookup("user.groups").is_none(),
            "user.groups must NOT resolve via scalar lookup",
        );
        // Other user.* tails also return None.
        assert!(ctx.lookup("user.id").is_none());
        assert!(ctx.lookup("user.name").is_none());
        // Symmetric: user.email IS resolved (positive control).
        assert_eq!(ctx.lookup("user.email").as_deref(), Some("alice@acme.com"));
    }
}
