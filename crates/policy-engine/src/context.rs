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
}
