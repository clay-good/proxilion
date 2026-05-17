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
}
