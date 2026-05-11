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
            "body" => self
                .body
                .get(tail)
                .map(|v| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string())),
            "headers" => self.headers.get(tail).cloned(),
            _ => None,
        }
    }
}
