//! Required-ops expression (Layer A cross-check).
//!
//! Each policy declares one or more `required_ops` templates like
//! `drive:read:file/${path.id}`. At evaluation time we substitute the
//! template variables against the `RequestContext` and produce an
//! `OpsExpression`. Adapters then verify the leaf PCA's ops set contains
//! every required atom (see Step 1.3 in spec.md).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::context::RequestContext;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsAtom {
    pub scheme: String,
    pub action: String,
    pub object: String,
}

impl OpsAtom {
    pub fn parse(s: &str) -> Result<Self, OpsParseError> {
        // Format: scheme:action:object   (object may itself contain `/` and `:`).
        let (scheme, rest) = s.split_once(':').ok_or(OpsParseError::Malformed)?;
        let (action, object) = rest.split_once(':').ok_or(OpsParseError::Malformed)?;
        if scheme.is_empty() || action.is_empty() || object.is_empty() {
            return Err(OpsParseError::Malformed);
        }
        Ok(Self {
            scheme: scheme.to_owned(),
            action: action.to_owned(),
            object: object.to_owned(),
        })
    }

    pub fn to_canonical(&self) -> String {
        format!("{}:{}:{}", self.scheme, self.action, self.object)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpsExpression {
    pub required: Vec<OpsAtom>,
}

#[derive(Debug, Error)]
pub enum OpsParseError {
    #[error("malformed ops atom (expected `scheme:action:object`)")]
    Malformed,
    #[error("template variable `{0}` not found in request context")]
    UnknownVar(String),
}

#[derive(Debug, Error)]
#[error("PCA chain is missing required ops: {missing:?}")]
pub struct MissingOps {
    pub missing: Vec<OpsAtom>,
}

impl OpsExpression {
    /// Resolve a single template into an atom by substituting `${...}` against `ctx`.
    pub fn resolve_one(template: &str, ctx: &RequestContext) -> Result<OpsAtom, OpsParseError> {
        let resolved = substitute(template, ctx)?;
        OpsAtom::parse(&resolved)
    }

    /// Resolve a list of templates. Each template produces one *or more*
    /// atoms: if exactly one `${var}` reference in the template resolves to a
    /// list-valued context lookup (`RequestContext::lookup_list`), the
    /// template is expanded once per list element. Templates referencing
    /// multiple list-valued vars are rejected with `OpsParseError::Malformed`
    /// (Cartesian-product expansion is out of scope; the recipient-domain use
    /// case in spec.md §2.1 needs only a single list var).
    pub fn resolve(templates: &[String], ctx: &RequestContext) -> Result<Self, OpsParseError> {
        let mut required = Vec::with_capacity(templates.len());
        for t in templates {
            required.extend(expand_template(t, ctx)?);
        }
        Ok(Self { required })
    }

    pub fn is_satisfied_by(&self, leaf_ops: &[OpsAtom]) -> Result<(), MissingOps> {
        let missing: Vec<OpsAtom> = self
            .required
            .iter()
            .filter(|need| !leaf_ops.iter().any(|have| have == *need))
            .cloned()
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(MissingOps { missing })
        }
    }
}

/// Expand a single template into one or more atoms, supporting at most one
/// list-valued substitution per template. See `OpsExpression::resolve`.
pub(crate) fn expand_template(
    template: &str,
    ctx: &RequestContext,
) -> Result<Vec<OpsAtom>, OpsParseError> {
    // Find every `${var}` reference. If exactly one resolves list-valued,
    // expand. Otherwise fall through to scalar substitution.
    let vars = collect_vars(template)?;
    let mut list_var: Option<(String, Vec<String>)> = None;
    for v in &vars {
        if let Some(list) = ctx.lookup_list(v) {
            if list_var.is_some() {
                // Two list-valued vars → ambiguous Cartesian product. Reject.
                return Err(OpsParseError::Malformed);
            }
            list_var = Some((v.clone(), list));
        }
    }
    match list_var {
        None => Ok(vec![OpsExpression::resolve_one(template, ctx)?]),
        Some((var, values)) => {
            let mut atoms = Vec::with_capacity(values.len());
            for v in values {
                // Substitute the list-var inline, then resolve the rest.
                let placeholder = format!("${{{var}}}");
                let staged = template.replace(&placeholder, &v);
                atoms.push(OpsExpression::resolve_one(&staged, ctx)?);
            }
            Ok(atoms)
        }
    }
}

fn collect_vars(template: &str) -> Result<Vec<String>, OpsParseError> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| OpsParseError::UnknownVar(after.to_owned()))?;
        out.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    Ok(out)
}

/// Substitute `${dotted.path}` references in `template` against `ctx`.
pub(crate) fn substitute(template: &str, ctx: &RequestContext) -> Result<String, OpsParseError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| OpsParseError::UnknownVar(after.to_owned()))?;
        let var = &after[..end];
        let value = ctx
            .lookup(var)
            .ok_or_else(|| OpsParseError::UnknownVar(var.to_owned()))?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RequestContext {
        let mut path = std::collections::HashMap::new();
        path.insert("id".to_string(), "abc123".to_string());
        RequestContext {
            vendor: "google".into(),
            action: "drive.files.get".into(),
            user: crate::context::UserCtx {
                email: "alice@acme.com".into(),
                groups: vec!["engineering".into()],
            },
            path,
            body: Default::default(),
            headers: Default::default(),
            customer_domain: "acme.com".into(),
        }
    }

    #[test]
    fn resolves_template() {
        let atom = OpsExpression::resolve_one("drive:read:file/${path.id}", &ctx()).unwrap();
        assert_eq!(atom.scheme, "drive");
        assert_eq!(atom.action, "read");
        assert_eq!(atom.object, "file/abc123");
    }

    #[test]
    fn unknown_var_errors() {
        let err =
            OpsExpression::resolve_one("drive:read:file/${path.missing}", &ctx()).unwrap_err();
        assert!(matches!(err, OpsParseError::UnknownVar(ref v) if v == "path.missing"));
    }

    #[test]
    fn list_valued_template_expands_to_n_atoms() {
        let mut body = std::collections::HashMap::new();
        body.insert(
            "to_domains".into(),
            serde_json::json!(["evil.example", "spam.example"]),
        );
        let mut c = ctx();
        c.body = body;
        let atoms = OpsExpression::resolve(
            &["gmail:send:${user.email}:to:${body.to_domains}".to_string()],
            &c,
        )
        .unwrap();
        assert_eq!(atoms.required.len(), 2);
        assert!(
            atoms
                .required
                .iter()
                .any(|a| a.object.contains("evil.example"))
        );
        assert!(
            atoms
                .required
                .iter()
                .any(|a| a.object.contains("spam.example"))
        );
    }

    #[test]
    fn scalar_template_still_resolves() {
        let exp =
            OpsExpression::resolve(&["drive:read:file/${path.id}".to_string()], &ctx()).unwrap();
        assert_eq!(exp.required.len(), 1);
        assert_eq!(exp.required[0].object, "file/abc123");
    }

    #[test]
    fn two_list_vars_rejected() {
        let mut body = std::collections::HashMap::new();
        body.insert("a".into(), serde_json::json!(["x", "y"]));
        body.insert("b".into(), serde_json::json!(["p", "q"]));
        let mut c = ctx();
        c.body = body;
        let err =
            OpsExpression::resolve(&["test:do:${body.a}:${body.b}".to_string()], &c).unwrap_err();
        assert!(matches!(err, OpsParseError::Malformed));
    }

    #[test]
    fn empty_list_yields_zero_atoms() {
        let mut body = std::collections::HashMap::new();
        body.insert("to_domains".into(), serde_json::json!([]));
        let mut c = ctx();
        c.body = body;
        let atoms = OpsExpression::resolve(
            &["gmail:send:${user.email}:to:${body.to_domains}".to_string()],
            &c,
        )
        .unwrap();
        assert!(atoms.required.is_empty());
    }

    #[test]
    fn ops_atom_parse_rejects_each_malformed_shape() {
        // Four distinct malformed shapes — each must surface
        // `OpsParseError::Malformed`. A future refactor that collapsed
        // the colon-counting + empty-segment checks into one would lose
        // the ability to test these independently.
        assert!(matches!(
            OpsAtom::parse("no-colon").unwrap_err(),
            OpsParseError::Malformed
        ));
        assert!(matches!(
            OpsAtom::parse("only:one-colon").unwrap_err(),
            OpsParseError::Malformed
        ));
        assert!(matches!(
            OpsAtom::parse(":missing:scheme").unwrap_err(),
            OpsParseError::Malformed
        ));
        assert!(matches!(
            OpsAtom::parse("scheme::missing-action").unwrap_err(),
            OpsParseError::Malformed
        ));
        assert!(matches!(
            OpsAtom::parse("scheme:action:").unwrap_err(),
            OpsParseError::Malformed
        ));
    }

    #[test]
    fn ops_atom_parse_keeps_extra_colons_and_slashes_in_object() {
        // Object is everything after the second colon — slashes and
        // additional colons are part of the identifier (the
        // `gmail:send:user@host:to:domain` shape used in templates needs
        // this). A regression that split on every colon would silently
        // truncate Gmail ops.
        let a = OpsAtom::parse("gmail:send:alice@acme.com:to:evil.example").unwrap();
        assert_eq!(a.scheme, "gmail");
        assert_eq!(a.action, "send");
        assert_eq!(a.object, "alice@acme.com:to:evil.example");
        let b = OpsAtom::parse("drive:read:file/abc/with/slashes").unwrap();
        assert_eq!(b.object, "file/abc/with/slashes");
    }

    #[test]
    fn ops_atom_to_canonical_round_trips_through_parse() {
        // `to_canonical()` is the inverse of `parse()` — the proxy uses
        // this round-trip to normalize PCA ops before chain comparison.
        // A drift in the format (e.g. URL-encoding the object) would
        // silently break leaf-ops matching.
        let original = "gmail:send:bob@external.com:to:external.com";
        let parsed = OpsAtom::parse(original).unwrap();
        assert_eq!(parsed.to_canonical(), original);
        // Symmetric: a hand-built atom round-trips too.
        let a = OpsAtom {
            scheme: "drive".into(),
            action: "read".into(),
            object: "file/x".into(),
        };
        let s = a.to_canonical();
        assert_eq!(OpsAtom::parse(&s).unwrap(), a);
    }

    #[test]
    fn ops_parse_error_display_strings_carry_operator_facing_hints() {
        // Both variants render a distinct operator-facing prefix the
        // troubleshooting docs key on; pin both.
        let m: OpsParseError = OpsParseError::Malformed;
        assert!(m.to_string().contains("scheme:action:object"));
        let u: OpsParseError = OpsParseError::UnknownVar("path.missing".into());
        assert!(u.to_string().contains("path.missing"));
        assert!(u.to_string().contains("template variable"));
    }

    #[test]
    fn missing_ops_display_surfaces_each_missing_atom() {
        // The adapter's 422 response body reads from `Display`; pin that
        // every missing atom appears in the rendered string so operators
        // can diagnose chain-walker faults without parsing `Debug`.
        let err = MissingOps {
            missing: vec![
                OpsAtom::parse("drive:read:file/xyz").unwrap(),
                OpsAtom::parse("drive:read:file/abc").unwrap(),
            ],
        };
        let s = err.to_string();
        assert!(s.contains("file/xyz"), "{s}");
        assert!(s.contains("file/abc"), "{s}");
        assert!(s.contains("missing"), "{s}");
    }

    #[test]
    fn is_satisfied_by_empty_required_is_ok_against_any_leaf() {
        // A policy with empty `required_ops` always passes Layer-A —
        // common for vendor.action pairs that are policy-gated only on
        // Layer-B (e.g. block-by-rule). A regression that errored on
        // empty would mass-deny these.
        let exp = OpsExpression::default();
        assert!(exp.is_satisfied_by(&[]).is_ok());
        assert!(
            exp.is_satisfied_by(&[OpsAtom::parse("drive:read:file/x").unwrap()])
                .is_ok()
        );
    }

    #[test]
    fn collect_vars_returns_each_var_in_left_to_right_order() {
        // `expand_template` iterates `vars` to find the list-valued one;
        // order isn't load-bearing today but the doc-comment commits to
        // left-to-right discovery and a future refactor to a HashSet
        // would silently lose the order (and the ability to surface the
        // *first* offending var in a Cartesian-product error).
        let vars = collect_vars("${a}:${body.b}:${user.email}").unwrap();
        assert_eq!(vars, vec!["a", "body.b", "user.email"]);
        // No vars in a literal template → empty.
        assert!(collect_vars("plain:literal:token").unwrap().is_empty());
    }

    #[test]
    fn substitute_passes_literal_through_and_rejects_unclosed_var() {
        // Literal template with no `${...}` survives byte-exact.
        let out = substitute("plain:literal", &ctx()).unwrap();
        assert_eq!(out, "plain:literal");
        // Unclosed `${...` errors with the remainder as the var name —
        // operator-facing, so they can spot the missing brace.
        let err = substitute("drive:read:${path.id", &ctx()).unwrap_err();
        assert!(matches!(err, OpsParseError::UnknownVar(ref v) if v.starts_with("path.id")));
    }

    #[test]
    fn missing_ops_lists_atoms() {
        let exp = OpsExpression {
            required: vec![
                OpsAtom::parse("drive:read:file/abc123").unwrap(),
                OpsAtom::parse("drive:read:file/xyz").unwrap(),
            ],
        };
        let leaf = vec![OpsAtom::parse("drive:read:file/abc123").unwrap()];
        let err = exp.is_satisfied_by(&leaf).unwrap_err();
        assert_eq!(err.missing.len(), 1);
        assert_eq!(err.missing[0].object, "file/xyz");
    }
}
