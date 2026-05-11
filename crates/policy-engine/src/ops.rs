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

    /// Resolve a list of templates.
    pub fn resolve(templates: &[String], ctx: &RequestContext) -> Result<Self, OpsParseError> {
        let mut required = Vec::with_capacity(templates.len());
        for t in templates {
            required.push(Self::resolve_one(t, ctx)?);
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
