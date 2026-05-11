//! Match-expression interpreter.
//!
//! Implements the operator vocabulary listed in spec.md §0.3:
//!   in, not_in, equals, not_equals, matches, greater_than, less_than,
//!   all, any, not, exists.
//!
//! Match expressions are authored in YAML and evaluated against a
//! `RequestContext`. We do *not* transpile to Rego here — a direct interpreter
//! is sufficient for the request-rate policy load and keeps the build slim.
//! A Rego backend can be slotted in behind the same `evaluate` API later.

use serde_yaml::Value as Yaml;
use thiserror::Error;

use crate::context::RequestContext;
use crate::ops::substitute;

#[derive(Debug, Error)]
pub enum MatchError {
    #[error("unsupported operator `{0}`")]
    UnsupportedOp(String),
    #[error("operator `{op}` expects {expected}, got {got}")]
    BadShape {
        op: String,
        expected: &'static str,
        got: String,
    },
    #[error("template error: {0}")]
    Template(#[from] crate::ops::OpsParseError),
}

/// Evaluate a YAML match expression against `ctx`.
///
/// Empty / null match matches everything (true).
pub fn evaluate(expr: &Yaml, ctx: &RequestContext) -> Result<bool, MatchError> {
    if expr.is_null() {
        return Ok(true);
    }
    let map = match expr.as_mapping() {
        Some(m) => m,
        None => {
            return Err(MatchError::BadShape {
                op: "<match>".into(),
                expected: "mapping",
                got: type_name(expr),
            });
        }
    };

    // Top-level mapping: AND of all entries.
    for (k, v) in map {
        let key = k.as_str().ok_or_else(|| MatchError::BadShape {
            op: "<match>".into(),
            expected: "string key",
            got: type_name(k),
        })?;
        if !eval_entry(key, v, ctx)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn eval_entry(key: &str, val: &Yaml, ctx: &RequestContext) -> Result<bool, MatchError> {
    match key {
        "all" => seq_each(val, "all", ctx, |b, acc| acc && b, true),
        "any" => seq_each(val, "any", ctx, |b, acc| acc || b, false),
        "not" => Ok(!evaluate(val, ctx)?),
        "exists" => {
            let var = val.as_str().ok_or_else(|| MatchError::BadShape {
                op: "exists".into(),
                expected: "string",
                got: type_name(val),
            })?;
            Ok(ctx.lookup(var).is_some())
        }
        // Otherwise: `key` is a field selector, `val` is `{ op: operand }`.
        field => eval_field(field, val, ctx),
    }
}

fn seq_each<F>(
    val: &Yaml,
    op: &str,
    ctx: &RequestContext,
    fold: F,
    init: bool,
) -> Result<bool, MatchError>
where
    F: Fn(bool, bool) -> bool,
{
    let seq = val.as_sequence().ok_or_else(|| MatchError::BadShape {
        op: op.to_string(),
        expected: "sequence",
        got: type_name(val),
    })?;
    let mut acc = init;
    for child in seq {
        acc = fold(evaluate(child, ctx)?, acc);
    }
    Ok(acc)
}

fn eval_field(field: &str, val: &Yaml, ctx: &RequestContext) -> Result<bool, MatchError> {
    let map = val.as_mapping().ok_or_else(|| MatchError::BadShape {
        op: field.to_string(),
        expected: "operator mapping",
        got: type_name(val),
    })?;
    let lhs = ctx.lookup(field);

    for (k, v) in map {
        let op = k.as_str().ok_or_else(|| MatchError::BadShape {
            op: "<op>".into(),
            expected: "string",
            got: type_name(k),
        })?;
        if !apply_op(op, lhs.as_deref(), v, ctx)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn apply_op(
    op: &str,
    lhs: Option<&str>,
    rhs: &Yaml,
    ctx: &RequestContext,
) -> Result<bool, MatchError> {
    match op {
        "equals" => Ok(lhs == as_str_subst(rhs, ctx)?.as_deref()),
        "not_equals" => Ok(lhs != as_str_subst(rhs, ctx)?.as_deref()),
        "in" => {
            let xs = as_str_seq(rhs, "in", ctx)?;
            Ok(lhs.map(|v| xs.iter().any(|x| x == v)).unwrap_or(false))
        }
        "not_in" => {
            let xs = as_str_seq(rhs, "not_in", ctx)?;
            Ok(lhs.map(|v| !xs.iter().any(|x| x == v)).unwrap_or(true))
        }
        "matches" => {
            let pat = as_str_subst(rhs, ctx)?.ok_or_else(|| MatchError::BadShape {
                op: "matches".into(),
                expected: "string",
                got: type_name(rhs),
            })?;
            let re = regex::Regex::new(&pat).map_err(|_| MatchError::BadShape {
                op: "matches".into(),
                expected: "valid regex",
                got: pat.clone(),
            })?;
            Ok(lhs.map(|v| re.is_match(v)).unwrap_or(false))
        }
        "greater_than" | "less_than" => {
            let a = lhs.and_then(|v| v.parse::<f64>().ok());
            let b = rhs.as_f64().or_else(|| rhs.as_i64().map(|i| i as f64));
            match (a, b) {
                (Some(a), Some(b)) => Ok(if op == "greater_than" { a > b } else { a < b }),
                _ => Ok(false),
            }
        }
        other => Err(MatchError::UnsupportedOp(other.to_owned())),
    }
}

fn as_str_subst(v: &Yaml, ctx: &RequestContext) -> Result<Option<String>, MatchError> {
    match v {
        Yaml::String(s) => Ok(Some(substitute(s, ctx)?)),
        Yaml::Number(n) => Ok(Some(n.to_string())),
        Yaml::Bool(b) => Ok(Some(b.to_string())),
        Yaml::Null => Ok(None),
        other => Err(MatchError::BadShape {
            op: "<rhs>".into(),
            expected: "scalar",
            got: type_name(other),
        }),
    }
}

fn as_str_seq(v: &Yaml, op: &str, ctx: &RequestContext) -> Result<Vec<String>, MatchError> {
    let seq = v.as_sequence().ok_or_else(|| MatchError::BadShape {
        op: op.to_string(),
        expected: "sequence",
        got: type_name(v),
    })?;
    seq.iter()
        .map(|x| {
            as_str_subst(x, ctx)?.ok_or_else(|| MatchError::BadShape {
                op: op.to_string(),
                expected: "scalar element",
                got: "null".into(),
            })
        })
        .collect()
}

fn type_name(v: &Yaml) -> String {
    match v {
        Yaml::Null => "null",
        Yaml::Bool(_) => "bool",
        Yaml::Number(_) => "number",
        Yaml::String(_) => "string",
        Yaml::Sequence(_) => "sequence",
        Yaml::Mapping(_) => "mapping",
        Yaml::Tagged(_) => "tagged",
    }
    .to_string()
}
