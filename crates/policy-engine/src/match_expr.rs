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

#[cfg(test)]
mod tests {
    //! Unit tests for the match-expression interpreter — the operator
    //! vocabulary from spec.md §0.3. Each operator branch in
    //! `apply_op` plus the combinator paths (`all`, `any`, `not`,
    //! `exists`) gets at least one happy-path and one boundary test.
    //! Adapter-level integration with the engine is covered separately
    //! in `tests/example_policies.rs`; here we exercise the
    //! interpreter in isolation.
    use super::*;
    use crate::context::{RequestContext, UserCtx};
    use std::collections::HashMap;

    fn ctx() -> RequestContext {
        let mut path = HashMap::new();
        path.insert("id".into(), "abc123".into());
        let mut headers = HashMap::new();
        headers.insert("x-tenant".into(), "acme".into());
        let mut body = HashMap::new();
        body.insert(
            "to_domains".into(),
            serde_json::json!(["evil.example", "spam.example"]),
        );
        body.insert("recipient_count".into(), serde_json::json!(7));
        body.insert("external_recipient".into(), serde_json::json!(true));
        RequestContext {
            vendor: "google".into(),
            action: "gmail.messages.send".into(),
            user: UserCtx {
                email: "alice@acme.com".into(),
                groups: vec!["engineering".into(), "secops".into()],
            },
            path,
            body,
            headers,
            customer_domain: "acme.com".into(),
        }
    }

    fn parse(yaml: &str) -> Yaml {
        serde_yaml::from_str(yaml).expect("test yaml parses")
    }

    // --- null / empty match ---------------------------------------

    #[test]
    fn null_expr_matches_anything() {
        let y = Yaml::Null;
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn empty_mapping_matches_anything() {
        let y = parse("{}");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    // --- equals / not_equals --------------------------------------

    #[test]
    fn equals_matches_user_email() {
        let y = parse("user.email: { equals: alice@acme.com }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn equals_rejects_mismatch() {
        let y = parse("user.email: { equals: bob@acme.com }");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn not_equals_inverts() {
        let y = parse("user.email: { not_equals: bob@acme.com }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn equals_resolves_template_in_rhs() {
        // `${user.email}` substitutes against ctx; matching against
        // itself trivially passes — proves the substitution wires.
        let y = parse("user.email: { equals: \"${user.email}\" }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn equals_on_bool_value_renders_via_string() {
        // body.external_recipient is bool true; rhs `true` is bool;
        // match-engine renders RHS via `as_str_subst` so the lhs
        // string-form ("true") needs to equal the rendered rhs.
        let y = parse("body.external_recipient: { equals: true }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    // --- in / not_in ----------------------------------------------

    #[test]
    fn in_matches_when_lhs_in_list() {
        let y = parse("user.email: { in: [alice@acme.com, bob@acme.com] }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn in_misses_when_lhs_absent() {
        let y = parse("user.email: { in: [bob@acme.com] }");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn not_in_matches_when_lhs_absent() {
        let y = parse("user.email: { not_in: [bob@acme.com] }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn not_in_misses_when_lhs_present() {
        let y = parse("user.email: { not_in: [alice@acme.com] }");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    /// `not_in` against a missing field returns true — "field not in
    /// list" is vacuously satisfied when the field doesn't exist.
    /// Documents the asymmetry vs `in` (which returns false).
    #[test]
    fn missing_field_in_returns_false() {
        let y = parse("body.nonexistent: { in: [x, y] }");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn missing_field_not_in_returns_true() {
        let y = parse("body.nonexistent: { not_in: [x, y] }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    // --- matches (regex) ------------------------------------------

    #[test]
    fn matches_accepts_regex_hit() {
        let y = parse("user.email: { matches: \"^alice@\" }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn matches_rejects_regex_miss() {
        let y = parse("user.email: { matches: \"^bob@\" }");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn matches_with_invalid_regex_errors() {
        let y = parse("user.email: { matches: \"[unclosed\" }");
        let err = evaluate(&y, &ctx()).unwrap_err();
        assert!(matches!(err, MatchError::BadShape { ref op, .. } if op == "matches"));
    }

    // --- greater_than / less_than ---------------------------------

    #[test]
    fn greater_than_compares_numerically() {
        let y = parse("body.recipient_count: { greater_than: 5 }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn less_than_compares_numerically() {
        let y = parse("body.recipient_count: { less_than: 10 }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn greater_than_non_numeric_lhs_returns_false() {
        // user.email isn't parseable as f64 — comparison returns false
        // rather than erroring (graceful degradation per
        // apply_op's `_ => Ok(false)` fall-through).
        let y = parse("user.email: { greater_than: 5 }");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    // --- all / any / not / exists ---------------------------------

    #[test]
    fn all_requires_every_child_true() {
        let y = parse(
            r#"
all:
  - user.email: { equals: alice@acme.com }
  - body.recipient_count: { greater_than: 1 }
"#,
        );
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn all_fails_on_any_child_false() {
        let y = parse(
            r#"
all:
  - user.email: { equals: alice@acme.com }
  - body.recipient_count: { greater_than: 100 }
"#,
        );
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn any_passes_when_one_child_true() {
        let y = parse(
            r#"
any:
  - user.email: { equals: bob@acme.com }
  - user.email: { equals: alice@acme.com }
"#,
        );
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn any_fails_when_all_children_false() {
        let y = parse(
            r#"
any:
  - user.email: { equals: bob@acme.com }
  - user.email: { equals: carol@acme.com }
"#,
        );
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn not_inverts_inner_result() {
        let y = parse("not: { user.email: { equals: bob@acme.com } }");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn exists_matches_when_field_present() {
        let y = parse("exists: user.email");
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn exists_misses_when_field_absent() {
        let y = parse("exists: body.nonexistent");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    // --- top-level AND semantics ----------------------------------

    /// Top-level mapping is AND of every key. Two clauses, both true →
    /// match passes.
    #[test]
    fn top_level_and_matches_when_all_clauses_match() {
        let y = parse(
            r#"
user.email: { equals: alice@acme.com }
body.external_recipient: { equals: true }
"#,
        );
        assert!(evaluate(&y, &ctx()).unwrap());
    }

    /// Two clauses, second false → match fails (short-circuit
    /// behavior verified indirectly via failure).
    #[test]
    fn top_level_and_fails_when_any_clause_misses() {
        let y = parse(
            r#"
user.email: { equals: alice@acme.com }
body.external_recipient: { equals: false }
"#,
        );
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    // --- shape / error paths --------------------------------------

    #[test]
    fn top_level_non_mapping_errors() {
        let y = parse("[a, b]");
        let err = evaluate(&y, &ctx()).unwrap_err();
        assert!(matches!(err, MatchError::BadShape { .. }));
    }

    #[test]
    fn unsupported_operator_errors() {
        let y = parse("user.email: { weird_op: foo }");
        let err = evaluate(&y, &ctx()).unwrap_err();
        assert!(matches!(err, MatchError::UnsupportedOp(ref op) if op == "weird_op"));
    }

    #[test]
    fn field_value_not_mapping_errors() {
        // `user.email: alice@acme.com` (scalar instead of operator map)
        // is rejected — encourages the explicit `{ equals: ... }`
        // shape and prevents accidental shortcuts that bypass the
        // type-checking apparatus.
        let y = parse("user.email: alice@acme.com");
        let err = evaluate(&y, &ctx()).unwrap_err();
        assert!(matches!(err, MatchError::BadShape { ref op, .. } if op == "user.email"));
    }

    #[test]
    fn all_non_sequence_errors() {
        let y = parse("all: foo");
        let err = evaluate(&y, &ctx()).unwrap_err();
        assert!(matches!(err, MatchError::BadShape { ref op, .. } if op == "all"));
    }

    #[test]
    fn exists_non_string_errors() {
        let y = parse("exists: [a, b]");
        let err = evaluate(&y, &ctx()).unwrap_err();
        assert!(matches!(err, MatchError::BadShape { ref op, .. } if op == "exists"));
    }

    // --- private-helper pure pins ---------------------------------

    #[test]
    fn as_str_subst_renders_yaml_null_as_ok_none() {
        // The Null arm returns `Ok(None)` — load-bearing for the
        // equals/not_equals arms, which compare `lhs == None` to detect
        // "missing field" without panicking. A regression that collapsed
        // Null into `Ok(Some("".into()))` would silently make every
        // missing-field equals-null comparison fire as a match against
        // the empty string, breaking the `field IS NULL`-style policy
        // shape. Pinned directly because the existing
        // `equals_on_bool_value_renders_via_string` test only covers
        // Bool/Number; Null was untested.
        let out = as_str_subst(&Yaml::Null, &ctx()).expect("Null is a valid scalar");
        assert!(out.is_none(), "Null must surface as None, not Some(\"\")");
    }

    #[test]
    fn as_str_subst_renders_yaml_number_and_bool_as_their_string_forms() {
        // The Number arm uses `n.to_string()`, the Bool arm uses
        // `b.to_string()`. The `equals_on_bool_value_renders_via_string`
        // test only covers the wired-through-evaluate path; pin the
        // helper outputs directly so a refactor that switched to
        // `format!("{n:?}")` (which would render integers with a
        // trailing `.0`) surfaces here as the wire-shape change rather
        // than as flaky policy matches across operator-authored YAML.
        let n = serde_yaml::from_str::<Yaml>("42").unwrap();
        assert_eq!(
            as_str_subst(&n, &ctx()).unwrap().as_deref(),
            Some("42"),
            "integer Number must render without a trailing .0",
        );
        let b = serde_yaml::from_str::<Yaml>("true").unwrap();
        assert_eq!(as_str_subst(&b, &ctx()).unwrap().as_deref(), Some("true"));
        let f = serde_yaml::from_str::<Yaml>("false").unwrap();
        assert_eq!(as_str_subst(&f, &ctx()).unwrap().as_deref(), Some("false"));
    }

    #[test]
    fn greater_than_with_float_rhs_round_trips_through_as_f64() {
        // The rhs is read via `rhs.as_f64().or_else(|| rhs.as_i64()...)`.
        // The integer branch is covered by the existing
        // `greater_than_compares_numerically` test (rhs: 5); the float
        // branch was unpinned despite YAML floats being a natural shape
        // for thresholds operators write as decimals (e.g. "spam_score:
        // greater_than: 0.95"). A regression that dropped the as_f64
        // primary path and relied on as_i64 alone would silently make
        // every decimal threshold round to zero and fire on every value.
        let y = parse("body.recipient_count: { greater_than: 6.5 }");
        assert!(evaluate(&y, &ctx()).unwrap(), "7 > 6.5 must be true");
        let y2 = parse("body.recipient_count: { greater_than: 7.5 }");
        assert!(!evaluate(&y2, &ctx()).unwrap(), "7 > 7.5 must be false");
    }

    #[test]
    fn less_than_with_non_numeric_lhs_returns_false_gracefully() {
        // Symmetric pin to `greater_than_non_numeric_lhs_returns_false`.
        // The fall-through `_ => Ok(false)` arm in apply_op covers both
        // less_than and greater_than but the test pin only existed for
        // greater_than — a refactor that special-cased less_than alone
        // (e.g. to error rather than silently return false) would slip
        // past unless this branch is independently pinned.
        let y = parse("user.email: { less_than: 5 }");
        assert!(!evaluate(&y, &ctx()).unwrap());
    }

    #[test]
    fn type_name_distinguishes_every_yaml_variant_via_explicit_input() {
        // `type_name` produces the operator-facing `got:` substring on
        // every BadShape error — operator log filters and docs page key
        // on the exact strings (`null` / `bool` / `number` / `string` /
        // `sequence` / `mapping`). The string set has been exercised
        // indirectly via the BadShape paths but never with one
        // assertion per variant in the same test. A regression that
        // pluralized one (`sequences`) or capitalized (`Mapping`) would
        // silently break docs cross-references; pin the full set here.
        assert_eq!(type_name(&Yaml::Null), "null");
        assert_eq!(
            type_name(&serde_yaml::from_str::<Yaml>("true").unwrap()),
            "bool",
        );
        assert_eq!(
            type_name(&serde_yaml::from_str::<Yaml>("3").unwrap()),
            "number",
        );
        assert_eq!(
            type_name(&serde_yaml::from_str::<Yaml>("'x'").unwrap()),
            "string",
        );
        assert_eq!(
            type_name(&serde_yaml::from_str::<Yaml>("[1, 2]").unwrap()),
            "sequence",
        );
        assert_eq!(
            type_name(&serde_yaml::from_str::<Yaml>("{a: 1}").unwrap()),
            "mapping",
        );
    }

    #[test]
    fn as_str_seq_rejects_non_sequence_rhs_with_bad_shape_and_op_label() {
        // `as_str_seq` errors with BadShape when rhs isn't a sequence —
        // operator-facing surface for malformed `in: 5` / `in: "x"`.
        // The op-label round-trips so the operator sees which clause
        // tripped. Pinned because the public tests only exercise the
        // happy path via in/not_in lookups.
        let scalar = serde_yaml::from_str::<Yaml>("5").unwrap();
        let err = as_str_seq(&scalar, "in", &ctx()).unwrap_err();
        match err {
            MatchError::BadShape { op, expected, got } => {
                assert_eq!(op, "in", "op label must round-trip from caller");
                assert_eq!(expected, "sequence");
                assert_eq!(got, "number");
            }
            other => panic!("expected BadShape, got {other:?}"),
        }
        // not_in label also round-trips (sibling caller).
        let s = serde_yaml::from_str::<Yaml>("'literal'").unwrap();
        let err = as_str_seq(&s, "not_in", &ctx()).unwrap_err();
        assert!(matches!(err, MatchError::BadShape { ref op, .. } if op == "not_in"));
    }

    #[test]
    fn match_error_unsupported_op_display_carries_backticked_operator() {
        // `#[error("unsupported operator `{0}`")]` — the backticks
        // around `{0}` are load-bearing: operator-facing log filters
        // and runbook examples key on the exact substring
        // ``unsupported operator `foo` `` to bucket "operator typo"
        // (e.g. `equls` instead of `equals`) separately from
        // `BadShape` faults (which use the prefix `"operator `..`
        // expects ..."`). A refactor that dropped the backticks for
        // "consistency with the other variants" would silently merge
        // the buckets — both would then start with `"operator "` and
        // a Loki filter on `operator \``…`\`` would lose precision.
        let e = MatchError::UnsupportedOp("weird_op".into());
        assert_eq!(e.to_string(), "unsupported operator `weird_op`");
    }

    #[test]
    fn match_error_bad_shape_display_renders_all_three_named_fields_in_order() {
        // `#[error("operator `{op}` expects {expected}, got {got}")]`
        // — the three named-field substitutions are emitted in the
        // operator/expected/got order matching the struct's field
        // declaration order. The dashboard's "policy authoring
        // errors" panel renders the Display verbatim; a refactor
        // that flipped to `expected/got/op` ordering "for grammar"
        // would silently break operator scripts that grep the suffix
        // for the actual-vs-expected type pair. Pin the full shape
        // with three distinct values so any ordering swap fails loud.
        let e = MatchError::BadShape {
            op: "in".into(),
            expected: "sequence",
            got: "number".into(),
        };
        assert_eq!(e.to_string(), "operator `in` expects sequence, got number");
    }

    #[test]
    fn match_error_bad_shape_display_static_str_expected_field_supports_typical_descriptors() {
        // The `expected` field is typed `&'static str` — pin the
        // shape across a small range of descriptors actually used
        // by the call sites (`"sequence"`, `"string"`, `"mapping"`)
        // so a refactor to `String` (the natural "consistency with
        // op and got" mistake) would surface as a compile error at
        // every construction site rather than as a silent allocation
        // per error. The `&'static str` type is also load-bearing
        // for the BadShape variant being cheap-clone for retry-tracing.
        for expected in ["sequence", "string", "mapping", "scalar"] {
            let e = MatchError::BadShape {
                op: "matches".into(),
                expected,
                got: "null".into(),
            };
            let s = e.to_string();
            assert!(s.contains(expected), "expected `{expected}` in: {s}");
            assert!(s.starts_with("operator `matches` expects "), "got: {s}");
            assert!(s.ends_with(", got null"), "got: {s}");
        }
    }

    #[test]
    fn match_error_template_display_carries_template_error_prefix_with_inner_passthrough() {
        // `#[error("template error: {0}")]` on `Template(#[from] OpsParseError)`
        // — distinct from the `"policy ops template: "` prefix that
        // `proxy::adapters::error::AppError::OpsTemplate` uses, even
        // though both wrap the SAME `OpsParseError` type. The two
        // prefixes are intentionally different layers (engine-side
        // vs adapter-side) so an operator runbook can grep
        // `"template error:"` for inline match-expr template faults
        // separately from `"policy ops template:"` for required_ops
        // template faults. A "harmonize the prefix across layers"
        // refactor would silently merge the two and force the
        // operator to re-walk the structured trace. Pin the prefix
        // AND the inner OpsParseError Display passthrough so
        // cross-module drift surfaces.
        let inner = crate::ops::OpsParseError::UnknownVar("ctx.missing".into());
        let e: MatchError = MatchError::from(inner);
        let s = e.to_string();
        assert!(s.starts_with("template error: "), "got: {s}");
        assert!(s.contains("ctx.missing"), "got: {s}");
    }

    #[test]
    fn match_error_bad_shape_display_op_field_supports_dotted_field_paths() {
        // The `op` field is typed `String` so it accepts both bare
        // operator names (`"in"`, `"matches"`) and dotted field
        // paths (`"user.email"`, `"resource.attributes.size"`) when
        // a top-level field-key surfaces in the BadShape. The
        // existing tests pin the bare-operator shape via `"in"` /
        // `"not_in"`; pin the dotted path so a refactor that
        // canonicalized `op` to the last segment (the natural
        // "strip the prefix for display brevity" mistake) would
        // silently drop the path context operators rely on to
        // locate the offending policy clause.
        let e = MatchError::BadShape {
            op: "user.contact.email".into(),
            expected: "mapping",
            got: "string".into(),
        };
        assert_eq!(
            e.to_string(),
            "operator `user.contact.email` expects mapping, got string",
        );
    }

    #[test]
    fn match_error_implements_std_error_trait_for_source_chain_walking() {
        // `Template(#[from] OpsParseError)` — `thiserror`'s `#[from]`
        // wires both the `From` conversion AND the `std::error::Error::source()`
        // chain so anyhow-style walkers can recover the inner
        // `OpsParseError` without parsing the Display string. Pin
        // that `source()` surfaces a non-None for the `Template` arm
        // and None for the other two arms (UnsupportedOp / BadShape
        // are leaf errors with no inner source). A refactor to a
        // hand-rolled `From` impl that didn't wire `source()` would
        // surface here — the chain-walker behavior is what makes the
        // adapter-side error chain in `AppError::OpsTemplate` work.
        use std::error::Error as _;
        let leaf_unsupported = MatchError::UnsupportedOp("x".into());
        assert!(
            leaf_unsupported.source().is_none(),
            "UnsupportedOp is a leaf — no inner source",
        );
        let leaf_bad_shape = MatchError::BadShape {
            op: "in".into(),
            expected: "sequence",
            got: "number".into(),
        };
        assert!(
            leaf_bad_shape.source().is_none(),
            "BadShape is a leaf — no inner source",
        );
        let chained: MatchError = crate::ops::OpsParseError::UnknownVar("ctx.x".into()).into();
        let src = chained.source().expect("Template wraps an inner source");
        // The inner source is the OpsParseError — its Display must
        // pass through the same substring as the wrapper's Display.
        assert!(src.to_string().contains("ctx.x"), "got: {}", src);
    }

    // ─── round 180 (2026-05-20): MatchError + evaluate operator-actionable surfaces ───

    #[test]
    fn match_error_is_send_sync_static_for_axum_evaluate_boundary() {
        // `MatchError` propagates up through `rego::Error::Match` and
        // then through `AppError::Policy` across the `.await`
        // boundary in the axum request handler before flowing into
        // the tokio::spawn'd audit-sink task. ALL three traits
        // (Send + Sync + 'static) are load-bearing for those call
        // sites — a refactor that gave `BadShape` a `Cell<u8>` field
        // "for an in-process unique-shape counter" would silently
        // break Sync at this boundary. Symmetric to round-176 +
        // round-177 + round-179 Send+Sync+'static pins extended to
        // the match-expression error type.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<MatchError>();
    }

    #[test]
    fn evaluate_is_referentially_transparent_across_fifty_repeated_calls() {
        // The hot path calls `evaluate(expr, &ctx)` once per policy
        // per request — the result MUST depend only on `(expr, ctx)`,
        // never on hidden per-call state (a once-cell match-result
        // LRU, a per-eval counter, a regex-compile cache that aliased
        // across calls). Pin referential transparency across 50
        // back-to-back calls on a multi-clause expression that
        // exercises both top-level AND (`user.email` + `body.size`)
        // and a nested `in:` operator. A refactor that introduced
        // a stateful between-call cache would surface here as a
        // divergence on call #2..#50. Symmetric to round-179
        // engine_evaluate referential-transparency pin one layer up.
        let expr: Yaml = serde_yaml::from_str(
            "\
user.email:
  equals: alice@acme.test
body.tier:
  in:
    - gold
    - silver
",
        )
        .unwrap();
        let mut ctx = RequestContext {
            vendor: "v".into(),
            action: "a".into(),
            customer_domain: "acme.test".into(),
            ..Default::default()
        };
        ctx.user.email = "alice@acme.test".into();
        ctx.body
            .insert("tier".into(), serde_json::Value::String("gold".into()));
        let first = evaluate(&expr, &ctx).unwrap();
        assert!(first, "fixture must match — sanity");
        for i in 1..50 {
            let next = evaluate(&expr, &ctx).unwrap();
            assert_eq!(next, first, "diverged on call #{i}");
        }
    }

    #[test]
    fn evaluate_with_null_yaml_matches_irrespective_of_ctx_contents() {
        // The doc-comment on `evaluate` pins: "Empty / null match
        // matches everything (true)." This is the vacuous-AND base
        // case the engine's `match:` clause depends on when the YAML
        // omits the block entirely (every-request policy). A
        // refactor that flipped null to `false` (the natural
        // "be safe by default" mistake) would silently disable
        // every match-less policy in the file. Pin the contract
        // across three distinct ctxs so a fold over `ctx` into the
        // result surfaces here. Symmetric to round-91 `allowed()`
        // empty-layers vacuous-true pin extended to the
        // match-expression base case one module down.
        let null_expr: Yaml = serde_yaml::from_str("~").unwrap();
        assert!(null_expr.is_null(), "fixture sanity");
        for vendor in ["drive", "gmail", ""] {
            let ctx = RequestContext {
                vendor: vendor.into(),
                action: "a".into(),
                ..Default::default()
            };
            assert!(
                evaluate(&null_expr, &ctx).unwrap(),
                "null expr must match vendor={vendor:?}",
            );
        }
    }

    #[test]
    fn match_error_unsupported_op_inner_field_is_owned_string_for_arc_share_safety() {
        // `UnsupportedOp(String)` — the inner is OWNED `String`, not
        // `&'static str` or `Cow<'_, str>`. The error propagates
        // across an `.await` boundary up through `rego::Error::Match`
        // into `AppError::Policy`, and the YAML source bytes (the
        // origin of the operator name) are dropped before the
        // audit-sink consumes the error. A refactor to a borrowed
        // form for "zero-alloc on the happy-path-never-hit branch"
        // would silently introduce a lifetime parameter that would
        // cascade through every consuming type. Pin the owned-String
        // type via the canonical require_string helper. Symmetric to
        // round-176 + round-177 + round-179 owned-String pins
        // extended to this error variant.
        fn require_string(_: &String) {}
        let inner = match MatchError::UnsupportedOp("weird_op".into()) {
            MatchError::UnsupportedOp(s) => s,
            other => panic!("expected UnsupportedOp, got {other:?}"),
        };
        require_string(&inner);
        assert_eq!(inner, "weird_op");
    }

    #[test]
    fn match_error_bad_shape_op_and_got_fields_are_owned_string_for_cross_await_propagation() {
        // `BadShape { op: String, expected: &'static str, got: String }`
        // — the `op` and `got` fields are OWNED `String` while
        // `expected` is `&'static str` (round-85 pinned the latter).
        // The asymmetry is load-bearing: `expected` is always a
        // compile-time literal ("mapping", "sequence", "string", ...)
        // so a static slice keeps the variant cheap to Clone for
        // retry tracing; `op` and `got` are runtime-derived from the
        // YAML and the actual value's `type_name`, so they MUST be
        // owned to survive the YAML source drop across the `.await`
        // boundary. Pin both owned-String fields via the canonical
        // require_string helper (round-85 didn't separately pin the
        // type, only the dotted-path acceptance). A refactor to a
        // borrowed form on either field would break cross-await
        // propagation. Symmetric to round-176 + round-177 + round-179
        // owned-String pins extended to BadShape's runtime-derived
        // sibling fields.
        fn require_string(_: &String) {}
        let (op, got) = match (MatchError::BadShape {
            op: "user.contact.email".into(),
            expected: "mapping",
            got: "string".into(),
        }) {
            MatchError::BadShape { op, got, .. } => (op, got),
            other => panic!("expected BadShape, got {other:?}"),
        };
        require_string(&op);
        require_string(&got);
        assert_eq!(op, "user.contact.email");
        assert_eq!(got, "string");
    }

    #[test]
    fn match_error_debug_carries_variant_name_for_operator_log_grep_bucketing() {
        // Operator alert filters in Loki / CloudWatch bucket match-
        // expression faults by Debug-variant-name (the dashboard's
        // "policy authoring errors" panel renders Display, but the
        // alert pipeline keys on Debug because it survives across
        // future variant additions without re-tuning the regex).
        // Pin the three variant-name substrings (UnsupportedOp /
        // BadShape / Template) in Debug output so a `#[derive(Debug)]`
        // drift to a hand-rolled impl that elided variant names
        // "for compactness" would silently merge all three into one
        // bucket. Symmetric to round-163 ConfigError + round-168
        // PicViolationRecord + round-173 ErrorCode + round-176
        // PolicyLoadError Debug variant-name sweeps extended to
        // MatchError.
        let unsupported = MatchError::UnsupportedOp("weird_op".into());
        assert!(
            format!("{unsupported:?}").contains("UnsupportedOp"),
            "Debug missing UnsupportedOp variant name: {unsupported:?}",
        );
        let bad_shape = MatchError::BadShape {
            op: "in".into(),
            expected: "sequence",
            got: "number".into(),
        };
        assert!(
            format!("{bad_shape:?}").contains("BadShape"),
            "Debug missing BadShape variant name: {bad_shape:?}",
        );
        let template: MatchError = crate::ops::OpsParseError::UnknownVar("ctx.x".into()).into();
        assert!(
            format!("{template:?}").contains("Template"),
            "Debug missing Template variant name: {template:?}",
        );
    }

    #[test]
    fn match_error_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // Pin the MatchError variant count at exactly 3 via exhaustive
        // match expression. A 4th variant landing (e.g.
        // `UnsupportedYamlType { type_name: &'static str }` to give
        // a distinct triage bucket for non-mapping match expressions
        // that BadShape currently collapses, or `EvalLimit { depth }`
        // for a future recursion-depth ceiling per spec.md §9 future
        // work) without matching every Display attribute + the rego
        // module's `#[from]` chain + the operator-facing dashboard
        // panel would surface here as a non-exhaustive compile error.
        // The enum is NOT `#[non_exhaustive]` — within the workspace
        // the match is fully closed and a new variant MUST update
        // every dispatch site in lockstep.
        fn variant_witness(e: &MatchError) -> u8 {
            match e {
                MatchError::UnsupportedOp(_) => 0,
                MatchError::BadShape { .. } => 1,
                MatchError::Template(_) => 2,
            }
        }
        let unsupported = MatchError::UnsupportedOp("weird".into());
        let bad_shape = MatchError::BadShape {
            op: "in".into(),
            expected: "sequence",
            got: "number".into(),
        };
        let template: MatchError = crate::ops::OpsParseError::UnknownVar("ctx.x".into()).into();
        let mut seen = std::collections::HashSet::new();
        for e in [&unsupported, &bad_shape, &template] {
            assert!(seen.insert(variant_witness(e)));
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn match_error_bad_shape_struct_variant_field_count_pinned_at_exactly_three_via_exhaustive_destructure()
     {
        // Pin the BadShape struct-variant field count at exactly 3
        // via exhaustive destructure (no `..`). The 3 fields are:
        // op + expected + got. A 4th field landing (e.g.
        // `policy_id: Option<String>` for back-attribution from
        // match error to the rule that emitted it, or
        // `field_path: Vec<String>` for nested-mapping breadcrumbs)
        // would silently bloat every MatchError::BadShape instance
        // flowing through the engine → policy_handle error log AND
        // silently change the existing Display rendering. The
        // existing `match_error_bad_shape_display_renders_all_three_named_fields_in_order`
        // pin walks the Display string; exhaustive destructure
        // catches a runtime-only 4th field that doesn't surface
        // through Display.
        let e = MatchError::BadShape {
            op: "in".into(),
            expected: "sequence",
            got: "number".into(),
        };
        match e {
            MatchError::BadShape {
                op: _,
                expected: _,
                got: _,
            } => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn match_error_bad_shape_expected_field_type_is_static_str_for_zero_alloc_label_propagation() {
        // The `expected` field on BadShape is `&'static str` (NOT
        // `String`) — pin via require_static_str. The 11-operator
        // vocabulary embeds literal strings ("sequence", "string",
        // "scalar", etc) at compile time; a refactor to `String`
        // "for ownership symmetry with op/got" would silently
        // allocate one String per BadShape construction on every
        // policy-author-error path. The
        // `match_error_bad_shape_display_static_str_expected_field_supports_typical_descriptors`
        // pin walks the values via Display; this pins the type
        // contract directly at compile time.
        fn require_static_str(_: &'static str) {}
        // Pull the field out via a destructure and pass it to the
        // require fn — if the field type were `String`, the
        // expression `expected` would be `String` (not `&'static
        // str`) and the call would fail to compile.
        let e = MatchError::BadShape {
            op: "in".into(),
            expected: "sequence",
            got: "number".into(),
        };
        if let MatchError::BadShape { expected, .. } = e {
            require_static_str(expected);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn evaluate_signature_pinned_via_fn_pointer_witness() {
        // Pin evaluate signature as
        // `fn(&Yaml, &RequestContext) -> Result<bool, MatchError>`
        // via fn-pointer witness. BOTH arguments are borrows — the
        // engine calls this per policy per request without owning
        // the parsed match expression (the Engine holds the Yaml
        // tree behind `Arc<PolicyDoc>`). A refactor to
        // `fn(Yaml, ...)` "for consume-and-cache opt" would silently
        // force the engine to clone the Yaml tree per evaluation,
        // on the hot path. The `Result<bool, MatchError>` return
        // is also pinned — a `Result<Outcome, ...>` refactor "to
        // unify the engine/match-expr error types" would force
        // every call site through the rego `?`-chain conversion.
        let _f: fn(&Yaml, &RequestContext) -> Result<bool, MatchError> = evaluate;
    }

    #[test]
    fn match_error_template_variant_implements_from_ops_parse_error_via_serde_question_mark_chain()
    {
        // `MatchError::Template(#[from] OpsParseError)` is the
        // load-bearing conversion path between the ops-substitute
        // helper and the match-expr interpreter — `apply_op`'s
        // `as_str_subst(rhs, ctx)?` bubbles OpsParseError up
        // through this From impl. The existing
        // `match_error_template_display_carries_template_error_prefix_with_inner_passthrough`
        // pin walks the Display rendering; the existing
        // `match_error_debug_carries_variant_name_for_operator_log_grep_bucketing`
        // test exercises the From impl but doesn't pin its signature.
        // Pin the From<OpsParseError> impl via require_from_impl AND
        // round-trip the inner OpsParseError through Template back
        // out so a refactor that lost the `#[from]` (and required
        // explicit `MatchError::Template(e)` at every call site)
        // would surface here as a missing trait-bound + a unwrap
        // failure on the inner extraction. Symmetric to round-255
        // OpsAtomView From<&OpsAtom> trait-bound pin extended to
        // MatchError::Template.
        fn require_from<T, S: From<T>>(t: T) -> S {
            S::from(t)
        }
        let inner = crate::ops::OpsParseError::UnknownVar("x.y".into());
        let m: MatchError = require_from::<crate::ops::OpsParseError, MatchError>(inner);
        match m {
            MatchError::Template(crate::ops::OpsParseError::UnknownVar(name)) => {
                assert_eq!(name, "x.y");
            }
            other => panic!("expected Template(UnknownVar), got {other:?}"),
        }
    }

    #[test]
    fn evaluate_handles_eleven_operator_vocabulary_via_spec_documented_set() {
        // The match-expression operator vocabulary per spec.md §0.3
        // is the closed set: `in`, `not_in`, `equals`, `not_equals`,
        // `matches`, `greater_than`, `less_than`, `all`, `any`,
        // `not`, `exists` (11 total). The existing per-operator
        // tests cover happy + sad paths individually; pin the FULL
        // 11-operator set as an end-to-end sweep so a refactor that
        // dropped an operator from `eval_entry` or `apply_op`
        // (without touching the docs) would surface here. Each YAML
        // fixture is a valid match expression that triggers ONE
        // operator's dispatch path. The contract: `evaluate(&yaml,
        // &ctx)` must return Ok for every operator (Ok(true) or
        // Ok(false) — we don't care which; we care that no operator
        // surfaces UnsupportedOp).
        let mut path = std::collections::HashMap::new();
        path.insert("id".to_string(), "abc".to_string());
        let ctx = RequestContext {
            vendor: "google".into(),
            action: "drive.files.get".into(),
            customer_domain: "acme.com".into(),
            path,
            ..Default::default()
        };
        let fixtures: &[(&str, &str)] = &[
            // Top-level operators (eval_entry dispatch path).
            ("all", "all: []"),
            ("any", "any: []"),
            ("not", "not: ~"),
            ("exists", "exists: path.id"),
            // Field-level operators (apply_op dispatch path).
            ("equals", "path.id: { equals: abc }"),
            ("not_equals", "path.id: { not_equals: xyz }"),
            ("in", "path.id: { in: [abc, def] }"),
            ("not_in", "path.id: { not_in: [xyz] }"),
            ("matches", "path.id: { matches: 'a.*' }"),
            ("greater_than", "path.id: { greater_than: 0 }"),
            ("less_than", "path.id: { less_than: 999999 }"),
        ];
        for (op_name, yaml_str) in fixtures {
            let yaml: Yaml = serde_yaml::from_str(yaml_str)
                .unwrap_or_else(|e| panic!("bad fixture for {op_name}: {e}"));
            let r = evaluate(&yaml, &ctx);
            assert!(
                r.is_ok(),
                "operator {op_name} must not error on spec-documented shape: got {r:?}",
            );
            // And it must NOT surface UnsupportedOp.
            if let Err(MatchError::UnsupportedOp(name)) = &r {
                panic!("operator {op_name} surfaces UnsupportedOp({name})");
            }
        }
        assert_eq!(fixtures.len(), 11, "spec.md §0.3 documents 11 operators");
    }
}
