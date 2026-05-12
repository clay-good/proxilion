//! Integration tests for `Engine::evaluate_with_trace` — qiuth-patterns.md §3.

use std::collections::HashMap;

use policy_engine::{
    Decision, Engine, PolicyEvalMode, PolicyLayer, RequestContext, UserCtx,
};
use serde_json::Value;
use shared_types::ErrorCode;

fn engine() -> Engine {
    let yaml = std::fs::read_to_string("../../config/policy.yaml").expect("policy yaml");
    Engine::new(&yaml).expect("policy parses")
}

fn gmail_ctx(external: bool, to_domain: &str) -> RequestContext {
    let mut body = HashMap::new();
    body.insert("external_recipient".into(), Value::Bool(external));
    body.insert("to_domain".into(), Value::String(to_domain.into()));
    body.insert(
        "to_domains".into(),
        Value::Array(vec![Value::String(to_domain.into())]),
    );
    RequestContext {
        vendor: "google".into(),
        action: "gmail.messages.send".into(),
        user: UserCtx {
            email: "alice@acme.com".into(),
            groups: vec![],
        },
        path: HashMap::new(),
        body,
        headers: HashMap::new(),
        customer_domain: "acme.com".into(),
    }
}

#[test]
fn trace_records_layer_a_and_layer_b_on_block() {
    let e = engine();
    let (outcome, trace) = e
        .evaluate_with_trace(&gmail_ctx(true, "evilcorp.example"))
        .expect("evaluates");

    assert_eq!(
        outcome.matched_policy_id.as_deref(),
        Some("gmail-external-send-gate")
    );
    assert!(matches!(outcome.decision, Decision::Block { .. }));

    // Layer A should be present and `passed: true` (the engine doesn't
    // round-trip the Trust Plane).
    let layer_a = trace
        .layers
        .iter()
        .find(|l| l.layer == PolicyLayer::LayerA)
        .expect("Layer A present");
    assert!(layer_a.passed);
    assert!(layer_a.matched_rule_id.is_some(), "Layer A records required-ops count");

    // Layer B should record the block with `policy_blocked`.
    let layer_b = trace
        .layers
        .iter()
        .find(|l| l.layer == PolicyLayer::LayerB)
        .expect("Layer B present");
    assert!(!layer_b.passed);
    assert_eq!(layer_b.error_code, Some(ErrorCode::PolicyBlocked));
    assert_eq!(
        layer_b.matched_rule_id.as_deref(),
        Some("gmail-external-send-gate")
    );

    // Trace marks the request as denied.
    assert!(!trace.allowed());

    // required_ops carries the one resolved atom for the external recipient.
    assert!(
        !trace.required_ops.is_empty(),
        "trace surfaces required ops for the block"
    );

    // Smoke check the duration field is populated.
    assert!(trace.duration_micros < 50_000, "<50ms is generous");
}

#[test]
fn trace_records_allow_when_no_policy_blocks() {
    let e = engine();
    let (outcome, trace) = e
        .evaluate_with_trace(&gmail_ctx(false, "acme.com"))
        .expect("evaluates");
    assert!(matches!(outcome.decision, Decision::Allow));

    // No matching policy → Layer A entry with no required ops, Layer B passed,
    // no read-filter slot (no policy was matched).
    let layer_b = trace
        .layers
        .iter()
        .find(|l| l.layer == PolicyLayer::LayerB)
        .expect("Layer B present");
    assert!(layer_b.passed);
    assert!(layer_b.error_code.is_none());
    assert!(trace.allowed());
}

#[test]
fn trace_records_read_filter_slot_when_policy_configures_one() {
    // The drive-injection-filter in config/policy.yaml carries a read_filter.
    let e = engine();
    let mut path = HashMap::new();
    path.insert("id".into(), "file-abc".into());
    let ctx = RequestContext {
        vendor: "google".into(),
        action: "drive.files.get".into(),
        user: UserCtx {
            email: "alice@acme.com".into(),
            groups: vec![],
        },
        path,
        body: HashMap::new(),
        headers: HashMap::new(),
        customer_domain: "acme.com".into(),
    };
    let (_outcome, trace) = e.evaluate_with_trace(&ctx).expect("evaluates");
    let rf = trace
        .layers
        .iter()
        .find(|l| l.layer == PolicyLayer::ReadFilter);
    assert!(rf.is_some(), "read-filter slot present when policy configures one");
    let rf = rf.unwrap();
    assert!(rf.passed, "engine emits pending=true; adapter mutates after scan");
}

/// qiuth-patterns.md §3.4 deviation 2 — `Comprehensive` mode walks every
/// later policy after the first match and records "would-also-have-matched"
/// diagnostics as extra Layer-B [`LayerOutcome`] entries.
#[test]
fn comprehensive_mode_records_would_also_match_diagnostics() {
    let yaml = r#"
- id: first-block
  vendor: google
  action: gmail.messages.send
  match:
    body.external_recipient:
      equals: true
  decision: block
- id: second-overlap
  vendor: google
  action: gmail.messages.send
  match:
    body.external_recipient:
      equals: true
  decision: require_confirmation
- id: third-allow
  vendor: google
  action: gmail.messages.send
  match:
    body.external_recipient:
      equals: true
  decision: allow
- id: unrelated-different-action
  vendor: google
  action: drive.files.get
  decision: allow
"#;
    let e = Engine::new(yaml).expect("policy parses");
    let ctx = gmail_ctx(true, "evilcorp.example");

    // Fail-fast: only the first match's Layer-B outcome is recorded.
    let (out_fast, trace_fast) = e.evaluate_with_trace(&ctx).expect("ff evaluates");
    assert_eq!(out_fast.matched_policy_id.as_deref(), Some("first-block"));
    let layer_b_count_fast = trace_fast
        .layers
        .iter()
        .filter(|l| l.layer == PolicyLayer::LayerB)
        .count();
    assert_eq!(layer_b_count_fast, 1, "fail-fast emits exactly one Layer-B");

    // Comprehensive: the first match plus two later overlaps.
    let (out_comp, trace_comp) = e
        .evaluate_with_trace_mode(&ctx, PolicyEvalMode::Comprehensive)
        .expect("comp evaluates");
    assert_eq!(out_comp.matched_policy_id.as_deref(), Some("first-block"));
    assert!(matches!(out_comp.decision, Decision::Block { .. }));
    let layer_b: Vec<_> = trace_comp
        .layers
        .iter()
        .filter(|l| l.layer == PolicyLayer::LayerB)
        .collect();
    assert_eq!(layer_b.len(), 3, "first match + two would-also-match overlaps");
    assert_eq!(layer_b[0].matched_rule_id.as_deref(), Some("first-block"));
    let ids: Vec<_> = layer_b[1..]
        .iter()
        .map(|l| l.matched_rule_id.as_deref().unwrap_or(""))
        .collect();
    assert!(ids.contains(&"second-overlap"));
    assert!(ids.contains(&"third-allow"));
    for l in &layer_b[1..] {
        assert!(
            l.detail.as_deref().unwrap_or("").starts_with("would_also_match:"),
            "diagnostic detail flagged with would_also_match prefix"
        );
    }

    // Final decision is the first match's — diagnostics are purely
    // informational, never override the hot-path verdict.
    assert!(!trace_comp.allowed());
}
