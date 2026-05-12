//! Integration tests for `Engine::evaluate_with_trace` — qiuth-patterns.md §3.

use std::collections::HashMap;

use policy_engine::{
    Decision, Engine, PolicyLayer, RequestContext, UserCtx,
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
