//! End-to-end policy evaluation for the gmail-external-send-gate from
//! `config/policy.yaml`. Bound to spec.md §2.1 + §9.

use std::collections::HashMap;

use policy_engine::{Decision, Engine, RequestContext, UserCtx};
use serde_json::Value;

fn engine() -> Engine {
    let yaml = std::fs::read_to_string("../../config/policy.yaml").expect("policy yaml");
    Engine::new(&yaml).expect("policy parses")
}

/// surface-delight-and-correctness.md §6.2 regression — a Layer-B gate that
/// matches directly on the list-valued `body.to_domains` field (rather than the
/// adapter-computed `body.external_recipient` boolean) must actually fire. This
/// is the recipient-domain gate from spec.md §9 expressed over the array. Before
/// the §6.2 fix the matcher stringified the array to its JSON literal and the
/// `not_in` set comparison never matched, silently disabling the gate.
fn list_match_engine() -> Engine {
    let yaml = r#"
- id: gmail-list-recipient-gate
  vendor: google
  action: gmail.messages.send
  match:
    body.to_domains:
      not_in: ["${customer_domain}"]
  decision: block
  override: requires_justification
  pic_mode: runtime-gate
"#;
    Engine::new(yaml).expect("inline list-match policy parses")
}

fn ctx_with_domains(domains: &[&str]) -> RequestContext {
    let mut body = HashMap::new();
    body.insert(
        "to_domains".into(),
        Value::Array(domains.iter().map(|d| Value::String((*d).into())).collect()),
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
fn list_match_blocks_fully_external_recipient_set() {
    // None of the recipient domains is the customer domain → `not_in`
    // (no-element-in-set) fires → block.
    let e = list_match_engine();
    let outcome = e
        .evaluate(&ctx_with_domains(&["evilcorp.example", "spamcorp.example"]))
        .unwrap();
    assert_eq!(
        outcome.matched_policy_id.as_deref(),
        Some("gmail-list-recipient-gate"),
        "list-valued not_in gate must match a fully-external send",
    );
    assert!(matches!(outcome.decision, Decision::Block { .. }));
}

#[test]
fn list_match_allows_when_an_internal_recipient_present() {
    // acme.com is among the recipients → `not_in` is false (an element is in
    // the set) → no match → default Allow.
    let e = list_match_engine();
    let outcome = e.evaluate(&ctx_with_domains(&["acme.com"])).unwrap();
    assert!(
        outcome.matched_policy_id.is_none(),
        "an internal recipient must not trip the external gate",
    );
    assert!(matches!(outcome.decision, Decision::Allow));
}

fn ctx_with_external(external: bool, to_domain: &str) -> RequestContext {
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
fn external_recipient_is_blocked() {
    let e = engine();
    let outcome = e
        .evaluate(&ctx_with_external(true, "evilcorp.example"))
        .unwrap();
    assert_eq!(
        outcome.matched_policy_id.as_deref(),
        Some("gmail-external-send-gate")
    );
    match outcome.decision {
        Decision::Block {
            override_allowed, ..
        } => {
            assert!(
                override_allowed,
                "policy declares override: requires_justification"
            );
        }
        other => panic!("expected Block, got {other:?}"),
    }
}

#[test]
fn internal_only_is_allowed() {
    let e = engine();
    // No `gmail.messages.send` policy matches when external_recipient is false,
    // so the default policy outcome is Allow.
    let outcome = e.evaluate(&ctx_with_external(false, "acme.com")).unwrap();
    assert!(matches!(outcome.decision, Decision::Allow));
}

#[test]
fn required_ops_resolves_to_send_atom() {
    let e = engine();
    let outcome = e
        .evaluate(&ctx_with_external(true, "evilcorp.example"))
        .unwrap();
    assert_eq!(outcome.required_ops.required.len(), 1);
    let atom = &outcome.required_ops.required[0];
    assert_eq!(atom.scheme, "gmail");
    assert_eq!(atom.action, "send");
    // object encodes both the from-user and the destination domain.
    assert!(atom.object.contains("alice@acme.com"), "atom={:?}", atom);
    assert!(atom.object.contains("evilcorp.example"));
}

/// spec.md §2.2 — `${body.to_domains}` is list-valued; the policy engine
/// produces one required-ops atom per unique recipient domain.
#[test]
fn required_ops_expands_per_recipient_domain() {
    let e = engine();
    let mut body = HashMap::new();
    body.insert("external_recipient".into(), Value::Bool(true));
    body.insert("to_domain".into(), Value::String("evilcorp.example".into()));
    body.insert(
        "to_domains".into(),
        Value::Array(vec![
            Value::String("evilcorp.example".into()),
            Value::String("spamcorp.example".into()),
            Value::String("acme.com".into()),
        ]),
    );
    let ctx = RequestContext {
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
    };
    let outcome = e.evaluate(&ctx).unwrap();
    assert_eq!(outcome.required_ops.required.len(), 3);
    let objects: Vec<&str> = outcome
        .required_ops
        .required
        .iter()
        .map(|a| a.object.as_str())
        .collect();
    assert!(objects.iter().any(|o| o.contains("evilcorp.example")));
    assert!(objects.iter().any(|o| o.contains("spamcorp.example")));
    assert!(objects.iter().any(|o| o.contains("acme.com")));
    // All atoms share scheme + action.
    for a in &outcome.required_ops.required {
        assert_eq!(a.scheme, "gmail");
        assert_eq!(a.action, "send");
        assert!(a.object.starts_with("alice@acme.com:to:"));
    }
}
