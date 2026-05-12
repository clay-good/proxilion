//! ui-less-surfaces.md §2 — observe-mode end-to-end.

use policy_engine::{Decision, Engine, RequestContext, UserCtx};
use std::collections::HashMap;

const POLICY: &str = r#"
- id: gmail-external-recipient
  vendor: google
  action: gmail.messages.send
  mode: observe
  match:
    body.external_recipient:
      equals: true
  decision: block
  override: requires_justification
  required_ops:
    - "gmail:send:${user.email}"

- id: drive-injection-filter
  vendor: google
  action: drive.files.get
  mode: enforce
  decision: allow
  required_ops:
    - "drive:read:file/${path.id}"

- id: ancient-disabled-rule
  vendor: google
  action: drive.files.delete
  mode: disabled
  decision: block
  required_ops: []
"#;

fn ctx(action: &str, body: HashMap<String, serde_json::Value>) -> RequestContext {
    RequestContext {
        vendor: "google".into(),
        action: action.into(),
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
fn observe_mode_demotes_block_to_allow_with_label() {
    let engine = Engine::new(POLICY).unwrap();
    let mut body = HashMap::new();
    body.insert("external_recipient".into(), serde_json::Value::Bool(true));
    let out = engine.evaluate(&ctx("gmail.messages.send", body)).unwrap();
    // Decision must be Allow so the adapter lets the request through.
    assert!(matches!(out.decision, Decision::Allow), "decision={:?}", out.decision);
    // But the "would have" label must record what happened.
    assert_eq!(out.observe_would_have.as_deref(), Some("observe_block"));
    assert_eq!(out.matched_policy_id.as_deref(), Some("gmail-external-recipient"));
    assert_eq!(out.mode, policy_engine::Mode::Observe);
}

#[test]
fn enforce_mode_passes_decision_through() {
    let engine = Engine::new(POLICY).unwrap();
    let mut path = HashMap::new();
    path.insert("id".into(), "0BabC".into());
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
    let out = engine.evaluate(&ctx).unwrap();
    assert!(matches!(out.decision, Decision::Allow));
    assert_eq!(out.observe_would_have, None);
    assert_eq!(out.mode, policy_engine::Mode::Enforce);
}

#[test]
fn disabled_mode_skips_evaluation() {
    let engine = Engine::new(POLICY).unwrap();
    // A delete action that the disabled policy would have blocked falls
    // through to the default Allow with no matched policy id.
    let out = engine.evaluate(&ctx("drive.files.delete", HashMap::new())).unwrap();
    assert_eq!(out.matched_policy_id, None);
    assert!(matches!(out.decision, Decision::Allow));
    assert_eq!(out.observe_would_have, None);
}

#[test]
fn default_mode_is_enforce_when_field_missing() {
    let yaml = r#"
- id: minimal
  vendor: google
  action: drive.files.get
  decision: block
  required_ops: []
"#;
    let engine = Engine::new(yaml).unwrap();
    let out = engine.evaluate(&ctx("drive.files.get", HashMap::new())).unwrap();
    // No `mode:` in YAML → enforce.
    assert!(matches!(out.decision, Decision::Block { .. }));
    assert_eq!(out.observe_would_have, None);
    assert_eq!(out.mode, policy_engine::Mode::Enforce);
}
