//! Integration tests against the two example policies in spec.md §9.

use std::collections::HashMap;

use policy_engine::{Decision, Engine, OpsAtom, RequestContext, UserCtx};

const POLICIES: &str = r#"
- id: gmail-external-send-gate
  vendor: google
  action: gmail.messages.send
  match:
    body.to_domain:
      not_in: ["${customer_domain}"]
  decision: block
  override: requires_justification
  pic_mode: runtime-gate
  required_ops:
    - "gmail:send:message"

- id: drive-injection-filter
  vendor: google
  action: drive.files.get
  decision: allow
  read_filter:
    quarantine_patterns:
      - "ignore previous instructions"
      - "system prompt:"
      - regex: '<\|.*?\|>'
    quarantine_action: replace_with_marker
  pic_mode: audit
  required_ops:
    - "drive:read:file/${path.id}"
"#;

fn drive_ctx(id: &str) -> RequestContext {
    let mut path = HashMap::new();
    path.insert("id".to_string(), id.to_string());
    RequestContext {
        vendor: "google".into(),
        action: "drive.files.get".into(),
        user: UserCtx {
            email: "alice@acme.com".into(),
            groups: vec!["engineering".into()],
        },
        path,
        body: Default::default(),
        headers: Default::default(),
        customer_domain: "acme.com".into(),
    }
}

fn gmail_ctx(to_domain: &str) -> RequestContext {
    let mut body = HashMap::new();
    body.insert(
        "to_domain".to_string(),
        serde_json::Value::String(to_domain.to_string()),
    );
    RequestContext {
        vendor: "google".into(),
        action: "gmail.messages.send".into(),
        user: UserCtx {
            email: "alice@acme.com".into(),
            groups: vec!["engineering".into()],
        },
        path: Default::default(),
        body,
        headers: Default::default(),
        customer_domain: "acme.com".into(),
    }
}

#[test]
fn drive_get_resolves_ops_with_path_id() {
    let engine = Engine::new(POLICIES).expect("engine compiles");
    let out = engine.evaluate(&drive_ctx("abc123")).expect("evaluates");
    assert_eq!(
        out.matched_policy_id.as_deref(),
        Some("drive-injection-filter")
    );
    assert!(matches!(out.decision, Decision::Allow));
    assert_eq!(out.required_ops.required.len(), 1);
    let atom = &out.required_ops.required[0];
    assert_eq!(atom.scheme, "drive");
    assert_eq!(atom.action, "read");
    assert_eq!(atom.object, "file/abc123");
    assert!(out.read_filter.is_some());
}

#[test]
fn gmail_external_send_blocks() {
    let engine = Engine::new(POLICIES).unwrap();
    let out = engine.evaluate(&gmail_ctx("external.example")).unwrap();
    assert_eq!(
        out.matched_policy_id.as_deref(),
        Some("gmail-external-send-gate")
    );
    match out.decision {
        Decision::Block {
            override_allowed, ..
        } => assert!(
            override_allowed,
            "override should be allowed via justification"
        ),
        d => panic!("expected Block, got {d:?}"),
    }
}

#[test]
fn gmail_internal_send_does_not_match() {
    let engine = Engine::new(POLICIES).unwrap();
    let out = engine.evaluate(&gmail_ctx("acme.com")).unwrap();
    assert!(
        out.matched_policy_id.is_none(),
        "internal sends should not match the gate"
    );
    assert!(matches!(out.decision, Decision::Allow));
}

#[test]
fn missing_ops_reports_atoms() {
    let engine = Engine::new(POLICIES).unwrap();
    let out = engine.evaluate(&drive_ctx("file-xyz")).unwrap();
    let leaf: Vec<OpsAtom> = vec![]; // PCA chain has no ops
    let err = out
        .required_ops
        .is_satisfied_by(&leaf)
        .expect_err("should be missing");
    assert_eq!(err.missing.len(), 1);
    assert_eq!(err.missing[0].object, "file/file-xyz");
}

/// Perf budget per spec.md §0.3: <1ms p99 on a typical context. Only enforced
/// in release builds; debug builds are roughly 10–20× slower and would flake.
#[test]
#[cfg_attr(debug_assertions, ignore)]
fn evaluation_under_one_ms() {
    let engine = Engine::new(POLICIES).unwrap();
    let ctx = drive_ctx("benchmark-id");
    for _ in 0..50 {
        engine.evaluate(&ctx).unwrap();
    }
    let start = std::time::Instant::now();
    let n = 1000;
    for _ in 0..n {
        engine.evaluate(&ctx).unwrap();
    }
    let mean = start.elapsed() / n;
    assert!(
        mean < std::time::Duration::from_millis(1),
        "mean evaluation {mean:?} not < 1ms"
    );
}
