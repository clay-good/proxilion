//! Per-policy `notifier_recipients:` override (ui-less-surfaces.md §5.4 dev 3).

use policy_engine::Engine;

const POLICY: &str = r#"
- id: only-to
  vendor: google
  action: gmail.messages.send
  decision: block
  notifier_recipients:
    to: security@acme.com

- id: full-override
  vendor: google
  action: drive.files.get
  decision: allow
  notifier_recipients:
    to:
      - sec-primary@acme.com
      - sec-backup@acme.com
    cc: ops@acme.com
    bcc:
      - audit@acme.com

- id: cc-only
  vendor: google
  action: calendar.events.insert
  decision: block
  notifier_recipients:
    cc: legal@acme.com

- id: no-override
  vendor: google
  action: calendar.events.update
  decision: block

- id: with-escalation
  vendor: google
  action: gmail.messages.send
  decision: block
  notifier_recipients:
    to: oncall@acme.com
    escalation_after_minutes: 10
"#;

fn engine() -> Engine {
    Engine::new(POLICY).expect("policy parses")
}

#[test]
fn single_string_to_is_normalized_to_vec() {
    let (to, cc, bcc) = engine()
        .email_recipients_for("only-to")
        .expect("override present");
    assert_eq!(to.as_deref(), Some(&["security@acme.com".to_string()][..]));
    assert!(cc.is_none());
    assert!(bcc.is_none());
}

#[test]
fn full_override_all_three_lists() {
    let (to, cc, bcc) = engine()
        .email_recipients_for("full-override")
        .expect("override present");
    assert_eq!(to.as_ref().unwrap().len(), 2);
    assert_eq!(cc.as_deref(), Some(&["ops@acme.com".to_string()][..]));
    assert_eq!(bcc.as_deref(), Some(&["audit@acme.com".to_string()][..]));
}

#[test]
fn cc_only_leaves_to_and_bcc_unset() {
    let (to, cc, bcc) = engine()
        .email_recipients_for("cc-only")
        .expect("override present");
    assert!(to.is_none(), "to inherits the global default");
    assert_eq!(cc.as_deref(), Some(&["legal@acme.com".to_string()][..]));
    assert!(bcc.is_none());
}

#[test]
fn policy_without_recipients_block_returns_none() {
    assert!(engine().email_recipients_for("no-override").is_none());
}

#[test]
fn unknown_policy_returns_none() {
    assert!(engine().email_recipients_for("no-such-id").is_none());
}

// ui-less-surfaces.md §5.7 dev 2 — escalation accessor.
#[test]
fn escalation_after_minutes_for_returns_configured_value() {
    let e = engine();
    assert_eq!(e.escalation_after_minutes_for("with-escalation"), Some(10));
}

#[test]
fn escalation_after_minutes_absent_when_only_recipients_set() {
    // `only-to` configures `to` but no `escalation_after_minutes`.
    let e = engine();
    assert!(e.escalation_after_minutes_for("only-to").is_none());
}

#[test]
fn escalation_after_minutes_absent_when_no_recipients_block() {
    assert!(
        engine()
            .escalation_after_minutes_for("no-override")
            .is_none()
    );
}

#[test]
fn escalation_after_minutes_unknown_policy_is_none() {
    assert!(
        engine()
            .escalation_after_minutes_for("no-such-id")
            .is_none()
    );
}
