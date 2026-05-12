//! Per-policy `notifier_burst:` override (ui-less-surfaces.md §5.6).

use policy_engine::Engine;

const POLICY: &str = r#"
- id: noisy
  vendor: google
  action: gmail.messages.send
  decision: block
  required_ops: []
  notifier_burst:
    threshold: 5
    window_seconds: 10

- id: quiet
  vendor: google
  action: drive.files.get
  decision: allow
  required_ops: []
  notifier_burst:
    threshold: 200

- id: default
  vendor: google
  action: calendar.events.insert
  decision: block
  required_ops: []
"#;

#[test]
fn loads_both_threshold_and_window_overrides() {
    let e = Engine::new(POLICY).unwrap();
    let (thr, win) = e.burst_override_for("noisy").unwrap();
    assert_eq!(thr, Some(5));
    assert_eq!(win, Some(10));
}

#[test]
fn loads_partial_override() {
    let e = Engine::new(POLICY).unwrap();
    let (thr, win) = e.burst_override_for("quiet").unwrap();
    assert_eq!(thr, Some(200));
    assert_eq!(win, None, "window not set falls through to default");
}

#[test]
fn policies_without_override_return_none() {
    let e = Engine::new(POLICY).unwrap();
    assert!(e.burst_override_for("default").is_none());
}

#[test]
fn unknown_policy_returns_none() {
    let e = Engine::new(POLICY).unwrap();
    assert!(e.burst_override_for("nope").is_none());
}
