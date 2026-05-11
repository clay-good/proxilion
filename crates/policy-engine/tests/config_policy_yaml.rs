#[test]
fn parses_config_policy_yaml() {
    let yaml = std::fs::read_to_string("../../config/policy.yaml").expect("read");
    let engine = policy_engine::Engine::new(&yaml).expect("policy engine parses");
    assert_eq!(engine.policy_count(), 2);
}
