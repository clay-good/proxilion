#[test]
fn parses_config_policy_yaml() {
    let yaml = std::fs::read_to_string("../../config/policy.yaml").expect("read");
    let engine = policy_engine::Engine::new(&yaml).expect("policy engine parses");
    // Drive read-filter + Gmail external-send gate + 3 Calendar policies
    // (read audit, insert gate, update gate). Bump whenever
    // `config/policy.yaml` adds or removes a policy.
    assert_eq!(engine.policy_count(), 5);
}
