//! Extended unit tests for Enumeration Analyzer
//!
//! Tests reconnaissance and network discovery pattern detection

use super::test_utils::*;
use threat_engine::analyzers::enumeration::EnumerationAnalyzer;

#[test]
fn test_nmap_basic_detection() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("nmap 192.168.1.1"));
    assert_threat_above(&result, 80.0);
    assert_pattern_detected(&result, "nmap");
}

#[test]
fn test_nmap_with_flags() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("nmap -sV -sS -p 1-65535 10.0.0.0/8"));
    assert_threat_above(&result, 85.0);
    assert_pattern_detected(&result, "Port scanning flags");
}

#[test]
fn test_masscan_detection() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("masscan 192.168.0.0/16 -p80,443"));
    assert_threat_above(&result, 85.0);
    assert_pattern_detected(&result, "masscan");
}

#[test]
fn test_gobuster_detection() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("gobuster dir -u http://target.com -w wordlist.txt"));
    assert_threat_above(&result, 75.0);
    assert_pattern_detected(&result, "gobuster");
}

#[test]
fn test_nikto_detection() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("nikto -h target.com"));
    assert_threat_above(&result, 80.0);
    assert_pattern_detected(&result, "nikto");
}

#[test]
fn test_nuclei_detection() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("nuclei -u http://target.com -t cves/"));
    assert_threat_above(&result, 80.0);
    assert_pattern_detected(&result, "nuclei");
}

// Edge cases

#[test]
fn test_empty_command() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call(""));
    assert_safe(&result);
}

#[test]
fn test_unicode_in_command() {
    let analyzer = EnumerationAnalyzer::new();
    // Unicode should not cause false positives
    let result = analyzer.analyze(&bash_call("echo '\u{1F600}' > file.txt"));
    assert_safe(&result);
}

#[test]
fn test_unicode_obfuscation_attempt() {
    let analyzer = EnumerationAnalyzer::new();
    // Unicode lookalikes for "nmap" shouldn't bypass
    let result = analyzer.analyze(&bash_call("nmap 10.0.0.1")); // real nmap
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_case_insensitive_nmap() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("NMAP -sV target.com"));
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_safe_dig_command() {
    let analyzer = EnumerationAnalyzer::new();
    // dig is lower severity - should detect but not be critical
    let result = analyzer.analyze(&bash_call("dig google.com"));
    assert_threat_above(&result, 45.0);
    assert_threat_below(&result, 60.0);
}

#[test]
fn test_safe_nslookup() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("nslookup example.com"));
    assert_threat_above(&result, 45.0);
    assert_threat_below(&result, 60.0);
}

// Safe commands that should not trigger

#[test]
fn test_safe_ls_command() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("ls -la /home/user"));
    assert_safe(&result);
}

#[test]
fn test_safe_cat_command() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("cat README.md"));
    assert_safe(&result);
}

#[test]
fn test_safe_grep_command() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("grep -r 'pattern' src/"));
    assert_safe(&result);
}

#[test]
fn test_safe_curl_command() {
    let analyzer = EnumerationAnalyzer::new();
    // Regular curl to API should not trigger enumeration
    let result = analyzer.analyze(&bash_call("curl https://api.github.com"));
    assert_safe(&result);
}

// Network tool call tests

#[test]
fn test_network_directory_traversal() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&network_request("GET", "http://target.com/../../../etc/passwd"));
    assert_threat_above(&result, 75.0);
    assert_pattern_detected(&result, "traversal");
}

#[test]
fn test_network_admin_path_probing() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&network_request("GET", "http://target.com/wp-admin/"));
    assert_threat_above(&result, 60.0);
    assert_pattern_detected(&result, "admin");
}

#[test]
fn test_network_env_file_access() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&network_request("GET", "http://target.com/.env"));
    assert_threat_above(&result, 70.0);
}

#[test]
fn test_network_parameter_fuzzing() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&network_request(
        "GET",
        "http://target.com/api?a=1&b=2&c=3&d=4&e=5&f=6&g=7"
    ));
    assert_threat_above(&result, 60.0);
    assert_pattern_detected(&result, "Multiple parameters");
}

#[test]
fn test_network_normal_api_call() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&network_request("GET", "https://api.example.com/v1/users"));
    assert_safe(&result);
}

// Filesystem tool call tests

#[test]
fn test_filesystem_path_traversal() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&fs_read("../../../etc/passwd"));
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_filesystem_sensitive_file() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&fs_read("/app/.env"));
    assert_threat_above(&result, 70.0);
}

#[test]
fn test_filesystem_git_folder() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&fs_read("/app/.git/config"));
    assert_threat_above(&result, 70.0);
}

#[test]
fn test_filesystem_normal_read() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&fs_read("/home/user/project/src/main.rs"));
    assert_safe(&result);
}

// Database tool call tests

#[test]
fn test_database_information_schema() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&db_query(
        "SELECT * FROM information_schema.tables",
        "main"
    ));
    assert_threat_above(&result, 75.0);
    assert_pattern_detected(&result, "enumeration");
}

#[test]
fn test_database_show_tables() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&db_query("SHOW TABLES", "main"));
    assert_threat_above(&result, 75.0);
}

#[test]
fn test_database_show_databases() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&db_query("SHOW DATABASES", "main"));
    assert_threat_above(&result, 75.0);
}

#[test]
fn test_database_normal_query() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&db_query(
        "SELECT id, name FROM users WHERE id = 1",
        "main"
    ));
    assert_safe(&result);
}

// IP address detection tests

#[test]
fn test_ipv4_address_detection() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("ping 192.168.1.1"));
    assert_threat_above(&result, 65.0);
    assert_pattern_detected(&result, "IP address");
}

#[test]
fn test_ipv4_invalid_should_not_match() {
    let analyzer = EnumerationAnalyzer::new();
    // 999.999.999.999 is not a valid IP
    let result = analyzer.analyze(&bash_call("echo 999.999.999.999"));
    assert_safe(&result);
}

#[test]
fn test_cidr_range_detection() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call("scan 10.0.0.0/8"));
    assert_threat_above(&result, 85.0);
    assert_pattern_detected(&result, "Network range");
}

// Combined patterns bonus

#[test]
fn test_multiple_patterns_increase_score() {
    let analyzer = EnumerationAnalyzer::new();
    // Multiple indicators should increase score
    let result = analyzer.analyze(&bash_call("nmap -sV -p 1-65535 192.168.1.0/24"));
    // Should have bonus for multiple patterns
    assert_threat_above(&result, 90.0);
}

// Args handling

#[test]
fn test_nmap_in_args() {
    let analyzer = EnumerationAnalyzer::new();
    let result = analyzer.analyze(&bash_call_with_args("sudo", vec!["nmap", "-sV", "target.com"]));
    assert_threat_above(&result, 80.0);
}
