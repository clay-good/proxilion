/// Defense Evasion Detection - Detects attempts to avoid detection
///
/// Identifies MITRE ATT&CK T1070, T1562, T1027 (Defense Evasion) patterns:
/// - Log deletion/clearing
/// - Security tool disabling
/// - File obfuscation
/// - Timestamp manipulation
/// - Process hiding

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct DefenseEvasionAnalyzer {
    log_clearing: Vec<&'static str>,
    security_disabling: Vec<&'static str>,
    obfuscation: Vec<&'static str>,
    timestamp_manipulation: Vec<&'static str>,
    process_hiding: Vec<&'static str>,
}

impl DefenseEvasionAnalyzer {
    pub fn new() -> Self {
        Self {
            log_clearing: vec![
                "rm -rf /var/log",
                "echo '' >",
                "cat /dev/null >",
                "truncate -s 0",
                "Clear-EventLog",
                "wevtutil cl",
                "history -c",
                "unset HISTFILE",
                "export HISTFILE=/dev/null",
                "shred",
            ],
            security_disabling: vec![
                "systemctl stop",
                "systemctl disable",
                "service stop",
                "chkconfig off",
                "ufw disable",
                "iptables -F",
                "setenforce 0",
                "Stop-Service",
                "Disable-WindowsOptionalFeature",
                "Set-MpPreference -DisableRealtimeMonitoring",
            ],
            obfuscation: vec![
                "base64 -d",
                "base64 --decode",
                "echo * | base64",
                "eval(",
                "exec(",
                "gzip -d",
                "gunzip",
                "openssl enc",
                "xxd -r",
                "perl -e",
            ],
            timestamp_manipulation: vec![
                "touch -t",
                "touch -d",
                "touch -r",
                "timestomp",
                "Set-ItemProperty -Name LastWriteTime",
            ],
            process_hiding: vec![
                "nohup",
                "disown",
                "&",
                "screen -dm",
                "tmux new -d",
                "/dev/shm",
                "LD_PRELOAD",
                "rootkit",
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "defense_evasion".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for log clearing
        for &pattern in &self.log_clearing {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Log clearing detected: {}", pattern));
                score = score.max(95.0);
                break;
            }
        }

        // Check for security tool disabling
        for &pattern in &self.security_disabling {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Security tool disabling: {}", pattern));
                score = score.max(92.0);
                break;
            }
        }

        // Check for obfuscation
        for &pattern in &self.obfuscation {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Code obfuscation detected: {}", pattern));
                score = score.max(75.0);
                break;
            }
        }

        // Check for timestamp manipulation
        for &pattern in &self.timestamp_manipulation {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Timestamp manipulation: {}", pattern));
                score = score.max(88.0);
                break;
            }
        }

        // Check for process hiding
        for &pattern in &self.process_hiding {
            if content_lower.contains(&pattern.to_lowercase()) {
                // "&" alone is too common, require more context
                if pattern == "&" && content.matches('&').count() > 2 {
                    patterns_found.push(format!("Process hiding technique: {}", pattern));
                    score = score.max(70.0);
                } else if pattern != "&" {
                    patterns_found.push(format!("Process hiding technique: {}", pattern));
                    score = score.max(85.0);
                }
                break;
            }
        }

        AnalyzerResult {
            analyzer_name: "defense_evasion".to_string(),
            threat_score: score.min(100.0),
            patterns: patterns_found,
            metadata: serde_json::json!({
                "mitre_attack": ["T1070", "T1562", "T1027"],
                "category": "defense_evasion"
            }),
        }
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

impl Default for DefenseEvasionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_clearing() {
        let analyzer = DefenseEvasionAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "echo '' > /var/log/auth.log".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 90.0);
    }

    #[test]
    fn test_security_disabling() {
        let analyzer = DefenseEvasionAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "systemctl stop firewalld".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 85.0);
    }

    #[test]
    fn test_safe_operations() {
        let analyzer = DefenseEvasionAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "ls -la".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);
        assert_eq!(result.threat_score, 0.0);
    }
}
