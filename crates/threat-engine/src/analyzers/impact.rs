/// Impact Detection - Detects destructive or disruptive actions
///
/// Identifies MITRE ATT&CK T1485, T1486, T1490 (Impact) patterns:
/// - Data destruction
/// - Ransomware behavior
/// - Service disruption
/// - Resource hijacking
/// - Defacement

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct ImpactAnalyzer {
    destruction_patterns: Vec<&'static str>,
    ransomware_patterns: Vec<&'static str>,
    service_disruption: Vec<&'static str>,
    resource_hijacking: Vec<&'static str>,
    defacement_patterns: Vec<&'static str>,
}

impl ImpactAnalyzer {
    pub fn new() -> Self {
        Self {
            destruction_patterns: vec![
                "rm -rf /",
                "rm -rf /*",
                "mkfs",
                "dd if=/dev/zero",
                "shred -vfz",
                "wipefs",
                "sgdisk --zap-all",
                "parted rm",
                ":(){ :|:& };:",  // Fork bomb
                "del /f /s /q",
                "format c:",
            ],
            ransomware_patterns: vec![
                "openssl enc -aes",
                "gpg --encrypt",
                "7z a -p",
                "zip -e",
                ".encrypted",
                ".locked",
                ".crypto",
                "DECRYPT_INSTRUCTIONS",
                "ransom",
                "bitcoin",
                "pay to unlock",
            ],
            service_disruption: vec![
                "systemctl stop",
                "kill -9",
                "killall",
                "pkill",
                "shutdown",
                "reboot",
                "halt",
                "poweroff",
                "init 0",
                "service stop",
                "sc stop",
                "Stop-Service",
            ],
            resource_hijacking: vec![
                "xmrig",
                "cpuminer",
                "ethminer",
                "cryptonight",
                "monero",
                "stratum+tcp",
                "mining pool",
                "hashrate",
                "cryptominer",
            ],
            defacement_patterns: vec![
                "index.html",
                "<title>Hacked",
                "defaced by",
                "pwned by",
                "owned by",
                "you have been hacked",
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "impact".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for data destruction (CRITICAL)
        for &pattern in &self.destruction_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Data destruction detected: {}", pattern));
                score = score.max(100.0);  // Maximum threat
                break;
            }
        }

        // Check for ransomware behavior
        let mut ransomware_indicators = 0;
        for &pattern in &self.ransomware_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                ransomware_indicators += 1;
                if !patterns_found.iter().any(|p| p.contains("Ransomware")) {
                    patterns_found.push(format!("Ransomware behavior: {}", pattern));
                }
            }
        }
        if ransomware_indicators >= 2 {
            score = score.max(98.0);
        } else if ransomware_indicators == 1 {
            score = score.max(85.0);
        }

        // Check for service disruption
        for &pattern in &self.service_disruption {
            if content_lower.contains(&pattern.to_lowercase()) {
                // shutdown/reboot can be legitimate, lower score
                if pattern.contains("shutdown") || pattern.contains("reboot") {
                    patterns_found.push(format!("Service disruption: {}", pattern));
                    score = score.max(60.0);
                } else {
                    patterns_found.push(format!("Service disruption: {}", pattern));
                    score = score.max(80.0);
                }
                break;
            }
        }

        // Check for resource hijacking (cryptomining)
        for &pattern in &self.resource_hijacking {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Resource hijacking/cryptomining: {}", pattern));
                score = score.max(95.0);
                break;
            }
        }

        // Check for defacement
        for &pattern in &self.defacement_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Defacement attempt: {}", pattern));
                score = score.max(88.0);
                break;
            }
        }

        AnalyzerResult {
            analyzer_name: "impact".to_string(),
            threat_score: score.min(100.0),
            patterns: patterns_found,
            metadata: serde_json::json!({
                "mitre_attack": ["T1485", "T1486", "T1490"],
                "category": "impact"
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

impl Default for ImpactAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_destruction() {
        let analyzer = ImpactAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "rm -rf /var/lib/important_data".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 90.0);
    }

    #[test]
    fn test_ransomware() {
        let analyzer = ImpactAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "find . -type f -exec openssl enc -aes-256-cbc -in {} -out {}.encrypted \\;".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 90.0);
    }

    #[test]
    fn test_cryptomining() {
        let analyzer = ImpactAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "xmrig -o pool.minexmr.com:4444".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 90.0);
    }

    #[test]
    fn test_safe_operations() {
        let analyzer = ImpactAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "ls -la".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert_eq!(result.threat_score, 0.0);
    }
}
