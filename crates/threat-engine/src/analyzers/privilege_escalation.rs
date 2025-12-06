/// Privilege Escalation Detection - Detects attempts to gain elevated privileges
///
/// Identifies MITRE ATT&CK T1548 (Abuse Elevation Control Mechanism) patterns:
/// - sudo/su usage
/// - setuid/setgid manipulation
/// - Permission changes (chmod, chown)
/// - UAC bypass attempts
/// - Container escape attempts

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct PrivilegeEscalationAnalyzer {
    sudo_patterns: Vec<&'static str>,
    permission_patterns: Vec<&'static str>,
    setuid_patterns: Vec<&'static str>,
    container_escape: Vec<&'static str>,
}

impl PrivilegeEscalationAnalyzer {
    pub fn new() -> Self {
        Self {
            sudo_patterns: vec![
                "sudo su",
                "sudo -i",
                "sudo bash",
                "sudo sh",
                "sudo /bin/bash",
                "sudo /bin/sh",
                "su -",
                "su root",
                "doas",           // OpenBSD sudo alternative
                "pkexec",         // PolicyKit
            ],
            permission_patterns: vec![
                "chmod 777",
                "chmod +s",
                "chmod 4755",
                "chmod u+s",
                "chmod g+s",
                "chown root",
                "chgrp root",
                "setcap",         // Linux capabilities
            ],
            setuid_patterns: vec![
                "setuid",
                "setgid",
                "chmod +s",
                "chmod 4",
                "chmod 2",        // SGID
                "find / -perm",
                "find / -user root -perm",
                "find . -perm -4000",
            ],
            container_escape: vec![
                "docker run --privileged",
                "docker run -v /:/host",
                "docker run --pid=host",
                "docker run --net=host",
                "kubectl exec",
                "nsenter",
                "unshare",
                "chroot",
                "capsh",          // Capability shell
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "privilege_escalation".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for sudo escalation
        for &pattern in &self.sudo_patterns {
            if content_lower.contains(pattern) {
                patterns_found.push(format!("Privilege escalation via sudo: {}", pattern));
                score += 85.0;
                break;
            }
        }

        // Check for permission manipulation
        for &pattern in &self.permission_patterns {
            if content_lower.contains(pattern) {
                patterns_found.push(format!("Dangerous permission change: {}", pattern));
                score += 80.0;
                break;
            }
        }

        // Check for setuid/setgid patterns
        for &pattern in &self.setuid_patterns {
            if content_lower.contains(pattern) {
                patterns_found.push(format!("SUID/SGID manipulation: {}", pattern));
                score += 90.0;
                break;
            }
        }

        // Check for container escape
        for &pattern in &self.container_escape {
            if content_lower.contains(pattern) {
                patterns_found.push(format!("Container escape attempt: {}", pattern));
                score += 95.0;
                break;
            }
        }

        // Check for specific dangerous combinations
        if content_lower.contains("sudo") && content_lower.contains("chmod") {
            patterns_found.push("Sudo + chmod combination (privilege elevation)".to_string());
            score += 75.0;
        }

        if content_lower.contains("sudo") && content_lower.contains("/etc/sudoers") {
            patterns_found.push("Critical: Attempting to modify sudoers file".to_string());
            score += 100.0;
        }

        if content_lower.contains("find") && content_lower.contains("-perm") && content_lower.contains("4000") {
            patterns_found.push("Searching for SUID binaries (privilege escalation recon)".to_string());
            score += 70.0;
        }

        // Check for password file access with sudo
        if content_lower.contains("sudo") &&
           (content_lower.contains("/etc/shadow") || content_lower.contains("/etc/passwd")) {
            patterns_found.push("Sudo access to password files".to_string());
            score += 90.0;
        }

        // Metadata
        let metadata = serde_json::json!({
            "pattern_count": patterns_found.len(),
            "mitre_technique": "T1548", // Abuse Elevation Control Mechanism
        });

        AnalyzerResult {
            analyzer_name: "privilege_escalation".to_string(),
            threat_score: score.min(100.0),
            patterns: patterns_found,
            metadata,
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
            MCPToolCall::Filesystem { path, .. } => path.clone(),
            MCPToolCall::Network { url, .. } => url.clone(),
            MCPToolCall::Database { query, .. } => query.clone(),
            MCPToolCall::Unknown { params, .. } => {
                serde_json::to_string(params).unwrap_or_default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_sudo_escalation() {
        let analyzer = PrivilegeEscalationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "sudo".to_string(),
            args: vec!["bash".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 85.0, "Sudo escalation should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("sudo")));
    }

    #[test]
    fn test_chmod_777() {
        let analyzer = PrivilegeEscalationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "chmod".to_string(),
            args: vec!["777".to_string(), "/bin/bash".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 80.0, "chmod 777 should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("permission")));
    }

    #[test]
    fn test_setuid_manipulation() {
        let analyzer = PrivilegeEscalationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "chmod".to_string(),
            args: vec!["+s".to_string(), "/tmp/exploit".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 90.0, "SUID manipulation should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("SUID")));
    }

    #[test]
    fn test_container_escape() {
        let analyzer = PrivilegeEscalationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "docker".to_string(),
            args: vec!["run".to_string(), "--privileged".to_string(), "alpine".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 95.0, "Container escape should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Container escape")));
    }

    #[test]
    fn test_sudoers_modification() {
        let analyzer = PrivilegeEscalationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "sudo".to_string(),
            args: vec!["vi".to_string(), "/etc/sudoers".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 100.0, "Sudoers modification should score maximum, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("sudoers")));
    }

    #[test]
    fn test_suid_binary_search() {
        let analyzer = PrivilegeEscalationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "find".to_string(),
            args: vec!["/".to_string(), "-perm".to_string(), "-4000".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 70.0, "SUID binary search should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("SUID binaries")));
    }

    #[test]
    fn test_no_false_positives() {
        let analyzer = PrivilegeEscalationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score < 10.0, "Normal command should not score, got {}", result.threat_score);
        assert!(result.patterns.is_empty());
    }
}
