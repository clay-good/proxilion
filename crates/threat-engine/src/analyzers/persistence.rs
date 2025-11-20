/// Persistence Detection - Detects attempts to maintain access
///
/// Identifies MITRE ATT&CK T1053, T1136, T1547 (Persistence) patterns:
/// - Cron job creation
/// - Startup script modification
/// - User account creation
/// - SSH key installation
/// - Backdoor installation

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct PersistenceAnalyzer {
    cron_patterns: Vec<&'static str>,
    startup_patterns: Vec<&'static str>,
    account_patterns: Vec<&'static str>,
    ssh_patterns: Vec<&'static str>,
    backdoor_patterns: Vec<&'static str>,
}

impl PersistenceAnalyzer {
    pub fn new() -> Self {
        Self {
            cron_patterns: vec![
                "crontab -e",
                "crontab -l",
                "*/etc/crontab",
                "*/etc/cron.d/",
                "/var/spool/cron",
                "@reboot",
                "* * * * *",
            ],
            startup_patterns: vec![
                "/etc/rc.local",
                "/etc/init.d/",
                "systemctl enable",
                ".bashrc",
                ".bash_profile",
                ".profile",
                "/etc/profile",
                "autostart",
                "launchd",
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
            ],
            account_patterns: vec![
                "useradd",
                "adduser",
                "usermod",
                "passwd",
                "/etc/passwd",
                "/etc/shadow",
                "net user /add",
                "New-LocalUser",
            ],
            ssh_patterns: vec![
                "authorized_keys",
                ".ssh/id_rsa",
                "ssh-keygen",
                "ssh-copy-id",
                "/root/.ssh",
                "StrictHostKeyChecking=no",
            ],
            backdoor_patterns: vec![
                "nc -l",
                "ncat -l",
                "socat",
                "mknod",
                "mkfifo",
                "/dev/tcp/",
                "bash -i",
                "sh -i",
                "python -c 'import socket",
                "perl -e",
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "persistence".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for cron job manipulation
        for &pattern in &self.cron_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Cron job manipulation: {}", pattern));
                score = score.max(85.0);
                break;
            }
        }

        // Check for startup script modification
        for &pattern in &self.startup_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Startup script modification: {}", pattern));
                score = score.max(80.0);
                break;
            }
        }

        // Check for account creation
        for &pattern in &self.account_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Account manipulation: {}", pattern));
                score = score.max(90.0);
                break;
            }
        }

        // Check for SSH key installation
        for &pattern in &self.ssh_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("SSH key installation: {}", pattern));
                score = score.max(88.0);
                break;
            }
        }

        // Check for backdoor patterns
        for &pattern in &self.backdoor_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Backdoor installation: {}", pattern));
                score = score.max(95.0);
                break;
            }
        }

        AnalyzerResult {
            analyzer_name: "persistence".to_string(),
            threat_score: score.min(100.0),
            patterns: patterns_found,
            metadata: serde_json::json!({
                "mitre_attack": ["T1053", "T1136", "T1547"],
                "category": "persistence"
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

impl Default for PersistenceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_detection() {
        let analyzer = PersistenceAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "echo '* * * * * /tmp/backdoor.sh' | crontab -".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 80.0);
        assert!(result.patterns.len() > 0);
    }

    #[test]
    fn test_ssh_key_installation() {
        let analyzer = PersistenceAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 80.0);
    }

    #[test]
    fn test_safe_operations() {
        let analyzer = PersistenceAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "ls -la".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);
        assert_eq!(result.threat_score, 0.0);
    }
}
