/// Lateral Movement Detection - Detects attempts to move within networks
///
/// Identifies MITRE ATT&CK T1021 (Remote Services) patterns:
/// - SSH to internal hosts
/// - RDP connections
/// - Internal network scanning
/// - Credential reuse across systems
/// - Service exploitation for lateral access

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct LateralMovementAnalyzer {
    ssh_patterns: Vec<&'static str>,
    rdp_patterns: Vec<&'static str>,
    internal_network_patterns: Vec<&'static str>,
    pivot_patterns: Vec<&'static str>,
}

impl LateralMovementAnalyzer {
    pub fn new() -> Self {
        Self {
            ssh_patterns: vec![
                "ssh ",
                "ssh root@",
                "ssh -i",
                "ssh-copy-id",
                "scp ",
                "rsync -e ssh",
            ],
            rdp_patterns: vec![
                "rdp",
                "mstsc",
                "xfreerdp",
                "rdesktop",
                "3389",
            ],
            internal_network_patterns: vec![
                "10.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "192.168.",
                "localhost",
                "127.0.0.1",
            ],
            pivot_patterns: vec![
                "proxychains",
                "ssh -D",
                "ssh -L",
                "ssh -R",
                "chisel",
                "ligolo",
                "port forward",
                "tunnel",
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "lateral_movement".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for SSH to internal networks
        let has_ssh = self.ssh_patterns.iter().any(|&p| content_lower.contains(p));
        let has_internal_ip = self.internal_network_patterns.iter().any(|&p| content_lower.contains(p));

        if has_ssh && has_internal_ip {
            patterns_found.push("SSH connection to internal network detected".to_string());
            score += 75.0;
        } else if has_ssh {
            patterns_found.push("SSH connection detected".to_string());
            score += 45.0;
        }

        // Check for RDP
        for &pattern in &self.rdp_patterns {
            if content_lower.contains(pattern) {
                patterns_found.push(format!("RDP/Remote Desktop pattern: {}", pattern));
                score += 70.0;
                break;
            }
        }

        // Check for pivoting/tunneling
        for &pattern in &self.pivot_patterns {
            if content_lower.contains(pattern) {
                patterns_found.push(format!("Network pivoting/tunneling: {}", pattern));
                score += 85.0;
                break;
            }
        }

        // Check for SSH with private key (potential credential reuse)
        if content_lower.contains("ssh") && content_lower.contains("-i") {
            patterns_found.push("SSH with private key (potential credential reuse)".to_string());
            score += 65.0;
        }

        // Check for multiple internal hosts
        let internal_count = self.internal_network_patterns.iter()
            .filter(|&&p| content_lower.matches(p).count() > 0)
            .count();

        if internal_count >= 2 {
            patterns_found.push(format!("Multiple internal network references ({} patterns)", internal_count));
            score += 60.0;
        }

        // Check for scp/rsync to internal hosts (file transfer = potential lateral movement)
        if (content_lower.contains("scp") || content_lower.contains("rsync")) && has_internal_ip {
            patterns_found.push("File transfer to internal host".to_string());
            score += 70.0;
        }

        // Check for SSH port forwarding
        if content_lower.contains("ssh") &&
           (content_lower.contains("-l") || content_lower.contains("-r") || content_lower.contains("-d")) {
            patterns_found.push("SSH port forwarding (potential pivoting)".to_string());
            score += 80.0;
        }

        // Check for network scanning of internal ranges
        if (content_lower.contains("nmap") || content_lower.contains("masscan")) && has_internal_ip {
            patterns_found.push("Internal network scanning (reconnaissance for lateral movement)".to_string());
            score += 75.0;
        }

        // Metadata
        let metadata = serde_json::json!({
            "pattern_count": patterns_found.len(),
            "has_internal_network": has_internal_ip,
            "has_ssh": has_ssh,
            "mitre_technique": "T1021", // Remote Services
        });

        AnalyzerResult {
            analyzer_name: "lateral_movement".to_string(),
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
    fn test_ssh_to_internal_host() {
        let analyzer = LateralMovementAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "ssh".to_string(),
            args: vec!["user@192.168.1.50".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 75.0, "SSH to internal host should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("internal network")));
    }

    #[test]
    fn test_ssh_port_forwarding() {
        let analyzer = LateralMovementAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "ssh".to_string(),
            args: vec!["-L".to_string(), "8080:localhost:80".to_string(), "user@server".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 80.0, "SSH port forwarding should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("port forwarding")));
    }

    #[test]
    fn test_rdp_connection() {
        let analyzer = LateralMovementAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "xfreerdp".to_string(),
            args: vec!["/v:192.168.1.100".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 70.0, "RDP connection should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("RDP")));
    }

    #[test]
    fn test_network_pivoting() {
        let analyzer = LateralMovementAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "proxychains".to_string(),
            args: vec!["nmap".to_string(), "192.168.1.0/24".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 85.0, "Network pivoting should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("pivoting") || p.contains("tunneling")));
    }

    #[test]
    fn test_scp_to_internal_host() {
        let analyzer = LateralMovementAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "scp".to_string(),
            args: vec!["file.txt".to_string(), "user@10.0.1.50:/tmp/".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 70.0, "SCP to internal host should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("File transfer")));
    }

    #[test]
    fn test_internal_network_scan() {
        let analyzer = LateralMovementAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-sS".to_string(), "192.168.0.0/16".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 75.0, "Internal network scan should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Internal network scanning")));
    }

    #[test]
    fn test_no_false_positives() {
        let analyzer = LateralMovementAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "git".to_string(),
            args: vec!["clone".to_string(), "https://github.com/user/repo.git".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score < 30.0, "Normal git command should not score high, got {}", result.threat_score);
    }
}
