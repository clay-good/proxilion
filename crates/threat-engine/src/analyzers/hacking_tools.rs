/// Hacking Tools Detection - Detects use of common penetration testing and attack tools
///
/// Identifies well-known security tools that are often used maliciously:
/// - Network scanners (nmap, masscan, zmap)
/// - Vulnerability scanners (nikto, sqlmap, wpscan)
/// - Password crackers (john, hashcat, hydra)
/// - Exploitation frameworks (metasploit, empire, covenant)
/// - Post-exploitation tools (mimikatz, bloodhound, impacket)

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct HackingToolsAnalyzer {
    network_scanners: Vec<&'static str>,
    vuln_scanners: Vec<&'static str>,
    password_crackers: Vec<&'static str>,
    exploit_frameworks: Vec<&'static str>,
    post_exploit_tools: Vec<&'static str>,
    cloud_exploit_tools: Vec<&'static str>,
}

impl HackingToolsAnalyzer {
    pub fn new() -> Self {
        Self {
            network_scanners: vec![
                "nmap",
                "masscan",
                "zmap",
                "unicornscan",
                "angry ip scanner",
                "zenmap",
            ],
            vuln_scanners: vec![
                "nikto",
                "sqlmap",
                "wpscan",
                "dirb",
                "dirbuster",
                "gobuster",
                "ffuf",
                "nuclei",
                "nessus",
                "openvas",
                "burp suite",
                "burpsuite",
                "zaproxy",
                "wfuzz",
            ],
            password_crackers: vec![
                "john",
                "hashcat",
                "hydra",
                "medusa",
                "ncrack",
                "ophcrack",
                "aircrack",
                "fcrackzip",
            ],
            exploit_frameworks: vec![
                "metasploit",
                "msfconsole",
                "msfvenom",
                "empire",
                "covenant",
                "cobalt strike",
                "cobaltstrike",
                "powershell empire",
                "sliver",
            ],
            post_exploit_tools: vec![
                "mimikatz",
                "bloodhound",
                "sharphound",
                "impacket",
                "crackmapexec",
                "evil-winrm",
                "powersploit",
                "rubeus",
                "kerberoast",
                "secretsdump",
            ],
            cloud_exploit_tools: vec![
                "pacu",
                "cloudgoat",
                "prowler",
                "scoutsuite",
                "cloudsploit",
                "gcp-scanner",
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "hacking_tools".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();
        let mut tool_categories = Vec::new();

        // Check for network scanners (High - 80 points)
        for &tool in &self.network_scanners {
            if content_lower.contains(tool) {
                patterns_found.push(format!("Network scanner detected: {}", tool));
                score += 80.0;
                tool_categories.push("network_scanner");
                break;
            }
        }

        // Check for vulnerability scanners (Critical - 90 points)
        for &tool in &self.vuln_scanners {
            if content_lower.contains(tool) {
                patterns_found.push(format!("Vulnerability scanner detected: {}", tool));
                score += 90.0;
                tool_categories.push("vuln_scanner");
                break;
            }
        }

        // Check for password crackers (Critical - 95 points)
        for &tool in &self.password_crackers {
            if content_lower.contains(tool) {
                patterns_found.push(format!("Password cracker detected: {}", tool));
                score += 95.0;
                tool_categories.push("password_cracker");
                break;
            }
        }

        // Check for exploitation frameworks (Critical - 100 points)
        for &tool in &self.exploit_frameworks {
            if content_lower.contains(tool) {
                patterns_found.push(format!("Exploitation framework detected: {}", tool));
                score += 100.0;
                tool_categories.push("exploit_framework");
                break;
            }
        }

        // Check for post-exploitation tools (Critical - 95 points)
        for &tool in &self.post_exploit_tools {
            if content_lower.contains(tool) {
                patterns_found.push(format!("Post-exploitation tool detected: {}", tool));
                score += 95.0;
                tool_categories.push("post_exploit");
                break;
            }
        }

        // Check for cloud exploitation tools (High - 85 points)
        for &tool in &self.cloud_exploit_tools {
            if content_lower.contains(tool) {
                patterns_found.push(format!("Cloud exploitation tool detected: {}", tool));
                score += 85.0;
                tool_categories.push("cloud_exploit");
                break;
            }
        }

        // Check for multiple tool categories (indicates sophisticated attack)
        if tool_categories.len() >= 2 {
            patterns_found.push(format!("Multiple attack tool categories detected ({} types)", tool_categories.len()));
            score += 50.0;
        }

        // Metadata
        let metadata = serde_json::json!({
            "pattern_count": patterns_found.len(),
            "tool_categories": tool_categories,
            "mitre_tactics": self.map_to_mitre(&tool_categories),
        });

        AnalyzerResult {
            analyzer_name: "hacking_tools".to_string(),
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

    fn map_to_mitre(&self, categories: &[&str]) -> Vec<&'static str> {
        let mut tactics = Vec::new();
        for &category in categories {
            match category {
                "network_scanner" => tactics.push("TA0043"), // Reconnaissance
                "vuln_scanner" => tactics.push("TA0043"),    // Reconnaissance
                "password_cracker" => tactics.push("TA0006"), // Credential Access
                "exploit_framework" => {
                    tactics.push("TA0001"); // Initial Access
                    tactics.push("TA0002"); // Execution
                }
                "post_exploit" => {
                    tactics.push("TA0004"); // Privilege Escalation
                    tactics.push("TA0007"); // Discovery
                }
                "cloud_exploit" => tactics.push("TA0007"), // Discovery
                _ => {}
            }
        }
        tactics.sort();
        tactics.dedup();
        tactics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_nmap_detection() {
        let analyzer = HackingToolsAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-sS".to_string(), "192.168.1.0/24".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 80.0, "nmap should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Network scanner")));
    }

    #[test]
    fn test_sqlmap_detection() {
        let analyzer = HackingToolsAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "sqlmap".to_string(),
            args: vec!["-u".to_string(), "http://target.com".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 90.0, "sqlmap should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Vulnerability scanner")));
    }

    #[test]
    fn test_metasploit_detection() {
        let analyzer = HackingToolsAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "msfconsole".to_string(),
            args: vec![],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 100.0, "metasploit should score maximum, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Exploitation framework")));
    }

    #[test]
    fn test_mimikatz_detection() {
        let analyzer = HackingToolsAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "mimikatz".to_string(),
            args: vec!["sekurlsa::logonpasswords".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 95.0, "mimikatz should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Post-exploitation")));
    }

    #[test]
    fn test_hydra_detection() {
        let analyzer = HackingToolsAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "hydra".to_string(),
            args: vec!["-l".to_string(), "admin".to_string(), "-P".to_string(), "wordlist.txt".to_string(), "ssh://target".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 95.0, "hydra should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Password cracker")));
    }

    #[test]
    fn test_multiple_tools() {
        let analyzer = HackingToolsAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-sV".to_string(), "target".to_string(), "&&".to_string(), "sqlmap".to_string(), "-u".to_string(), "http://target".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 90.0, "Multiple tools should score very high, got {}", result.threat_score);
        assert!(result.patterns.len() >= 2, "Should detect multiple tool categories");
    }

    #[test]
    fn test_no_false_positives() {
        let analyzer = HackingToolsAnalyzer::new();

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
