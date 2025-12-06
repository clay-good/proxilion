//! Enumeration Analyzer - Detects reconnaissance and discovery attacks
//!
//! Ported from Proxilion v2 POC and adapted for MCP protocol.
//! Detects: nmap, masscan, directory brute-forcing, port scanning, etc.

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;
use regex::Regex;
use std::collections::HashMap;

pub struct EnumerationAnalyzer {
    ip_patterns: Vec<Regex>,
    cidr_pattern: Regex,
    recon_tools: Vec<ReconTool>,
    url_path_patterns: Vec<PathPattern>,
}

#[derive(Debug, Clone)]
struct ReconTool {
    name: &'static str,
    pattern: Regex,
    severity: f64,
    category: ToolCategory,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ToolCategory {
    NetworkScanner,
    PortScanner,
    DirectoryBrute,
    VulnScanner,
    ServiceDetection,
}

#[derive(Debug, Clone)]
struct PathPattern {
    name: &'static str,
    pattern: Regex,
    severity: f64,
}

impl EnumerationAnalyzer {
    pub fn new() -> Self {
        Self {
            // Better IPv4 pattern that validates octet ranges (0-255)
            ip_patterns: vec![
                Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
                Regex::new(r"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}").unwrap(), // IPv6
            ],
            // Pre-compile CIDR pattern to avoid panic in hot path
            cidr_pattern: Regex::new(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])").unwrap(),
            recon_tools: vec![
                ReconTool {
                    name: "nmap",
                    pattern: Regex::new(r"(?i)\bnmap\b").unwrap(),
                    severity: 85.0,
                    category: ToolCategory::NetworkScanner,
                },
                ReconTool {
                    name: "masscan",
                    pattern: Regex::new(r"(?i)\bmasscan\b").unwrap(),
                    severity: 90.0,
                    category: ToolCategory::PortScanner,
                },
                ReconTool {
                    name: "gobuster",
                    pattern: Regex::new(r"(?i)\bgobuster\b").unwrap(),
                    severity: 80.0,
                    category: ToolCategory::DirectoryBrute,
                },
                ReconTool {
                    name: "dirb",
                    pattern: Regex::new(r"(?i)\bdirb\b").unwrap(),
                    severity: 75.0,
                    category: ToolCategory::DirectoryBrute,
                },
                ReconTool {
                    name: "nikto",
                    pattern: Regex::new(r"(?i)\bnikto\b").unwrap(),
                    severity: 85.0,
                    category: ToolCategory::VulnScanner,
                },
                ReconTool {
                    name: "nuclei",
                    pattern: Regex::new(r"(?i)\bnuclei\b").unwrap(),
                    severity: 85.0,
                    category: ToolCategory::VulnScanner,
                },
                ReconTool {
                    name: "nslookup",
                    pattern: Regex::new(r"(?i)\bnslookup\b").unwrap(),
                    severity: 50.0,
                    category: ToolCategory::ServiceDetection,
                },
                ReconTool {
                    name: "dig",
                    pattern: Regex::new(r"(?i)\bdig\b").unwrap(),
                    severity: 50.0,
                    category: ToolCategory::ServiceDetection,
                },
                ReconTool {
                    name: "shodan",
                    pattern: Regex::new(r"(?i)\bshodan\b").unwrap(),
                    severity: 70.0,
                    category: ToolCategory::ServiceDetection,
                },
            ],
            // URL path patterns (for Network tool calls) - excludes legitimate API paths
            url_path_patterns: vec![
                PathPattern {
                    name: "directory_traversal",
                    pattern: Regex::new(r"\.\./|\.\.\\").unwrap(),
                    severity: 80.0,
                },
                PathPattern {
                    name: "admin_paths",
                    pattern: Regex::new(r"(?i)/(admin|phpmyadmin|wp-admin|cpanel|backup|\.git/)").unwrap(),
                    severity: 65.0,
                },
                PathPattern {
                    name: "sensitive_files",
                    pattern: Regex::new(r"(?i)(\.env|web\.config|phpinfo\.php|config\.php)").unwrap(),
                    severity: 75.0,
                },
            ],
        }
    }

    /// Analyze a single MCP tool call for enumeration patterns
    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let mut patterns = Vec::new();
        let mut metadata = HashMap::new();
        let mut max_severity = 0.0;

        match tool_call {
            MCPToolCall::Bash { command, args, .. } => {
                // Build full command string
                let full_command = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                };

                metadata.insert("command".to_string(), serde_json::json!(full_command.clone()));

                // Check for reconnaissance tools
                for tool in &self.recon_tools {
                    if tool.pattern.is_match(&full_command) {
                        patterns.push(format!("{} reconnaissance tool detected", tool.name));
                        max_severity = f64::max(max_severity, tool.severity);
                        metadata.insert(
                            "tool_detected".to_string(),
                            serde_json::json!(tool.name),
                        );
                        metadata.insert(
                            "tool_category".to_string(),
                            serde_json::json!(format!("{:?}", tool.category)),
                        );
                    }
                }

                // Check for IP addresses in command (indicates network scanning)
                if self.ip_patterns.iter().any(|p| p.is_match(&full_command)) {
                    patterns.push("IP address target detected".to_string());
                    max_severity = f64::max(max_severity, 70.0);
                }

                // Check for network range notation (e.g., 192.168.1.0/24) using pre-compiled regex
                if self.cidr_pattern.is_match(&full_command) {
                    patterns.push("Network range scanning detected".to_string());
                    max_severity = f64::max(max_severity, 90.0);
                }

                // Check for port scanning flags
                let port_scan_flags = ["-p", "--ports", "-sV", "-sS", "-sT", "-sU"];
                if port_scan_flags
                    .iter()
                    .any(|flag| full_command.contains(flag))
                {
                    patterns.push("Port scanning flags detected".to_string());
                    max_severity = f64::max(max_severity, 85.0);
                }
            }

            MCPToolCall::Network { method, url, .. } => {
                metadata.insert("url".to_string(), serde_json::json!(url));
                metadata.insert("method".to_string(), serde_json::json!(method));

                // Check for suspicious URL path patterns (using URL-specific patterns)
                for url_pattern in &self.url_path_patterns {
                    if url_pattern.pattern.is_match(url) {
                        patterns.push(format!("{} detected in URL", url_pattern.name));
                        max_severity = f64::max(max_severity, url_pattern.severity);
                    }
                }

                // Check for parameter fuzzing - fixed to only count if '?' exists
                if let Some(query_start) = url.find('?') {
                    let query_part = &url[query_start..];
                    let param_count = if query_part.len() > 1 {
                        query_part.matches('&').count() + 1
                    } else {
                        0
                    };
                    if param_count > 5 {
                        patterns.push(format!("Multiple parameters ({}) - possible fuzzing", param_count));
                        max_severity = f64::max(max_severity, 65.0);
                    }
                }
            }

            MCPToolCall::Filesystem { path, .. } => {
                metadata.insert("path".to_string(), serde_json::json!(path));

                // Check for path traversal
                if path.contains("..") {
                    patterns.push("Directory traversal attempt detected".to_string());
                    max_severity = f64::max(max_severity, 85.0);
                }

                // Check for sensitive file access
                let sensitive_patterns = [".env", ".git", "config", "credentials", "secrets"];
                if sensitive_patterns.iter().any(|p| path.contains(p)) {
                    patterns.push("Sensitive file access detected".to_string());
                    max_severity = f64::max(max_severity, 75.0);
                }
            }

            MCPToolCall::Database { query, .. } => {
                metadata.insert("query".to_string(), serde_json::json!(query));

                // Check for information schema queries (reconnaissance)
                if query.to_lowercase().contains("information_schema")
                    || query.to_lowercase().contains("show tables")
                    || query.to_lowercase().contains("show databases")
                {
                    patterns.push("Database enumeration detected".to_string());
                    max_severity = f64::max(max_severity, 80.0);
                }
            }

            _ => {}
        }

        // Calculate final score
        let score = if patterns.is_empty() {
            0.0
        } else {
            // Bonus for multiple pattern types
            let bonus = (patterns.len() as f64 - 1.0) * 5.0;
            (max_severity + bonus).min(100.0)
        };

        AnalyzerResult {
            analyzer_name: "enumeration".to_string(),
            threat_score: score,
            patterns,
            metadata: serde_json::json!(metadata),
        }
    }
}

impl Default for EnumerationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmap_detection() {
        let analyzer = EnumerationAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-sV".to_string(), "192.168.1.0/24".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score > 80.0);
        assert!(result.patterns.contains(&"nmap reconnaissance tool detected".to_string()));
        assert!(result.patterns.contains(&"Network range scanning detected".to_string()));
    }

    #[test]
    fn test_safe_command() {
        let analyzer = EnumerationAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert_eq!(result.threat_score, 0.0);
        assert!(result.patterns.is_empty());
    }

    #[test]
    fn test_directory_traversal() {
        let analyzer = EnumerationAnalyzer::new();
        let tool_call = MCPToolCall::Network {
            method: "GET".to_string(),
            url: "http://example.com/../../etc/passwd".to_string(),
            headers: HashMap::new(),
            body: None,
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score > 70.0);
        assert!(result.patterns.iter().any(|p| p.contains("traversal")));
    }
}
