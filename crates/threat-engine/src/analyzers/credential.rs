//! Credential Analyzer - Detects credential harvesting and exfiltration
//!
//! Ported from Proxilion v2 POC and adapted for MCP protocol.
//! Detects: .env files, API keys, SSH keys, cloud credentials, secrets

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;
use regex::Regex;
use std::collections::HashMap;

pub struct CredentialAnalyzer {
    credential_patterns: Vec<CredentialPattern>,
    sensitive_files: Vec<SensitiveFile>,
    cloud_providers: Vec<CloudProvider>,
}

#[derive(Debug, Clone)]
struct CredentialPattern {
    name: &'static str,
    regex: Regex,
    severity: f64, // 0-100
    entropy_threshold: Option<f64>,
}

#[derive(Debug, Clone)]
struct SensitiveFile {
    path: &'static str,
    severity: f64, // 0-100
    category: FileCategory,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FileCategory {
    EnvironmentFile,
    CloudCredentials,
    SSHKeys,
    DatabaseConfig,
    APIKeys,
    CertificatesKeys,
    SystemSecrets,
}

#[derive(Debug, Clone)]
struct CloudProvider {
    name: &'static str,
    key_pattern: Regex,
    secret_pattern: Option<Regex>,
}

impl CredentialAnalyzer {
    pub fn new() -> Self {
        Self {
            credential_patterns: vec![
                CredentialPattern {
                    name: "password_assignment",
                    regex: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([^'"\s]{8,})['"]?"#)
                        .unwrap(),
                    severity: 60.0,
                    entropy_threshold: Some(3.5),
                },
                CredentialPattern {
                    name: "api_key",
                    regex: Regex::new(
                        r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#,
                    )
                    .unwrap(),
                    severity: 75.0,
                    entropy_threshold: Some(4.0),
                },
                CredentialPattern {
                    name: "secret_token",
                    regex: Regex::new(
                        r#"(?i)(secret|token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#,
                    )
                    .unwrap(),
                    severity: 70.0,
                    entropy_threshold: Some(4.0),
                },
                CredentialPattern {
                    name: "access_key",
                    regex: Regex::new(
                        r#"(?i)(access[_-]?key|accesskey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"#,
                    )
                    .unwrap(),
                    severity: 75.0,
                    entropy_threshold: Some(3.8),
                },
                CredentialPattern {
                    name: "private_key",
                    regex: Regex::new(
                        r#"-----BEGIN (RSA|OPENSSH|PRIVATE|EC|DSA) (PRIVATE )?KEY-----"#,
                    )
                    .unwrap(),
                    severity: 90.0,
                    entropy_threshold: None, // Keys have inherent high entropy
                },
                CredentialPattern {
                    name: "bearer_token",
                    regex: Regex::new(r#"(?i)bearer\s+([a-z0-9\-._~+/]+=*)"#).unwrap(),
                    severity: 65.0,
                    entropy_threshold: Some(4.0),
                },
                CredentialPattern {
                    name: "jwt_token",
                    regex: Regex::new(r#"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"#)
                        .unwrap(),
                    severity: 70.0,
                    entropy_threshold: None, // JWTs are structured
                },
                CredentialPattern {
                    name: "database_url",
                    regex: Regex::new(r#"(?i)(mongodb|mysql|postgresql|redis)://[^:]+:[^@]+@"#)
                        .unwrap(),
                    severity: 80.0,
                    entropy_threshold: None,
                },
            ],
            sensitive_files: vec![
                SensitiveFile {
                    path: ".env",
                    severity: 70.0,
                    category: FileCategory::EnvironmentFile,
                },
                SensitiveFile {
                    path: ".env.local",
                    severity: 70.0,
                    category: FileCategory::EnvironmentFile,
                },
                SensitiveFile {
                    path: ".env.production",
                    severity: 85.0,
                    category: FileCategory::EnvironmentFile,
                },
                SensitiveFile {
                    path: ".env.staging",
                    severity: 75.0,
                    category: FileCategory::EnvironmentFile,
                },
                SensitiveFile {
                    path: "credentials.json",
                    severity: 80.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: "credentials.yml",
                    severity: 80.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: "credentials.yaml",
                    severity: 80.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: ".aws/credentials",
                    severity: 90.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: ".aws/config",
                    severity: 75.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: ".azure/credentials",
                    severity: 90.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: ".gcp/credentials.json",
                    severity: 90.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: "gcloud/credentials.db",
                    severity: 85.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: ".ssh/id_rsa",
                    severity: 95.0,
                    category: FileCategory::SSHKeys,
                },
                SensitiveFile {
                    path: ".ssh/id_ed25519",
                    severity: 95.0,
                    category: FileCategory::SSHKeys,
                },
                SensitiveFile {
                    path: ".ssh/id_ecdsa",
                    severity: 95.0,
                    category: FileCategory::SSHKeys,
                },
                SensitiveFile {
                    path: ".ssh/id_dsa",
                    severity: 90.0,
                    category: FileCategory::SSHKeys,
                },
                SensitiveFile {
                    path: ".ssh/authorized_keys",
                    severity: 80.0,
                    category: FileCategory::SSHKeys,
                },
                SensitiveFile {
                    path: "database.yml",
                    severity: 75.0,
                    category: FileCategory::DatabaseConfig,
                },
                SensitiveFile {
                    path: "database.yaml",
                    severity: 75.0,
                    category: FileCategory::DatabaseConfig,
                },
                SensitiveFile {
                    path: "db.config",
                    severity: 70.0,
                    category: FileCategory::DatabaseConfig,
                },
                SensitiveFile {
                    path: "config/database.yml",
                    severity: 75.0,
                    category: FileCategory::DatabaseConfig,
                },
                SensitiveFile {
                    path: ".git/config",
                    severity: 60.0,
                    category: FileCategory::SystemSecrets,
                },
                SensitiveFile {
                    path: ".git-credentials",
                    severity: 85.0,
                    category: FileCategory::SystemSecrets,
                },
                SensitiveFile {
                    path: ".netrc",
                    severity: 80.0,
                    category: FileCategory::SystemSecrets,
                },
                SensitiveFile {
                    path: "secrets.yml",
                    severity: 85.0,
                    category: FileCategory::SystemSecrets,
                },
                SensitiveFile {
                    path: "secrets.yaml",
                    severity: 85.0,
                    category: FileCategory::SystemSecrets,
                },
                SensitiveFile {
                    path: "secrets.json",
                    severity: 85.0,
                    category: FileCategory::SystemSecrets,
                },
                SensitiveFile {
                    path: ".npmrc",
                    severity: 70.0,
                    category: FileCategory::APIKeys,
                },
                SensitiveFile {
                    path: ".pypirc",
                    severity: 70.0,
                    category: FileCategory::APIKeys,
                },
                SensitiveFile {
                    path: ".dockercfg",
                    severity: 75.0,
                    category: FileCategory::APIKeys,
                },
                SensitiveFile {
                    path: ".docker/config.json",
                    severity: 75.0,
                    category: FileCategory::APIKeys,
                },
                SensitiveFile {
                    path: "kubeconfig",
                    severity: 85.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: ".kube/config",
                    severity: 85.0,
                    category: FileCategory::CloudCredentials,
                },
                SensitiveFile {
                    path: "cert.pem",
                    severity: 70.0,
                    category: FileCategory::CertificatesKeys,
                },
                SensitiveFile {
                    path: "privkey.pem",
                    severity: 95.0,
                    category: FileCategory::CertificatesKeys,
                },
                SensitiveFile {
                    path: "server.key",
                    severity: 90.0,
                    category: FileCategory::CertificatesKeys,
                },
            ],
            cloud_providers: vec![
                CloudProvider {
                    name: "AWS",
                    key_pattern: Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
                    // More specific AWS secret pattern with context to reduce false positives
                    secret_pattern: Some(Regex::new(r#"(?i)(?:aws[_-]?)?secret[_-]?(?:access[_-]?)?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"#).unwrap()),
                },
                CloudProvider {
                    name: "Google Cloud",
                    key_pattern: Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#).unwrap(),
                    secret_pattern: None,
                },
                CloudProvider {
                    name: "Azure",
                    // More specific Azure pattern with context to avoid false positives on UUIDs
                    key_pattern: Regex::new(
                        r#"(?i)(?:azure[_-]?)?(?:client[_-]?)?(?:secret|key|password)[\"']?\s*[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?"#,
                    )
                    .unwrap(),
                    secret_pattern: None,
                },
                CloudProvider {
                    name: "GitHub",
                    key_pattern: Regex::new(r#"ghp_[a-zA-Z0-9]{36}"#).unwrap(),
                    secret_pattern: None,
                },
                CloudProvider {
                    name: "GitLab",
                    key_pattern: Regex::new(r#"glpat-[a-zA-Z0-9\-_]{20}"#).unwrap(),
                    secret_pattern: None,
                },
                CloudProvider {
                    name: "Slack",
                    key_pattern: Regex::new(
                        r#"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}"#,
                    )
                    .unwrap(),
                    secret_pattern: None,
                },
                CloudProvider {
                    name: "Stripe",
                    key_pattern: Regex::new(r#"sk_live_[0-9a-zA-Z]{24}"#).unwrap(),
                    secret_pattern: None,
                },
            ],
        }
    }

    /// Calculate Shannon entropy of a string
    /// High entropy (>4.0) indicates randomness typical of real credentials
    fn calculate_entropy(data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = HashMap::new();
        for byte in data.bytes() {
            *frequency.entry(byte).or_insert(0) += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in frequency.values() {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    /// Detect cloud provider credentials in content
    fn detect_cloud_credentials(&self, content: &str) -> Vec<(String, f64)> {
        let mut detections = Vec::new();

        for provider in &self.cloud_providers {
            if provider.key_pattern.is_match(content) {
                detections.push((format!("{} credential detected", provider.name), 85.0));

                // Check for paired secret if pattern exists
                if let Some(ref secret_pattern) = provider.secret_pattern {
                    if secret_pattern.is_match(content) {
                        detections.push((
                            format!("{} key-secret pair detected", provider.name),
                            95.0,
                        ));
                    }
                }
            }
        }

        detections
    }

    /// Detect credential patterns with entropy validation
    fn detect_credential_patterns(&self, content: &str) -> Vec<(String, f64)> {
        let mut detections = Vec::new();

        for pattern in &self.credential_patterns {
            if let Some(captures) = pattern.regex.captures(content) {
                // Check entropy if threshold is set
                let entropy_valid = if let Some(threshold) = pattern.entropy_threshold {
                    // Try to get the captured credential value (group 2 if it exists)
                    if let Some(credential) = captures.get(2) {
                        let entropy = Self::calculate_entropy(credential.as_str());
                        entropy >= threshold
                    } else {
                        true // No specific capture group, validate by pattern match alone
                    }
                } else {
                    true // No entropy threshold
                };

                if entropy_valid {
                    detections.push((format!("{} pattern matched", pattern.name), pattern.severity));
                }
            }
        }

        detections
    }

    /// Check if a file path is sensitive
    fn check_sensitive_file(&self, file_path: &str) -> Option<(String, f64, FileCategory)> {
        let file_lower = file_path.to_lowercase();

        for sensitive in &self.sensitive_files {
            if file_lower.contains(sensitive.path) {
                return Some((
                    format!("Sensitive file accessed: {} ({:?})", file_path, sensitive.category),
                    sensitive.severity,
                    sensitive.category.clone(),
                ));
            }
        }

        None
    }

    /// Analyze a single MCP tool call for credential access patterns
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

                // Check for credential patterns in command arguments
                let credential_detections = self.detect_credential_patterns(&full_command);
                for (pattern, severity) in credential_detections {
                    patterns.push(pattern);
                    max_severity = f64::max(max_severity, severity);
                }

                // Check for cloud credentials in command
                let cloud_detections = self.detect_cloud_credentials(&full_command);
                for (pattern, severity) in cloud_detections {
                    patterns.push(pattern);
                    max_severity = f64::max(max_severity, severity);
                }

                // Check for sensitive file access in commands (cat, grep, less, tail, head, etc.)
                let file_commands = ["cat", "grep", "less", "tail", "head", "more", "vim", "nano", "emacs"];
                let is_file_command = file_commands.iter().any(|&cmd| command == cmd || full_command.starts_with(&format!("{} ", cmd)));

                // Also check command alone without args (e.g., "cat .env")
                if is_file_command || file_commands.contains(&command.as_str()) {
                    // Extract potential file paths from arguments
                    for arg in args {
                        if let Some((pattern, severity, category)) = self.check_sensitive_file(arg) {
                            patterns.push(pattern);
                            max_severity = f64::max(max_severity, severity);
                            metadata.insert("file_category".to_string(), serde_json::json!(format!("{:?}", category)));
                        }
                    }

                    // Also check if command itself contains filename (for merged command strings)
                    if let Some((pattern, severity, category)) = self.check_sensitive_file(&full_command) {
                        if !patterns.contains(&pattern) {  // Avoid duplicates
                            patterns.push(pattern);
                            max_severity = f64::max(max_severity, severity);
                            metadata.insert("file_category".to_string(), serde_json::json!(format!("{:?}", category)));
                        }
                    }
                }

                // Check for credential dumping commands
                let dump_patterns = [
                    ("env", "Environment variable dump detected", 65.0),
                    ("printenv", "Environment variable dump detected", 65.0),
                    ("export", "Environment export detected", 60.0),
                    ("echo $", "Environment variable access detected", 55.0),
                ];

                for (dump_cmd, pattern_name, severity) in dump_patterns {
                    if full_command.contains(dump_cmd) {
                        patterns.push(pattern_name.to_string());
                        max_severity = f64::max(max_severity, severity);
                        break;
                    }
                }
            }

            MCPToolCall::Filesystem { operation, path, content } => {
                metadata.insert("path".to_string(), serde_json::json!(path));
                metadata.insert("operation".to_string(), serde_json::json!(format!("{:?}", operation)));

                // Check if accessing sensitive file
                if let Some((pattern, severity, category)) = self.check_sensitive_file(path) {
                    patterns.push(pattern);
                    max_severity = f64::max(max_severity, severity);
                    metadata.insert("file_category".to_string(), serde_json::json!(format!("{:?}", category)));
                }

                // If reading/writing content, check for credentials in content
                if let Some(content_bytes) = content {
                    if let Ok(content_str) = String::from_utf8(content_bytes.clone()) {
                        // Limit analysis to first 50KB to avoid performance issues
                        // Use character-aware truncation to avoid panic on UTF-8 boundaries
                        let analyzed_content: String = if content_str.len() > 50000 {
                            content_str.chars().take(50000).collect()
                        } else {
                            content_str.clone()
                        };

                        // Check for credential patterns
                        let credential_detections = self.detect_credential_patterns(&analyzed_content);
                        for (pattern, severity) in credential_detections {
                            patterns.push(pattern);
                            max_severity = f64::max(max_severity, severity);
                        }

                        // Check for cloud credentials
                        let cloud_detections = self.detect_cloud_credentials(&analyzed_content);
                        for (pattern, severity) in cloud_detections {
                            patterns.push(pattern);
                            max_severity = f64::max(max_severity, severity);
                        }
                    }
                }
            }

            MCPToolCall::Network { url, body, .. } => {
                metadata.insert("url".to_string(), serde_json::json!(url));

                // Check for credentials in URL (e.g., http://user:pass@host)
                if url.contains('@') && (url.contains("://") || url.contains(':')) {
                    patterns.push("Credentials embedded in URL".to_string());
                    max_severity = f64::max(max_severity, 75.0);
                }

                // Check request body for credentials
                if let Some(body_bytes) = body {
                    if let Ok(body_str) = String::from_utf8(body_bytes.clone()) {
                        let analyzed_body = if body_str.len() > 50000 {
                            &body_str[..50000]
                        } else {
                            &body_str
                        };

                        let credential_detections = self.detect_credential_patterns(analyzed_body);
                        for (pattern, severity) in credential_detections {
                            patterns.push(format!("{} in request body", pattern));
                            max_severity = f64::max(max_severity, severity);
                        }

                        let cloud_detections = self.detect_cloud_credentials(analyzed_body);
                        for (pattern, severity) in cloud_detections {
                            patterns.push(format!("{} in request body", pattern));
                            max_severity = f64::max(max_severity, severity);
                        }
                    }
                }
            }

            MCPToolCall::Database { query, .. } => {
                metadata.insert("query".to_string(), serde_json::json!(query));

                // Check for credential tables
                let credential_tables = ["users", "credentials", "api_keys", "secrets", "tokens", "auth"];
                let query_lower = query.to_lowercase();

                for table in credential_tables {
                    if query_lower.contains(table) && (query_lower.contains("select") || query_lower.contains("dump")) {
                        patterns.push(format!("Credential table query: {}", table));
                        max_severity = f64::max(max_severity, 70.0);
                        break;
                    }
                }

                // Check for password columns
                if query_lower.contains("password") || query_lower.contains("passwd") || query_lower.contains("pwd") {
                    patterns.push("Password column access detected".to_string());
                    max_severity = f64::max(max_severity, 75.0);
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
            analyzer_name: "credential".to_string(),
            threat_score: score,
            patterns,
            metadata: serde_json::json!(metadata),
        }
    }
}

impl Default for CredentialAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_file_access() {
        let analyzer = CredentialAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec![".env".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 70.0);
        assert!(result
            .patterns
            .iter()
            .any(|p| p.contains("Sensitive file accessed")));
    }

    #[test]
    fn test_aws_credentials_access() {
        let analyzer = CredentialAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec!["/home/user/.aws/credentials".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 90.0);
        assert!(result
            .patterns
            .iter()
            .any(|p| p.contains("CloudCredentials")));
    }

    #[test]
    fn test_ssh_key_access() {
        let analyzer = CredentialAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec!["/home/user/.ssh/id_rsa".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 95.0);
        assert!(result.patterns.iter().any(|p| p.contains("SSHKeys")));
    }

    #[test]
    fn test_safe_file_access() {
        let analyzer = CredentialAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec!["README.md".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert_eq!(result.threat_score, 0.0);
        assert!(result.patterns.is_empty());
    }

    #[test]
    fn test_env_dump() {
        let analyzer = CredentialAnalyzer::new();
        let tool_call = MCPToolCall::Bash {
            command: "env".to_string(),
            args: vec![],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 65.0);
        assert!(result
            .patterns
            .iter()
            .any(|p| p.contains("Environment variable dump")));
    }

    #[test]
    fn test_cloud_credential_detection() {
        let analyzer = CredentialAnalyzer::new();

        // AWS access key in command
        let tool_call = MCPToolCall::Bash {
            command: "echo".to_string(),
            args: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 85.0);
        assert!(result.patterns.iter().any(|p| p.contains("AWS credential")));
    }

    #[test]
    fn test_entropy_calculation() {
        // High entropy string (random)
        let high_entropy = "aB3xR9mK2pL7qN5jD8fG1hS4wE6yU0tI";
        assert!(CredentialAnalyzer::calculate_entropy(high_entropy) > 4.0);

        // Low entropy string (repetitive)
        let low_entropy = "aaaaaaaaaaaaaaaa";
        assert!(CredentialAnalyzer::calculate_entropy(low_entropy) < 1.0);

        // Medium entropy (word)
        let medium_entropy = "password";
        assert!(CredentialAnalyzer::calculate_entropy(medium_entropy) > 2.0);
        assert!(CredentialAnalyzer::calculate_entropy(medium_entropy) < 4.0);
    }
}
