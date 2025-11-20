/// Hallucination Analyzer - Detects AI-generated fabrications and artifacts
///
/// Identifies AI hallucination patterns that may indicate GTG-1002 social engineering:
/// - Fabricated file paths, URLs, or resource references
/// - Overly confident assertions without verification
/// - AI-typical language patterns (definitely, certainly, guaranteed, etc.)
///
/// NOTE: This is a simplified stateless version. Full hallucination detection
/// with narrative consistency checking and pattern repetition requires session state.

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct HallucinationAnalyzer {
    fabricated_patterns: Vec<&'static str>,
    confidence_phrases: Vec<&'static str>,
    ai_typical_markers: Vec<&'static str>,
}

impl HallucinationAnalyzer {
    pub fn new() -> Self {
        Self {
            // Patterns that indicate fabricated/hallucinated content
            fabricated_patterns: vec![
                "example.com",
                "fake_",
                "dummy_",
                "test_file_that_doesnt_exist",
                "/tmp/nonexistent",
                "nonexistent-",
                "fake-callback",
                "http://localhost:99999",
                "placeholder",
                "sample_data",
                "mock_",
                "demo_file",
            ],
            // Overly confident AI phrases (indicates hallucination)
            confidence_phrases: vec![
                "definitely",
                "certainly",
                "absolutely",
                "without a doubt",
                "guaranteed to work",
                "100% certain",
                "always works",
                "never fails",
                "perfectly safe",
                "completely secure",
                "will definitely",
                "will certainly",
                "is guaranteed",
                "totally safe",
                "absolutely works",
            ],
            // AI-typical language markers
            ai_typical_markers: vec![
                "as an ai",
                "as a language model",
                "i cannot actually",
                "i don't actually have",
                "i'm an ai assistant",
                "i can't perform",
                "however, i should note",
                "it's important to understand",
                "let me explain",
                "to be clear",
                "it's worth noting",
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "hallucination".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Detect fabricated references
        let mut fabrication_count = 0;
        for &pattern in &self.fabricated_patterns {
            if content_lower.contains(pattern) {
                fabrication_count += 1;
                patterns_found.push(format!("Fabricated/hallucinated reference: {}", pattern));
                score += 40.0;
            }
        }

        if fabrication_count >= 3 {
            patterns_found.push(format!("Multiple fabricated references ({} detected) - likely AI hallucination", fabrication_count));
            score += 30.0;
        }

        // Detect overly confident AI assertions
        let mut confidence_count = 0;
        for &phrase in &self.confidence_phrases {
            if content_lower.contains(phrase) {
                confidence_count += 1;
                if confidence_count == 1 {
                    patterns_found.push(format!("Overly confident AI assertion: '{}'", phrase));
                }
                score += 25.0;
            }
        }

        if confidence_count >= 3 {
            patterns_found.push(format!("Multiple confidence markers ({}) - AI over-assertion pattern", confidence_count));
            score += 25.0;
        }

        // Detect AI self-identification (very suspicious in attack context)
        let mut ai_marker_count = 0;
        for &marker in &self.ai_typical_markers {
            if content_lower.contains(marker) {
                ai_marker_count += 1;
                patterns_found.push(format!("AI self-identification marker: '{}'", marker));
                score += 50.0; // High score - AI should not be self-identifying in tool calls
                break; // Only count once
            }
        }

        // Detect generic/template responses
        if self.is_template_response(&content_lower) {
            patterns_found.push("Generic template response (possible AI hallucination)".to_string());
            score += 30.0;
        }

        // Detect fabricated tool output patterns
        if self.is_fabricated_output(&content_lower) {
            patterns_found.push("Fabricated tool output detected (AI hallucination)".to_string());
            score += 60.0;
        }

        // Detect suspiciously perfect results
        if content_lower.contains("successfully exploited") && content.len() < 100 {
            patterns_found.push("Suspiciously brief 'success' message (likely hallucinated)".to_string());
            score += 55.0;
        }

        // Detect fabricated error-free execution claims
        if (content_lower.contains("command executed successfully")
            || content_lower.contains("operation completed successfully"))
            && !content_lower.contains("error")
            && content.len() < 60
        {
            patterns_found.push("Generic success message without details (hallucination indicator)".to_string());
            score += 45.0;
        }

        // Metadata
        let metadata = serde_json::json!({
            "fabrication_count": fabrication_count,
            "confidence_phrase_count": confidence_count,
            "ai_marker_count": ai_marker_count,
            "pattern_count": patterns_found.len(),
        });

        AnalyzerResult {
            analyzer_name: "hallucination".to_string(),
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

    /// Detect template-style responses that AI might generate
    fn is_template_response(&self, content: &str) -> bool {
        let template_patterns = [
            "command executed successfully",
            "operation completed",
            "successfully completed",
            "request was successful",
            "http/1.1 200 ok",
        ];

        let mut pattern_matches = 0;
        for pattern in &template_patterns {
            if content.contains(pattern) {
                pattern_matches += 1;
            }
        }

        // If content is short and contains template patterns, likely hallucinated
        pattern_matches > 0 && content.len() < 100
    }

    /// Detect fabricated tool output
    fn is_fabricated_output(&self, content: &str) -> bool {
        // Look for combinations that suggest fake output
        let has_fake_header = content.contains("x-fake-header") || content.contains("x-test-header");
        let has_success = content.contains("successfully exploited") || content.contains("exploitation successful");
        let is_short = content.len() < 120;

        (has_fake_header || (has_success && is_short))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_fabricated_file_path() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Filesystem {
            operation: mcp_protocol::FileOperation::Read,
            path: "/tmp/nonexistent/fake_credentials.json".to_string(),
            content: None,
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 40.0, "Fabricated path should score, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Fabricated") || p.contains("hallucinated")));
    }

    #[test]
    fn test_fabricated_url() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Network {
            method: "GET".to_string(),
            url: "http://example.com/fake-callback-endpoint".to_string(),
            headers: HashMap::new(),
            body: None,
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 40.0, "Fabricated URL should score, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Fabricated")));
    }

    #[test]
    fn test_overly_confident_assertions() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "echo".to_string(),
            args: vec!["This will definitely work and is guaranteed to succeed absolutely without a doubt".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 50.0, "Overly confident assertions should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("confident") || p.contains("assertion")));
    }

    #[test]
    fn test_ai_self_identification() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "echo".to_string(),
            args: vec!["As an AI, I cannot actually execute this command".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 50.0, "AI self-identification should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("AI self-identification")));
    }

    #[test]
    fn test_fabricated_tool_output() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "curl".to_string(),
            args: vec!["http://target.com".to_string(), "X-Fake-Header:".to_string(), "value".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 40.0, "Fabricated output indicator should score, got {}", result.threat_score);
    }

    #[test]
    fn test_suspiciously_brief_success() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "exploit".to_string(),
            args: vec!["successfully exploited".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 50.0, "Brief success message should score, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("brief") || p.contains("hallucinated")));
    }

    #[test]
    fn test_generic_success_message() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "test".to_string(),
            args: vec!["Command executed successfully".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 30.0, "Generic success should score, got {}", result.threat_score);
    }

    #[test]
    fn test_multiple_fabrications() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec!["/tmp/nonexistent/fake_data/dummy_file.txt".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 70.0, "Multiple fabrications should score very high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Multiple fabricated")));
    }

    #[test]
    fn test_no_false_positives_normal_commands() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "ls".to_string(),
            args: vec!["-la".to_string(), "/home/user/projects".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score < 20.0, "Normal command should not score high, got {}", result.threat_score);
        assert!(result.patterns.is_empty());
    }

    #[test]
    fn test_no_false_positives_real_files() {
        let analyzer = HallucinationAnalyzer::new();

        let tool_call = MCPToolCall::Filesystem {
            operation: mcp_protocol::FileOperation::Read,
            path: "/home/user/documents/report.pdf".to_string(),
            content: None,
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score < 20.0, "Real file path should not score, got {}", result.threat_score);
        assert!(result.patterns.is_empty());
    }
}
