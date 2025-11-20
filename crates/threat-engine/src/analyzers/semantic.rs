/// Semantic Analyzer - Uses Claude Sonnet 4.5 for intent analysis
///
/// This analyzer adds semantic understanding to pattern-based detection by:
/// 1. Analyzing the intent behind tool calls
/// 2. Detecting obfuscation attempts
/// 3. Understanding context that patterns might miss
/// 4. Providing risk boost/reduction based on reasoning
///
/// Only runs for ambiguous cases (pattern score 40-80) to optimize cost and latency.

use mcp_protocol::MCPToolCall;
use crate::AnalyzerResult;
use serde_json::json;
use std::collections::HashMap;

#[cfg(feature = "semantic-analysis")]
use {
    reqwest::Client,
    serde::{Deserialize, Serialize},
    sha2::{Sha256, Digest},
    base64::{Engine as _, engine::general_purpose},
};

/// Semantic analysis result from Claude
#[derive(Debug, Clone)]
#[cfg(feature = "semantic-analysis")]
#[derive(Serialize, Deserialize)]
struct SemanticAnalysisResponse {
    /// Risk boost (-30 to +30)
    risk_boost: f64,
    /// Reasoning for the analysis
    reasoning: String,
    /// Confidence in the analysis (0-1)
    confidence: f64,
    /// Is this malicious?
    is_malicious: bool,
}

pub struct SemanticAnalyzer {
    #[cfg(feature = "semantic-analysis")]
    client: Option<Client>,
    #[cfg(feature = "semantic-analysis")]
    api_key: Option<String>,
    #[cfg(feature = "semantic-analysis")]
    cache: HashMap<String, SemanticAnalysisResponse>,
}

impl SemanticAnalyzer {
    pub fn new() -> Self {
        #[cfg(feature = "semantic-analysis")]
        {
            let api_key = std::env::var("ANTHROPIC_API_KEY").ok();
            let client = if api_key.is_some() {
                Some(Client::new())
            } else {
                None
            };

            Self {
                client,
                api_key,
                cache: HashMap::new(),
            }
        }

        #[cfg(not(feature = "semantic-analysis"))]
        {
            Self {}
        }
    }

    /// Analyze tool call with semantic understanding
    pub async fn analyze(&mut self, tool_call: &MCPToolCall, pattern_score: f64) -> AnalyzerResult {
        // Skip semantic analysis if:
        // 1. Pattern score is clearly safe (< 40) or clearly malicious (> 80)
        // 2. Semantic analysis is not enabled
        // 3. No API key is configured

        #[cfg(not(feature = "semantic-analysis"))]
        {
            return AnalyzerResult {
                analyzer_name: "semantic".to_string(),
                threat_score: 0.0,
                patterns: vec!["Semantic analysis not enabled (compile with --features semantic-analysis)".to_string()],
                metadata: json!({"skipped": true, "reason": "feature disabled"}),
            };
        }

        #[cfg(feature = "semantic-analysis")]
        {
            // Skip if clearly safe or clearly malicious
            if pattern_score < 40.0 || pattern_score > 80.0 {
                return AnalyzerResult {
                    analyzer_name: "semantic".to_string(),
                    threat_score: 0.0,
                    patterns: vec![],
                    metadata: json!({
                        "skipped": true,
                        "reason": if pattern_score < 40.0 { "clearly_safe" } else { "clearly_malicious" },
                        "pattern_score": pattern_score
                    }),
                };
            }

            // Skip if no API key
            if self.api_key.is_none() || self.client.is_none() {
                return AnalyzerResult {
                    analyzer_name: "semantic".to_string(),
                    threat_score: 0.0,
                    patterns: vec!["Semantic analysis skipped (no ANTHROPIC_API_KEY)".to_string()],
                    metadata: json!({"skipped": true, "reason": "no_api_key"}),
                };
            }

            // Check cache
            let cache_key = self.generate_cache_key(tool_call);
            if let Some(cached) = self.cache.get(&cache_key) {
                return self.build_result(cached.clone(), pattern_score, true);
            }

            // Call Claude API
            match self.analyze_with_claude(tool_call, pattern_score).await {
                Ok(response) => {
                    // Cache the result
                    self.cache.insert(cache_key, response.clone());
                    self.build_result(response, pattern_score, false)
                }
                Err(e) => {
                    AnalyzerResult {
                        analyzer_name: "semantic".to_string(),
                        threat_score: 0.0,
                        patterns: vec![format!("Semantic analysis failed: {}", e)],
                        metadata: json!({"error": e.to_string()}),
                    }
                }
            }
        }
    }

    #[cfg(feature = "semantic-analysis")]
    fn generate_cache_key(&self, tool_call: &MCPToolCall) -> String {
        let tool_str = format!("{:?}", tool_call);
        let mut hasher = Sha256::new();
        hasher.update(tool_str.as_bytes());
        let hash = hasher.finalize();
        general_purpose::STANDARD.encode(hash)
    }

    #[cfg(feature = "semantic-analysis")]
    async fn analyze_with_claude(
        &self,
        tool_call: &MCPToolCall,
        pattern_score: f64,
    ) -> Result<SemanticAnalysisResponse, Box<dyn std::error::Error>> {
        let client = self.client.as_ref().ok_or("No HTTP client")?;
        let api_key = self.api_key.as_ref().ok_or("No API key")?;

        // Format tool call for analysis
        let tool_description = self.format_tool_call(tool_call);

        // Use Anthropic's prompt caching to reduce costs
        // Cache the static system prompt
        let system_prompt = r#"You are a cybersecurity expert analyzing MCP tool calls for malicious intent.

Analyze commands and determine:
1. Is this likely malicious or benign?
2. What is the intent behind this command?
3. Are there signs of obfuscation or evasion?
4. Should the risk score be adjusted? (provide a boost from -30 to +30)

Respond ONLY with valid JSON in this exact format:
{
  "risk_boost": <number between -30 and 30>,
  "reasoning": "<your explanation>",
  "confidence": <number between 0 and 1>,
  "is_malicious": <true or false>
}"#;

        let request_body = json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"}
                }
            ],
            "messages": [{
                "role": "user",
                "content": format!("Tool Call:\n{}\n\nPattern-based Threat Score: {}", tool_description, pattern_score)
            }]
        });

        let response = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", "prompt-caching-2024-07-31")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(format!("Claude API error {}: {}", status, body).into());
        }

        let response_json: serde_json::Value = response.json().await?;

        // Track cache usage for cost monitoring
        let cache_creation_tokens = response_json["usage"]["cache_creation_input_tokens"].as_u64().unwrap_or(0);
        let cache_read_tokens = response_json["usage"]["cache_read_input_tokens"].as_u64().unwrap_or(0);
        let input_tokens = response_json["usage"]["input_tokens"].as_u64().unwrap_or(0);

        tracing::debug!(
            "Semantic prompt caching - Creation: {}, Read: {}, Regular: {}",
            cache_creation_tokens,
            cache_read_tokens,
            input_tokens
        );

        // Extract content from Claude response
        let content = response_json["content"][0]["text"]
            .as_str()
            .ok_or("No content in response")?;

        // Parse JSON from content
        let analysis: SemanticAnalysisResponse = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse Claude response: {}", e))?;

        Ok(analysis)
    }

    #[cfg(feature = "semantic-analysis")]
    fn format_tool_call(&self, tool_call: &MCPToolCall) -> String {
        match tool_call {
            MCPToolCall::Bash { command, args, env } => {
                let mut desc = format!("Command: {} {}", command, args.join(" "));
                if !env.is_empty() {
                    desc.push_str(&format!("\nEnvironment: {:?}", env));
                }
                desc
            }
            MCPToolCall::Network { method, url, headers, .. } => {
                let mut desc = format!("Network Request: {} {}", method, url);
                if !headers.is_empty() {
                    desc.push_str(&format!("\nHeaders: {:?}", headers));
                }
                desc
            }
            MCPToolCall::Filesystem { operation, path, .. } => {
                format!("Filesystem: {:?} {}", operation, path)
            }
            MCPToolCall::Database { query, connection } => {
                format!("Database Query: {}\nConnection: {}", query, connection)
            }
            MCPToolCall::Unknown { tool_name, params } => {
                format!("Unknown Tool: {}\nParams: {}", tool_name, params)
            }
        }
    }

    #[cfg(feature = "semantic-analysis")]
    fn build_result(
        &self,
        analysis: SemanticAnalysisResponse,
        pattern_score: f64,
        from_cache: bool,
    ) -> AnalyzerResult {
        let adjusted_score = (pattern_score + analysis.risk_boost).max(0.0).min(100.0);

        let mut patterns = vec![
            format!("Semantic analysis: {}", analysis.reasoning),
        ];

        if analysis.is_malicious {
            patterns.push("Claude AI detected malicious intent".to_string());
        }

        if analysis.risk_boost > 10.0 {
            patterns.push(format!("High risk adjustment: +{:.1}", analysis.risk_boost));
        } else if analysis.risk_boost < -10.0 {
            patterns.push(format!("Risk reduction: {:.1}", analysis.risk_boost));
        }

        AnalyzerResult {
            analyzer_name: "semantic".to_string(),
            threat_score: analysis.risk_boost.abs(),
            patterns,
            metadata: json!({
                "risk_boost": analysis.risk_boost,
                "adjusted_score": adjusted_score,
                "confidence": analysis.confidence,
                "is_malicious": analysis.is_malicious,
                "from_cache": from_cache,
                "pattern_score": pattern_score
            }),
        }
    }
}

impl Default for SemanticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_analyzer_creation() {
        let analyzer = SemanticAnalyzer::new();
        // Just verify it can be created
        assert!(true);
    }

    #[cfg(feature = "semantic-analysis")]
    #[tokio::test]
    async fn test_semantic_skip_clearly_safe() {
        let mut analyzer = SemanticAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call, 10.0).await;

        // Should skip semantic analysis for clearly safe commands
        assert_eq!(result.threat_score, 0.0);
        assert!(result.metadata["skipped"].as_bool().unwrap_or(false));
    }

    #[cfg(feature = "semantic-analysis")]
    #[tokio::test]
    async fn test_semantic_skip_clearly_malicious() {
        let mut analyzer = SemanticAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-sV".to_string(), "0.0.0.0/0".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call, 95.0).await;

        // Should skip semantic analysis for clearly malicious commands
        assert_eq!(result.threat_score, 0.0);
        assert!(result.metadata["skipped"].as_bool().unwrap_or(false));
    }

    #[cfg(not(feature = "semantic-analysis"))]
    #[tokio::test]
    async fn test_semantic_disabled_without_feature() {
        let mut analyzer = SemanticAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec![".env".to_string()],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call, 60.0).await;

        // Should indicate feature is disabled
        assert!(result.patterns.iter().any(|p| p.contains("not enabled")));
    }
}
