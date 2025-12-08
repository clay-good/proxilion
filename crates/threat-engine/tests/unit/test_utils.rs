//! Test utilities for threat engine unit tests
//!
//! Provides common setup functions and assertions for analyzer testing.

use mcp_protocol::{MCPToolCall, FileOperation};
use std::collections::HashMap;

/// Create a bash tool call for testing
pub fn bash_call(command: &str) -> MCPToolCall {
    MCPToolCall::Bash {
        command: command.to_string(),
        args: vec![],
        env: HashMap::new(),
    }
}

/// Create a bash tool call with args
pub fn bash_call_with_args(command: &str, args: Vec<&str>) -> MCPToolCall {
    MCPToolCall::Bash {
        command: command.to_string(),
        args: args.into_iter().map(String::from).collect(),
        env: HashMap::new(),
    }
}

/// Create a bash tool call with environment
pub fn bash_call_with_env(command: &str, env: HashMap<String, String>) -> MCPToolCall {
    MCPToolCall::Bash {
        command: command.to_string(),
        args: vec![],
        env,
    }
}

/// Create a filesystem read operation
pub fn fs_read(path: &str) -> MCPToolCall {
    MCPToolCall::Filesystem {
        operation: FileOperation::Read,
        path: path.to_string(),
        content: None,
    }
}

/// Create a filesystem write operation
pub fn fs_write(path: &str, content: &str) -> MCPToolCall {
    MCPToolCall::Filesystem {
        operation: FileOperation::Write,
        path: path.to_string(),
        content: Some(content.as_bytes().to_vec()),
    }
}

/// Create a network request
pub fn network_request(method: &str, url: &str) -> MCPToolCall {
    MCPToolCall::Network {
        method: method.to_string(),
        url: url.to_string(),
        headers: HashMap::new(),
        body: None,
    }
}

/// Create a network request with headers
pub fn network_request_with_headers(method: &str, url: &str, headers: HashMap<String, String>) -> MCPToolCall {
    MCPToolCall::Network {
        method: method.to_string(),
        url: url.to_string(),
        headers,
        body: None,
    }
}

/// Create a database query
pub fn db_query(query: &str, connection: &str) -> MCPToolCall {
    MCPToolCall::Database {
        query: query.to_string(),
        connection: connection.to_string(),
    }
}

/// Create an unknown tool call
pub fn unknown_tool(name: &str, params: serde_json::Value) -> MCPToolCall {
    MCPToolCall::Unknown {
        tool_name: name.to_string(),
        params,
    }
}

/// Assert that threat score is zero (safe)
pub fn assert_safe(result: &threat_engine::AnalyzerResult) {
    assert!(
        result.threat_score == 0.0,
        "Expected safe (score 0), got score {} with patterns: {:?}",
        result.threat_score,
        result.patterns
    );
}

/// Assert that threat score is above threshold
pub fn assert_threat_above(result: &threat_engine::AnalyzerResult, threshold: f64) {
    assert!(
        result.threat_score >= threshold,
        "Expected threat score >= {}, got {} with patterns: {:?}",
        threshold,
        result.threat_score,
        result.patterns
    );
}

/// Assert that threat score is below threshold
pub fn assert_threat_below(result: &threat_engine::AnalyzerResult, threshold: f64) {
    assert!(
        result.threat_score < threshold,
        "Expected threat score < {}, got {} with patterns: {:?}",
        threshold,
        result.threat_score,
        result.patterns
    );
}

/// Assert that specific pattern was detected
pub fn assert_pattern_detected(result: &threat_engine::AnalyzerResult, pattern_substring: &str) {
    assert!(
        result.patterns.iter().any(|p| p.contains(pattern_substring)),
        "Expected pattern containing '{}', got patterns: {:?}",
        pattern_substring,
        result.patterns
    );
}

/// Assert no patterns detected
pub fn assert_no_patterns(result: &threat_engine::AnalyzerResult) {
    assert!(
        result.patterns.is_empty(),
        "Expected no patterns, got: {:?}",
        result.patterns
    );
}
