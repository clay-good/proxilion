//! MCP Protocol Parser
//!
//! Implements the Model Context Protocol (MCP) message parser and transparent proxy.
//!
//! MCP Spec: https://spec.modelcontextprotocol.io/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MCPError {
    #[error("Invalid JSON-RPC version: {0}")]
    InvalidVersion(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid method: {0}")]
    InvalidMethod(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Security policy violation: {reason} (score: {score})")]
    SecurityViolation { reason: String, score: f64 },
}

/// MCP JSON-RPC 2.0 Message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPMessage {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

/// MCP JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<MCPErrorResponse>,
    pub id: serde_json::Value,
}

/// MCP Error Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPErrorResponse {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Parsed MCP Tool Call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MCPToolCall {
    /// Bash command execution
    Bash {
        command: String,
        args: Vec<String>,
        env: HashMap<String, String>,
    },

    /// Filesystem operation
    Filesystem {
        operation: FileOperation,
        path: String,
        content: Option<Vec<u8>>,
    },

    /// Network request
    Network {
        method: String,
        url: String,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
    },

    /// Database query
    Database {
        query: String,
        connection: String,
    },

    /// Unknown/Other tool
    Unknown {
        tool_name: String,
        params: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperation {
    Read,
    Write,
    Delete,
    List,
    Create,
}

impl MCPMessage {
    /// Parse a JSON-RPC 2.0 message
    pub fn parse(json: &str) -> Result<Self, MCPError> {
        let msg: MCPMessage = serde_json::from_str(json)
            .map_err(|e| MCPError::ParseError(e.to_string()))?;

        // Validate JSON-RPC version
        if msg.jsonrpc != "2.0" {
            return Err(MCPError::InvalidVersion(msg.jsonrpc));
        }

        Ok(msg)
    }

    /// Extract tool call from MCP message
    pub fn extract_tool_call(&self) -> Result<MCPToolCall, MCPError> {
        // Parse based on method name
        match self.method.as_str() {
            "tools/call" => self.parse_tool_call(),
            _ => Ok(MCPToolCall::Unknown {
                tool_name: self.method.clone(),
                params: self.params.clone(),
            }),
        }
    }

    fn parse_tool_call(&self) -> Result<MCPToolCall, MCPError> {
        let params = self.params.as_object()
            .ok_or_else(|| MCPError::MissingField("params".to_string()))?;

        let tool_name = params.get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MCPError::MissingField("name".to_string()))?;

        match tool_name {
            "bash" | "shell" | "exec" => self.parse_bash_call(params),
            "filesystem" | "read_file" | "write_file" | "list_directory" => self.parse_filesystem_call(params),
            "http_request" | "fetch" => self.parse_network_call(params),
            "sql_query" | "database_query" => self.parse_database_call(params),
            _ => Ok(MCPToolCall::Unknown {
                tool_name: tool_name.to_string(),
                params: self.params.clone(),
            }),
        }
    }

    fn parse_bash_call(&self, params: &serde_json::Map<String, serde_json::Value>) -> Result<MCPToolCall, MCPError> {
        let arguments = params.get("arguments")
            .and_then(|v| v.as_object())
            .ok_or_else(|| MCPError::MissingField("arguments".to_string()))?;

        let command = arguments.get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MCPError::MissingField("command".to_string()))?
            .to_string();

        // Extract args array from JSON if present
        let args = if let Some(args_array) = arguments.get("args").and_then(|v| v.as_array()) {
            // Use explicit args array from JSON
            args_array.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        } else {
            // Fallback: parse command string into parts
            let parts: Vec<String> = command.split_whitespace()
                .map(|s| s.to_string())
                .collect();
            parts.into_iter().skip(1).collect()
        };

        // Extract command name (first part before args)
        let cmd = command.split_whitespace()
            .next()
            .unwrap_or(&command)
            .to_string();

        Ok(MCPToolCall::Bash {
            command: cmd,
            args,
            env: HashMap::new(),
        })
    }

    fn parse_filesystem_call(&self, params: &serde_json::Map<String, serde_json::Value>) -> Result<MCPToolCall, MCPError> {
        let args = params.get("arguments")
            .and_then(|v| v.as_object())
            .ok_or_else(|| MCPError::MissingField("arguments".to_string()))?;

        let path = args.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MCPError::MissingField("path".to_string()))?
            .to_string();

        let operation = if args.contains_key("content") {
            FileOperation::Write
        } else {
            FileOperation::Read
        };

        Ok(MCPToolCall::Filesystem {
            operation,
            path,
            content: None,
        })
    }

    fn parse_network_call(&self, params: &serde_json::Map<String, serde_json::Value>) -> Result<MCPToolCall, MCPError> {
        let args = params.get("arguments")
            .and_then(|v| v.as_object())
            .ok_or_else(|| MCPError::MissingField("arguments".to_string()))?;

        let url = args.get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MCPError::MissingField("url".to_string()))?
            .to_string();

        let method = args.get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string();

        Ok(MCPToolCall::Network {
            method,
            url,
            headers: HashMap::new(),
            body: None,
        })
    }

    fn parse_database_call(&self, params: &serde_json::Map<String, serde_json::Value>) -> Result<MCPToolCall, MCPError> {
        let args = params.get("arguments")
            .and_then(|v| v.as_object())
            .ok_or_else(|| MCPError::MissingField("arguments".to_string()))?;

        let query = args.get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MCPError::MissingField("query".to_string()))?
            .to_string();

        Ok(MCPToolCall::Database {
            query,
            connection: String::new(),
        })
    }
}

impl MCPResponse {
    /// Create a success response
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response
    pub fn error(id: serde_json::Value, code: i32, message: String, data: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(MCPErrorResponse {
                code,
                message,
                data,
            }),
            id,
        }
    }

    /// Create a security violation error
    pub fn security_violation(id: serde_json::Value, threat_score: f64, patterns: Vec<String>) -> Self {
        Self::error(
            id,
            -32000, // Server error code
            "Security policy violation".to_string(),
            Some(serde_json::json!({
                "threat_score": threat_score,
                "patterns": patterns,
            })),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mcp_message() {
        let json = r#"{
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "bash",
                "arguments": {
                    "command": "ls -la"
                }
            },
            "id": 1
        }"#;

        let msg = MCPMessage::parse(json).unwrap();
        assert_eq!(msg.method, "tools/call");
        assert_eq!(msg.jsonrpc, "2.0");
    }

    #[test]
    fn test_extract_bash_tool_call() {
        let json = r#"{
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "bash",
                "arguments": {
                    "command": "nmap -sV 192.168.1.0/24"
                }
            },
            "id": 1
        }"#;

        let msg = MCPMessage::parse(json).unwrap();
        let tool_call = msg.extract_tool_call().unwrap();

        match tool_call {
            MCPToolCall::Bash { command, args, .. } => {
                assert_eq!(command, "nmap");
                assert_eq!(args[0], "-sV");
            }
            _ => panic!("Expected Bash tool call"),
        }
    }
}
