//! Gateway Configuration
//!
//! Defines operational modes and policy settings

use serde::{Deserialize, Serialize};

/// Session storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStoreType {
    /// Redis - Production (requires REDIS_URL)
    Redis,
    /// In-memory - Testing/demo only
    InMemory,
}

/// Gateway operational mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayMode {
    /// Monitor mode: Analyze and log, never block
    /// Perfect for trials and risk-free evaluation
    Monitor,

    /// Alert mode: Analyze, log, and send alerts but allow all requests
    /// Good for observability before enforcing
    Alert,

    /// Block mode: Block high-threat operations (score ≥70)
    /// Standard production mode
    Block,

    /// Terminate mode: Block and terminate sessions for critical threats (score ≥90)
    /// Maximum security mode
    Terminate,
}

impl Default for GatewayMode {
    fn default() -> Self {
        GatewayMode::Block
    }
}

impl GatewayMode {
    /// Check if this mode should block a given threat score
    pub fn should_block(&self, threat_score: f64) -> bool {
        match self {
            GatewayMode::Monitor => false,  // Never block in monitor mode
            GatewayMode::Alert => false,    // Never block in alert mode
            GatewayMode::Block => threat_score >= 70.0,
            GatewayMode::Terminate => threat_score >= 70.0,
        }
    }

    /// Check if this mode should terminate session
    pub fn should_terminate(&self, threat_score: f64) -> bool {
        match self {
            GatewayMode::Monitor => false,
            GatewayMode::Alert => false,
            GatewayMode::Block => false,
            GatewayMode::Terminate => threat_score >= 90.0,
        }
    }

    /// Get description for this mode
    pub fn description(&self) -> &'static str {
        match self {
            GatewayMode::Monitor => "Analyze and log only - never blocks",
            GatewayMode::Alert => "Analyze, log, and alert - never blocks",
            GatewayMode::Block => "Block high-threat operations (score ≥70)",
            GatewayMode::Terminate => "Block and terminate critical threats (score ≥90)",
        }
    }
}

/// Gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Operational mode
    pub mode: GatewayMode,

    /// Listen address
    pub listen_addr: String,

    /// Upstream MCP server (optional - for transparent proxy mode)
    pub upstream_mcp: Option<String>,

    /// Log all requests (even safe ones)
    pub log_all_requests: bool,

    /// Custom threat score thresholds
    pub thresholds: ThreatThresholds,

    /// Session storage backend
    pub session_store: SessionStoreType,

    /// Redis URL (if using Redis)
    pub redis_url: Option<String>,

    /// Session TTL in seconds
    pub session_ttl_seconds: u64,

    /// Enable semantic analysis (requires ANTHROPIC_API_KEY)
    pub enable_semantic_analysis: bool,

    /// Anthropic model to use (default: claude-sonnet-4-20250514)
    pub semantic_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatThresholds {
    pub alert: f64,     // Default: 50.0
    pub block: f64,     // Default: 70.0
    pub terminate: f64, // Default: 90.0
}

impl Default for ThreatThresholds {
    fn default() -> Self {
        Self {
            alert: 50.0,
            block: 70.0,
            terminate: 90.0,
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            mode: GatewayMode::Block,
            listen_addr: "0.0.0.0:8787".to_string(),
            upstream_mcp: None,
            log_all_requests: false,
            thresholds: ThreatThresholds::default(),
            session_store: SessionStoreType::Redis,
            redis_url: Some("redis://localhost:6379".to_string()),
            session_ttl_seconds: 86400, // 24 hours
            enable_semantic_analysis: false,
            semantic_model: "claude-sonnet-4-20250514".to_string(),
        }
    }
}

impl GatewayConfig {
    /// Load from environment variables
    pub fn from_env() -> Self {
        let mode = std::env::var("MODE")
            .ok()
            .and_then(|m| match m.to_lowercase().as_str() {
                "monitor" => Some(GatewayMode::Monitor),
                "alert" => Some(GatewayMode::Alert),
                "block" => Some(GatewayMode::Block),
                "terminate" => Some(GatewayMode::Terminate),
                _ => None,
            })
            .unwrap_or_default();

        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8787".to_string());

        let upstream_mcp = std::env::var("UPSTREAM_MCP").ok();

        let log_all_requests = std::env::var("LOG_ALL_REQUESTS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let session_store = std::env::var("SESSION_STORE")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "redis" => Some(SessionStoreType::Redis),
                "inmemory" => Some(SessionStoreType::InMemory),
                _ => None,
            })
            .unwrap_or(SessionStoreType::Redis);

        let redis_url = std::env::var("REDIS_URL").ok();

        let session_ttl_seconds = std::env::var("SESSION_TTL_HOURS")
            .ok()
            .and_then(|h| h.parse::<u64>().ok())
            .map(|h| h * 3600)
            .unwrap_or(86400); // 24 hours default

        let enable_semantic_analysis = std::env::var("ENABLE_SEMANTIC_ANALYSIS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let semantic_model = std::env::var("SEMANTIC_MODEL")
            .unwrap_or_else(|_| "claude-sonnet-4-20250514".to_string());

        Self {
            mode,
            listen_addr,
            upstream_mcp,
            log_all_requests,
            thresholds: ThreatThresholds::default(),
            session_store,
            redis_url,
            session_ttl_seconds,
            enable_semantic_analysis,
            semantic_model,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_mode_never_blocks() {
        let mode = GatewayMode::Monitor;
        assert!(!mode.should_block(100.0));
        assert!(!mode.should_terminate(100.0));
    }

    #[test]
    fn test_block_mode_blocks_high_threats() {
        let mode = GatewayMode::Block;
        assert!(!mode.should_block(50.0));
        assert!(mode.should_block(70.0));
        assert!(mode.should_block(90.0));
        assert!(!mode.should_terminate(90.0)); // Block mode doesn't terminate
    }

    #[test]
    fn test_terminate_mode() {
        let mode = GatewayMode::Terminate;
        assert!(!mode.should_block(50.0));
        assert!(mode.should_block(70.0));
        assert!(mode.should_terminate(95.0));
    }
}
