//! Prometheus metrics for Proxilion MCP Security Gateway
//!
//! This module provides comprehensive metrics for monitoring gateway health,
//! threat detection rates, performance, and analyzer effectiveness.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, register_int_counter_vec,
    CounterVec, Encoder, Gauge, HistogramVec, IntCounterVec, TextEncoder,
};

lazy_static! {
    // Request metrics
    pub static ref REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "proxilion_requests_total",
        "Total number of analysis requests",
        &["decision"]  // Allow, Alert, Block, Terminate
    ).unwrap();

    pub static ref REQUESTS_BY_USER: IntCounterVec = register_int_counter_vec!(
        "proxilion_requests_by_user_total",
        "Total requests per user",
        &["user_id"]
    ).unwrap();

    // Threat detection metrics
    pub static ref THREATS_DETECTED: IntCounterVec = register_int_counter_vec!(
        "proxilion_threats_detected_total",
        "Total threats detected by analyzer",
        &["analyzer", "decision"]
    ).unwrap();

    pub static ref THREATS_BLOCKED: IntCounterVec = register_int_counter_vec!(
        "proxilion_threats_blocked_total",
        "Total threats blocked",
        &["analyzer"]
    ).unwrap();

    pub static ref THREAT_SCORE_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "proxilion_threat_score",
        "Distribution of threat scores",
        &["analyzer"],
        vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    ).unwrap();

    // Performance metrics
    pub static ref ANALYSIS_DURATION: HistogramVec = register_histogram_vec!(
        "proxilion_analysis_duration_seconds",
        "Time spent analyzing requests",
        &["analyzer"],
        vec![0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0]
    ).unwrap();

    pub static ref TOTAL_ANALYSIS_DURATION: HistogramVec = register_histogram_vec!(
        "proxilion_total_analysis_duration_seconds",
        "Total time for complete analysis",
        &[],
        vec![0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0]
    ).unwrap();

    // Session metrics
    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "proxilion_active_sessions",
        "Number of active sessions"
    ).unwrap();

    pub static ref SESSIONS_CREATED: IntCounterVec = register_int_counter_vec!(
        "proxilion_sessions_created_total",
        "Total sessions created",
        &["user_id"]
    ).unwrap();

    pub static ref SESSIONS_TERMINATED: IntCounterVec = register_int_counter_vec!(
        "proxilion_sessions_terminated_total",
        "Total sessions terminated due to threats",
        &["reason"]
    ).unwrap();

    // Analyzer-specific metrics
    pub static ref ANALYZER_INVOCATIONS: IntCounterVec = register_int_counter_vec!(
        "proxilion_analyzer_invocations_total",
        "Total analyzer invocations",
        &["analyzer"]
    ).unwrap();

    pub static ref ANALYZER_ERRORS: IntCounterVec = register_int_counter_vec!(
        "proxilion_analyzer_errors_total",
        "Total analyzer errors",
        &["analyzer"]
    ).unwrap();

    // Pattern detection metrics
    pub static ref PATTERNS_DETECTED: IntCounterVec = register_int_counter_vec!(
        "proxilion_patterns_detected_total",
        "Total patterns detected",
        &["pattern_type"]
    ).unwrap();

    // GTG-1002 specific metrics
    pub static ref GTG1002_INDICATORS: IntCounterVec = register_int_counter_vec!(
        "proxilion_gtg1002_indicators_total",
        "GTG-1002 attack indicators detected",
        &["indicator_type"]  // social_engineering, autonomous_agent, multi_target, high_velocity
    ).unwrap();

    // Semantic analysis metrics (Claude API)
    pub static ref SEMANTIC_ANALYSIS_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "proxilion_semantic_analysis_requests_total",
        "Total semantic analysis requests",
        &["analyzer", "result"]  // success, timeout, error
    ).unwrap();

    pub static ref SEMANTIC_ANALYSIS_COST: CounterVec = register_counter_vec!(
        "proxilion_semantic_analysis_cost_usd",
        "Estimated cost of semantic analysis",
        &["analyzer"]
    ).unwrap();

    // Prompt caching metrics
    pub static ref PROMPT_CACHE_HITS: IntCounterVec = register_int_counter_vec!(
        "proxilion_prompt_cache_hits_total",
        "Prompt cache hits (cost savings)",
        &["analyzer"]
    ).unwrap();

    pub static ref PROMPT_CACHE_MISSES: IntCounterVec = register_int_counter_vec!(
        "proxilion_prompt_cache_misses_total",
        "Prompt cache misses (full cost)",
        &["analyzer"]
    ).unwrap();

    pub static ref PROMPT_CACHE_TOKENS_SAVED: IntCounterVec = register_int_counter_vec!(
        "proxilion_prompt_cache_tokens_saved_total",
        "Tokens saved via prompt caching",
        &["analyzer"]
    ).unwrap();

    pub static ref PROMPT_CACHE_COST_SAVED: CounterVec = register_counter_vec!(
        "proxilion_prompt_cache_cost_saved_usd",
        "Estimated cost saved via prompt caching",
        &["analyzer"]
    ).unwrap();

    // Error metrics
    pub static ref ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "proxilion_errors_total",
        "Total errors by type",
        &["error_type"]
    ).unwrap();

    // Health metrics
    pub static ref GATEWAY_UP: Gauge = register_gauge!(
        "proxilion_gateway_up",
        "Gateway is up (1) or down (0)"
    ).unwrap();

    pub static ref REDIS_CONNECTED: Gauge = register_gauge!(
        "proxilion_redis_connected",
        "Redis connection status (1=connected, 0=disconnected)"
    ).unwrap();
}

/// Record a threat detection
pub fn record_threat_detected(analyzer: &str, decision: &str, score: f64) {
    THREATS_DETECTED
        .with_label_values(&[analyzer, decision])
        .inc();

    if decision == "Block" || decision == "Terminate" {
        THREATS_BLOCKED.with_label_values(&[analyzer]).inc();
    }

    THREAT_SCORE_HISTOGRAM
        .with_label_values(&[analyzer])
        .observe(score);
}

/// Record analysis duration for a specific analyzer
#[allow(dead_code)]
pub fn record_analyzer_duration(analyzer: &str, duration_secs: f64) {
    ANALYSIS_DURATION
        .with_label_values(&[analyzer])
        .observe(duration_secs);
}

/// Record total analysis duration for the complete request
pub fn record_analysis_duration(duration_secs: f64) {
    TOTAL_ANALYSIS_DURATION.with_label_values(&[]).observe(duration_secs);
}

/// Record a request
#[allow(dead_code)]
pub fn record_request(decision: &str, user_id: &str) {
    REQUESTS_TOTAL.with_label_values(&[decision]).inc();
    REQUESTS_BY_USER.with_label_values(&[user_id]).inc();
}

/// Record analyzer invocation
#[allow(dead_code)]
pub fn record_analyzer_invocation(analyzer: &str) {
    ANALYZER_INVOCATIONS.with_label_values(&[analyzer]).inc();
}

/// Record analyzer error
#[allow(dead_code)]
pub fn record_analyzer_error(analyzer: &str) {
    ANALYZER_ERRORS.with_label_values(&[analyzer]).inc();
}

/// Record pattern detection
#[allow(dead_code)]
pub fn record_pattern_detected(pattern_type: &str) {
    PATTERNS_DETECTED.with_label_values(&[pattern_type]).inc();
}

/// Record GTG-1002 indicator
pub fn record_gtg1002_indicator(indicator_type: &str) {
    GTG1002_INDICATORS
        .with_label_values(&[indicator_type])
        .inc();
}

/// Record semantic analysis request
#[allow(dead_code)]
pub fn record_semantic_analysis(analyzer: &str, result: &str, estimated_cost_usd: f64) {
    SEMANTIC_ANALYSIS_REQUESTS
        .with_label_values(&[analyzer, result])
        .inc();

    SEMANTIC_ANALYSIS_COST
        .with_label_values(&[analyzer])
        .inc_by(estimated_cost_usd);
}

/// Record error
#[allow(dead_code)]
pub fn record_error(error_type: &str) {
    ERRORS_TOTAL.with_label_values(&[error_type]).inc();
}

/// Update active sessions gauge
#[allow(dead_code)]
pub fn update_active_sessions(count: i64) {
    ACTIVE_SESSIONS.set(count as f64);
}

/// Record session creation
#[allow(dead_code)]
pub fn record_session_created(user_id: &str) {
    SESSIONS_CREATED.with_label_values(&[user_id]).inc();
}

/// Record session termination due to threat
pub fn record_session_terminated(_threat_score: f64) {
    SESSIONS_TERMINATED.with_label_values(&["high_threat"]).inc();
}

/// Record request blocked
pub fn record_request_blocked(_threat_score: f64) {
    THREATS_BLOCKED.with_label_values(&["composite"]).inc();
}

/// Record user request
pub fn record_user_request(user_id: &str) {
    REQUESTS_BY_USER.with_label_values(&[user_id]).inc();
}

/// Record semantic analysis request
pub fn record_semantic_analysis_request() {
    SEMANTIC_ANALYSIS_REQUESTS
        .with_label_values(&["semantic", "success"])
        .inc();
}

/// Record semantic analysis cost
pub fn record_semantic_analysis_cost(cost_usd: f64) {
    SEMANTIC_ANALYSIS_COST
        .with_label_values(&["semantic"])
        .inc_by(cost_usd);
}

/// Record prompt cache hit
#[allow(dead_code)]
pub fn record_prompt_cache_hit(analyzer: &str, tokens_saved: u64) {
    PROMPT_CACHE_HITS
        .with_label_values(&[analyzer])
        .inc();

    PROMPT_CACHE_TOKENS_SAVED
        .with_label_values(&[analyzer])
        .inc_by(tokens_saved);

    // Calculate cost saved
    // Cache reads: $0.30/MTok vs regular input: $3.00/MTok
    // Savings: $2.70/MTok
    let cost_saved = (tokens_saved as f64 / 1_000_000.0) * 2.70;
    PROMPT_CACHE_COST_SAVED
        .with_label_values(&[analyzer])
        .inc_by(cost_saved);
}

/// Record prompt cache miss
#[allow(dead_code)]
pub fn record_prompt_cache_miss(analyzer: &str) {
    PROMPT_CACHE_MISSES
        .with_label_values(&[analyzer])
        .inc();
}

/// Update gateway health
pub fn update_gateway_health(is_up: bool) {
    GATEWAY_UP.set(if is_up { 1.0 } else { 0.0 });
}

/// Update Redis connection status
pub fn update_redis_status(is_connected: bool) {
    REDIS_CONNECTED.set(if is_connected { 1.0 } else { 0.0 });
}

/// Encode all metrics for Prometheus
pub fn encode_metrics() -> Result<String, anyhow::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_threat_detected() {
        record_threat_detected("enumeration", "Block", 85.0);
        record_threat_detected("credential", "Terminate", 95.0);

        // Verify counters incremented (basic smoke test)
        let metrics = encode_metrics().unwrap();
        assert!(metrics.contains("proxilion_threats_detected_total"));
        assert!(metrics.contains("proxilion_threats_blocked_total"));
    }

    #[test]
    fn test_encode_metrics() {
        // Record some metrics to ensure they appear in output
        record_user_request("test_user");
        update_gateway_health(true);

        let metrics = encode_metrics().unwrap();
        assert!(metrics.contains("proxilion_requests_by_user_total"));
        assert!(metrics.contains("proxilion_gateway_up"));
        assert!(!metrics.is_empty());
    }
}
