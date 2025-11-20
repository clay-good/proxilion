/// Request Rate Analyzer - Detects autonomous high-frequency behavior
///
/// Identifies automated tool usage through rate analysis:
/// - Burst detection (>100 requests/minute)
/// - Sustained high-frequency activity (>1 req/sec for 5 minutes)
/// - Machine-like timing patterns (too regular)
/// - Accelerating attack patterns
///
/// Requires session state for rate tracking across requests.

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct RequestRateAnalyzer {
    critical_rate: f64,  // 2.0 req/sec
    high_rate: f64,      // 1.0 req/sec
    medium_rate: f64,    // 0.5 req/sec
    burst_threshold: u32, // 100 requests/minute
}

/// Rate limit statistics from session state
pub struct RateStats {
    pub requests_last_minute: u32,
    pub requests_last_hour: u32,
    pub total_requests: u64,
    pub request_timestamps: Vec<i64>,
}

impl RequestRateAnalyzer {
    pub fn new() -> Self {
        Self {
            critical_rate: 2.0,
            high_rate: 1.0,
            medium_rate: 0.5,
            burst_threshold: 100,
        }
    }

    /// Analyze request rate with session state
    pub fn analyze_with_session(&self, _tool_call: &MCPToolCall, rate_stats: &RateStats, now: i64) -> AnalyzerResult {
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for burst activity (>100 req/min)
        if rate_stats.requests_last_minute >= self.burst_threshold {
            patterns_found.push(format!(
                "BURST: {} requests in last minute (automated tool signature)",
                rate_stats.requests_last_minute
            ));
            score += 90.0;
        } else if rate_stats.requests_last_minute >= 50 {
            patterns_found.push(format!(
                "High request rate: {} requests/minute",
                rate_stats.requests_last_minute
            ));
            score += 70.0;
        } else if rate_stats.requests_last_minute >= 30 {
            patterns_found.push(format!(
                "Elevated request rate: {} requests/minute",
                rate_stats.requests_last_minute
            ));
            score += 50.0;
        }

        // Check sustained high-frequency activity
        if rate_stats.requests_last_hour >= 2000 {
            patterns_found.push(format!(
                "Sustained high-frequency activity: {} requests/hour",
                rate_stats.requests_last_hour
            ));
            score += 85.0;
        } else if rate_stats.requests_last_hour >= 1000 {
            patterns_found.push(format!(
                "Sustained elevated activity: {} requests/hour",
                rate_stats.requests_last_hour
            ));
            score += 65.0;
        }

        // Detect machine-like timing patterns
        if rate_stats.request_timestamps.len() >= 10 {
            if let Some(machine_pattern) = self.detect_machine_timing(&rate_stats.request_timestamps) {
                patterns_found.push(machine_pattern);
                score += 75.0;
            }
        }

        // Detect acceleration (increasing rate)
        if rate_stats.request_timestamps.len() >= 20 {
            if self.is_accelerating(&rate_stats.request_timestamps) {
                patterns_found.push("Accelerating request rate (automated attack ramp-up)".to_string());
                score += 60.0;
            }
        }

        // Metadata
        let metadata = serde_json::json!({
            "requests_last_minute": rate_stats.requests_last_minute,
            "requests_last_hour": rate_stats.requests_last_hour,
            "total_requests": rate_stats.total_requests,
            "rate_per_second": rate_stats.requests_last_minute as f64 / 60.0,
            "pattern_count": patterns_found.len(),
        });

        AnalyzerResult {
            analyzer_name: "request_rate".to_string(),
            threat_score: score.min(100.0),
            patterns: patterns_found,
            metadata,
        }
    }

    /// Detect machine-like timing (too regular intervals)
    fn detect_machine_timing(&self, timestamps: &[i64]) -> Option<String> {
        if timestamps.len() < 10 {
            return None;
        }

        // Take last 10 timestamps
        let recent: Vec<i64> = timestamps.iter().rev().take(10).cloned().collect();

        // Calculate intervals
        let mut intervals = Vec::new();
        for i in 0..recent.len()-1 {
            intervals.push((recent[i] - recent[i+1]).abs());
        }

        if intervals.is_empty() {
            return None;
        }

        // Calculate mean interval
        let mean = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;

        // Calculate standard deviation
        let variance = intervals.iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / intervals.len() as f64;

        let std_dev = variance.sqrt();

        // Coefficient of variation (CV = std_dev / mean)
        let cv = if mean > 0.0 { std_dev / mean } else { 1.0 };

        // Low CV (<0.2) indicates very regular, machine-like timing
        if cv < 0.2 && mean < 5000.0 {
            Some(format!(
                "Machine-like timing pattern detected (CV: {:.2}, mean interval: {:.0}ms)",
                cv, mean
            ))
        } else {
            None
        }
    }

    /// Detect accelerating request rate
    fn is_accelerating(&self, timestamps: &[i64]) -> bool {
        if timestamps.len() < 20 {
            return false;
        }

        // Take last 20 timestamps
        let recent: Vec<i64> = timestamps.iter().rev().take(20).cloned().collect();

        // Split into early and late halves
        let mid = recent.len() / 2;
        let early = &recent[mid..];
        let late = &recent[..mid];

        if early.len() < 2 || late.len() < 2 {
            return false;
        }

        // Calculate rate for each half (events per second)
        let early_duration = (early[0] - early[early.len()-1]) as f64 / 1000.0;
        let late_duration = (late[0] - late[late.len()-1]) as f64 / 1000.0;

        if early_duration <= 0.0 || late_duration <= 0.0 {
            return false;
        }

        let early_rate = early.len() as f64 / early_duration;
        let late_rate = late.len() as f64 / late_duration;

        // Rate increased by >50%
        late_rate > early_rate * 1.5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burst_detection() {
        let analyzer = RequestRateAnalyzer::new();

        let stats = RateStats {
            requests_last_minute: 150,
            requests_last_hour: 200,
            total_requests: 200,
            request_timestamps: vec![],
        };

        let result = analyzer.analyze_with_session(
            &mcp_protocol::MCPToolCall::Bash {
                command: "test".to_string(),
                args: vec![],
                env: std::collections::HashMap::new(),
            },
            &stats,
            1000000,
        );

        assert!(result.threat_score >= 90.0, "Burst should score critical, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("BURST")));
    }

    #[test]
    fn test_sustained_high_frequency() {
        let analyzer = RequestRateAnalyzer::new();

        let stats = RateStats {
            requests_last_minute: 40,
            requests_last_hour: 2500,
            total_requests: 2500,
            request_timestamps: vec![],
        };

        let result = analyzer.analyze_with_session(
            &mcp_protocol::MCPToolCall::Bash {
                command: "test".to_string(),
                args: vec![],
                env: std::collections::HashMap::new(),
            },
            &stats,
            1000000,
        );

        assert!(result.threat_score >= 80.0, "Sustained high frequency should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Sustained")));
    }

    #[test]
    fn test_machine_timing() {
        let analyzer = RequestRateAnalyzer::new();

        // Create perfectly regular timestamps (exactly 1 second apart)
        let mut timestamps = vec![];
        for i in 0..15 {
            timestamps.push(1000000 + (i * 1000)); // Exactly 1000ms apart
        }

        let stats = RateStats {
            requests_last_minute: 15,
            requests_last_hour: 15,
            total_requests: 15,
            request_timestamps: timestamps,
        };

        let result = analyzer.analyze_with_session(
            &mcp_protocol::MCPToolCall::Bash {
                command: "test".to_string(),
                args: vec![],
                env: std::collections::HashMap::new(),
            },
            &stats,
            1015000,
        );

        assert!(result.threat_score >= 70.0, "Machine timing should score high, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Machine-like")));
    }

    #[test]
    fn test_accelerating_rate() {
        let analyzer = RequestRateAnalyzer::new();

        // Create accelerating pattern: early slow, late fast
        let mut timestamps = vec![];
        // First 10: 5 seconds apart (slow)
        for i in 0..10 {
            timestamps.push(1000000 + (i * 5000));
        }
        // Last 10: 1 second apart (fast)
        for i in 10..20 {
            timestamps.push(1050000 + ((i - 10) * 1000));
        }

        let stats = RateStats {
            requests_last_minute: 20,
            requests_last_hour: 20,
            total_requests: 20,
            request_timestamps: timestamps,
        };

        let result = analyzer.analyze_with_session(
            &mcp_protocol::MCPToolCall::Bash {
                command: "test".to_string(),
                args: vec![],
                env: std::collections::HashMap::new(),
            },
            &stats,
            1060000,
        );

        assert!(result.threat_score >= 50.0, "Acceleration should be detected, got {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Accelerating")));
    }

    #[test]
    fn test_normal_human_rate() {
        let analyzer = RequestRateAnalyzer::new();

        // Normal human activity: ~10 requests/minute with variation
        let mut timestamps = vec![];
        let base = 1000000i64;
        let intervals = [3000, 7000, 5000, 4000, 8000, 6000, 5500, 4500, 7500, 6500]; // Varied intervals
        let mut current = base;
        for &interval in &intervals {
            timestamps.push(current);
            current += interval;
        }

        let stats = RateStats {
            requests_last_minute: 10,
            requests_last_hour: 100,
            total_requests: 150,
            request_timestamps: timestamps,
        };

        let result = analyzer.analyze_with_session(
            &mcp_protocol::MCPToolCall::Bash {
                command: "ls".to_string(),
                args: vec![],
                env: std::collections::HashMap::new(),
            },
            &stats,
            current,
        );

        assert!(result.threat_score < 50.0, "Normal rate should not score high, got {}", result.threat_score);
    }
}
