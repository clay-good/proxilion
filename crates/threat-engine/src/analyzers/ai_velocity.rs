/// AI Velocity Analyzer - Detects autonomous AI operation patterns
///
/// Adapted for MCP tool call analysis. This analyzer detects patterns that suggest
/// autonomous AI operation rather than human-supervised interaction by examining:
/// - Batch processing indicators (multiple targets, parallel operations)
/// - Automated pattern indicators (loops, iterations, systematic enumeration)
/// - Lack of human oversight indicators (no confirmation, no pauses)
///
/// Note: Full velocity analysis requires session history. This version provides
/// pattern-based detection that works on individual tool calls.

use mcp_protocol::MCPToolCall;
use crate::AnalyzerResult;
use serde_json::json;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Pre-compiled regex for IP address detection
    static ref IP_PATTERN: Regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();

    /// Pre-compiled regex for port range detection
    static ref PORT_RANGE_PATTERN: Regex = Regex::new(r"(\d+)-(\d+)").unwrap();
}

pub struct AIVelocityAnalyzer;

impl AIVelocityAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Detect batch processing patterns in commands
    fn detect_batch_patterns(&self, arguments: &str) -> Vec<(String, f64)> {
        let mut patterns = Vec::new();
        let lower = arguments.to_lowercase();

        // Pattern 1: Large network ranges
        if let Some(score) = self.detect_network_range(&lower) {
            patterns.push((
                format!("Large network range scan detected (automated enumeration)"),
                score,
            ));
        }

        // Pattern 2: Multiple targets in single command
        if let Some(count) = self.count_targets(&arguments) {
            if count >= 100 {
                patterns.push((
                    format!("Mass targeting: {} targets in single command (automated operation)", count),
                    90.0,
                ));
            } else if count >= 50 {
                patterns.push((
                    format!("Bulk operation: {} targets detected", count),
                    75.0,
                ));
            } else if count >= 20 {
                patterns.push((
                    format!("Batch processing: {} targets", count),
                    60.0,
                ));
            }
        }

        // Pattern 3: Loop/iteration indicators
        if self.has_loop_indicators(&lower) {
            patterns.push((
                "Automated loop/iteration detected (for/while/xargs)".to_string(),
                70.0,
            ));
        }

        // Pattern 4: Parallel execution flags
        if self.has_parallel_execution(&lower) {
            patterns.push((
                "Parallel execution flag detected (GNU parallel, xargs -P, &)".to_string(),
                75.0,
            ));
        }

        // Pattern 5: No-confirmation flags (automated mode)
        if self.has_no_confirmation_flags(&lower) {
            patterns.push((
                "Automated mode flags: --yes, --force, --no-confirm".to_string(),
                65.0,
            ));
        }

        // Pattern 6: High-speed scanning flags
        if self.has_high_speed_flags(&lower) {
            patterns.push((
                "High-speed scanning flags detected (--max-rate, -T5, --fast)".to_string(),
                80.0,
            ));
        }

        patterns
    }

    /// Detect network range size (larger = more likely automated)
    fn detect_network_range(&self, command: &str) -> Option<f64> {
        // /8 networks (16.7M hosts)
        if command.contains("/8") || command.contains("0.0.0.0/8") {
            return Some(100.0);
        }

        // /16 networks (65K hosts)
        if command.contains("/16") {
            return Some(95.0);
        }

        // /24 networks (254 hosts)
        if command.contains("/24") {
            return Some(70.0);
        }

        // Common large ranges
        if command.contains("0-255") || command.contains("1-65535") {
            return Some(90.0);
        }

        None
    }

    /// Count number of targets in command
    fn count_targets(&self, command: &str) -> Option<usize> {
        let mut count = 0;

        // Count IP addresses using pre-compiled regex
        count += IP_PATTERN.find_iter(command).count();

        // Count comma-separated items in common flags
        for flag in &["-t", "--target", "--host", "-h", "--ip"] {
            if let Some(pos) = command.find(flag) {
                let remaining = &command[pos..];
                if let Some(value_start) = remaining.find(char::is_whitespace) {
                    let value = remaining[value_start..].split_whitespace().next()?;
                    count += value.split(',').count();
                }
            }
        }

        // Count port ranges (e.g., 1-1000) using pre-compiled regex
        if let Some(caps) = PORT_RANGE_PATTERN.captures(command) {
            if let (Ok(start), Ok(end)) = (caps[1].parse::<usize>(), caps[2].parse::<usize>()) {
                if end > start {
                    count += end - start;
                }
            }
        }

        if count > 0 {
            Some(count)
        } else {
            None
        }
    }

    /// Check for loop/iteration indicators
    fn has_loop_indicators(&self, command: &str) -> bool {
        let loop_keywords = [
            "for ", "while ", "do ", "done",
            "xargs", "parallel",
            "| while", "| for",
        ];

        loop_keywords.iter().any(|kw| command.contains(kw))
    }

    /// Check for parallel execution indicators
    fn has_parallel_execution(&self, command: &str) -> bool {
        let parallel_indicators = [
            "parallel",
            "xargs -p",
            "xargs -n",
            "&", // Background execution
            "--parallel",
            "-j ", // Make-style parallel jobs
            "--max-procs",
        ];

        parallel_indicators.iter().any(|ind| command.contains(ind))
    }

    /// Check for no-confirmation flags
    fn has_no_confirmation_flags(&self, command: &str) -> bool {
        let no_confirm = [
            "--yes",
            "--force",
            "--no-confirm",
            "--assume-yes",
            "-y ",
            "--non-interactive",
            "--batch",
        ];

        no_confirm.iter().any(|flag| command.contains(flag))
    }

    /// Check for high-speed scanning flags
    fn has_high_speed_flags(&self, command: &str) -> bool {
        let speed_flags = [
            "--max-rate",
            "-t5", // nmap timing template 5 (insane)
            "-t4", // nmap timing template 4 (aggressive)
            "--min-rate",
            "--scan-delay 0",
            "--fast",
            "--quick",
        ];

        speed_flags.iter().any(|flag| command.contains(flag))
    }

    /// Analyze tool call for AI velocity patterns
    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        // Extract command/arguments based on tool type
        let arguments = match tool_call {
            MCPToolCall::Bash { command, args, .. } => {
                let mut full_cmd = command.clone();
                if !args.is_empty() {
                    full_cmd.push(' ');
                    full_cmd.push_str(&args.join(" "));
                }
                full_cmd
            },
            MCPToolCall::Network { url, method, .. } => {
                format!("{} {}", method, url)
            },
            MCPToolCall::Filesystem { operation, path, .. } => {
                format!("{:?} {}", operation, path)
            },
            MCPToolCall::Database { query, .. } => {
                query.clone()
            },
            MCPToolCall::Unknown { params, .. } => {
                params.to_string()
            },
        };

        // Detect batch patterns
        let patterns_with_scores = self.detect_batch_patterns(&arguments);

        if patterns_with_scores.is_empty() {
            return AnalyzerResult {
                analyzer_name: "ai_velocity".to_string(),
                threat_score: 0.0,
                patterns: Vec::new(),
                metadata: json!({}),
            };
        }

        // Calculate aggregate score (max + diversity bonus)
        let max_score = patterns_with_scores
            .iter()
            .map(|(_, score)| *score)
            .fold(0.0f64, f64::max);

        let diversity_bonus = ((patterns_with_scores.len() as f64 - 1.0) * 5.0).min(15.0);
        let threat_score = (max_score + diversity_bonus).min(100.0);

        // Extract pattern descriptions
        let patterns: Vec<String> = patterns_with_scores
            .iter()
            .map(|(desc, _)| desc.clone())
            .collect();

        // Build metadata
        let metadata = json!({
            "patterns_detected": patterns.len(),
            "max_individual_score": max_score,
            "diversity_bonus": diversity_bonus,
        });

        AnalyzerResult {
            analyzer_name: "ai_velocity".to_string(),
            threat_score,
            patterns,
            metadata,
        }
    }
}

impl Default for AIVelocityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mass_network_scan() {
        let analyzer = AIVelocityAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-sV".to_string(), "192.168.0.0/16".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 90.0, "Should detect mass network scan, got: {}", result.threat_score);
        assert!(!result.patterns.is_empty());
        assert!(result.patterns.iter().any(|p| p.contains("network range")));
    }

    #[test]
    fn test_parallel_execution() {
        let analyzer = AIVelocityAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec!["targets.txt".to_string(), "|".to_string(), "parallel".to_string(), "nmap".to_string(), "-sV".to_string(), "{}".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 65.0, "Should detect parallel execution, got: {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("parallel") || p.contains("loop")));
    }

    #[test]
    fn test_high_speed_scan() {
        let analyzer = AIVelocityAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-T5".to_string(), "--max-rate".to_string(), "10000".to_string(), "192.168.1.0/24".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 70.0, "Should detect high-speed scan, got: {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("High-speed") || p.contains("network range")));
    }

    #[test]
    fn test_automated_mode_flags() {
        let analyzer = AIVelocityAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "apt-get".to_string(),
            args: vec!["install".to_string(), "nmap".to_string(), "--yes".to_string(), "--force".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert!(result.threat_score >= 60.0, "Should detect automated flags, got: {}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Automated mode")));
    }

    #[test]
    fn test_normal_command_no_false_positive() {
        let analyzer = AIVelocityAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "ls".to_string(),
            args: vec!["-la".to_string(), "/home/user".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        assert_eq!(result.threat_score, 0.0, "Should not flag normal command");
        assert!(result.patterns.is_empty());
    }

    #[test]
    fn test_multiple_patterns_bonus() {
        let analyzer = AIVelocityAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "parallel".to_string(),
            args: vec!["-j".to_string(), "10".to_string(), "nmap".to_string(), "-T5".to_string(),
                      "--yes".to_string(), "--max-rate".to_string(), "10000".to_string(),
                      ":::".to_string(), "192.168.0.0/16".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call);

        // Should detect: network range, parallel execution, high-speed, automated flags
        assert!(result.threat_score >= 95.0, "Should have high score with multiple patterns, got: {}", result.threat_score);
        assert!(result.patterns.len() >= 3, "Should detect multiple patterns");
    }
}
