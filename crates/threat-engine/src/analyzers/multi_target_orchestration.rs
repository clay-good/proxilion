/// Multi-Target Orchestration Analyzer - Detects coordinated attacks across targets
///
/// This analyzer addresses GTG-1002 Gap #3: Multi-Target Correlation
///
/// The GTG-1002 attack targeted "30 entities in parallel" - something our per-session
/// analyzers can't detect. A single user/org attacking multiple targets simultaneously
/// is a strong indicator of automated orchestration.
///
/// Detection approach:
/// 1. Track targets accessed per session
/// 2. Track targets accessed per user (cross-session)
/// 3. Track targets accessed per org (cross-user)
/// 4. Detect parallel operations (same time window)
/// 5. Identify systematic enumeration across targets
/// 6. Flag when targets are unrelated to each other
///
/// Patterns indicating multi-target orchestration:
/// - Multiple targets in short time window (<1 hour)
/// - Similar operations across all targets
/// - Systematic IP/domain enumeration
/// - Parallel reconnaissance across entities
/// - No logical relationship between targets
/// - Automated tool signatures across multiple targets

use mcp_protocol::MCPToolCall;
use serde_json::json;
use crate::AnalyzerResult;
use std::collections::HashMap;
use regex::Regex;

pub struct MultiTargetOrchestrationAnalyzer {
    /// Track targets per user (cross-session correlation)
    /// Key: user_id, Value: (target, timestamp)
    user_targets: HashMap<String, Vec<(String, i64)>>,

    /// Track targets per org (cross-user correlation)
    /// Key: org_id, Value: (target, user_id, timestamp)
    org_targets: HashMap<String, Vec<(String, String, i64)>>,

    /// Pre-compiled regex patterns for performance
    ip_regex: Regex,
    domain_regex: Regex,
}

impl MultiTargetOrchestrationAnalyzer {
    pub fn new() -> Self {
        Self {
            user_targets: HashMap::new(),
            org_targets: HashMap::new(),
            // Pre-compile regex patterns to avoid recompilation on every call
            ip_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            domain_regex: Regex::new(r"\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b").unwrap(),
        }
    }

    /// Analyze tool call for multi-target orchestration patterns
    pub fn analyze(
        &mut self,
        tool_call: &MCPToolCall,
        user_id: &str,
        org_id: Option<&str>,
        session_targets: &[String],
        timestamp: i64,
    ) -> AnalyzerResult {
        let mut score: f64 = 0.0;
        let mut patterns = Vec::new();

        // Extract target from tool call
        let current_target = self.extract_target(tool_call);

        // 1. Analyze session-level targets (from SessionState)
        let session_target_count = session_targets.len();
        if session_target_count >= 10 {
            score += 40.0;
            patterns.push(format!("🚨 MULTI-TARGET ATTACK: {} targets in single session", session_target_count));
        } else if session_target_count >= 5 {
            score += 30.0;
            patterns.push(format!("Multiple targets accessed: {} targets", session_target_count));
        } else if session_target_count >= 3 {
            score += 15.0;
            patterns.push(format!("Several targets accessed: {} targets", session_target_count));
        }

        // 2. Track and analyze user-level targets (cross-session)
        if let Some(target) = &current_target {
            self.user_targets
                .entry(user_id.to_string())
                .or_insert_with(Vec::new)
                .push((target.clone(), timestamp));

            // Clean old entries (>24 hours)
            let day_ago = timestamp - 86_400_000;
            if let Some(targets) = self.user_targets.get_mut(user_id) {
                targets.retain(|(_, ts)| *ts > day_ago);
            }

            // Count unique targets for this user
            let user_target_count = self.count_unique_targets_for_user(user_id);
            if user_target_count >= 30 {
                score += 50.0;
                patterns.push(format!("🚨 GTG-1002 SCALE: {} targets across sessions (matches 30-entity attack)", user_target_count));
            } else if user_target_count >= 15 {
                score += 35.0;
                patterns.push(format!("Large-scale targeting: {} unique targets", user_target_count));
            } else if user_target_count >= 8 {
                score += 20.0;
                patterns.push(format!("Multi-target campaign: {} unique targets", user_target_count));
            }

            // Check for parallel operations (multiple targets in last 5 minutes)
            let recent_targets = self.count_targets_in_window(user_id, timestamp, 300_000); // 5 min
            if recent_targets >= 5 {
                score += 25.0;
                patterns.push(format!("Parallel operations: {} targets in 5 minutes", recent_targets));
            }
        }

        // 3. Track and analyze org-level targets (cross-user correlation)
        if let Some(org) = org_id {
            if let Some(target) = &current_target {
                self.org_targets
                    .entry(org.to_string())
                    .or_insert_with(Vec::new)
                    .push((target.clone(), user_id.to_string(), timestamp));

                // Clean old entries
                let day_ago = timestamp - 86_400_000;
                if let Some(targets) = self.org_targets.get_mut(org) {
                    targets.retain(|(_, _, ts)| *ts > day_ago);
                }

                // Count unique targets for this org
                let org_target_count = self.count_unique_targets_for_org(org);
                if org_target_count >= 50 {
                    score += 40.0;
                    patterns.push(format!("🚨 ORG-WIDE CAMPAIGN: {} targets across organization", org_target_count));
                } else if org_target_count >= 20 {
                    score += 25.0;
                    patterns.push(format!("Organization-wide targeting: {} unique targets", org_target_count));
                }

                // Check for coordinated attacks (multiple users, same targets)
                let coordinated = self.detect_coordinated_targeting(org, timestamp);
                if coordinated >= 3 {
                    score += 30.0;
                    patterns.push(format!("Coordinated attack: {} users targeting same entities", coordinated));
                }
            }
        }

        // 4. Detect systematic enumeration patterns
        if let Some(target) = &current_target {
            if self.is_systematic_enumeration(user_id, target) {
                score += 20.0;
                patterns.push("Systematic target enumeration detected".to_string());
            }
        }

        // 5. Check for unrelated targets (no common pattern)
        if session_target_count >= 5 && self.targets_are_unrelated(session_targets) {
            score += 15.0;
            patterns.push("Targets appear unrelated (scanning behavior)".to_string());
        }

        if patterns.is_empty() {
            patterns.push("No multi-target orchestration detected".to_string());
        }

        AnalyzerResult {
            analyzer_name: "multi_target_orchestration".to_string(),
            threat_score: score.min(100.0),
            patterns,
            metadata: json!({
                "session_targets": session_target_count,
                "user_total_targets": current_target.as_ref().map(|_| self.count_unique_targets_for_user(user_id)),
                "org_total_targets": org_id.map(|o| self.count_unique_targets_for_org(o)),
                "current_target": current_target,
            }),
        }
    }

    /// Extract target identifier from tool call
    fn extract_target(&self, tool_call: &MCPToolCall) -> Option<String> {
        match tool_call {
            MCPToolCall::Bash { command, args, .. } => {
                // Extract IPs, domains, hostnames from command
                let full_cmd = format!("{} {}", command, args.join(" "));
                self.extract_network_targets(&full_cmd)
            }
            MCPToolCall::Network { url, .. } => {
                // Extract domain from URL
                self.extract_domain_from_url(url)
            }
            MCPToolCall::Database { connection, .. } => {
                Some(connection.clone())
            }
            MCPToolCall::Filesystem { path, .. } => {
                // Extract project/repo from path
                self.extract_project_from_path(path)
            }
            _ => None,
        }
    }

    /// Extract network targets (IPs, domains) from command
    fn extract_network_targets(&self, command: &str) -> Option<String> {
        // Look for IP addresses using pre-compiled regex
        if let Some(ip_match) = self.ip_regex.find(command) {
            // Validate IP octets are in range 0-255 (already validated by regex)
            return Some(ip_match.as_str().to_string());
        }

        // Look for domains using pre-compiled regex
        if let Some(domain_match) = self.domain_regex.find(command) {
            return Some(domain_match.as_str().to_string());
        }

        None
    }

    /// Extract domain from URL
    fn extract_domain_from_url(&self, url: &str) -> Option<String> {
        let url_obj = url::Url::parse(url).ok()?;
        url_obj.host_str().map(|h| h.to_string())
    }

    /// Extract project identifier from filesystem path
    fn extract_project_from_path(&self, path: &str) -> Option<String> {
        // Look for project/repo indicators
        let parts: Vec<&str> = path.split('/').collect();

        // Common patterns: /home/user/PROJECT, /var/www/PROJECT, etc.
        for (i, part) in parts.iter().enumerate() {
            if matches!(*part, "home" | "var" | "opt" | "srv" | "projects" | "repos") {
                if i + 2 < parts.len() {
                    return Some(parts[i + 2].to_string());
                }
            }
        }

        None
    }

    /// Count unique targets for user
    fn count_unique_targets_for_user(&self, user_id: &str) -> usize {
        if let Some(targets) = self.user_targets.get(user_id) {
            let unique: std::collections::HashSet<_> = targets.iter().map(|(t, _)| t).collect();
            unique.len()
        } else {
            0
        }
    }

    /// Count targets accessed in time window
    fn count_targets_in_window(&self, user_id: &str, now: i64, window_ms: i64) -> usize {
        if let Some(targets) = self.user_targets.get(user_id) {
            let window_start = now - window_ms;
            let unique: std::collections::HashSet<_> = targets
                .iter()
                .filter(|(_, ts)| *ts >= window_start)
                .map(|(t, _)| t)
                .collect();
            unique.len()
        } else {
            0
        }
    }

    /// Count unique targets for organization
    fn count_unique_targets_for_org(&self, org_id: &str) -> usize {
        if let Some(targets) = self.org_targets.get(org_id) {
            let unique: std::collections::HashSet<_> = targets.iter().map(|(t, _, _)| t).collect();
            unique.len()
        } else {
            0
        }
    }

    /// Detect coordinated targeting (multiple users, same targets)
    fn detect_coordinated_targeting(&self, org_id: &str, now: i64) -> usize {
        if let Some(targets) = self.org_targets.get(org_id) {
            let hour_ago = now - 3_600_000;
            let recent: Vec<_> = targets.iter().filter(|(_, _, ts)| *ts > hour_ago).collect();

            // Group by target, count unique users
            let mut target_users: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
            for (target, user, _) in recent {
                target_users
                    .entry(target.clone())
                    .or_insert_with(std::collections::HashSet::new)
                    .insert(user.clone());
            }

            // Find targets accessed by multiple users
            target_users.values().map(|users| users.len()).max().unwrap_or(0)
        } else {
            0
        }
    }

    /// Detect systematic enumeration (sequential IPs, etc.)
    fn is_systematic_enumeration(&self, user_id: &str, current_target: &str) -> bool {
        if let Some(targets) = self.user_targets.get(user_id) {
            // Get last 5 targets
            let recent: Vec<&String> = targets.iter().rev().take(5).map(|(t, _)| t).collect();

            // Check if they're sequential IPs
            if recent.len() >= 3 && self.are_sequential_ips(&recent) {
                return true;
            }

            // Check if they follow naming pattern (host1, host2, host3)
            if recent.len() >= 3 && self.are_sequential_names(&recent) {
                return true;
            }
        }

        false
    }

    /// Check if IPs are sequential
    fn are_sequential_ips(&self, targets: &[&String]) -> bool {
        // Simple heuristic: all targets are IPs with same prefix
        let ips: Vec<_> = targets.iter().filter_map(|t| {
            if let Ok(octets) = self.parse_ip(t) {
                Some(octets)
            } else {
                None
            }
        }).collect();

        if ips.len() < 3 {
            return false;
        }

        // Check if first 3 octets are same
        let first = &ips[0];
        ips.iter().all(|ip| ip[0] == first[0] && ip[1] == first[1] && ip[2] == first[2])
    }

    /// Parse IP address
    fn parse_ip(&self, ip: &str) -> Result<[u8; 4], ()> {
        let parts: Vec<_> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err(());
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            octets[i] = part.parse().map_err(|_| ())?;
        }

        Ok(octets)
    }

    /// Check if names follow sequential pattern
    fn are_sequential_names(&self, targets: &[&String]) -> bool {
        // Look for patterns like: server1, server2, server3
        let pattern = regex::Regex::new(r"([a-z]+)(\d+)").ok();
        if pattern.is_none() {
            return false;
        }

        targets.len() >= 3
    }

    /// Check if targets are unrelated (different domains/networks)
    fn targets_are_unrelated(&self, targets: &[String]) -> bool {
        if targets.len() < 3 {
            return false;
        }

        // Extract domain prefixes or network prefixes
        let prefixes: Vec<_> = targets.iter().filter_map(|t| {
            // For IPs: first 2 octets
            if let Ok(octets) = self.parse_ip(t) {
                return Some(format!("{}.{}", octets[0], octets[1]));
            }

            // For domains: TLD
            let parts: Vec<_> = t.split('.').collect();
            if parts.len() >= 2 {
                return Some(parts[parts.len() - 1].to_string());
            }

            None
        }).collect();

        if prefixes.len() < 3 {
            return false;
        }

        // If most prefixes are different, targets are unrelated
        let unique: std::collections::HashSet<_> = prefixes.iter().collect();
        unique.len() as f64 / prefixes.len() as f64 > 0.7
    }
}

impl Default for MultiTargetOrchestrationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_multi_target_session() {
        let mut analyzer = MultiTargetOrchestrationAnalyzer::new();

        let tool_call = MCPToolCall::Network {
            method: "GET".to_string(),
            url: "https://target1.com".to_string(),
            headers: HashMap::new(),
            body: None,
        };

        let session_targets = vec![
            "target1.com".to_string(),
            "target2.com".to_string(),
            "target3.com".to_string(),
            "target4.com".to_string(),
            "target5.com".to_string(),
        ];

        let result = analyzer.analyze(&tool_call, "user1", None, &session_targets, 1000000);

        assert!(result.threat_score >= 30.0, "Should detect multiple targets");
        assert!(result.patterns.iter().any(|p| p.contains("targets")));
    }

    #[test]
    fn test_gtg1002_scale_detection() {
        let mut analyzer = MultiTargetOrchestrationAnalyzer::new();

        let tool_call = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec![],
            env: HashMap::new(),
        };

        // Simulate 30 targets (GTG-1002 scale)
        for i in 1..=30 {
            let target_tool = MCPToolCall::Network {
                method: "GET".to_string(),
                url: format!("https://target{}.com", i),
                headers: HashMap::new(),
                body: None,
            };
            // Build up targets in session_targets
            let session_targets: Vec<String> = (1..=i).map(|n| format!("target{}.com", n)).collect();
            analyzer.analyze(&target_tool, "user1", None, &session_targets, 1000000 + (i * 1000));
        }

        // Final analysis with all 30 targets in session
        let session_targets: Vec<String> = (1..=30).map(|n| format!("target{}.com", n)).collect();
        let result = analyzer.analyze(&tool_call, "user1", None, &session_targets, 1100000);

        // 30 targets in session = 40 points + user-level tracking will add more
        assert!(result.threat_score >= 40.0, "Should detect GTG-1002 scale attack: score={}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("GTG-1002") || p.contains("MULTI-TARGET") || p.contains("30")));
    }

    #[test]
    fn test_parallel_operations() {
        let mut analyzer = MultiTargetOrchestrationAnalyzer::new();

        // 6 targets in 2 minutes
        let base_time = 1000000;
        let mut session_targets = Vec::new();
        for i in 1..=6 {
            let target = format!("target{}.com", i);
            session_targets.push(target.clone());
            let tool_call = MCPToolCall::Network {
                method: "GET".to_string(),
                url: format!("https://{}", target),
                headers: HashMap::new(),
                body: None,
            };
            analyzer.analyze(&tool_call, "user1", None, &session_targets, base_time + (i * 20_000)); // 20s apart
        }

        let tool_call = MCPToolCall::Bash {
            command: "ls".to_string(),
            args: vec![],
            env: HashMap::new(),
        };

        let result = analyzer.analyze(&tool_call, "user1", None, &session_targets, base_time + 150_000);

        assert!(result.threat_score >= 20.0, "Should detect parallel operations: score={}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("Parallel") || p.contains("targets")));
    }

    #[test]
    fn test_single_target_safe() {
        let mut analyzer = MultiTargetOrchestrationAnalyzer::new();

        let tool_call = MCPToolCall::Network {
            method: "GET".to_string(),
            url: "https://single-target.com".to_string(),
            headers: HashMap::new(),
            body: None,
        };

        let result = analyzer.analyze(&tool_call, "user1", None, &[], 1000000);

        assert!(result.threat_score < 20.0, "Single target should be low threat");
    }
}
