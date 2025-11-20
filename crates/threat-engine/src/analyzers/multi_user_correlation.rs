/// Multi-User Correlation Analyzer
///
/// Detects coordinated attacks across multiple users in the same organization.
/// This catches distributed reconnaissance, credential stuffing campaigns,
/// and multi-agent orchestration that bypasses single-session detection.
///
/// GTG-1002 used multiple AI instances simultaneously - this detects that pattern.

use crate::{AnalyzerResult, MCPToolCall};
use mcp_protocol::FileOperation;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Organization-level activity tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgActivityStats {
    pub org_id: String,
    pub user_activities: HashMap<String, UserActivity>,
    pub active_sessions: usize,
    pub time_window_start: i64,
    pub time_window_end: i64,
}

/// Per-user activity within the organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    pub user_id: String,
    pub active_sessions: usize,
    pub tools_used: Vec<String>,
    pub targets_discovered: HashSet<String>,
    pub request_count: usize,
    pub last_request_time: i64,
}

/// Multi-user correlation analyzer
pub struct MultiUserCorrelationAnalyzer {
    /// Minimum users for coordinated attack detection
    min_users_for_coordination: usize,

    /// Time window for correlation (milliseconds)
    correlation_window_ms: i64,
}

impl MultiUserCorrelationAnalyzer {
    pub fn new() -> Self {
        Self {
            min_users_for_coordination: 3,
            correlation_window_ms: 3_600_000, // 1 hour
        }
    }

    /// Analyze organization-wide activity for coordinated attacks
    pub fn analyze_with_org_context(
        &self,
        tool_call: &MCPToolCall,
        org_stats: &OrgActivityStats,
    ) -> AnalyzerResult {
        let mut threat_score: f64 = 0.0;
        let mut patterns = Vec::new();

        // Pattern 1: Distributed Reconnaissance
        let recon_result = self.detect_distributed_reconnaissance(org_stats);
        if recon_result.threat_score > 0.0 {
            threat_score = threat_score.max(recon_result.threat_score);
            patterns.extend(recon_result.patterns);
        }

        // Pattern 2: Coordinated Credential Stuffing
        let cred_result = self.detect_credential_stuffing(org_stats);
        if cred_result.threat_score > 0.0 {
            threat_score = threat_score.max(cred_result.threat_score);
            patterns.extend(cred_result.patterns);
        }

        // Pattern 3: Multi-Agent Orchestration (GTG-1002 signature)
        let orchestration_result = self.detect_multi_agent_orchestration(org_stats);
        if orchestration_result.threat_score > 0.0 {
            threat_score = threat_score.max(orchestration_result.threat_score);
            patterns.extend(orchestration_result.patterns);
        }

        // Pattern 4: Time-Window Attack Coordination
        let timing_result = self.detect_time_window_coordination(org_stats, tool_call);
        if timing_result.threat_score > 0.0 {
            threat_score = threat_score.max(timing_result.threat_score);
            patterns.extend(timing_result.patterns);
        }

        AnalyzerResult {
            analyzer_name: "multi_user_correlation".to_string(),
            threat_score,
            patterns,
            metadata: serde_json::json!({
                "active_users": org_stats.user_activities.len(),
                "active_sessions": org_stats.active_sessions,
                "time_window_hours": (org_stats.time_window_end - org_stats.time_window_start) as f64 / 3_600_000.0,
            }),
        }
    }

    /// Detect distributed reconnaissance across multiple users
    ///
    /// Example: GTG-1002 splitting network scan across 5 AI instances
    /// User A: nmap 10.0.0.1-50
    /// User B: nmap 10.0.0.51-100
    /// User C: nmap 10.0.0.101-150
    /// User D: nmap 10.0.0.151-200
    /// User E: nmap 10.0.0.201-255
    fn detect_distributed_reconnaissance(&self, org_stats: &OrgActivityStats) -> AnalyzerResult {
        let mut threat_score = 0.0;
        let mut patterns = Vec::new();

        // Count users performing reconnaissance in time window
        let recon_users: Vec<_> = org_stats
            .user_activities
            .iter()
            .filter(|(_, activity)| {
                activity.tools_used.iter().any(|tool| {
                    tool.contains("nmap")
                        || tool.contains("masscan")
                        || tool.contains("rustscan")
                        || tool.contains("zmap")
                        || tool.contains("ping")
                        || tool.contains("traceroute")
                })
            })
            .collect();

        if recon_users.len() >= self.min_users_for_coordination {
            threat_score = 90.0;
            patterns.push(format!(
                "CRITICAL: Distributed reconnaissance - {} users scanning network simultaneously",
                recon_users.len()
            ));

            // Check if targeting overlapping network ranges
            let mut all_targets = HashSet::new();
            for (_, activity) in &recon_users {
                all_targets.extend(activity.targets_discovered.iter().cloned());
            }

            if all_targets.len() > 20 {
                threat_score = 100.0;
                patterns.push(format!(
                    "CRITICAL: Coordinated network scan covering {} targets",
                    all_targets.len()
                ));
            }
        }

        AnalyzerResult {
            analyzer_name: "distributed_reconnaissance".to_string(),
            threat_score,
            patterns,
            metadata: serde_json::json!({
                "recon_users": recon_users.len(),
                "total_targets": org_stats.user_activities.values()
                    .flat_map(|a| a.targets_discovered.iter())
                    .collect::<HashSet<_>>()
                    .len(),
            }),
        }
    }

    /// Detect coordinated credential stuffing campaigns
    ///
    /// Example: Multiple users attempting different credential paths
    /// User A: cat .ssh/id_rsa
    /// User B: cat .aws/credentials
    /// User C: cat .env
    /// User D: cat .kube/config
    fn detect_credential_stuffing(&self, org_stats: &OrgActivityStats) -> AnalyzerResult {
        let mut threat_score = 0.0;
        let mut patterns = Vec::new();

        // Count users accessing credentials
        let cred_users: Vec<_> = org_stats
            .user_activities
            .iter()
            .filter(|(_, activity)| {
                activity.tools_used.iter().any(|tool| {
                    tool.contains(".ssh/")
                        || tool.contains(".aws/")
                        || tool.contains(".env")
                        || tool.contains("credentials")
                        || tool.contains("secret")
                        || tool.contains("password")
                        || tool.contains("token")
                        || tool.contains("api_key")
                })
            })
            .collect();

        if cred_users.len() >= self.min_users_for_coordination {
            threat_score = 95.0;
            patterns.push(format!(
                "CRITICAL: Coordinated credential harvesting - {} users accessing secrets",
                cred_users.len()
            ));

            // Check if different credential types being targeted
            let mut credential_types = HashSet::new();
            for (_, activity) in &cred_users {
                for tool in &activity.tools_used {
                    if tool.contains(".ssh/") {
                        credential_types.insert("SSH");
                    }
                    if tool.contains(".aws/") {
                        credential_types.insert("AWS");
                    }
                    if tool.contains(".env") {
                        credential_types.insert("ENV");
                    }
                    if tool.contains(".kube/") {
                        credential_types.insert("Kubernetes");
                    }
                }
            }

            if credential_types.len() >= 3 {
                threat_score = 100.0;
                patterns.push(format!(
                    "TERMINATE: Multi-platform credential theft - {} credential types targeted",
                    credential_types.len()
                ));
            }
        }

        AnalyzerResult {
            analyzer_name: "credential_stuffing".to_string(),
            threat_score,
            patterns,
            metadata: serde_json::json!({
                "cred_users": cred_users.len(),
            }),
        }
    }

    /// Detect multi-agent orchestration (GTG-1002 signature)
    ///
    /// GTG-1002: "Multiple MCP servers... simultaneously"
    /// Detects 5+ parallel sessions from same org targeting different infrastructure
    fn detect_multi_agent_orchestration(&self, org_stats: &OrgActivityStats) -> AnalyzerResult {
        let mut threat_score = 0.0;
        let mut patterns = Vec::new();

        // GTG-1002 used multiple parallel sessions
        if org_stats.active_sessions >= 5 {
            threat_score = 85.0;
            patterns.push(format!(
                "HIGH: Multi-agent orchestration detected - {} parallel sessions",
                org_stats.active_sessions
            ));

            // Count unique targets across all users
            let unique_targets: HashSet<_> = org_stats
                .user_activities
                .values()
                .flat_map(|activity| activity.targets_discovered.iter())
                .collect();

            if unique_targets.len() >= 10 {
                threat_score = 95.0;
                patterns.push(format!(
                    "CRITICAL: Coordinated multi-target campaign - {} infrastructure targets",
                    unique_targets.len()
                ));
            }

            // Check request velocity (GTG-1002: "physically impossible" rates)
            let total_requests: usize = org_stats
                .user_activities
                .values()
                .map(|a| a.request_count)
                .sum();

            let time_window_seconds =
                (org_stats.time_window_end - org_stats.time_window_start) / 1000;
            let requests_per_second = total_requests as f64 / time_window_seconds as f64;

            if requests_per_second > 2.0 {
                threat_score = 100.0;
                patterns.push(format!(
                    "TERMINATE: Automated orchestration - {:.1} req/sec across {} agents (not humanly possible)",
                    requests_per_second,
                    org_stats.user_activities.len()
                ));
            }
        }

        AnalyzerResult {
            analyzer_name: "multi_agent_orchestration".to_string(),
            threat_score,
            patterns,
            metadata: serde_json::json!({
                "parallel_sessions": org_stats.active_sessions,
                "unique_targets": org_stats
                    .user_activities
                    .values()
                    .flat_map(|a| a.targets_discovered.iter())
                    .collect::<HashSet<_>>()
                    .len(),
            }),
        }
    }

    /// Detect time-window coordination patterns
    ///
    /// Example: Multiple users starting attacks within minutes of each other
    fn detect_time_window_coordination(
        &self,
        org_stats: &OrgActivityStats,
        _tool_call: &MCPToolCall,
    ) -> AnalyzerResult {
        let mut threat_score = 0.0;
        let mut patterns = Vec::new();

        // Check if multiple users started within tight time window
        let mut start_times: Vec<i64> = org_stats
            .user_activities
            .values()
            .map(|a| a.last_request_time)
            .collect();

        start_times.sort();

        if start_times.len() >= 3 {
            // Check if first 3 users started within 5 minutes
            let first = start_times[0];
            let third = start_times[2];
            let time_spread_minutes = (third - first) / 60_000;

            if time_spread_minutes <= 5 {
                // Only flag if tools are suspicious (not just git/npm/cargo)
                let has_suspicious_tools = org_stats.user_activities.values().any(|activity| {
                    activity.tools_used.iter().any(|tool| {
                        tool.contains("nmap")
                            || tool.contains("curl http")
                            || tool.contains(".ssh/")
                            || tool.contains(".env")
                            || tool.contains("credentials")
                            || tool.contains("masscan")
                            || tool.contains("sqlmap")
                    })
                });

                if has_suspicious_tools {
                    threat_score = 80.0;
                    patterns.push(format!(
                        "HIGH: Coordinated timing - {} users started within {} minutes",
                        start_times.len(),
                        time_spread_minutes
                    ));
                }
            }
        }

        AnalyzerResult {
            analyzer_name: "time_window_coordination".to_string(),
            threat_score,
            patterns,
            metadata: serde_json::json!({}),
        }
    }
}

impl Default for MultiUserCorrelationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_org_stats(
        users: Vec<(&str, Vec<&str>, Vec<&str>)>,
    ) -> OrgActivityStats {
        let mut user_activities = HashMap::new();

        for (user_id, tools, targets) in users {
            user_activities.insert(
                user_id.to_string(),
                UserActivity {
                    user_id: user_id.to_string(),
                    active_sessions: 1,
                    tools_used: tools.iter().map(|s| s.to_string()).collect(),
                    targets_discovered: targets.iter().map(|s| s.to_string()).collect(),
                    request_count: tools.len(),
                    last_request_time: 1000000,
                },
            );
        }

        let active_sessions = user_activities.len();

        OrgActivityStats {
            org_id: "test-org".to_string(),
            user_activities,
            active_sessions,
            time_window_start: 1000000,
            time_window_end: 1003600000, // 1 hour window
        }
    }

    #[test]
    fn test_distributed_reconnaissance_detection() {
        let analyzer = MultiUserCorrelationAnalyzer::new();

        // Simulate 5 users scanning different network segments
        let org_stats = create_test_org_stats(vec![
            ("user1", vec!["nmap 10.0.0.1-50"], vec!["10.0.0.0/24"]),
            ("user2", vec!["nmap 10.0.0.51-100"], vec!["10.0.0.0/24"]),
            ("user3", vec!["nmap 10.0.0.101-150"], vec!["10.0.0.0/24"]),
            ("user4", vec!["nmap 10.0.0.151-200"], vec!["10.0.0.0/24"]),
            ("user5", vec!["nmap 10.0.0.201-255"], vec!["10.0.0.0/24"]),
        ]);

        let tool = MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze_with_org_context(&tool, &org_stats);

        assert!(
            result.threat_score >= 90.0,
            "Distributed recon should score critical, got {}",
            result.threat_score
        );
        assert!(result
            .patterns
            .iter()
            .any(|p| p.contains("Distributed reconnaissance")));
    }

    #[test]
    fn test_coordinated_credential_stuffing() {
        let analyzer = MultiUserCorrelationAnalyzer::new();

        // Simulate 4 users accessing different credential types
        let org_stats = create_test_org_stats(vec![
            ("user1", vec!["cat .ssh/id_rsa"], vec![]),
            ("user2", vec!["cat .aws/credentials"], vec![]),
            ("user3", vec!["cat .env"], vec![]),
            ("user4", vec!["cat .kube/config"], vec![]),
        ]);

        let tool = MCPToolCall::Filesystem {
            operation: FileOperation::Read,
            path: ".ssh/id_rsa".to_string(),
            content: None,
        };

        let result = analyzer.analyze_with_org_context(&tool, &org_stats);

        assert!(
            result.threat_score >= 95.0,
            "Coordinated credential stuffing should score critical, got {}",
            result.threat_score
        );
        assert!(result
            .patterns
            .iter()
            .any(|p| p.contains("credential harvesting")));
    }

    #[test]
    fn test_multi_agent_orchestration_gtg1002() {
        let analyzer = MultiUserCorrelationAnalyzer::new();

        // Simulate GTG-1002: 5 parallel sessions targeting different infrastructure
        let org_stats = OrgActivityStats {
            org_id: "evil-org".to_string(),
            user_activities: [
                ("agent1", "internal-db", 50),
                ("agent2", "api-gateway", 45),
                ("agent3", "auth-service", 60),
                ("agent4", "data-warehouse", 55),
                ("agent5", "logging-system", 50),
            ]
            .iter()
            .map(|(user, target, count)| {
                (
                    user.to_string(),
                    UserActivity {
                        user_id: user.to_string(),
                        active_sessions: 1,
                        tools_used: vec![format!("curl http://{}", target)],
                        targets_discovered: [target.to_string()].into(),
                        request_count: *count,
                        last_request_time: 1000000,
                    },
                )
            })
            .collect(),
            active_sessions: 5,
            time_window_start: 1000000,
            time_window_end: 1060000, // 1 minute window = 260 req/min total
        };

        let tool = MCPToolCall::Bash {
            command: "curl".to_string(),
            args: vec!["http://internal-db".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze_with_org_context(&tool, &org_stats);

        assert!(
            result.threat_score >= 95.0,
            "GTG-1002 orchestration should score TERMINATE, got {}",
            result.threat_score
        );
        assert!(result
            .patterns
            .iter()
            .any(|p| p.contains("orchestration") || p.contains("Automated")));
    }

    #[test]
    fn test_normal_team_activity_no_false_positive() {
        let analyzer = MultiUserCorrelationAnalyzer::new();

        // Simulate normal team doing legitimate development work
        let org_stats = create_test_org_stats(vec![
            ("dev1", vec!["git status", "npm install"], vec![]),
            ("dev2", vec!["cargo build", "cargo test"], vec![]),
            ("dev3", vec!["docker ps", "docker logs app"], vec![]),
        ]);

        let tool = MCPToolCall::Bash {
            command: "git".to_string(),
            args: vec!["status".to_string()],
            env: std::collections::HashMap::new(),
        };

        let result = analyzer.analyze_with_org_context(&tool, &org_stats);

        assert!(
            result.threat_score < 50.0,
            "Normal team activity should not trigger, got {}",
            result.threat_score
        );
    }
}
