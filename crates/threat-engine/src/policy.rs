//! Custom Policy DSL for Proxilion
//!
//! Allows users to define threat detection rules in TOML configuration files.
//!
//! # Example Policy File
//!
//! ```toml
//! # proxilion-policy.toml
//!
//! [settings]
//! alert_threshold = 50
//! block_threshold = 70
//! terminate_threshold = 90
//!
//! [[rules]]
//! name = "block-nmap"
//! description = "Block network scanning tools"
//! pattern = "nmap|masscan|zmap"
//! action = "block"
//! score = 85
//!
//! [[rules]]
//! name = "allow-git"
//! description = "Allow standard git operations"
//! pattern = "^git (status|log|diff|add|commit|push|pull|fetch|branch|checkout)"
//! action = "allow"
//! score = 0
//!
//! [[allowlists.users]]
//! id = "security-team@company.com"
//! bypass_patterns = ["nmap", "metasploit"]
//!
//! [[blocklists.commands]]
//! pattern = "rm -rf /"
//! reason = "Destructive command"
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;
use regex::Regex;

/// Policy configuration loaded from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub settings: PolicySettings,

    #[serde(default)]
    pub rules: Vec<Rule>,

    #[serde(default)]
    pub allowlists: Allowlists,

    #[serde(default)]
    pub blocklists: Blocklists,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    #[serde(default = "default_alert_threshold")]
    pub alert_threshold: f64,

    #[serde(default = "default_block_threshold")]
    pub block_threshold: f64,

    #[serde(default = "default_terminate_threshold")]
    pub terminate_threshold: f64,

    /// Maximum score adjustment from custom rules
    #[serde(default = "default_max_score_adjustment")]
    pub max_score_adjustment: f64,

    /// Enable/disable specific analyzers
    #[serde(default)]
    pub disabled_analyzers: Vec<String>,

    /// Enable/disable specific analyzers
    #[serde(default)]
    pub enabled_analyzers: Vec<String>,
}

fn default_alert_threshold() -> f64 { 50.0 }
fn default_block_threshold() -> f64 { 70.0 }
fn default_terminate_threshold() -> f64 { 90.0 }
fn default_max_score_adjustment() -> f64 { 50.0 }

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            alert_threshold: default_alert_threshold(),
            block_threshold: default_block_threshold(),
            terminate_threshold: default_terminate_threshold(),
            max_score_adjustment: default_max_score_adjustment(),
            disabled_analyzers: Vec::new(),
            enabled_analyzers: Vec::new(),
        }
    }
}

/// A custom detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: String,

    /// Regex pattern to match against command/path/query
    pub pattern: String,

    /// What to do when pattern matches
    pub action: RuleAction,

    /// Score adjustment when matched (-100 to +100)
    #[serde(default)]
    pub score: f64,

    /// Target to match against (command, path, url, query, all)
    #[serde(default = "default_target")]
    pub target: MatchTarget,

    /// Optional conditions for rule activation
    #[serde(default)]
    pub conditions: RuleConditions,

    /// Priority for rule ordering (higher = checked first)
    #[serde(default)]
    pub priority: i32,

    /// Whether this rule is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_target() -> MatchTarget { MatchTarget::All }
fn default_enabled() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Allow and skip further analysis
    Allow,
    /// Alert but continue processing
    Alert,
    /// Block the request
    Block,
    /// Terminate the session
    Terminate,
    /// Just adjust score, continue normal processing
    Adjust,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MatchTarget {
    /// Match against bash commands
    Command,
    /// Match against file paths
    Path,
    /// Match against URLs
    Url,
    /// Match against database queries
    Query,
    /// Match against all fields
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConditions {
    /// Only apply if user matches pattern
    #[serde(default)]
    pub user_pattern: Option<String>,

    /// Only apply during certain hours (0-23)
    #[serde(default)]
    pub hours: Option<Vec<u32>>,

    /// Only apply on certain days (0=Sunday, 6=Saturday)
    #[serde(default)]
    pub days: Option<Vec<u32>>,

    /// Only apply if session has this many requests
    #[serde(default)]
    pub min_session_requests: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Allowlists {
    /// Users who bypass certain patterns
    #[serde(default)]
    pub users: Vec<UserAllowlist>,

    /// Commands that are always allowed
    #[serde(default)]
    pub commands: Vec<CommandAllowlist>,

    /// Paths that are always allowed
    #[serde(default)]
    pub paths: Vec<PathAllowlist>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAllowlist {
    /// User ID pattern (supports regex)
    pub id: String,

    /// Patterns this user can bypass
    #[serde(default)]
    pub bypass_patterns: Vec<String>,

    /// Maximum threat score for this user (overrides normal thresholds)
    #[serde(default)]
    pub max_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAllowlist {
    /// Command pattern (regex)
    pub pattern: String,

    /// Reason for allowing
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAllowlist {
    /// Path pattern (regex)
    pub pattern: String,

    /// Reason for allowing
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Blocklists {
    /// Commands that are always blocked
    #[serde(default)]
    pub commands: Vec<CommandBlocklist>,

    /// Paths that are always blocked
    #[serde(default)]
    pub paths: Vec<PathBlocklist>,

    /// IPs/domains that are always blocked
    #[serde(default)]
    pub network: Vec<NetworkBlocklist>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandBlocklist {
    /// Command pattern (regex)
    pub pattern: String,

    /// Reason for blocking
    #[serde(default)]
    pub reason: String,

    /// Score to assign when matched
    #[serde(default = "default_blocklist_score")]
    pub score: f64,
}

fn default_blocklist_score() -> f64 { 100.0 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathBlocklist {
    /// Path pattern (regex)
    pub pattern: String,

    /// Reason for blocking
    #[serde(default)]
    pub reason: String,

    /// Score to assign when matched
    #[serde(default = "default_blocklist_score")]
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBlocklist {
    /// IP or domain pattern (regex)
    pub pattern: String,

    /// Reason for blocking
    #[serde(default)]
    pub reason: String,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            settings: PolicySettings::default(),
            rules: Vec::new(),
            allowlists: Allowlists::default(),
            blocklists: Blocklists::default(),
        }
    }
}

impl Policy {
    /// Load policy from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| PolicyError::IoError(e.to_string()))?;
        Self::from_str(&content)
    }

    /// Parse policy from TOML string
    pub fn from_str(content: &str) -> Result<Self, PolicyError> {
        let policy: Policy = toml::from_str(content)
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the policy configuration
    pub fn validate(&self) -> Result<(), PolicyError> {
        // Validate thresholds
        if self.settings.alert_threshold >= self.settings.block_threshold {
            return Err(PolicyError::ValidationError(
                "alert_threshold must be less than block_threshold".to_string()
            ));
        }
        if self.settings.block_threshold >= self.settings.terminate_threshold {
            return Err(PolicyError::ValidationError(
                "block_threshold must be less than terminate_threshold".to_string()
            ));
        }

        // Validate rule patterns are valid regex
        for rule in &self.rules {
            Regex::new(&rule.pattern)
                .map_err(|e| PolicyError::InvalidPattern(rule.name.clone(), e.to_string()))?;

            if let Some(ref user_pattern) = rule.conditions.user_pattern {
                Regex::new(user_pattern)
                    .map_err(|e| PolicyError::InvalidPattern(
                        format!("{}.conditions.user_pattern", rule.name),
                        e.to_string()
                    ))?;
            }
        }

        // Validate allowlist patterns
        for user in &self.allowlists.users {
            Regex::new(&user.id)
                .map_err(|e| PolicyError::InvalidPattern(
                    format!("allowlist.user.{}", user.id),
                    e.to_string()
                ))?;
        }

        // Validate blocklist patterns
        for cmd in &self.blocklists.commands {
            Regex::new(&cmd.pattern)
                .map_err(|e| PolicyError::InvalidPattern(
                    format!("blocklist.command.{}", cmd.pattern),
                    e.to_string()
                ))?;
        }

        Ok(())
    }

    /// Check if a user is allowlisted for a pattern
    pub fn is_user_allowlisted(&self, user_id: &str, pattern: &str) -> bool {
        for user in &self.allowlists.users {
            if let Ok(user_regex) = Regex::new(&user.id) {
                if user_regex.is_match(user_id) {
                    for bypass in &user.bypass_patterns {
                        if pattern.contains(bypass) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a command is in the blocklist
    pub fn check_command_blocklist(&self, command: &str) -> Option<(&str, f64)> {
        for block in &self.blocklists.commands {
            if let Ok(regex) = Regex::new(&block.pattern) {
                if regex.is_match(command) {
                    return Some((&block.reason, block.score));
                }
            }
        }
        None
    }

    /// Evaluate custom rules against a command
    pub fn evaluate_rules(&self, command: &str, user_id: Option<&str>) -> RuleEvaluation {
        let mut result = RuleEvaluation::default();

        // Sort rules by priority (higher first)
        let mut sorted_rules: Vec<_> = self.rules.iter()
            .filter(|r| r.enabled)
            .collect();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in sorted_rules {
            // Check conditions
            if let Some(ref user_pattern) = rule.conditions.user_pattern {
                if let Some(uid) = user_id {
                    if let Ok(regex) = Regex::new(user_pattern) {
                        if !regex.is_match(uid) {
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            }

            // Check pattern match
            if let Ok(regex) = Regex::new(&rule.pattern) {
                if regex.is_match(command) {
                    result.matched_rules.push(rule.name.clone());
                    result.score_adjustment += rule.score.clamp(
                        -self.settings.max_score_adjustment,
                        self.settings.max_score_adjustment
                    );

                    match rule.action {
                        RuleAction::Allow => {
                            result.action = Some(RuleAction::Allow);
                            result.reason = Some(rule.description.clone());
                            return result; // Allow rules short-circuit
                        }
                        RuleAction::Block => {
                            result.action = Some(RuleAction::Block);
                            result.reason = Some(rule.description.clone());
                        }
                        RuleAction::Terminate => {
                            result.action = Some(RuleAction::Terminate);
                            result.reason = Some(rule.description.clone());
                            return result; // Terminate rules short-circuit
                        }
                        RuleAction::Alert => {
                            if result.action.is_none() {
                                result.action = Some(RuleAction::Alert);
                                result.reason = Some(rule.description.clone());
                            }
                        }
                        RuleAction::Adjust => {
                            // Just score adjustment, no action override
                        }
                    }
                }
            }
        }

        result
    }
}

/// Result of evaluating custom rules
#[derive(Debug, Clone, Default)]
pub struct RuleEvaluation {
    /// Rules that matched
    pub matched_rules: Vec<String>,
    /// Total score adjustment
    pub score_adjustment: f64,
    /// Forced action (if any)
    pub action: Option<RuleAction>,
    /// Reason for the action
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub enum PolicyError {
    IoError(String),
    ParseError(String),
    ValidationError(String),
    InvalidPattern(String, String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::IoError(e) => write!(f, "IO error: {}", e),
            PolicyError::ParseError(e) => write!(f, "Parse error: {}", e),
            PolicyError::ValidationError(e) => write!(f, "Validation error: {}", e),
            PolicyError::InvalidPattern(name, e) => write!(f, "Invalid pattern in {}: {}", name, e),
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = Policy::default();
        assert_eq!(policy.settings.alert_threshold, 50.0);
        assert_eq!(policy.settings.block_threshold, 70.0);
        assert_eq!(policy.settings.terminate_threshold, 90.0);
    }

    #[test]
    fn test_parse_simple_policy() {
        let toml = r#"
            [settings]
            alert_threshold = 40
            block_threshold = 60
            terminate_threshold = 80

            [[rules]]
            name = "block-nmap"
            pattern = "nmap"
            action = "block"
            score = 85
        "#;

        let policy = Policy::from_str(toml).unwrap();
        assert_eq!(policy.settings.alert_threshold, 40.0);
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].name, "block-nmap");
    }

    #[test]
    fn test_rule_evaluation() {
        let toml = r#"
            [settings]
            alert_threshold = 50
            block_threshold = 70
            terminate_threshold = 90
            max_score_adjustment = 100

            [[rules]]
            name = "allow-git"
            pattern = "^git (status|log|diff)"
            action = "allow"
            score = 0
            priority = 100

            [[rules]]
            name = "block-nmap"
            pattern = "nmap"
            action = "block"
            score = 85
            priority = 50
        "#;

        let policy = Policy::from_str(toml).unwrap();

        // Git should be allowed
        let result = policy.evaluate_rules("git status", None);
        assert_eq!(result.action, Some(RuleAction::Allow));

        // Nmap should be blocked
        let result = policy.evaluate_rules("nmap -sV target.com", None);
        assert_eq!(result.action, Some(RuleAction::Block));
        assert_eq!(result.score_adjustment, 85.0);

        // Unknown command - no rule match
        let result = policy.evaluate_rules("ls -la", None);
        assert!(result.action.is_none());
    }

    #[test]
    fn test_user_allowlist() {
        let toml = r#"
            [[allowlists.users]]
            id = "security-team@.*"
            bypass_patterns = ["nmap", "metasploit"]
        "#;

        let policy = Policy::from_str(toml).unwrap();

        assert!(policy.is_user_allowlisted("security-team@company.com", "nmap"));
        assert!(!policy.is_user_allowlisted("developer@company.com", "nmap"));
    }

    #[test]
    fn test_command_blocklist() {
        let toml = r#"
            [[blocklists.commands]]
            pattern = "rm -rf /"
            reason = "Destructive command"
            score = 100
        "#;

        let policy = Policy::from_str(toml).unwrap();

        let result = policy.check_command_blocklist("rm -rf /");
        assert!(result.is_some());
        let (reason, score) = result.unwrap();
        assert_eq!(reason, "Destructive command");
        assert_eq!(score, 100.0);
    }

    #[test]
    fn test_invalid_threshold_order() {
        let toml = r#"
            [settings]
            alert_threshold = 80
            block_threshold = 70
            terminate_threshold = 90
        "#;

        let result = Policy::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_regex() {
        let toml = r#"
            [[rules]]
            name = "bad-regex"
            pattern = "[invalid"
            action = "block"
        "#;

        let result = Policy::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_conditional_rules() {
        let toml = r#"
            [[rules]]
            name = "security-team-nmap"
            pattern = "nmap"
            action = "allow"
            score = 0
            [rules.conditions]
            user_pattern = "security-.*@company.com"
        "#;

        let policy = Policy::from_str(toml).unwrap();

        // Security team can use nmap
        let result = policy.evaluate_rules("nmap -sV target.com", Some("security-admin@company.com"));
        assert_eq!(result.action, Some(RuleAction::Allow));

        // Regular users cannot
        let result = policy.evaluate_rules("nmap -sV target.com", Some("developer@company.com"));
        assert!(result.action.is_none());
    }
}
