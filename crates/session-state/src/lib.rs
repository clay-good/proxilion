///! Session State Management for Proxilion MCP Gateway
///!
///! Provides portable session state tracking with multiple storage backends:
///! - Redis (primary for Docker/self-hosted)
///! - In-Memory (for testing/demo)
///! - PostgreSQL (optional, for enterprises)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

// Export store trait and implementations
pub mod store;
pub use store::{SessionStore, SessionStoreError};

/// Maximum number of events to keep in session history
const MAX_EVENTS: usize = 1000;

/// Maximum number of timestamps to track for rate limiting
const MAX_TIMESTAMPS: usize = 1000;

/// Session state for tracking user interactions and threat patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier
    pub session_id: String,

    /// User ID (from API key)
    pub user_id: String,

    /// Session creation timestamp (milliseconds)
    pub created_at: i64,

    /// Last activity timestamp (milliseconds)
    pub last_activity: i64,

    /// Event history (rolling window, max 1000 events)
    pub events: VecDeque<SessionEvent>,

    /// Total request count
    pub total_requests: u64,

    /// Blocked request count
    pub blocked_requests: u64,

    /// Alerted request count
    pub alerted_requests: u64,

    /// Maximum threat score seen in session
    pub max_threat_score: f64,

    /// Request timestamps for rate limiting (rolling window)
    pub request_timestamps: VecDeque<i64>,

    /// Target contexts for parallel_targets analyzer
    pub target_contexts: HashMap<String, TargetContext>,

    /// Authentication attempts for auth_timing analyzer
    pub auth_attempts: Vec<AuthAttempt>,

    /// Attack phases for session_progression analyzer
    pub attack_phases: Vec<AttackPhase>,

    /// Attack phase enums (simplified tracking)
    pub attack_phase_enums: Vec<AttackPhaseEnum>,

    /// Session status
    pub status: SessionStatus,

    /// Conversation history for social engineering detection (last 50 turns)
    pub conversation_history: VecDeque<ConversationTurn>,

    /// Organization ID (for cross-session correlation)
    pub org_id: Option<String>,
}

/// Individual session event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Event timestamp (milliseconds)
    pub timestamp: i64,

    /// Tool call type (Bash, Filesystem, Network, etc.)
    #[serde(alias = "tool_name")]
    pub tool_call_type: String,

    /// Calculated threat score
    pub threat_score: f64,

    /// Decision made
    pub decision: String,

    /// Patterns detected
    pub patterns: Vec<String>,

    /// Analyzer that triggered highest score (optional for backwards compatibility)
    #[serde(default)]
    pub top_analyzer: String,

    /// User message that led to this tool call (for conversation analysis)
    #[serde(default)]
    pub user_message: Option<String>,

    /// AI response that preceded this tool call (for conversation analysis)
    #[serde(default)]
    pub ai_response: Option<String>,
}

/// Conversation turn for analyzing social engineering patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTurn {
    /// Timestamp of conversation turn
    pub timestamp: i64,

    /// User message
    pub user_message: String,

    /// AI response (optional - might not have one yet)
    pub ai_response: Option<String>,

    /// Tool calls made in this turn
    pub tool_calls: Vec<String>,

    /// Threat score for this turn
    pub threat_score: f64,
}

impl SessionEvent {
    /// Get tool name (alias for tool_call_type)
    pub fn tool_name(&self) -> &str {
        &self.tool_call_type
    }
}

/// Target context for multi-target detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetContext {
    /// Target identifier (project_id, domain, IP, etc.)
    pub target_id: String,

    /// First time this target was accessed
    pub first_seen: i64,

    /// Last time this target was accessed
    pub last_seen: i64,

    /// Number of operations on this target
    pub event_count: u32,

    /// Operations performed on this target
    pub operations: Vec<String>,
}

/// Authentication attempt record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAttempt {
    /// Timestamp of auth attempt
    pub timestamp: i64,

    /// Target system/service
    pub target: String,

    /// Success or failure
    pub success: bool,

    /// Authentication method (password, key, token, etc.)
    pub method: String,
}

/// Attack phase tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPhase {
    /// Phase name (reconnaissance, exploitation, exfiltration, etc.)
    pub phase: String,

    /// Phase start time
    pub start_time: i64,

    /// Phase end time (None if still active)
    pub end_time: Option<i64>,

    /// Events in this phase
    pub event_ids: Vec<usize>,
}

/// Session status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    /// Active session
    Active,

    /// Session terminated due to critical threat
    Terminated,

    /// Session expired (idle timeout)
    Expired,
}

/// Rate limit check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitResult {
    /// Is rate limit exceeded?
    pub exceeded: bool,

    /// Is request allowed? (inverse of exceeded)
    pub allowed: bool,

    /// Requests in last minute
    pub requests_last_minute: u32,

    /// Requests in last hour
    pub requests_last_hour: u32,

    /// Requests in last day
    pub requests_last_day: u32,

    /// Retry after seconds (if exceeded)
    pub retry_after_seconds: u32,
}

/// Rate statistics for request_rate analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateStats {
    pub requests_last_minute: u32,
    pub requests_last_hour: u32,
    pub total_requests: u64,
    pub request_timestamps: Vec<i64>,
}

/// Session progression statistics for session_progression analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressionStats {
    pub attack_phases: Vec<String>,
    pub max_phase_reached: usize,
    pub phase_transitions: usize,
    pub session_age_hours: f64,
}

/// Attack phase enum (matches threat-engine analyzers)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AttackPhaseEnum {
    Benign = 0,
    Reconnaissance = 1,
    ResourceDevelopment = 2,
    InitialAccess = 3,
    Execution = 4,
    Persistence = 5,
    PrivilegeEscalation = 6,
    DefenseEvasion = 7,
    CredentialAccess = 8,
    Discovery = 9,
    LateralMovement = 10,
    Collection = 11,
    Exfiltration = 12,
}

impl AttackPhaseEnum {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackPhaseEnum::Benign => "benign",
            AttackPhaseEnum::Reconnaissance => "reconnaissance",
            AttackPhaseEnum::ResourceDevelopment => "resource_development",
            AttackPhaseEnum::InitialAccess => "initial_access",
            AttackPhaseEnum::Execution => "execution",
            AttackPhaseEnum::Persistence => "persistence",
            AttackPhaseEnum::PrivilegeEscalation => "privilege_escalation",
            AttackPhaseEnum::DefenseEvasion => "defense_evasion",
            AttackPhaseEnum::CredentialAccess => "credential_access",
            AttackPhaseEnum::Discovery => "discovery",
            AttackPhaseEnum::LateralMovement => "lateral_movement",
            AttackPhaseEnum::Collection => "collection",
            AttackPhaseEnum::Exfiltration => "exfiltration",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "reconnaissance" => AttackPhaseEnum::Reconnaissance,
            "resource_development" => AttackPhaseEnum::ResourceDevelopment,
            "initial_access" => AttackPhaseEnum::InitialAccess,
            "execution" => AttackPhaseEnum::Execution,
            "persistence" => AttackPhaseEnum::Persistence,
            "privilege_escalation" => AttackPhaseEnum::PrivilegeEscalation,
            "defense_evasion" => AttackPhaseEnum::DefenseEvasion,
            "credential_access" => AttackPhaseEnum::CredentialAccess,
            "discovery" => AttackPhaseEnum::Discovery,
            "lateral_movement" => AttackPhaseEnum::LateralMovement,
            "collection" => AttackPhaseEnum::Collection,
            "exfiltration" => AttackPhaseEnum::Exfiltration,
            _ => AttackPhaseEnum::Benign,
        }
    }
}

impl SessionState {
    /// Create a new session
    pub fn new(session_id: String, user_id: String, timestamp: i64) -> Self {
        Self {
            session_id,
            user_id,
            created_at: timestamp,
            last_activity: timestamp,
            events: VecDeque::with_capacity(MAX_EVENTS),
            total_requests: 0,
            blocked_requests: 0,
            alerted_requests: 0,
            max_threat_score: 0.0,
            request_timestamps: VecDeque::with_capacity(MAX_TIMESTAMPS),
            target_contexts: HashMap::new(),
            auth_attempts: Vec::new(),
            attack_phases: Vec::new(),
            attack_phase_enums: Vec::new(),
            status: SessionStatus::Active,
            conversation_history: VecDeque::with_capacity(50),
            org_id: None,
        }
    }

    /// Simplified constructor for Workers (uses current time)
    pub fn new_now(session_id: String, user_id: String) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self::new(session_id, user_id, now)
    }

    /// Add attack phase enum for simplified tracking
    pub fn add_attack_phase(&mut self, phase: AttackPhaseEnum) {
        // Only add if it's not the last phase
        if self.attack_phase_enums.last() != Some(&phase) {
            self.attack_phase_enums.push(phase);
        }
    }

    /// Add an event to the session
    pub fn add_event(&mut self, event: SessionEvent) {
        // Update last activity
        self.last_activity = event.timestamp;

        // Update counters
        self.total_requests += 1;
        match event.decision.as_str() {
            "Block" => self.blocked_requests += 1,
            "Alert" => self.alerted_requests += 1,
            _ => {}
        }

        // Update max threat score
        if event.threat_score > self.max_threat_score {
            self.max_threat_score = event.threat_score;
        }

        // Add to event history (rolling window)
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);

        // Add timestamp for rate limiting
        if self.request_timestamps.len() >= MAX_TIMESTAMPS {
            self.request_timestamps.pop_front();
        }
        self.request_timestamps.push_back(self.last_activity);
    }

    /// Get event history
    pub fn get_events(&self, limit: Option<usize>) -> Vec<SessionEvent> {
        let limit = limit.unwrap_or(self.events.len());
        self.events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Check rate limits
    pub fn check_rate_limit(&self, now: i64) -> RateLimitResult {
        let one_minute_ago = now - 60_000;
        let one_hour_ago = now - 3_600_000;
        let one_day_ago = now - 86_400_000;

        let requests_last_minute = self
            .request_timestamps
            .iter()
            .filter(|&&ts| ts >= one_minute_ago)
            .count() as u32;

        let requests_last_hour = self
            .request_timestamps
            .iter()
            .filter(|&&ts| ts >= one_hour_ago)
            .count() as u32;

        let requests_last_day = self
            .request_timestamps
            .iter()
            .filter(|&&ts| ts >= one_day_ago)
            .count() as u32;

        // Rate limit thresholds
        let exceeded = requests_last_minute > 100 || requests_last_hour > 1000;

        let retry_after_seconds = if exceeded {
            if requests_last_minute > 100 {
                60 // Wait 1 minute
            } else {
                300 // Wait 5 minutes
            }
        } else {
            0
        };

        RateLimitResult {
            exceeded,
            allowed: !exceeded,
            requests_last_minute,
            requests_last_hour,
            requests_last_day,
            retry_after_seconds,
        }
    }

    /// Update target context
    pub fn update_target(&mut self, target_id: String, operation: String, timestamp: i64) {
        let context = self.target_contexts
            .entry(target_id.clone())
            .or_insert(TargetContext {
                target_id: target_id.clone(),
                first_seen: timestamp,
                last_seen: timestamp,
                event_count: 0,
                operations: Vec::new(),
            });

        context.last_seen = timestamp;
        context.event_count += 1;
        context.operations.push(operation);

        // Keep only last 100 operations per target
        if context.operations.len() > 100 {
            context.operations.remove(0);
        }
    }

    /// Get all target contexts
    pub fn get_targets(&self) -> Vec<&TargetContext> {
        self.target_contexts.values().collect()
    }

    /// Count active targets in time window
    pub fn count_active_targets(&self, window_ms: i64, now: i64) -> usize {
        let window_start = now - window_ms;
        self.target_contexts
            .values()
            .filter(|ctx| ctx.last_seen >= window_start)
            .count()
    }

    /// Record authentication attempt
    pub fn record_auth_attempt(&mut self, attempt: AuthAttempt) {
        self.auth_attempts.push(attempt);

        // Keep only last 1000 auth attempts
        if self.auth_attempts.len() > 1000 {
            self.auth_attempts.remove(0);
        }
    }

    /// Get recent auth attempts
    pub fn get_auth_attempts(&self, window_ms: i64, now: i64) -> Vec<&AuthAttempt> {
        let window_start = now - window_ms;
        self.auth_attempts
            .iter()
            .filter(|a| a.timestamp >= window_start)
            .collect()
    }

    /// Start or update attack phase
    pub fn update_attack_phase(&mut self, phase: String, timestamp: i64) {
        // Check if phase already exists and is active
        if let Some(existing) = self.attack_phases.iter_mut().find(|p| p.phase == phase && p.end_time.is_none()) {
            // Phase is ongoing, add event
            existing.event_ids.push(self.events.len());
        } else {
            // End previous active phases
            for p in &mut self.attack_phases {
                if p.end_time.is_none() {
                    p.end_time = Some(timestamp);
                }
            }

            // Start new phase
            self.attack_phases.push(AttackPhase {
                phase,
                start_time: timestamp,
                end_time: None,
                event_ids: vec![self.events.len()],
            });
        }
    }

    /// Get attack phase progression
    pub fn get_phase_progression(&self) -> Vec<&AttackPhase> {
        self.attack_phases.iter().collect()
    }

    /// Terminate session
    pub fn terminate(&mut self) {
        self.status = SessionStatus::Terminated;
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.status == SessionStatus::Active
    }

    /// Get session age in milliseconds
    pub fn age_ms(&self, now: i64) -> i64 {
        now - self.created_at
    }

    /// Get idle time in milliseconds
    pub fn idle_ms(&self, now: i64) -> i64 {
        now - self.last_activity
    }

    /// Add conversation turn
    pub fn add_conversation_turn(&mut self, turn: ConversationTurn) {
        // Keep only last 50 conversation turns
        if self.conversation_history.len() >= 50 {
            self.conversation_history.pop_front();
        }
        self.conversation_history.push_back(turn);
    }

    /// Get conversation history (last N turns)
    pub fn get_conversation_history(&self, limit: Option<usize>) -> Vec<ConversationTurn> {
        let limit = limit.unwrap_or(self.conversation_history.len());
        self.conversation_history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get recent conversation context for semantic analysis
    pub fn get_conversation_context(&self, turns: usize) -> String {
        let recent_turns: Vec<_> = self.conversation_history
            .iter()
            .rev()
            .take(turns)
            .collect();

        let mut context = String::new();
        for (i, turn) in recent_turns.iter().rev().enumerate() {
            context.push_str(&format!("\n--- Turn {} ---\n", i + 1));
            context.push_str(&format!("User: {}\n", turn.user_message));
            if let Some(ai_resp) = &turn.ai_response {
                context.push_str(&format!("AI: {}\n", ai_resp));
            }
            if !turn.tool_calls.is_empty() {
                context.push_str(&format!("Tool calls: {}\n", turn.tool_calls.join(", ")));
            }
        }
        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_session() {
        let session = SessionState::new(
            "sess_123".to_string(),
            "user_456".to_string(),
            1000000,
        );

        assert_eq!(session.session_id, "sess_123");
        assert_eq!(session.user_id, "user_456");
        assert_eq!(session.total_requests, 0);
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn test_add_event() {
        let mut session = SessionState::new(
            "sess_123".to_string(),
            "user_456".to_string(),
            1000000,
        );

        let event = SessionEvent {
            timestamp: 1001000,
            tool_call_type: "Bash".to_string(),
            threat_score: 75.0,
            decision: "Block".to_string(),
            patterns: vec!["nmap detected".to_string()],
            top_analyzer: "enumeration".to_string(),
            user_message: None,
            ai_response: None,
        };

        session.add_event(event);

        assert_eq!(session.total_requests, 1);
        assert_eq!(session.blocked_requests, 1);
        assert_eq!(session.max_threat_score, 75.0);
        assert_eq!(session.events.len(), 1);
    }

    #[test]
    fn test_rate_limiting() {
        let mut session = SessionState::new(
            "sess_123".to_string(),
            "user_456".to_string(),
            1000000,
        );

        // Add 150 requests in last minute
        let now = 2000000;
        for i in 0..150 {
            let event = SessionEvent {
                timestamp: now - 59000 + (i * 100), // Within last minute
                tool_call_type: "Bash".to_string(),
                threat_score: 10.0,
                decision: "Allow".to_string(),
                patterns: vec![],
                top_analyzer: "none".to_string(),
                user_message: None,
                ai_response: None,
            };
            session.add_event(event);
        }

        let rate_limit = session.check_rate_limit(now);
        assert!(rate_limit.exceeded, "Should exceed rate limit");
        assert!(rate_limit.requests_last_minute > 100);
    }

    #[test]
    fn test_target_tracking() {
        let mut session = SessionState::new(
            "sess_123".to_string(),
            "user_456".to_string(),
            1000000,
        );

        session.update_target("target1".to_string(), "read".to_string(), 1001000);
        session.update_target("target2".to_string(), "write".to_string(), 1002000);
        session.update_target("target1".to_string(), "execute".to_string(), 1003000);

        assert_eq!(session.target_contexts.len(), 2);
        assert_eq!(session.count_active_targets(10000, 1003000), 2);

        let target1 = session.target_contexts.get("target1").unwrap();
        assert_eq!(target1.event_count, 2);
        assert_eq!(target1.operations.len(), 2);
    }

    #[test]
    fn test_attack_phase_progression() {
        let mut session = SessionState::new(
            "sess_123".to_string(),
            "user_456".to_string(),
            1000000,
        );

        session.update_attack_phase("reconnaissance".to_string(), 1001000);
        session.update_attack_phase("exploitation".to_string(), 1002000);
        session.update_attack_phase("exfiltration".to_string(), 1003000);

        let progression = session.get_phase_progression();
        assert_eq!(progression.len(), 3);
        assert_eq!(progression[0].phase, "reconnaissance");
        assert!(progression[0].end_time.is_some());
        assert_eq!(progression[2].phase, "exfiltration");
        assert!(progression[2].end_time.is_none()); // Still active
    }

    #[test]
    fn test_rolling_window() {
        let mut session = SessionState::new(
            "sess_123".to_string(),
            "user_456".to_string(),
            1000000,
        );

        // Add more than MAX_EVENTS
        for i in 0..(MAX_EVENTS + 100) {
            let event = SessionEvent {
                timestamp: 1000000 + i as i64,
                tool_call_type: "Bash".to_string(),
                threat_score: 10.0,
                decision: "Allow".to_string(),
                patterns: vec![],
                top_analyzer: "none".to_string(),
                user_message: None,
                ai_response: None,
            };
            session.add_event(event);
        }

        // Should only keep MAX_EVENTS
        assert_eq!(session.events.len(), MAX_EVENTS);
        assert_eq!(session.total_requests, (MAX_EVENTS + 100) as u64);
    }
}
