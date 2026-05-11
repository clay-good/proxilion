//! Decision types returned by policy evaluation (Layer B).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block {
        reason: String,
        override_allowed: bool,
    },
    RequireConfirmation {
        reason: String,
    },
    RateLimit {
        burst: u32,
        per_seconds: u32,
    },
}

#[derive(Debug, Clone)]
pub struct ReadFilter {
    pub quarantine_patterns: Vec<Pattern>,
    pub quarantine_action: QuarantineAction,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    Literal(String),
    Regex(regex::Regex),
}

impl Pattern {
    pub fn is_match(&self, haystack: &str) -> bool {
        match self {
            Pattern::Literal(s) => haystack.contains(s.as_str()),
            Pattern::Regex(r) => r.is_match(haystack),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineAction {
    ReplaceWithMarker,
    StripSilently,
    BlockRequest,
}
