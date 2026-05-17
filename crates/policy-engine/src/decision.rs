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

#[cfg(test)]
mod tests {
    use super::*;

    // --- Pattern::is_match ----------------------------------------

    #[test]
    fn literal_pattern_matches_substring() {
        let p = Pattern::Literal("ignore previous".into());
        assert!(p.is_match("please ignore previous instructions"));
        assert!(!p.is_match("nothing to see here"));
    }

    /// Literal match is case-sensitive — adapters that need
    /// case-insensitive matching use regex patterns. Pinning the
    /// behavior so a future refactor doesn't silently change it.
    #[test]
    fn literal_pattern_is_case_sensitive() {
        let p = Pattern::Literal("Hello".into());
        assert!(p.is_match("Hello world"));
        assert!(!p.is_match("hello world"));
    }

    #[test]
    fn regex_pattern_matches_with_anchors() {
        let p = Pattern::Regex(regex::Regex::new(r"^ignore\b").unwrap());
        assert!(p.is_match("ignore previous instructions"));
        assert!(!p.is_match("please ignore previous"));
    }

    #[test]
    fn regex_pattern_supports_alternation() {
        let p = Pattern::Regex(regex::Regex::new(r"(?i)(system|user) prompt").unwrap());
        assert!(p.is_match("the SYSTEM PROMPT was..."));
        assert!(p.is_match("user prompt injection"));
        assert!(!p.is_match("no match"));
    }

    // --- Decision serde -------------------------------------------

    /// `kind` tagging is the wire-format contract for any consumer
    /// (operator dashboard, audit log, SIEM forwarder). Snapshot the
    /// JSON shape per variant.
    #[test]
    fn decision_allow_round_trips() {
        let d = Decision::Allow;
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(s, r#"{"kind":"allow"}"#);
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_block_carries_reason_and_override_flag() {
        let d = Decision::Block {
            reason: "external recipient".into(),
            override_allowed: true,
        };
        let s = serde_json::to_string(&d).unwrap();
        assert!(s.contains(r#""kind":"block""#));
        assert!(s.contains(r#""reason":"external recipient""#));
        assert!(s.contains(r#""override_allowed":true"#));
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_require_confirmation_round_trips() {
        let d = Decision::RequireConfirmation {
            reason: "external share".into(),
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_rate_limit_round_trips() {
        let d = Decision::RateLimit {
            burst: 5,
            per_seconds: 60,
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    /// snake_case kind values are part of the public wire contract
    /// (operator dashboards key off them). Renaming a variant must
    /// fail this snapshot loudly.
    #[test]
    fn quarantine_action_copy_and_eq_traits_work_at_use_sites() {
        // The read-filter dispatcher matches on the variant by value
        // (not by reference) — `Copy` lets the per-pattern processor
        // pass the action down without explicit `.clone()`. A regression
        // that dropped `Copy` would surface here as a compile error
        // rather than confusing failures at the dispatcher call site.
        let a = QuarantineAction::ReplaceWithMarker;
        let a2 = a; // Copy
        assert_eq!(a, a2);
        assert_ne!(
            QuarantineAction::ReplaceWithMarker,
            QuarantineAction::StripSilently
        );
        assert_ne!(
            QuarantineAction::StripSilently,
            QuarantineAction::BlockRequest
        );
        assert_ne!(
            QuarantineAction::ReplaceWithMarker,
            QuarantineAction::BlockRequest
        );
    }

    #[test]
    fn read_filter_clone_carries_patterns_and_action_independently() {
        // `ReadFilter` is `Clone` so the per-request engine snapshot can
        // hand a copy to the response-body scanner without giving up
        // ownership. Pin that the clone is shape-equivalent (same
        // pattern count) and that mutating one side's `Vec` doesn't
        // touch the other (no `Rc`/`Arc` smuggled into the inner vec).
        let f = ReadFilter {
            quarantine_patterns: vec![
                Pattern::Literal("ignore previous".into()),
                Pattern::Regex(regex::Regex::new(r"(?i)system prompt").unwrap()),
            ],
            quarantine_action: QuarantineAction::ReplaceWithMarker,
        };
        let mut c = f.clone();
        assert_eq!(c.quarantine_patterns.len(), 2);
        assert_eq!(c.quarantine_action, f.quarantine_action);
        c.quarantine_patterns.push(Pattern::Literal("extra".into()));
        // Original unchanged.
        assert_eq!(f.quarantine_patterns.len(), 2);
        assert_eq!(c.quarantine_patterns.len(), 3);
    }

    #[test]
    fn literal_pattern_matches_empty_haystack_against_empty_needle_only() {
        // The literal arm uses `str::contains`, which returns true for
        // the empty-needle case against any haystack — that's the
        // standard Rust semantic. A future refactor to a hand-rolled
        // matcher that gated on `needle.is_empty()` would change this
        // and silently break a policy that uses the empty string as a
        // catch-all marker. (Unusual, but documenting current behaviour.)
        let empty = Pattern::Literal(String::new());
        assert!(empty.is_match(""));
        assert!(empty.is_match("any text"));
        // Non-empty needle against empty haystack — must NOT match.
        let p = Pattern::Literal("needle".into());
        assert!(!p.is_match(""));
    }

    #[test]
    fn decision_kind_wire_strings_are_stable() {
        let cases: &[(Decision, &str)] = &[
            (Decision::Allow, "allow"),
            (
                Decision::Block {
                    reason: "x".into(),
                    override_allowed: false,
                },
                "block",
            ),
            (
                Decision::RequireConfirmation { reason: "x".into() },
                "require_confirmation",
            ),
            (
                Decision::RateLimit {
                    burst: 1,
                    per_seconds: 1,
                },
                "rate_limit",
            ),
        ];
        for (d, want_kind) in cases {
            let v: serde_json::Value =
                serde_json::from_str(&serde_json::to_string(d).unwrap()).unwrap();
            assert_eq!(v["kind"].as_str(), Some(*want_kind));
        }
    }
}
