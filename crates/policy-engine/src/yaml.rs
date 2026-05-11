//! YAML policy-document schema.
//!
//! A `PolicyDoc` mirrors a single entry in a customer-authored policy file
//! (see spec.md §9 examples). The match/decision blocks are kept as raw YAML
//! values; the matcher lives in `match_expr.rs`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDoc {
    pub id: String,
    pub vendor: String,
    pub action: String,

    /// Free-form match expression (see `match_expr::Matcher`).
    #[serde(default, rename = "match")]
    pub match_: serde_yaml::Value,

    /// Either a bare string (`"allow"`, `"block"`, ...) or a structured decision
    /// (`{ block: { reason: ..., override: requires_justification } }`).
    #[serde(default)]
    pub decision: serde_yaml::Value,

    #[serde(default)]
    pub read_filter: Option<ReadFilterCfg>,

    #[serde(default)]
    pub required_ops: Vec<String>,

    #[serde(default = "default_pic_mode")]
    pub pic_mode: PicMode,

    /// Optional shorthand seen in spec.md §9 examples (`override: requires_justification`).
    #[serde(default, rename = "override")]
    pub override_: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PicMode {
    Audit,
    RuntimeGate,
}

fn default_pic_mode() -> PicMode {
    PicMode::Audit
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFilterCfg {
    #[serde(default)]
    pub quarantine_patterns: Vec<QuarantinePatternCfg>,
    #[serde(default = "default_quarantine_action")]
    pub quarantine_action: QuarantineActionCfg,
}

fn default_quarantine_action() -> QuarantineActionCfg {
    QuarantineActionCfg::ReplaceWithMarker
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QuarantinePatternCfg {
    Literal(String),
    Regex { regex: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineActionCfg {
    ReplaceWithMarker,
    StripSilently,
    BlockRequest,
}

/// Top-level YAML doc: a sequence of policies.
pub fn parse_policies(yaml: &str) -> Result<Vec<PolicyDoc>, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}
