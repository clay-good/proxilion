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

    /// Per-policy enforcement mode (ui-less-surfaces.md §2). `enforce` is the
    /// production posture; `observe` records what *would* have happened and
    /// lets the request through; `disabled` skips evaluation entirely.
    #[serde(default = "default_mode")]
    pub mode: Mode,

    /// Optional shorthand seen in spec.md §9 examples (`override: requires_justification`).
    #[serde(default, rename = "override")]
    pub override_: Option<String>,

    /// Per-policy burst-suppression override (ui-less-surfaces.md §5.6).
    /// Both fields are optional individually so a policy can override just
    /// threshold OR just window. Absent fields fall back to the global
    /// default in `BurstConfig::default()`.
    #[serde(default)]
    pub notifier_burst: Option<BurstCfg>,

    /// Per-policy body audit minimization (ui-less-surfaces.md §6.4).
    /// `None` → bodies are NOT persisted (the privacy default).
    /// `Some(Hash)` → SHA-256 of req+resp bytes is stored.
    /// `Some(RedactPii)` → regex-based redaction (email, SSN, phone, CC).
    /// `Some(Full)` → raw bytes persisted.
    #[serde(default)]
    pub audit_body: Option<AuditBodyMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditBodyMode {
    Hash,
    RedactPii,
    Full,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BurstCfg {
    #[serde(default)]
    pub threshold: Option<usize>,
    #[serde(default)]
    pub window_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Evaluate, decide, and act. Production posture.
    Enforce,
    /// Evaluate, record `would_have_*` outcome, let the request through.
    Observe,
    /// Skip evaluation entirely. Useful as an emergency disable.
    Disabled,
}

fn default_mode() -> Mode {
    // Default to enforce so a policy missing the field doesn't silently
    // demote to observe — ui-less-surfaces.md §2.1 calls this out as the
    // safe production posture.
    Mode::Enforce
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
