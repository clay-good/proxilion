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

    /// Per-policy email recipient routing (ui-less-surfaces.md §5.4 dev 3).
    /// When present, the email notifier overrides the global `to`/`cc`/`bcc`
    /// from `notifier_config.email` for any blocked action that matches this
    /// policy. `None` → fall through to the global recipient list. Each
    /// field is independently optional: a policy can override just `to` and
    /// inherit `cc` / `bcc`.
    #[serde(default)]
    pub notifier_recipients: Option<RecipientsCfg>,

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

/// Per-policy email recipient override. ui-less-surfaces.md §5.4 dev 3.
/// Accepts either a single string or an array of strings per field, mirroring
/// the `notifier_config.email` payload shape. Each field is independently
/// optional — `None` means "inherit the global value."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientsCfg {
    #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
    pub to: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
    pub cc: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
    pub bcc: Option<Vec<String>>,
    /// Per-policy escalation deadline in minutes (ui-less-surfaces.md
    /// §5.7 dev 2). When set, the adapter writes
    /// `escalation_at = blocked_at + N min` on the blocked_actions row;
    /// the expiry sweeper re-fires the email notifier (subject prefixed
    /// REMINDER:) when the deadline passes without a decision, then
    /// stamps `escalated_at` so escalation runs at most once per row.
    /// `None` → no escalation for this policy.
    #[serde(default)]
    pub escalation_after_minutes: Option<u32>,
}

fn deserialize_string_or_vec_opt<'de, D>(de: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum One {
        S(String),
        V(Vec<String>),
    }
    Option::<One>::deserialize(de).map(|opt| {
        opt.map(|o| match o {
            One::S(s) => vec![s],
            One::V(v) => v,
        })
    })
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
