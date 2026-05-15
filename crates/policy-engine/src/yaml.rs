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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_safe_production_posture() {
        // ui-less-surfaces.md §2.1 — `enforce` is the default mode so an
        // operator who forgets the field doesn't silently demote.
        assert_eq!(default_mode(), Mode::Enforce);
        // PIC audit-only by default; runtime-gate is opt-in.
        assert_eq!(default_pic_mode(), PicMode::Audit);
        // Read-filter default replaces matched bytes with a marker, keeping
        // the response visible to the agent rather than blocking the call.
        assert!(matches!(
            default_quarantine_action(),
            QuarantineActionCfg::ReplaceWithMarker
        ));
    }

    #[test]
    fn parse_policies_minimal_doc_applies_field_defaults() {
        let yaml = "\
- id: p1
  vendor: google
  action: drive.files.get
";
        let docs = parse_policies(yaml).unwrap();
        assert_eq!(docs.len(), 1);
        let d = &docs[0];
        assert_eq!(d.id, "p1");
        assert_eq!(d.mode, Mode::Enforce);
        assert_eq!(d.pic_mode, PicMode::Audit);
        assert!(d.required_ops.is_empty());
        assert!(d.read_filter.is_none());
        assert!(d.notifier_burst.is_none());
        assert!(d.audit_body.is_none());
    }

    #[test]
    fn parse_policies_round_trips_observe_mode_and_runtime_gate() {
        let yaml = "\
- id: p1
  vendor: google
  action: drive.files.get
  mode: observe
  pic_mode: runtime-gate
";
        let docs = parse_policies(yaml).unwrap();
        assert_eq!(docs[0].mode, Mode::Observe);
        assert_eq!(docs[0].pic_mode, PicMode::RuntimeGate);
    }

    #[test]
    fn parse_policies_audit_body_modes() {
        for (yaml_val, expect) in [
            ("hash", AuditBodyMode::Hash),
            ("redact_pii", AuditBodyMode::RedactPii),
            ("full", AuditBodyMode::Full),
        ] {
            let y = format!("- id: p\n  vendor: v\n  action: a\n  audit_body: {yaml_val}\n");
            let d = &parse_policies(&y).unwrap()[0];
            assert_eq!(d.audit_body, Some(expect));
        }
    }

    #[test]
    fn parse_policies_rejects_unknown_mode_value() {
        let yaml = "\
- id: p1
  vendor: g
  action: a
  mode: paranoid
";
        // `Mode` is a closed enum (serde rejects unknown variants by default).
        assert!(parse_policies(yaml).is_err());
    }

    #[test]
    fn recipients_cfg_accepts_string_or_vec() {
        let yaml = "\
- id: p1
  vendor: g
  action: a
  notifier_recipients:
    to: alice@example.com
    cc:
      - bob@example.com
      - carol@example.com
";
        let d = &parse_policies(yaml).unwrap()[0];
        let r = d.notifier_recipients.as_ref().unwrap();
        assert_eq!(
            r.to.as_deref(),
            Some(&["alice@example.com".to_string()][..])
        );
        assert_eq!(
            r.cc.as_deref(),
            Some(
                &[
                    "bob@example.com".to_string(),
                    "carol@example.com".to_string()
                ][..]
            )
        );
        assert!(r.bcc.is_none());
    }

    #[test]
    fn quarantine_patterns_accept_literal_or_regex() {
        let yaml = "\
- id: p1
  vendor: g
  action: a
  read_filter:
    quarantine_patterns:
      - ignore previous
      - regex: '<\\|.*?\\|>'
";
        let d = &parse_policies(yaml).unwrap()[0];
        let pats = &d.read_filter.as_ref().unwrap().quarantine_patterns;
        assert_eq!(pats.len(), 2);
        assert!(matches!(pats[0], QuarantinePatternCfg::Literal(_)));
        assert!(matches!(pats[1], QuarantinePatternCfg::Regex { .. }));
    }

    #[test]
    fn burst_cfg_fields_are_each_optional() {
        // Threshold alone, window alone, both, neither — all valid shapes.
        for body in [
            "notifier_burst:\n    threshold: 10",
            "notifier_burst:\n    window_seconds: 30",
            "notifier_burst:\n    threshold: 10\n    window_seconds: 30",
            "",
        ] {
            let y = format!("- id: p\n  vendor: g\n  action: a\n  {body}\n");
            let docs = parse_policies(&y).unwrap();
            assert_eq!(docs.len(), 1, "yaml: {y}");
        }
    }
}
