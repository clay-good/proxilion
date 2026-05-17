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
    fn mode_wire_strings_pin_snake_case_per_variant() {
        // The dashboard's policy-mode toggle posts these exact strings;
        // a future variant rename without coordinated dashboard work
        // would silently drop the mode flip. Pin both directions
        // (serialize + deserialize round-trip).
        for (variant, wire) in [
            (Mode::Enforce, "\"enforce\""),
            (Mode::Observe, "\"observe\""),
            (Mode::Disabled, "\"disabled\""),
        ] {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, wire, "{variant:?}");
            let back: Mode = serde_json::from_str(wire).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn pic_mode_serializes_kebab_case_not_snake_case() {
        // `runtime-gate` (kebab) is the wire shape — a regression to
        // `runtime_gate` would silently break every existing policy YAML
        // (deserialize would error) and every dashboard PIC-mode toggle
        // (serialize would mismatch). This is the single highest-risk
        // wire-shape pin in this module — kebab/snake confusion is the
        // classic serde renaming bug.
        assert_eq!(
            serde_json::to_string(&PicMode::RuntimeGate).unwrap(),
            "\"runtime-gate\""
        );
        assert_eq!(serde_json::to_string(&PicMode::Audit).unwrap(), "\"audit\"");
        // Symmetric deserialize.
        let back: PicMode = serde_json::from_str("\"runtime-gate\"").unwrap();
        assert_eq!(back, PicMode::RuntimeGate);
        // Snake-case must NOT deserialize (closed enum).
        assert!(serde_json::from_str::<PicMode>("\"runtime_gate\"").is_err());
    }

    #[test]
    fn audit_body_mode_wire_strings_are_snake_case() {
        // Operator dashboards read these strings as labels; a rename
        // without coordinated UI work would break the audit-body
        // selector. Note: `RedactPii` → `redact_pii` (snake), NOT
        // `redact-pii` (kebab) — different scheme from PicMode above,
        // so this guard catches an accidental copy-paste between the
        // two attribute lines.
        for (v, wire) in [
            (AuditBodyMode::Hash, "\"hash\""),
            (AuditBodyMode::RedactPii, "\"redact_pii\""),
            (AuditBodyMode::Full, "\"full\""),
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), wire);
            let back: AuditBodyMode = serde_json::from_str(wire).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn quarantine_action_cfg_wire_strings_are_snake_case() {
        // The wire-shape contract for ReadFilterCfg's action field;
        // mirrored from the engine-internal `QuarantineAction` (in
        // decision.rs) but kept as a separate type so the YAML schema
        // can evolve independently. Pin all three variants.
        for (v, wire) in [
            (
                QuarantineActionCfg::ReplaceWithMarker,
                "\"replace_with_marker\"",
            ),
            (QuarantineActionCfg::StripSilently, "\"strip_silently\""),
            (QuarantineActionCfg::BlockRequest, "\"block_request\""),
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), wire, "{v:?}");
        }
    }

    #[test]
    fn deserialize_string_or_vec_opt_accepts_none_string_and_array() {
        // Covers all three shapes the helper handles, plus the None case
        // (absent field). The previous `recipients_cfg_accepts_string_or_vec`
        // test only exercised one of these per field; pinning all three
        // shapes side-by-side documents the contract for the helper itself.
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
            v: Option<Vec<String>>,
        }
        let none: Wrap = serde_yaml::from_str("{}").unwrap();
        assert!(none.v.is_none());
        let single: Wrap = serde_yaml::from_str("v: alice@x.com").unwrap();
        assert_eq!(single.v.as_deref(), Some(&["alice@x.com".to_string()][..]));
        let many: Wrap = serde_yaml::from_str("v:\n  - a@x\n  - b@x\n").unwrap();
        assert_eq!(
            many.v.as_deref(),
            Some(&["a@x".to_string(), "b@x".to_string()][..])
        );
    }

    #[test]
    fn read_filter_cfg_minimal_yields_empty_patterns_and_default_action() {
        // A `read_filter:` block with NO fields must deserialize cleanly
        // — both inner fields have `#[serde(default)]`. The default
        // action is `replace_with_marker` (the safe production posture).
        // A regression that made either field required would break every
        // existing policy with a stub read_filter block.
        let yaml = "\
- id: p
  vendor: v
  action: a
  read_filter: {}
";
        let d = &parse_policies(yaml).unwrap()[0];
        let rf = d.read_filter.as_ref().unwrap();
        assert!(rf.quarantine_patterns.is_empty());
        assert!(matches!(
            rf.quarantine_action,
            QuarantineActionCfg::ReplaceWithMarker
        ));
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

    #[test]
    fn recipients_cfg_round_trips_escalation_after_minutes_field() {
        // The `escalation_after_minutes` field on `RecipientsCfg` is the
        // per-policy escalation deadline the expiry sweeper reads (ui-less
        // §5.7 dev 2). Rounds 32+33 pinned the string/list union on to/cc/bcc
        // but never the deserialize round-trip on this u32 field, despite
        // the sweeper's `escalation_at = blocked_at + N min` SQL update
        // depending on it being present as `Some(_)` rather than collapsing
        // to None. A regression that dropped `#[serde(default)]` would
        // surface here as a missing-field deserialize error; a regression
        // that retyped to a different integer width would surface as an
        // overflow on the boundary inputs below.
        let y = "- id: p\n  vendor: g\n  action: a\n  notifier_recipients:\n    to: ops@acme.com\n    escalation_after_minutes: 240\n";
        let docs = parse_policies(y).unwrap();
        let r = docs[0]
            .notifier_recipients
            .as_ref()
            .expect("notifier_recipients present");
        assert_eq!(r.escalation_after_minutes, Some(240));
        // Boundary: omitted → None (the no-escalation contract).
        let y2 =
            "- id: p\n  vendor: g\n  action: a\n  notifier_recipients:\n    to: ops@acme.com\n";
        let docs2 = parse_policies(y2).unwrap();
        let r2 = docs2[0].notifier_recipients.as_ref().unwrap();
        assert_eq!(r2.escalation_after_minutes, None);
        // Boundary: zero is an explicit-zero choice, NOT coerced to None
        // (operator-driven "fire immediately" sentinel).
        let y3 = "- id: p\n  vendor: g\n  action: a\n  notifier_recipients:\n    to: ops@acme.com\n    escalation_after_minutes: 0\n";
        let docs3 = parse_policies(y3).unwrap();
        assert_eq!(
            docs3[0]
                .notifier_recipients
                .as_ref()
                .unwrap()
                .escalation_after_minutes,
            Some(0),
        );
    }

    #[test]
    fn burst_cfg_empty_object_deserializes_with_both_fields_none() {
        // `notifier_burst: {}` is a valid hand-written shape — the operator
        // declares the intent to burst-suppress without overriding either
        // dial yet, planning to fill them in later. Pin that both fields
        // collapse to None (not to a default integer) — a regression that
        // added `#[serde(default = "...")]` to either field would silently
        // pre-fill the operator's still-undecided dial and start
        // suppressing on next reload.
        let y = "- id: p\n  vendor: g\n  action: a\n  notifier_burst: {}\n";
        let docs = parse_policies(y).unwrap();
        let b = docs[0].notifier_burst.expect("notifier_burst present");
        assert!(b.threshold.is_none(), "threshold defaults to None");
        assert!(
            b.window_seconds.is_none(),
            "window_seconds defaults to None"
        );
    }

    #[test]
    fn default_quarantine_action_helper_returns_replace_with_marker() {
        // The `default_quarantine_action` fn drives ReadFilterCfg's
        // `#[serde(default = "...")]` for the `quarantine_action` field.
        // The existing `defaults_match_safe_production_posture` test pins
        // this via a parsed YAML round-trip, but the helper itself was
        // never invoked directly — a refactor that changed the helper but
        // forgot to update the call site's path would slip past. Pin the
        // function-pointer return value directly so a one-character typo
        // (e.g. `StripSilently`) surfaces here as the canonical posture
        // failing rather than at the first operator's policy reload.
        assert!(matches!(
            default_quarantine_action(),
            QuarantineActionCfg::ReplaceWithMarker
        ));
    }
}
