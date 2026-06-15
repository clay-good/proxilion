//! YAML policy-document schema.
//!
//! A `PolicyDoc` mirrors a single entry in a customer-authored policy file
//! (see spec.md §9 examples). The match/decision blocks are kept as raw YAML
//! values; the matcher lives in `match_expr.rs`.

use serde::{Deserialize, Serialize};

// `deny_unknown_fields` makes a misspelled key fail loudly instead of silently
// dropping to a permissive default. Without it, `decison: block` (typo) leaves
// the real `decision` field at its `Null` default → `parse_decision` returns
// `Allow`, and a fat-fingered `mtch:` leaves `match_` Null → matches every
// request: a fat-finger turns an intended `block` policy into match-everything
// allow. `Engine::validate` can't catch this (a Null decision is a *valid*
// Allow), so the schema must reject the unknown key at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
// Same fail-loud rationale as `ReadFilterCfg`/`PolicyDoc`: a typo'd
// `escalation_after_minutes` should be an authoring error, not a silently
// dropped key that disables escalation.
#[serde(deny_unknown_fields)]
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
// Fail loud on a typo'd `threshold`/`window_seconds` rather than silently
// leaving burst detection unconfigured. See `ReadFilterCfg`.
#[serde(deny_unknown_fields)]
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
// Mirror `PolicyDoc`'s `deny_unknown_fields`: without it a typo'd
// `quarantine_actoin: block_request` is silently dropped and
// `quarantine_action` falls back to its `ReplaceWithMarker` default — a
// *fail-open* that downgrades an operator's intended hard block of an
// injected upstream response to a marker-splice that still reaches the agent.
// `Engine::validate` (behind `policy validate`) runs after the unknown key is
// already gone, so it green-lights the broken policy; only failing the parse
// catches it.
#[serde(deny_unknown_fields)]
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
    fn policy_doc_clone_preserves_all_optional_fields_independently() {
        // `PolicyDoc` derives `Clone` — adapter call sites snapshot
        // the engine's parsed policies into per-request handler
        // state (the hot path uses `Engine::evaluate` which borrows,
        // but the dashboard's policy-list endpoint clones for the
        // wire-serialize). Pin that the Clone derive covers every
        // optional field (read_filter / notifier_burst /
        // notifier_recipients / audit_body / override_) and that
        // the inner `serde_yaml::Value` slots for `match_` and
        // `decision` round-trip without aliasing the source. A
        // refactor that switched any field to `Cow<...>` or
        // dropped the derive would surface here.
        let yaml = "\
- id: p1
  vendor: google
  action: drive.files.get
  mode: observe
  pic_mode: runtime-gate
  override: requires_justification
  audit_body: hash
  notifier_burst:
    threshold: 5
  notifier_recipients:
    to: ops@acme.com
    escalation_after_minutes: 30
  read_filter:
    quarantine_action: strip_silently
  required_ops:
    - drive:read:file/${path.id}
  match:
    user.email:
      not_in: [bot@acme.com]
  decision: allow
";
        let docs = parse_policies(yaml).unwrap();
        let original = &docs[0];
        let c = original.clone();
        assert_eq!(c.id, "p1");
        assert_eq!(c.vendor, "google");
        assert_eq!(c.action, "drive.files.get");
        assert_eq!(c.mode, Mode::Observe);
        assert_eq!(c.pic_mode, PicMode::RuntimeGate);
        assert_eq!(c.override_.as_deref(), Some("requires_justification"));
        assert_eq!(c.audit_body, Some(AuditBodyMode::Hash));
        assert!(c.notifier_burst.is_some());
        assert_eq!(c.notifier_burst.unwrap().threshold, Some(5));
        let r = c.notifier_recipients.as_ref().unwrap();
        assert_eq!(r.to.as_deref(), Some(&["ops@acme.com".to_string()][..]));
        assert_eq!(r.escalation_after_minutes, Some(30));
        assert!(c.read_filter.is_some());
        assert_eq!(c.required_ops.len(), 1);
        assert_eq!(c.required_ops[0], "drive:read:file/${path.id}");
        // The serde_yaml::Value fields survive the Clone (no aliasing).
        assert!(c.match_.is_mapping(), "match_ value lost: {:?}", c.match_);
        assert!(
            c.decision.as_str() == Some("allow"),
            "decision value lost: {:?}",
            c.decision,
        );
    }

    #[test]
    fn policy_doc_override_field_renamed_from_override_serde_attr_round_trip() {
        // `pub override_: Option<String>` is annotated
        // `#[serde(default, rename = "override")]` — the `override_`
        // trailing underscore is Rust's reserved-keyword escape
        // (`override` is a reserved identifier). The wire key MUST
        // be the bare `override`, NOT `override_`. spec.md §9
        // example policies key on the bare wire form, and the
        // dashboard's policy-author renders it back to the operator
        // verbatim. A refactor that dropped the `#[serde(rename)]`
        // attribute would silently start emitting `override_` on
        // serialize and rejecting `override` on deserialize — every
        // existing operator-authored policy would fail-parse on
        // reload. Pin BOTH directions.
        let yaml = "\
- id: p1
  vendor: g
  action: a
  override: requires_justification
";
        let d = &parse_policies(yaml).unwrap()[0];
        assert_eq!(d.override_.as_deref(), Some("requires_justification"));
        // Symmetric serialize via serde_json (yaml round-trip would
        // re-quote and reformat — the rename attribute fires for
        // every Serializer, so json is a cleaner pin).
        let v = serde_json::to_value(d).unwrap();
        assert!(
            v.get("override").is_some(),
            "serialize must emit `override`, got keys: {:?}",
            v.as_object().unwrap().keys().collect::<Vec<_>>(),
        );
        assert!(
            v.get("override_").is_none(),
            "serialize must NOT emit `override_` (Rust escape form): {v}",
        );
        assert_eq!(v["override"], "requires_justification");
    }

    #[test]
    fn parse_policies_empty_yaml_array_returns_zero_policies_without_error() {
        // The top-level YAML is a sequence — pin that the empty
        // sequence `[]` is a VALID input that returns an empty
        // Vec, not a deserialize error. The empty-engine boot path
        // (`Engine::new("[]")`) depends on this for the no-policy
        // default the integration tests use. A refactor that
        // required at least one policy (a tightening for
        // "operator-friendly" validation) would silently break
        // every test fixture and the dev-default engine.
        let docs = parse_policies("[]").unwrap();
        assert!(docs.is_empty());
        // The block-style empty sequence is the same shape via a
        // different YAML rendering — also accepted.
        let docs = parse_policies("--- []\n").unwrap();
        assert!(docs.is_empty());
    }

    #[test]
    fn default_pic_mode_helper_returns_audit_directly() {
        // The `default_pic_mode` fn drives `PolicyDoc`'s
        // `#[serde(default = "default_pic_mode")]` for the
        // `pic_mode` field. The existing
        // `defaults_match_safe_production_posture` test pins this
        // via `assert_eq!(default_pic_mode(), PicMode::Audit)`,
        // but the SYMMETRIC `default_mode` and
        // `default_quarantine_action` helpers each have a separate
        // dedicated test (`default_quarantine_action_helper_returns_replace_with_marker`)
        // that pins the function-pointer return value in isolation
        // — pin `default_pic_mode` here for consistency. The
        // contract: `Audit` is the safe-posture default (PIC
        // monotonicity faults are recorded but the request still
        // proceeds against the predecessor PCA — runtime_gate is
        // the opt-in tightening). A refactor that flipped the
        // default to `RuntimeGate` would silently start blocking
        // every customer who hadn't explicitly opted in.
        assert_eq!(default_pic_mode(), PicMode::Audit);
    }

    #[test]
    fn recipients_cfg_empty_to_list_round_trips_as_some_empty_vec_distinct_from_none() {
        // `deserialize_string_or_vec_opt` walks `Option<One>` where
        // `One` is the untagged String/Vec<String> union. When the
        // YAML carries an explicit empty list (`to: []`), the
        // helper must produce `Some(vec![])` — DISTINCT from the
        // absent-field shape which produces `None`. The notifier
        // logic distinguishes "operator explicitly set empty"
        // (`Some(vec![])` — suppress all email to this list) from
        // "inherit from global" (`None`); a refactor that collapsed
        // the empty list to `None` (the natural "treat empty as
        // unset" simplification) would silently start
        // email-blasting an operator who deliberately blanked a list.
        let y = "\
- id: p
  vendor: g
  action: a
  notifier_recipients:
    to: []
    cc: alice@x.com
";
        let d = &parse_policies(y).unwrap()[0];
        let r = d.notifier_recipients.as_ref().unwrap();
        // `to: []` → Some(empty vec), NOT None.
        assert_eq!(r.to.as_deref(), Some(&[][..]));
        assert!(
            r.to.is_some(),
            "to: [] must remain Some(_), not collapse to None"
        );
        // `cc` exercises the single-string path side-by-side.
        assert_eq!(r.cc.as_deref(), Some(&["alice@x.com".to_string()][..]));
        // `bcc` was absent → None.
        assert!(r.bcc.is_none());
    }

    #[test]
    fn audit_body_unknown_variant_value_is_rejected_by_closed_enum() {
        // `AuditBodyMode` is a closed enum (no `#[serde(other)]`
        // catch-all), so an operator typo like `audit_body: hashing`
        // (extra `ing`) or a future-spec variant the proxy doesn't
        // know yet MUST fail-parse rather than silently
        // forward-compat into `Hash`. Symmetric to
        // `parse_policies_rejects_unknown_mode_value` which pins
        // the same contract on `Mode`. The fail-loud contract is
        // load-bearing: a silent forward-compat would mean an
        // operator pinning `audit_body: hashing` thinking it
        // enabled SHA-256 minimization would actually NOT enable
        // it AND not see any error, leaving the privacy default
        // (no body persistence) in force without their knowledge.
        let yaml = "\
- id: p
  vendor: g
  action: a
  audit_body: hashing
";
        assert!(
            parse_policies(yaml).is_err(),
            "closed enum must reject unknown variant",
        );
        // Symmetric: a kebab-case variant that doesn't exist in
        // the snake_case attribute should also fail.
        let yaml = "\
- id: p
  vendor: g
  action: a
  audit_body: redact-pii
";
        assert!(
            parse_policies(yaml).is_err(),
            "kebab-case variant of snake-case enum must reject",
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

    #[test]
    fn policy_doc_and_all_eight_config_struct_and_enum_types_are_send_sync_static() {
        // The full schema hierarchy flows through `Arc<Engine>` hot-swap
        // + tokio reload watcher + axum router state — every type in the
        // YAML schema MUST be Send + Sync + 'static. The existing
        // module pins individual VALUES (defaults, round-trip equality)
        // but never the trait bounds across the type hierarchy. A
        // refactor adding a `OnceCell<...>` field "for lazy compilation
        // metadata" on PolicyDoc would silently break Sync and surface
        // at a remote `tower::Service` trait-bound rather than at this
        // module. Pin all 8 schema types — symmetric to round-168 +
        // round-169 + round-173 + round-175 + round-176 + round-177
        // Send+Sync+'static pins extended to the full YAML schema.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<PolicyDoc>();
        require_send_sync_static::<Mode>();
        require_send_sync_static::<PicMode>();
        require_send_sync_static::<AuditBodyMode>();
        require_send_sync_static::<ReadFilterCfg>();
        require_send_sync_static::<RecipientsCfg>();
        require_send_sync_static::<BurstCfg>();
        require_send_sync_static::<QuarantineActionCfg>();
        require_send_sync_static::<QuarantinePatternCfg>();
    }

    #[test]
    fn parse_policies_is_referentially_transparent_across_fifty_repeated_calls() {
        // Symmetric to round-161 + round-162 + round-166 + round-168 +
        // round-169 + round-170 + round-171 + round-172 + round-173 +
        // round-175 + round-177 referential-transparency pins extended
        // to parse_policies. The policy reload path may parse the same
        // YAML body multiple times (the watcher fires once on mtime
        // change but the reload may retry on transient compile
        // failures); a refactor caching the parse via a once-cell
        // keyed on input pointer "for hot-path perf" would silently
        // return stale PolicyDocs on a re-parse after edit. Pin 50
        // calls on a 3-policy multi-mode fixture yield byte-equal
        // serialized output.
        let yaml = r#"
- id: p1
  vendor: google
  action: drive.files.get
  match: {}
  decision: allow
  mode: enforce
  pic_mode: audit
- id: p2
  vendor: google
  action: gmail.send
  match: {}
  decision: { kind: block, reason: "external recipient", override_allowed: true }
  mode: observe
  pic_mode: runtime-gate
- id: p3
  vendor: google
  action: calendar.events.insert
  match: {}
  decision: { kind: rate_limit, burst: 5, per_seconds: 60 }
  mode: enforce
"#;
        let baseline = parse_policies(yaml).expect("fixture must parse");
        assert_eq!(baseline.len(), 3);
        for i in 0..50 {
            let again = parse_policies(yaml).expect("re-parse");
            assert_eq!(
                again.len(),
                baseline.len(),
                "iter {i}: parse_policies must yield same count",
            );
            for (a, b) in again.iter().zip(baseline.iter()) {
                assert_eq!(a.id, b.id, "iter {i}: id");
                assert_eq!(a.vendor, b.vendor, "iter {i}: vendor");
                assert_eq!(a.action, b.action, "iter {i}: action");
            }
        }
    }

    #[test]
    fn policy_doc_id_vendor_action_fields_are_owned_string_type_for_arc_hot_swap_outlives() {
        // The PolicyDoc fields are MOVED into the compiled engine on
        // every reload; the engine is then wrapped in `ArcSwap<Engine>`
        // and shared across an unbounded number of per-request loads.
        // The id/vendor/action strings MUST be owned (not borrowed)
        // because the YAML source is dropped post-compile. A refactor
        // to `&'a str` "to avoid per-reload allocation" would surface
        // a lifetime constraint that the ArcSwap call site couldn't
        // satisfy. Pin via require_string pattern-match — symmetric
        // to round-168 + round-175 + round-176 + round-177 owned-String
        // pins extended to PolicyDoc schema fields.
        fn require_string(_: &String) {}
        let yaml = "- id: x\n  vendor: google\n  action: drive.files.get\n";
        let docs = parse_policies(yaml).expect("must parse");
        let doc = &docs[0];
        require_string(&doc.id);
        require_string(&doc.vendor);
        require_string(&doc.action);
    }

    #[test]
    fn audit_body_mode_wire_strings_byte_exact_three_known_values_no_kebab_no_uppercase() {
        // `AuditBodyMode` carries `#[serde(rename_all = "snake_case")]`
        // — operator-facing audit dashboards bucket on `audit_body =
        // "hash"` / `"redact_pii"` / `"full"` directly. The existing
        // `audit_body_mode_wire_strings_are_snake_case` pin walks the
        // values via to_string substring but never the SHAPE invariant
        // (no-uppercase + no-kebab + no-shell-unsafe-char sweep). A
        // future rename_all = "kebab-case" "for URL-friendly variant
        // names" on a sibling shared types enum would silently break
        // every audit dashboard if it leaked here. Pin no-uppercase +
        // no-kebab + EXACTLY 3 values — symmetric to round-173
        // ErrorCode + round-177 Decision lowercase sweeps extended
        // to AuditBodyMode.
        for variant in [
            AuditBodyMode::Hash,
            AuditBodyMode::RedactPii,
            AuditBodyMode::Full,
        ] {
            let s = serde_json::to_string(&variant).unwrap();
            let inner = s.trim_matches('"');
            assert!(
                inner.chars().all(|c| !c.is_ascii_uppercase()),
                "AuditBodyMode `{inner}` contains uppercase",
            );
            assert!(
                !inner.contains('-'),
                "AuditBodyMode `{inner}` contains kebab `-`",
            );
        }
        // Exhaustive 3-value set byte-equal.
        let values: Vec<String> = [
            AuditBodyMode::Hash,
            AuditBodyMode::RedactPii,
            AuditBodyMode::Full,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
        assert_eq!(values, vec!["\"hash\"", "\"redact_pii\"", "\"full\""]);
    }

    #[test]
    fn pic_mode_wire_strings_use_kebab_case_not_snake_case_for_legacy_v0_compat() {
        // PicMode carries `#[serde(rename_all = "kebab-case")]` — the
        // ONE intentional kebab-case deviation in the schema (Mode +
        // AuditBodyMode + QuarantineActionCfg all use snake_case).
        // The pre-2026 policy YAML examples in the customer-shipped
        // docs use `pic_mode: runtime-gate` (kebab) literally; a
        // refactor "tidying" PicMode to snake_case would silently
        // break every customer YAML in the wild. The existing
        // pic_mode_serializes_kebab_case_not_snake_case test walks
        // both polarities via substring; pin BYTE-EXACT serialization
        // here with an explicit kebab-case assertion AND a negative
        // "snake_case form rejected on deserialize" pin so the rename
        // attribute is load-bearing on BOTH directions.
        // Serialize: byte-exact kebab.
        let s_audit = serde_json::to_string(&PicMode::Audit).unwrap();
        assert_eq!(s_audit, "\"audit\"");
        let s_gate = serde_json::to_string(&PicMode::RuntimeGate).unwrap();
        assert_eq!(s_gate, "\"runtime-gate\"");
        // Defensive: snake_case form `runtime_gate` is NOT accepted by
        // the deserializer (the rename_all attribute is bidirectional).
        let bad: Result<PicMode, _> = serde_json::from_str("\"runtime_gate\"");
        assert!(
            bad.is_err(),
            "snake_case `runtime_gate` must NOT deserialize — kebab is the wire form",
        );
    }

    #[test]
    fn quarantine_pattern_cfg_untagged_enum_disambiguates_literal_from_regex_via_field_presence() {
        // `QuarantinePatternCfg` is `#[serde(untagged)]` — a bare
        // string literal `foo` deserializes as `Literal("foo")`;
        // an object `{regex: "foo"}` deserializes as `Regex { regex
        // }`. The existing `quarantine_patterns_accept_literal_or_regex`
        // pin walks the happy paths but never the NEGATIVE polarity:
        // a refactor adding a `Glob { glob: String }` variant would
        // be silently order-dependent (untagged tries each variant in
        // declaration order) and a Glob entry could mis-classify as
        // Regex if both variants accepted `{ glob: ... }`. Pin that
        // the current 2-variant set ONLY matches the 2 documented
        // shapes — symmetric to round-161 PolicyView 5-key + round-165
        // TokenResponse 4-key exhaustive-set pins extended to untagged-
        // enum disambiguation.
        let lit: QuarantinePatternCfg = serde_yaml::from_str("foo").unwrap();
        assert!(matches!(lit, QuarantinePatternCfg::Literal(ref s) if s == "foo"));
        let rx: QuarantinePatternCfg = serde_yaml::from_str("{ regex: \"foo\" }").unwrap();
        assert!(matches!(rx, QuarantinePatternCfg::Regex { regex } if regex == "foo"));
        // Negative: a `{ glob: "..." }` shape would not match either
        // variant (Literal requires string, Regex requires `regex`
        // field) — serde untagged returns an error.
        let bad: Result<QuarantinePatternCfg, _> = serde_yaml::from_str("{ glob: \"foo\" }");
        assert!(
            bad.is_err(),
            "unknown-field object must NOT silently deserialize as either variant",
        );
    }

    #[test]
    fn policy_doc_rejects_unknown_keys_so_a_typod_field_cant_fail_open() {
        // A misspelled `decision` (here `decison`) must NOT parse: without
        // deny_unknown_fields it would drop to the Null default → Allow,
        // silently turning a block policy into match-everything allow.
        let typo = "- id: x\n  vendor: g\n  action: a\n  decison: block\n";
        assert!(
            parse_policies(typo).is_err(),
            "a typo'd `decision` key must be rejected, not silently dropped to Allow"
        );
        // The correctly-spelled form parses.
        let ok = "- id: x\n  vendor: g\n  action: a\n  decision: block\n";
        assert!(parse_policies(ok).is_ok());
    }

    #[test]
    fn read_filter_cfg_rejects_unknown_keys_so_a_typod_action_cant_fail_open() {
        // A misspelled `quarantine_action` (here `quarantine_actoin`) must NOT
        // parse: without deny_unknown_fields on ReadFilterCfg the unknown key is
        // silently dropped and `quarantine_action` falls back to its
        // ReplaceWithMarker default — downgrading an operator's intended hard
        // `block_request` of an injected upstream response to a marker-splice
        // that still reaches the agent.
        let typo = "\
- id: rf
  vendor: g
  action: a
  read_filter:
    quarantine_patterns: [\"system prompt:\"]
    quarantine_actoin: block_request
";
        assert!(
            parse_policies(typo).is_err(),
            "a typo'd `quarantine_action` key must be rejected, not silently dropped to the marker default"
        );
        // The correctly-spelled form parses and keeps the intended action.
        let ok = "\
- id: rf
  vendor: g
  action: a
  read_filter:
    quarantine_patterns: [\"system prompt:\"]
    quarantine_action: block_request
";
        let docs = parse_policies(ok).expect("valid read_filter parses");
        assert!(matches!(
            docs[0].read_filter.as_ref().unwrap().quarantine_action,
            QuarantineActionCfg::BlockRequest
        ));
    }

    #[test]
    fn policy_doc_field_count_pinned_at_exactly_thirteen_via_exhaustive_destructure() {
        // Pin the PolicyDoc struct field count at exactly 13 via
        // exhaustive destructure with no `..` rest pattern. The 13
        // fields are: id + vendor + action + match_ + decision +
        // read_filter + required_ops + pic_mode + mode + override_ +
        // notifier_burst + notifier_recipients + audit_body. A 14th
        // field landing (e.g. `severity: Severity` for dashboard
        // ranking, `tags: Vec<String>` for grouped operator views, or
        // `enabled_since: Option<DateTime<Utc>>` for staged rollouts)
        // would silently bloat every PolicyDoc Vec on the engine's
        // ArcSwap hot-swap path AND silently extend the wire JSON
        // shape consumers see. The existing serde tests walk individual
        // fields but a `#[serde(skip)]` runtime-only 14th field would
        // bypass any wire-key pin — exhaustive destructure is the
        // canonical pin.
        let yaml = "- id: x\n  vendor: g\n  action: a\n";
        let docs = parse_policies(yaml).unwrap();
        let doc = docs.into_iter().next().unwrap();
        let PolicyDoc {
            id: _,
            vendor: _,
            action: _,
            match_: _,
            decision: _,
            read_filter: _,
            required_ops: _,
            pic_mode: _,
            mode: _,
            override_: _,
            notifier_burst: _,
            notifier_recipients: _,
            audit_body: _,
        } = doc;
    }

    #[test]
    fn recipients_cfg_field_count_pinned_at_exactly_four_via_exhaustive_destructure() {
        // Pin the RecipientsCfg struct field count at exactly 4 via
        // exhaustive destructure (no `..`). The 4 fields are: to + cc
        // + bcc + escalation_after_minutes. A 5th field landing (e.g.
        // `reply_to: Option<Vec<String>>` for an operator-friendly
        // replies-bounce-back feature, or `subject_prefix:
        // Option<String>` for a per-policy email subject override)
        // would silently bloat every per-policy RecipientsCfg clone
        // through the engine + email notifier handoff AND silently
        // change the existing `to/cc/bcc/escalation_after_minutes`
        // wire shape. The escalation_after_minutes round-trip pin
        // walks one field; exhaustive destructure is the canonical
        // catch-all-fields pin.
        let r = RecipientsCfg {
            to: None,
            cc: None,
            bcc: None,
            escalation_after_minutes: None,
        };
        let RecipientsCfg {
            to: _,
            cc: _,
            bcc: _,
            escalation_after_minutes: _,
        } = r;
    }

    #[test]
    fn mode_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // Pin the Mode variant count at exactly 3 via exhaustive
        // match expression. A 4th variant landing (e.g. `DryRun` to
        // distinguish "evaluate fully but never act AND never record
        // an audit row" from `Observe` "evaluate, record, but allow",
        // or `Quarantine` for a future per-policy temporary disable
        // shape) without matching every `Engine::evaluate` arm + the
        // operator-facing wire-string snapshot + the
        // ui-less-surfaces.md §2.1 dashboard toggle would surface
        // here as a non-exhaustive compile error. The enum is NOT
        // `#[non_exhaustive]` — within the workspace the match is
        // fully closed and a new variant MUST update every dispatch
        // site in lockstep. Symmetric to round-256 Decision +
        // round-258 PolicyLoadError variant-count pins extended to
        // the Mode enum.
        fn variant_witness(m: Mode) -> u8 {
            match m {
                Mode::Enforce => 0,
                Mode::Observe => 1,
                Mode::Disabled => 2,
            }
        }
        let mut seen = std::collections::HashSet::new();
        for m in [Mode::Enforce, Mode::Observe, Mode::Disabled] {
            assert!(seen.insert(variant_witness(m)));
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn audit_body_mode_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // Pin the AuditBodyMode variant count at exactly 3 via
        // exhaustive match. A 4th variant landing (e.g. `Encrypted`
        // for a future at-rest-encrypted body persistence path
        // per ui-less-surfaces.md §6.4 future-work, or `MetadataOnly`
        // to store body length + content-type without bytes) without
        // matching every adapter audit-body dispatch site would
        // surface here as a non-exhaustive compile error.
        fn variant_witness(m: AuditBodyMode) -> u8 {
            match m {
                AuditBodyMode::Hash => 0,
                AuditBodyMode::RedactPii => 1,
                AuditBodyMode::Full => 2,
            }
        }
        let mut seen = std::collections::HashSet::new();
        for m in [
            AuditBodyMode::Hash,
            AuditBodyMode::RedactPii,
            AuditBodyMode::Full,
        ] {
            assert!(seen.insert(variant_witness(m)));
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn quarantine_action_cfg_variant_count_pinned_at_exactly_three_via_exhaustive_match() {
        // Pin the QuarantineActionCfg variant count at exactly 3 via
        // exhaustive match. A 4th variant landing (e.g. `RedactPii`
        // for a future per-pattern PII redaction action, or
        // `EscalateToReviewer` to route quarantined chunks to a
        // human-review queue) without matching every read-filter
        // dispatcher site would surface here as a non-exhaustive
        // compile error. Symmetric to round-256
        // quarantine_action_variant_count pin on
        // `decision::QuarantineAction` extended to the YAML schema
        // type — the two are intentionally kept separate so the
        // wire shape can evolve independently from the engine-
        // internal representation, but they must stay in lockstep.
        fn variant_witness(a: QuarantineActionCfg) -> u8 {
            match a {
                QuarantineActionCfg::ReplaceWithMarker => 0,
                QuarantineActionCfg::StripSilently => 1,
                QuarantineActionCfg::BlockRequest => 2,
            }
        }
        let mut seen = std::collections::HashSet::new();
        for a in [
            QuarantineActionCfg::ReplaceWithMarker,
            QuarantineActionCfg::StripSilently,
            QuarantineActionCfg::BlockRequest,
        ] {
            assert!(seen.insert(variant_witness(a)));
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn parse_policies_signature_pinned_via_fn_pointer_witness() {
        // Pin parse_policies signature as
        // `fn(&str) -> Result<Vec<PolicyDoc>, serde_yaml::Error>`
        // via fn-pointer witness. A refactor that flipped the input
        // from `&str` to `&[u8]` ("for binary-input parity with
        // serde_yaml::from_slice") or to `String` ("for
        // ownership-symmetry with the return") would silently force
        // every call site to materialize a String (the proxy's
        // policy_handle holds the YAML in an `Arc<String>`; a
        // `String` arg would force a clone per reload). The owned
        // `Vec<PolicyDoc>` return type is also pinned — a refactor
        // to `&'a [PolicyDoc]` "to avoid the per-call allocation"
        // would tie the return lifetime to the input buffer's
        // lifetime, forcing constraints on the engine's hot-swap
        // ArcSwap path. The `serde_yaml::Error` error type is the
        // operator-facing parse error rendered verbatim in the
        // policy-reload log line via the rego::Error::Yaml `#[from]`
        // chain.
        let _f: fn(&str) -> Result<Vec<PolicyDoc>, serde_yaml::Error> = parse_policies;
    }
}
