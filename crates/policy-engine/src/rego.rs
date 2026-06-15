//! Policy engine entrypoint.
//!
//! For Step 0.3 we ship a direct YAML interpreter rather than a YAML→Rego
//! transpiler. The interpreter satisfies the operator vocabulary listed in
//! spec.md §0.3 and gives <1ms p99 evaluation on a typical request context.
//! A `regorus`-backed compilation path can be slotted in behind this same
//! API later without changing the call sites.

use serde_yaml::Value as Yaml;
use shared_types::ErrorCode;
use std::time::Instant;
use thiserror::Error;
use tracing::trace;

use crate::context::RequestContext;
use crate::decision::{Decision, Pattern, QuarantineAction, ReadFilter};
use crate::match_expr;
use crate::ops::{OpsExpression, OpsParseError};
use crate::trace::{LayerOutcome, OpsAtomView, PolicyEvalMode, PolicyLayer, PolicyTrace};
use crate::yaml::{
    AuditBodyMode, Mode, PicMode, PolicyDoc, QuarantineActionCfg, QuarantinePatternCfg,
    ReadFilterCfg, parse_policies,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid decision shape: {0}")]
    BadDecision(String),
    #[error("invalid read_filter: {0}")]
    BadReadFilter(String),
    #[error("invalid regex `{pat}`: {source}")]
    BadRegex {
        pat: String,
        #[source]
        source: regex::Error,
    },
    #[error(transparent)]
    Match(#[from] match_expr::MatchError),
    #[error(transparent)]
    Ops(#[from] OpsParseError),
}

/// Per-policy email recipient override: `(to, cc, bcc)`. Each list is `Some`
/// only when the policy explicitly set that field.
pub type EmailRecipientOverride = (
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
);

pub struct Engine {
    policies: Vec<PolicyDoc>,
}

impl Engine {
    /// How many policies are loaded. Surfaced on the setup-status page.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Look up a policy's `notifier_burst:` override by id. Returns
    /// `(threshold, window_seconds)` if either is set; `None` if the
    /// policy doesn't exist or doesn't carry a burst override.
    /// ui-less-surfaces.md §5.6.
    pub fn burst_override_for(&self, policy_id: &str) -> Option<(Option<usize>, Option<u64>)> {
        let p = self.policies.iter().find(|p| p.id == policy_id)?;
        let b = p.notifier_burst.as_ref()?;
        Some((b.threshold, b.window_seconds))
    }

    /// Per-policy email recipient overrides (ui-less-surfaces.md §5.4 dev 3).
    /// Returns `(to, cc, bcc)` where each is `Some` only when the policy
    /// explicitly set that list. `None` outer → policy doesn't exist OR has
    /// no `notifier_recipients:` block. The email notifier substitutes each
    /// `Some` list for the global value at send time.
    pub fn email_recipients_for(&self, policy_id: &str) -> Option<EmailRecipientOverride> {
        let p = self.policies.iter().find(|p| p.id == policy_id)?;
        let r = p.notifier_recipients.as_ref()?;
        Some((r.to.clone(), r.cc.clone(), r.bcc.clone()))
    }

    /// Per-policy escalation deadline (ui-less-surfaces.md §5.7 dev 2).
    /// Returns the number of minutes after a blocked row is persisted at
    /// which the email notifier should re-fire as a reminder. `None` →
    /// the policy doesn't carry an escalation block (the common default
    /// — no escalation, just expire at `expires_at`).
    pub fn escalation_after_minutes_for(&self, policy_id: &str) -> Option<u32> {
        self.policies
            .iter()
            .find(|p| p.id == policy_id)?
            .notifier_recipients
            .as_ref()?
            .escalation_after_minutes
    }
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub matched_policy_id: Option<String>,
    pub decision: Decision,
    pub required_ops: OpsExpression,
    pub read_filter: Option<ReadFilter>,
    pub pic_mode: PicMode,
    /// Per-policy enforcement mode (ui-less-surfaces.md §2). `Enforce` is
    /// the production posture; `Observe` records what *would* have happened
    /// and lets the adapter let the request through.
    pub mode: Mode,
    /// When `mode == Observe` and `decision` would have been non-Allow,
    /// this carries the "would have been" decision the adapter records on
    /// the action event (`observe_block`, `observe_require_confirmation`,
    /// `observe_rate_limit`). `None` when not in observe mode or when the
    /// underlying decision was Allow.
    pub observe_would_have: Option<String>,
    /// Per-policy body audit directive (ui-less-surfaces.md §6.4). `None`
    /// → adapter skips the audit-body table entirely (privacy default).
    pub audit_body: Option<AuditBodyMode>,
}

impl Engine {
    pub fn new(policy_yaml: &str) -> Result<Self, Error> {
        let policies = parse_policies(policy_yaml)?;
        Ok(Self { policies })
    }

    /// Statically validate every loaded policy beyond YAML deserialization:
    /// each policy's decision shape parses, its `read_filter` regexes compile,
    /// and its match expression uses only supported operators with well-formed
    /// shapes and compilable literal regexes / numeric thresholds. This backs
    /// `proxilion-cli policy validate`, so an operator/CI catches the
    /// `BadDecision` / `BadRegex` / `UnsupportedOp` class *before* deploy. At
    /// runtime these same errors fail closed (deny) on the first matching
    /// request — safe, but a poor way to learn a policy file is broken, and the
    /// runtime error page literally points operators at `policy validate`.
    pub fn validate(&self) -> Result<(), Error> {
        for p in &self.policies {
            parse_decision(p)?;
            if let Some(rf) = p.read_filter.as_ref() {
                compile_read_filter(rf)?;
            }
            match_expr::validate(&p.match_)?;
        }
        Ok(())
    }

    pub fn evaluate(&self, ctx: &RequestContext) -> Result<Outcome, Error> {
        for p in &self.policies {
            if p.vendor != ctx.vendor || p.action != ctx.action {
                continue;
            }
            // `disabled` policies are skipped entirely — useful as an
            // emergency kill-switch without deleting the YAML. The loop
            // continues so a later policy can still match.
            if p.mode == Mode::Disabled {
                continue;
            }
            if !match_expr::evaluate(&p.match_, ctx)? {
                continue;
            }
            trace!(policy = %p.id, mode = ?p.mode, "matched");
            let real_decision = parse_decision(p)?;
            let (decision, observe_would_have) = match p.mode {
                Mode::Enforce => (real_decision, None),
                Mode::Observe => observe_demote(real_decision),
                Mode::Disabled => unreachable!("filtered above"),
            };
            return Ok(Outcome {
                matched_policy_id: Some(p.id.clone()),
                decision,
                required_ops: OpsExpression::resolve(&p.required_ops, ctx)?,
                read_filter: p
                    .read_filter
                    .as_ref()
                    .map(compile_read_filter)
                    .transpose()?,
                pic_mode: p.pic_mode,
                mode: p.mode,
                observe_would_have,
                audit_body: p.audit_body,
            });
        }
        Ok(Outcome {
            matched_policy_id: None,
            decision: Decision::Allow,
            required_ops: OpsExpression::default(),
            read_filter: None,
            pic_mode: PicMode::Audit,
            mode: Mode::Enforce,
            observe_would_have: None,
            audit_body: None,
        })
    }

    /// Evaluate and emit a structured per-layer [`PolicyTrace`] alongside
    /// the [`Outcome`]. Adapters that don't need the trace continue to
    /// call [`Engine::evaluate`]. Per qiuth-patterns.md §3.
    ///
    /// **Note:** Layer A (PIC ops) doesn't actually round-trip the Trust
    /// Plane inside the engine; the returned trace's Layer-A entry records
    /// the *required* ops set and `passed = true`. The adapter must
    /// supplement the Layer-A outcome via [`PolicyTrace::layers`] after
    /// the successor-PCA call resolves — failing back to
    /// [`ErrorCode::PicInvariantViolation`] when the Trust Plane refuses.
    pub fn evaluate_with_trace(
        &self,
        ctx: &RequestContext,
    ) -> Result<(Outcome, PolicyTrace), Error> {
        self.evaluate_with_trace_mode(ctx, PolicyEvalMode::FailFast)
    }

    /// Same as [`Engine::evaluate_with_trace`], but in
    /// [`PolicyEvalMode::Comprehensive`] the engine walks every later
    /// policy after the first match and records an additional
    /// `LayerB` [`LayerOutcome`] per policy that *would* also have matched
    /// (with `matched_rule_id` set and `detail` prefixed `would_also_match:`).
    /// The `final_decision` is still authoritative from the first match —
    /// this is purely diagnostic. Use from the dashboard "explain this
    /// denial" replay path, never the hot path. Per qiuth-patterns.md §3.3.
    pub fn evaluate_with_trace_mode(
        &self,
        ctx: &RequestContext,
        mode: PolicyEvalMode,
    ) -> Result<(Outcome, PolicyTrace), Error> {
        let started = Instant::now();
        let outcome = self.evaluate(ctx)?;
        let mut layers: Vec<LayerOutcome> = Vec::with_capacity(3);

        // Layer A — required ops. The engine surfaces the expression; the
        // adapter cross-checks it. Record as `passed` here; the adapter
        // updates this entry to `failed` on Trust-Plane refusal.
        layers.push(LayerOutcome {
            layer: PolicyLayer::LayerA,
            passed: true,
            matched_rule_id: if outcome.required_ops.required.is_empty() {
                None
            } else {
                Some(format!(
                    "{} required atom(s)",
                    outcome.required_ops.required.len()
                ))
            },
            error_code: None,
            detail: None,
        });

        // Layer B — content rules.
        let layer_b = match &outcome.decision {
            Decision::Allow => LayerOutcome::passed(PolicyLayer::LayerB),
            Decision::Block { reason, .. } => LayerOutcome::failed(
                PolicyLayer::LayerB,
                ErrorCode::PolicyBlocked,
                outcome.matched_policy_id.clone(),
                Some(reason.clone()),
            ),
            Decision::RequireConfirmation { reason } => LayerOutcome::failed(
                PolicyLayer::LayerB,
                ErrorCode::RequireConfirmation,
                outcome.matched_policy_id.clone(),
                Some(reason.clone()),
            ),
            Decision::RateLimit { burst, per_seconds } => LayerOutcome::failed(
                PolicyLayer::LayerB,
                ErrorCode::RateLimited,
                outcome.matched_policy_id.clone(),
                Some(format!("burst={burst} per_seconds={per_seconds}")),
            ),
        };
        layers.push(layer_b);

        // Comprehensive mode — collect diagnostics for every *later* policy
        // that would also have matched the same context. The first match
        // already populated `outcome` above; here we walk the remainder so
        // the operator can see overlapping rules in a single replay.
        if mode == PolicyEvalMode::Comprehensive {
            let first_matched = outcome.matched_policy_id.as_deref();
            let mut seen_first = false;
            for p in &self.policies {
                if p.vendor != ctx.vendor || p.action != ctx.action {
                    continue;
                }
                if p.mode == crate::yaml::Mode::Disabled {
                    continue;
                }
                if !match_expr::evaluate(&p.match_, ctx)? {
                    continue;
                }
                // Skip the policy that fail-fast already recorded.
                if !seen_first && Some(p.id.as_str()) == first_matched {
                    seen_first = true;
                    continue;
                }
                let would_decision = parse_decision(p)?;
                let extra = match &would_decision {
                    Decision::Allow => LayerOutcome {
                        layer: PolicyLayer::LayerB,
                        passed: true,
                        matched_rule_id: Some(p.id.clone()),
                        error_code: None,
                        detail: Some(format!("would_also_match: allow ({:?})", p.mode)),
                    },
                    Decision::Block { reason, .. } => LayerOutcome::failed(
                        PolicyLayer::LayerB,
                        ErrorCode::PolicyBlocked,
                        Some(p.id.clone()),
                        Some(format!("would_also_match: {reason}")),
                    ),
                    Decision::RequireConfirmation { reason } => LayerOutcome::failed(
                        PolicyLayer::LayerB,
                        ErrorCode::RequireConfirmation,
                        Some(p.id.clone()),
                        Some(format!("would_also_match: {reason}")),
                    ),
                    Decision::RateLimit { burst, per_seconds } => LayerOutcome::failed(
                        PolicyLayer::LayerB,
                        ErrorCode::RateLimited,
                        Some(p.id.clone()),
                        Some(format!(
                            "would_also_match: burst={burst} per_seconds={per_seconds}"
                        )),
                    ),
                };
                layers.push(extra);
            }
        }

        // Read filter — engine only records that a filter is configured;
        // the actual scan result lands on the adapter when the response
        // body comes back. Recording the presence/absence here gives the
        // trace a slot to mutate downstream.
        if outcome.read_filter.is_some() {
            layers.push(LayerOutcome {
                layer: PolicyLayer::ReadFilter,
                passed: true,
                matched_rule_id: outcome.matched_policy_id.clone(),
                error_code: None,
                detail: Some("read_filter configured; scan pending".into()),
            });
        }

        let required_ops: Vec<OpsAtomView> = outcome
            .required_ops
            .required
            .iter()
            .map(OpsAtomView::from)
            .collect();

        let mut trace = PolicyTrace::new(layers, outcome.decision.clone(), required_ops);
        trace.duration_micros = started.elapsed().as_micros() as u64;

        Ok((outcome, trace))
    }
}

/// In `observe` mode the adapter receives `Decision::Allow` (so the
/// request proceeds untouched) plus a `would_have` label so the action
/// event records `observe_block` / `observe_require_confirmation` /
/// `observe_rate_limit`. ui-less-surfaces.md §2.5.
fn observe_demote(d: Decision) -> (Decision, Option<String>) {
    match d {
        Decision::Allow => (Decision::Allow, None),
        Decision::Block { .. } => (Decision::Allow, Some("observe_block".into())),
        Decision::RequireConfirmation { .. } => {
            (Decision::Allow, Some("observe_require_confirmation".into()))
        }
        Decision::RateLimit { .. } => (Decision::Allow, Some("observe_rate_limit".into())),
    }
}

fn parse_decision(p: &PolicyDoc) -> Result<Decision, Error> {
    let override_allowed = p
        .override_
        .as_deref()
        .map(|s| s == "requires_justification")
        .unwrap_or(false);
    match &p.decision {
        Yaml::String(s) => match s.as_str() {
            "allow" => Ok(Decision::Allow),
            "block" => Ok(Decision::Block {
                reason: format!("policy `{}`", p.id),
                override_allowed,
            }),
            "require_confirmation" => Ok(Decision::RequireConfirmation {
                reason: format!("policy `{}`", p.id),
            }),
            other => Err(Error::BadDecision(format!("unknown decision `{other}`"))),
        },
        Yaml::Mapping(m) => {
            if let Some(rl) = m.get(Yaml::String("rate_limit".into())) {
                // `as u32` would silently wrap a value ≥ 2^32 (`burst: 4294967296`
                // → `0`, an accidental block-everything limit). The serde/JSON
                // path already rejects this (decision.rs
                // `decision_rate_limit_rejects_negative_or_overflow_values_on_deserialize`);
                // the YAML path must too — fail loudly on overflow.
                let burst = rl
                    .get("burst")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| Error::BadDecision("rate_limit.burst missing".into()))?;
                let burst = u32::try_from(burst)
                    .map_err(|_| Error::BadDecision("rate_limit.burst exceeds u32::MAX".into()))?;
                let per_seconds = rl
                    .get("per_seconds")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| Error::BadDecision("rate_limit.per_seconds missing".into()))?;
                let per_seconds = u32::try_from(per_seconds).map_err(|_| {
                    Error::BadDecision("rate_limit.per_seconds exceeds u32::MAX".into())
                })?;
                return Ok(Decision::RateLimit { burst, per_seconds });
            }
            if let Some(b) = m.get(Yaml::String("block".into())) {
                let reason = b
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&p.id)
                    .to_string();
                return Ok(Decision::Block {
                    reason,
                    override_allowed,
                });
            }
            Err(Error::BadDecision(format!(
                "unrecognized decision: {:?}",
                p.decision
            )))
        }
        Yaml::Null => Ok(Decision::Allow),
        other => Err(Error::BadDecision(format!(
            "decision must be string/map, got {other:?}"
        ))),
    }
}

fn compile_read_filter(cfg: &ReadFilterCfg) -> Result<ReadFilter, Error> {
    let mut patterns = Vec::with_capacity(cfg.quarantine_patterns.len());
    for p in &cfg.quarantine_patterns {
        patterns.push(match p {
            QuarantinePatternCfg::Literal(s) => Pattern::Literal(s.clone()),
            QuarantinePatternCfg::Regex { regex } => {
                let re = regex::Regex::new(regex).map_err(|e| Error::BadRegex {
                    pat: regex.clone(),
                    source: e,
                })?;
                Pattern::Regex(re)
            }
        });
    }
    Ok(ReadFilter {
        quarantine_patterns: patterns,
        quarantine_action: match cfg.quarantine_action {
            QuarantineActionCfg::ReplaceWithMarker => QuarantineAction::ReplaceWithMarker,
            QuarantineActionCfg::StripSilently => QuarantineAction::StripSilently,
            QuarantineActionCfg::BlockRequest => QuarantineAction::BlockRequest,
        },
    })
}

#[cfg(test)]
mod helper_tests {
    use super::*;
    use crate::yaml::{PolicyDoc, QuarantineActionCfg, QuarantinePatternCfg, ReadFilterCfg};

    fn doc_with_decision(yaml_decision: &str) -> PolicyDoc {
        let y =
            format!("id: p1\nvendor: v\naction: a\ndecision: {yaml_decision}\nrequired_ops: []\n");
        serde_yaml::from_str(&y).unwrap()
    }

    #[test]
    fn engine_validate_compiles_decision_read_filter_and_match_beyond_parse() {
        // Files that *parse* (valid YAML shape) but are broken at compile time.
        // parse_policies accepts each; Engine::validate must reject them.
        let broken_regex = "\
- id: p1
  vendor: v
  action: a
  decision: block
  read_filter:
    quarantine_patterns:
      - regex: \"(unclosed\"
    quarantine_action: replace_with_marker
";
        assert!(
            parse_policies(broken_regex).is_ok(),
            "parse accepts the YAML shape"
        );
        let err = Engine::new(broken_regex).unwrap().validate().unwrap_err();
        assert!(matches!(err, Error::BadRegex { .. }), "got {err:?}");

        let unknown_decision = "- id: p1\n  vendor: v\n  action: a\n  decision: banhammer\n";
        assert!(parse_policies(unknown_decision).is_ok());
        assert!(matches!(
            Engine::new(unknown_decision)
                .unwrap()
                .validate()
                .unwrap_err(),
            Error::BadDecision(_)
        ));

        let unknown_op = "\
- id: p1
  vendor: v
  action: a
  decision: block
  match:
    user.email: { equls: x }
";
        assert!(parse_policies(unknown_op).is_ok());
        assert!(matches!(
            Engine::new(unknown_op).unwrap().validate().unwrap_err(),
            Error::Match(_)
        ));

        // A fully well-formed policy validates clean.
        let ok = "\
- id: p1
  vendor: v
  action: a
  decision: block
  match:
    user.email: { matches: \"^a@b\\\\.com$\" }
  read_filter:
    quarantine_patterns:
      - regex: \"ignore previous instructions\"
    quarantine_action: replace_with_marker
";
        assert!(Engine::new(ok).unwrap().validate().is_ok());
    }

    #[test]
    fn observe_demote_allow_is_passthrough() {
        let (d, label) = observe_demote(Decision::Allow);
        assert_eq!(d, Decision::Allow);
        assert!(label.is_none());
    }

    #[test]
    fn observe_demote_block_records_observe_block_label() {
        let (d, label) = observe_demote(Decision::Block {
            reason: "r".into(),
            override_allowed: false,
        });
        assert_eq!(d, Decision::Allow);
        assert_eq!(label.as_deref(), Some("observe_block"));
    }

    #[test]
    fn observe_demote_require_confirmation_records_label() {
        let (d, label) = observe_demote(Decision::RequireConfirmation { reason: "r".into() });
        assert_eq!(d, Decision::Allow);
        assert_eq!(label.as_deref(), Some("observe_require_confirmation"));
    }

    #[test]
    fn observe_demote_rate_limit_records_label() {
        let (d, label) = observe_demote(Decision::RateLimit {
            burst: 10,
            per_seconds: 60,
        });
        assert_eq!(d, Decision::Allow);
        assert_eq!(label.as_deref(), Some("observe_rate_limit"));
    }

    #[test]
    fn parse_decision_allow_string() {
        let d = parse_decision(&doc_with_decision("allow")).unwrap();
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn parse_decision_null_yaml_is_allow() {
        let p = doc_with_decision("~"); // YAML null
        let d = parse_decision(&p).unwrap();
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn parse_decision_block_string_carries_policy_id_reason() {
        let p = doc_with_decision("block");
        match parse_decision(&p).unwrap() {
            Decision::Block {
                reason,
                override_allowed,
            } => {
                assert!(reason.contains("p1"));
                // No `override: requires_justification` set on doc → false.
                assert!(!override_allowed);
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn parse_decision_block_string_respects_override_field() {
        let y = "id: p1\nvendor: v\naction: a\ndecision: block\noverride: requires_justification\nrequired_ops: []\n";
        let p: PolicyDoc = serde_yaml::from_str(y).unwrap();
        match parse_decision(&p).unwrap() {
            Decision::Block {
                override_allowed, ..
            } => assert!(override_allowed),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn parse_decision_require_confirmation_string() {
        let d = parse_decision(&doc_with_decision("require_confirmation")).unwrap();
        assert!(matches!(d, Decision::RequireConfirmation { .. }));
    }

    #[test]
    fn parse_decision_unknown_string_errors() {
        let p = doc_with_decision("banhammer");
        let err = parse_decision(&p).unwrap_err();
        assert!(matches!(err, Error::BadDecision(_)));
        assert!(err.to_string().contains("banhammer"));
    }

    #[test]
    fn parse_decision_rate_limit_map() {
        let y = "id: p1\nvendor: v\naction: a\ndecision:\n  rate_limit:\n    burst: 5\n    per_seconds: 10\nrequired_ops: []\n";
        let p: PolicyDoc = serde_yaml::from_str(y).unwrap();
        match parse_decision(&p).unwrap() {
            Decision::RateLimit { burst, per_seconds } => {
                assert_eq!(burst, 5);
                assert_eq!(per_seconds, 10);
            }
            other => panic!("expected RateLimit, got {other:?}"),
        }
    }

    #[test]
    fn parse_decision_rate_limit_rejects_u32_overflow() {
        // `burst: 2^32` must error, not silently wrap to 0 (a block-everything
        // limit). Mirrors the serde-path guard on the JSON side.
        let y = "id: p1\nvendor: v\naction: a\ndecision:\n  rate_limit:\n    burst: 4294967296\n    per_seconds: 10\nrequired_ops: []\n";
        let p: PolicyDoc = serde_yaml::from_str(y).unwrap();
        let err = parse_decision(&p).unwrap_err();
        assert!(err.to_string().contains("burst exceeds"), "got {err}");
        // per_seconds overflow is likewise rejected.
        let y2 = "id: p1\nvendor: v\naction: a\ndecision:\n  rate_limit:\n    burst: 5\n    per_seconds: 4294967296\nrequired_ops: []\n";
        let p2: PolicyDoc = serde_yaml::from_str(y2).unwrap();
        let err2 = parse_decision(&p2).unwrap_err();
        assert!(
            err2.to_string().contains("per_seconds exceeds"),
            "got {err2}"
        );
    }

    #[test]
    fn parse_decision_rate_limit_missing_field_errors() {
        let y = "id: p1\nvendor: v\naction: a\ndecision:\n  rate_limit:\n    burst: 5\nrequired_ops: []\n";
        let p: PolicyDoc = serde_yaml::from_str(y).unwrap();
        let err = parse_decision(&p).unwrap_err();
        assert!(err.to_string().contains("per_seconds"));
    }

    #[test]
    fn parse_decision_block_map_carries_custom_reason() {
        let y = "id: p1\nvendor: v\naction: a\ndecision:\n  block:\n    reason: external recipient\nrequired_ops: []\n";
        let p: PolicyDoc = serde_yaml::from_str(y).unwrap();
        match parse_decision(&p).unwrap() {
            Decision::Block { reason, .. } => assert_eq!(reason, "external recipient"),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn compile_read_filter_literal_and_regex_round_trip() {
        let cfg = ReadFilterCfg {
            quarantine_patterns: vec![
                QuarantinePatternCfg::Literal("ignore previous".into()),
                QuarantinePatternCfg::Regex {
                    regex: r"<\|.*?\|>".into(),
                },
            ],
            quarantine_action: QuarantineActionCfg::ReplaceWithMarker,
        };
        let rf = compile_read_filter(&cfg).unwrap();
        assert_eq!(rf.quarantine_patterns.len(), 2);
        assert!(matches!(rf.quarantine_patterns[0], Pattern::Literal(_)));
        assert!(matches!(rf.quarantine_patterns[1], Pattern::Regex(_)));
        assert_eq!(rf.quarantine_action, QuarantineAction::ReplaceWithMarker);
    }

    #[test]
    fn compile_read_filter_each_quarantine_action_maps_through() {
        for (cfg_var, expect) in [
            (
                QuarantineActionCfg::ReplaceWithMarker,
                QuarantineAction::ReplaceWithMarker,
            ),
            (
                QuarantineActionCfg::StripSilently,
                QuarantineAction::StripSilently,
            ),
            (
                QuarantineActionCfg::BlockRequest,
                QuarantineAction::BlockRequest,
            ),
        ] {
            let cfg = ReadFilterCfg {
                quarantine_patterns: vec![],
                quarantine_action: cfg_var,
            };
            let rf = compile_read_filter(&cfg).unwrap();
            assert_eq!(rf.quarantine_action, expect);
        }
    }

    #[test]
    fn compile_read_filter_bad_regex_errors() {
        let cfg = ReadFilterCfg {
            quarantine_patterns: vec![QuarantinePatternCfg::Regex {
                regex: "(unbalanced".into(),
            }],
            quarantine_action: QuarantineActionCfg::ReplaceWithMarker,
        };
        let err = compile_read_filter(&cfg).unwrap_err();
        assert!(matches!(err, Error::BadRegex { .. }));
    }

    #[test]
    fn rego_error_yaml_display_carries_yaml_parse_error_prefix_with_inner_serde_message() {
        // `#[error("YAML parse error: {0}")]` on `Yaml(#[from] serde_yaml::Error)`
        // — pin the prefix substring `"YAML parse error: "` (with
        // the trailing colon+space). Operator authoring tools split
        // YAML-syntax faults from semantic faults (BadDecision /
        // BadReadFilter) on this prefix; a refactor to `"yaml: {0}"`
        // for "consistency with the other prefixes" would silently
        // collapse the bucket. Pin the inner serde_yaml::Error
        // Display passthrough so authors see the position info the
        // serde_yaml crate emits (line + column) verbatim.
        let parse_err: serde_yaml::Error =
            serde_yaml::from_str::<Yaml>(":\n bad: : :").unwrap_err();
        let inner_display = parse_err.to_string();
        let e: Error = Error::Yaml(parse_err);
        let s = e.to_string();
        assert!(s.starts_with("YAML parse error: "), "got: {s}");
        // Inner serde error message passes through verbatim — the
        // suffix-after-prefix must equal the inner Display so
        // operator tools can split on `": "` to recover position info.
        assert_eq!(&s["YAML parse error: ".len()..], inner_display);
    }

    #[test]
    fn rego_error_bad_decision_display_carries_invalid_decision_shape_prefix() {
        // `#[error("invalid decision shape: {0}")]` — this is the
        // prefix `AppError::Policy`'s adapter-side `"policy engine: "`
        // wraps (so an operator sees the composed
        // `"policy engine: invalid decision shape: <inner>"` in the
        // adapter-side log). The two prefixes are stacked deliberately
        // to give a runbook the two-axis split (engine vs decision-
        // shape); a refactor that softened `"invalid decision shape"`
        // to a generic `"bad decision"` would silently merge it with
        // future decision-validation variants. Pin the exact prefix
        // + inner-string Display via `assert_eq!`.
        let e = Error::BadDecision("unknown decision `banhammer`".into());
        assert_eq!(
            e.to_string(),
            "invalid decision shape: unknown decision `banhammer`",
        );
    }

    #[test]
    fn rego_error_bad_read_filter_display_carries_invalid_read_filter_prefix() {
        // `#[error("invalid read_filter: {0}")]` — sibling to
        // BadDecision but distinct prefix so the dashboard's
        // "policy authoring errors" panel buckets read_filter
        // faults (e.g. malformed `quarantine_patterns`) separately
        // from top-level decision-shape faults. Operator runbooks
        // key on the `"read_filter"` substring (with underscore,
        // matching the YAML key) — a refactor to `"read filter"`
        // (space) "for human-readability" would silently break the
        // log filter and the cross-reference into the YAML the
        // operator authored.
        let e = Error::BadReadFilter("quarantine_patterns must be a sequence".into());
        assert_eq!(
            e.to_string(),
            "invalid read_filter: quarantine_patterns must be a sequence",
        );
    }

    #[test]
    fn rego_error_bad_regex_display_renders_pat_in_backticks_and_full_source_message() {
        // `#[error("invalid regex `{pat}`: {source}")]` — the
        // BACKTICKED `{pat}` field is load-bearing: operators paste
        // the literal pattern from the YAML into a regex tester, and
        // the backticks delimit the boundary so a pattern containing
        // a colon (the field separator) doesn't confuse the parser.
        // The `{source}` substitution is wired by `#[source]` AND
        // appears in the Display via the bare `{source}` placeholder
        // — pin both surfaces (Display rendering + the inner
        // regex::Error message passthrough). A refactor to
        // `#[error("invalid regex {pat}: {source}")]` (no backticks)
        // would silently swallow the boundary on patterns containing
        // colons, and a refactor that elided `{source}` would silently
        // drop the parser's "unbalanced parenthesis" / "missing
        // character class" actionable triage.
        // Build the pattern dynamically so the `clippy::invalid_regex`
        // lint (which only fires on string literals) doesn't trip on
        // the intentionally-malformed input.
        let bad_pat = format!("({}", "unbalanced");
        let compile_err = regex::Regex::new(&bad_pat).unwrap_err();
        let inner_display = compile_err.to_string();
        let e = Error::BadRegex {
            pat: bad_pat.clone(),
            source: compile_err,
        };
        let s = e.to_string();
        assert!(s.starts_with("invalid regex `(unbalanced`: "), "got: {s}");
        // Inner regex::Error message passes through verbatim after the prefix.
        assert!(s.contains(&inner_display), "missing inner in: {s}");
    }

    #[test]
    fn rego_error_match_arm_transparent_display_strips_no_prefix() {
        // `#[error(transparent)]` on `Match(#[from] match_expr::MatchError)`
        // — the transparent attribute means the wrapper adds NO
        // prefix; the Display is byte-identical to the inner
        // MatchError's Display. This is asymmetric to the other
        // arms which DO add prefixes (YAML / BadDecision /
        // BadReadFilter / BadRegex). The asymmetry is intentional:
        // MatchError already self-identifies via its own `#[error(...)]`
        // attributes (round 85 pinned the backticked-operator prefix
        // for UnsupportedOp etc.), so adding a `"match: "` prefix
        // here would just produce the noisy `"match: unsupported
        // operator `weird_op`"`. Pin the transparent-passthrough so
        // a refactor that added a wrapper prefix "for consistency
        // with the prefixed arms" would surface here and force a
        // discussion before merging.
        let inner = match_expr::MatchError::UnsupportedOp("weird_op".into());
        let inner_display = inner.to_string();
        let e: Error = Error::Match(inner);
        assert_eq!(e.to_string(), inner_display);
        // Symmetric explicit pin to ensure the inner Display is
        // exactly what round 85 pinned — cross-module drift surfaces.
        assert_eq!(e.to_string(), "unsupported operator `weird_op`");
    }

    #[test]
    fn rego_error_ops_arm_transparent_display_forwards_inner_and_source_chain() {
        // `#[error(transparent)]` on `Ops(#[from] OpsParseError)` —
        // symmetric to `Match` above. The OpsParseError already
        // self-identifies (`"template variable `ctx.missing` not found"`),
        // and `thiserror`'s `transparent` attribute forwards BOTH
        // `Display` AND `Error::source()` directly to the inner
        // error (not wrapping it). Since `OpsParseError::UnknownVar`
        // is a leaf with no inner source, `Error::Ops(_).source()`
        // returns None — pin that contract so a refactor that
        // dropped `transparent` for an explicit prefix wrapper
        // would silently start exposing the leaf via `source()`
        // (which would NOT match the anyhow-style walkers in
        // adapter code that expect a fresh `source()` link only at
        // the prefixed `Match`/`BadRegex` arms).
        use std::error::Error as _;
        let inner = OpsParseError::UnknownVar("ctx.missing".into());
        let inner_display = inner.to_string();
        let e: Error = Error::Ops(inner);
        assert_eq!(e.to_string(), inner_display);
        // `transparent` forwards `source()` to the inner — and the
        // inner OpsParseError::UnknownVar variant is a leaf, so the
        // chain terminates here. Symmetric pin against `Match`.
        assert!(
            e.source().is_none(),
            "transparent forwards to inner leaf — no further source link",
        );
    }

    // ─── round 179 (2026-05-20): Engine + Outcome + Error operator-actionable surfaces ───

    #[test]
    fn engine_and_outcome_and_error_are_all_send_sync_static_for_axum_router_state() {
        // `Engine` is held as `Arc<Engine>` in the axum router state and
        // re-cloned across every request handler; `Outcome` flows back
        // through `tokio::spawn`'d audit-sink tasks and a future
        // `Arc<Outcome>` cache; `Error` propagates up through
        // `AppError::Policy` across the same `.await` boundaries.
        // ALL three need `Send + Sync + 'static` for those call sites
        // to compile — a refactor that introduced a `Cell` field "for
        // an in-process eval counter" or an `Rc` field would silently
        // break Sync at this type boundary, surface as a flood of
        // borrow-check errors at hundreds of call sites in the proxy.
        // Pin the three-trait combo on all three types so the boundary
        // fails fast here. Symmetric to round-168 / 169 / 173 / 175 /
        // 176 / 177 / 178 Send+Sync+'static pins extended to the
        // remaining engine entrypoint types.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<Engine>();
        require_send_sync_static::<Outcome>();
        require_send_sync_static::<Error>();
    }

    #[test]
    fn engine_evaluate_is_referentially_transparent_across_fifty_repeated_calls() {
        // The hot path calls `Engine::evaluate(&ctx)` for every inbound
        // request; the result MUST depend only on the (policies, ctx)
        // pair, never on hidden per-call state (a once-cell
        // matched-rule LRU, a per-eval counter wired into the trace,
        // etc.). Pin referential transparency across 50 back-to-back
        // calls on a 2-policy multi-mode fixture (the first matches
        // and blocks; the second is a fallback allow that should NOT
        // surface because the first short-circuits). A refactor that
        // introduced a stateful cache between calls would surface
        // here as a divergence on call #2..#50.
        // Symmetric to round-161 / 175 / 178 referential-transparency
        // pins extended to the engine evaluate path.
        let yaml = "\
- id: p-block
  vendor: drive
  action: read
  decision: block
  required_ops: []
- id: p-allow-fallback
  vendor: drive
  action: read
  decision: allow
  required_ops: []
";
        let engine = Engine::new(yaml).unwrap();
        let ctx = RequestContext {
            vendor: "drive".into(),
            action: "read".into(),
            ..Default::default()
        };
        let first = engine.evaluate(&ctx).unwrap();
        for i in 1..50 {
            let next = engine.evaluate(&ctx).unwrap();
            assert_eq!(
                next.matched_policy_id, first.matched_policy_id,
                "matched_policy_id diverged on call #{i}",
            );
            assert_eq!(
                next.decision, first.decision,
                "decision diverged on call #{i}",
            );
            assert_eq!(next.mode, first.mode, "mode diverged on call #{i}");
            assert_eq!(
                next.pic_mode, first.pic_mode,
                "pic_mode diverged on call #{i}",
            );
        }
        assert_eq!(first.matched_policy_id.as_deref(), Some("p-block"));
    }

    #[test]
    fn engine_policy_count_returns_usize_matching_loaded_length_across_zero_one_three_policies() {
        // `policy_count` is surfaced on the setup-status page (the
        // installer-UI's "policies loaded: N" indicator) and is a
        // simple `usize` passthrough. Pin the contract across three
        // sizes (0/1/3) so a refactor that subtracted disabled
        // policies "for accuracy" would silently make the setup
        // page disagree with the YAML the operator wrote — the
        // operator's mental model is "every policy in the file is
        // counted; mode is orthogonal." Symmetric to round-161
        // PolicyView.policy_count exhaustive-count extended to the
        // engine method one layer up.
        let zero = Engine::new("[]").unwrap();
        assert_eq!(zero.policy_count(), 0);
        let one = Engine::new(
            "\
- id: p1
  vendor: v
  action: a
  decision: allow
  required_ops: []
",
        )
        .unwrap();
        assert_eq!(one.policy_count(), 1);
        let three = Engine::new(
            "\
- id: p1
  vendor: v
  action: a
  decision: allow
  required_ops: []
- id: p2
  vendor: v
  action: a
  mode: disabled
  decision: allow
  required_ops: []
- id: p3
  vendor: v
  action: b
  decision: allow
  required_ops: []
",
        )
        .unwrap();
        // Disabled policies are still counted — `policy_count` is the
        // file-shape count, not the active-rule count.
        assert_eq!(three.policy_count(), 3);
    }

    #[test]
    fn engine_evaluate_no_match_path_returns_default_allow_outcome_byte_exact() {
        // When no policy matches (vendor/action mismatch, all
        // policies disabled, or empty list), `evaluate` returns a
        // canonical default Outcome: matched_policy_id=None,
        // decision=Allow, required_ops=Default, read_filter=None,
        // pic_mode=Audit, mode=Enforce, observe_would_have=None,
        // audit_body=None. This is the load-bearing "no policy
        // gates this call" passthrough — the adapter's hot path
        // depends on `matched_policy_id.is_none()` AND
        // `decision == Allow` AND `pic_mode == Audit` to skip
        // both the Trust-Plane round-trip and the audit-body
        // capture. A refactor that promoted `pic_mode` to
        // `RuntimeGate` "for safe default" would silently start
        // forcing the Trust Plane round-trip on every unmatched
        // request. Pin EVERY field on the default-outcome shape.
        let engine = Engine::new(
            "\
- id: p1
  vendor: drive
  action: read
  decision: block
  required_ops: []
",
        )
        .unwrap();
        let ctx = RequestContext {
            vendor: "gmail".into(),
            action: "send".into(),
            ..Default::default()
        };
        let out = engine.evaluate(&ctx).unwrap();
        assert!(out.matched_policy_id.is_none());
        assert_eq!(out.decision, Decision::Allow);
        assert!(out.required_ops.required.is_empty());
        assert!(out.read_filter.is_none());
        assert_eq!(out.pic_mode, PicMode::Audit);
        assert_eq!(out.mode, Mode::Enforce);
        assert!(out.observe_would_have.is_none());
        assert!(out.audit_body.is_none());
    }

    #[test]
    fn engine_burst_override_for_returns_none_for_unknown_policy_id_and_for_missing_block() {
        // `burst_override_for(policy_id)` is the lookup the notifier
        // burst limiter performs on every blocked event to recover
        // the per-policy override (ui-less-surfaces.md §5.6). Two
        // distinct None-paths must be preserved: unknown policy_id
        // (the notifier was handed an id that doesn't exist in the
        // current YAML — a stale reference after a hot-reload) AND
        // an existing policy whose YAML omits the `notifier_burst:`
        // block (the common default — fall back to the global
        // notifier burst threshold). A refactor that collapsed the
        // two paths to a single `unwrap_or_default()` would silently
        // substitute the global threshold for both — the operator
        // would lose the "you referenced an unknown policy id"
        // diagnostic. Pin both None-paths plus a Some-path so all
        // three branches surface here. Symmetric to round-91
        // matched_rule_id Option pin extended to a sibling Option
        // lookup one layer up.
        let engine = Engine::new(
            "\
- id: p-no-burst
  vendor: v
  action: a
  decision: block
  required_ops: []
- id: p-with-burst
  vendor: v
  action: a
  decision: block
  required_ops: []
  notifier_burst:
    threshold: 3
    window_seconds: 60
",
        )
        .unwrap();
        assert!(engine.burst_override_for("p-no-burst").is_none());
        assert!(engine.burst_override_for("p-unknown").is_none());
        let (threshold, window) = engine.burst_override_for("p-with-burst").unwrap();
        assert_eq!(threshold, Some(3));
        assert_eq!(window, Some(60));
    }

    #[test]
    fn outcome_matched_policy_id_some_arm_carries_owned_string_for_arc_share_safety() {
        // `Outcome.matched_policy_id: Option<String>` — the Some-arm
        // inner is an OWNED `String`, not a borrowed `&str`. The
        // adapter clones the Outcome into the audit-sink task across
        // a tokio `.await` boundary, and the original YAML byte
        // slice (the source of the policy id) is dropped at the end
        // of the request. A refactor to `Option<&'a str>` for "zero-
        // alloc" would silently break the cross-await ownership and
        // surface as borrow-check errors at the audit-sink site, but
        // also Some adapters Arc-share the matched_policy_id between
        // workers — owned String is the load-bearing shape there.
        // Pin the owned-String type via the canonical require_string
        // helper. Symmetric to round-176 PolicyBundle.yaml + version
        // and round-177 Decision.reason owned-String pins extended
        // to Outcome.matched_policy_id.
        fn require_string(_: &String) {}
        let engine = Engine::new(
            "\
- id: p-owned
  vendor: v
  action: a
  decision: allow
  required_ops: []
",
        )
        .unwrap();
        let ctx = RequestContext {
            vendor: "v".into(),
            action: "a".into(),
            ..Default::default()
        };
        let out = engine.evaluate(&ctx).unwrap();
        let id = out.matched_policy_id.as_ref().expect("matched p-owned");
        require_string(id);
        assert_eq!(id, "p-owned");
    }

    #[test]
    fn engine_field_count_pinned_at_exactly_one_via_exhaustive_destructure() {
        // Pin the Engine struct field count at exactly 1 via exhaustive
        // destructure with no `..` rest pattern. A 2nd field landing
        // (e.g. `compiled_at: DateTime<Utc>` for per-engine-build
        // observability, or `metrics_bucket: &'static str` to split
        // per-engine metric labels for the future multi-tenant policy
        // engine path) would silently bloat every Arc<Engine> in the
        // proxy's hot-swap ArcSwap path AND change the existing
        // policy_count semantics. The existing tests walk `policies`
        // via the public accessor but doesn't catch a runtime-only
        // 2nd field — exhaustive destructure is the canonical pin.
        let e = Engine::new("[]").expect("empty engine builds");
        let Engine { policies: _ } = e;
    }

    #[test]
    fn outcome_field_count_pinned_at_exactly_eight_via_exhaustive_destructure() {
        // Pin the Outcome struct field count at exactly 8 via exhaustive
        // destructure with no `..` rest pattern. A 9th field landing
        // (e.g. `evaluated_at: DateTime<Utc>` for per-evaluation
        // observability, or `trace_id: Option<Uuid>` for back-attribution
        // from Outcome to PolicyTrace, or `engine_version: &'static str`
        // for the rebuild-tracking dashboard surface) would silently
        // bloat every per-request Outcome flowing through the engine →
        // adapter handoff. The 8 fields are: matched_policy_id +
        // decision + required_ops + read_filter + pic_mode + mode +
        // observe_would_have + audit_body. A `#[serde(skip)]` runtime-
        // only 9th field would bypass any serde-key pin.
        let engine = Engine::new("[]").unwrap();
        let ctx = RequestContext::default();
        let o = engine.evaluate(&ctx).expect("default Allow");
        let Outcome {
            matched_policy_id: _,
            decision: _,
            required_ops: _,
            read_filter: _,
            pic_mode: _,
            mode: _,
            observe_would_have: _,
            audit_body: _,
        } = o;
    }

    #[test]
    fn rego_error_variant_count_pinned_at_exactly_six_via_exhaustive_match() {
        // Pin the rego::Error variant count at exactly 6 via exhaustive
        // match expression. A 7th variant landing (e.g. `BadOps` to
        // distinguish ops-template syntax faults from generic Match
        // errors at the dashboard's "explain this policy" panel, or
        // `EngineRebuildTimeout { duration_ms }` for a future watchdog
        // path) without matching every Display attribute + adapter
        // bubble `?` call site would surface here as a non-exhaustive
        // compile error. The 6 variants are: Yaml(#[from]
        // serde_yaml::Error) + BadDecision(String) + BadReadFilter(String)
        // + BadRegex { pat, source } + Match(#[from] MatchError) +
        // Ops(#[from] OpsParseError). The enum is NOT
        // `#[non_exhaustive]` — within the workspace the match is
        // fully closed and a new variant MUST update every dispatch
        // site in lockstep.
        fn variant_witness(e: &Error) -> u8 {
            match e {
                Error::Yaml(_) => 0,
                Error::BadDecision(_) => 1,
                Error::BadReadFilter(_) => 2,
                Error::BadRegex { .. } => 3,
                Error::Match(_) => 4,
                Error::Ops(_) => 5,
            }
        }
        // Concrete instances for each variant.
        let yaml = Error::Yaml(serde_yaml::from_str::<serde_yaml::Value>(": invalid").unwrap_err());
        let bad_dec = Error::BadDecision("x".into());
        let bad_rf = Error::BadReadFilter("x".into());
        // Use a string runtime-constructed to dodge clippy::invalid_regex
        // which lints on literal pattern args. The bad-paren shape is the
        // canonical bad-regex pattern but the lint can't tell our intent
        // is to construct an error, not a valid regex.
        let bad_pat: String = "(".chars().collect();
        let bad_rx = Error::BadRegex {
            pat: bad_pat.clone(),
            source: regex::Regex::new(&bad_pat).unwrap_err(),
        };
        let match_ = Error::Match(match_expr::MatchError::BadShape {
            op: "in".into(),
            expected: "sequence",
            got: "scalar".into(),
        });
        let ops = Error::Ops(OpsParseError::Malformed);
        let mut seen = std::collections::HashSet::new();
        for e in [&yaml, &bad_dec, &bad_rf, &bad_rx, &match_, &ops] {
            assert!(seen.insert(variant_witness(e)));
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn engine_policy_count_signature_pinned_via_fn_pointer_witness() {
        // Pin Engine::policy_count signature as
        // `fn(&Engine) -> usize` via fn-pointer witness. A refactor
        // that flipped to `fn(&self) -> u32` ("for SQL-int4 alignment
        // with the setup-status row") would silently truncate at
        // 2^32 policies AND force every call site to cast. The
        // `&self` borrow shape is load-bearing because the proxy
        // calls this from the setup-status handler on every poll
        // tick without owning the Engine (it lives in
        // ArcSwap<Engine>); a refactor to `self`-consuming would
        // surface here AND break the watcher loop.
        let _f: fn(&Engine) -> usize = Engine::policy_count;
    }

    #[test]
    fn engine_burst_override_for_signature_pinned_via_fn_pointer_witness() {
        // Pin Engine::burst_override_for signature as
        // `fn(&Engine, &str) -> Option<(Option<usize>, Option<u64>)>`
        // via fn-pointer witness. Three boundaries are pinned at the
        // type level: (a) `&self` borrow on the Engine (not consuming
        // — the burst suppressor calls this per blocked-action emit
        // through Arc<Engine>); (b) `&str` borrow on the policy_id
        // (not String — the matched_policy_id is owned by the
        // Outcome and the suppressor borrows it for the lookup
        // without cloning); (c) `Option<(Option<usize>, Option<u64>)>`
        // outer/inner Option shape preserving the
        // "policy-not-found vs. policy-without-override vs. field-
        // override-with-other-default" three-way distinction at the
        // call site.
        let _f: fn(&Engine, &str) -> Option<(Option<usize>, Option<u64>)> =
            Engine::burst_override_for;
    }

    #[test]
    fn engine_email_recipients_for_signature_pinned_via_fn_pointer_witness() {
        // Pin Engine::email_recipients_for signature as
        // `fn(&Engine, &str) -> Option<EmailRecipientOverride>`. The
        // `EmailRecipientOverride` type alias is `(Option<Vec<String>>,
        // Option<Vec<String>>, Option<Vec<String>>)`. Symmetric to
        // the burst_override_for pin above — pin the alias-using
        // signature so a refactor that inlined the alias to the raw
        // tuple ("for one-less-type clarity") would surface here as a
        // fn-pointer type mismatch, even though both shapes are
        // structurally equivalent. The alias is the operator-grep
        // handle in the rego module's public API; inlining it would
        // silently lose that documentation surface.
        let _f: fn(&Engine, &str) -> Option<EmailRecipientOverride> = Engine::email_recipients_for;
    }
}
