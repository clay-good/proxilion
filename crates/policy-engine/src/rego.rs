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
    parse_policies, AuditBodyMode, Mode, PicMode, PolicyDoc, QuarantineActionCfg,
    QuarantinePatternCfg, ReadFilterCfg,
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
    pub fn email_recipients_for(
        &self,
        policy_id: &str,
    ) -> Option<(Option<Vec<String>>, Option<Vec<String>>, Option<Vec<String>>)> {
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
                read_filter: p.read_filter.as_ref().map(compile_read_filter).transpose()?,
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
                let burst = rl
                    .get("burst")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| Error::BadDecision("rate_limit.burst missing".into()))?
                    as u32;
                let per_seconds = rl
                    .get("per_seconds")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| Error::BadDecision("rate_limit.per_seconds missing".into()))?
                    as u32;
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
            Err(Error::BadDecision(format!("unrecognized decision: {:?}", p.decision)))
        }
        Yaml::Null => Ok(Decision::Allow),
        other => Err(Error::BadDecision(format!("decision must be string/map, got {other:?}"))),
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

