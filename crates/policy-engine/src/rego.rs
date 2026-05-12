//! Policy engine entrypoint.
//!
//! For Step 0.3 we ship a direct YAML interpreter rather than a YAML→Rego
//! transpiler. The interpreter satisfies the operator vocabulary listed in
//! spec.md §0.3 and gives <1ms p99 evaluation on a typical request context.
//! A `regorus`-backed compilation path can be slotted in behind this same
//! API later without changing the call sites.

use serde_yaml::Value as Yaml;
use thiserror::Error;
use tracing::trace;

use crate::context::RequestContext;
use crate::decision::{Decision, Pattern, QuarantineAction, ReadFilter};
use crate::match_expr;
use crate::ops::{OpsExpression, OpsParseError};
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

