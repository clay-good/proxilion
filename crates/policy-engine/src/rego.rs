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
    parse_policies, PicMode, PolicyDoc, QuarantineActionCfg, QuarantinePatternCfg, ReadFilterCfg,
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
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub matched_policy_id: Option<String>,
    pub decision: Decision,
    pub required_ops: OpsExpression,
    pub read_filter: Option<ReadFilter>,
    pub pic_mode: PicMode,
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
            if !match_expr::evaluate(&p.match_, ctx)? {
                continue;
            }
            trace!(policy = %p.id, "matched");
            return Ok(Outcome {
                matched_policy_id: Some(p.id.clone()),
                decision: parse_decision(p)?,
                required_ops: OpsExpression::resolve(&p.required_ops, ctx)?,
                read_filter: p.read_filter.as_ref().map(compile_read_filter).transpose()?,
                pic_mode: p.pic_mode,
            });
        }
        Ok(Outcome {
            matched_policy_id: None,
            decision: Decision::Allow,
            required_ops: OpsExpression::default(),
            read_filter: None,
            pic_mode: PicMode::Audit,
        })
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

