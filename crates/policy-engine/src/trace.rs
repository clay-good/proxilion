//! Per-layer evaluation trace for a single request.
//!
//! Per qiuth-patterns.md §3 — the policy decision is a *structure*, not a
//! verdict. Operators inspecting a denied call learn which layer tripped
//! without reading application logs, and the dashboard / CLI can render
//! "why" alongside "what."
//!
//! The trace is produced by [`crate::Engine::evaluate_with_trace`]. The
//! existing [`crate::Engine::evaluate`] continues to return `Outcome`
//! unchanged — adapters that don't want the structured trace pay nothing.
//!
//! ## Layer A vs Layer B
//!
//! Today's Proxilion has two policy gates per request: Layer A (PIC ops
//! invariants, enforced at the Trust Plane via [`crate::ops::OpsExpression`])
//! and Layer B (YAML rules, evaluated locally). Read-filter quarantining
//! runs over the response body and is treated as a third layer for trace
//! purposes — the layer's outcome is "matched + which patterns" rather
//! than allow/block.
//!
//! Layer A doesn't actually evaluate inside `Engine::evaluate`: the engine
//! emits the `required_ops` expression and the adapter cross-checks it
//! against the Trust-Plane-issued PCA. So the trace's Layer-A entry is
//! filled in by the adapter once that round-trip resolves; the engine
//! only fills in Layer B (and a stub Layer-A entry that records the
//! `required_ops` shape).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::ErrorCode;
use uuid::Uuid;

use crate::decision::Decision;
use crate::ops::OpsAtom;

/// Which policy layer produced an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    /// PIC ops invariants — chain authority enforcement.
    LayerA,
    /// YAML / Rego content rules — body-shape, recipient, etc.
    LayerB,
    /// Read filter — response-body quarantine.
    ReadFilter,
}

/// One layer's verdict on this request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerOutcome {
    pub layer: PolicyLayer,
    /// `true` when the layer accepted the request.
    pub passed: bool,
    /// Layer-specific identifier: `policy_id` for Layer B, the resolved
    /// `OpsAtom` set for Layer A (rendered as a stringified atom list),
    /// `read_filter` for the read-filter layer.
    pub matched_rule_id: Option<String>,
    /// Stable error code when `passed == false`. Maps directly to the
    /// `code` field on adapter error responses.
    pub error_code: Option<ErrorCode>,
    /// Human-readable detail — **not** stable wire contract; the structured
    /// fields are.
    pub detail: Option<String>,
}

impl LayerOutcome {
    pub fn passed(layer: PolicyLayer) -> Self {
        Self {
            layer,
            passed: true,
            matched_rule_id: None,
            error_code: None,
            detail: None,
        }
    }

    pub fn failed(
        layer: PolicyLayer,
        error_code: ErrorCode,
        matched_rule_id: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            layer,
            passed: false,
            matched_rule_id,
            error_code: Some(error_code),
            detail,
        }
    }
}

/// Whether the engine stops at the first deny or continues evaluating
/// later layers/rules for diagnostic completeness. The production hot
/// path uses [`PolicyEvalMode::FailFast`]; the dashboard's "explain this
/// denial" replay uses [`PolicyEvalMode::Comprehensive`]. Per
/// qiuth-patterns.md §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyEvalMode {
    #[default]
    FailFast,
    Comprehensive,
}

/// Full per-request trace. Logged structurally, returned on the
/// request-detail API, optionally surfaced via `X-Proxilion-Trace-Id`
/// on responses (id only, never body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTrace {
    pub trace_id: Uuid,
    pub evaluated_at: DateTime<Utc>,
    pub duration_micros: u64,
    pub layers: Vec<LayerOutcome>,
    pub final_decision: Decision,
    /// Required ops atoms surfaced by Layer-B for the adapter to enforce.
    /// Empty when no policy matched.
    pub required_ops: Vec<OpsAtomView>,
}

/// Wire-friendly view of an [`OpsAtom`]: avoids leaking the internal
/// struct shape into the trace JSON contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsAtomView {
    pub scheme: String,
    pub action: String,
    pub object: String,
}

impl From<&OpsAtom> for OpsAtomView {
    fn from(a: &OpsAtom) -> Self {
        Self {
            scheme: a.scheme.clone(),
            action: a.action.clone(),
            object: a.object.clone(),
        }
    }
}

impl PolicyTrace {
    pub fn new(layers: Vec<LayerOutcome>, decision: Decision, required_ops: Vec<OpsAtomView>) -> Self {
        Self {
            trace_id: Uuid::new_v4(),
            evaluated_at: Utc::now(),
            duration_micros: 0,
            layers,
            final_decision: decision,
            required_ops,
        }
    }

    /// `true` when every layer recorded `passed = true`.
    pub fn allowed(&self) -> bool {
        self.layers.iter().all(|l| l.passed) && matches!(self.final_decision, Decision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passed_outcome_has_no_error() {
        let o = LayerOutcome::passed(PolicyLayer::LayerB);
        assert!(o.passed);
        assert!(o.error_code.is_none());
    }

    #[test]
    fn failed_outcome_carries_code() {
        let o = LayerOutcome::failed(
            PolicyLayer::LayerB,
            ErrorCode::PolicyBlocked,
            Some("gmail-external-recipient".into()),
            Some("external recipient".into()),
        );
        assert!(!o.passed);
        assert_eq!(o.error_code, Some(ErrorCode::PolicyBlocked));
        assert_eq!(o.matched_rule_id.as_deref(), Some("gmail-external-recipient"));
    }

    #[test]
    fn trace_allowed_when_all_layers_pass() {
        let t = PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::LayerA),
                LayerOutcome::passed(PolicyLayer::LayerB),
            ],
            Decision::Allow,
            vec![],
        );
        assert!(t.allowed());
    }

    #[test]
    fn trace_denied_when_any_layer_fails() {
        let t = PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::LayerA),
                LayerOutcome::failed(
                    PolicyLayer::LayerB,
                    ErrorCode::PolicyBlocked,
                    Some("p1".into()),
                    None,
                ),
            ],
            Decision::Block { reason: "policy".into(), override_allowed: true },
            vec![],
        );
        assert!(!t.allowed());
    }

    #[test]
    fn ops_atom_view_round_trips_fields() {
        let a = OpsAtom {
            scheme: "drive".into(),
            action: "read".into(),
            object: "file/abc".into(),
        };
        let v: OpsAtomView = (&a).into();
        assert_eq!(v.scheme, "drive");
        assert_eq!(v.action, "read");
        assert_eq!(v.object, "file/abc");
    }
}
