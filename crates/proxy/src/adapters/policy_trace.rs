//! Adapter-side helpers for the `PolicyTrace` flow (qiuth-patterns.md §3).
//!
//! The policy engine emits a structured trace alongside its `Outcome`; the
//! adapter then mutates two slots as the request progresses:
//!
//! - **Layer A** flips to `failed` when the Trust Plane refuses the
//!   successor PCA (the engine optimistically marks it `passed` because
//!   the ops-shape check happens engine-side).
//! - **ReadFilter** flips when the response body scan triggers — either
//!   to `failed` (BlockRequest pattern) or stays `passed` with a `detail`
//!   describing the quarantine action taken.
//!
//! At the end of each request the adapter emits a single structured
//! `tracing::info!` (or `warn!` on deny) carrying the full trace so the
//! audit pipeline can reconstruct "why" without reading scattered logs.

use policy_engine::{LayerOutcome, PolicyLayer, PolicyTrace};
use shared_types::ErrorCode;

/// Replace (or append) the trace entry for `layer` with `replacement`.
pub fn set_layer(trace: &mut PolicyTrace, layer: PolicyLayer, replacement: LayerOutcome) {
    if let Some(slot) = trace.layers.iter_mut().find(|l| l.layer == layer) {
        *slot = replacement;
    } else {
        trace.layers.push(replacement);
    }
}

/// Mark Layer A as failed (Trust Plane refused successor PCA).
pub fn mark_layer_a_failed(trace: &mut PolicyTrace, detail: String) {
    set_layer(
        trace,
        PolicyLayer::LayerA,
        LayerOutcome::failed(
            PolicyLayer::LayerA,
            ErrorCode::PicInvariantViolation,
            None,
            Some(detail),
        ),
    );
}

/// Mark ReadFilter as completed with the given outcome.
pub fn mark_read_filter(
    trace: &mut PolicyTrace,
    blocked: bool,
    matched_policy_id: Option<String>,
    detail: String,
) {
    let outcome = if blocked {
        LayerOutcome::failed(
            PolicyLayer::ReadFilter,
            ErrorCode::ReadFilterBlocked,
            matched_policy_id,
            Some(detail),
        )
    } else {
        LayerOutcome {
            layer: PolicyLayer::ReadFilter,
            passed: true,
            matched_rule_id: matched_policy_id,
            error_code: None,
            detail: Some(detail),
        }
    };
    set_layer(trace, PolicyLayer::ReadFilter, outcome);
}

/// One-line summary suitable for the `summary` field of the structured
/// log event. Renders each layer as `name=ok` or `name=<code>`.
pub fn summary(trace: &PolicyTrace) -> String {
    trace
        .layers
        .iter()
        .map(|l| {
            let layer = match l.layer {
                PolicyLayer::LayerA => "layer_a",
                PolicyLayer::LayerB => "layer_b",
                PolicyLayer::ReadFilter => "read_filter",
            };
            if l.passed {
                format!("{layer}=ok")
            } else {
                let code = l
                    .error_code
                    .map(|c| c.as_str())
                    .unwrap_or("unknown");
                format!("{layer}={code}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Emit the trace as a structured `tracing` event. Allowed traces log
/// at INFO; denied traces log at WARN so operators can filter cleanly.
pub fn emit(trace: &PolicyTrace, request_id: uuid::Uuid, vendor: &str, action: &str) {
    let summary = summary(trace);
    let trace_json = serde_json::to_string(trace).unwrap_or_else(|_| "<trace serialization failed>".to_string());
    if trace.allowed() {
        tracing::info!(
            request_id = %request_id,
            trace_id = %trace.trace_id,
            vendor = vendor,
            action = action,
            duration_micros = trace.duration_micros,
            summary = %summary,
            trace = %trace_json,
            "policy trace"
        );
    } else {
        tracing::warn!(
            request_id = %request_id,
            trace_id = %trace.trace_id,
            vendor = vendor,
            action = action,
            duration_micros = trace.duration_micros,
            summary = %summary,
            trace = %trace_json,
            "policy trace (denied)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_engine::Decision;

    fn fresh_trace() -> PolicyTrace {
        PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::LayerA),
                LayerOutcome::passed(PolicyLayer::LayerB),
            ],
            Decision::Allow,
            vec![],
        )
    }

    #[test]
    fn mark_layer_a_failed_replaces_passed_entry() {
        let mut t = fresh_trace();
        mark_layer_a_failed(&mut t, "missing drive:write:bob/*".into());
        let la = t.layers.iter().find(|l| l.layer == PolicyLayer::LayerA).unwrap();
        assert!(!la.passed);
        assert_eq!(la.error_code, Some(ErrorCode::PicInvariantViolation));
        assert_eq!(la.detail.as_deref(), Some("missing drive:write:bob/*"));
    }

    #[test]
    fn mark_read_filter_appends_when_absent() {
        let mut t = fresh_trace();
        assert!(t.layers.iter().all(|l| l.layer != PolicyLayer::ReadFilter));
        mark_read_filter(&mut t, false, Some("p1".into()), "no matches".into());
        let rf = t.layers.iter().find(|l| l.layer == PolicyLayer::ReadFilter).unwrap();
        assert!(rf.passed);
        assert_eq!(rf.matched_rule_id.as_deref(), Some("p1"));
    }

    #[test]
    fn summary_renders_codes() {
        let mut t = fresh_trace();
        mark_layer_a_failed(&mut t, "x".into());
        let s = summary(&t);
        assert!(s.contains("layer_a=pic_invariant_violation"));
        assert!(s.contains("layer_b=ok"));
    }
}
