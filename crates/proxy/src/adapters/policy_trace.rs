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
                let code = l.error_code.map(|c| c.as_str()).unwrap_or("unknown");
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
    let trace_json =
        serde_json::to_string(trace).unwrap_or_else(|_| "<trace serialization failed>".to_string());
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
        let la = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .unwrap();
        assert!(!la.passed);
        assert_eq!(la.error_code, Some(ErrorCode::PicInvariantViolation));
        assert_eq!(la.detail.as_deref(), Some("missing drive:write:bob/*"));
    }

    #[test]
    fn mark_read_filter_appends_when_absent() {
        let mut t = fresh_trace();
        assert!(t.layers.iter().all(|l| l.layer != PolicyLayer::ReadFilter));
        mark_read_filter(&mut t, false, Some("p1".into()), "no matches".into());
        let rf = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::ReadFilter)
            .unwrap();
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

    #[test]
    fn mark_read_filter_blocked_sets_failed_with_code() {
        let mut t = fresh_trace();
        mark_read_filter(&mut t, true, Some("p-secret".into()), "hit".into());
        let rf = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::ReadFilter)
            .unwrap();
        assert!(!rf.passed);
        assert_eq!(rf.error_code, Some(ErrorCode::ReadFilterBlocked));
        assert_eq!(rf.matched_rule_id.as_deref(), Some("p-secret"));
        assert_eq!(rf.detail.as_deref(), Some("hit"));
    }

    #[test]
    fn mark_read_filter_replaces_existing_entry() {
        let mut t = fresh_trace();
        mark_read_filter(&mut t, false, Some("p1".into()), "first pass".into());
        // Second call must replace, not append a duplicate ReadFilter entry.
        mark_read_filter(&mut t, true, Some("p2".into()), "second hit".into());
        let rf: Vec<_> = t
            .layers
            .iter()
            .filter(|l| l.layer == PolicyLayer::ReadFilter)
            .collect();
        assert_eq!(rf.len(), 1, "ReadFilter must not duplicate");
        assert!(!rf[0].passed);
        assert_eq!(rf[0].matched_rule_id.as_deref(), Some("p2"));
    }

    #[test]
    fn set_layer_appends_when_layer_absent() {
        let mut t = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        set_layer(
            &mut t,
            PolicyLayer::LayerB,
            LayerOutcome::passed(PolicyLayer::LayerB),
        );
        assert_eq!(t.layers.len(), 1);
        assert_eq!(t.layers[0].layer, PolicyLayer::LayerB);
    }

    #[test]
    fn set_layer_replaces_only_matching_layer_leaving_siblings_intact() {
        // The replace-or-append helper is the only mutation primitive
        // — pin that replacing one layer does NOT disturb its
        // neighbors' order or content. A refactor that scanned the
        // Vec with `iter().enumerate()` and called `Vec::swap_remove`
        // would silently scramble ordering. The downstream `summary`
        // helper renders in Vec order, so an order swap would flip
        // the comma-joined string the operator log filters key on.
        let mut t = PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::LayerA),
                LayerOutcome::passed(PolicyLayer::LayerB),
                LayerOutcome::passed(PolicyLayer::ReadFilter),
            ],
            Decision::Allow,
            vec![],
        );
        set_layer(
            &mut t,
            PolicyLayer::LayerB,
            LayerOutcome::failed(
                PolicyLayer::LayerB,
                ErrorCode::PolicyBlocked,
                Some("p1".into()),
                Some("explicit".into()),
            ),
        );
        assert_eq!(t.layers.len(), 3);
        assert_eq!(t.layers[0].layer, PolicyLayer::LayerA);
        assert!(t.layers[0].passed);
        assert_eq!(t.layers[1].layer, PolicyLayer::LayerB);
        assert!(!t.layers[1].passed);
        assert_eq!(t.layers[2].layer, PolicyLayer::ReadFilter);
        assert!(t.layers[2].passed);
    }

    #[test]
    fn summary_join_uses_comma_and_preserves_layer_order() {
        // The comma-separator and the Vec-order rendering together
        // form the wire-shape operator log filters parse. Pin BOTH:
        // an alphabetical-sort regression ("clean up the summary")
        // would put `layer_a` before `layer_b` even when LayerB
        // landed first; a tab/space separator regression would break
        // every Grafana log-derived metric keyed on the canonical
        // form. The trace below puts ReadFilter FIRST to make the
        // order assertion meaningful (alphabetical would put `layer_a`
        // first).
        let t = PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::ReadFilter),
                LayerOutcome::passed(PolicyLayer::LayerA),
            ],
            Decision::Allow,
            vec![],
        );
        let s = summary(&t);
        assert_eq!(s, "read_filter=ok,layer_a=ok", "got: {s}");
    }

    #[test]
    fn emit_does_not_panic_on_allowed_and_denied_traces() {
        // `emit` is `tracing`-only — it never returns a value. The
        // operator-visible contract is "single structured event per
        // request, INFO on allow / WARN on deny, never panics". Pin
        // the don't-panic invariant on both paths (the alternative is
        // a request that successfully gates but then panics in the
        // trace emitter, which would crash the worker). The fallback-
        // serialization path (`<trace serialization failed>`) is hard
        // to trigger without a custom Serialize impl that errors —
        // accepted; this test pins the happy paths only.
        let t = fresh_trace();
        emit(&t, uuid::Uuid::new_v4(), "google", "drive.files.get");
        let mut denied = fresh_trace();
        mark_layer_a_failed(&mut denied, "missing".into());
        emit(&denied, uuid::Uuid::new_v4(), "google", "drive.files.get");
    }

    #[test]
    fn summary_renders_read_filter_label_and_empty_layers() {
        let empty = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        assert_eq!(summary(&empty), "");

        let mut t = fresh_trace();
        mark_read_filter(&mut t, true, None, "x".into());
        let s = summary(&t);
        // Verify each layer label string (the wire contract operators key
        // structured-log filters on) is correct.
        assert!(s.contains("layer_a=ok"));
        assert!(s.contains("layer_b=ok"));
        assert!(s.contains("read_filter=read_filter_blocked"));
    }

    #[test]
    fn summary_renders_unknown_for_failed_layer_with_no_error_code() {
        // `summary()` falls back to `"unknown"` when a failed layer
        // carries `error_code: None`. The fallback is the `unwrap_or`
        // arm on the rendered code substring and is what surfaces in
        // the comma-joined summary when a hand-constructed
        // `LayerOutcome` lands in the trace without going through
        // `LayerOutcome::failed()` (which always sets a code).
        // Operator dashboards split on `=unknown` as the "trace was
        // mutated by hand without a code" tripwire — a refactor that
        // collapsed the fallback to `""` (empty) would silently
        // produce `layer_b=` and break log-derived metrics keyed on
        // the `=<word>` pattern.
        let t = PolicyTrace::new(
            vec![LayerOutcome {
                layer: PolicyLayer::LayerB,
                passed: false,
                matched_rule_id: None,
                error_code: None,
                detail: None,
            }],
            Decision::Allow,
            vec![],
        );
        assert_eq!(summary(&t), "layer_b=unknown");
    }

    #[test]
    fn mark_layer_a_failed_always_sets_matched_rule_id_to_none() {
        // `mark_layer_a_failed` hardcodes `None` for the
        // `matched_rule_id` field — Layer A faults are PIC
        // monotonicity failures, NOT policy-rule matches, so the
        // helper never carries a policy_id. Pin this contract so a
        // refactor that "for consistency with mark_read_filter"
        // added a `matched_policy_id` parameter would surface here.
        // The dashboard's "PCA refused" alert keys on `layer_a` rows
        // with `matched_rule_id: null` as the discriminant against
        // any future Layer A variant that DOES carry a policy id.
        let mut t = fresh_trace();
        mark_layer_a_failed(&mut t, "missing drive:write:bob/*".into());
        let la = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .unwrap();
        assert!(
            la.matched_rule_id.is_none(),
            "got: {:?}",
            la.matched_rule_id
        );
        assert_eq!(la.error_code, Some(ErrorCode::PicInvariantViolation));
    }

    #[test]
    fn mark_read_filter_passed_arm_carries_none_error_code_with_detail_present() {
        // The `blocked=false` arm of `mark_read_filter` constructs
        // a `LayerOutcome` directly (not via `LayerOutcome::passed()`
        // or `LayerOutcome::failed()`) so it can carry BOTH
        // `passed: true` AND a `detail: Some(_)` describing the
        // quarantine action that ran. This is the only place in the
        // adapter where a passed layer surfaces a `detail` — pin
        // the four-axis shape (passed=true, error_code=None,
        // matched_rule_id=Some, detail=Some) so a refactor that
        // routed through `LayerOutcome::passed()` (which drops
        // `detail`) would silently strip the per-event quarantine
        // count from the structured log.
        let mut t = fresh_trace();
        mark_read_filter(
            &mut t,
            false,
            Some("drive-secret-scanner".into()),
            "quarantined 3 of 12 chunks".into(),
        );
        let rf = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::ReadFilter)
            .unwrap();
        assert!(rf.passed);
        assert!(
            rf.error_code.is_none(),
            "passed arm must NOT set an error_code"
        );
        assert_eq!(rf.matched_rule_id.as_deref(), Some("drive-secret-scanner"));
        assert_eq!(rf.detail.as_deref(), Some("quarantined 3 of 12 chunks"));
    }

    #[test]
    fn set_layer_replaces_only_first_matching_entry_when_duplicates_exist() {
        // `set_layer` uses `iter_mut().find(|l| l.layer == layer)` —
        // a linear scan that returns the FIRST matching slot. If a
        // caller (today: only the engine's initial construction +
        // `mark_*` helpers) accidentally produced a trace with two
        // entries for the same layer, only the first one would be
        // replaced. Pin this contract: the helper is single-replace,
        // not replace-all. A refactor to `iter_mut().filter(...).for_each(|s| *s = ...)`
        // (replace-all) would silently double-mutate a malformed
        // trace and mask the duplicate; the current single-replace
        // semantic preserves the duplicate as a visible bug for
        // operator triage.
        let mut t = PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::LayerB),
                LayerOutcome::passed(PolicyLayer::LayerA),
                LayerOutcome::passed(PolicyLayer::LayerB),
            ],
            Decision::Allow,
            vec![],
        );
        set_layer(
            &mut t,
            PolicyLayer::LayerB,
            LayerOutcome::failed(
                PolicyLayer::LayerB,
                ErrorCode::PolicyBlocked,
                Some("p1".into()),
                Some("first".into()),
            ),
        );
        // Length unchanged — single-replace, no append.
        assert_eq!(t.layers.len(), 3);
        // First LayerB entry (index 0) was replaced.
        assert!(!t.layers[0].passed);
        assert_eq!(t.layers[0].error_code, Some(ErrorCode::PolicyBlocked));
        // LayerA in the middle untouched.
        assert!(t.layers[1].passed);
        assert_eq!(t.layers[1].layer, PolicyLayer::LayerA);
        // Second LayerB entry (index 2) preserved unchanged — single-replace.
        assert!(t.layers[2].passed);
        assert_eq!(t.layers[2].layer, PolicyLayer::LayerB);
    }

    #[test]
    fn summary_single_failed_layer_renders_without_trailing_separator() {
        // `summary()` joins the per-layer renderings with `","` via
        // `Vec::join`. On a single-element Vec the join produces NO
        // separator — pin that contract so a refactor that swapped
        // to a manual `for { push(','); push(layer) }` loop (which
        // would emit a trailing comma) would silently break operator
        // log filters keyed on the exact `"layer_a=pic_invariant_violation"`
        // shape with no trailing punctuation. The empty-Vec case is
        // already pinned by `summary_renders_read_filter_label_and_empty_layers`;
        // this fills in the single-element boundary.
        let t = PolicyTrace::new(
            vec![LayerOutcome::failed(
                PolicyLayer::LayerA,
                ErrorCode::PicInvariantViolation,
                None,
                Some("missing".into()),
            )],
            Decision::Allow,
            vec![],
        );
        let s = summary(&t);
        assert_eq!(s, "layer_a=pic_invariant_violation");
        assert!(!s.ends_with(','), "no trailing separator allowed: {s:?}");
    }

    #[test]
    fn mark_read_filter_blocked_with_none_policy_id_omits_matched_rule_id() {
        // Symmetric to round-2's existing `mark_read_filter_blocked_sets_failed_with_code`
        // which only pinned the `Some(_)` arm. The `None` arm fires
        // when an ad-hoc / default-deny scan triggers without a
        // matched policy (e.g. a global scanner that runs on every
        // response). The dashboard's "scan triggered" panel
        // distinguishes per-policy hits from global-scanner hits on
        // the presence of `matched_rule_id` — a refactor that
        // unwrap_or-defaulted the field to `"unknown"` to "always
        // surface something" would silently merge the two buckets.
        let mut t = fresh_trace();
        mark_read_filter(&mut t, true, None, "secret detected".into());
        let rf = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::ReadFilter)
            .unwrap();
        assert!(!rf.passed);
        assert_eq!(rf.error_code, Some(ErrorCode::ReadFilterBlocked));
        assert!(
            rf.matched_rule_id.is_none(),
            "None-policy-id arm must NOT synthesize a rule id; got: {:?}",
            rf.matched_rule_id,
        );
        assert_eq!(rf.detail.as_deref(), Some("secret detected"));
    }
}
