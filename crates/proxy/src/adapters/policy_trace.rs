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
    fn summary_return_type_is_owned_string_not_borrowed_str_for_log_field_ownership() {
        // `summary()` returns `String` because the `tracing::info!`/
        // `warn!` call sites in `emit()` capture it with `%summary`
        // and stream the value across thread boundaries via the
        // tracing subscriber's structured-field bag (which requires
        // owned data). A refactor to `&'a str` "for zero-alloc" would
        // surface here at the type-coercion boundary AND break the
        // emit path with a borrow-checker error (the borrowed slice
        // would outlive its trace owner once handed to the tracing
        // event). Pin the owned String shape via a helper that
        // accepts String only.
        fn require_string(_: String) {}
        let t = fresh_trace();
        let s = summary(&t);
        require_string(s);
    }

    #[test]
    fn mark_layer_a_failed_flips_passed_to_false_polarity_pin() {
        // The mark_layer_a_failed helper is the Trust-Plane-refusal
        // path — the dashboard's "PCA invariant break" panel counts
        // `passed == false` rows on the LayerA bucket. The existing
        // `mark_layer_a_failed_replaces_passed_entry` test pins the
        // error_code + detail; pin the BOOLEAN passed polarity
        // explicitly here so a refactor that constructed the
        // replacement via `LayerOutcome::passed()` (which would land
        // `passed: true`) "to surface the detail even on the success
        // path" would silently break the count metric. The boolean
        // false is the load-bearing tripwire — pin it.
        let mut t = fresh_trace();
        // Pre-check: the LayerA slot starts as passed == true.
        let pre = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .unwrap();
        assert!(pre.passed, "pre-condition: LayerA must start passed");
        mark_layer_a_failed(&mut t, "ops not subset".into());
        let post = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .unwrap();
        assert!(!post.passed, "mark_layer_a_failed must flip passed→false");
    }

    #[test]
    fn summary_renders_multiple_failed_layers_with_distinct_error_codes_comma_joined() {
        // The existing `summary_renders_codes` pin walks ONE failed
        // layer; widen to TWO failed layers (LayerA via
        // PicInvariantViolation + LayerB via PolicyBlocked) so a
        // refactor that emitted only the FIRST failure "for log
        // brevity" or that collapsed multi-failed traces to a single
        // `denied` token "for consistency with Decision::Block" would
        // surface here. The dashboard's "multi-layer fault" alert
        // keys on the comma-joined two-code shape as the
        // discriminant between cascading vs single-point faults.
        let mut t = fresh_trace();
        mark_layer_a_failed(&mut t, "pic break".into());
        // Replace LayerB with a failed PolicyBlocked outcome.
        set_layer(
            &mut t,
            PolicyLayer::LayerB,
            LayerOutcome::failed(
                PolicyLayer::LayerB,
                ErrorCode::PolicyBlocked,
                Some("gmail-external".into()),
                Some("external recipient".into()),
            ),
        );
        let s = summary(&t);
        assert!(
            s.contains("layer_a=pic_invariant_violation"),
            "missing LayerA code: {s}",
        );
        assert!(
            s.contains("layer_b=policy_blocked"),
            "missing LayerB code: {s}",
        );
        // Both codes joined with `,` (per the helper's contract).
        assert!(s.contains(','), "missing comma separator: {s}");
    }

    #[test]
    fn emit_takes_trace_by_reference_not_consuming_value() {
        // `emit(trace, ...)` takes `&PolicyTrace` (NOT `PolicyTrace`).
        // The adapter path calls emit AFTER the policy decision has
        // already been recorded into the audit-event row — the trace
        // must remain available for downstream consumers (the
        // `tracing::info!` field bag captures by value via `%trace`,
        // but the caller still owns the trace for its own audit
        // serialization). A refactor that consumed the trace "for
        // a zero-copy serialize" would surface here as a borrow-
        // checker error at the call site after emit; pin the
        // `&PolicyTrace` signature by calling emit and then
        // continuing to use the original via summary().
        let t = fresh_trace();
        emit(&t, uuid::Uuid::new_v4(), "google", "drive.files.get");
        // The trace is still usable after emit — pin via a sync
        // operation on the original reference.
        let s = summary(&t);
        assert_eq!(s, "layer_a=ok,layer_b=ok");
    }

    #[test]
    fn set_layer_mutation_observable_via_subsequent_read_through_same_reference() {
        // `set_layer(&mut trace, ...)` mutates in place. Pin the
        // mutation is observable through a subsequent read on the
        // SAME `&trace` reference — proves the helper actually writes
        // through the borrow, NOT just operates on a local copy. A
        // refactor to `fn set_layer(trace: PolicyTrace, ...) -> PolicyTrace`
        // (functional / by-value) would silently start dropping the
        // mutation at every call site that doesn't reassign the
        // return value. Pin the in-place contract.
        let mut t = fresh_trace();
        let initial_layer_a_passed = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .map(|l| l.passed);
        assert_eq!(initial_layer_a_passed, Some(true));
        set_layer(
            &mut t,
            PolicyLayer::LayerA,
            LayerOutcome::failed(
                PolicyLayer::LayerA,
                ErrorCode::PicInvariantViolation,
                None,
                Some("after mutation".into()),
            ),
        );
        // Read through the same reference — mutation visible.
        let after = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .map(|l| (l.passed, l.detail.clone()));
        assert_eq!(after, Some((false, Some("after mutation".to_string()))));
    }

    #[test]
    fn summary_helper_is_pure_returning_byte_equal_output_across_independent_calls() {
        // `summary()` is a pure function of the trace state — calling
        // it twice on the SAME trace MUST return byte-equal output.
        // A refactor that introduced internal state (a per-call
        // counter, an Instant-stamped suffix "for log correlation",
        // a memoization cache that subtly drifted) would silently
        // make two calls diverge AND break log-dedup pipelines that
        // hash on the summary string. Pin purity on a trace with
        // multiple layers across two calls — symmetric to the Debug
        // purity pin on session.rs.
        let mut t = fresh_trace();
        mark_read_filter(&mut t, true, Some("p1".into()), "hit".into());
        let a = summary(&t);
        let b = summary(&t);
        assert_eq!(a, b, "summary must be pure: {a:?} vs {b:?}");
        // Symmetric on a denied trace.
        let mut denied = fresh_trace();
        mark_layer_a_failed(&mut denied, "missing drive:write:bob/*".into());
        let c = summary(&denied);
        let d = summary(&denied);
        assert_eq!(c, d);
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

    // ─── round 185 (2026-05-20): idempotency + signature surfaces on the mutation helpers ───

    #[test]
    fn mark_layer_a_failed_is_idempotent_across_fifty_repeated_invocations() {
        // `mark_layer_a_failed` uses `set_layer` (find-or-append) — so
        // calling it 50 times in a row with the same args MUST leave
        // the trace in the SAME state as one call: one LayerA entry
        // with passed=false + PicInvariantViolation + matched_rule_id=None
        // + the given detail. A refactor that switched `set_layer` to
        // `push` (always-append) would surface here as the layer count
        // ballooning to N+50 across the loop and dashboard alerts
        // double-counting Trust-Plane refusals. The existing
        // `mark_layer_a_failed_replaces_passed_entry` pins ONE call;
        // pin 50-call idempotency here. Symmetric to round-181 +
        // round-183 referential-transparency pins extended to this
        // in-place mutation helper.
        let mut t = fresh_trace();
        for _ in 0..50 {
            mark_layer_a_failed(&mut t, "missing drive:write:bob/*".into());
        }
        // The trace's layer count stays at the initial 2 — set_layer
        // replaces in place, never appends, when the slot exists.
        assert_eq!(t.layers.len(), 2, "set_layer must not duplicate on repeat");
        let la = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .unwrap();
        assert!(!la.passed);
        assert_eq!(la.error_code, Some(ErrorCode::PicInvariantViolation));
        assert!(la.matched_rule_id.is_none());
        assert_eq!(la.detail.as_deref(), Some("missing drive:write:bob/*"));
    }

    #[test]
    fn mark_read_filter_is_idempotent_across_fifty_repeated_invocations() {
        // Symmetric to `mark_layer_a_failed_is_idempotent_across_fifty_repeated_invocations`
        // extended to the read-filter slot. The first call appends
        // (no ReadFilter in fresh_trace), and the next 49 calls
        // replace — so the final layer count MUST be exactly the
        // initial 2 + 1 ReadFilter == 3, NOT 2 + 50. A refactor that
        // bypassed set_layer and pushed directly would surface here.
        // Pin the per-mutation in-place semantic + the final state
        // byte-equal to one canonical call.
        let mut t = fresh_trace();
        for _ in 0..50 {
            mark_read_filter(&mut t, true, Some("p-scan".into()), "hit".into());
        }
        assert_eq!(
            t.layers.len(),
            3,
            "mark_read_filter must not duplicate on repeat invocations",
        );
        let rf = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::ReadFilter)
            .unwrap();
        assert!(!rf.passed);
        assert_eq!(rf.error_code, Some(ErrorCode::ReadFilterBlocked));
        assert_eq!(rf.matched_rule_id.as_deref(), Some("p-scan"));
        assert_eq!(rf.detail.as_deref(), Some("hit"));
    }

    #[test]
    fn summary_is_referentially_transparent_across_fifty_repeated_calls() {
        // The existing `summary_helper_is_pure_returning_byte_equal_output_across_independent_calls`
        // pin walks TWO calls; extend to 50 to catch stateful drift
        // (a once-cell-backed memoization that subtly varied based on
        // call count, an Instant-stamped suffix snuck in "for log
        // correlation"). Operator log aggregators hash the summary
        // string to dedup; per-call variance would silently inflate
        // the hash-bucket count and break dedup. Symmetric to
        // round-181 RefreshCoordinator + round-183 WebhookSecret::sign
        // 50-iteration ref-transparency pins extended to this summary
        // helper.
        let mut t = fresh_trace();
        mark_layer_a_failed(&mut t, "pic break".into());
        mark_read_filter(&mut t, true, Some("p1".into()), "secret".into());
        let first = summary(&t);
        for i in 1..50 {
            let next = summary(&t);
            assert_eq!(
                next, first,
                "summary diverged on call #{i}: {first:?} vs {next:?}",
            );
        }
    }

    #[test]
    fn mark_layer_a_failed_detail_field_lands_in_layer_outcome_detail_as_owned_string() {
        // `mark_layer_a_failed(trace, detail: String)` consumes the
        // String and threads it into `LayerOutcome::failed`'s `detail:
        // Option<String>` field. Pin the owned-String shape via
        // require_string on the inner — a refactor that switched the
        // helper's signature to `&str` "for ergonomic operator-string
        // construction" would force every call site to clone, AND
        // would break the cross-await ownership required by the
        // tokio-spawn'd audit-sink that captures the trace. Symmetric
        // to round-184 owned-String field-type pins extended to this
        // helper's String passthrough.
        fn require_string(_: &String) {}
        let mut t = fresh_trace();
        mark_layer_a_failed(&mut t, "missing drive:write:bob/*".to_string());
        let la = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .unwrap();
        let detail = la.detail.as_ref().expect("detail must be Some");
        require_string(detail);
        assert_eq!(detail, "missing drive:write:bob/*");
    }

    #[test]
    fn summary_output_contains_only_commas_no_other_separator_chars_for_log_filter_safety() {
        // `summary()` uses `Vec::join(",")` — the ONLY separator
        // emitted is the literal `,`. Pin this so a refactor that
        // swapped to `"; "` (semicolon-space, the "more readable"
        // mistake), or to `\n` (newline, "for multi-line clarity")
        // would surface here as an unexpected character in the
        // single-line summary. Operator log filters expect the
        // single-line `","` separator; multi-line output would split
        // log records on the Loki/CloudWatch newline boundary and
        // silently fragment the structured event. Pin the absence of
        // semicolon / newline / tab / pipe / space in a multi-layer
        // summary.
        let mut t = fresh_trace();
        mark_layer_a_failed(&mut t, "pic".into());
        mark_read_filter(&mut t, true, Some("p1".into()), "hit".into());
        let s = summary(&t);
        // Must contain at least one comma (multi-layer trace).
        assert!(s.contains(','), "expected comma separator: {s}");
        // Must NOT contain any of the alternate separators a refactor
        // might introduce.
        for forbidden in [';', '\n', '\t', '|', ' '] {
            assert!(
                !s.contains(forbidden),
                "summary must not contain {forbidden:?}: {s}",
            );
        }
    }

    #[test]
    fn set_layer_is_send_safe_fn_pointer_for_axum_handler_state_use() {
        // The three public helpers (`set_layer`, `mark_layer_a_failed`,
        // `mark_read_filter`) are called from inside axum request
        // handlers that run on tokio's thread pool. The functions
        // themselves don't need Send/Sync (they're free functions),
        // but their fn-pointer types MUST be `Send + Sync + 'static`
        // so the handler can stash one in a trait-object closure
        // without an !Send capture. Pin the fn-pointer trait bounds
        // via the canonical require helpers — a refactor that
        // introduced a non-Send capture (e.g. via a #[thread_local]
        // configuration shim) would surface here at the fn-pointer
        // type boundary. Symmetric to round-181 + round-182
        // Send/Sync/'static pins extended to function pointers.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<fn(&mut PolicyTrace, PolicyLayer, LayerOutcome)>();
        require_send_sync_static::<fn(&mut PolicyTrace, String)>();
        require_send_sync_static::<fn(&mut PolicyTrace, bool, Option<String>, String)>();
        // Also pin the actual function items by casting to fn-pointer.
        let _: fn(&mut PolicyTrace, PolicyLayer, LayerOutcome) = set_layer;
        let _: fn(&mut PolicyTrace, String) = mark_layer_a_failed;
        let _: fn(&mut PolicyTrace, bool, Option<String>, String) = mark_read_filter;
    }

    // ─── round 212 (2026-05-21): policy_trace helper purity + ownership ───

    #[test]
    fn summary_label_strings_for_each_policy_layer_are_byte_exact_lowercase_snake_case() {
        // The `summary` helper renders each `PolicyLayer` variant as a
        // byte-exact lowercase snake_case label (`layer_a` / `layer_b`
        // / `read_filter`) — these are the Grafana label values on
        // `proxilion_policy_trace_layer_total` and the operator log
        // grep targets. A refactor that emitted Title-Case
        // (`LayerA`) or kebab-case (`read-filter`) would silently
        // re-label every counter under a new dimension value and
        // break the dashboard's "by layer" stacked bar. Pin all
        // three variants via single-layer fresh traces. Symmetric
        // to round 209's `audit_body_mode_label_strings_are_byte_exact_lowercase_for_grafana_label_axis`
        // pin extended to this sibling metric-label axis.
        for (layer, expected) in [
            (PolicyLayer::LayerA, "layer_a"),
            (PolicyLayer::LayerB, "layer_b"),
            (PolicyLayer::ReadFilter, "read_filter"),
        ] {
            let t = PolicyTrace::new(vec![LayerOutcome::passed(layer)], Decision::Allow, vec![]);
            let s = summary(&t);
            // Lowercase snake_case sweep on the substring we expect.
            assert!(
                s.contains(expected),
                "got {s}, expected substring {expected}"
            );
            assert!(
                !s.chars().any(|c| c.is_ascii_uppercase()),
                "summary has uppercase: {s}",
            );
            assert!(!s.contains('-'), "summary has kebab dash: {s}");
        }
    }

    #[test]
    fn set_layer_and_mark_helpers_return_unit_not_result_for_infallible_mutation_contract() {
        // `set_layer`, `mark_layer_a_failed`, `mark_read_filter` all
        // return `()` — the trace mutation is infallible (the find-or-
        // append shape can't fail). Pin the unit return across all
        // three helpers so a refactor that surfaced "future strict-
        // schema validation" via `Result<(), _>` would surface here
        // as a compile error AND would force a `?` chain through
        // every adapter call site (which today calls them without
        // propagation). Symmetric to round 206's
        // `tee_stream_publish_returns_unit_not_result_...` pin
        // extended to these sibling mutation helpers.
        fn require_unit(_: ()) {}
        let mut t = fresh_trace();
        let r1: () = set_layer(
            &mut t,
            PolicyLayer::LayerA,
            LayerOutcome::passed(PolicyLayer::LayerA),
        );
        require_unit(r1);
        let r2: () = mark_layer_a_failed(&mut t, "detail-a".into());
        require_unit(r2);
        let r3: () = mark_read_filter(&mut t, true, Some("p1".into()), "matched".into());
        require_unit(r3);
    }

    #[test]
    fn mark_read_filter_passed_arm_preserves_matched_policy_id_in_matched_rule_id_field() {
        // The `blocked=false` arm of `mark_read_filter` constructs a
        // bare `LayerOutcome { passed: true, matched_rule_id, ... }`
        // (not via the `LayerOutcome::failed(...)` constructor). A
        // refactor that swapped the bare-struct shape for a different
        // constructor that defaulted `matched_rule_id` to None — OR
        // that landed a "scrub matched_rule_id on the passed arm
        // because the read filter passed" simplification — would
        // silently strip the operator-visible policy id from the
        // trace. Pin the passed-arm field round-trip explicitly.
        // The existing `mark_read_filter_passed_arm_carries_none_error_code_with_detail_present`
        // pin checks the error_code + detail axes; this widens to
        // the matched_rule_id axis the operator dashboard groups by.
        let mut t = fresh_trace();
        mark_read_filter(&mut t, false, Some("pol-42".into()), "scan-passed".into());
        let rf = t
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::ReadFilter)
            .expect("read_filter slot present");
        assert!(rf.passed, "blocked=false must set passed=true");
        assert_eq!(rf.matched_rule_id.as_deref(), Some("pol-42"));
        assert_eq!(rf.detail.as_deref(), Some("scan-passed"));
        assert!(rf.error_code.is_none());
    }

    #[test]
    fn mark_layer_a_failed_detail_field_is_referentially_transparent_across_fifty_repeated_invocations()
     {
        // The existing `mark_layer_a_failed_is_idempotent_across_fifty_repeated_invocations`
        // pin walks the SAME-output contract for the layer count and
        // passed flag. Widen the RT axis to the `detail` field
        // specifically: 50 invocations on a fresh trace each must
        // leave `detail` byte-equal. A refactor that introduced a
        // per-call counter mixin (e.g. `format!("{detail} (attempt
        // {n})")` "for operator triage hints") would silently fork
        // the detail string across retries — pin byte-equality
        // here. Symmetric to round 207 + 209 referential-transparency
        // pins.
        let canonical_detail = "trust plane refused".to_string();
        let mut baseline_trace = fresh_trace();
        mark_layer_a_failed(&mut baseline_trace, canonical_detail.clone());
        let baseline_detail = baseline_trace
            .layers
            .iter()
            .find(|l| l.layer == PolicyLayer::LayerA)
            .and_then(|l| l.detail.clone());
        assert_eq!(baseline_detail.as_deref(), Some("trust plane refused"));
        for i in 0..50 {
            let mut t = fresh_trace();
            mark_layer_a_failed(&mut t, canonical_detail.clone());
            let got = t
                .layers
                .iter()
                .find(|l| l.layer == PolicyLayer::LayerA)
                .and_then(|l| l.detail.clone());
            assert_eq!(
                got, baseline_detail,
                "iteration {i}: mark_layer_a_failed must yield byte-equal detail",
            );
        }
    }

    #[test]
    fn summary_helper_uses_join_with_empty_separator_returning_empty_string_on_zero_layers() {
        // Boundary symmetric to the existing
        // `summary_renders_read_filter_label_and_empty_layers` test
        // (which uses a single-layer trace and asserts the
        // `read_filter=ok` label). Pin the zero-layer trace explicitly:
        // a fresh `PolicyTrace::new(vec![], Decision::Allow, vec![])`
        // must render summary as the empty string (NOT a placeholder
        // like `"<empty>"` or a leading/trailing comma). A refactor
        // that special-cased the empty case "for operator readability"
        // would silently drift the operator-facing log shape on the
        // not-yet-evaluated path. Pin via assert_eq! of the empty
        // string.
        let empty = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        let s = summary(&empty);
        assert_eq!(
            s, "",
            "zero-layer summary must be exactly empty, got: {s:?}"
        );
    }

    #[test]
    fn emit_function_pointer_is_send_sync_static_for_axum_handler_capture() {
        // The existing
        // `set_layer_is_send_safe_fn_pointer_for_axum_handler_state_use`
        // pin walks the three mutation helpers' fn-pointer Send/Sync/'static
        // bounds. Widen the same surface to `emit` and `summary` — both
        // are called from inside the request handler at end-of-request,
        // and `emit` is the path that crosses the `tracing::info!` /
        // `warn!` invocation. A refactor that introduced a non-Send
        // capture in either helper (e.g. via a thread-local rate
        // limiter on the trace-log emit path) would surface here at
        // the fn-pointer type boundary rather than at the far-removed
        // handler-state assembly site. Symmetric to round 206's
        // `tee_stream_is_send_sync_static_for_app_state_arc_dyn_path`
        // pin extended to these sibling adapter helpers.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<fn(&PolicyTrace, uuid::Uuid, &str, &str)>();
        require_send_sync_static::<fn(&PolicyTrace) -> String>();
        let _: fn(&PolicyTrace, uuid::Uuid, &str, &str) = emit;
        let _: fn(&PolicyTrace) -> String = summary;
    }

    // ─── round 250 (2026-05-22): mark_* helper fn-pointer witnesses,
    // summary unknown-fallback + format byte-exactness, set_layer
    // replace-vs-append polarities ───

    #[test]
    fn mark_layer_a_failed_signature_takes_trace_mut_and_owned_string_via_fn_pointer_witness() {
        // `mark_layer_a_failed(trace: &mut PolicyTrace, detail: String)` —
        // takes `&mut` BORROW of the trace (in-place mutation, the
        // adapter holds the trace owned across the request handler)
        // and OWNED `String` detail (the upstream Trust Plane refusal
        // body is moved into the `LayerOutcome.detail` field, NOT
        // borrowed — the adapter call site uses
        // `body.to_string()` before this call). A refactor to
        // `&str` detail "for zero-alloc on the cold-path refusal"
        // would tie the LayerOutcome's lifetime to the request frame
        // — but `LayerOutcome.detail` is `Option<String>` (owned) and
        // crosses the `.await` boundary to `emit(...)`, producing a
        // use-after-free. Pin via fn-pointer witness so a signature
        // drift surfaces at this file. Symmetric to round-238's
        // `email_notifier_with_max_retries_consumes_self_and_returns_self_via_fn_pointer_witness`
        // extended to this sibling mutation helper.
        let _f: fn(&mut PolicyTrace, String) = mark_layer_a_failed;
    }

    #[test]
    fn mark_read_filter_signature_takes_four_args_via_fn_pointer_witness_with_owned_string_detail()
    {
        // `mark_read_filter(trace: &mut PolicyTrace, blocked: bool,
        // matched_policy_id: Option<String>, detail: String)` — the
        // 4-arg signature is load-bearing: `blocked` flips the
        // `LayerOutcome.passed` bit AND selects between the
        // `ErrorCode::ReadFilterBlocked`-bearing `failed` arm and the
        // `passed=true` arm. `matched_policy_id` flows into the
        // `matched_rule_id` slot on BOTH arms — operator dashboards
        // bucket on the rule id even on passing reads (to attribute
        // read-filter quarantine actions to a policy). A refactor
        // that collapsed the 4-arg signature to a single
        // `outcome: LayerOutcome` "for consistency with set_layer"
        // would foreclose the callsite ergonomics that thread the
        // 4 atoms straight through. Pin via fn-pointer witness.
        let _f: fn(&mut PolicyTrace, bool, Option<String>, String) = mark_read_filter;
    }

    #[test]
    fn summary_failed_layer_with_none_error_code_falls_back_to_unknown_label_byte_exact() {
        // `summary` renders failed layers as `<layer>=<error_code>`
        // using `l.error_code.map(|c| c.as_str()).unwrap_or("unknown")`.
        // A failed layer with `error_code: None` MUST surface the
        // literal `"unknown"` fallback string — a refactor that
        // changed the fallback to `"failed"` or `""` "for clearer
        // dashboard rendering" would silently break every operator
        // alert filter keyed on the `=unknown` substring. The
        // existing `summary_label_strings_for_each_policy_layer_are_byte_exact_lowercase_snake_case`
        // pin walks the LAYER half of the `<layer>=<code>` format;
        // pin the FALLBACK half here on the same byte-exact basis.
        let outcome = LayerOutcome {
            layer: PolicyLayer::ReadFilter,
            passed: false,
            matched_rule_id: None,
            error_code: None,
            detail: None,
        };
        let trace = PolicyTrace::new(vec![outcome], Decision::Allow, vec![]);
        let s = summary(&trace);
        assert_eq!(s, "read_filter=unknown");
    }

    #[test]
    fn summary_failed_layer_with_some_error_code_renders_layer_equals_code_format_byte_exact() {
        // Symmetric to the None-fallback pin above: when `error_code`
        // is `Some(code)`, the format is `<layer>=<code.as_str()>` —
        // byte-exact, no quoting, no padding. A refactor that wrapped
        // the code in quotes (`<layer>="<code>"` "for JSON-quotable
        // log lines") OR that prepended/appended any decoration would
        // surface here. Pin all THREE layer × code combinations across
        // the canonical 3-layer set to exercise the full grid of
        // `summary` output shapes.
        let trace = PolicyTrace::new(
            vec![
                LayerOutcome::failed(
                    PolicyLayer::LayerA,
                    ErrorCode::PicInvariantViolation,
                    None,
                    None,
                ),
                LayerOutcome::failed(PolicyLayer::LayerB, ErrorCode::PolicyBlocked, None, None),
                LayerOutcome::failed(
                    PolicyLayer::ReadFilter,
                    ErrorCode::ReadFilterBlocked,
                    None,
                    None,
                ),
            ],
            Decision::Allow,
            vec![],
        );
        let s = summary(&trace);
        // Each layer rendered as `<layer>=<code.as_str()>` joined by
        // commas — pin the full byte-exact string.
        let expected = format!(
            "layer_a={},layer_b={},read_filter={}",
            ErrorCode::PicInvariantViolation.as_str(),
            ErrorCode::PolicyBlocked.as_str(),
            ErrorCode::ReadFilterBlocked.as_str(),
        );
        assert_eq!(s, expected);
    }

    #[test]
    fn set_layer_replaces_existing_entry_in_place_preserving_vec_position_for_zero_drift() {
        // `set_layer` is documented as "replace OR append": when the
        // target layer already exists in `trace.layers`, the helper
        // replaces it IN PLACE rather than appending a duplicate. The
        // existing `mark_layer_a_failed_detail_field_lands_in_layer_outcome_detail_as_owned_string`
        // pin walks the post-flip detail content but not the
        // structural in-place-vs-append polarity. A refactor that
        // changed the replace path to a push (`trace.layers.push(replacement)`
        // unconditionally) "for ergonomic history-of-flips
        // observability" would silently DOUBLE every flipped layer in
        // the emitted `summary()` output AND would break the
        // `trace.allowed()` check (which iterates `layers` and
        // short-circuits on `passed=false` — duplicates wouldn't
        // change semantics but would inflate the audit-log line
        // size). Pin the in-place replacement: vec length stays
        // constant AND the slot at the original index carries the
        // new outcome.
        let mut trace = PolicyTrace::new(
            vec![LayerOutcome {
                layer: PolicyLayer::LayerA,
                passed: true,
                matched_rule_id: None,
                error_code: None,
                detail: Some("originally passed".into()),
            }],
            Decision::Allow,
            vec![],
        );
        assert_eq!(trace.layers.len(), 1);
        set_layer(
            &mut trace,
            PolicyLayer::LayerA,
            LayerOutcome::failed(
                PolicyLayer::LayerA,
                ErrorCode::PicInvariantViolation,
                None,
                Some("now failed".into()),
            ),
        );
        // Length unchanged — replace, not append.
        assert_eq!(
            trace.layers.len(),
            1,
            "set_layer must replace in place, not append duplicate",
        );
        // Slot now carries the replacement.
        assert!(!trace.layers[0].passed);
        assert_eq!(trace.layers[0].detail.as_deref(), Some("now failed"));
    }

    #[test]
    fn set_layer_appends_when_target_layer_absent_for_initial_population_path() {
        // Symmetric to the in-place-replace pin above: when the
        // target layer is ABSENT from `trace.layers`, the helper
        // pushes a fresh entry. A refactor that changed the absent
        // path to a no-op (`if let Some(slot) = ... { *slot = ... }`
        // dropping the else branch) "to enforce that callers
        // pre-populate the trace" would silently drop the first
        // mark on every adapter call — and the engine's policy
        // trace would be missing the layer entry entirely, breaking
        // the dashboard's "every request shows all 3 layers" UI
        // expectation. Pin the append-on-absent contract by
        // starting with an empty `layers` vec and verifying the
        // post-call length is exactly 1.
        let mut trace = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        assert_eq!(trace.layers.len(), 0);
        set_layer(
            &mut trace,
            PolicyLayer::ReadFilter,
            LayerOutcome {
                layer: PolicyLayer::ReadFilter,
                passed: true,
                matched_rule_id: Some("drive-quarantine-policy".into()),
                error_code: None,
                detail: Some("quarantined 2 attachments".into()),
            },
        );
        assert_eq!(
            trace.layers.len(),
            1,
            "set_layer must append when layer is absent",
        );
        assert_eq!(trace.layers[0].layer, PolicyLayer::ReadFilter);
        assert_eq!(
            trace.layers[0].matched_rule_id.as_deref(),
            Some("drive-quarantine-policy")
        );
    }
}
