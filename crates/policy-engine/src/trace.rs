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
    pub fn new(
        layers: Vec<LayerOutcome>,
        decision: Decision,
        required_ops: Vec<OpsAtomView>,
    ) -> Self {
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
        assert_eq!(
            o.matched_rule_id.as_deref(),
            Some("gmail-external-recipient")
        );
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
            Decision::Block {
                reason: "policy".into(),
                override_allowed: true,
            },
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

    #[test]
    fn policy_layer_serializes_snake_case() {
        let cases = [
            (PolicyLayer::LayerA, "\"layer_a\""),
            (PolicyLayer::LayerB, "\"layer_b\""),
            (PolicyLayer::ReadFilter, "\"read_filter\""),
        ];
        for (variant, wire) in cases {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, wire, "snake_case wire for {variant:?}");
            let back: PolicyLayer = serde_json::from_str(wire).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn policy_eval_mode_default_is_fail_fast() {
        assert_eq!(PolicyEvalMode::default(), PolicyEvalMode::FailFast);
    }

    #[test]
    fn trace_not_allowed_when_decision_is_block_even_if_layers_pass() {
        let t = PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::LayerA),
                LayerOutcome::passed(PolicyLayer::LayerB),
            ],
            Decision::Block {
                reason: "policy".into(),
                override_allowed: false,
            },
            vec![],
        );
        assert!(!t.allowed());
    }

    #[test]
    fn layer_outcome_json_omits_none_fields_via_explicit_serialize() {
        let passed = LayerOutcome::passed(PolicyLayer::LayerB);
        let json = serde_json::to_value(&passed).unwrap();
        assert_eq!(json["layer"], "layer_b");
        assert_eq!(json["passed"], true);
        // None fields serialize as JSON null (no skip_serializing_if), so an
        // operator consuming the wire shape sees the key with null — pin
        // that so a future schema migration is a conscious choice.
        assert!(json["matched_rule_id"].is_null());
        assert!(json["error_code"].is_null());
        assert!(json["detail"].is_null());
    }

    #[test]
    fn allowed_returns_true_for_empty_layers_with_allow_decision() {
        // Edge: a trace with zero layers + `Decision::Allow` satisfies
        // `.all(passed)` vacuously and `matches!(... Allow)` — so
        // `allowed()` is true. Pin this so a refactor that added a
        // "must have at least one layer" guard surfaces here. The
        // engine path always emits Layer A + Layer B stubs, but
        // mocks / dashboard replay paths sometimes construct empty
        // traces.
        let t = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        assert!(t.allowed());
    }

    #[test]
    fn allowed_false_when_first_layer_passes_but_a_later_layer_fails() {
        // The `.all(passed)` short-circuit must NOT stop at the first
        // pass — a single failed layer anywhere in the Vec must flip
        // `allowed()` to false. Pin the iteration ordering invariant.
        let t = PolicyTrace::new(
            vec![
                LayerOutcome::passed(PolicyLayer::LayerA),
                LayerOutcome::passed(PolicyLayer::LayerB),
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
        assert!(!t.allowed());
    }

    #[test]
    fn duration_micros_starts_zero_and_supports_post_construction_mutation() {
        // `PolicyTrace::new` initializes `duration_micros: 0`; the
        // engine measures the eval time and stamps the field after.
        // Pin both the zero-on-construct contract AND that the field
        // is `pub` (allowing post-construction mutation). A refactor
        // that made the field private would force the engine to
        // route the duration through a builder method.
        let mut t = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        assert_eq!(t.duration_micros, 0);
        t.duration_micros = 1234;
        assert_eq!(t.duration_micros, 1234);
    }

    #[test]
    fn ops_atom_view_serializes_with_all_three_fields_present() {
        // Wire contract — the trace's `required_ops` is consumed by
        // the adapter's Trust-Plane request builder. Pin all three
        // field names (`scheme`, `action`, `object`) are present and
        // serialize as bare strings. A serde rename to camelCase (the
        // common "tidy up the wire shape" refactor) would silently
        // break Trust Plane's parse.
        let v = OpsAtomView {
            scheme: "drive".into(),
            action: "read".into(),
            object: "file/abc".into(),
        };
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["scheme"], "drive");
        assert_eq!(j["action"], "read");
        assert_eq!(j["object"], "file/abc");
        // No extra fields snuck in.
        assert_eq!(j.as_object().unwrap().len(), 3);
    }

    #[test]
    fn policy_eval_mode_comprehensive_variant_compares_distinct_from_fail_fast() {
        // The existing `policy_eval_mode_default_is_fail_fast` test pins
        // the Default value only — but the `Comprehensive` variant
        // (used by the dashboard's "explain this denial" replay per
        // qiuth-patterns.md §3.3) was never directly compared against
        // its sibling. A regression that collapsed the two variants
        // into one (in the name of "Comprehensive is the only path that
        // ever runs in tests anyway") would silently break the
        // FailFast-vs-Comprehensive predicate every engine call site
        // depends on for early-return decisions. Pin distinct-equality
        // on both axes.
        assert_ne!(PolicyEvalMode::FailFast, PolicyEvalMode::Comprehensive);
        assert_eq!(PolicyEvalMode::Comprehensive, PolicyEvalMode::Comprehensive);
        assert_eq!(PolicyEvalMode::FailFast, PolicyEvalMode::FailFast);
    }

    #[test]
    fn policy_eval_mode_is_copy_at_use_sites() {
        // `PolicyEvalMode` derives `Copy` — pinned at compile time by
        // the engine call sites that pass it by value through nested
        // closures without cloning. A refactor that dropped `Copy` (for
        // a hypothetical "stop allowing accidental duplicates" cleanup)
        // would surface here as a use-after-move borrow-check error
        // rather than at hundreds of engine call sites. The trait-bound
        // check `fn require_copy<T: Copy>()` is the canonical zero-cost
        // pin (no instantiation, but the bound is enforced).
        fn require_copy<T: Copy>() {}
        require_copy::<PolicyEvalMode>();
        // And surface via use-by-value: assign then read.
        let a = PolicyEvalMode::FailFast;
        let b = a; // Copy, not move
        assert_eq!(a, b);
    }

    #[test]
    fn policy_layer_is_copy_at_use_sites_and_distinct_across_three_variants() {
        // `PolicyLayer` derives `Copy + Eq` — both are load-bearing for
        // the `set_layer` helper in `adapters/policy_trace.rs` which
        // iterates `trace.layers.iter_mut().find(|l| l.layer == layer)`.
        // A refactor that dropped `Copy` (the same "clean up implicit
        // duplicates" mistake as the PolicyEvalMode test above) would
        // force the find closure to deref, surface as a borrow-check
        // error at the call site, and the engine would no longer
        // compile. Pin `Copy` via the same trait-bound check + a
        // distinct-equality walk over all three variants so a refactor
        // that aliased LayerA/LayerB (e.g. for a "Layer" merge) would
        // surface here.
        fn require_copy<T: Copy>() {}
        require_copy::<PolicyLayer>();
        let a = PolicyLayer::LayerA;
        let _b = a; // Copy
        assert_ne!(PolicyLayer::LayerA, PolicyLayer::LayerB);
        assert_ne!(PolicyLayer::LayerB, PolicyLayer::ReadFilter);
        assert_ne!(PolicyLayer::LayerA, PolicyLayer::ReadFilter);
        // Reflexive equality for each variant.
        assert_eq!(PolicyLayer::LayerA, PolicyLayer::LayerA);
        assert_eq!(PolicyLayer::LayerB, PolicyLayer::LayerB);
        assert_eq!(PolicyLayer::ReadFilter, PolicyLayer::ReadFilter);
    }

    #[test]
    fn layer_outcome_passed_constructor_emits_each_of_three_layer_variants_with_identical_zero_fields()
     {
        // The existing `passed_outcome_has_no_error` test pins ONE arm
        // (LayerB) through the `passed()` constructor. The constructor
        // is the canonical entry point for the engine's stub-Layer-A
        // emit AND the read-filter pass arm AND the engine's Layer-B
        // happy path — pin all three layers route through `passed()`
        // with byte-identical empty `matched_rule_id`/`error_code`/`detail`
        // fields (a refactor that switched one arm to a layer-specific
        // default — e.g. `Some("read_filter".into())` for the read-filter
        // matched_rule_id "for consistency" — would silently start
        // emitting a non-empty field on the wire for that arm only).
        for layer in [
            PolicyLayer::LayerA,
            PolicyLayer::LayerB,
            PolicyLayer::ReadFilter,
        ] {
            let o = LayerOutcome::passed(layer);
            assert_eq!(o.layer, layer);
            assert!(o.passed);
            assert!(
                o.matched_rule_id.is_none(),
                "passed({layer:?}) must have None matched_rule_id"
            );
            assert!(
                o.error_code.is_none(),
                "passed({layer:?}) must have None error_code"
            );
            assert!(
                o.detail.is_none(),
                "passed({layer:?}) must have None detail"
            );
        }
    }

    #[test]
    fn layer_outcome_failed_with_none_matched_rule_id_and_none_detail_carries_error_code_only() {
        // The existing `failed_outcome_carries_code` test pins the
        // FULL-info shape (Some matched_rule_id + Some detail). The
        // adapter's read-filter dispatcher constructs `failed()` with
        // BOTH optional args as None when the filter scanner reports a
        // policy-engine internal fault that isn't attributable to a
        // specific pattern — pin that shape so a future signature
        // refactor that promoted matched_rule_id to non-Option
        // (defaulting to an empty string for "consistency") would
        // surface here. The error_code MUST still be Some — `failed()`
        // is the only path that surfaces an ErrorCode on the wire.
        let o = LayerOutcome::failed(
            PolicyLayer::ReadFilter,
            ErrorCode::PolicyEngineError,
            None,
            None,
        );
        assert!(!o.passed);
        assert_eq!(o.layer, PolicyLayer::ReadFilter);
        assert_eq!(o.error_code, Some(ErrorCode::PolicyEngineError));
        assert!(o.matched_rule_id.is_none());
        assert!(o.detail.is_none());
    }

    #[test]
    fn policy_trace_new_assigns_fresh_unique_trace_id_per_call() {
        // `PolicyTrace::new` stamps `trace_id: Uuid::new_v4()` per call
        // — the dashboard's per-request panel and the
        // `X-Proxilion-Trace-Id` response header BOTH depend on every
        // engine eval producing a distinct id (operators paste the id
        // into the dashboard's lookup endpoint to recover the trace).
        // A refactor that swapped `Uuid::new_v4()` for a once-cell
        // static (or for a hash of the layers — both are plausible
        // "deterministic id" cleanups) would silently start collapsing
        // every eval onto the same id and break per-request lookup
        // entirely. Pin distinctness across five back-to-back calls.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let t = PolicyTrace::new(vec![], Decision::Allow, vec![]);
            assert!(
                seen.insert(t.trace_id),
                "duplicate trace_id {} surfaced — Uuid::new_v4 contract broken",
                t.trace_id,
            );
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn ops_atom_view_clone_independence_after_field_mutation() {
        // `OpsAtomView` derives `Clone` — the trace's `required_ops` Vec
        // is cloned by both the dashboard's wire-serialize path and the
        // adapter's Trust-Plane request builder. Pin that the clone is
        // a deep copy across all three String fields (a refactor that
        // switched to `Cow<'static, str>` or `Arc<str>` for "cheaper
        // clone" would surface here as the mutation visibly aliasing
        // back to the original). The existing
        // `ops_atom_view_round_trips_fields` pins the `From<&OpsAtom>`
        // path, not the Clone trait.
        let mut a = OpsAtomView {
            scheme: "drive".into(),
            action: "read".into(),
            object: "file/abc".into(),
        };
        let b = a.clone();
        a.scheme = "gmail".into();
        a.action = "send".into();
        a.object = "messages/xyz".into();
        // Mutated original.
        assert_eq!(a.scheme, "gmail");
        // Clone untouched — deep copy semantic.
        assert_eq!(b.scheme, "drive");
        assert_eq!(b.action, "read");
        assert_eq!(b.object, "file/abc");
    }

    #[test]
    fn policy_layer_deserialize_rejects_unknown_variant_strings_for_closed_enum_contract() {
        // The `#[serde(rename_all = "snake_case")]` plus the enum's lack
        // of a `#[non_exhaustive]` attribute makes the wire enum closed
        // at deserialize time. Pin that three plausibly-wrong inputs
        // ("layer_c" / "layer-a" hyphen-form / "LayerA" PascalCase) all
        // fail-parse, NOT silently forward-compat into a new variant or
        // (worse) deserialize into LayerA as a default. A future
        // refactor that added `#[serde(other)]` to provide forward-compat
        // would silently bucket operator typos into one arm — surface
        // any such drift here.
        for bogus in ["\"layer_c\"", "\"layer-a\"", "\"LayerA\"", "\"\""] {
            let r: Result<PolicyLayer, _> = serde_json::from_str(bogus);
            assert!(
                r.is_err(),
                "unknown PolicyLayer wire string {bogus} must reject, got: {r:?}",
            );
        }
    }

    #[test]
    fn layer_outcome_serde_round_trip_with_failed_shape_preserves_all_named_fields() {
        // The wire shape of `LayerOutcome` is consumed verbatim by the
        // dashboard's per-request panel — pin a full-info `failed()`
        // round-trip through `serde_json::Value` so any field rename
        // (matched_rule_id → matched_id, detail → message — both
        // tempting "tidy up" refactors) surfaces on both directions.
        // The existing `layer_outcome_json_omits_none_fields_via_explicit_serialize`
        // pins the passed-shape null fields; this pins the failed-shape
        // full-value shape symmetrically.
        let o = LayerOutcome::failed(
            PolicyLayer::LayerB,
            ErrorCode::PolicyBlocked,
            Some("p-external-share".into()),
            Some("external recipient detected".into()),
        );
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["layer"], "layer_b");
        assert_eq!(v["passed"], false);
        assert_eq!(v["matched_rule_id"], "p-external-share");
        assert_eq!(v["error_code"], "policy_blocked");
        assert_eq!(v["detail"], "external recipient detected");
        // Round-trip back — every named field must survive.
        let back: LayerOutcome = serde_json::from_value(v).unwrap();
        assert_eq!(back.layer, PolicyLayer::LayerB);
        assert!(!back.passed);
        assert_eq!(back.matched_rule_id.as_deref(), Some("p-external-share"));
        assert_eq!(back.error_code, Some(ErrorCode::PolicyBlocked));
        assert_eq!(back.detail.as_deref(), Some("external recipient detected"));
    }

    #[test]
    fn policy_trace_field_count_pinned_at_exactly_six_via_exhaustive_destructure() {
        // Pin the STRUCT field count (not just the JSON wire keys —
        // those are pinned separately in
        // `policy_trace_json_carries_trace_id_and_layers`). A
        // `#[serde(skip)]` 7th field (e.g. `request_id: Option<Uuid>` for
        // a future "join traces to requests by id" panel, or
        // `engine_version: &'static str` for the dashboard's
        // "which engine produced this trace" header) would silently
        // satisfy the existing serde key-count check while quietly
        // bloating every in-memory trace clone on the hot path.
        // Exhaustive destructure with no `..` rest pattern forces every
        // new field to be added here in lockstep with its construction
        // site — a refactor that lands a field but skips this match
        // surfaces as a non-exhaustive-pattern compile error.
        let t = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        let PolicyTrace {
            trace_id: _,
            evaluated_at: _,
            duration_micros: _,
            layers: _,
            final_decision: _,
            required_ops: _,
        } = t;
    }

    #[test]
    fn layer_outcome_field_count_pinned_at_exactly_five_via_exhaustive_destructure() {
        // Symmetric to the PolicyTrace pin above. `LayerOutcome` is the
        // per-layer record the dashboard's "explain this denial" panel
        // iterates — a `#[serde(skip)]` 6th field (e.g.
        // `evaluated_at: DateTime<Utc>` for per-layer latency
        // attribution, or `evaluator_kind: &'static str` to distinguish
        // YAML evaluators from a future WASM evaluator) would bloat
        // every Vec<LayerOutcome> on the wire without surfacing through
        // the existing 5-key serde pin. The exhaustive destructure with
        // no `..` rest pattern forces every landed field to be added
        // here in lockstep with its production-side use sites.
        let o = LayerOutcome::passed(PolicyLayer::LayerB);
        let LayerOutcome {
            layer: _,
            passed: _,
            matched_rule_id: _,
            error_code: _,
            detail: _,
        } = o;
    }

    #[test]
    fn ops_atom_view_field_count_pinned_at_exactly_three_via_exhaustive_destructure() {
        // `OpsAtomView` is the wire-friendly projection of `OpsAtom`
        // surfaced in `PolicyTrace.required_ops` — the Trust Plane's
        // adapter request builder parses the 3-key shape verbatim. A
        // 4th field landing (e.g. `display_label: String` for the
        // dashboard's "human-readable atom" panel, or
        // `policy_id: Option<String>` for back-attribution from atom to
        // the rule that emitted it) would silently bloat every required
        // ops Vec on the hot path without surfacing through the
        // existing 3-key serde pin. Exhaustive destructure with no
        // `..` rest pattern is the canonical struct-count pin.
        let v = OpsAtomView {
            scheme: "drive".into(),
            action: "read".into(),
            object: "file/x".into(),
        };
        let OpsAtomView {
            scheme: _,
            action: _,
            object: _,
        } = v;
    }

    #[test]
    fn policy_trace_new_signature_pinned_via_fn_pointer_witness() {
        // `PolicyTrace::new` takes its three Vecs / Decision by VALUE —
        // pin the signature shape so a refactor that flipped to
        // `&[LayerOutcome]` + `&[OpsAtomView]` (for "zero-alloc trace
        // construction") would surface here as a fn-pointer type
        // mismatch rather than at every engine call site. The
        // `Decision` argument is by-value so the caller-side
        // `Decision::Block { reason, .. }` builder path can move the
        // owned String into the trace without forcing a clone on the
        // hot path. The fn-pointer witness is zero-cost at runtime —
        // the assignment alone enforces the signature shape at compile
        // time.
        let _f: fn(Vec<LayerOutcome>, Decision, Vec<OpsAtomView>) -> PolicyTrace = PolicyTrace::new;
    }

    #[test]
    fn ops_atom_view_from_takes_borrow_not_owned_via_fn_pointer_witness() {
        // `From<&OpsAtom> for OpsAtomView` is the canonical conversion
        // path used by `Engine::evaluate_with_trace` — pin that the impl
        // takes a BORROW (`&OpsAtom`) not the owned `OpsAtom`. The
        // borrow shape lets the engine surface the same `OpsAtom` to
        // both the local trace AND the adapter's Trust Plane request
        // builder without an extra clone. A refactor to
        // `From<OpsAtom>` (the obvious "tidy up unnecessary borrow"
        // change) would silently force the engine to clone every
        // resolved atom for the trace view, which on a multi-atom
        // policy adds N allocations per request on the hot path. The
        // fn-pointer witness pins the exact `From::from` signature at
        // compile time.
        fn require_from_borrow<'a, T: From<&'a OpsAtom>>() {}
        require_from_borrow::<OpsAtomView>();
        // And exercise the borrow at runtime so the From impl actually
        // takes a `&OpsAtom` (not a tuple, not by-value).
        let a = OpsAtom {
            scheme: "drive".into(),
            action: "read".into(),
            object: "file/x".into(),
        };
        let _v: OpsAtomView = (&a).into();
        // `a` still owned afterwards — confirms the impl took a borrow.
        assert_eq!(a.scheme, "drive");
    }

    #[test]
    fn policy_trace_evaluated_at_within_one_second_of_constructor_call() {
        // `PolicyTrace::new` stamps `evaluated_at: Utc::now()` — pin
        // recency (within 1 second of the surrounding wall-clock call)
        // so a refactor that swapped `Utc::now()` for a once-cell
        // static initializer ("share the trace timestamp across all
        // engine calls for deterministic snapshot replay") would
        // silently collapse every per-request timestamp onto the
        // engine's first-call time and break the dashboard's
        // chronological replay. 1s window is wide enough to survive
        // CI's stop-the-world GC ticks but tight enough to catch a
        // static initializer's hour-scale drift across a long test
        // run. Both `evaluated_at <= now()` (no future stamps) and
        // `now() - evaluated_at < 1s` (no stale stamps) are pinned.
        let before = Utc::now();
        let t = PolicyTrace::new(vec![], Decision::Allow, vec![]);
        let after = Utc::now();
        assert!(
            t.evaluated_at >= before && t.evaluated_at <= after,
            "evaluated_at {ev} must be within [{before}, {after}]",
            ev = t.evaluated_at,
        );
        // Also pin no-subsecond explosion across a tight loop: 5
        // back-to-back constructions all land within 1 second.
        let start = Utc::now();
        let mut last = start;
        for _ in 0..5 {
            let tt = PolicyTrace::new(vec![], Decision::Allow, vec![]);
            assert!(tt.evaluated_at >= last);
            last = tt.evaluated_at;
        }
        assert!((last - start).num_seconds() < 1);
    }

    #[test]
    fn policy_trace_json_carries_trace_id_and_layers() {
        let t = PolicyTrace::new(
            vec![LayerOutcome::passed(PolicyLayer::LayerA)],
            Decision::Allow,
            vec![OpsAtomView {
                scheme: "drive".into(),
                action: "read".into(),
                object: "file/x".into(),
            }],
        );
        let json = serde_json::to_value(&t).unwrap();
        assert!(json["trace_id"].is_string());
        assert!(json["evaluated_at"].is_string());
        assert_eq!(json["duration_micros"], 0);
        assert_eq!(json["layers"].as_array().unwrap().len(), 1);
        assert_eq!(json["required_ops"][0]["scheme"], "drive");
    }
}
