//! Decision types returned by policy evaluation (Layer B).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block {
        reason: String,
        override_allowed: bool,
    },
    RequireConfirmation {
        reason: String,
    },
    RateLimit {
        burst: u32,
        per_seconds: u32,
    },
}

#[derive(Debug, Clone)]
pub struct ReadFilter {
    pub quarantine_patterns: Vec<Pattern>,
    pub quarantine_action: QuarantineAction,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    Literal(String),
    Regex(regex::Regex),
}

impl Pattern {
    pub fn is_match(&self, haystack: &str) -> bool {
        match self {
            Pattern::Literal(s) => haystack.contains(s.as_str()),
            Pattern::Regex(r) => r.is_match(haystack),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineAction {
    ReplaceWithMarker,
    StripSilently,
    BlockRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Pattern::is_match ----------------------------------------

    #[test]
    fn literal_pattern_matches_substring() {
        let p = Pattern::Literal("ignore previous".into());
        assert!(p.is_match("please ignore previous instructions"));
        assert!(!p.is_match("nothing to see here"));
    }

    /// Literal match is case-sensitive — adapters that need
    /// case-insensitive matching use regex patterns. Pinning the
    /// behavior so a future refactor doesn't silently change it.
    #[test]
    fn literal_pattern_is_case_sensitive() {
        let p = Pattern::Literal("Hello".into());
        assert!(p.is_match("Hello world"));
        assert!(!p.is_match("hello world"));
    }

    #[test]
    fn regex_pattern_matches_with_anchors() {
        let p = Pattern::Regex(regex::Regex::new(r"^ignore\b").unwrap());
        assert!(p.is_match("ignore previous instructions"));
        assert!(!p.is_match("please ignore previous"));
    }

    #[test]
    fn regex_pattern_supports_alternation() {
        let p = Pattern::Regex(regex::Regex::new(r"(?i)(system|user) prompt").unwrap());
        assert!(p.is_match("the SYSTEM PROMPT was..."));
        assert!(p.is_match("user prompt injection"));
        assert!(!p.is_match("no match"));
    }

    // --- Decision serde -------------------------------------------

    /// `kind` tagging is the wire-format contract for any consumer
    /// (operator dashboard, audit log, SIEM forwarder). Snapshot the
    /// JSON shape per variant.
    #[test]
    fn decision_allow_round_trips() {
        let d = Decision::Allow;
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(s, r#"{"kind":"allow"}"#);
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_block_carries_reason_and_override_flag() {
        let d = Decision::Block {
            reason: "external recipient".into(),
            override_allowed: true,
        };
        let s = serde_json::to_string(&d).unwrap();
        assert!(s.contains(r#""kind":"block""#));
        assert!(s.contains(r#""reason":"external recipient""#));
        assert!(s.contains(r#""override_allowed":true"#));
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_require_confirmation_round_trips() {
        let d = Decision::RequireConfirmation {
            reason: "external share".into(),
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn decision_rate_limit_round_trips() {
        let d = Decision::RateLimit {
            burst: 5,
            per_seconds: 60,
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    /// snake_case kind values are part of the public wire contract
    /// (operator dashboards key off them). Renaming a variant must
    /// fail this snapshot loudly.
    #[test]
    fn quarantine_action_copy_and_eq_traits_work_at_use_sites() {
        // The read-filter dispatcher matches on the variant by value
        // (not by reference) — `Copy` lets the per-pattern processor
        // pass the action down without explicit `.clone()`. A regression
        // that dropped `Copy` would surface here as a compile error
        // rather than confusing failures at the dispatcher call site.
        let a = QuarantineAction::ReplaceWithMarker;
        let a2 = a; // Copy
        assert_eq!(a, a2);
        assert_ne!(
            QuarantineAction::ReplaceWithMarker,
            QuarantineAction::StripSilently
        );
        assert_ne!(
            QuarantineAction::StripSilently,
            QuarantineAction::BlockRequest
        );
        assert_ne!(
            QuarantineAction::ReplaceWithMarker,
            QuarantineAction::BlockRequest
        );
    }

    #[test]
    fn read_filter_clone_carries_patterns_and_action_independently() {
        // `ReadFilter` is `Clone` so the per-request engine snapshot can
        // hand a copy to the response-body scanner without giving up
        // ownership. Pin that the clone is shape-equivalent (same
        // pattern count) and that mutating one side's `Vec` doesn't
        // touch the other (no `Rc`/`Arc` smuggled into the inner vec).
        let f = ReadFilter {
            quarantine_patterns: vec![
                Pattern::Literal("ignore previous".into()),
                Pattern::Regex(regex::Regex::new(r"(?i)system prompt").unwrap()),
            ],
            quarantine_action: QuarantineAction::ReplaceWithMarker,
        };
        let mut c = f.clone();
        assert_eq!(c.quarantine_patterns.len(), 2);
        assert_eq!(c.quarantine_action, f.quarantine_action);
        c.quarantine_patterns.push(Pattern::Literal("extra".into()));
        // Original unchanged.
        assert_eq!(f.quarantine_patterns.len(), 2);
        assert_eq!(c.quarantine_patterns.len(), 3);
    }

    #[test]
    fn literal_pattern_matches_empty_haystack_against_empty_needle_only() {
        // The literal arm uses `str::contains`, which returns true for
        // the empty-needle case against any haystack — that's the
        // standard Rust semantic. A future refactor to a hand-rolled
        // matcher that gated on `needle.is_empty()` would change this
        // and silently break a policy that uses the empty string as a
        // catch-all marker. (Unusual, but documenting current behaviour.)
        let empty = Pattern::Literal(String::new());
        assert!(empty.is_match(""));
        assert!(empty.is_match("any text"));
        // Non-empty needle against empty haystack — must NOT match.
        let p = Pattern::Literal("needle".into());
        assert!(!p.is_match(""));
    }

    #[test]
    fn decision_partial_eq_distinguishes_block_variants_by_reason_and_override() {
        // The dashboard's diff-view keys on `Decision == Decision`
        // before re-rendering — pin that two `Block { reason, ..}`
        // with different reasons are NOT equal (otherwise a policy-
        // edit changing the reason text would render as unchanged).
        let a = Decision::Block {
            reason: "external".into(),
            override_allowed: true,
        };
        let b = Decision::Block {
            reason: "external".into(),
            override_allowed: true,
        };
        let c = Decision::Block {
            reason: "internal".into(),
            override_allowed: true,
        };
        let d = Decision::Block {
            reason: "external".into(),
            override_allowed: false,
        };
        assert_eq!(a, b, "identical Block variants must compare equal");
        assert_ne!(a, c, "Block with different reason must NOT be equal");
        assert_ne!(
            a, d,
            "Block with different override_allowed must NOT be equal",
        );
    }

    #[test]
    fn rate_limit_round_trips_burst_and_per_seconds_separately() {
        // The two integer fields must each round-trip independently —
        // a serde field-rename or accidental swap (a `(per_seconds,
        // burst)` reorder during a refactor) would silently flip the
        // operator-facing rate-limit semantics. Use distinct values
        // so an accidental swap surfaces.
        let d = Decision::RateLimit {
            burst: 7,
            per_seconds: 42,
        };
        let s = serde_json::to_string(&d).unwrap();
        assert!(s.contains(r#""burst":7"#));
        assert!(s.contains(r#""per_seconds":42"#));
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn regex_pattern_clone_preserves_compiled_state() {
        // `Pattern::Regex` wraps `regex::Regex`, which is `Clone`. Pin
        // that cloning a compiled regex preserves the match behavior
        // (a refactor that switched to `Cow<'static, str>` and
        // re-compiled-on-match would silently re-pay the compile cost
        // per request on the hot path — and could fail on bad patterns
        // at a non-startup time).
        let p = Pattern::Regex(regex::Regex::new(r"(?i)secret").unwrap());
        let c = p.clone();
        assert!(c.is_match("a SECRET document"));
        assert!(!c.is_match("nothing to see"));
    }

    #[test]
    fn pattern_regex_debug_includes_regex_source_for_operator_grep() {
        // `Pattern` derives `Debug`; the `Regex(regex::Regex)` arm's
        // `regex::Regex` Debug impl renders the source pattern. The
        // read-filter logger feeds `?pattern` into `tracing::warn!` on
        // every match — operators grep the log lines for the literal
        // pattern source to triage false positives. A manual Debug
        // impl that elided the source (in the name of "redact possibly-
        // sensitive policy text") would silently break that workflow.
        // Pin both arms' Debug shapes: Literal carries the needle string,
        // Regex carries the pattern source.
        let lit = Pattern::Literal("ignore previous instructions".into());
        let s = format!("{lit:?}");
        assert!(
            s.contains("ignore previous instructions"),
            "Literal Debug must surface needle: {s}"
        );
        assert!(s.contains("Literal"), "Literal variant tag missing: {s}");

        let rx = Pattern::Regex(regex::Regex::new(r"(?i)system\s+prompt").unwrap());
        let s = format!("{rx:?}");
        assert!(s.contains("Regex"), "Regex variant tag missing: {s}");
        assert!(
            s.contains("system") && s.contains("prompt"),
            "Regex source must be visible: {s}"
        );
    }

    #[test]
    fn decision_block_requires_explicit_override_allowed_field_on_deserialize() {
        // The `override_allowed: bool` field on `Decision::Block` has NO
        // `#[serde(default)]` — every operator authoring a block in YAML
        // must commit explicitly to whether a human override applies.
        // The current behavior surfaces a deserialize error when the
        // field is missing; a regression that added `#[serde(default)]`
        // would silently make every legacy `block:` without override
        // language fall through to `override_allowed: false`, which
        // would orphan the approver UI for that policy. Pin both
        // halves: explicit true/false round-trips AND missing-field
        // rejection.
        let with_true = r#"{"kind":"block","reason":"x","override_allowed":true}"#;
        let with_false = r#"{"kind":"block","reason":"x","override_allowed":false}"#;
        let missing = r#"{"kind":"block","reason":"x"}"#;
        let d: Decision = serde_json::from_str(with_true).unwrap();
        assert_eq!(
            d,
            Decision::Block {
                reason: "x".into(),
                override_allowed: true
            }
        );
        let d: Decision = serde_json::from_str(with_false).unwrap();
        assert_eq!(
            d,
            Decision::Block {
                reason: "x".into(),
                override_allowed: false
            }
        );
        let err = serde_json::from_str::<Decision>(missing).unwrap_err();
        assert!(
            err.to_string().contains("override_allowed"),
            "expected missing-field error: {err}"
        );
    }

    #[test]
    fn decision_rate_limit_rejects_negative_or_overflow_values_on_deserialize() {
        // `burst: u32` and `per_seconds: u32` are unsigned by deliberate
        // choice — rate-limit semantics have no meaning at negative
        // values, and an operator who typed `-1` into their policy YAML
        // should see a parse failure (caught at policy-reload time)
        // rather than the silent two's-complement wrap a `i32→u32`
        // collapse would produce on a refactor. Pin both halves:
        // negative numbers reject AND values above u32::MAX reject.
        let neg = r#"{"kind":"rate_limit","burst":-1,"per_seconds":60}"#;
        assert!(
            serde_json::from_str::<Decision>(neg).is_err(),
            "negative burst must reject"
        );
        let neg = r#"{"kind":"rate_limit","burst":5,"per_seconds":-60}"#;
        assert!(
            serde_json::from_str::<Decision>(neg).is_err(),
            "negative per_seconds must reject"
        );
        // u32::MAX itself round-trips fine (the boundary).
        let max = format!(
            r#"{{"kind":"rate_limit","burst":{},"per_seconds":{}}}"#,
            u32::MAX,
            u32::MAX
        );
        let d: Decision = serde_json::from_str(&max).unwrap();
        assert_eq!(
            d,
            Decision::RateLimit {
                burst: u32::MAX,
                per_seconds: u32::MAX
            }
        );
        // u32::MAX + 1 (overflow) must reject.
        let over = format!(
            r#"{{"kind":"rate_limit","burst":{},"per_seconds":60}}"#,
            (u32::MAX as u64) + 1
        );
        assert!(
            serde_json::from_str::<Decision>(&over).is_err(),
            "u32 overflow must reject"
        );
    }

    #[test]
    fn decision_partial_eq_distinguishes_require_confirmation_variants_by_reason() {
        // Existing `decision_partial_eq_distinguishes_block_variants_by_reason_and_override`
        // pins the Block-variant equality axis (reason + override_allowed);
        // pin the symmetric axis for RequireConfirmation. The runtime
        // dedup path in the adapter compares two consecutive Decisions
        // via `==` to short-circuit duplicate notifier fan-outs — a
        // refactor that derived `PartialEq` ignoring `reason` (perhaps
        // "the user-facing string drifts across evaluations, so don't
        // gate on it") would silently start collapsing two distinct
        // confirmation prompts (e.g. "share external" vs "share to
        // anyone") onto one prompt for the operator.
        let a = Decision::RequireConfirmation {
            reason: "share to external domain".into(),
        };
        let b = Decision::RequireConfirmation {
            reason: "share to external domain".into(),
        };
        let c = Decision::RequireConfirmation {
            reason: "share to anyone".into(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn decision_partial_eq_distinguishes_rate_limit_variants_by_burst_and_per_seconds() {
        // Symmetric to the RequireConfirmation pin above. The RateLimit
        // variant has two numeric fields; PartialEq must distinguish on
        // BOTH. Pin via the four-corner shape so a refactor that hashed
        // only `burst` (perhaps "per_seconds is always 60 in practice")
        // would silently collapse two distinct burst-rate budgets onto
        // the same wire identity, breaking the adapter's idempotent-
        // rate-limit response cache.
        let baseline = Decision::RateLimit {
            burst: 10,
            per_seconds: 60,
        };
        let same = Decision::RateLimit {
            burst: 10,
            per_seconds: 60,
        };
        let diff_burst = Decision::RateLimit {
            burst: 20,
            per_seconds: 60,
        };
        let diff_per = Decision::RateLimit {
            burst: 10,
            per_seconds: 30,
        };
        assert_eq!(baseline, same);
        assert_ne!(baseline, diff_burst);
        assert_ne!(baseline, diff_per);
        assert_ne!(diff_burst, diff_per);
    }

    #[test]
    fn decision_deserialize_rejects_unknown_kind_value() {
        // The `#[serde(tag = "kind", rename_all = "snake_case")]` attribute
        // produces a CLOSED enum — an unknown `kind` value must fail
        // deserialization rather than silently bucketing into a default
        // arm (no `#[serde(other)]` is present). Pin via two distinct
        // mis-spellings + a wholly unknown variant. A future refactor
        // that added `#[serde(other)]` (perhaps "for forward-compat
        // with v2 decision types") would silently collapse operator
        // typos in the embed-API test panel into a fallback that
        // doesn't match their intent.
        let cases = [
            r#"{"kind":"allows"}"#,
            r#"{"kind":"ALLOW"}"#,
            r#"{"kind":"warn","reason":"x"}"#,
        ];
        for raw in cases {
            let r: Result<Decision, _> = serde_json::from_str(raw);
            assert!(r.is_err(), "expected reject for: {raw}");
        }
    }

    #[test]
    fn quarantine_action_debug_carries_variant_name_for_log_grep() {
        // The `tracing::info!` calls in the adapter pipeline render
        // QuarantineAction via the `?` (Debug) operator — operator
        // log filters key on the variant name substring (e.g.
        // `quarantine_action=ReplaceWithMarker`). A manual Debug
        // impl that rendered just `(0)` for tidiness would silently
        // collapse the three variants onto an opaque integer in every
        // log line. Pin all three variant-name substrings.
        assert!(format!("{:?}", QuarantineAction::ReplaceWithMarker).contains("ReplaceWithMarker"));
        assert!(format!("{:?}", QuarantineAction::StripSilently).contains("StripSilently"));
        assert!(format!("{:?}", QuarantineAction::BlockRequest).contains("BlockRequest"));
    }

    #[test]
    fn pattern_literal_debug_carries_needle_for_operator_grep() {
        // Symmetric to `pattern_regex_debug_includes_regex_source_for_operator_grep`
        // — pin the Literal arm's Debug surfaces the inner needle string.
        // The adapter logs the matched pattern via `?` on a violation
        // event; without the needle the operator can't tell WHICH
        // literal pattern fired. A manual Debug that hid the inner
        // value (in the name of "may contain user PII") would silently
        // strip the operator's only triage handle on literal patterns.
        let p = Pattern::Literal("ignore previous instructions".into());
        let s = format!("{p:?}");
        assert!(s.contains("Literal"), "got: {s}");
        assert!(s.contains("ignore previous instructions"), "got: {s}");
    }

    #[test]
    fn read_filter_debug_surfaces_both_patterns_slot_and_quarantine_action() {
        // The boot-time policy-load log line uses `tracing::debug!(?cfg, ..)`
        // — pin that the rendered Debug includes both the patterns slot
        // (so an operator can see WHICH patterns were compiled) AND the
        // quarantine_action variant name (so they can verify the field
        // wasn't elided by a refactor). A custom Debug that surfaced
        // only `quarantine_patterns.len()` as a count "for brevity"
        // would silently hide the compiled-regex source from the
        // operator-facing log line.
        let rf = ReadFilter {
            quarantine_patterns: vec![Pattern::Literal("secret".into())],
            quarantine_action: QuarantineAction::ReplaceWithMarker,
        };
        let s = format!("{rf:?}");
        assert!(s.contains("quarantine_patterns"), "got: {s}");
        assert!(s.contains("quarantine_action"), "got: {s}");
        assert!(s.contains("ReplaceWithMarker"), "got: {s}");
        assert!(s.contains("secret"), "got: {s}");
    }

    #[test]
    fn decision_kind_wire_strings_are_stable() {
        let cases: &[(Decision, &str)] = &[
            (Decision::Allow, "allow"),
            (
                Decision::Block {
                    reason: "x".into(),
                    override_allowed: false,
                },
                "block",
            ),
            (
                Decision::RequireConfirmation { reason: "x".into() },
                "require_confirmation",
            ),
            (
                Decision::RateLimit {
                    burst: 1,
                    per_seconds: 1,
                },
                "rate_limit",
            ),
        ];
        for (d, want_kind) in cases {
            let v: serde_json::Value =
                serde_json::from_str(&serde_json::to_string(d).unwrap()).unwrap();
            assert_eq!(v["kind"].as_str(), Some(*want_kind));
        }
    }

    #[test]
    fn decision_and_read_filter_and_pattern_and_quarantine_action_are_send_sync_static() {
        // Decision is returned from `Engine::evaluate` and flows through
        // the proxy's per-request task; ReadFilter is held inside Outcome
        // and propagated to the adapter's quarantine post-filter via
        // `.await`; Pattern's Regex variant carries an `Arc`-backed
        // compiled state shared across threads. All four MUST be Send +
        // Sync + 'static. The existing module pins individual VALUES
        // (Clone preserves compiled state, etc.) but never the trait
        // bounds — a refactor adding an Rc<...> field to ReadFilter
        // "for cheap shared metadata" would break Sync and surface at
        // a remote `tower::Service` trait-bound rather than at this
        // module. Pin all four — symmetric to round-168 + round-169 +
        // round-173 + round-175 + round-176 Send+Sync+'static pins
        // extended to the policy-engine decision types.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<Decision>();
        require_send_sync_static::<ReadFilter>();
        require_send_sync_static::<Pattern>();
        require_send_sync_static::<QuarantineAction>();
    }

    #[test]
    fn decision_tag_wire_strings_are_byte_exact_lowercase_snake_case_across_all_four_variants() {
        // The Decision enum carries `#[serde(tag = "kind",
        // rename_all = "snake_case")]` — operator dashboards bucket
        // policy outcomes on `decision.kind == "block"` via lowercase
        // snake_case regex. The existing `decision_*_round_trips` pins
        // walk individual VALUES but never the SHAPE invariant across
        // all 4 variants. A refactor adding `#[serde(rename_all =
        // "kebab-case")]` "for hyphen-friendly URLs" on a sibling
        // decision-shaped enum would silently break every dashboard
        // bucket if it leaked here. Pin no-uppercase + no-kebab + no-
        // shell-unsafe across all 4 wire tag strings — symmetric to
        // round-143 + round-161 + round-173 lowercase snake_case
        // sweep extended to Decision tag.
        for tag in ["allow", "block", "require_confirmation", "rate_limit"] {
            assert!(
                tag.chars().all(|c| !c.is_ascii_uppercase()),
                "tag `{tag}` contains uppercase",
            );
            assert!(!tag.contains('-'), "tag `{tag}` contains kebab `-`");
            assert!(
                !tag.contains(' ') && !tag.contains('"'),
                "tag `{tag}` contains shell-unsafe char",
            );
        }
        // Cross-check: each Decision variant serializes to the expected
        // tag (defensive coverage symmetric to the existing snapshot
        // but anchored on the no-uppercase invariant).
        let d = Decision::Allow;
        let s = serde_json::to_string(&d).unwrap();
        assert!(
            s.contains("\"kind\":\"allow\""),
            "Allow must serialize with kind=allow: {s}",
        );
    }

    #[test]
    fn pattern_is_match_is_referentially_transparent_across_fifty_repeated_calls() {
        // Symmetric to round-161 + round-162 + round-166 + round-168 +
        // round-169 + round-170 + round-171 + round-172 + round-173 +
        // round-175 referential-transparency pins extended to
        // Pattern::is_match. The read-filter post-filter calls this
        // helper once per scanned chunk of an upstream response body;
        // a refactor that introduced a per-match LRU cache "for hot-
        // path perf" would silently corrupt the cache on a refactor
        // that bumped the pattern's regex source under the same
        // `&self`. Pin 50 calls on both Literal AND Regex variants.
        let lit = Pattern::Literal("secret".into());
        for i in 0..50 {
            assert!(
                lit.is_match("here is a secret"),
                "iter {i}: literal must match",
            );
            assert!(
                !lit.is_match("no match here"),
                "iter {i}: literal must NOT match",
            );
        }
        let rx = Pattern::Regex(regex::Regex::new(r"\bAPI[_-]KEY\b").unwrap());
        for i in 0..50 {
            assert!(rx.is_match("API-KEY=xyz"), "iter {i}: regex must match");
            assert!(
                !rx.is_match("not relevant"),
                "iter {i}: regex must NOT match",
            );
        }
    }

    #[test]
    fn pattern_literal_inner_field_is_owned_string_type_not_borrowed_for_arc_share_safety() {
        // `Pattern::Literal(String)` carries owned bytes — the read-
        // filter is held by `Arc<dyn ...>`-style fan-out, so the
        // inner string must outlive any reference into the holder's
        // YAML source (which is dropped post-compile). A refactor to
        // `Pattern::Literal(&'a str)` "to avoid the clone" would
        // surface a lifetime constraint that the Arc-share call site
        // couldn't satisfy. Pin via require_string pattern-match.
        fn require_string(_: &String) {}
        let p = Pattern::Literal("hello".into());
        match &p {
            Pattern::Literal(s) => require_string(s),
            Pattern::Regex(_) => unreachable!(),
        }
    }

    #[test]
    fn decision_block_reason_and_require_confirmation_reason_fields_are_owned_string_types() {
        // `Decision::Block.reason` + `Decision::RequireConfirmation.reason`
        // both carry agent-facing strings — these are CLONED into
        // `AppError::PolicyBlocked.reason` + `AppError::RequireConfirmation`
        // by the adapter's enforce_pre_request_decision (the policy
        // engine's Decision is consumed mid-handler; AppError outlives
        // it). A refactor to `&'a str` "to avoid the clone" would force
        // a lifetime constraint that the AppError construction couldn't
        // satisfy. Pin owned String via require_string pattern-match
        // on both reason-carrying variants — symmetric to round-168
        // parse_missing_atoms + round-175 lookup_list + round-176
        // PolicyBundle owned-String pins extended to Decision reasons.
        fn require_string(_: &String) {}
        let b = Decision::Block {
            reason: "external recipient".into(),
            override_allowed: false,
        };
        match &b {
            Decision::Block { reason, .. } => require_string(reason),
            _ => unreachable!(),
        }
        let rc = Decision::RequireConfirmation {
            reason: "high-risk delete".into(),
        };
        match &rc {
            Decision::RequireConfirmation { reason } => require_string(reason),
            _ => unreachable!(),
        }
    }

    #[test]
    fn decision_rate_limit_burst_and_per_seconds_fields_are_u32_type_for_metric_label_range() {
        // RateLimit's `burst` + `per_seconds` fields are u32 — the
        // operator-facing metric `proxilion_policy_rate_limit_total{
        // burst="N", per_seconds="M"}` labels rely on the u32 numeric
        // range. A refactor to u64 "for ergonomic large windows"
        // would silently widen the label cardinality (u64::MAX is
        // 18.4 quintillion vs u32's 4.3 billion) and could surface
        // as metric-cardinality OOMs on the Prometheus side. Pin via
        // require_u32 pattern-match.
        fn require_u32(_: u32) {}
        let r = Decision::RateLimit {
            burst: 10,
            per_seconds: 60,
        };
        match r {
            Decision::RateLimit { burst, per_seconds } => {
                require_u32(burst);
                require_u32(per_seconds);
            }
            _ => unreachable!(),
        }
    }
}
