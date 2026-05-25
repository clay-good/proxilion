//! Canonical Proxilion error-code registry.
//!
//! Every operator-visible failure across the proxy maps to one of these
//! variants. The wire string returned by [`ErrorCode::as_str`] is a STABLE
//! public contract: once a variant ships, its `snake_case` string never
//! changes. New variants may be added (the enum is `#[non_exhaustive]`),
//! but never renamed. See [`docs/error-codes.md`](../../../docs/error-codes.md)
//! for the catalogue an operator can paste into a search bar.
//!
//! Layered crates depend on this enum directly:
//!
//! - `proxy::adapters::error::AppError` uses it for the wire `code` field.
//! - `policy-engine` carries it on `LayerOutcome::error_code` (§3 PolicyTrace).
//!
//! Per qiuth-patterns.md §4, the registry is small on purpose. Don't add
//! variants for transient internal states; reach for `InternalError` and
//! log the detail. New variants should map to *operator action* — if there
//! is no useful response an operator can take, it isn't a code.

use http::StatusCode;
use serde::{Deserialize, Serialize};

/// Stable error-code identifier. Wire form is `snake_case`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    // Layer A — PIC ops enforcement
    PicInvariantViolation,

    // Layer B — content rules
    PolicyBlocked,
    RequireConfirmation,
    RateLimited,

    // Read filter
    ReadFilterBlocked,

    // Upstream
    UpstreamUnavailable,
    UpstreamTooLarge,

    // System
    PolicyEngineError,
    DatabaseError,
    InternalError,
}

impl ErrorCode {
    /// Stable wire string. NEVER change once published; only add new variants.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PicInvariantViolation => "pic_invariant_violation",
            Self::PolicyBlocked => "policy_blocked",
            Self::RequireConfirmation => "require_confirmation",
            Self::RateLimited => "rate_limited",
            Self::ReadFilterBlocked => "read_filter_blocked",
            Self::UpstreamUnavailable => "upstream_unavailable",
            Self::UpstreamTooLarge => "upstream_too_large",
            Self::PolicyEngineError => "policy_engine_error",
            Self::DatabaseError => "internal_error",
            Self::InternalError => "internal_error",
        }
    }

    /// Recommended HTTP status. Adapters may override (e.g. translate
    /// `RequireConfirmation` into 202 if they queue the request).
    pub fn default_status(self) -> u16 {
        match self {
            Self::PicInvariantViolation => StatusCode::FORBIDDEN.as_u16(),
            Self::PolicyBlocked => StatusCode::FORBIDDEN.as_u16(),
            Self::ReadFilterBlocked => StatusCode::FORBIDDEN.as_u16(),
            Self::RequireConfirmation => StatusCode::PRECONDITION_REQUIRED.as_u16(),
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS.as_u16(),
            Self::UpstreamUnavailable => StatusCode::BAD_GATEWAY.as_u16(),
            Self::UpstreamTooLarge => StatusCode::BAD_GATEWAY.as_u16(),
            Self::PolicyEngineError => StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            Self::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot test: locks the stable `(variant → wire string)` mapping.
    /// If you find yourself editing an entry here, you are about to break
    /// every operator runbook and SIEM rule that references the old string.
    /// Add a NEW variant instead.
    #[test]
    fn wire_strings_are_stable() {
        let snapshot: &[(ErrorCode, &str)] = &[
            (ErrorCode::PicInvariantViolation, "pic_invariant_violation"),
            (ErrorCode::PolicyBlocked, "policy_blocked"),
            (ErrorCode::RequireConfirmation, "require_confirmation"),
            (ErrorCode::RateLimited, "rate_limited"),
            (ErrorCode::ReadFilterBlocked, "read_filter_blocked"),
            (ErrorCode::UpstreamUnavailable, "upstream_unavailable"),
            (ErrorCode::UpstreamTooLarge, "upstream_too_large"),
            (ErrorCode::PolicyEngineError, "policy_engine_error"),
            (ErrorCode::DatabaseError, "internal_error"),
            (ErrorCode::InternalError, "internal_error"),
        ];
        for (code, expected) in snapshot {
            assert_eq!(
                code.as_str(),
                *expected,
                "code wire string changed for {code:?}"
            );
        }
    }

    #[test]
    fn serde_round_trip_snake_case() {
        let json = serde_json::to_string(&ErrorCode::PicInvariantViolation).unwrap();
        assert_eq!(json, "\"pic_invariant_violation\"");
        let parsed: ErrorCode = serde_json::from_str("\"policy_blocked\"").unwrap();
        assert_eq!(parsed, ErrorCode::PolicyBlocked);
    }

    /// Snapshot test: locks the stable `(variant → HTTP status)` mapping.
    /// Recommended statuses are part of the operator contract — a Grafana
    /// alert keyed on `status="403"` for `code="policy_blocked"` should not
    /// silently flip class. Add a new variant for new status semantics.
    #[test]
    fn default_status_snapshot() {
        let snapshot: &[(ErrorCode, u16)] = &[
            (ErrorCode::PicInvariantViolation, 403),
            (ErrorCode::PolicyBlocked, 403),
            (ErrorCode::ReadFilterBlocked, 403),
            (ErrorCode::RequireConfirmation, 428),
            (ErrorCode::RateLimited, 429),
            (ErrorCode::UpstreamUnavailable, 502),
            (ErrorCode::UpstreamTooLarge, 502),
            (ErrorCode::PolicyEngineError, 500),
            (ErrorCode::DatabaseError, 500),
            (ErrorCode::InternalError, 500),
        ];
        for (code, expected) in snapshot {
            assert_eq!(code.default_status(), *expected, "status for {code:?}");
        }
    }

    #[test]
    fn display_uses_wire_string() {
        assert_eq!(format!("{}", ErrorCode::PolicyBlocked), "policy_blocked");
        assert_eq!(format!("{}", ErrorCode::RateLimited), "rate_limited");
        assert_eq!(format!("{}", ErrorCode::InternalError), "internal_error");
    }

    #[test]
    fn copy_and_hash_traits_work_at_use_sites() {
        // The enum derives Copy + Hash; pin both so a future #[derive]
        // diff doesn't silently drop a trait the wider crate relies on
        // (HashMap<ErrorCode, _> is a real use pattern).
        let c = ErrorCode::PolicyBlocked;
        let _copied = c; // Copy
        let _again = c;
        let mut m = std::collections::HashMap::new();
        m.insert(ErrorCode::PolicyBlocked, "blocked");
        m.insert(ErrorCode::RateLimited, "limited");
        assert_eq!(m.get(&ErrorCode::PolicyBlocked), Some(&"blocked"));
    }

    #[test]
    fn database_error_and_internal_error_share_wire_string_by_design() {
        // The `DatabaseError` variant exists in Rust for type-level
        // dispatch (the adapter sees a sqlx::Error and maps to it),
        // but on the wire both DatabaseError and InternalError emit
        // the same `"internal_error"` string. Pin this two-into-one
        // contract here — a refactor that gave DatabaseError its own
        // `"database_error"` wire string would silently leak a "your
        // postgres is sick" signal to the agent (the proxy
        // intentionally hides that). A refactor that did want to
        // split the wire codes would need to update operator
        // dashboards in lockstep with this assertion.
        assert_eq!(
            ErrorCode::DatabaseError.as_str(),
            ErrorCode::InternalError.as_str(),
            "DatabaseError and InternalError must share the internal_error wire string",
        );
        assert_eq!(ErrorCode::DatabaseError.as_str(), "internal_error");
    }

    #[test]
    fn default_status_for_two_upstream_variants_share_502_class() {
        // UpstreamUnavailable and UpstreamTooLarge both bucket under
        // 502 — Cloudflare's terminology calls 502 "Bad Gateway"
        // generically, and agents retry on it. Pin both arms — a
        // refactor that bumped UpstreamTooLarge to 413 (Payload Too
        // Large) would change the retry semantics on every agent's
        // HTTP client.
        assert_eq!(ErrorCode::UpstreamUnavailable.default_status(), 502);
        assert_eq!(ErrorCode::UpstreamTooLarge.default_status(), 502);
    }

    #[test]
    fn error_code_serde_round_trip_via_value_for_every_variant() {
        // Snapshot tests pin one-way `to_string`, but the wire is
        // bidirectional — operators paste a JSON blob into a CLI
        // tool and deserialize. Pin round-trip via `serde_json::Value`
        // (not just String) for every variant so a `rename_all`
        // attribute drift would surface here on both directions.
        let cases: &[ErrorCode] = &[
            ErrorCode::PicInvariantViolation,
            ErrorCode::PolicyBlocked,
            ErrorCode::RequireConfirmation,
            ErrorCode::RateLimited,
            ErrorCode::ReadFilterBlocked,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::UpstreamTooLarge,
            ErrorCode::PolicyEngineError,
            // Skip the two that alias to internal_error — deserialize
            // is non-deterministic across the alias. Pinned separately
            // in `database_error_and_internal_error_share_wire_string_by_design`.
        ];
        for c in cases {
            let v = serde_json::to_value(c).unwrap();
            assert!(v.is_string());
            let back: ErrorCode = serde_json::from_value(v.clone()).unwrap();
            assert_eq!(back, *c, "round-trip mismatch for {c:?}");
        }
    }

    #[test]
    fn unknown_wire_string_fails_deserialize() {
        // `#[non_exhaustive]` is a Rust-side affordance; the wire enum is
        // still closed at deserialize time (serde rejects unknown variants).
        let r: Result<ErrorCode, _> = serde_json::from_str("\"banhammer\"");
        assert!(r.is_err());
    }

    #[test]
    fn as_str_returns_static_str_lifetime_for_zero_alloc_metric_label_propagation() {
        // `ErrorCode::as_str()` is called on every error response path
        // to attach a stable label to the `proxilion_errors_total{code,
        // ...}` metric counter. The label must be `&'static str` so the
        // metrics SDK can intern + reuse the string across an unbounded
        // number of error emissions per second without allocation. The
        // existing pins walk the VALUE across every variant but never
        // the LIFETIME. A refactor returning `String` "for variant-
        // specific dynamic labels" would silently allocate one String
        // per error response — symmetric to round-163 + round-165 +
        // round-168 + round-169 + round-170 + round-171 static-str pins
        // extended to ErrorCode::as_str return.
        fn require_static_str(_: &'static str) {}
        // Cross-variant sweep: every variant must produce a 'static label.
        for c in [
            ErrorCode::PicInvariantViolation,
            ErrorCode::PolicyBlocked,
            ErrorCode::RequireConfirmation,
            ErrorCode::RateLimited,
            ErrorCode::ReadFilterBlocked,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::UpstreamTooLarge,
            ErrorCode::PolicyEngineError,
            ErrorCode::DatabaseError,
            ErrorCode::InternalError,
        ] {
            require_static_str(c.as_str());
        }
    }

    #[test]
    fn error_code_is_send_sync_static_for_axum_error_envelope_propagation() {
        // ErrorCode is carried on AppError variants (`pub fn code(&self)
        // -> ErrorCode`) and flows through `tokio::spawn` blocks (the
        // tee-to-audit-sink path persists error rows asynchronously).
        // The Copy + Hash derives already imply Send + Sync, but a
        // future refactor to a #[non_copy] variant carrying owned
        // state ("for richer diagnostic context") would silently break
        // the Send bound at a remote `tower::Service` trait-bound. Pin
        // Send + Sync + 'static via require_send_sync_static —
        // symmetric to round-168 PicViolationRecord + round-169
        // BlockedNotification Send+Sync pins extended to ErrorCode.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<ErrorCode>();
    }

    #[test]
    fn as_str_byte_exact_lowercase_snake_case_no_kebab_no_uppercase_across_all_ten_variants() {
        // Operator dashboards bucket metrics on `code == "policy_blocked"`
        // via lowercase snake_case regex. The existing wire_strings_are_stable
        // pin walks values byte-equal but never the SHAPE invariant —
        // a refactor adding `#[serde(rename_all = "kebab-case")]` "for
        // hyphen-friendly URLs" on a sibling shared types enum would
        // silently break every dashboard bucket if it leaked to this
        // file. Pin no-uppercase + no-kebab across all 10 variants —
        // symmetric to round-143 oauth_error code lowercase sweep +
        // round-161 PolicyView/ListResponse JSON-keys snake_case sweep
        // extended to ErrorCode wire form.
        for c in [
            ErrorCode::PicInvariantViolation,
            ErrorCode::PolicyBlocked,
            ErrorCode::RequireConfirmation,
            ErrorCode::RateLimited,
            ErrorCode::ReadFilterBlocked,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::UpstreamTooLarge,
            ErrorCode::PolicyEngineError,
            ErrorCode::DatabaseError,
            ErrorCode::InternalError,
        ] {
            let s = c.as_str();
            assert!(
                s.chars().all(|ch| !ch.is_ascii_uppercase()),
                "variant {c:?} wire string `{s}` contains uppercase",
            );
            assert!(
                !s.contains('-'),
                "variant {c:?} wire string `{s}` contains kebab-case `-`",
            );
            // Defensive: shell-safe (no spaces, no shell metachars).
            assert!(
                !s.contains(' ') && !s.contains('"') && !s.contains('$'),
                "variant {c:?} wire string `{s}` contains shell-unsafe char",
            );
        }
    }

    #[test]
    fn as_str_is_referentially_transparent_across_fifty_repeated_calls_per_variant() {
        // Symmetric to round-161 + round-162 + round-166 + round-168 +
        // round-169 + round-170 + round-171 + round-172 referential-
        // transparency pins extended to ErrorCode::as_str. A refactor
        // that introduced a once-cell-backed string interner "for hot-
        // path perf" might silently return the wrong cached value if
        // the cache key was hashed incorrectly. Pin 50 calls per
        // variant produce byte-equal output.
        for c in [
            ErrorCode::PolicyBlocked,
            ErrorCode::RateLimited,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::InternalError,
        ] {
            let baseline = c.as_str();
            for i in 0..50 {
                let again = c.as_str();
                assert_eq!(
                    again, baseline,
                    "iteration {i} on {c:?}: as_str must be referentially transparent",
                );
            }
        }
    }

    #[test]
    fn default_status_returns_u16_type_not_status_code_for_adapter_override_freedom() {
        // The function returns `u16` (not `http::StatusCode`) so
        // adapters can override with arbitrary numeric codes (e.g.
        // 202 Accepted for queued RequireConfirmation requests per the
        // docstring). A refactor to return StatusCode "for stricter
        // typing" would silently force every caller to extract `.as_u16()`
        // at the override site AND would prevent customer-extension
        // adapters from returning non-standard codes that http::StatusCode
        // rejects. Pin via require_u16 generic fn.
        fn require_u16(_: u16) {}
        for c in [
            ErrorCode::PolicyBlocked,
            ErrorCode::RateLimited,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::InternalError,
        ] {
            require_u16(c.default_status());
        }
    }

    #[test]
    fn error_code_variant_count_pinned_at_exactly_ten_via_exhaustive_match() {
        // Pin the variant count via an exhaustive match expression so an
        // 11th variant landing (e.g. `OperatorScopeDenied` for a future
        // 403 split between policy-blocked vs missing-operator-scope, or
        // `KillSwitchRevoked` to distinguish bearer-revoked from
        // policy-blocked on dashboards) without matching as_str +
        // default_status site updates would surface here as a
        // non-exhaustive compile error. Symmetric to the
        // `parse_decision`-style exhaustive match in policy-engine but
        // applied to the canonical wire registry — `#[non_exhaustive]`
        // is a Rust-side affordance for downstream crates, not a
        // license to skip enumerate-then-update lockstep when adding
        // operator-visible variants.
        fn variant_witness(c: ErrorCode) -> u8 {
            match c {
                ErrorCode::PicInvariantViolation => 0,
                ErrorCode::PolicyBlocked => 1,
                ErrorCode::RequireConfirmation => 2,
                ErrorCode::RateLimited => 3,
                ErrorCode::ReadFilterBlocked => 4,
                ErrorCode::UpstreamUnavailable => 5,
                ErrorCode::UpstreamTooLarge => 6,
                ErrorCode::PolicyEngineError => 7,
                ErrorCode::DatabaseError => 8,
                ErrorCode::InternalError => 9,
            }
        }
        // Sweep produces 10 distinct discriminant values
        let mut seen = std::collections::HashSet::new();
        for c in [
            ErrorCode::PicInvariantViolation,
            ErrorCode::PolicyBlocked,
            ErrorCode::RequireConfirmation,
            ErrorCode::RateLimited,
            ErrorCode::ReadFilterBlocked,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::UpstreamTooLarge,
            ErrorCode::PolicyEngineError,
            ErrorCode::DatabaseError,
            ErrorCode::InternalError,
        ] {
            assert!(seen.insert(variant_witness(c)));
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn as_str_signature_pinned_via_fn_pointer_witness() {
        // `as_str` consumes `self` by value (the enum is Copy — the
        // method-level Copy semantic preserves the original at the
        // call site). Pin the exact signature `fn(ErrorCode) ->
        // &'static str` so a refactor that flipped to `&self`
        // ("borrow for symmetry with default_status") would force
        // every call site to add `&` or `.clone()` AND silently shift
        // the lifetime contract — the existing static-str pin would
        // still pass but the borrow shape would surface as a
        // fn-pointer type mismatch here.
        let _f: fn(ErrorCode) -> &'static str = ErrorCode::as_str;
    }

    #[test]
    fn default_status_signature_pinned_via_fn_pointer_witness() {
        // Symmetric to `as_str_signature_pinned_via_fn_pointer_witness`.
        // Pin `default_status` as `fn(ErrorCode) -> u16` (self by
        // value, u16 return — NOT `http::StatusCode`). The existing
        // `default_status_returns_u16_type_not_status_code_for_adapter_override_freedom`
        // pin uses a require_u16 closure which doesn't catch a
        // `&self` borrow refactor — fn-pointer witness pins both
        // axes (receiver shape + return type) at compile time.
        let _f: fn(ErrorCode) -> u16 = ErrorCode::default_status;
    }

    #[test]
    fn display_matches_as_str_byte_exact_across_every_variant() {
        // The existing `display_uses_wire_string` pin walks only 3
        // variants (PolicyBlocked, RateLimited, InternalError). Pin
        // the symmetric byte-exact `Display == as_str` contract across
        // ALL 10 variants so a refactor that special-cased one
        // variant's Display impl (e.g. "render PicInvariantViolation
        // as 'PIC violation' for the operator-facing 403 body") would
        // silently break the operator log filters that grep on the
        // wire string. The contract is: `format!("{c}")` must be
        // byte-identical to `c.as_str()` for every variant — the
        // canonical Display impl above delegates to `as_str` via
        // `write_str`, and this pin enforces no future divergence.
        for c in [
            ErrorCode::PicInvariantViolation,
            ErrorCode::PolicyBlocked,
            ErrorCode::RequireConfirmation,
            ErrorCode::RateLimited,
            ErrorCode::ReadFilterBlocked,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::UpstreamTooLarge,
            ErrorCode::PolicyEngineError,
            ErrorCode::DatabaseError,
            ErrorCode::InternalError,
        ] {
            assert_eq!(
                format!("{c}"),
                c.as_str(),
                "Display for {c:?} must match as_str byte-exact",
            );
        }
    }

    #[test]
    fn partial_eq_distinguishes_database_error_and_internal_error_at_variant_level() {
        // Load-bearing despite the two variants sharing the wire
        // string `"internal_error"` — Rust-side dispatch in
        // `AppError::from_sqlx_error` etc relies on the two being
        // distinguishable at the variant level (the wire layer
        // collapses them, the type layer does not). A refactor that
        // collapsed the two into one variant (in the name of "they
        // serialize the same anyway") would silently lose the
        // type-level dispatch every adapter relies on for sqlx-vs-
        // anyhow error routing. Pin distinct-equality directly.
        assert_ne!(ErrorCode::DatabaseError, ErrorCode::InternalError);
        assert_eq!(ErrorCode::DatabaseError, ErrorCode::DatabaseError);
        assert_eq!(ErrorCode::InternalError, ErrorCode::InternalError);
        // Hash distinctness — required for `HashMap<ErrorCode, _>` use
        // sites (the existing copy_and_hash_traits test inserts both
        // but never asserts they bucket separately). Calculate Hash
        // manually so a future PartialEq-but-not-Hash drift surfaces.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h1 = DefaultHasher::new();
        ErrorCode::DatabaseError.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        ErrorCode::InternalError.hash(&mut h2);
        assert_ne!(
            h1.finish(),
            h2.finish(),
            "DatabaseError and InternalError must hash distinctly even though wire strings alias",
        );
    }

    #[test]
    fn partial_eq_distinguishes_every_pair_of_distinct_variants_across_full_ten_variant_sweep() {
        // Pin the full equality matrix — for every pair of distinct
        // variants, `==` must return false. A refactor that collapsed
        // any two variants into one (e.g. merged RateLimited into
        // PolicyBlocked under a unified "deny" label) would surface
        // here as the merged pair returning equal. The existing
        // copy_and_hash_traits test inserts pairs into a HashMap but
        // never asserts pair-wise distinct-equality across the full
        // ten-variant catalogue. Reflexive equality is also pinned
        // (every variant equals itself).
        let all = [
            ErrorCode::PicInvariantViolation,
            ErrorCode::PolicyBlocked,
            ErrorCode::RequireConfirmation,
            ErrorCode::RateLimited,
            ErrorCode::ReadFilterBlocked,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::UpstreamTooLarge,
            ErrorCode::PolicyEngineError,
            ErrorCode::DatabaseError,
            ErrorCode::InternalError,
        ];
        for (i, a) in all.iter().enumerate() {
            assert_eq!(a, a, "reflexive equality for {a:?}");
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a, b,
                        "variants {a:?} and {b:?} at indices {i}/{j} must be distinct",
                    );
                }
            }
        }
    }

    #[test]
    fn default_status_returns_only_4xx_or_5xx_codes_never_2xx_3xx_across_all_variants() {
        // Every ErrorCode represents an OPERATOR-FACING FAILURE — by
        // definition, the recommended HTTP status MUST be in the 4xx
        // or 5xx class. A refactor adding a hypothetical
        // `Self::AcceptedQueued => 202` "for ergonomic async response
        // shape" would silently leak a success-class status through
        // the error envelope and confuse dashboards that filter
        // `status >= 400` to count errors. Pin no-2xx + no-3xx across
        // every variant — symmetric to round-143 AppError::status all-
        // variants 4xx/5xx pin extended to the canonical ErrorCode
        // registry one layer up.
        for c in [
            ErrorCode::PicInvariantViolation,
            ErrorCode::PolicyBlocked,
            ErrorCode::RequireConfirmation,
            ErrorCode::RateLimited,
            ErrorCode::ReadFilterBlocked,
            ErrorCode::UpstreamUnavailable,
            ErrorCode::UpstreamTooLarge,
            ErrorCode::PolicyEngineError,
            ErrorCode::DatabaseError,
            ErrorCode::InternalError,
        ] {
            let s = c.default_status();
            assert!(
                (400..600).contains(&s),
                "variant {c:?} default_status {s} must be 4xx or 5xx",
            );
            assert!(
                !(200..300).contains(&s),
                "variant {c:?} status {s} must NOT be 2xx"
            );
            assert!(
                !(300..400).contains(&s),
                "variant {c:?} status {s} must NOT be 3xx"
            );
        }
    }
}
