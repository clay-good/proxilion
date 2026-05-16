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
    fn unknown_wire_string_fails_deserialize() {
        // `#[non_exhaustive]` is a Rust-side affordance; the wire enum is
        // still closed at deserialize time (serde rejects unknown variants).
        let r: Result<ErrorCode, _> = serde_json::from_str("\"banhammer\"");
        assert!(r.is_err());
    }
}
