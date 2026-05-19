//! PKCE S256 verification.
//!
//! RFC 7636 §4.6: code_challenge = BASE64URL-NO-PAD(SHA256(code_verifier)).
//! Constant-time compare via `subtle`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PkceError {
    #[error("verifier failed PKCE check")]
    Mismatch,
    #[error("verifier malformed (length must be 43..=128 characters)")]
    VerifierLength,
}

/// Verify a PKCE code_verifier against the stored code_challenge (S256 only).
pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> Result<(), PkceError> {
    let len = verifier.len();
    if !(43..=128).contains(&len) {
        return Err(PkceError::VerifierLength);
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    if bool::from(computed.as_bytes().ct_eq(challenge.as_bytes())) {
        Ok(())
    } else {
        Err(PkceError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_example_vector() {
        // From RFC 7636 §B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce_s256(verifier, challenge).is_ok());
    }

    #[test]
    fn mismatch_rejected() {
        let verifier = "a".repeat(43);
        let err = verify_pkce_s256(&verifier, "bogus").unwrap_err();
        assert!(matches!(err, PkceError::Mismatch));
    }

    #[test]
    fn short_verifier_rejected() {
        let err = verify_pkce_s256("tooshort", "anything").unwrap_err();
        assert!(matches!(err, PkceError::VerifierLength));
    }

    #[test]
    fn boundary_42_chars_rejected_and_43_chars_accepted_as_length() {
        // RFC 7636 §4.1 — length is **43..=128**. The boundary just below
        // (42) must trip VerifierLength; 43 must pass the length check and
        // proceed to the SHA-256 / compare path (where it then mismatches
        // because the challenge is bogus — that's a Mismatch, not a length
        // error). Keeping these on separate assertions so a future refactor
        // that collapses the two errors surfaces the regression by variant.
        let v42 = "a".repeat(42);
        assert!(matches!(
            verify_pkce_s256(&v42, "bogus").unwrap_err(),
            PkceError::VerifierLength,
        ));
        let v43 = "a".repeat(43);
        assert!(matches!(
            verify_pkce_s256(&v43, "bogus").unwrap_err(),
            PkceError::Mismatch,
        ));
    }

    #[test]
    fn boundary_128_chars_accepted_and_129_rejected() {
        // Symmetric upper boundary — 128 chars must pass length, 129 must
        // not. The verifier is bogus so the 128 case still errors, but with
        // Mismatch, not VerifierLength.
        let v128 = "a".repeat(128);
        assert!(matches!(
            verify_pkce_s256(&v128, "bogus").unwrap_err(),
            PkceError::Mismatch,
        ));
        let v129 = "a".repeat(129);
        assert!(matches!(
            verify_pkce_s256(&v129, "bogus").unwrap_err(),
            PkceError::VerifierLength,
        ));
    }

    #[test]
    fn empty_verifier_rejected_as_length_not_mismatch() {
        // The fail-closed contract: an empty string MUST trip the
        // length check before any SHA-256 work. A regression that
        // swapped the order (compute digest first, then check length)
        // would burn cycles on every malformed inbound request — and
        // potentially expose timing-side channels through the
        // SHA-256 cost variance. Pin VerifierLength on `""`.
        let err = verify_pkce_s256("", "anything").unwrap_err();
        assert!(matches!(err, PkceError::VerifierLength));
    }

    #[test]
    fn challenge_comparison_is_case_sensitive() {
        // base64url is case-sensitive — a refactor that lower-cased
        // both sides "for robustness" would silently weaken the PKCE
        // guarantee against a downgrade attack. Compute the real
        // challenge from a 43-char verifier, then upper-case it and
        // assert Mismatch (NOT Ok). The verifier itself stays valid
        // (passes the length check), isolating the case-sensitivity
        // contract on the challenge side.
        let verifier = "a".repeat(43);
        let digest = Sha256::digest(verifier.as_bytes());
        let real = URL_SAFE_NO_PAD.encode(digest);
        // Sanity: the real challenge matches.
        assert!(verify_pkce_s256(&verifier, &real).is_ok());
        // ASCII-upper variant must NOT match.
        let upper = real.to_ascii_uppercase();
        assert_ne!(real, upper, "test invariant: real must have a case to flip");
        assert!(matches!(
            verify_pkce_s256(&verifier, &upper).unwrap_err(),
            PkceError::Mismatch,
        ));
    }

    #[test]
    fn pkce_error_implements_std_error_trait_for_anyhow_chains() {
        // Adapter call sites bubble PkceError through `anyhow::Error`
        // chains for structured logging — pin that the `thiserror`
        // derive lands the `std::error::Error` impl so a refactor
        // that dropped `#[derive(Error)]` would surface at the trait-
        // object cast below rather than only at the call-site type
        // mismatch (which can be far from this file).
        let e: PkceError = PkceError::Mismatch;
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.to_string().contains("PKCE"));
    }

    #[test]
    fn pkce_error_source_is_none_for_both_variants_leaf_contract() {
        // The existing `pkce_error_implements_std_error_trait_for_anyhow_chains`
        // test pins the `std::error::Error` trait via dyn-cast on the
        // Mismatch variant only and asserts only the `to_string()`
        // substring — it does NOT walk `source()`. Both variants are
        // leaf errors (no `#[source]` / `#[from]` inner), so
        // `source()` MUST return None for both. A refactor that
        // chained an inner cause (e.g. `Mismatch { inner: sqlx::Error }`
        // for "richer triage") would silently change the anyhow chain
        // walk shape, making the OAuth callback log render two
        // entries instead of one for a PKCE failure — pin the leaf
        // contract explicitly across both variants.
        use std::error::Error;
        let m: PkceError = PkceError::Mismatch;
        let l: PkceError = PkceError::VerifierLength;
        let dyn_m: &(dyn Error + 'static) = &m;
        let dyn_l: &(dyn Error + 'static) = &l;
        assert!(dyn_m.source().is_none(), "Mismatch is a leaf");
        assert!(dyn_l.source().is_none(), "VerifierLength is a leaf");
    }

    #[test]
    fn pkce_error_debug_carries_variant_name_for_operator_grep() {
        // The OAuth callback's failure-triage path traces
        // `tracing::warn!(?err, ..)` — operators grep for the variant
        // name to bucket "verifier mismatch (likely a tampered code_verifier)"
        // vs. "verifier malformed (length out of range)". A manual
        // Debug impl that hid the variant name (e.g. rendered as
        // `PkceError(1)` after a refactor to a numeric error code)
        // would silently collapse the two failure modes onto an opaque
        // integer in every operator log line. Pin both variant names
        // in the Debug render.
        let s = format!("{:?}", PkceError::Mismatch);
        assert!(s.contains("Mismatch"), "got: {s}");
        let s = format!("{:?}", PkceError::VerifierLength);
        assert!(s.contains("VerifierLength"), "got: {s}");
    }

    #[test]
    fn verifier_length_check_counts_bytes_not_unicode_codepoints() {
        // RFC 7636 §4.1 specifies the verifier as ASCII characters from
        // the [A-Z][a-z][0-9]-._~ unreserved set — the 43..=128 bound is
        // a byte count. Rust's `str::len()` returns BYTES, which matches
        // the RFC. Pin the byte-semantic via a multi-byte UTF-8 string:
        // 43 × `é` (2 bytes each = 86 bytes) MUST pass the length check
        // (since 86 is in 43..=128) and proceed to the Mismatch path
        // — not surface a "43 codepoints" interpretation that would
        // reject it as too short. Symmetric: 11 × `é` (22 bytes, below
        // 43) MUST be rejected as VerifierLength. A refactor to
        // `verifier.chars().count()` would surface here as flipping the
        // two errors. This isn't a "valid PKCE inbound" — actual PKCE
        // verifiers are ASCII — but the BYTE-vs-CHAR distinction is the
        // load-bearing invariant against `chars().count()` refactors.
        let v_86_bytes = "é".repeat(43);
        assert_eq!(v_86_bytes.len(), 86);
        assert!(
            matches!(
                verify_pkce_s256(&v_86_bytes, "bogus").unwrap_err(),
                PkceError::Mismatch,
            ),
            "86-byte verifier must pass length, fall to Mismatch",
        );
        let v_22_bytes = "é".repeat(11);
        assert_eq!(v_22_bytes.len(), 22);
        assert!(
            matches!(
                verify_pkce_s256(&v_22_bytes, "bogus").unwrap_err(),
                PkceError::VerifierLength,
            ),
            "22-byte verifier must trip VerifierLength",
        );
    }

    #[test]
    fn empty_challenge_with_valid_length_verifier_yields_mismatch_not_panic() {
        // The challenge side is fed directly into a constant-time byte
        // comparison; a wire-shape edge is an empty challenge string
        // (length 0) against a valid-length verifier. The current
        // implementation MUST yield Mismatch (the computed b64url
        // challenge for any 43-byte verifier is 43 bytes long, so an
        // empty challenge never equals it) and MUST NOT panic in the
        // `ct_eq` path (subtle's ct_eq returns Choice(0) for
        // length-mismatched slices, not a panic — a refactor that
        // pre-checked `assert_eq!(a.len(), b.len())` for "tidiness"
        // would surface here as a panic on the empty-challenge edge).
        let verifier = "a".repeat(43);
        let err = verify_pkce_s256(&verifier, "").unwrap_err();
        assert!(matches!(err, PkceError::Mismatch), "got {err:?}");
    }

    #[test]
    fn computed_challenge_is_exactly_43_bytes_for_any_input_length() {
        // The base64url-no-pad encoding of a SHA-256 digest is always
        // 43 bytes (32 bytes input → ceil(32*8/6) = 43 chars, no
        // padding). The PKCE wire shape on the callback storage side
        // depends on this — the `code_challenge` column is sized to
        // 43 chars in the OAuth state table, and a refactor that
        // swapped to standard base64 (WITH padding, 44 chars) or to
        // hex (64 chars) would silently overflow the column on the
        // first PKCE flow after deploy. Pin the 43-byte invariant
        // across three verifier lengths so a per-length silent
        // truncation surfaces here too.
        for verifier_str in ["a".repeat(43), "b".repeat(64), "c".repeat(128)] {
            let digest = Sha256::digest(verifier_str.as_bytes());
            let encoded = URL_SAFE_NO_PAD.encode(digest);
            assert_eq!(
                encoded.len(),
                43,
                "b64url-no-pad of SHA-256 must be 43 chars (input len {})",
                verifier_str.len(),
            );
            // And `verify_pkce_s256` with the byte-identical computed
            // challenge MUST return Ok — round-trip pin.
            assert!(verify_pkce_s256(&verifier_str, &encoded).is_ok());
        }
    }

    #[test]
    fn mismatch_returned_when_challenge_differs_by_one_trailing_byte() {
        // Boundary on the constant-time compare: flip a single trailing
        // byte of the real challenge and pin that the verifier fails
        // closed. Without this pin, a refactor to a length-only check
        // (e.g. `if computed.len() == challenge.len() { Ok(()) }`) would
        // silently pass — the existing `mismatch_rejected` test walks a
        // wholly bogus challenge that also fails a length check, so it
        // doesn't isolate the byte-comparison path. Pin a 43-byte
        // bogus challenge that has the SAME LENGTH as the real one but
        // differs in one byte at the tail.
        let verifier = "a".repeat(43);
        let digest = Sha256::digest(verifier.as_bytes());
        let real = URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(real.len(), 43);
        // Flip the last byte to a different valid b64url char.
        let mut tampered = real.clone();
        let last = tampered.pop().unwrap();
        let flipped = if last == 'A' { 'B' } else { 'A' };
        tampered.push(flipped);
        assert_eq!(tampered.len(), 43);
        assert_ne!(tampered, real);
        assert!(matches!(
            verify_pkce_s256(&verifier, &tampered).unwrap_err(),
            PkceError::Mismatch,
        ));
    }

    #[test]
    fn pkce_error_is_send_sync_static_for_anyhow_chain_boundary() {
        // PkceError flows through anyhow chains in the OAuth callback —
        // anyhow's blanket impl requires `Send + Sync + 'static`. A
        // refactor that introduced a non-Send field (e.g. `Rc<str>` on
        // a future `Mismatch { computed: Rc<str> }` "for cheap inner
        // borrowing") would surface as a confusing anyhow trait-bound
        // error at the call site instead of cleanly at the error type
        // boundary. Pin the three-trait combo here so a refactor fails
        // fast at this file.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<PkceError>();
    }

    #[test]
    fn verify_pkce_s256_is_referentially_transparent_across_repeated_calls() {
        // The function is pure: no clock, no env, no global state. Pin
        // referential transparency by calling 50 times with the same
        // args and asserting all 50 results are equal — both happy path
        // (Ok) AND the two error paths (Mismatch / VerifierLength). A
        // refactor that introduced a once-cell-backed memoization layer
        // "for hot-path performance" would still pass the equality
        // check, but a refactor that introduced any form of state
        // (a counter, a rate-limit, a "first-call returns Ok then
        // subsequent calls require...") would surface here.
        let verifier_43 = "a".repeat(43);
        let digest = Sha256::digest(verifier_43.as_bytes());
        let real_challenge = URL_SAFE_NO_PAD.encode(digest);
        for _ in 0..50 {
            assert!(verify_pkce_s256(&verifier_43, &real_challenge).is_ok());
            assert!(matches!(
                verify_pkce_s256(&verifier_43, "bogus43char_____").unwrap_err(),
                PkceError::Mismatch,
            ));
            assert!(matches!(
                verify_pkce_s256("short", "anything").unwrap_err(),
                PkceError::VerifierLength,
            ));
        }
    }

    #[test]
    fn verifier_with_internal_whitespace_passes_length_but_yields_mismatch_no_trim() {
        // RFC 7636 §4.1 confines verifiers to the unreserved character
        // set ([A-Z][a-z][0-9]-._~), but the verify function is BYTE-
        // ORIENTED — it does NOT validate the character class and does
        // NOT trim whitespace. A refactor that called `.trim()` "for
        // robustness against operator-side encoding bugs" would silently
        // change the byte input to SHA-256 and produce a different
        // computed challenge — silently breaking the PKCE round-trip
        // for any verifier that happened to carry trailing whitespace
        // (e.g. from a copy-paste). Pin that the length check passes
        // on a 43-byte string with a literal space char in the middle,
        // and the function proceeds to the Mismatch path (no trim).
        let v = format!("{}{}{}", "a".repeat(20), " ", "a".repeat(22));
        assert_eq!(v.len(), 43);
        assert!(matches!(
            verify_pkce_s256(&v, "bogus").unwrap_err(),
            PkceError::Mismatch,
        ));
    }

    #[test]
    fn challenge_with_embedded_null_byte_yields_mismatch_without_panic() {
        // Edge: a challenge string containing a NUL byte (`\0`). The
        // base64url-no-pad encoding never produces NUL, so the real
        // challenge can't carry one — but the function MUST NOT panic
        // on inbound data with surprising bytes. Pin that a challenge
        // of length 43 with a NUL byte in the middle yields Mismatch
        // (the byte-comparison correctly differs from the real digest
        // encoding) and does NOT panic in the `ct_eq` path. A refactor
        // that pre-checked `assert!(challenge.is_ascii_alphanumeric())`
        // for "input hygiene" would surface here as a panic instead of
        // a clean Mismatch error.
        let verifier = "a".repeat(43);
        let mut tampered = String::with_capacity(43);
        tampered.push_str(&"a".repeat(20));
        tampered.push('\0');
        tampered.push_str(&"a".repeat(22));
        assert_eq!(tampered.len(), 43);
        let err = verify_pkce_s256(&verifier, &tampered).unwrap_err();
        assert!(matches!(err, PkceError::Mismatch), "got {err:?}");
    }

    #[test]
    fn pkce_error_exhaustive_match_compiles_with_exactly_two_arms() {
        // PkceError has exactly two variants today (Mismatch /
        // VerifierLength). Pin the variant count at the type-level via
        // an exhaustive match so a refactor that added a third variant
        // (e.g. `Internal` to wrap a downstream error) would surface
        // here as either a non-exhaustive-match compile error OR a
        // failing arm assertion. The existing string-based tests cover
        // the two variant names individually but don't enforce the
        // variant-count cap — a refactor that added an `Internal`
        // variant without updating the OAuth callback's failure-triage
        // grep buckets would silently surface a third grep bucket.
        for e in [PkceError::Mismatch, PkceError::VerifierLength] {
            match e {
                PkceError::Mismatch => {}
                PkceError::VerifierLength => {}
            }
        }
        // Sanity: the two distinct variants produce distinct Debug
        // strings (so the match-arm coverage above is real, not a
        // collapse of two equivalent shapes).
        assert_ne!(
            format!("{:?}", PkceError::Mismatch),
            format!("{:?}", PkceError::VerifierLength),
        );
    }

    #[test]
    fn compute_then_verify_round_trips_across_five_distinct_verifier_lengths() {
        // For every verifier length in {43, 50, 64, 96, 128} compute the
        // canonical challenge and pin that `verify_pkce_s256` returns
        // Ok against the computed challenge. The existing
        // `computed_challenge_is_exactly_43_bytes_for_any_input_length`
        // pin covers 43/64/128; widen to 50 + 96 so the boundary
        // intermediates between the named boundaries are also pinned.
        // A refactor that special-cased one specific length (e.g.
        // "fast path for the 43-byte verifier" using a non-constant-
        // time compare) would surface here as that specific length
        // diverging from the others.
        for &len in &[43, 50, 64, 96, 128] {
            let verifier = "x".repeat(len);
            let digest = Sha256::digest(verifier.as_bytes());
            let challenge = URL_SAFE_NO_PAD.encode(digest);
            assert!(
                verify_pkce_s256(&verifier, &challenge).is_ok(),
                "verifier of length {len} should round-trip via its canonical challenge",
            );
        }
    }

    #[test]
    fn error_display_strings_are_stable_for_log_filters() {
        // Operator log filters key on the substring "PKCE check" /
        // "length must be 43..=128". A future variant rename or message
        // tweak must be a conscious wire-shape change.
        assert!(
            PkceError::Mismatch
                .to_string()
                .contains("verifier failed PKCE check")
        );
        assert!(
            PkceError::VerifierLength
                .to_string()
                .contains("length must be 43..=128"),
        );
    }
}
