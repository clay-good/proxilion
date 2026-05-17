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
