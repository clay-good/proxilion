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
}
