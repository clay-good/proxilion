//! Agent bearer tokens.
//!
//! Format: `pxl_live_` + 52 base32 chars (256 bits at 5 bits/char rounded up).
//! Per spec.md §1.1 the upstream prompt says "32-bytes-base32"; we pick
//! Crockford-RFC4648 unpadded base32 of 32 bytes — yielding ⌈32·8/5⌉ = 52
//! chars. The stored shape is sha256(bearer).

use base32::Alphabet;
use rand::RngCore;
use sha2::{Digest, Sha256};

const PREFIX: &str = "pxl_live_";
const RAW_BYTES: usize = 32;
#[allow(dead_code)] // used by Bearer::parse + tests
const TOKEN_LEN: usize = PREFIX.len() + 52;

/// A live bearer. Wrapper type to keep accidental Debug-prints from leaking
/// the token; we never derive `Debug` on the inner string.
pub struct Bearer(String);

impl Bearer {
    pub fn generate() -> Self {
        let mut buf = [0u8; RAW_BYTES];
        rand::thread_rng().fill_bytes(&mut buf);
        let enc = base32::encode(Alphabet::Rfc4648 { padding: false }, &buf);
        // base32 of 32 bytes without padding is exactly 52 chars.
        debug_assert_eq!(enc.len(), 52);
        Self(format!("{PREFIX}{enc}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[allow(dead_code)] // used by tests and (in §1.2) the bearer middleware
    pub fn parse(input: &str) -> Option<&str> {
        if input.len() != TOKEN_LEN || !input.starts_with(PREFIX) {
            return None;
        }
        let body = &input[PREFIX.len()..];
        // base32 alphabet check.
        if !body
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
        {
            return None;
        }
        Some(input)
    }

    pub fn hash(&self) -> BearerHash {
        BearerHash::of(self.as_str())
    }
}

impl std::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bearer").field("redacted", &"[…]").finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BearerHash(pub [u8; 32]);

impl BearerHash {
    pub fn of(bearer: &str) -> Self {
        let d = Sha256::digest(bearer.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        Self(out)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for BearerHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only the first 8 hex chars for telemetry correlation.
        let head = self.0[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        write!(f, "BearerHash({head}…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_bearer_round_trips_format_check() {
        let b = Bearer::generate();
        assert!(Bearer::parse(b.as_str()).is_some());
        assert_eq!(b.as_str().len(), TOKEN_LEN);
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(Bearer::parse("pxl_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_none());
    }

    #[test]
    fn rejects_lowercase_body() {
        let bad = format!("{PREFIX}{}", "a".repeat(52));
        assert!(Bearer::parse(&bad).is_none());
    }

    #[test]
    fn hash_is_stable() {
        let a = BearerHash::of("pxl_live_AAAA");
        let b = BearerHash::of("pxl_live_AAAA");
        assert_eq!(a, b);
    }

    #[test]
    fn debug_does_not_leak() {
        let b = Bearer::generate();
        let dbg = format!("{b:?}");
        assert!(!dbg.contains(b.as_str()), "Bearer Debug must not leak the token");
    }
}
