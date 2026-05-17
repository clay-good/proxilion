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
        if !body.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7')) {
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
        assert!(
            Bearer::parse("pxl_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_none()
        );
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
        assert!(
            !dbg.contains(b.as_str()),
            "Bearer Debug must not leak the token"
        );
    }

    #[test]
    fn parse_rejects_length_below_and_above_token_len() {
        // Off-by-one boundaries on either side of TOKEN_LEN. A future
        // refactor that loosened the length check to `>=` or `>` would
        // surface here as a regression rather than silently widening the
        // accept set.
        let one_short = format!("{PREFIX}{}", "A".repeat(51));
        assert!(Bearer::parse(&one_short).is_none(), "51-char body rejected");
        let one_long = format!("{PREFIX}{}", "A".repeat(53));
        assert!(Bearer::parse(&one_long).is_none(), "53-char body rejected");
    }

    #[test]
    fn parse_rejects_digits_outside_base32_alphabet() {
        // RFC 4648 base32 omits `0` / `1` / `8` / `9` (visually similar to
        // O/I/B/g). Pin each — a sloppy alphabet check that admitted all
        // ascii digits would surface here.
        for bad in ['0', '1', '8', '9'] {
            let body: String = std::iter::once(bad)
                .chain(std::iter::repeat_n('A', 51))
                .collect();
            let s = format!("{PREFIX}{body}");
            assert!(
                Bearer::parse(&s).is_none(),
                "digit {bad} should not parse but did",
            );
        }
    }

    #[test]
    fn bearer_hash_as_bytes_returns_full_32_byte_view() {
        // The killswitch + audit paths take `as_bytes()` and hand it to
        // sqlx for the `bearer_sha256 = $1` predicate. Pin both the length
        // and the back-to-back equality with the raw `[u8; 32]` so a future
        // refactor that returned a hex string (or truncated head) would
        // surface here.
        let h = BearerHash::of("pxl_live_AAAA");
        let bytes = h.as_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, &h.0);
    }

    #[test]
    fn bearer_hash_debug_truncates_to_short_prefix() {
        // The Debug impl is what shows up in tracing fields for
        // correlation. A regression that printed the full 64-char hex
        // would let log aggregators store rotatable secrets in plain text.
        let h = BearerHash::of("pxl_live_AAAA");
        let dbg = format!("{h:?}");
        let full_hex: String = h.0.iter().map(|b| format!("{b:02x}")).collect();
        assert!(dbg.contains("BearerHash("));
        assert!(!dbg.contains(&full_hex), "Debug must not include full hash",);
        // The 4-byte prefix (8 hex chars) IS visible — that's the design.
        let head: String = h.0[..4].iter().map(|b| format!("{b:02x}")).collect();
        assert!(dbg.contains(&head));
    }

    #[test]
    fn two_generated_bearers_are_distinct() {
        // 256 bits of entropy per token — collision probability is
        // negligible at scale 2, so a regression that hard-coded a sample
        // value or reset the RNG would surface immediately.
        let a = Bearer::generate();
        let b = Bearer::generate();
        assert_ne!(a.as_str(), b.as_str());
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn parse_rejects_empty_string_and_prefix_only() {
        // Two boundaries the existing tests skipped: an empty string
        // (auth middleware sometimes receives this from a header
        // present with no value) and the prefix alone (length 9, no
        // body). Both must reject — pin the `len != TOKEN_LEN` check
        // catching them on the fast path rather than falling through
        // to the alphabet scan.
        assert!(Bearer::parse("").is_none());
        assert!(Bearer::parse(PREFIX).is_none());
        // Half-typed bearer (prefix + 26 chars of body) — must also
        // reject. A regression that loosened the length check to a
        // minimum bound would surface here.
        let half = format!("{PREFIX}{}", "A".repeat(26));
        assert!(Bearer::parse(&half).is_none());
    }

    #[test]
    fn parse_returns_input_slice_byte_for_byte_when_valid() {
        // `parse` returns `Some(input)` — the same slice it was handed.
        // Pin the byte-for-byte identity so a future refactor that
        // normalized the body (e.g. ToAscii) would surface here. The
        // auth middleware passes the parsed slice into a SHA-256
        // hasher; any normalization would silently invalidate every
        // bearer hash already in the database.
        let b = Bearer::generate();
        let parsed = Bearer::parse(b.as_str()).unwrap();
        assert_eq!(parsed.as_bytes(), b.as_str().as_bytes());
        assert_eq!(parsed.len(), TOKEN_LEN);
    }

    #[test]
    fn bearer_hash_clone_yields_independent_array() {
        // `BearerHash` is `Clone` so the killswitch path can stash a
        // copy in the kill_cache without consuming the original. Pin
        // that the clone owns its `[u8; 32]` (arrays are Copy, so this
        // is trivially true today — but a refactor to `Box<[u8; 32]>`
        // would change the semantic and could land an Rc-shared
        // buffer through the wrong constructor).
        let a = BearerHash::of("pxl_live_AAAA");
        let mut b = a.clone();
        // Mutate b — a must be unaffected.
        b.0[0] ^= 0xff;
        assert_ne!(a.0[0], b.0[0]);
    }

    #[test]
    fn bearer_hash_partial_eq_distinguishes_different_inputs() {
        // BearerHash derives PartialEq+Eq; pin both axes — equal inputs hash
        // equal, distinct inputs hash distinct. The middleware uses Eq to
        // detect a hash-already-revoked condition; a future refactor that
        // broke it would silently miss every match.
        let a = BearerHash::of("pxl_live_AAAA");
        let b = BearerHash::of("pxl_live_AAAA");
        let c = BearerHash::of("pxl_live_BBBB");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
