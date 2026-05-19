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
    fn prefix_constant_is_byte_exact_pxl_underscore_live_underscore() {
        // PREFIX is the version tag the auth middleware AND the dashboard
        // UI's "this looks like a live bearer" copy-detector both key on.
        // A refactor to `pxl-live-` (kebab) or `proxilion_live_` (longer
        // brand prefix) would silently break every operator's grep + every
        // existing bearer in the database (the SHA-256 hash includes the
        // prefix bytes). Pin the byte sequence AND the length explicitly
        // so a change to either surfaces here AND in the consumer pins.
        assert_eq!(PREFIX, "pxl_live_");
        assert_eq!(PREFIX.len(), 9);
        assert_eq!(PREFIX.as_bytes(), b"pxl_live_");
    }

    #[test]
    fn token_len_equals_prefix_plus_fifty_two_base32_chars_per_spec() {
        // TOKEN_LEN is structurally `PREFIX.len() + 52` — the base32-of-
        // 32-bytes-unpadded encoding is exactly 52 chars (⌈32·8/5⌉ = 52).
        // A refactor to padded base32 would push to 56 chars; a swap to
        // base64-url would push to 43; either would change TOKEN_LEN AND
        // invalidate every existing stored bearer. Pin all three constants
        // (RAW_BYTES + PREFIX.len() + TOKEN_LEN) so a refactor of any one
        // without the others surfaces as a structural mismatch here.
        assert_eq!(RAW_BYTES, 32);
        assert_eq!(TOKEN_LEN, 61);
        assert_eq!(TOKEN_LEN, PREFIX.len() + 52);
    }

    #[test]
    fn bearer_hash_method_matches_bearer_hash_of_as_str_for_generated_token() {
        // `Bearer::hash()` is a convenience wrapper over
        // `BearerHash::of(self.as_str())`. The middleware path uses both
        // forms (the auth handler hashes `Bearer::generate().hash()`;
        // the killswitch handler hashes the bearer string it pulled out
        // of a SQL row via `BearerHash::of`). A refactor that diverged
        // them (e.g. `Bearer::hash()` started salting with a per-process
        // nonce "for cache-key uniqueness") would silently make every
        // newly issued bearer un-revokable via the killswitch path —
        // because the bearer middleware's lookup hash wouldn't match
        // the killswitch handler's. Pin the equivalence directly.
        let b = Bearer::generate();
        assert_eq!(b.hash(), BearerHash::of(b.as_str()));
    }

    #[test]
    fn parse_rejects_body_with_mixed_uppercase_and_lowercase_chars() {
        // The alphabet check `b'A'..=b'Z' | b'2'..=b'7'` is uppercase-only.
        // A body that mixes case (e.g. `AaAa...`) MUST reject — a refactor
        // that swapped to `.to_ascii_uppercase()` before alphabet check
        // "for operator-typing tolerance" would silently widen the accept
        // set and break the SHA-256 hash identity (the auth middleware
        // hashes the slice byte-for-byte). Pin both a mixed-case shape
        // AND a single lowercase char in an otherwise valid body.
        let mixed = format!(
            "{PREFIX}{}",
            "AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
        );
        assert_eq!(mixed.len(), TOKEN_LEN);
        assert!(Bearer::parse(&mixed).is_none(), "mixed case must reject");
        // One lowercase char in an otherwise valid uppercase body.
        let one_low = format!("{PREFIX}{}{}", "a", "A".repeat(51));
        assert_eq!(one_low.len(), TOKEN_LEN);
        assert!(
            Bearer::parse(&one_low).is_none(),
            "single lowercase must reject"
        );
    }

    #[test]
    fn parse_rejects_body_with_url_safe_or_padding_chars() {
        // RFC 4648 base32 (the variant we use) excludes the base32-hex
        // alphabet's `=` padding char AND the base64-url alphabet's `-`
        // and `_`. A refactor that swapped to base32hex or base64-url
        // "for shorter tokens" would still produce valid-length strings
        // but would silently change the wire shape — break every existing
        // stored bearer. Pin each excluded char.
        for bad in ['=', '-', '_', '+', '/'] {
            let body: String = std::iter::once(bad)
                .chain(std::iter::repeat_n('A', 51))
                .collect();
            let s = format!("{PREFIX}{body}");
            assert_eq!(s.len(), TOKEN_LEN);
            assert!(
                Bearer::parse(&s).is_none(),
                "char {bad} should not parse but did",
            );
        }
    }

    #[test]
    fn bearer_hash_of_is_deterministic_across_distinct_input_lengths() {
        // `BearerHash::of` is `sha256(input.as_bytes())` — pin determinism
        // across input lengths (empty, single byte, full token, oversized
        // 1KB). The killswitch handler hashes whatever string it pulled
        // out of `agent_bearers.bearer`; a refactor that truncated the
        // input before hashing "for SHA-256 performance" (sha256 is fast
        // enough at any size) would silently make all-equal-prefix bearers
        // collide. Pin self-equality across lengths AND distinctness across
        // distinct inputs at the same length.
        let empty_a = BearerHash::of("");
        let empty_b = BearerHash::of("");
        assert_eq!(empty_a, empty_b);
        let one_a = BearerHash::of("x");
        let one_b = BearerHash::of("x");
        assert_eq!(one_a, one_b);
        assert_ne!(empty_a, one_a);
        let long = "A".repeat(1024);
        let long_a = BearerHash::of(&long);
        let long_b = BearerHash::of(&long);
        assert_eq!(long_a, long_b);
        // Distinctness: 1024 'A's vs 1024 'B's hash differently.
        let other_long = "B".repeat(1024);
        assert_ne!(long_a, BearerHash::of(&other_long));
    }

    #[test]
    fn bearer_and_bearer_hash_are_send_sync_static_for_axum_extractor_boundary() {
        // The auth middleware extractor holds `Bearer` across `.await`
        // points in the request handler, and the killswitch+kill_cache
        // paths hold `BearerHash` across async boundaries on the
        // tokio runtime. An `Rc<String>` field on `Bearer` "for cheap
        // clone of the inner string" or a `Cell<[u8; 32]>` on
        // `BearerHash` "for interior-mutable rehashing on demand" would
        // break `Send` and surface at the AppState/handler assembly
        // site with an opaque tower::Service trait-bound rather than at
        // this file. Pin all three bounds (`Send + Sync + 'static`) on
        // BOTH types so a refactor of either lands clean diagnostics.
        fn require_send_sync_static<T: Send + Sync + 'static>(_: &T) {}
        let b = Bearer::generate();
        let h = b.hash();
        require_send_sync_static(&b);
        require_send_sync_static(&h);
    }

    #[test]
    fn bearer_hash_of_byte_exact_for_well_known_sha256_vector_abc() {
        // SHA-256 of "abc" is one of the most widely cross-published
        // test vectors (FIPS 180-4 §B.1 + RFC 6234 §A.5):
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        // `BearerHash::of` is `sha256(input.as_bytes())`. Pin the
        // byte-exact 32-byte output for this vector so a refactor that
        // swapped the hash function (e.g. to BLAKE3 "for speed") OR
        // that prepended a per-process salt "for cache-key uniqueness"
        // would surface here against the canonical FIPS vector — not as
        // a flaky downstream production incident months later when an
        // old bearer's stored hash mysteriously stopped matching.
        let h = BearerHash::of("abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(h.as_bytes(), &expected);
    }

    #[test]
    fn bearer_generate_emits_prefix_exactly_once_at_offset_zero() {
        // The generator concats PREFIX + 52-char base32 body — the prefix
        // appears exactly once, at byte offset 0, with no internal
        // duplication. A refactor that, e.g., changed `format!("{PREFIX}
        // {enc}")` to `format!("{PREFIX}{PREFIX}{enc}")` (an easy
        // mistake when wrapping for env-tag like `pxl_test_pxl_live_…`)
        // would surface here. Pin BOTH that the prefix occurs exactly
        // once AND that it occupies bytes [0..9), not somewhere later
        // (e.g. a refactor that produced `<base32>pxl_live_<base32>`).
        let b = Bearer::generate();
        let s = b.as_str();
        let count = s.matches(PREFIX).count();
        assert_eq!(count, 1, "PREFIX should appear exactly once, got {count}");
        assert_eq!(&s[..PREFIX.len()], PREFIX, "PREFIX must be at offset 0");
    }

    #[test]
    fn bearer_hash_of_is_referentially_transparent_across_fifty_repeated_calls() {
        // Hashing is pure; pin determinism explicitly across 50 sequential
        // calls on the same input. A refactor that introduced any form of
        // hidden state (a per-process counter, a static OnceCell salt, a
        // PRNG-seeded XOR layer "to defeat rainbow tables" — already
        // pointless for 256-bit bearers) would surface here on the first
        // diverging call. The existing `hash_is_stable` pin only checks
        // two calls; widen to 50 so an N-th-call special case surfaces.
        let base = BearerHash::of("pxl_live_repeat_test");
        for i in 0..50 {
            let again = BearerHash::of("pxl_live_repeat_test");
            assert_eq!(again, base, "hash drifted on iteration {i}");
        }
    }

    #[test]
    fn bearer_as_str_returns_slice_covering_full_token_length() {
        // `as_str` returns a view over the inner `String` — pin that
        // the slice spans the FULL TOKEN_LEN bytes, not a truncated
        // head or a redaction shape. The auth middleware feeds this
        // slice directly into `BearerHash::of`, so any accessor-level
        // mangling would silently break the SHA-256 identity that the
        // killswitch path's lookup keys on. A refactor that returned
        // `&self.0[..PREFIX.len()]` "for safe logging" would surface
        // here. Pin both the length AND that the slice begins with
        // PREFIX (i.e. the accessor returned the head, not the tail).
        let b = Bearer::generate();
        let s = b.as_str();
        assert_eq!(s.len(), TOKEN_LEN);
        assert!(s.starts_with(PREFIX));
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

    #[test]
    fn one_thousand_generated_bearers_yield_one_thousand_distinct_hashes() {
        // 256-bit entropy per token means birthday collisions are
        // negligible at scale 1000 (~5e-71 expected). Pin distinctness
        // across 1000 generations so a refactor that, e.g., re-seeded
        // the RNG once per process from a static value "for replayable
        // tests" or that hard-coded a sample body in a debug build
        // would surface immediately — the HashSet would shrink below
        // 1000 and the assertion would carry the exact diff in the
        // failure message. The existing `two_generated_bearers_are_distinct`
        // pin only checks N=2; widen to N=1000 so an N-th-call special
        // case (e.g. a free-list-style counter that wrapped) surfaces.
        use std::collections::HashSet;
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let b = Bearer::generate();
            seen.insert(b.hash().0);
        }
        assert_eq!(seen.len(), 1000, "bearer collision in 1000 generations");
    }
}
