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
    fn bearer_parse_return_type_is_option_borrowed_str_via_fn_pointer_witness() {
        // `Bearer::parse` is called from the auth middleware on the
        // Authorization-header bearer-extract path and returns `Some(input)` —
        // the SAME borrowed slice it was handed. Pin the return type as
        // `Option<&'a str>` via a fn-pointer witness with explicit lifetime
        // so a refactor that returned `Option<String>` "to give downstream a
        // standalone owned value" would silently heap-allocate per request
        // AND would break the `parse_returns_input_slice_byte_for_byte_when_valid`
        // byte-equality pin's call chain (which threads the very same
        // borrowed slice into a SHA-256 hasher; a normalized owned copy
        // would silently invalidate every persisted bearer hash). The
        // fn-pointer witness is the load-bearing type-level catch — the
        // 'a lifetime binds the input borrow to the output borrow.
        // Symmetric to round-216 GoogleClient::from_env return-type +
        // round-215 verify_pkce_s256 return-type fn-pointer pins.
        let _f: for<'a> fn(&'a str) -> Option<&'a str> = Bearer::parse;
    }

    #[test]
    fn bearer_hash_of_return_type_is_owned_self_by_value_via_fn_pointer_witness() {
        // `BearerHash::of` is called from BOTH the auth middleware (hashes
        // the bearer just extracted from the header) AND the killswitch
        // path (hashes the bearer string pulled out of a SQL row). Pin the
        // return type as OWNED `BearerHash` by-value via a fn-pointer
        // witness so a refactor to `Arc<BearerHash>` "for cheap cross-task
        // share" would force every call site to deref or .as_ref() —
        // breaking the kill_cache `Arc<dyn ActionStream>`-shape AppState
        // contract — AND would silently change the per-call ownership
        // semantic the killswitch handler relies on. The owned-by-value
        // shape is load-bearing for the kill_cache `mark` write path
        // which takes `[u8; 32]` by-value (see kill_cache round-201 pin
        // `mark_signature_takes_owned_hash_by_value`).
        let _f: fn(&str) -> BearerHash = BearerHash::of;
    }

    #[test]
    fn bearer_generate_return_type_is_owned_self_by_value_via_fn_pointer_witness() {
        // `Bearer::generate` is the boot-time + ad-hoc bearer-mint helper —
        // production wires it through the `/api/v1/agents` POST handler.
        // Pin the return type as OWNED `Bearer` by-value via a fn-pointer
        // witness so a refactor to `Result<Bearer, RngError>` "for surface-
        // visible RNG-failure triage" (rand 0.8's `OsRng::fill_bytes` is
        // infallible by construction; surfacing a Result would break every
        // handler that today writes `let b = Bearer::generate();` without a
        // `?`) would surface here at the fn-pointer type rather than at the
        // far-removed handler call site. The OWNED-by-value (not
        // `Arc<Bearer>`) arm is also load-bearing — the handler hands the
        // bearer off into a SQL INSERT then drops it; an Arc-wrap would
        // force a deref at every accessor call.
        let _f: fn() -> Bearer = Bearer::generate;
    }

    #[test]
    fn bearer_hash_as_bytes_return_type_is_borrowed_slice_view_via_fn_pointer_witness() {
        // `BearerHash::as_bytes` is called from the killswitch + audit
        // paths and feeds the slice directly into sqlx's `bearer_sha256 = $1`
        // bind. Pin the return type as `&[u8]` borrowed-slice-view via a
        // fn-pointer witness with explicit lifetime so a refactor that
        // returned `Vec<u8>` "to give downstream an owned copy for cross-
        // await persistence" would silently heap-allocate per call AND
        // break the existing `bearer_hash_as_bytes_returns_full_32_byte_view`
        // pin's slice-identity contract (which checks `bytes == &h.0`).
        // The borrowed-slice arm is load-bearing for sqlx's `&[u8]` bind
        // path which avoids the extra Vec allocation on the hot path.
        // Symmetric to round-210 EmailNotifier::proxy_public_url() &str
        // borrowed-view pin extended to this sibling accessor.
        let _f: for<'a> fn(&'a BearerHash) -> &'a [u8] = BearerHash::as_bytes;
    }

    #[test]
    fn bearer_hash_inner_field_is_array_32_bytes_not_vec_or_arc_via_destructure() {
        // `BearerHash` has EXACTLY ONE tuple-struct field: `[u8; 32]`
        // (the SHA-256 output). Pin the inner-field type via a destructure
        // with explicit `[u8; 32]` binding so a refactor to `Vec<u8>` "for
        // dynamic-length-hash future-proofing" OR `Arc<[u8; 32]>` "for
        // cheap clone" would surface here. The fixed-size array shape is
        // load-bearing for: (a) the kill_cache's `[u8; 32]` key type
        // (round-201 `mark_signature_takes_owned_hash_by_value`), (b) the
        // `as_bytes` zero-copy slice view (it returns `&self.0`), and
        // (c) the `Debug` impl's `self.0[..4]` slice (which would change
        // semantics under Vec/Arc indexing). A refactor to either would
        // ripple through all three consumers.
        let h = BearerHash::of("pxl_live_AAAA");
        let BearerHash(inner) = h;
        let _check: [u8; 32] = inner;
    }

    #[test]
    fn prefix_constant_type_is_static_str_for_format_macro_const_concat_compat() {
        // `PREFIX: &str` is the `&'static str` type the format macro
        // `format!("{PREFIX}{enc}")` in `Bearer::generate` interpolates
        // verbatim. Pin the type via a fn-pointer witness so a refactor
        // to `lazy_static! { static ref PREFIX: String = ... }` "for
        // runtime-configurable bearer prefix per environment (test/staging/
        // prod)" would force a Deref coercion at every interpolation site
        // AND would break the `prefix_constant_is_byte_exact_pxl_underscore_live_underscore`
        // existing pin's `PREFIX.as_bytes() == b"pxl_live_"` byte-identity
        // contract (which depends on the static literal's stable allocation).
        // The `&'static str` lifetime is also load-bearing for: (a) the
        // `&input[PREFIX.len()..]` slice op in `parse`, and (b) the
        // `format!("{PREFIX}{enc}")` const-concat optimization. Symmetric
        // to round-213 CURRENT_PIC_PROFILE &'static str pin.
        fn require_static_str(_: &'static str) {}
        require_static_str(PREFIX);
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

    // ─── round 246 (2026-05-22): Bearer tuple-struct field-count + inner-
    // type layout, as_str + hash fn-pointer witnesses, BearerHash derived-
    // traits, RAW_BYTES + TOKEN_LEN usize-static type pins ───

    #[test]
    fn bearer_tuple_struct_field_count_pinned_at_exactly_one_string_via_exhaustive_destructure() {
        // `Bearer(String)` — tuple struct with EXACTLY 1 positional
        // field. A 2nd field landing (e.g. `Bearer(String,
        // chrono::DateTime<Utc>)` "for capturing mint-time on each
        // bearer for telemetry" OR `Bearer(String, BearerHash)` "to
        // pre-compute the hash and avoid recomputing on every middleware
        // dispatch") without matching `Bearer::generate()` construction
        // wiring would silently zero-initialize the new field on every
        // bearer mint — and the manual `Debug` impl
        // ([bearer.rs:53](crates/proxy/src/crypto/bearer.rs#L53)) would
        // also need updating to redact the new field. Pin the
        // 1-positional layout via exhaustive destructure with no `..`
        // rest pattern so a refactor surfaces at this file. Symmetric
        // to round-242's `cache_error_db_variant_layout_pinned_tuple_via_exhaustive_destructure_one_positional_inner_sqlx`
        // extended to this sibling secret-bearing wrapper.
        let b = Bearer::generate();
        let Bearer(_inner) = b;
    }

    #[test]
    fn bearer_inner_field_pinned_owned_string_via_explicit_type_destructure_binding() {
        // `Bearer(String)` — the inner is owned `String`, NOT
        // `&'static str` or `Cow<'static, str>`. The bearer is minted
        // at runtime via random RNG (no static literal); the wrapper
        // crosses an `.await` in the POST `/api/v1/agents` handler
        // (the SQL INSERT path holds the bearer string until persistence
        // completes). A refactor to `Bearer(&'static str)` is
        // impossible by construction (no static literal for random
        // tokens), but a refactor to `Bearer(Cow<'a, str>)` "for
        // borrow-or-own flexibility" would introduce a lifetime
        // parameter that cascades through every `AuthState` accessor.
        // Pin via explicit `let s: String = inner;` type ascription
        // after destructure so a width-drift refactor surfaces here.
        // Symmetric to round-242's
        // `cached_pca_pic_profile_field_pinned_owned_string_via_require_for_runtime_drift_marker`
        // extended to this sibling secret-bearing wrapper inner.
        let b = Bearer::generate();
        let Bearer(inner) = b;
        let _check: String = inner;
    }

    #[test]
    fn bearer_as_str_signature_self_borrow_returns_str_borrow_via_fn_pointer_witness() {
        // `Bearer::as_str(&self) -> &str` — takes `&self` BORROW,
        // returns `&str` BORROW into the inner String. The auth
        // middleware feeds this slice directly into `BearerHash::of`
        // — the borrow's lifetime is the Bearer's lifetime. A refactor
        // to `pub fn as_str(self) -> String` "for ownership transfer"
        // OR `pub fn as_str(&self) -> String` "to give downstream an
        // owned copy" would force a heap allocation per middleware
        // dispatch AND would break the SHA-256 hash identity (the
        // owned String's bytes would equal the borrow's bytes, but the
        // call shape would force consumers to bind a temporary that
        // shortens the slice's lifetime). Pin via fn-pointer witness
        // with explicit `for<'a> fn(&'a Bearer) -> &'a str` so a
        // signature drift surfaces here at the type boundary.
        // Symmetric to round-218's
        // `bearer_hash_as_bytes_return_type_is_borrowed_slice_view_via_fn_pointer_witness`
        // extended to this sibling accessor.
        let _f: for<'a> fn(&'a Bearer) -> &'a str = Bearer::as_str;
    }

    #[test]
    fn bearer_hash_method_signature_self_borrow_returns_owned_bearer_hash_via_fn_pointer_witness() {
        // `Bearer::hash(&self) -> BearerHash` — takes `&self` BORROW,
        // returns OWNED `BearerHash` by value. The middleware's
        // hot-path bearer-revocation check calls
        // `bearer.hash()` to compare against the kill_cache; the
        // owned-by-value return shape lets the caller move the
        // BearerHash into the kill_cache lookup without an Arc bump.
        // A refactor to `Bearer::hash(&self) -> Arc<BearerHash>` "for
        // cheap cross-task share" OR to `Bearer::hash(self) ->
        // BearerHash` "consuming the bearer at hash time" would
        // foreclose: (a) the `cache.contains(bearer.hash())` lookup
        // pattern that holds the bearer for subsequent reads, and
        // (b) the bearer-survives-hash invariant the auth middleware
        // relies on for `req.extensions_mut().insert(Arc::new(session))`
        // mid-flow. Pin via fn-pointer witness. Symmetric to
        // round-218's
        // `bearer_hash_of_return_type_is_owned_self_by_value_via_fn_pointer_witness`
        // extended to this sibling builder-method.
        let _f: fn(&Bearer) -> BearerHash = Bearer::hash;
    }

    #[test]
    fn bearer_hash_required_derived_traits_clone_partial_eq_eq_via_require_for_revocation_lookup() {
        // `#[derive(Clone, PartialEq, Eq)]` on `BearerHash` — the
        // killswitch + audit paths rely on all three:
        //   * `Clone` — the kill_cache write path takes the hash
        //     by-value; the caller clones to retain a reference for
        //     subsequent reads.
        //   * `PartialEq + Eq` — the middleware compares the inbound
        //     bearer's hash against the kill_cache's recorded hash via
        //     `==` for the revocation check.
        // A refactor that dropped any of the three derives "for
        // explicit semantics" would: drop Clone → force every caller
        // to manually copy the `[u8; 32]` and rebuild a BearerHash;
        // drop PartialEq+Eq → force every comparison site to walk
        // `.0` byte-by-byte. Pin all three via require_traits so a
        // derive removal surfaces here rather than at the kill_cache
        // call site. Symmetric to round-225's webhook signing-secret
        // derived-traits pin extended to this sibling revocation-
        // identity wrapper.
        fn require_clone_eq<T: Clone + PartialEq + Eq>() {}
        require_clone_eq::<BearerHash>();
    }

    #[test]
    fn raw_bytes_and_token_len_constants_both_usize_for_layout_invariant_compile_time_compat() {
        // Module-private constants `RAW_BYTES: usize = 32` and
        // `TOKEN_LEN: usize = 61` (= 9 + 52). Both ARE pinned as `usize`
        // implicitly by the `pub fn parse(input: &str)` slice-index op
        // (`input[PREFIX.len()..]` requires `usize`) but the TYPE has
        // never been DIRECTLY pinned. A refactor to `u32` "for SQL
        // int4 alignment when surfaced via API envelope" would force a
        // cast at every slice site AND would silently change the
        // overflow domain on the `if input.len() != TOKEN_LEN` guard
        // (string len is `usize`; a `u32` comparison would force a
        // `usize→u32` cast that panics on inputs above `u32::MAX` on
        // 64-bit hosts). Pin both constants as `usize` via
        // require_usize. Symmetric to round-242's
        // `cached_pca_hop_field_pinned_i32_via_require_for_postgres_int4_signed_domain`
        // (which pins `i32` for postgres int4 contract); this pins
        // `usize` for str-len compatibility. The existing
        // `token_len_equals_prefix_plus_fifty_two_base32_chars_per_spec`
        // pin walks the VALUES; pin the TYPES here in lockstep.
        fn require_usize(_: usize) {}
        require_usize(RAW_BYTES);
        require_usize(TOKEN_LEN);
    }

    // ─── round 294 (2026-05-26): Bearer/BearerHash Send+Sync + Debug-safety + layout pins ───

    #[test]
    fn bearer_and_bearer_hash_both_send_and_sync_directly_for_axum_middleware_cross_await_propagation()
     {
        // `Bearer` AND `BearerHash` both flow through the bearer
        // middleware at [crates/proxy/src/auth_middleware.rs](../auth_middleware.rs)
        // across `.await` boundaries — `BearerHash` rides in the
        // SessionContext extracted on every request AND `Bearer`
        // lives in the OAuth callback's `bearer.hash()` call site
        // before being moved into the encrypted-storage path. Pin
        // Send+Sync directly on BOTH types (rather than via a
        // composite Send+Sync+'static at the wrap site) so a
        // refactor that landed a `Rc<...>` OR `Cell<...>` inner
        // field on EITHER type would surface here at the type
        // boundary rather than at the auth-middleware tower::Service
        // trait cascade. Symmetric to round-292
        // `tee_stream_is_send_and_sync_directly_for_arc_dyn_action_stream_object_safety`
        // + round-293 `pkce_error_is_sync_directly_not_just_via_static_for_async_oauth_callback_middleware`
        // extended to this sibling bearer-credential pair.
        fn require_send<T: Send>() {}
        fn require_sync<T: Sync>() {}
        require_send::<Bearer>();
        require_sync::<Bearer>();
        require_send::<BearerHash>();
        require_sync::<BearerHash>();
    }

    #[test]
    fn prefix_constant_byte_exact_pxl_live_with_namespace_structure_pinned_for_token_family_contract()
     {
        // `PREFIX = "pxl_live_"` (line 12) — the operator-visible
        // token family marker. The existing
        // `prefix_constant_type_is_static_str_for_format_macro_const_concat_compat`
        // pin walks the TYPE axis (`&'static str`); pin the
        // STRUCTURAL byte-exact contract here. The 9-byte prefix
        // distinguishes live agent bearers from sibling token
        // families: `pxl_operator_` (operator-auth tokens, see
        // operator_auth.rs SCOPE_CATALOGUE family discriminator),
        // `pxl_test_` (test-only tokens not yet wired), and any
        // future `pxl_<family>_` namespace. A refactor that
        // collapsed the prefix to `pxl_` "for ergonomic prefix
        // testing" would silently merge the live + operator token
        // families AND break the dashboard's family-discriminator
        // panel that anchors on the byte-exact prefix. Pin the
        // exact 9-byte literal AND the structural `pxl_<family>_`
        // shape so a one-byte drift surfaces. Symmetric to
        // round-290 CURRENT_PIC_PROFILE namespace+version pin
        // extended to this sibling token-family namespace.
        assert_eq!(PREFIX, "pxl_live_");
        assert_eq!(PREFIX.len(), 9);
        assert!(PREFIX.starts_with("pxl_"));
        assert!(PREFIX.ends_with("_"));
        // Defensive: the family token "live" sits between the two
        // underscores at offset 4..8.
        assert_eq!(&PREFIX[4..8], "live");
        // Pairwise-distinct from the sibling operator token family
        // (operator_auth.rs uses `pxl_operator_` — a refactor that
        // accidentally collapsed both to the same prefix would
        // break per-family middleware dispatch).
        assert_ne!(PREFIX, "pxl_operator_");
    }

    #[test]
    fn token_len_constant_equals_exactly_sixty_one_via_prefix_nine_plus_body_fifty_two_for_layout()
    {
        // `TOKEN_LEN = PREFIX.len() + 52` (line 15) — the FULL
        // bearer-string byte length used by `Bearer::parse` to
        // reject any wrong-length input. The existing
        // `token_len_equals_prefix_plus_fifty_two_base32_chars_per_spec`
        // pin checks the symbolic formula `PREFIX.len() + 52`; pin
        // the NUMERIC VALUE 61 here so a refactor that legitimately
        // bumps the namespace prefix (`pxl_live_` → `pxl_live_v2_`)
        // would surface here as a constant-value drift — AND the
        // bumped prefix would land WITHOUT a coordinated rev of the
        // base32 body width. The numeric pin gives a second anchor
        // a refactor can't satisfy by just updating PREFIX. Symmetric
        // to round-285 `siem_forwarder_max_retries_default_pinned_at_exactly_three`
        // numeric-value pin extended to this sibling token-layout
        // constant.
        assert_eq!(
            TOKEN_LEN, 61,
            "TOKEN_LEN must equal 61 = 9-byte prefix + 52-char base32 body"
        );
        // And the formula must hold (the existing test pins this
        // axis; cross-anchor here so a one-side refactor surfaces
        // here at the numeric value rather than only at the
        // formula).
        assert_eq!(TOKEN_LEN, PREFIX.len() + 52);
    }

    #[test]
    fn bearer_debug_rendering_does_not_contain_pxl_live_prefix_or_any_base32_body_substring() {
        // The existing `debug_does_not_leak` pin checks that the
        // full token string doesn't appear in the Debug output;
        // tighten the contract here so a refactor that displayed
        // ONLY the prefix (e.g. `Bearer("pxl_live_…")` to "give
        // operators a token-family hint without leaking the body")
        // would still surface as a regression. The pxl_live_ prefix
        // itself MUST NOT appear in Debug output — combined with
        // the existing pin, this catches a wider class of
        // half-leakage refactors. Pin three byte-substring
        // negations: the PREFIX, ANY 8-char base32 substring from
        // the body, AND the literal "redacted" marker which IS
        // expected in the canonical render.
        let b = Bearer::generate();
        let dbg = format!("{b:?}");
        assert!(
            !dbg.contains("pxl_live_"),
            "Bearer Debug must NOT contain the token-family prefix, got: {dbg}"
        );
        let body = &b.as_str()[PREFIX.len()..];
        // First 8 chars of the body — if these leak, an attacker
        // with log access has 40 bits of the 256-bit token and
        // the rest is brute-forceable.
        let body_head: String = body.chars().take(8).collect();
        assert!(
            !dbg.contains(&body_head),
            "Bearer Debug must NOT contain any 8-char base32 body substring"
        );
        // Positive marker: the canonical "redacted" marker IS
        // present, distinguishing the safe "redacted" render from
        // a hypothetical empty-Debug refactor.
        assert!(
            dbg.contains("redacted"),
            "Bearer Debug must contain the canonical `redacted` marker"
        );
    }

    #[test]
    fn bearer_hash_debug_rendering_carries_only_first_four_bytes_as_eight_hex_chars_for_log_safety()
    {
        // The custom Debug impl at line 75-84 renders BearerHash as
        // `BearerHash(<8-hex>…)` — first 4 bytes (8 hex chars) of
        // the 32-byte hash, then an ellipsis. Operators correlate
        // by the 8-hex prefix in logs without exposing enough hash
        // to invert against rainbow tables (4 bytes = 32 bits;
        // SHA-256 preimage resistance at full output means even 4
        // bytes shown is fine — a refactor that widened the
        // truncation to e.g. 16 hex chars (8 bytes / 64 bits)
        // would weaken the contract). Pin the 8-hex-char shape
        // byte-exact via direct substring assertion + length-bound
        // sweep. The first 4 bytes of `BearerHash::of("test")`
        // (SHA-256 of "test") are deterministic — pin against the
        // known prefix `9f86d081`. Symmetric to round-291
        // `error_body_with_fix_signature_pinned_via_fn_pointer_witness`
        // operator-log-safety pin extended to this sibling
        // BearerHash Debug rendering.
        let h = BearerHash::of("test");
        let dbg = format!("{h:?}");
        // SHA-256("test") starts with bytes 9f 86 d0 81 ... — pin
        // the 8-hex-char prefix in the Debug output.
        assert!(
            dbg.contains("9f86d081"),
            "BearerHash Debug must contain SHA-256(\"test\") 8-hex prefix, got: {dbg}"
        );
        // And the Debug output's length is bounded — the format
        // is `BearerHash(<8>…)` so length ≈ 11 + 8 + 4 (ellipsis is
        // 3-byte UTF-8) = 23 bytes. A refactor that widened the
        // truncation to 16 hex chars would land at length 31. Pin
        // the upper bound conservatively at 25 bytes so a 16-hex
        // widening AND a hypothetical full-32-hex-byte render
        // both surface here.
        assert!(
            dbg.len() < 25,
            "BearerHash Debug must not leak more than 8-hex prefix, got {} bytes: {dbg}",
            dbg.len()
        );
        // Defensive: the full SHA-256 hex (64 chars) MUST NOT
        // appear — a refactor that removed the truncation would
        // surface here as the longer prefix substring would
        // suddenly match.
        let full_hex: String = h.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(full_hex.len(), 64);
        assert!(
            !dbg.contains(&full_hex),
            "BearerHash Debug must NOT contain the full 64-hex hash"
        );
    }

    #[test]
    fn bearer_hash_as_bytes_returns_exactly_thirty_two_bytes_for_sha256_output_width_contract() {
        // `BearerHash::as_bytes(&self) -> &[u8]` returns a borrowed
        // slice over the inner `[u8; 32]` array — the slice MUST be
        // exactly 32 bytes (the SHA-256 output width). The existing
        // `bearer_hash_inner_field_is_array_32_bytes_not_vec_or_arc_via_destructure`
        // pin walks the FIELD type at construction; pin the
        // ACCESSOR-output length here so a refactor that returned a
        // sub-slice (e.g. `&self.0[..16]` "for truncated hash
        // storage to save 16 bytes per row") would surface here as
        // a length drift. The sqlx column for `bearer_sha256` is
        // bytea sized 32; a 16-byte slice would either error at
        // bind time OR silently store a truncated hash that fails
        // every subsequent revocation lookup. Pin via direct
        // length assertion across multiple inputs. Symmetric to
        // round-284 `sha256_hex_output_width_pinned_at_sixty_four_lowercase_hex_chars`
        // extended to this sibling SHA-256 byte-width accessor.
        for s in [
            "",
            "abc",
            "test",
            "pxl_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let h = BearerHash::of(s);
            assert_eq!(
                h.as_bytes().len(),
                32,
                "BearerHash::as_bytes must return exactly 32 bytes for input {s:?}"
            );
        }
    }
}
