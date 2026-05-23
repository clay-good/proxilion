//! AES-256-GCM envelope encryption for Google OAuth tokens.
//!
//! Key is exactly 32 bytes; nonce is 96-bit random per message. We persist
//! nonce + ciphertext separately so the schema mirrors what AES-GCM actually
//! produces (the auth tag is appended to the ciphertext by `aes-gcm`).

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("encryption key must be exactly 32 bytes; got {0}")]
    BadKeyLen(usize),
    #[error("AES-GCM operation failed")]
    Aead,
}

#[derive(Debug, Clone)]
pub struct Ciphertext {
    pub nonce: Vec<u8>,
    pub bytes: Vec<u8>,
}

/// Holds the master encryption key. Never derive Debug-print the inner key.
pub struct TokenCipher {
    cipher: Aes256Gcm,
}

impl TokenCipher {
    pub fn from_bytes(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 32 {
            return Err(CipherError::BadKeyLen(key.len()));
        }
        let key = Key::<Aes256Gcm>::from_slice(key);
        Ok(Self {
            cipher: Aes256Gcm::new(key),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Ciphertext, CipherError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let bytes = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CipherError::Aead)?;
        Ok(Ciphertext {
            nonce: nonce.to_vec(),
            bytes,
        })
    }

    pub fn decrypt(&self, ct: &Ciphertext) -> Result<Vec<u8>, CipherError> {
        if ct.nonce.len() != 12 {
            return Err(CipherError::Aead);
        }
        let nonce = Nonce::from_slice(&ct.nonce);
        self.cipher
            .decrypt(nonce, ct.bytes.as_slice())
            .map_err(|_| CipherError::Aead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn round_trip() {
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let ct = c.encrypt(b"ya29.example-google-access-token").unwrap();
        assert_eq!(ct.nonce.len(), 12);
        let pt = c.decrypt(&ct).unwrap();
        assert_eq!(pt, b"ya29.example-google-access-token");
    }

    #[test]
    fn distinct_nonces() {
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let a = c.encrypt(b"hi").unwrap();
        let b = c.encrypt(b"hi").unwrap();
        assert_ne!(a.nonce, b.nonce, "nonce must be random per encryption");
        assert_ne!(
            a.bytes, b.bytes,
            "ciphertext must differ across encryptions"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let c1 = TokenCipher::from_bytes(&key()).unwrap();
        let mut bad = key();
        bad[0] ^= 1;
        let c2 = TokenCipher::from_bytes(&bad).unwrap();
        let ct = c1.encrypt(b"secret").unwrap();
        assert!(c2.decrypt(&ct).is_err());
    }

    #[test]
    fn short_key_rejected() {
        assert!(matches!(
            TokenCipher::from_bytes(&[0u8; 16]),
            Err(CipherError::BadKeyLen(16))
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected_by_gcm_tag() {
        // The GCM auth tag is appended to the ciphertext by `aes-gcm`; a
        // single-byte flip anywhere in `bytes` must surface CipherError::Aead
        // rather than yielding garbage plaintext. This is the AEAD contract —
        // a future refactor that switched to CTR-only would silently pass.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let mut ct = c.encrypt(b"some secret plaintext").unwrap();
        ct.bytes[0] ^= 1;
        let err = c.decrypt(&ct).unwrap_err();
        assert!(matches!(err, CipherError::Aead));
    }

    #[test]
    fn wrong_nonce_length_rejected_without_aead_call() {
        // The decrypt path pre-checks nonce.len() == 12 before handing to
        // aes-gcm. A persisted row with a corrupt nonce column would
        // otherwise panic inside `Nonce::from_slice` (which expects exactly
        // 12 bytes). Pin both the short and long cases.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let pt = c.encrypt(b"hi").unwrap();
        let short = Ciphertext {
            nonce: vec![0u8; 11],
            bytes: pt.bytes.clone(),
        };
        assert!(matches!(c.decrypt(&short), Err(CipherError::Aead)));
        let long = Ciphertext {
            nonce: vec![0u8; 13],
            bytes: pt.bytes,
        };
        assert!(matches!(c.decrypt(&long), Err(CipherError::Aead)));
    }

    #[test]
    fn ciphertext_clone_yields_independent_buffer() {
        // `Ciphertext` is `Clone` so the encryption helper can persist one
        // copy and hand another to the metrics path. Pin that the clone
        // owns its bytes (no shared backing storage that a later mutation
        // would corrupt across).
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let a = c.encrypt(b"value").unwrap();
        let mut b = a.clone();
        b.bytes[0] ^= 0xff;
        assert_ne!(a.bytes[0], b.bytes[0], "clone must own its buffer");
        assert!(c.decrypt(&a).is_ok(), "original still decrypts");
    }

    #[test]
    fn bad_key_len_error_display_includes_actual_length() {
        // Operators routinely paste a 16-byte hex string thinking it's a
        // 32-byte key (or a 64-char hex string forgetting to hex-decode).
        // The error message must surface the actual length so the
        // troubleshooting docs page can point at "expected 32, got N".
        let e = CipherError::BadKeyLen(17).to_string();
        assert!(e.contains("32"), "must mention required length");
        assert!(e.contains("17"), "must surface actual length");
    }

    #[test]
    fn empty_plaintext_round_trips_with_nonzero_ciphertext() {
        // The Google OAuth refresh-token field is optional — when the
        // upstream omits it, the proxy still encrypts an empty byte
        // slice to keep the schema's NOT NULL ciphertext column
        // satisfied (the Option wrapper lives one level up). Pin that
        // an empty plaintext yields a non-empty ciphertext (the GCM
        // auth tag is 16 bytes), and that decrypt round-trips it
        // back to empty.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let ct = c.encrypt(b"").unwrap();
        assert!(!ct.bytes.is_empty(), "GCM auth tag must be present");
        assert_eq!(ct.bytes.len(), 16, "empty PT + 16-byte tag");
        let pt = c.decrypt(&ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn large_plaintext_round_trips_through_encrypt_decrypt() {
        // OAuth ID tokens can be a few KB; pin that the cipher handles
        // a payload larger than the AES block size + nonce/tag overhead
        // without truncation. The fixed-size buffer scenario this
        // catches is a refactor that allocated a small `[u8; N]` for
        // the ciphertext instead of letting `aes-gcm` size the Vec.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let pt: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let ct = c.encrypt(&pt).unwrap();
        assert_eq!(ct.bytes.len(), pt.len() + 16, "GCM tag overhead");
        let back = c.decrypt(&ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn aead_error_display_is_stable_for_log_filters() {
        // Operator log filters key on the substring "AES-GCM operation
        // failed" for tamper / corrupt-row / wrong-key alerting.
        // The Display impl comes from `#[error("AES-GCM operation
        // failed")]` — pin it here so a future tweak ("AEAD failed",
        // "decryption failed") moves in lockstep with the alerting
        // rules. The BadKeyLen Display already has its actual-length
        // pinned elsewhere; this fills in the Aead arm.
        let s = CipherError::Aead.to_string();
        assert_eq!(s, "AES-GCM operation failed");
    }

    #[test]
    fn from_bytes_boundary_31_and_33_bytes_rejected_with_actual_length() {
        // The 32-byte requirement is the boundary; existing pins walk
        // 0 / 16 / empty but not the just-off-by-one shapes. Operators
        // who pasted a 64-char hex string have sometimes hex-decoded it
        // wrong and landed on 31 (a leading zero stripped) or 33 (an
        // extra nybble). Pin both boundaries so the error carries the
        // actual length — a refactor that pre-padded to 32 ("for
        // robustness") would silently accept a truncated key and the
        // produced ciphertext would later decrypt against the wrong
        // bytes.
        match TokenCipher::from_bytes(&[0u8; 31]) {
            Err(CipherError::BadKeyLen(31)) => {}
            Err(e) => panic!("expected BadKeyLen(31), got {e:?}"),
            Ok(_) => panic!("expected error for 31-byte key"),
        }
        match TokenCipher::from_bytes(&[0u8; 33]) {
            Err(CipherError::BadKeyLen(33)) => {}
            Err(e) => panic!("expected BadKeyLen(33), got {e:?}"),
            Ok(_) => panic!("expected error for 33-byte key"),
        }
    }

    #[test]
    fn decrypt_with_zero_length_nonce_rejected_without_panic() {
        // Boundary: the existing `wrong_nonce_length_rejected_without_aead_call`
        // pin walks 11 / 13 but not the explicit zero-byte nonce shape
        // (a corrupt-row scenario where the persisted `nonce` column
        // got NULL-treated-as-empty by a deserializer). The current
        // `ct.nonce.len() != 12` guard handles this — pin the no-panic
        // contract directly so a refactor that switched to
        // `Nonce::from_slice(&ct.nonce)` first (without the length
        // pre-check) would panic on the zero-length slice. The
        // `nonce.len() != 12` guard MUST come before any nonce slicing.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let pt = c.encrypt(b"hi").unwrap();
        let zero = Ciphertext {
            nonce: Vec::new(),
            bytes: pt.bytes,
        };
        assert!(matches!(c.decrypt(&zero), Err(CipherError::Aead)));
    }

    #[test]
    fn cipher_error_implements_std_error_trait_for_anyhow_chain_walking() {
        // Adapter call sites bubble CipherError through `anyhow::Error`
        // chains for structured logging at the OAuth-token-persist
        // path — pin that the `thiserror` derive lands the
        // `std::error::Error` impl for both variants. Both arms are
        // leaves (no inner error), so `source()` must return None.
        // A refactor that swapped to a hand-rolled error type and
        // forgot the trait would surface here at the dyn-cast rather
        // than only at the far `?` call site.
        let len: CipherError = CipherError::BadKeyLen(17);
        let aead: CipherError = CipherError::Aead;
        let dyn_len: &dyn std::error::Error = &len;
        let dyn_aead: &dyn std::error::Error = &aead;
        assert!(std::error::Error::source(dyn_len).is_none());
        assert!(std::error::Error::source(dyn_aead).is_none());
    }

    #[test]
    fn encrypt_empty_plaintext_still_yields_distinct_nonces_across_calls() {
        // The existing `distinct_nonces` pin walks `b"hi"`; pin the
        // empty-plaintext shape symmetrically. The Google OAuth
        // refresh-token field can be omitted (encrypted as empty),
        // and two consecutive empty encryptions must still produce
        // distinct nonces — a refactor that special-cased empty
        // plaintexts to a fixed nonce "for speed" would silently
        // collapse every empty-token row's IV onto a constant and
        // break the IV-uniqueness guarantee AES-GCM relies on.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let a = c.encrypt(b"").unwrap();
        let b = c.encrypt(b"").unwrap();
        assert_ne!(a.nonce, b.nonce, "nonce must be random per encryption");
        // The 16-byte auth tag will be deterministic for a constant
        // (empty) plaintext under the same key + nonce — but since
        // the nonces differ, the tag bytes must also differ.
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn ciphertext_debug_renders_field_names_for_operator_grep() {
        // `Ciphertext` derives Debug — the OAuth persistence path
        // sometimes traces a redacted ciphertext shape via
        // `tracing::debug!(?ct, ..)` during failure triage. Pin that
        // the rendered Debug includes the `nonce` and `bytes` field
        // names so an operator filter keyed on those substrings
        // works. A manual Debug that rendered the bytes inline
        // (e.g. as hex without the field names) would silently
        // strip the operator's grep handle. Note: this test does
        // NOT pin that the bytes are redacted — that's a separate
        // operator concern; the current derive renders them
        // verbatim.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let ct = c.encrypt(b"x").unwrap();
        let s = format!("{ct:?}");
        assert!(s.contains("nonce"), "got: {s}");
        assert!(s.contains("bytes"), "got: {s}");
        assert!(s.contains("Ciphertext"), "got: {s}");
    }

    #[test]
    fn nonce_is_exactly_12_bytes_per_aes_gcm_spec() {
        // AES-GCM's nonce MUST be exactly 12 bytes (96 bits) per
        // NIST SP 800-38D — the `Aes256Gcm::generate_nonce` helper
        // produces this length, and the `decrypt` path rejects
        // anything else. Pin the length on the encrypt side directly
        // (existing tests pin the decrypt-rejection side for !=12).
        // A refactor that swapped to a larger nonce "for safety
        // margin" would silently break wire compat with any
        // already-persisted Ciphertext row.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        for _ in 0..3 {
            let ct = c.encrypt(b"sample").unwrap();
            assert_eq!(ct.nonce.len(), 12, "nonce MUST be 96 bits");
        }
    }

    #[test]
    fn token_cipher_and_cipher_error_and_ciphertext_are_send_sync_static() {
        // `TokenCipher` is held as `Arc<TokenCipher>` inside both AuthState
        // and OAuthState — axum's State + tokio task boundaries require
        // `Send + Sync + 'static`. `CipherError` flows through anyhow
        // chains at the OAuth callback + token-refresh paths.
        // `Ciphertext` crosses tokio task boundaries between the
        // OAuth-token persist write and the decrypt read. A refactor
        // that introduced a !Send field (e.g. `nonce: Rc<[u8]>` "for
        // cheap clone") would break Send at the AppState site rather
        // than as a far-removed trait-bound error. Pin all three
        // trait bounds on all three types here — symmetric to the
        // siem/email/cat_key send-sync pins on other modules.
        fn require_send_sync_static<T: Send + Sync + 'static>() {}
        require_send_sync_static::<TokenCipher>();
        require_send_sync_static::<CipherError>();
        require_send_sync_static::<Ciphertext>();
    }

    #[test]
    fn cipher_error_debug_carries_variant_names_for_grep_bucketing() {
        // `CipherError` derives Debug — the OAuth-token-persist path
        // bubbles cipher faults through `?e` log spans and operators
        // grep by variant name to bucket "operator misconfigured the
        // key" (BadKeyLen, at-boot) vs "persisted row corrupted"
        // (Aead, at-runtime). A hand-rolled `impl Debug` that hid
        // variant names "to compact" the line would break the bucket.
        // Pin both variant names — symmetric to the AuthFail / ApiError
        // variant-name pins on other modules.
        let bkl = format!("{:?}", CipherError::BadKeyLen(17));
        assert!(bkl.contains("BadKeyLen"), "got: {bkl}");
        let aead = format!("{:?}", CipherError::Aead);
        assert!(aead.contains("Aead"), "got: {aead}");
    }

    #[test]
    fn ciphertext_clone_preserves_both_nonce_and_bytes_byte_equal() {
        // The existing `ciphertext_clone_yields_independent_buffer`
        // test pins independence of the bytes buffer post-mutation,
        // but does NOT pin that the clone starts byte-equal across
        // BOTH the nonce AND the bytes fields. A refactor that
        // swapped any field to `Vec::new()` "for compactness" or
        // `nonce: Arc<[u8]>` (which would alias) would surface here.
        // Pin field-by-field byte equality immediately post-clone
        // before any mutation, on a non-trivial ciphertext.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let original = c.encrypt(b"some non-trivial plaintext").unwrap();
        let cloned = original.clone();
        assert_eq!(
            cloned.nonce, original.nonce,
            "nonce must round-trip clone byte-equal"
        );
        assert_eq!(
            cloned.bytes, original.bytes,
            "bytes must round-trip clone byte-equal"
        );
        // And the clone must decrypt to the same plaintext as the original.
        assert_eq!(c.decrypt(&original).unwrap(), c.decrypt(&cloned).unwrap(),);
    }

    #[test]
    fn cipher_error_bad_key_len_display_carries_byte_exact_prefix_with_actual_length() {
        // `#[error("encryption key must be exactly 32 bytes; got {0}")]`
        // — the existing `bad_key_len_error_display_includes_actual_length`
        // pin uses substring checks (`.contains("32")` +
        // `.contains("17")`); pin the byte-exact full Display via
        // `assert_eq!` so a refactor that softened the message to
        // "key must be 32 bytes (got N)" (paren-wrapping the actual
        // length) would still satisfy `.contains("17")` but surface
        // here. Operator-onboarding docs link to the exact "must be
        // exactly 32 bytes; got N" string as the canonical "your env
        // var is wrong size" hint.
        for n in [17usize, 0, 31, 33, 64, 1024] {
            let s = CipherError::BadKeyLen(n).to_string();
            let expected = format!("encryption key must be exactly 32 bytes; got {n}");
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn decrypt_with_empty_bytes_and_valid_12_byte_nonce_errors_without_panic() {
        // Boundary: a corrupt-row scenario where the persisted
        // `bytes` column got NULL-treated-as-empty by a deserializer,
        // but the `nonce` survived intact at the correct 12-byte
        // length. The 12-byte nonce passes the pre-check, so
        // `cipher.decrypt(nonce, &[])` is invoked — AES-GCM rejects
        // a zero-byte input (no room for the 16-byte auth tag) AND
        // must NOT panic. The existing zero-length-nonce pin covers
        // the nonce-side; pin the bytes-side here so a refactor that
        // swapped to `unsafe { ct.bytes.get_unchecked(..16) }` "for
        // hot-path elision" would surface here.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let probe = c.encrypt(b"hi").unwrap();
        let truncated = Ciphertext {
            nonce: probe.nonce, // valid 12-byte nonce
            bytes: Vec::new(),  // empty ciphertext bytes
        };
        assert!(matches!(c.decrypt(&truncated), Err(CipherError::Aead)));
    }

    #[test]
    fn encrypt_ciphertext_overhead_is_always_plaintext_len_plus_sixteen() {
        // AES-GCM appends a 16-byte authentication tag to the ciphertext
        // — pin that `ct.bytes.len() == plaintext.len() + 16` for a
        // spread of plaintext sizes. The existing pins cover empty (0)
        // and 4096 bytes only; pin the intermediate sizes (1, 32, 100,
        // 1024) so a refactor that swapped to a longer tag (e.g.
        // GCM-SIV's 16+16 nonce-misuse-resistance shape) "for safety
        // margin" would silently change wire shape and break every
        // existing persisted Ciphertext row's length invariant. SIEM
        // ingestors that pre-compute `bytes - 16` to recover plaintext
        // length would silently drift by 16 bytes per row.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        for size in [1usize, 32, 100, 1024] {
            let pt = vec![0xa5u8; size];
            let ct = c.encrypt(&pt).unwrap();
            assert_eq!(
                ct.bytes.len(),
                pt.len() + 16,
                "GCM tag overhead must be exactly 16 bytes for pt.len()={size}",
            );
        }
    }

    #[test]
    fn cipher_error_variant_count_pinned_at_exactly_two_via_exhaustive_match_no_underscore_fallback()
     {
        // `CipherError` has EXACTLY two variants today (`BadKeyLen(usize)` /
        // `Aead`). Pin the variant count at the type level via an exhaustive
        // match with NO `_` fallback so a refactor that landed a third
        // variant (e.g. `KeyRotationStale` for a future per-tenant key-rotation
        // scheme, or `KmsUnreachable` for a remote-KMS plug-in) would surface
        // here as a non-exhaustive-match compile error rather than silently
        // adding a third operator-grep bucket to OAuth-token-persist alerts
        // (the existing `bad_key_len_error_display_includes_actual_length` +
        // `aead_error_display_is_stable_for_log_filters` pins anchor on two
        // Display substrings; a third variant landing without those pins
        // would silently drift the bucket count). Symmetric to round-191
        // SlackInteractError + round-215 PkceError exhaustive-2-arm pins.
        for e in [CipherError::BadKeyLen(0), CipherError::Aead] {
            match e {
                CipherError::BadKeyLen(_) => {}
                CipherError::Aead => {}
            }
        }
    }

    #[test]
    fn ciphertext_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_dotdot_rest() {
        // `Ciphertext` has EXACTLY two public fields today (`nonce: Vec<u8>`
        // / `bytes: Vec<u8>`). Pin the field count at the type level via an
        // exhaustive destructure with NO `..` rest pattern so a future field
        // landing without matching INSERT/SELECT column wiring would surface
        // here as a non-exhaustive-pattern compile error. The OAuth-token-
        // persist path serializes a `Ciphertext` into two distinct columns
        // (`*_nonce` / `*_bytes`) — a third field (e.g. `aad: Vec<u8>` for
        // additional-authenticated-data binding) landing without matching
        // column wiring would silently drop the field on every persist AND
        // fill an Aad-shaped default on every fetch, masking the
        // authentication-data-binding contract drift. Symmetric to round-213
        // CachedPca field-count + round-214 ActionEvent field-count
        // exhaustive-destructure pins extended to this sibling persistence-
        // path struct.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let ct = c.encrypt(b"x").unwrap();
        let Ciphertext { nonce, bytes } = ct;
        assert_eq!(nonce.len(), 12);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn from_bytes_return_type_is_result_token_cipher_cipher_error_via_fn_pointer_witness() {
        // `TokenCipher::from_bytes` is called at boot from the
        // OAuth/server-state assembly chain via `?` to bubble key-length
        // failures into the boot-time error envelope. Pin the return type
        // as `Result<TokenCipher, CipherError>` via a fn-pointer witness so
        // a refactor that promoted the error to `anyhow::Error` "for
        // richer triage at boot" would break the `String`-bodied error-grep
        // contract pinned by `bad_key_len_error_display_includes_actual_length`
        // + `cipher_error_bad_key_len_display_carries_byte_exact_prefix_with_actual_length`
        // — and would silently widen the boot-time error chain shape that
        // the operator's startup-failure runbook keys on. The fn-pointer
        // witness is the load-bearing type-level catch: a refactor would
        // fail to type-check at this line rather than at a far-removed `?`
        // call site. Symmetric to round-215 verify_pkce_s256 return-type
        // + round-216 GoogleClient::from_env return-type fn-pointer pins.
        let _f: fn(&[u8]) -> Result<TokenCipher, CipherError> = TokenCipher::from_bytes;
    }

    #[test]
    fn encrypt_return_type_is_result_ciphertext_cipher_error_via_fn_pointer_witness() {
        // Symmetric to `from_bytes_return_type_is_result_…` — pin the
        // encrypt method's signature as
        // `fn(&TokenCipher, &[u8]) -> Result<Ciphertext, CipherError>` via
        // a fn-pointer witness. The OAuth-token-persist hot path uses
        // `cipher.encrypt(plaintext)?` to bubble GCM faults into the
        // anyhow chain; a refactor that promoted the error to
        // `anyhow::Error` "for inner-cause chain" OR that changed the
        // success type to `Vec<u8>` "flattening nonce+bytes into a single
        // wire-format blob for compactness" would break the persist path's
        // schema mirroring (the table has two distinct columns) AND would
        // surface here as a fn-pointer-type mismatch rather than at the
        // far-removed `?` call site. Pin BOTH the success type
        // (`Ciphertext`) and the error type (`CipherError`).
        let _f: fn(&TokenCipher, &[u8]) -> Result<Ciphertext, CipherError> = TokenCipher::encrypt;
    }

    #[test]
    fn decrypt_return_type_is_result_owned_vec_u8_cipher_error_via_fn_pointer_witness() {
        // Symmetric pin to the encrypt fn-pointer pin above. The OAuth-token-
        // refresh-load path uses `cipher.decrypt(&row.ct)?` to bubble
        // tamper / corrupt-row failures into the anyhow chain; the success
        // arm is the OWNED `Vec<u8>` plaintext that the caller hands to
        // `String::from_utf8` for the bearer string. Pin via fn-pointer
        // witness so a refactor that returned `Cow<'a, [u8]>` "to avoid
        // allocating on the decrypt hot path" would surface here at the
        // type boundary rather than at the `String::from_utf8(plaintext)?`
        // call site (where the diagnostic would mention lifetimes far from
        // this file). The owned-Vec arm is load-bearing for the cross-await
        // token-refresh-then-persist chain.
        let _f: fn(&TokenCipher, &Ciphertext) -> Result<Vec<u8>, CipherError> =
            TokenCipher::decrypt;
    }

    #[test]
    fn encrypt_produces_distinct_nonces_across_fifty_repeated_calls_on_same_plaintext() {
        // The existing `distinct_nonces` + `encrypt_empty_plaintext_still_yields_distinct_nonces`
        // pins walk N=2 distinct-nonce shapes. AES-GCM's security argument
        // depends on the IV (nonce) being unique across every encryption
        // under a given key — pin a WIDER sweep (N=50) on the same plaintext
        // under the same key. A refactor that introduced any form of
        // deterministic-nonce derivation "for AEAD-SIV nonce-misuse-
        // resistance ergonomics" (e.g. nonce = HKDF(key, plaintext_prefix))
        // would still pass the N=2 pin if the first two plaintexts happened
        // to differ — pin N=50 with a HashSet so a deterministic-nonce
        // regression surfaces immediately as a collision. The collision-
        // probability on a 96-bit nonce at scale 50 is ~1e-25 — negligible
        // for a test gate. Symmetric to round-218
        // `one_thousand_generated_bearers_yield_one_thousand_distinct_hashes`
        // anti-entropy-loss pin extended to this sibling-IV-uniqueness
        // contract.
        use std::collections::HashSet;
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let mut nonces: HashSet<Vec<u8>> = HashSet::with_capacity(50);
        for _ in 0..50 {
            let ct = c.encrypt(b"identical plaintext for all 50 calls").unwrap();
            assert_eq!(ct.nonce.len(), 12);
            nonces.insert(ct.nonce);
        }
        assert_eq!(
            nonces.len(),
            50,
            "AES-GCM IV-uniqueness regression: collision in 50 calls",
        );
    }

    #[test]
    fn empty_key_rejected_with_zero_length() {
        // Boundary: a missing env var sometimes shows up as an empty byte
        // slice. The variant must carry `0`, not panic on the indexing path.
        // (TokenCipher intentionally has no Debug impl — it holds the
        // master key — so we match on the result rather than `unwrap_err`.)
        match TokenCipher::from_bytes(&[]) {
            Err(CipherError::BadKeyLen(0)) => {}
            Err(e) => panic!("expected BadKeyLen(0), got {e:?}"),
            Ok(_) => panic!("expected error for empty key"),
        }
    }

    // ─── round 245 (2026-05-22): CipherError variant-payload layouts +
    // AES-256-only key-size contract + Ciphertext field-types ───

    #[test]
    fn cipher_error_bad_key_len_inner_field_pinned_usize_via_explicit_type_destructure_binding() {
        // `CipherError::BadKeyLen(usize)` — the existing
        // `cipher_error_bad_key_len_display_carries_byte_exact_prefix_with_actual_length`
        // pin walks the Display passthrough but not the INNER TYPE.
        // A refactor to `BadKeyLen(u32)` "for SQL int4 alignment when
        // surfaced via /api/v1/setup error envelope" would silently
        // truncate `usize` lengths above `u32::MAX` (pathological env-var
        // shapes) AND would change the Display format spec on
        // 32-vs-64-bit platforms. The error is currently `pub` but the
        // INNER usize is positional — pin via destructure with explicit
        // `let n: usize = …` binding so a width-drift refactor surfaces
        // here at the type boundary. Symmetric to round-242's
        // `cached_pca_hop_field_pinned_i32_via_require_for_postgres_int4_signed_domain`
        // extended to this sibling tuple-variant inner.
        let e = CipherError::BadKeyLen(17);
        let CipherError::BadKeyLen(n) = e else {
            panic!("expected BadKeyLen variant");
        };
        let _check: usize = n;
        assert_eq!(n, 17);
    }

    #[test]
    fn cipher_error_aead_unit_variant_layout_pinned_via_match_arm_no_pattern_binding() {
        // `CipherError::Aead` — UNIT variant (no inner data), distinct
        // from the tuple-with-usize layout of `BadKeyLen`. A refactor
        // to a tuple variant (`Aead(aes_gcm::Error)` "for inner-cause
        // chain through anyhow's source() walk") would force every
        // operator log filter that anchors on the byte-exact
        // `"AES-GCM operation failed"` Display string (pinned by
        // `aead_error_display_is_stable_for_log_filters`) to also
        // ingest the variant's inner debug. The unit-variant layout
        // is load-bearing for the no-secret-leak contract (the
        // existing `auth_fail_decrypt_does_not_carry_cipher_internals_in_message`
        // pin extends this: AuthFail::Decrypt also masks inner cipher
        // details). Pin the unit-variant layout via a match arm with
        // NO inner-binding pattern. Symmetric to round-242's
        // `cache_error_db_variant_layout_pinned_tuple_via_exhaustive_destructure_one_positional_inner_sqlx`
        // (which pins a TUPLE-positional layout); this pins the
        // UNIT-no-inner counterpart.
        let e = CipherError::Aead;
        match e {
            CipherError::Aead => {} // unit-variant — NO inner-binding pattern
            other => panic!("expected Aead, got {other:?}"),
        }
    }

    #[test]
    fn from_bytes_rejects_16_byte_aes_128_and_24_byte_aes_192_keys_for_aes_256_only_contract() {
        // The cipher is specifically AES-256-GCM — 32-byte keys ONLY.
        // 16-byte (AES-128) and 24-byte (AES-192) keys ARE valid AES key
        // sizes per FIPS 197, but the proxy's threat model requires
        // 256-bit envelope encryption for OAuth tokens at rest (spec.md
        // §1.2). The existing `short_key_rejected` pin walks 16 bytes;
        // pin 24-byte AES-192 as well so an operator pasting a 24-byte
        // key (the "compromise between 128 and 256" mistake) surfaces
        // the same BadKeyLen-with-actual-length triage. Pin both sizes
        // here together with their canonical AES-variant names in the
        // error context, so a refactor to accept AES-128/192 "for
        // backward-compat with smaller keys" would silently weaken the
        // envelope-encryption contract on every persisted OAuth-token
        // row. Symmetric to round-218's
        // `parse_rejects_digits_outside_base32_alphabet` extended to
        // this sibling key-size domain check.
        match TokenCipher::from_bytes(&[0u8; 16]) {
            Err(CipherError::BadKeyLen(16)) => {}
            Err(e) => panic!("16-byte (AES-128): expected BadKeyLen(16), got {e:?}"),
            Ok(_) => panic!("16-byte (AES-128) key must be rejected"),
        }
        match TokenCipher::from_bytes(&[0u8; 24]) {
            Err(CipherError::BadKeyLen(24)) => {}
            Err(e) => panic!("24-byte (AES-192): expected BadKeyLen(24), got {e:?}"),
            Ok(_) => panic!("24-byte (AES-192) key must be rejected"),
        }
        // Sanity: 32 bytes (AES-256) is accepted — this differentiates
        // the rejection above from a blanket-reject regression.
        assert!(TokenCipher::from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn ciphertext_nonce_and_bytes_fields_both_pinned_owned_vec_u8_via_require_for_postgres_bytea_persist()
     {
        // `Ciphertext { nonce: Vec<u8>, bytes: Vec<u8> }` — both fields
        // OWNED `Vec<u8>`. The OAuth-token-persist path serializes each
        // into a distinct Postgres `bytea` column via `.bind(&ct.nonce)`
        // + `.bind(&ct.bytes)`. sqlx's `Encode<Postgres>` for `&Vec<u8>`
        // routes to the `bytea` column type. A refactor to `bytes::Bytes`
        // "for cheap clone across the OAuth-callback fan-out" would
        // change the sqlx Encode resolution path (Bytes doesn't have a
        // direct Postgres encode; it would force `.as_ref()` at every
        // bind site) AND would tie the buffer lifetime to the upstream
        // Google response's body buffer freed at the `.json().await`
        // boundary — producing a use-after-free when the row outlives
        // the response. Pin BOTH fields are owned `Vec<u8>` via
        // `require_vec_u8`. Symmetric to round-242's
        // `cached_pca_cbor_signature_fields_both_pinned_owned_vec_u8_via_require_for_postgres_bytea_bind`
        // extended to this sibling Ciphertext envelope.
        fn require_vec_u8(_: Vec<u8>) {}
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let ct = c.encrypt(b"sample plaintext").unwrap();
        require_vec_u8(ct.nonce);
        let ct2 = c.encrypt(b"sample plaintext").unwrap();
        require_vec_u8(ct2.bytes);
    }

    #[test]
    fn encrypt_ciphertext_length_is_referentially_transparent_across_fifty_calls_same_plaintext() {
        // `cipher.encrypt(plaintext)` produces a ciphertext whose
        // `bytes.len()` is deterministically `plaintext.len() + 16`
        // (16-byte GCM auth tag) — the BYTES content varies per call
        // (due to random nonce), but the LENGTH is referentially
        // transparent. The existing
        // `encrypt_ciphertext_overhead_is_always_plaintext_len_plus_sixteen`
        // pin walks 4 distinct plaintext sizes; pin the LENGTH-RT
        // contract across 50 SEQUENTIAL calls on the same plaintext
        // here so a refactor that introduced any form of length-
        // dependent state (a thread-local pad-byte counter, a
        // compression layer "for at-rest size savings") would surface
        // here as the 50-call sweep diverging from the baseline length.
        // Symmetric to round-242's
        // `cached_pca_new_referentially_transparent_across_fifty_calls_on_same_input`
        // extended to this sibling length-determinism contract.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        let plaintext = b"identical plaintext across all 50 calls";
        let baseline = c.encrypt(plaintext).unwrap();
        let expected_len = plaintext.len() + 16; // GCM tag
        assert_eq!(baseline.bytes.len(), expected_len);
        for i in 0..50 {
            let again = c.encrypt(plaintext).unwrap();
            assert_eq!(
                again.bytes.len(),
                expected_len,
                "iter {i}: ciphertext length drifted from baseline",
            );
            assert_eq!(again.nonce.len(), 12, "iter {i}: nonce length drifted");
        }
    }

    #[test]
    fn self_encrypted_ciphertext_decrypts_to_byte_equal_plaintext_across_twenty_five_random_inputs()
    {
        // The fundamental AEAD round-trip contract: `decrypt(encrypt(pt))
        // == pt` for any plaintext under the same key. The existing
        // pins walk specific inputs (Google access token, "hi",
        // 4096-byte, empty); pin the wider contract via 25 random
        // plaintexts of varying lengths (1, 2, 3, ..., 25 bytes — small
        // enough to exercise the per-message GCM block-padding edge
        // cases). A refactor that introduced any form of plaintext-
        // length-dependent corruption (e.g. a chunking layer for "future
        // streaming support" that mishandled non-block-aligned tails)
        // would surface here at one of the 25 lengths. Distinct from
        // the existing length-fixed RT pins because this varies the
        // plaintext shape, not just the count of trials. Symmetric to
        // round-218's
        // `one_thousand_generated_bearers_yield_one_thousand_distinct_hashes`
        // anti-regression-at-scale pin extended to this sibling
        // round-trip-at-varying-length contract.
        let c = TokenCipher::from_bytes(&key()).unwrap();
        for len in 1usize..=25 {
            let pt: Vec<u8> = (0..len).map(|i| ((i * 13 + 7) % 251) as u8).collect();
            let ct = c.encrypt(&pt).unwrap();
            let back = c.decrypt(&ct).unwrap();
            assert_eq!(back, pt, "round-trip failed for plaintext length {len}",);
        }
    }
}
