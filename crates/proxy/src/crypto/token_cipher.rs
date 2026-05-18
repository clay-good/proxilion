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
}
