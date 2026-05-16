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
