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
        assert_ne!(a.bytes, b.bytes, "ciphertext must differ across encryptions");
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
}
