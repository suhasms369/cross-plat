use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand_core::OsRng;
use zeroize::Zeroize;
use crate::error::{MeshError, Result};

/// Wraps AES-256-GCM. Cloneable so each peer connection holds its own copy.
#[derive(Clone)]
pub struct SessionCipher {
    key_bytes: [u8; 32],
    cipher:    Aes256Gcm,
}

impl SessionCipher {
    pub fn new(key_bytes: [u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Self { key_bytes, cipher }
    }

    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key_bytes
    }

    /// Returns: [12-byte nonce] ++ [ciphertext + 16-byte GCM tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| MeshError::Crypto(format!("Encrypt failed: {}", e)))?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Input: [12-byte nonce] ++ [ciphertext + GCM tag]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 28 { // 12 nonce + 16 tag minimum
            return Err(MeshError::Crypto("Ciphertext too short".into()));
        }
        let nonce = Nonce::from_slice(&data[..12]);
        self.cipher
            .decrypt(nonce, &data[12..])
            .map_err(|e| MeshError::Crypto(format!("Decrypt failed (bad key or tampered data): {}", e)))
    }
}

impl Drop for SessionCipher {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionCipher(<redacted>)")
    }
}
