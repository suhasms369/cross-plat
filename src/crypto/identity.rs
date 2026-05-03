use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use std::path::PathBuf;
use anyhow::Result;
use crate::error::MeshError;

// ── Identity keypair ──────────────────────────────────────────────────────────

pub struct Identity {
    pub signing_key:   SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        Self { signing_key: sk, verifying_key: vk }
    }

    /// Load from disk, or generate and save if not found.
    pub fn load_or_generate(path: &PathBuf) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != 32 {
                return Err(MeshError::Crypto("Identity key file must be 32 bytes".into()).into());
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let sk = SigningKey::from_bytes(&key_bytes);
            let vk = sk.verifying_key();
            return Ok(Self { signing_key: sk, verifying_key: vk });
        }

        let id = Self::generate();
        id.save(path)?;
        tracing::info!("Generated new identity key → {:?}", path);
        tracing::info!("Your pubkey (add to other nodes' config): {}", id.pubkey_hex());
        Ok(id)
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
        std::fs::write(path, self.signing_key.to_bytes())?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey_bytes())
    }
}

// ── Standalone verify (used when checking peer messages) ─────────────────────

pub fn verify_signature(pubkey_bytes: &[u8; 32], msg: &[u8], sig_bytes: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| MeshError::Crypto(format!("Bad pubkey: {}", e)))?;
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(msg, &sig)
        .map_err(|e| MeshError::Auth(format!("Signature invalid: {}", e)).into())
}

// ── Session-key derivation (PSK + nonces → AES key) ─────────────────────────

/// Derives a 32-byte AES session key from:
///   - mesh_psk: manually distributed pre-shared key
///   - nonce_a, nonce_b: 32-byte random nonces exchanged during auth handshake
///
/// SHA-256(domain || psk || nonce_a || nonce_b)
/// Not HKDF but sufficient for a closed LAN homelab.
pub fn derive_session_key(mesh_psk: &[u8; 32], nonce_a: &[u8; 32], nonce_b: &[u8; 32]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(b"meshkvm-v1-session");
    h.update(mesh_psk);
    h.update(nonce_a);
    h.update(nonce_b);
    h.finalize().into()
}

/// Derives the NEXT session key during rotation:
///   SHA-256(domain || current_key || new_nonce)
pub fn derive_rotation_key(current_key: &[u8; 32], new_nonce: &[u8; 32]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(b"meshkvm-v1-rotation");
    h.update(current_key);
    h.update(new_nonce);
    h.finalize().into()
}
