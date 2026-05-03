use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::Result;

/// Persisted to disk so replay protection survives reboots.
/// Stored at /var/lib/meshkvm/state.toml (or XDG data dir).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PersistentState {
    /// Last accepted key-rotation sequence number per peer name.
    /// We reject any rotation with seq ≤ this value.
    pub rotation_seqs: HashMap<String, u64>,
}

impl PersistentState {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&raw)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Increment and return the next outgoing sequence number for this peer.
    pub fn next_seq(&mut self, peer: &str) -> u64 {
        let s = self.rotation_seqs.entry(peer.to_string()).or_insert(0);
        *s += 1;
        *s
    }

    /// Returns true if the incoming seq is fresh (> last seen). Updates if so.
    pub fn accept_seq(&mut self, peer: &str, seq: u64) -> bool {
        let last = self.rotation_seqs.entry(peer.to_string()).or_insert(0);
        if seq > *last {
            *last = seq;
            true
        } else {
            false
        }
    }
}
