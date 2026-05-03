use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::{MeshError, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub node:     NodeConfig,
    pub session:  SessionConfig,
    pub topology: TopologyConfig,
    pub display:  DisplayConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    pub name:         String,
    pub identity_key: PathBuf,
    pub mesh_psk:     String, // 64-char hex → 32 bytes
    #[serde(default = "default_ctrl")]  pub control_port: u16,
    #[serde(default = "default_data")]  pub data_port:    u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    #[serde(default = "default_rotation")]  pub rotation_interval_secs:  u64,
    #[serde(default = "default_hb_ms")]     pub heartbeat_interval_ms:   u64,
    #[serde(default = "default_hb_miss")]   pub heartbeat_miss_threshold: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TopologyConfig {
    /// Node names ordered left → right
    pub order: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DisplayConfig {
    pub width:  u32,
    pub height: u32,
    #[serde(default = "default_edge_px")] pub edge_threshold_px: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerConfig {
    pub name:    String,
    pub mac:     String,
    pub address: String,
    pub pubkey:  String, // hex-encoded Ed25519 verifying key (32 bytes → 64 hex chars)
}

fn default_ctrl()    -> u16 { 24801 }
fn default_data()    -> u16 { 24802 }
fn default_rotation()-> u64 { 86400 }
fn default_hb_ms()   -> u64 { 500 }
fn default_hb_miss() -> u32 { 3 }
fn default_edge_px() -> u32 { 5 }

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| MeshError::Config(format!("Cannot read config: {}", e)))?;
        toml::from_str(&content)
            .map_err(|e| MeshError::Config(format!("Parse error: {}", e)))
    }

    pub fn mesh_psk_bytes(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.node.mesh_psk)
            .map_err(|e| MeshError::Config(format!("Invalid mesh_psk hex: {}", e)))?;
        bytes.try_into()
            .map_err(|_| MeshError::Config("mesh_psk must be exactly 32 bytes (64 hex chars)".into()))
    }

    /// Node directly to the left of us in the topology order
    pub fn left_neighbor(&self) -> Option<&str> {
        let pos = self.my_position()?;
        if pos == 0 { None } else { Some(&self.topology.order[pos - 1]) }
    }

    /// Node directly to the right of us in the topology order
    pub fn right_neighbor(&self) -> Option<&str> {
        let pos = self.my_position()?;
        self.topology.order.get(pos + 1).map(String::as_str)
    }

    pub fn my_position(&self) -> Option<usize> {
        self.topology.order.iter().position(|n| n == &self.node.name)
    }

    pub fn peer_by_name(&self, name: &str) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| p.name == name)
    }

    pub fn peer_pubkey_bytes(&self, name: &str) -> Result<[u8; 32]> {
        let peer = self.peer_by_name(name)
            .ok_or_else(|| MeshError::Config(format!("Peer '{}' not in config", name)))?;
        let bytes = hex::decode(&peer.pubkey)
            .map_err(|e| MeshError::Config(format!("Invalid pubkey hex for '{}': {}", name, e)))?;
        bytes.try_into()
            .map_err(|_| MeshError::Config(format!("Pubkey for '{}' must be 32 bytes", name)))
    }
}
