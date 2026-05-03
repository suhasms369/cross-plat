use serde::{Deserialize, Serialize};

// ── Newtype wrappers for serde on fixed-size byte arrays ─────────────────────

/// A 32-byte value serialized as a hex string.
#[derive(Clone, PartialEq)]
pub struct Bytes32(pub [u8; 32]);

/// A 64-byte value serialized as a hex string.
#[derive(Clone, PartialEq)]
pub struct Bytes64(pub [u8; 64]);

impl Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}
impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let h = String::deserialize(d)?;
        let v = hex::decode(&h).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = v.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(Self(arr))
    }
}
impl std::fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes32({})", &hex::encode(self.0)[..8])
    }
}

impl Serialize for Bytes64 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}
impl<'de> Deserialize<'de> for Bytes64 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let h = String::deserialize(d)?;
        let v = hex::decode(&h).map_err(serde::de::Error::custom)?;
        let arr: [u8; 64] = v.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(Self(arr))
    }
}
impl std::fmt::Debug for Bytes64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes64({}…)", &hex::encode(&self.0[..4]))
    }
}

// ── Control-plane messages (TCP, length-prefixed JSON) ────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum ControlMsg {
    // ── Handshake (plaintext until session key established) ───────────────
    AuthChallenge {
        server_nonce:  Bytes32,
        server_pubkey: Bytes32,
    },
    AuthResponse {
        client_nonce:  Bytes32,
        client_pubkey: Bytes32,
        signature:     Bytes64,
    },
    AuthAck {
        accepted:  bool,
        signature: Bytes64,
        reason:    Option<String>,
    },

    // ── Key rotation (encrypted, signed) ──────────────────────────────────
    KeyRotate {
        seq:            u64,
        timestamp_secs: u64,
        new_nonce:      Bytes32,
        signature:      Bytes64,
    },
    KeyRotateAck { seq: u64 },

    // ── Heartbeat ─────────────────────────────────────────────────────────
    Heartbeat    { seq: u64, timestamp_ms: u64 },
    HeartbeatAck { seq: u64 },

    // ── Gossip ────────────────────────────────────────────────────────────
    NeighborList {
        from:           String,
        neighbors:      Vec<NeighborInfo>,
        timestamp_secs: u64,
        signature:      Bytes64,
    },

    // ── Clipboard ─────────────────────────────────────────────────────────
    ClipboardSync { content: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NeighborInfo {
    pub name:   String,
    pub mac:    String,
    pub status: PeerStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum PeerStatus { Up, Down }

// ── Data-plane messages (UDP) ─────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum DataMsg {
    MouseMove   { x: f64, y: f64 },
    MouseButton { button: u8, pressed: bool },
    MouseScroll { delta_x: f64, delta_y: f64 },
    KeyEvent    { key_code: u32, key_name: Option<String>, pressed: bool },
    EdgeHandoff { from_node: String, edge: String, cursor_y_norm: f64 },
    EdgeReturn  { to_node:   String, edge: String, cursor_y_norm: f64 },
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

pub fn encode_control(msg: &ControlMsg) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let len  = json.len() as u32;
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

pub fn encode_control_encrypted(
    msg: &ControlMsg,
    cipher: &crate::crypto::session::SessionCipher,
) -> anyhow::Result<Vec<u8>> {
    let json      = serde_json::to_vec(msg)?;
    let encrypted = cipher.encrypt(&json)?;
    let len       = encrypted.len() as u32;
    let mut buf   = Vec::with_capacity(4 + encrypted.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&encrypted);
    Ok(buf)
}
