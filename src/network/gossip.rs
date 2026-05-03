use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time;

use crate::config::Config;
use crate::crypto::identity::Identity;
use crate::crypto::identity::verify_signature;
use crate::network::peer::{SharedPeerState, PeerStatus};
use crate::network::protocol::{ControlMsg, NeighborInfo, PeerStatus as ProtoStatus, encode_control_encrypted};
use anyhow::Result;

/// Learned via gossip: "node X can be reached via direct peer Y"
#[derive(Debug, Clone)]
pub struct KnownVia {
    pub peer_name:    String, // the node we learned about
    pub peer_mac:     String,
    pub via:          String, // which direct neighbor told us
    pub status:       ProtoStatus,
}

pub type GossipTable = Arc<Mutex<HashMap<String, KnownVia>>>;

/// Runs forever. Every 30s, broadcast our current neighbor list to all connected peers.
pub async fn run_gossip_loop(
    config: Arc<Config>,
    identity: Arc<Identity>,
    peers: Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx: Arc<Mutex<HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
) {
    let mut ticker = time::interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        broadcast_neighbor_list(&config, &identity, &peers, &peer_tx).await;
    }
}

async fn broadcast_neighbor_list(
    config: &Config,
    identity: &Identity,
    peers: &Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx: &Arc<Mutex<HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
) {
    let peers_map = peers.lock().await;
    let tx_map   = peer_tx.lock().await;

    // Build neighbor list from current peer states
    let mut neighbors: Vec<NeighborInfo> = Vec::new();
    for (name, ps) in peers_map.iter() {
        let s = ps.lock().await;
        neighbors.push(NeighborInfo {
            name:   name.clone(),
            mac:    s.mac.clone(),
            status: if s.status == PeerStatus::Authenticated {
                ProtoStatus::Up
            } else {
                ProtoStatus::Down
            },
        });
    }

    let ts = now_secs();

    // Sign: Ed25519 over JSON of (from + neighbors + ts)
    let payload = serde_json::json!({
        "from": config.node.name,
        "neighbors": neighbors,
        "timestamp_secs": ts,
    });
    let sig = identity.sign(payload.to_string().as_bytes());

    let msg = ControlMsg::NeighborList {
        from: config.node.name.clone(),
        neighbors: neighbors.clone(),
        timestamp_secs: ts,
        signature: crate::network::protocol::Bytes64(sig),
    };

    // Send to all authenticated peers
    for (name, ps) in peers_map.iter() {
        let s = ps.lock().await;
        if let Some(cipher) = &s.cipher {
            if let Ok(bytes) = encode_control_encrypted(&msg, cipher) {
                if let Some(tx) = tx_map.get(name) {
                    let _ = tx.try_send(bytes);
                }
            }
        }
    }
}

/// Handle an incoming NeighborList message from a direct peer.
/// Verifies signature, then updates our 2-hop gossip table.
pub async fn handle_neighbor_list(
    msg: NeighborList,
    from_peer: &str,
    config: &Config,
    gossip_table: &GossipTable,
) -> Result<()>
where NeighborList: std::fmt::Debug
{
    // Verify we know this peer's pubkey
    let peer_pubkey = config.peer_pubkey_bytes(from_peer)?;

    // Reconstruct signing payload
    let payload = serde_json::json!({
        "from": msg.from,
        "neighbors": msg.neighbors,
        "timestamp_secs": msg.timestamp_secs,
    });
    verify_signature(&peer_pubkey, payload.to_string().as_bytes(), &msg.signature.0)?;

    // Update gossip table: all nodes listed by this peer are reachable via them
    let mut table = gossip_table.lock().await;
    for neighbor in &msg.neighbors {
        // Don't gossip ourselves
        if neighbor.name == config.node.name { continue; }
        // Don't overwrite a direct peer entry with an indirect one
        if config.peer_by_name(&neighbor.name).is_some() { continue; }

        table.insert(neighbor.name.clone(), KnownVia {
            peer_name: neighbor.name.clone(),
            peer_mac:  neighbor.mac.clone(),
            via:       from_peer.to_string(),
            status:    neighbor.status.clone(),
        });
    }

    tracing::debug!("Gossip from {}: updated {} indirect entries", from_peer, msg.neighbors.len());
    Ok(())
}

// Wrapper to make the ControlMsg variant usable in handle_neighbor_list
#[derive(Debug)]
pub struct NeighborList {
    pub from:            String,
    pub neighbors:       Vec<NeighborInfo>,
    pub timestamp_secs:  u64,
    pub signature: crate::network::protocol::Bytes64,
}

impl TryFrom<ControlMsg> for NeighborList {
    type Error = anyhow::Error;
    fn try_from(msg: ControlMsg) -> Result<Self> {
        match msg {
            ControlMsg::NeighborList { from, neighbors, timestamp_secs, signature } =>
                Ok(Self { from, neighbors, timestamp_secs, signature }),
            _ => anyhow::bail!("Not a NeighborList message"),
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
