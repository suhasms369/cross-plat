use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time;

use crate::config::Config;
use crate::network::peer::{SharedPeerState, PeerStatus};
use crate::network::protocol::ControlMsg;

use crate::network::protocol::encode_control_encrypted;

/// Runs forever. Every heartbeat_interval_ms, sends a Heartbeat to each peer
/// and increments their missed counter. When HeartbeatAck arrives (handled in
/// read loop), the counter resets. When missed >= threshold, mark peer Down.
pub async fn run_heartbeat_loop(
    config: Arc<Config>,
    peers: Arc<Mutex<HashMap<String, SharedPeerState>>>,
    // channel to actually send bytes to each peer's TCP writer
    peer_tx: Arc<Mutex<HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
) {
    let interval  = Duration::from_millis(config.session.heartbeat_interval_ms);
    let threshold = config.session.heartbeat_miss_threshold;
    let mut seq: u64 = 0;
    let mut ticker = time::interval(interval);

    loop {
        ticker.tick().await;
        seq += 1;

        let peers_map = peers.lock().await;
        let tx_map   = peer_tx.lock().await;

        for (name, ps) in peers_map.iter() {
            let mut state = ps.lock().await;

            if state.status == PeerStatus::Down {
                // Already marked down — nothing to send
                continue;
            }

            let cipher = match &state.cipher {
                Some(c) => c.clone(),
                None    => continue, // not yet authenticated
            };

            state.missed_heartbeats += 1;

            if state.missed_heartbeats >= threshold {
                tracing::warn!("Peer {} is DOWN (missed {} heartbeats)", name, state.missed_heartbeats);
                state.status = PeerStatus::Down;
                continue;
            }

            // Build and send heartbeat
            let msg = ControlMsg::Heartbeat {
                seq,
                timestamp_ms: now_ms(),
            };
            if let Ok(bytes) = encode_control_encrypted(&msg, &cipher) {
                if let Some(tx) = tx_map.get(name) {
                    let _ = tx.try_send(bytes);
                }
            }
        }
    }
}

/// Call this when a HeartbeatAck arrives for a peer — resets missed counter.
pub async fn on_heartbeat_ack(peer_state: &SharedPeerState) {
    let mut s = peer_state.lock().await;
    s.missed_heartbeats = 0;
    if s.status == PeerStatus::Down {
        tracing::info!("Peer {} is back UP", s.name);
        s.status = PeerStatus::Authenticated;
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
