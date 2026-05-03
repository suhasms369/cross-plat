//! Incoming control-message dispatcher.
//! The read tasks in peer.rs call `dispatch()` for every decrypted message.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::network::gossip::{GossipTable, NeighborList, handle_neighbor_list};
use crate::network::heartbeat::on_heartbeat_ack;
use crate::network::peer::{SharedPeerState, PeerSender};
use crate::network::protocol::{ControlMsg, encode_control_encrypted};
use crate::network::rotation::handle_key_rotate;

pub struct DispatchCtx {
    pub from_peer:  String,
    pub config:     Arc<Config>,
    pub peers:      Arc<Mutex<HashMap<String, SharedPeerState>>>,
    pub peer_tx:    Arc<Mutex<HashMap<String, PeerSender>>>,
    pub gossip:     GossipTable,
    pub state_path: PathBuf,
}

pub async fn dispatch(msg: ControlMsg, peer_state: &SharedPeerState, ctx: &DispatchCtx) {
    match msg {
        // ── Heartbeat ─────────────────────────────────────────────────────
        ControlMsg::Heartbeat { seq, .. } => {
            // Echo back an ack
            let ack = ControlMsg::HeartbeatAck { seq };
            let cipher = peer_state.lock().await.cipher.clone();
            if let Some(cipher) = cipher {
                if let Ok(bytes) = encode_control_encrypted(&ack, &cipher) {
                    let tx_map = ctx.peer_tx.lock().await;
                    if let Some(tx) = tx_map.get(&ctx.from_peer) {
                        let _ = tx.try_send(bytes);
                    }
                }
            }
        }

        // ── HeartbeatAck ──────────────────────────────────────────────────
        ControlMsg::HeartbeatAck { .. } => {
            on_heartbeat_ack(peer_state).await;
        }

        // ── Gossip ────────────────────────────────────────────────────────
        ControlMsg::NeighborList { from, neighbors, timestamp_secs, signature } => {
            let nl = NeighborList { from, neighbors, timestamp_secs, signature };
            if let Err(e) = handle_neighbor_list(nl, &ctx.from_peer, &ctx.config, &ctx.gossip).await {
                tracing::warn!("Gossip from {}: {}", ctx.from_peer, e);
            }
        }

        // ── Key rotation ──────────────────────────────────────────────────
        ControlMsg::KeyRotate { .. } => {
            if let Err(e) = handle_key_rotate(
                msg,
                &ctx.from_peer,
                &ctx.config,
                &ctx.peers,
                &ctx.peer_tx,
                &ctx.state_path,
            ).await {
                tracing::warn!("KeyRotate from {}: {}", ctx.from_peer, e);
            }
        }

        ControlMsg::KeyRotateAck { seq } => {
            tracing::debug!("KeyRotateAck from {} seq={}", ctx.from_peer, seq);
        }

        // ── Clipboard ─────────────────────────────────────────────────────
        ControlMsg::ClipboardSync { content } => {
            if let Ok(text) = String::from_utf8(content) {
                let cb = crate::input::clipboard::Clipboard::new();
                if let Ok(cb) = cb {
                    if let Err(e) = cb.set_text(&text) {
                        tracing::warn!("Clipboard set failed: {}", e);
                    } else {
                        tracing::debug!("Clipboard synced ({} bytes)", text.len());
                    }
                }
            }
        }

        // Auth messages only occur during handshake — unexpected here
        ControlMsg::AuthChallenge { .. }
        | ControlMsg::AuthResponse { .. }
        | ControlMsg::AuthAck     { .. } => {
            tracing::warn!("Unexpected auth message from {} after handshake", ctx.from_peer);
        }
    }
}
