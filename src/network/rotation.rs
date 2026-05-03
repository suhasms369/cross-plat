use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::time;
use rand::Rng;

use crate::config::Config;
use crate::crypto::identity::{Identity, derive_rotation_key, verify_signature};
use crate::crypto::session::SessionCipher;
use crate::network::peer::{SharedPeerState, PeerStatus, PeerSender};
use crate::network::protocol::{ControlMsg, Bytes32, Bytes64, encode_control_encrypted};
use crate::state::PersistentState;

pub async fn run_rotation_loop(
    config:     Arc<Config>,
    identity:   Arc<Identity>,
    peers:      Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx:    Arc<Mutex<HashMap<String, PeerSender>>>,
    state_path: PathBuf,
) {
    let interval = Duration::from_secs(config.session.rotation_interval_secs);
    let mut ticker = time::interval(interval);
    ticker.tick().await; // skip first tick — no rotation needed on startup

    loop {
        ticker.tick().await;
        let peer_names: Vec<String> = peers.lock().await.keys().cloned().collect();
        for peer_name in peer_names {
            if let Err(e) = rotate_with_peer(
                &peer_name, &identity, &config, &peers, &peer_tx, &state_path,
            ).await {
                tracing::warn!("Key rotation failed with {}: {}", peer_name, e);
            }
        }
    }
}

async fn rotate_with_peer(
    peer_name:  &str,
    identity:   &Identity,
    _config:     &Config,
    peers:      &Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx:    &Arc<Mutex<HashMap<String, PeerSender>>>,
    state_path: &PathBuf,
) -> anyhow::Result<()> {
    let current_cipher = {
        let map = peers.lock().await;
        let ps  = map.get(peer_name).ok_or_else(|| anyhow::anyhow!("Peer not found"))?;
        let s   = ps.lock().await;
        if s.status != PeerStatus::Authenticated { return Ok(()); }
        s.cipher.clone().ok_or_else(|| anyhow::anyhow!("No cipher"))?
    };

    let mut pstate = PersistentState::load(state_path).unwrap_or_default();
    let seq        = pstate.next_seq(peer_name);
    let ts         = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let new_nonce: [u8; 32] = rand::thread_rng().gen();

    let mut to_sign = Vec::with_capacity(48);
    to_sign.extend_from_slice(&seq.to_be_bytes());
    to_sign.extend_from_slice(&ts.to_be_bytes());
    to_sign.extend_from_slice(&new_nonce);
    let sig = identity.sign(&to_sign);

    let msg   = ControlMsg::KeyRotate { seq, timestamp_secs: ts, new_nonce: Bytes32(new_nonce), signature: Bytes64(sig) };
    let bytes = encode_control_encrypted(&msg, &current_cipher)?;
    peer_tx.lock().await.get(peer_name)
        .ok_or_else(|| anyhow::anyhow!("No tx for peer"))?
        .send(bytes).await?;

    // Both sides derive the new key from current_key + new_nonce
    let new_key    = derive_rotation_key(current_cipher.key_bytes(), &new_nonce);
    let new_cipher = SessionCipher::new(new_key);

    if let Some(ps) = peers.lock().await.get(peer_name) {
        ps.lock().await.cipher = Some(new_cipher);
    }
    pstate.save(state_path).ok();
    tracing::info!("Key rotation → {} (seq {})", peer_name, seq);
    Ok(())
}

/// Handle an incoming KeyRotate from a peer — verify, check replay, derive new key, ack.
pub async fn handle_key_rotate(
    msg:        ControlMsg,
    from_peer:  &str,
    config:     &Config,
    peers:      &Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx:    &Arc<Mutex<HashMap<String, PeerSender>>>,
    state_path: &PathBuf,
) -> anyhow::Result<()> {
    let (seq, ts, new_nonce, sig) = match msg {
        ControlMsg::KeyRotate { seq, timestamp_secs, new_nonce, signature } =>
            (seq, timestamp_secs, new_nonce.0, signature.0),
        _ => anyhow::bail!("Not a KeyRotate message"),
    };

    // ±5 minute clock skew tolerance
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.abs_diff(ts) > 300 {
        anyhow::bail!("Timestamp skew too large: {} vs {}", ts, now);
    }

    // Verify sender's Ed25519 signature
    let peer_pubkey = config.peer_pubkey_bytes(from_peer)?;
    let mut signed  = Vec::with_capacity(48);
    signed.extend_from_slice(&seq.to_be_bytes());
    signed.extend_from_slice(&ts.to_be_bytes());
    signed.extend_from_slice(&new_nonce);
    verify_signature(&peer_pubkey, &signed, &sig)?;

    // Replay protection
    let mut pstate = PersistentState::load(state_path).unwrap_or_default();
    if !pstate.accept_seq(from_peer, seq) {
        anyhow::bail!("Replay detected: seq {} already seen for {}", seq, from_peer);
    }
    pstate.save(state_path).ok();

    // Derive new key
    let current_cipher = {
        let ps = {
            let map = peers.lock().await;
            map.get(from_peer).ok_or_else(|| anyhow::anyhow!("Peer not found"))?.clone()
        };
        let guard = ps.lock().await;
        guard.cipher.clone().ok_or_else(|| anyhow::anyhow!("No cipher"))?
    };

    let new_key    = derive_rotation_key(current_cipher.key_bytes(), &new_nonce);
    let new_cipher = SessionCipher::new(new_key);

    if let Some(ps) = peers.lock().await.get(from_peer) {
        ps.lock().await.cipher = Some(new_cipher.clone());
    }

    // Ack with new key — proves we derived it
    let ack   = ControlMsg::KeyRotateAck { seq };
    let bytes = encode_control_encrypted(&ack, &new_cipher)?;
    if let Some(tx) = peer_tx.lock().await.get(from_peer) {
        let _ = tx.try_send(bytes);
    }

    tracing::info!("Key rotation ← {} (seq {}) — new key active", from_peer, seq);
    Ok(())
}
