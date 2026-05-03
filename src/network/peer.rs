use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use rand::Rng;
use anyhow::{Result, Context};

use crate::config::{Config, PeerConfig};
use crate::crypto::identity::{Identity, verify_signature, derive_session_key};
use crate::crypto::session::SessionCipher;
use crate::network::dispatch::{DispatchCtx, dispatch};
use crate::network::gossip::GossipTable;
use crate::network::protocol::{ControlMsg, Bytes32, Bytes64, encode_control};

type TcpWriteHalf = tokio::net::tcp::OwnedWriteHalf;

// ── Per-peer shared state ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus { Connecting, Authenticated, Down }

#[derive(Debug)]
pub struct PeerState {
    pub name:              String,
    pub mac:               String,
    pub status:            PeerStatus,
    pub cipher:            Option<SessionCipher>,
    pub missed_heartbeats: u32,
}

impl PeerState {
    pub fn new(name: String, mac: String) -> Self {
        Self { name, mac, status: PeerStatus::Connecting, cipher: None, missed_heartbeats: 0 }
    }
}

pub type SharedPeerState = Arc<Mutex<PeerState>>;
pub type PeerSender      = mpsc::Sender<Vec<u8>>;

// ── Auth: CLIENT connecting to server ─────────────────────────────────────────

pub async fn connect_and_auth(
    peer_cfg:    &PeerConfig,
    identity:    &Identity,
    config:      Arc<Config>,
    peer_state:  SharedPeerState,
    peers:       Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx_map: Arc<Mutex<HashMap<String, PeerSender>>>,
    gossip:      GossipTable,
    state_path:  PathBuf,
) -> Result<PeerSender> {
    let addr = format!("{}:{}", peer_cfg.address, config.node.control_port)
        .parse::<std::net::SocketAddr>()
        .context("Invalid peer address")?;

    tracing::info!("Connecting to {} at {}", peer_cfg.name, addr);
    let stream = TcpStream::connect(addr).await
        .context(format!("Cannot connect to {}", peer_cfg.name))?;

    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));

    // Step 1: receive challenge
    let (server_nonce, server_pubkey_bytes) = match read_control_plain(&mut reader).await? {
        ControlMsg::AuthChallenge { server_nonce, server_pubkey } =>
            (server_nonce.0, server_pubkey.0),
        _ => anyhow::bail!("Expected AuthChallenge"),
    };

    let expected = config.peer_pubkey_bytes(&peer_cfg.name)?;
    if server_pubkey_bytes != expected {
        anyhow::bail!("Server pubkey mismatch for {}", peer_cfg.name);
    }

    // Step 2: sign and respond
    let client_nonce: [u8; 32] = rand::thread_rng().gen();
    let mut to_sign = [server_nonce, client_nonce].concat();
    let sig = identity.sign(&to_sign);

    send_plain(&writer, &ControlMsg::AuthResponse {
        client_nonce:  Bytes32(client_nonce),
        client_pubkey: Bytes32(identity.pubkey_bytes()),
        signature:     Bytes64(sig),
    }).await?;

    // Step 3: verify countersig
    let server_sig = match read_control_plain(&mut reader).await? {
        ControlMsg::AuthAck { accepted: true, signature, .. } => signature.0,
        ControlMsg::AuthAck { accepted: false, reason, .. } =>
            anyhow::bail!("Auth rejected by {}: {:?}", peer_cfg.name, reason),
        _ => anyhow::bail!("Expected AuthAck"),
    };

    to_sign = [client_nonce, server_nonce].concat();
    verify_signature(&server_pubkey_bytes, &to_sign, &server_sig)?;

    // Step 4: derive session key
    let mesh_psk    = config.mesh_psk_bytes()?;
    let session_key = derive_session_key(&mesh_psk, &server_nonce, &client_nonce);
    let cipher      = SessionCipher::new(session_key);

    tracing::info!("✓ Authenticated with {}", peer_cfg.name);
    {
        let mut s  = peer_state.lock().await;
        s.status   = PeerStatus::Authenticated;
        s.cipher   = Some(cipher);
    }

    // Spawn write task
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
    let writer_c  = writer.clone();
    let pn        = peer_cfg.name.clone();
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if writer_c.lock().await.write_all(&bytes).await.is_err() {
                tracing::warn!("[{}] write task ended", pn);
                break;
            }
        }
    });

    // Spawn read + dispatch task
    let ps_c   = peer_state.clone();
    let ctx    = DispatchCtx {
        from_peer:  peer_cfg.name.clone(),
        config:     config.clone(),
        peers,
        peer_tx:    peer_tx_map,
        gossip,
        state_path,
    };
    tokio::spawn(async move {
        loop {
            match read_control_encrypted_with_cipher(&mut reader, &ps_c).await {
                Ok(msg)  => dispatch(msg, &ps_c, &ctx).await,
                Err(e)   => {
                    tracing::warn!("[{}] read error: {}", ctx.from_peer, e);
                    ps_c.lock().await.status = PeerStatus::Down;
                    break;
                }
            }
        }
    });

    Ok(tx)
}

// ── Auth: SERVER accepting incoming connection ─────────────────────────────────

pub async fn accept_and_auth(
    stream:      TcpStream,
    identity:    &Identity,
    config:      Arc<Config>,
    peers:       Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx_map: Arc<Mutex<HashMap<String, PeerSender>>>,
    gossip:      GossipTable,
    state_path:  PathBuf,
) -> Result<(String, SharedPeerState, PeerSender)> {
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));

    // Step 1: send challenge
    let server_nonce: [u8; 32] = rand::thread_rng().gen();
    send_plain(&writer, &ControlMsg::AuthChallenge {
        server_nonce:  Bytes32(server_nonce),
        server_pubkey: Bytes32(identity.pubkey_bytes()),
    }).await?;

    // Step 2: receive response
    let (client_nonce, client_pubkey_bytes, client_sig) =
        match read_control_plain(&mut reader).await? {
            ControlMsg::AuthResponse { client_nonce, client_pubkey, signature } =>
                (client_nonce.0, client_pubkey.0, signature.0),
            _ => anyhow::bail!("Expected AuthResponse"),
        };

    // Look up peer in allowlist by pubkey
    let peer_cfg = config.peers.iter()
        .find(|p| Config::peer_pubkey_bytes_from_hex(&p.pubkey)
            .map(|b| b == client_pubkey_bytes)
            .unwrap_or(false))
        .context("Client pubkey not in allowlist")?
        .clone();

    verify_signature(&client_pubkey_bytes, &[server_nonce, client_nonce].concat(), &client_sig)?;

    // Step 3: countersig ack
    let countersig = identity.sign(&[client_nonce, server_nonce].concat());
    send_plain(&writer, &ControlMsg::AuthAck {
        accepted:  true,
        signature: Bytes64(countersig),
        reason:    None,
    }).await?;

    // Step 4: derive session key
    let mesh_psk    = config.mesh_psk_bytes()?;
    let session_key = derive_session_key(&mesh_psk, &server_nonce, &client_nonce);
    let cipher      = SessionCipher::new(session_key);

    tracing::info!("✓ Accepted auth from {}", peer_cfg.name);

    let peer_state = Arc::new(Mutex::new(PeerState::new(peer_cfg.name.clone(), peer_cfg.mac.clone())));
    {
        let mut s = peer_state.lock().await;
        s.status  = PeerStatus::Authenticated;
        s.cipher  = Some(cipher);
    }

    // Spawn write task
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
    let writer_c  = writer.clone();
    let pn        = peer_cfg.name.clone();
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if writer_c.lock().await.write_all(&bytes).await.is_err() {
                tracing::warn!("[{}] write task ended", pn);
                break;
            }
        }
    });

    // Spawn read + dispatch task
    let ps_c = peer_state.clone();
    let ctx  = DispatchCtx {
        from_peer:  peer_cfg.name.clone(),
        config:     config.clone(),
        peers,
        peer_tx:    peer_tx_map,
        gossip,
        state_path,
    };
    tokio::spawn(async move {
        loop {
            match read_control_encrypted_with_cipher(&mut reader, &ps_c).await {
                Ok(msg)  => dispatch(msg, &ps_c, &ctx).await,
                Err(e)   => {
                    tracing::warn!("[{}] read error: {}", ctx.from_peer, e);
                    ps_c.lock().await.status = PeerStatus::Down;
                    break;
                }
            }
        }
    });

    Ok((peer_cfg.name.clone(), peer_state, tx))
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

pub async fn read_control_plain<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<ControlMsg> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_048_576 { anyhow::bail!("Message too large: {} bytes", len); }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

pub async fn read_control_encrypted_with_cipher<R: AsyncReadExt + Unpin>(
    r:  &mut R,
    ps: &SharedPeerState,
) -> Result<ControlMsg> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_048_576 { anyhow::bail!("Message too large"); }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;

    let cipher = ps.lock().await.cipher.clone()
        .context("No session cipher yet")?;
    let plain = cipher.decrypt(&buf)?;
    Ok(serde_json::from_slice(&plain)?)
}

async fn send_plain(w: &Arc<Mutex<TcpWriteHalf>>, msg: &ControlMsg) -> Result<()> {
    w.lock().await.write_all(&encode_control(msg)?).await?;
    Ok(())
}

// ── Config helper ─────────────────────────────────────────────────────────────

impl Config {
    pub fn peer_pubkey_bytes_from_hex(hex_str: &str) -> anyhow::Result<[u8; 32]> {
        let bytes = hex::decode(hex_str)?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("Pubkey must be 32 bytes"))
    }
}
