mod config;
mod crypto;
mod error;
mod input;
mod network;
mod state;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tracing::info;

use config::Config;
use crypto::identity::Identity;
use input::capture::start_capture;
use input::inject::spawn_injector;
use input::clipboard::Clipboard;

use network::gossip::{GossipTable, run_gossip_loop};
use network::heartbeat::run_heartbeat_loop;
use network::peer::{SharedPeerState, PeerState, PeerSender, connect_and_auth, accept_and_auth};
use network::protocol::{DataMsg, ControlMsg, encode_control_encrypted};
use network::rotation::run_rotation_loop;
use network::router::{ActiveNode, Router};

const HELP: &str = r#"meshkvm — Secure P2P software KVM

USAGE:
    meshkvm [OPTIONS]

OPTIONS:
    --config <path>     Config file (default: ~/.config/meshkvm/config.toml)
    --keygen            Generate identity keypair and print pubkey, then exit
    --out <path>        Key output path for --keygen (default: ~/.config/meshkvm/identity.key)
    --help, -h          Show this help

SECURITY MODEL:
    Ed25519 identity keys  — generated once per machine, distributed via USB/cloud
    AES-256-GCM            — every packet encrypted, per-packet nonces
    PSK                    — shared 32-byte key, manually distributed
    Key rotation           — automatic every 24h, replay-protected
    Signed gossip          — 2-hop neighbor awareness, all messages verified
    MAC allowlist          — hardware identity layer on top of crypto

SETUP (3 steps):
    1. Run `meshkvm --keygen` on EACH machine.
       Copy each machine's pubkey into the other machines' config.toml [[peers]] blocks.
    2. Generate a shared PSK:  openssl rand -hex 32
       Paste into mesh_psk in every config.toml.
    3. Run `meshkvm` on all machines.

EXAMPLES:
    meshkvm --keygen --out /etc/meshkvm/identity.key
    meshkvm --config /etc/meshkvm/config.toml
    RUST_LOG=debug meshkvm
"#;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Logging ───────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("meshkvm=info".parse()?)
        )
        .compact()
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print!("{}", HELP);
        return Ok(());
    }

    let config_path = args.iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir().join("meshkvm/config.toml"));

    // ── Keygen mode ───────────────────────────────────────────────────────────
    if args.contains(&"--keygen".to_string()) {
        let key_path = args.iter()
            .position(|a| a == "--out")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or_else(|| config_dir().join("meshkvm/identity.key"));
        let id = Identity::load_or_generate(&key_path)?;
        println!("\nIdentity key: {:?}", key_path);
        println!("\nPublic key (add to other nodes' [[peers]] pubkey field):\n\n  {}\n", id.pubkey_hex());
        return Ok(());
    }

    // ── Load config + identity ────────────────────────────────────────────────
    info!("Loading config from {:?}", config_path);
    let config   = Arc::new(Config::load(&config_path)?);
    let identity = Arc::new(Identity::load_or_generate(&config.node.identity_key)?);

    info!("Node: {} | pubkey: {}", config.node.name, identity.pubkey_hex());
    info!("Topology: {:?}", config.topology.order);
    match config.left_neighbor()  { Some(n) => info!("← Left:  {}", n), None => info!("← Left:  <edge>") }
    match config.right_neighbor() { Some(n) => info!("→ Right: {}", n), None => info!("→ Right: <edge>") }

    let state_path = data_dir().join("meshkvm/state.toml");

    // ── Shared state ──────────────────────────────────────────────────────────
    let peers:   Arc<Mutex<HashMap<String, SharedPeerState>>> = Arc::new(Mutex::new(HashMap::new()));
    let peer_tx: Arc<Mutex<HashMap<String, PeerSender>>>      = Arc::new(Mutex::new(HashMap::new()));
    let gossip:  GossipTable = Arc::new(Mutex::new(HashMap::new()));
    let router   = Arc::new(Router::new(config.clone(), peers.clone(), gossip.clone()));

    // ── TCP listener ──────────────────────────────────────────────────────────
    {
        let cfg   = config.clone();
        let id    = identity.clone();
        let p     = peers.clone();
        let ptx   = peer_tx.clone();
        let g     = gossip.clone();
        let sp    = state_path.clone();
        let bind  = format!("0.0.0.0:{}", config.node.control_port);

        tokio::spawn(async move {
            let listener = TcpListener::bind(&bind).await.expect("Cannot bind control port");
            info!("Listening on {}", bind);
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Incoming from {}", addr);
                        let (cfg, id, p, ptx, g, sp) =
                            (cfg.clone(), id.clone(), p.clone(), ptx.clone(), g.clone(), sp.clone());
                        tokio::spawn(async move {
                            match accept_and_auth(stream, &id, cfg, p.clone(), ptx.clone(), g, sp).await {
                                Ok((name, ps, tx)) => {
                                    p.lock().await.insert(name.clone(), ps);
                                    ptx.lock().await.insert(name, tx);
                                }
                                Err(e) => tracing::warn!("Auth failed from {}: {}", addr, e),
                            }
                        });
                    }
                    Err(e) => tracing::error!("Accept: {}", e),
                }
            }
        });
    }

    // ── Connect to all configured peers ───────────────────────────────────────
    for peer_cfg in &config.peers {
        // Pre-insert peer state + placeholder channel
        let ps = Arc::new(Mutex::new(PeerState::new(peer_cfg.name.clone(), peer_cfg.mac.clone())));
        peers.lock().await.insert(peer_cfg.name.clone(), ps.clone());
        let (placeholder, _) = mpsc::channel::<Vec<u8>>(1);
        peer_tx.lock().await.insert(peer_cfg.name.clone(), placeholder);

        let (pcfg, cfg, id, p, ptx, g, sp) = (
            peer_cfg.clone(), config.clone(), identity.clone(),
            peers.clone(), peer_tx.clone(), gossip.clone(), state_path.clone(),
        );
        let ps_c = ps.clone();

        tokio::spawn(async move {
            loop {
                match connect_and_auth(&pcfg, &id, cfg.clone(), ps_c.clone(), p.clone(), ptx.clone(), g.clone(), sp.clone()).await {
                    Ok(tx) => {
                        ptx.lock().await.insert(pcfg.name.clone(), tx);
                        info!("Connected to {}", pcfg.name);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Cannot connect to {}: {} — retry in 5s", pcfg.name, e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    // ── Background loops ──────────────────────────────────────────────────────
    {
        let (cfg, p, tx) = (config.clone(), peers.clone(), peer_tx.clone());
        tokio::spawn(async move { run_heartbeat_loop(cfg, p, tx).await });
    }
    {
        let (cfg, id, p, tx) = (config.clone(), identity.clone(), peers.clone(), peer_tx.clone());
        tokio::spawn(async move { run_gossip_loop(cfg, id, p, tx).await });
    }
    {
        let (cfg, id, p, tx, sp) = (config.clone(), identity.clone(), peers.clone(), peer_tx.clone(), state_path.clone());
        tokio::spawn(async move { run_rotation_loop(cfg, id, p, tx, sp).await });
    }

    // ── Clipboard watcher ─────────────────────────────────────────────────────
    {
        let p = peers.clone(); let ptx = peer_tx.clone();
        tokio::spawn(async move {
            let cb = match Clipboard::new() {
                Ok(c)  => c,
                Err(e) => { tracing::warn!("Clipboard unavailable: {}", e); return; }
            };
            let mut last: Option<String> = None;
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let current = cb.get_text();
                if input::clipboard::clipboard_changed(&current, &last) {
                    if let Some(ref text) = current {
                        broadcast_control(
                            &ControlMsg::ClipboardSync { content: text.as_bytes().to_vec() },
                            &p, &ptx,
                        ).await;
                    }
                    last = current;
                }
            }
        });
    }

    // ── UDP send socket ──────────────────────────────────────────────────────────
    let udp_send = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // ── Input capture → route → forward ──────────────────────────────────────
    let (input_tx, mut input_rx) = mpsc::channel::<DataMsg>(1024);
    start_capture(input_tx);

    let injector = spawn_injector().context("Injector init")?;
    let (rc, cc, pc, ptxc, inj_input, udp_fwd) = (router.clone(), config.clone(), peers.clone(), peer_tx.clone(), injector.clone(), udp_send.clone());

    tokio::spawn(async move {
        while let Some(msg) = input_rx.recv().await {
            use network::router::RouteDecision::*;
            match rc.current_destination().await {
                Local => {
                    if let DataMsg::MouseMove { x, y } = &msg {
                        if let Some(edge) = detect_edge(*x, *y, &cc) {
                            if let SendTo(peer) = rc.route_edge(edge).await {
                                info!("Edge → {} ({})", peer, edge);
                                rc.set_active(ActiveNode::Remote(peer.clone())).await;
                                send_data(&peer, DataMsg::EdgeHandoff {
                                    from_node:     cc.node.name.clone(),
                                    edge:          edge.into(),
                                    cursor_y_norm: y / cc.display.height as f64,
                                }, &pc, &cc, &udp_fwd).await;
                            }
                        }
                    }
                }
                SendTo(peer) => {
                    if let DataMsg::MouseMove { x, y } = &msg {
                        if let Some(edge) = detect_edge(*x, *y, &cc) {
                            info!("Return edge — reclaiming control");
                            rc.set_active(ActiveNode::Local).await;
                            send_data(&peer, DataMsg::EdgeReturn {
                                to_node:       cc.node.name.clone(),
                                edge:          edge.into(),
                                cursor_y_norm: y / cc.display.height as f64,
                            }, &pc, &cc, &udp_fwd).await;
                            continue;
                        }
                    }
                    send_data(&peer, msg, &pc, &cc, &udp_fwd).await;
                }
                Block => {}
            }
        }
    });

    // ── UDP receiver (inject incoming events) ─────────────────────────────────
    {
        let bind  = format!("0.0.0.0:{}", config.node.data_port);
        let sock  = tokio::net::UdpSocket::bind(&bind).await?;
        info!("UDP data port: {}", bind);
        let p2    = peers.clone();
        let inj   = injector.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                if let Ok((n, _)) = sock.recv_from(&mut buf).await {
                    let data = &buf[..n];
                    let map  = p2.lock().await;
                    for ps in map.values() {
                        let s = ps.lock().await;
                        if let Some(cipher) = &s.cipher {
                            if let Ok(plain) = cipher.decrypt(data) {
                                if let Ok(msg) = serde_json::from_slice::<DataMsg>(&plain) {
                                    inj.inject(msg);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    info!("meshkvm running — Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn detect_edge(x: f64, _y: f64, cfg: &Config) -> Option<&'static str> {
    let t = cfg.display.edge_threshold_px as f64;
    let w = cfg.display.width as f64;
    // Use a wider deadzone (3x threshold) to prevent flicker at edges
    if x <= t           { return Some("left");  }
    if x >= w - t       { return Some("right"); }
    None
}

/// Once handed off, only return control when cursor reaches the OPPOSITE edge
/// with a larger deadzone to prevent immediate bounce-back.
fn detect_return_edge(x: f64, _y: f64, cfg: &Config, active_edge: &str) -> bool {
    let w   = cfg.display.width as f64;
    let pad = (cfg.display.edge_threshold_px * 5) as f64; // 5x deadzone for return
    match active_edge {
        "right" => x <= pad,          // came from right, return when hitting left side
        "left"  => x >= w - pad,      // came from left, return when hitting right side
        _       => false,
    }
}

async fn send_data(
    peer:    &str,
    msg:     DataMsg,
    peers:   &Arc<Mutex<HashMap<String, SharedPeerState>>>,
    config:  &Config,
    udp_tx:  &Arc<UdpSocket>,
) {
    let cipher = {
        let m = peers.lock().await;
        match m.get(peer) { Some(ps) => ps.lock().await.cipher.clone(), None => return }
    };
    // Find peer address from config
    let peer_addr = match config.peer_by_name(peer) {
        Some(p) => format!("{}:{}", p.address, config.node.data_port),
        None => return,
    };
    if let Some(c) = cipher {
        if let Ok(json) = serde_json::to_vec(&msg) {
            if let Ok(enc) = c.encrypt(&json) {
                let _ = udp_tx.send_to(&enc, &peer_addr).await;
            }
        }
    }
}

async fn broadcast_control(
    msg:     &ControlMsg,
    peers:   &Arc<Mutex<HashMap<String, SharedPeerState>>>,
    peer_tx: &Arc<Mutex<HashMap<String, PeerSender>>>,
) {
    let map   = peers.lock().await;
    let txmap = peer_tx.lock().await;
    for (name, ps) in map.iter() {
        let s = ps.lock().await;
        if let Some(c) = &s.cipher {
            if let Ok(bytes) = encode_control_encrypted(msg, c) {
                if let Some(tx) = txmap.get(name) { let _ = tx.try_send(bytes); }
            }
        }
    }
}

fn config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_|
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".config"))
}

fn data_dir() -> PathBuf {
    std::env::var("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|_|
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".local/share"))
}
