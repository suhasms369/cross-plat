# meshkvm

**Secure P2P software KVM** — share mouse, keyboard, and clipboard across Mac, Windows, and Linux on a LAN.

No server required. Every node is a peer. If one machine goes down the others keep working and route around it.

---

## Security model

| Layer | Mechanism |
|---|---|
| Identity | Ed25519 keypair per machine — generated once, distributed manually |
| Transport | AES-256-GCM — every packet, unique nonce per packet |
| Pre-shared key | 32-byte PSK distributed via USB/cloud once at setup |
| Key rotation | Automatic every 24h — new key derived, old key dead |
| Replay protection | Persistent per-peer sequence numbers survive reboots |
| Gossip | Signed neighbor lists — 2-hop mesh awareness |
| MAC allowlist | Hardware identity layer on top of crypto |

**Threat model:** An attacker on your LAN with a cloned MAC address and a network sniffer still cannot read your traffic, forge messages, replay old auth packets, or inject fake topology data.

---

## Architecture

```
meshkvm/
├── src/
│   ├── main.rs               Entry point, tokio runtime, all loop spawns
│   ├── config.rs             TOML config loader + topology helpers
│   ├── error.rs              Custom error types
│   ├── state.rs              Persistent replay-protection counters (survives reboot)
│   │
│   ├── crypto/
│   │   ├── identity.rs       Ed25519 keygen, sign, verify, session key derivation
│   │   └── session.rs        AES-256-GCM encrypt/decrypt with per-packet nonces
│   │
│   ├── network/
│   │   ├── protocol.rs       All wire types: ControlMsg + DataMsg, Bytes32/64 serde
│   │   ├── peer.rs           4-step auth handshake (client + server), write/read tasks
│   │   ├── dispatch.rs       Routes every incoming control message to its handler
│   │   ├── heartbeat.rs      500ms heartbeat, miss threshold → mark peer Down
│   │   ├── gossip.rs         30s signed neighbor broadcast, 2-hop table
│   │   ├── rotation.rs       24h session key rotation + incoming rotation handler
│   │   └── router.rs         Edge trigger, route decision, gossip fallback
│   │
│   └── input/
│       ├── capture.rs        rdev listener → DataMsg channel
│       ├── inject.rs         enigo injection on receiving end
│       └── clipboard.rs      Platform CLI clipboard (pbcopy / xclip / PowerShell)
│
├── Cargo.toml
├── Cargo.lock
├── config.example.toml       Template — copy to ~/.config/meshkvm/config.toml
└── README.md
```

---

## Setup

### Step 1 — Build

```bash
# Requires Rust toolchain: https://rustup.rs
cargo build --release
# Binary: target/release/meshkvm
```

### Step 2 — Generate identity keys (run on EACH machine)

```bash
./meshkvm --keygen
```

This creates `~/.config/meshkvm/identity.key` and prints your **public key**. Copy that hex string — you'll paste it into the other machines' config.

### Step 3 — Generate the shared PSK (run once, on any machine)

```bash
openssl rand -hex 32
```

This gives you a 64-character hex string. Paste it into `mesh_psk` in every machine's config. Distribute via USB stick or your Nextcloud — it never needs to go over the network again.

### Step 4 — Configure

```bash
cp config.example.toml ~/.config/meshkvm/config.toml
# Edit with your node name, IPs, MACs, pubkeys, and PSK
```

Key fields:

```toml
[node]
name = "linux-box"           # must match your entry in topology.order
mesh_psk = "64hexchars..."   # same on ALL nodes

[topology]
order = ["linux-box", "windows-box", "macbook"]   # left → right

[[peers]]
name    = "windows-box"
mac     = "11:22:33:44:55:66"
address = "192.168.1.100"
pubkey  = "hexed25519pubkey"  # from `meshkvm --keygen` on that machine
```

### Step 5 — Run

```bash
./meshkvm

# Verbose logging:
RUST_LOG=debug ./meshkvm

# Custom config path:
./meshkvm --config /etc/meshkvm/config.toml
```

---

## How it works

**Topology** is a static ordered list. Moving your cursor off the **right edge** hands off to the next node. Off the **left edge** returns. If a node is down, the mesh checks the gossip table for a 2-hop path and routes around it.

**Auth handshake** (4 steps):
1. Server sends a random nonce + its pubkey
2. Client signs `(server_nonce || client_nonce)` with its Ed25519 key, sends back its pubkey + nonce
3. Server verifies signature, sends countersignature back
4. Both sides independently derive `session_key = SHA256(PSK || server_nonce || client_nonce)` — nothing in transit

**Key rotation** (every 24h):
- Initiator generates a new nonce, signs it, sends encrypted under current key
- Both sides derive `new_key = SHA256("rotation" || current_key || new_nonce)`
- Receiver acks with new key — proves it derived correctly
- Old key is dead. Sequence number persisted to disk — replay blocked even after reboot.

---

## Platform notes

| Platform | Requirements |
|---|---|
| **Linux** | `xclip` (X11) or `wl-clipboard` (Wayland) for clipboard sync. rdev may need uinput permissions. |
| **macOS** | Grant **Accessibility** permissions in System Settings → Privacy & Security. |
| **Windows** | Allow inbound on TCP 24801 and UDP 24802 in Windows Firewall. |

### Run as service (Linux systemd)

```ini
# /etc/systemd/system/meshkvm.service
[Unit]
Description=meshkvm P2P KVM
After=network.target

[Service]
ExecStart=/usr/local/bin/meshkvm
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now meshkvm
```

---

## Ports

| Port | Protocol | Purpose |
|---|---|---|
| 24801 | TCP | Control plane — auth, heartbeat, gossip, key rotation, clipboard |
| 24802 | UDP | Data plane — mouse and keyboard events |

Both configurable in `config.toml`.
