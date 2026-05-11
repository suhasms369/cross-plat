# meshkvm

[![CI](https://github.com/suhasms369/cross-plat/actions/workflows/ci.yml/badge.svg)](https://github.com/suhasms369/cross-plat/actions/workflows/ci.yml)
[![License: GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
![Platforms](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)

## Known Bugs — Help Wanted

The core is working (auth, encryption, mesh routing, cross-platform CI) but these need fixing:

### 🐛 Input not suppressed on sender [`good first issue`]
When controlling a remote machine, local OS still processes mouse/keyboard events causing duplication.
**Fix:** Switch `rdev::listen` → `rdev::grab` in `src/input/capture.rs`. Pass `Arc<AtomicBool>` 
from router to suppress events when `is_remote = true`.

### 🐛 Mac → Windows direction broken [`good first issue`]  
One-way only currently. Likely display resolution mismatch in config — MacBook is 1440x900 
logical pixels not 1920x1080. Fix edge detection in `src/main.rs detect_edge()`.

### 🐛 Key mapping incorrect across platforms [`help wanted`]
rdev key names don't map 1:1 to enigo key names on all platforms.
Fix the lookup table in `src/input/inject.rs name_to_key()`.

### 💡 Nice to have
- mDNS auto-discovery instead of static IPs in config
- TUI status display (peer status, active node, key rotation countdown)  
- Wayland capture support (`libei` / `wlr-input-inhibitor`)
- macOS Universal Binary (lipo x86_64 + arm64)

**Secure P2P software KVM** — share your mouse, keyboard, and clipboard across Linux, macOS, and Windows machines on a LAN. No server, no cloud, no subscription.

Move your cursor off the edge of one screen and it appears on the next — just like a hardware KVM, but in software with a proper security model built in from scratch.

---

## Why not Barrier / Deskflow / lan-mouse?

| | Barrier | Deskflow | lan-mouse | **meshkvm** |
|---|---|---|---|---|
| Actively maintained | ✗ | ✓ | ✓ | ✓ |
| Memory-safe language | ✗ (C++) | ✗ (C++) | ✓ (Rust) | ✓ (Rust) |
| No single point of failure | ✗ | ✗ | ✗ | ✓ |
| Automatic key rotation | ✗ | ✗ | ✗ | ✓ |
| Replay attack protection | ✗ | ✗ | ✗ | ✓ |
| Signed gossip / mesh routing | ✗ | ✗ | ✗ | ✓ |
| Manual key distribution | ✗ | ✗ | ✗ | ✓ |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Topology (linear)                 │
│                                                     │
│   [linux-box] ←──────→ [windows-box] ←──────→ [macbook]  │
│       ↑                     ↑                   ↑   │
│   Direct peer           Direct peer         Direct peer  │
│       └─────────── 2-hop gossip ────────────────┘   │
│            (if windows-box is down, linux-box       │
│             can still reach macbook via gossip)     │
└─────────────────────────────────────────────────────┘

Control plane (TCP 24801) — auth, heartbeat, gossip, key rotation, clipboard
Data plane    (UDP 24802) — mouse events, keyboard events, edge handoff
```

### Module map

```
src/
├── main.rs              Runtime, all loop spawns, UDP receiver, edge detection
├── config.rs            TOML loader, left/right neighbor resolution
├── error.rs             Typed error enum
├── state.rs             Persistent replay-protection counters (survives reboot)
│
├── crypto/
│   ├── identity.rs      Ed25519 keygen, sign, verify, session key derivation
│   └── session.rs       AES-256-GCM encrypt/decrypt, per-packet nonces, zeroize on drop
│
├── network/
│   ├── protocol.rs      ControlMsg + DataMsg wire types, Bytes32/Bytes64 serde
│   ├── peer.rs          4-step auth handshake (client + server), write/read tasks
│   ├── dispatch.rs      Routes every incoming control message to its handler
│   ├── heartbeat.rs     500ms ping, miss threshold → mark peer Down (~1.5s detection)
│   ├── gossip.rs        30s signed neighbor broadcast, 2-hop routing table
│   ├── rotation.rs      24h session key rotation + incoming rotation handler
│   └── router.rs        Edge trigger, live route decision, gossip fallback
│
└── input/
    ├── capture.rs       rdev global listener → DataMsg channel
    ├── inject.rs        enigo injection on receiving end
    └── clipboard.rs     Platform CLI clipboard (pbcopy / xclip / wl-copy / PowerShell)
```

---

## Security model

### Keys

Two key types, distributed once manually (USB stick or your own cloud):

```
Key 1 — Ed25519 identity keypair (per machine)
  Private key: never leaves the machine it was generated on
  Public key:  pasted into all other nodes' config as a hex string
  Used for:    authenticating peers, signing gossip, signing key rotation

Key 2 — AES-256-GCM session key (derived, auto-rotated)
  Derived from: PSK + two nonces exchanged during auth handshake
  Used for:     encrypting all control and data traffic
  Rotated:      every 24h automatically, old key immediately dead
```

One additional value distributed manually:

```
mesh_psk — 32-byte pre-shared key (same on all nodes)
  Generated with: openssl rand -hex 32
  Used for:       mixing into session key derivation
  Never sent:     over the network, ever
```

### Auth handshake (4 steps, no key material in transit)

```
Server                              Client
  │                                   │
  │── AuthChallenge ─────────────────>│  server_nonce + server_pubkey
  │                                   │
  │<─ AuthResponse ───────────────────│  client_nonce + client_pubkey
  │                                   │  + Ed25519_sign(server_nonce || client_nonce)
  │                                   │
  │  verify sig against client_pubkey │
  │  check client_pubkey in allowlist │
  │                                   │
  │── AuthAck ───────────────────────>│  Ed25519_sign(client_nonce || server_nonce)
  │                                   │
  │  verify countersig                │
  │                                   │
  Both independently derive:          │
  session_key = SHA256(PSK || server_nonce || client_nonce)
```

### Key rotation (every 24h)

```
Initiator generates new_nonce
Signs: Ed25519(seq || timestamp || new_nonce)
Sends: KeyRotate message encrypted under current session key

Receiver:
  1. Verifies timestamp within ±5 minutes
  2. Verifies Ed25519 signature
  3. Checks seq > last_seen_seq (persistent, survives reboot)
  4. Derives: new_key = SHA256("rotation" || current_key || new_nonce)
  5. Acks with new key — proves derivation succeeded

Old key is dead. New key is live.
```

### Threat matrix

| Attack | Mitigation |
|---|---|
| MAC spoofing | Ed25519 challenge-response — cloned MAC without private key fails handshake |
| Replay auth | Per-handshake nonce — captured packets are useless |
| Replay key rotation | Persistent monotonic sequence numbers, survive reboots |
| Gossip poisoning | Every gossip message signed with sender's Ed25519 key |
| MITM on rotation | Rotation payload encrypted to recipient's pubkey + signed |
| Session key sniffing | AES-256-GCM — attacker sees ciphertext only |
| Compromised node | Remove from allowlist on all nodes, rotate PSK |

---

## Setup

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Build

```bash
git clone https://github.com/suhasms369/cross-plat
cd cross-plat
cargo build --release
# Binary: target/release/meshkvm  (or meshkvm.exe on Windows)
```

Or grab a pre-built binary from [Releases](https://github.com/suhasms369/cross-plat/releases).

### 3. Generate identity keys — run on EACH machine

```bash
./meshkvm --keygen
```

Output:
```
Identity key: "/home/user/.config/meshkvm/identity.key"

Public key (add to other nodes' [[peers]] pubkey field):

  0784bf95300acc0102a0ba25192232c70b888b983d92eba5afd6a3758060b431
```

Copy that hex string. You'll paste it into the other machines' config.

### 4. Generate the shared PSK — run once on any machine

```bash
openssl rand -hex 32
# e.g.: a3f1c2d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2
```

Copy this 64-character string. It goes into `mesh_psk` in **every** machine's config.

### 5. Configure each machine

```bash
cp config.example.toml ~/.config/meshkvm/config.toml
$EDITOR ~/.config/meshkvm/config.toml
```

```toml
[node]
name         = "linux-box"          # must match your entry in topology.order
identity_key = "/home/user/.config/meshkvm/identity.key"
mesh_psk     = "a3f1c2d4..."        # 64-char hex from step 4 — SAME on all nodes

[topology]
order = ["linux-box", "windows-box", "macbook"]  # left → right order

[display]
width  = 1920
height = 1080

[[peers]]
name    = "windows-box"
mac     = "11:22:33:44:55:66"        # MAC address of that machine's NIC
address = "192.168.1.100"            # LAN IP
pubkey  = "HEX_PUBKEY_FROM_STEP_3"  # from `meshkvm --keygen` on that machine

[[peers]]
name    = "macbook"
mac     = "aa:bb:cc:dd:ee:ff"
address = "192.168.1.101"
pubkey  = "HEX_PUBKEY_FROM_STEP_3"
```

### 6. Run

```bash
# Normal
./meshkvm

# Verbose
RUST_LOG=debug ./meshkvm

# Custom config
./meshkvm --config /etc/meshkvm/config.toml
```

---

## Platform notes

### Linux

- Clipboard: install `xclip` (X11) or `wl-clipboard` (Wayland)
  ```bash
  sudo apt install xclip       # X11
  sudo apt install wl-clipboard # Wayland
  ```
- rdev may need `uinput` group for input injection:
  ```bash
  sudo usermod -aG input $USER  # then re-login
  ```

### macOS

- Grant **Accessibility** permissions: System Settings → Privacy & Security → Accessibility → meshkvm ✓
- If you see "damaged app": `xattr -c meshkvm` after copying

### Windows

- Allow inbound on **TCP 24801** and **UDP 24802** in Windows Firewall
- Run as Administrator if input injection fails

### Run as a service (Linux systemd)

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
User=your-username

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now meshkvm
```

---

## Ports

| Port | Proto | Purpose |
|---|---|---|
| 24801 | TCP | Control — auth, heartbeat, gossip, key rotation, clipboard |
| 24802 | UDP | Data — mouse, keyboard, edge handoff |

Both are configurable in `config.toml`.

---

## Contributing

PRs welcome. A few areas that would be great to have:

- **TUI status display** — show peer status, active node, key rotation countdown
- **Auto-discovery** — mDNS/Avahi peer discovery instead of static IPs
- **Wayland capture** — rdev has limited Wayland support; a `libei`/`wlr-input-inhibitor` path would help
- **macOS Universal Binary** — combine x86_64 + arm64 with `lipo`

Please run `cargo fmt` and `cargo clippy` before submitting.

---

## License

GPL-2.0. See [LICENSE](LICENSE).

Built by [suhasms369](https://github.com/suhasms369).
