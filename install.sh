#!/usr/bin/env bash
# meshkvm install script — Linux and macOS
set -e

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${HOME}/.config/meshkvm"
DATA_DIR="${HOME}/.local/share/meshkvm"

echo "==> Building meshkvm (release)"
cargo build --release

echo "==> Installing binary to ${INSTALL_DIR}"
sudo install -m 755 target/release/meshkvm "${INSTALL_DIR}/meshkvm"

echo "==> Creating config directory: ${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"

if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    cp config.example.toml "${CONFIG_DIR}/config.toml"
    echo "    Config template written — edit ${CONFIG_DIR}/config.toml before running"
else
    echo "    Config already exists — skipping"
fi

echo ""
echo "==> Next steps:"
echo ""
echo "    1. Generate your identity key:"
echo "       meshkvm --keygen"
echo ""
echo "    2. Generate a shared PSK (run once, paste into all nodes):"
echo "       openssl rand -hex 32"
echo ""
echo "    3. Edit your config:"
echo "       \$EDITOR ${CONFIG_DIR}/config.toml"
echo ""
echo "    4. Run:"
echo "       meshkvm"
echo ""
