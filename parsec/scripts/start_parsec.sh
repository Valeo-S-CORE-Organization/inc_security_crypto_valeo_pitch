#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG="$SCRIPT_DIR/../config.toml"
PARSEC_BIN="${PARSEC_BIN:-$HOME/.cargo/bin/parsec}"
SOCKET="/tmp/parsec/run/parsec.sock"

# Ensure runtime dirs exist
mkdir -p "$(dirname "$SOCKET")"
mkdir -p "$HOME/.pkcs11-engine/parsec/mappings"

if [[ ! -x "$PARSEC_BIN" ]]; then
    echo "parsec binary not found at $PARSEC_BIN" >&2
    echo "install: cargo install parsec-service --features 'pkcs11-provider,unix-peer-credentials-authenticator'" >&2
    exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
    echo "config not found: $CONFIG" >&2
    exit 1
fi

# Kill any stale instance
pkill -f "parsec -c $CONFIG" 2>/dev/null || true
rm -f "$SOCKET"

echo "starting parsec with $CONFIG"
exec "$PARSEC_BIN" -c "$CONFIG"
