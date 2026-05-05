#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOCKET="/home/omar/.pkcs11-engine/parsec/run/parsec.sock"

# Resolve the client binary: Bazel output first, then Cargo
if [[ -f "$REPO_ROOT/bazel-bin/parsec/parsec_client" ]]; then
    CLIENT="$REPO_ROOT/bazel-bin/parsec/parsec_client"
elif [[ -f "$REPO_ROOT/target/debug/parsec_client" ]]; then
    CLIENT="$REPO_ROOT/target/debug/parsec_client"
elif [[ -f "$REPO_ROOT/target/release/parsec_client" ]]; then
    CLIENT="$REPO_ROOT/target/release/parsec_client"
else
    echo "parsec_client binary not found — build with:" >&2
    echo "  bazel build //parsec:parsec_client" >&2
    echo "  or: cargo build --bin parsec_client" >&2
    exit 1
fi

if [[ ! -S "$SOCKET" ]]; then
    echo "Parsec socket not found at $SOCKET — is the service running?" >&2
    echo "  start with: parsec/scripts/start_parsec.sh" >&2
    exit 1
fi

export PARSEC_SERVICE_ENDPOINT="unix:$SOCKET"
exec "$CLIENT" "$@"
