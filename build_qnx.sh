#!/bin/bash
set -e

# Source QNX environment
source ~/qnx800/qnxsdp-env.sh

# OpenSSL configuration for cross-compilation
export OPENSSL_LIB_DIR="$QNX_TARGET/aarch64le/usr/lib"
export OPENSSL_INCLUDE_DIR="$QNX_TARGET/usr/include"
export OPENSSL_DIR="$QNX_TARGET"
export PKG_CONFIG_ALLOW_CROSS=1

# Compiler settings
export CC="qcc -Vgcc_ntoaarch64le"
export CXX="qcc -Vgcc_ntoaarch64le_cxx"

CMD=${1:-build}
shift || true

if [ "$CMD" = "examples" ]; then
    CMD="build"
    if [ -n "$1" ]; then
        EXAMPLE_NAME="$1"
        shift
        set -- "--example" "$EXAMPLE_NAME" "$@"
    else
        set -- "--examples" "$@"
    fi
fi

echo "Running 'cargo $CMD' for QNX SDP 8.0 (aarch64)..."
cargo $CMD --target aarch64-unknown-nto-qnx800 --release "$@"
