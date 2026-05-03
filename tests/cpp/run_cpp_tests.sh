#!/usr/bin/env bash
set -euo pipefail

BASE_PATH="$TEST_SRCDIR/_main"
LIB_DIR="$BASE_PATH/src"
BINARY="$BASE_PATH/cpp/test_cpp_bin"

export LD_LIBRARY_PATH="${LIB_DIR}:${LD_LIBRARY_PATH:-}"

echo "Running test binary: $BINARY"
echo "Looking for library in: $LIB_DIR"

if [[ -x "$BINARY" ]]; then
    "$BINARY"
else
    echo "ERROR: Binary not found or not executable at $BINARY"
    # Debug: show what IS in the sandbox if we fail
    find "$TEST_SRCDIR" -name "*.so"
    exit 1
fi
