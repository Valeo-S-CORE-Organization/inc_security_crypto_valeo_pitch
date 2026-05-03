#!/usr/bin/env bash
set -euo pipefail

if [ -d "${TEST_SRCDIR}/_main" ]; then
    WS_PATH="${TEST_SRCDIR}/_main"
elif [ -d "${TEST_SRCDIR}/cryptoki" ]; then
    WS_PATH="${TEST_SRCDIR}/cryptoki"
else
    echo "ERROR: Could not find workspace root in $TEST_SRCDIR"
    ls -R "$TEST_SRCDIR"
    exit 1
fi

LIB_DIR="${WS_PATH}/src"
BINARY="${WS_PATH}/cpp/test_cpp_bin"

export LD_LIBRARY_PATH="${LIB_DIR}:${LD_LIBRARY_PATH:-}"

# 3. Execute the binary built by //cpp:test_cpp_bin
echo "--- Starting Native Wrapper Test ---"
exec "${WS_PATH}/cpp/test_cpp_bin"
