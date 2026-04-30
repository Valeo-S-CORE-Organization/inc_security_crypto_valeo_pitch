#!/usr/bin/env bash
set -euo pipefail

# Bazel sets TEST_SRCDIR to the runfiles root.
SO_DIR="${TEST_SRCDIR}/cryptoki/src"
export LD_LIBRARY_PATH="${SO_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

exec "${TEST_SRCDIR}/cryptoki/cpp/test_cpp_bin"
