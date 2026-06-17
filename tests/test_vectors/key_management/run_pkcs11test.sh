#!/usr/bin/env bash
set -euo pipefail

# Bazel sets TEST_SRCDIR to the runfiles root.
SO_DIR="${TEST_SRCDIR}/cryptoki/src"
export LD_LIBRARY_PATH="${SO_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

exec "${TEST_SRCDIR}/cryptoki/cpp/pkcs11test/pkcs11test" \
    -m libcryptoki.so \
    -l "${SO_DIR}" \
    -s 0 \
    -u 1234 \
    -o so-pin \
    -I \
    --gtest_filter="-Ciphers*:HMACs*:Duals*:*DES*:*MD5-RSA*:*SHA1-RSA*"
