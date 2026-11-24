# Demo for testing crypto daemon and client via IPC (UNIX Domain Sockets)

This is an integration test intended for verifying crypto daemon and client via IPC.

## Requirements

1. S-CORE environment is already initialized.
2. Bazel is already installed.
3. Linux environment (e.g. Ubuntu 22.04).
4. Run commands as root or with `sudo` permissions to create `/opt/crypto` directories.

## Overview

The demo consists of:
- `crypto_daemon`: S-CORE Crypto daemon handling cryptographic requests via UNIX domain sockets.
- `score_demo`: Client application requesting HMAC and Key Management operations via IPC.
- `init_pkcs11_token`: Setup utility initializing the PKCS#11 token and importing integration test keys.

# Steps to run demo without bazel (integration environment)

## Prepare Environment

> Note: Ensure integration_test_config.bin was generated with the test user's UID listed in both 
> allowed_uids and the application-resource mapping. If test user's UID is neither 0 nor 1000,
> the settings in `score/tests/test_vectors/config/integration_test_config.json` need to be adapted.

### Common Directory Setup

```bash
mkdir -p /opt/crypto/share
mkdir -p /opt/crypto/etc
cp -r score/tests/test_vectors /opt/crypto/share && rm -r /opt/crypto/share/test_vectors/config
cp score/tests/test_vectors/config/*.kv /opt/crypto/etc
cp bazel-bin/score/tests/test_vectors/config/integration_test_config.bin /opt/crypto/etc
cp score/tests/config/logging.json /opt/crypto/etc
```

### Option A: Using Default SoftHSM Backend

```bash
# 1. Build using default SoftHSM
bazel build //score/...

# 2. Setup directory and SoftHSM configuration
mkdir -p /tmp/softhsm_tokens
export SOFTHSM2_CONF=/tmp/softhsm2.conf
printf "directories.tokendir = /tmp/softhsm_tokens\nobjectstore.backend = file\nlog.level = INFO\n" > /tmp/softhsm2.conf

# 3. Initialize token
./bazel-bin/score/tests/integration_tests/init_pkcs11_token \
  --token-label PKCS11_TOKEN \
  --so-pin 12345678 \
  --user-pin 1234 \
  --import-key-file /opt/crypto/share/test_vectors/mac/key_aes_256.key \
  --import-key-label integration_test_hmac
```

### Option B: Using Rust Cryptoki Backend

```bash
# 1. Build with Cryptoki backend active
bazel build //score/... \
  --//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped

# 2. Setup directory and Cryptoki token store
mkdir -p /tmp/cryptoki_tokens
export CRYPTOKI_STORE=/tmp/cryptoki_tokens/token.json

# 3. Initialize token
./bazel-bin/score/tests/integration_tests/init_pkcs11_token \
  --token-label PKCS11_TOKEN \
  --so-pin 12345678 \
  --user-pin 1234 \
  --import-key-file /opt/crypto/share/test_vectors/mac/key_aes_256.key \
  --import-key-label integration_test_hmac
```

## Start Daemon

```bash
export CRYPTO_CONFIG_FILE=/opt/crypto/etc/integration_test_config.bin
export SOFTHSM2_CONF=/tmp/softhsm2.conf                             # If using SoftHSM2
export CRYPTOKI_STORE=/tmp/cryptoki_tokens/token.json               # If using Rust Cryptoki
export MW_LOG_CONFIG_FILE=/opt/crypto/etc/logging.json

./bazel-bin/score/crypto/src/daemon/crypto_daemon
```

> `MW_LOG_CONFIG_FILE` points to the logging config in `/opt/crypto/etc/logging.json`.
> It enables verbose console logging (`kVerbose`). Omit it to fall back to the default log level (`kWarn`) — debug messages will not be shown.

## Start Demo

```bash
./bazel-bin/score/tests/integration_tests/score_demo
```
