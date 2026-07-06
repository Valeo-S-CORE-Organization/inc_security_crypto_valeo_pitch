<!--
*******************************************************************************
Copyright (c) 2026 Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
*******************************************************************************
-->
# C++ & Rust Bazel Template Repository

This repository serves as a **template** for setting up **C++ and Rust projects** using **Bazel**.
It provides a **standardized project structure**, ensuring best practices for:

- **Build configuration** with Bazel.
- **Testing** (unit and integration tests).
- **Documentation** setup.
- **CI/CD workflows**.
- **Development environment** configuration.

---

## 📂 Project Structure

| File/Folder                         | Description                                       |
| ----------------------------------- | ------------------------------------------------- |
| `README.md`                         | Short description & build instructions            |
| `score/`                            | Crypto component                                  |
| `tests/`                            | Unit tests (UT) and integration tests (IT)        |
| `examples/`                         | Example files used for guidance                   |
| `third_party/`                      | Build file for external dependencies (e.g. gRPC)  |
| `docs/`                             | Documentation (Doxygen for C++ / mdBook for Rust) |
| `.vscode/`                          | Recommended VS Code settings                      |
| `.bazelrc`, `MODULE.bazel`, `BUILD` | Bazel configuration & settings                    |
| `project_config.bzl`                | Project-specific metadata for Bazel macros        |

### Score Folder Layout

```
score/                            ← Source code  ◄ main
├── mw/crypto/
│   └── api/                      ← [LIBRARY]
│       ├── common/
│       ├── config/               ← API config
│       ├── contexts/             ← Crypto contexts
│       ├── objects/              ← Key/cert objects
│       └── src/                  ← Entry point
│
└── crypto/
    ├── api/
    │   └── control_plane/        ← [LIB CTRL-PLANE]
    │
    ├── ipc/
    │   └── grpc_adapter/         ← [IPC — gRPC]
    │
    └── daemon/
        ├── control_plane/        ← [DAEMON CTRL-PLANE]
        ├── mediator/             ← [MEDIATOR]
        ├── data_manager/         ← [DATA MANAGER]
        ├── key_management/       ← [KEY MANAGEMENT]
        ├── config/               ← [CONFIG]
        └── provider/
            ├── score_provider/   ← [SW PROVIDER / OpenSSL]
            └── pkcs11/           ← [HW PROVIDER / PKCS#11]
```

---

## 🚀 Getting Started

### 1️⃣ Clone the Repository

```sh
git clone https://github.com/eclipse-score/YOUR_PROJECT.git
cd YOUR_PROJECT
```

### 2️⃣ Build the Examples of module

> DISCLAIMER: Depending what module implements, it's possible that different
> configuration flags needs to be set on command line.

To build all targets of the module the following command can be used:

```sh
# host platform
bazel build //score/...
# qnx arm architecture
# check .bazelrc for available host (x86_64) and target (aarch64) configurations
bazel build //score/... --config=aarch64-qnx
```

### 3️⃣ Run Tests

```sh
# pre-requisite: pull ubuntu docker image within devcontainer (once)
docker pull ubuntu:24.04

# host platform
bazel test //tests/...
# with detailed output and no caching
bazel test //tests/... --test_output=all --cache_test_results=no
```

Note: Run the `docker pull` command from a VS Code Terminal associated with the devcontainer. This properly sets up all environment variables, which may not be the case when just using docker to attach to the running container.

---

## 🛠 Tools & Linters

The template integrates **tools and linters** from **centralized repositories** to ensure consistency across projects.

- **C++:** `clang-tidy`, `cppcheck`, `Google Test`
- **Rust:** `clippy`, `rustfmt`, `Rust Unit Tests`
- **CI/CD:** GitHub Actions for automated builds and tests

---

## 📖 Documentation

- A **centralized docs structure** is planned.

```sh
bazel run //:docs
```

---

## ⚙️ `project_config.bzl`

This file defines project-specific metadata used by Bazel macros, such as `dash_license_checker`.

### 📌 Purpose

It provides structured configuration that helps determine behavior such as:

- Source language type (used to determine license check file format)
- Safety level or other compliance info (e.g. ASIL level)

### 📄 Example Content

```python
PROJECT_CONFIG = {
    "asil_level": "QM",  # or "ASIL-A", "ASIL-B", etc.
    "source_code": ["cpp", "rust"]  # Languages used in the module
}
```

### 🔧 Use Case

When used with macros like `dash_license_checker`, it allows dynamic selection of file types
 (e.g., `cargo`, `requirements`) based on the languages declared in `source_code`.

## DevContainer Setup

### Known Issue: Pre-commit Hook Not Running
**Problem:** The pre-commit hook does not run when using `git commit` inside the DevContainer.

**Cause:** A stale `core.hooksPath` configuration overrides the default hook lookup path.

**Fix:** Unset the custom hooks path:

```bash
git config --unset core.hooksPath
```

Note: For a permanent fix, run this command on the **host machine** (outside the DevContainer).
The DevContainer only receives a copy of the host's Git configuration at build time, so changes
made inside the container will not persist after a rebuild.

---

# Valeo Cryptoki Integration Guide

This document describes how the `@score/crypto/provider` Rust PKCS#11 module is integrated into the `score_crypto` daemon, replacing the default SoftHSM implementation.

## Overview

The integration bridges a custom Rust-based PKCS#11 provider with the existing C++ daemon architecture. To achieve this cleanly and natively:

1.  **Toolchain Configuration**: The integration uses the Ferrocene Rust toolchain (Rust 1.83.0+) to support modern Rust features (like `lazy_cell` and `unsafe extern "C"`) required by dependencies such as `score_logging` and `openssl`.
2.  **Compile-Time Toggles**: A Bazel `--define use_rust_pkcs11=true` flag is used to conditionally:
    *   Link `//score/cryptoki:cryptoki_cdylib` instead of `libsofthsm`.
    *   Inject the `USE_RUST_PKCS11=1` C++ preprocessor macro.
    *   Switch header includes from `<cryptoki.h>` to the Rust module's `<pkcs11.h>`.
3.  **Runtime Provider Remapping**: When the `USE_RUST_PKCS11` macro is active, the daemon dynamically remaps key-slot provider references from the legacy `"SOFTHSM"` string to `"SCORE_CRYPTO_PROVIDER"`. This ensures existing configuration files and client code remain compatible without modification.

## Prerequisites

Ensure your environment is set up to build the project. The `.bazelrc` is already configured to map the `host_config_1` configuration to the required Ferrocene toolchain for Linux, and `target_config_2` for `aarch64-qnx`.

## Building

Because the Rust module relies on specific toolchains and isolated extensions, you must pass the appropriate flags to Bazel.

### Building for Linux (Host)

To build the main `crypto_daemon` and the integration tools for your local machine:

```bash
bazel build //score/crypto/daemon:crypto_daemon \
            //tests/integration_tests:cryptoki_demo_client \
            //tests/integration_tests:init_softhsm_token \
    --config=host_config_1 \
    --define use_rust_pkcs11=true \
    --experimental_isolated_extension_usages
```

### Cross-Compiling for QNX (Target)

To build the daemon and tests for QNX (`aarch64-qnx`), use the `target_config_2` configuration. The workspace is configured to correctly map both target and host Ferrocene toolchains to ensure procedural macros build correctly, and automatically disables incompatible shared memory modules.

```bash
bazel build //score/... //tests/... \
    --config=target_config_2 \
    --define use_rust_pkcs11=true \
    --experimental_isolated_extension_usages
```
*(Note: Sphinx documentation targets are typically excluded when cross-compiling).*

## Running the Integration Demo

The `cryptoki_demo_client` exercises both HASH (software) and MAC (hardware) operations against the Rust PKCS#11 token. To run it successfully on your host, you must first initialize the token and start the daemon.

### 1. Initialize the Token and Key
Use the `init_softhsm_token` tool to initialize a local token store and import a test key. Since it's built with `--define use_rust_pkcs11=true`, it will talk directly to the Rust module rather than SoftHSM.

```bash
mkdir -p /tmp/rust_tokens
export CRYPTOKI_STORE=/tmp/rust_tokens/token.json

bazel run //tests/integration_tests:init_softhsm_token \
  --config=host_config_1 --define use_rust_pkcs11=true --experimental_isolated_extension_usages \
  -- \
  --token-dir /tmp/rust_tokens \
  --config-path /tmp/rust_tokens/softhsm2.conf \
  --token-label ValeoCryptokiToken \
  --so-pin so-pin \
  --user-pin 1234 \
  --import-key-file $PWD/tests/test_vectors/mac/key_aes_256.key \
  --import-key-label integration_test_hmac
```

### 2. Start the Daemon
Start the daemon in the background (or in a separate terminal) so it picks up the Rust token store and the test configuration:

```bash
export CRYPTO_CONFIG_FILE=$PWD/bazel-bin/tests/test_vectors/config/integration_test_config.bin
export CRYPTOKI_STORE=/tmp/rust_tokens/token.json

bazel run //score/crypto/daemon:crypto_daemon \
  --config=host_config_1 --define use_rust_pkcs11=true --experimental_isolated_extension_usages
```

### 3. Run the Client
Execute the demo client in another terminal to perform cryptographic operations against the running daemon:

```bash
export USE_RUST_PKCS11=1
bazel run //tests/integration_tests: \
  --config=host_config_1 --define use_rust_pkcs11=true --experimental_isolated_extension_usages
```

## Troubleshooting

*   **Toolchain Errors**: If you encounter errors mentioning `rules_rust` or missing toolchains, ensure you are including `--config=host_config_1` or `--config=target_config_2` in your Bazel command. This is strictly required to activate the Ferrocene compiler capable of building the module.
*   **Missing Symbols / Header Errors**: If the C++ compilation fails looking for `<cryptoki.h>`, ensure you have included `--define use_rust_pkcs11=true`.
*   **LoadKey Failed**: If the client fails with `[FAIL] LoadKey failed`, ensure the token was initialized correctly in Step 1 and that the `CRYPTOKI_STORE` environment variable is set for the daemon before running it.
*   **QNX Build Missing Headers**: If QNX fails to compile `typed_memory.h`, ensure `--@score_baselibs//score/memory/shared/flags:use_typedshmd=false` is correctly set in your `.bazelrc` for `shared_qnx`.

# Use of genAI in this repository
The repository partially contains AI-generated code by using GitHub Copilot Business.
This notice needs to remain attached to any reproduction of this repository.
