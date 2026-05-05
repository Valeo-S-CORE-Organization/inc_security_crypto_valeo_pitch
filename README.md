# Cryptoki

A PKCS#11 v3.0 software token written in Rust. Drop it in where you'd use a YubiKey or a Thales HSM — anything that speaks PKCS#11 will just work. The crypto operations are behind a trait, so the backend is whatever you plug in: a software library, a TPM, a real HSM. The repo ships an OpenSSL implementation to demo the layers, but that's not the point.

---

## What is this?

Cryptoki is a **software HSM** — a shared library (`.so` / `.dylib`) that speaks the full PKCS#11 v3.0 C API. From the caller's perspective it's indistinguishable from a hardware token. From our perspective it's a chance to do things the right way: safe Rust, auditable code, no surprises.

A few things worth highlighting:

* **Complete PKCS#11 surface.** All v2.40 + v3.0 entry points are exported, with unsupported flows returning spec-appropriate codes (`CKR_FUNCTION_NOT_SUPPORTED`, etc.).
* **Both dispatch tables.** We expose the v2.40 `CK_FUNCTION_LIST` (68 slots) and the v3.0 `CK_FUNCTION_LIST_3_0` (24 extra slots), plus `C_GetInterface` / `C_GetInterfaceList` for clients that do capability discovery.
* **Fork-safe.** A `pthread_atfork` child handler closes inherited lock FDs and reseeds the CSPRNG — no parent/child RNG state sharing.
* **Pluggable backend.** The `CryptoProvider` trait is the only interface the PKCS#11 layer talks to. It doesn't know or care what's underneath — a software library, a TPM, an HSM, whatever. The included OpenSSL implementation is a working reference, not a dependency.

---

## Getting Started

### Prerequisites

Stable Rust toolchain. If you're using the bundled OpenSSL reference backend, you'll also need the OpenSSL dev headers (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on Fedora). A custom backend may have different requirements.

### Build

```bash
cargo build --release
```

### Bazel workflow

The repository builds fully with native `rules_rust`.

#### Build targets

```bash
# Rust library
bazel build //src:cryptoki_lib

# Both example binaries
bazel build //examples:pkcs11_demo
bazel build //examples:pkcs11_business_demo
```

#### Test

```bash
# All 22 Rust integration tests (native rust_test, sandboxed, cached)
bazel test //tests:integration_tests

# Single test
bazel test //tests:pkcs11_integration

# C++ Google Test conformance suite
bazel test //tests/cpp:cpp_tests
```

#### Layout

| Path | Contents |
| --- | --- |
| `MODULE.bazel` | `rules_rust` + `crate_universe` (`crate.from_cargo(...)`) |
| `src/BUILD` | `rust_library` → `//src:cryptoki_lib` |
| `examples/BUILD` | `rust_binary` per example |
| `tests/BUILD` | 22 native `rust_test` targets + `integration_tests` suite |
| `tests/rust/BUILD` | Smoke test |
| `tests/cpp/BUILD` | C++ `cc_test` via gtest |

#### Notes

* Dependencies resolved through `crate_universe`; `package_name = ""` refers to the workspace root crate.
* Tests that use `mod common` include `tests/common/mod.rs` explicitly in `srcs`.
* `serial_test` proc-macro (used by `always_authenticate`, `persistence_integration`, `pkcs11_v3_integration`) is pulled via `proc_macro_deps`.
* Each test target is independently cacheable — Bazel only reruns tests whose inputs changed.

### Run the tests

```bash
cargo test
```

### Try the demo

There's an end-to-end example that walks through the full v3.0 call sequence — initialization, sessions, key generation (AES, RSA, EC, Ed25519, ChaCha20), encrypt/decrypt, sign/verify, hashing, interface discovery, and cleanup:

```bash
cargo run --example pkcs11_demo
```

### Configuration

* **Storage path:** defaults to `~/.cryptoki/token.json`. Override with `CRYPTOKI_STORE=/path/to/store.json`.
* **Legacy algorithms:** MD5 and SHA-1 are hidden by default. Set `CRYPTOKI_LEGACY=1` to expose them — but don't do this in production.

---

## Architecture

The PKCS#11 layer is organized as small operation-focused modules with thin hubs:

```text
┌──────────────────────────────────────────────────────────────────────┐
│                      External caller                                 │
└────────────────────────────┬─────────────────────────────────────────┘
                             │  C ABI  (unsafe extern "C")
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│  src/pkcs11/ffi_api_*  —  FFI boundary + orchestrators               │
│                                                                      │
│  GlobalState: OnceLock<RwLock<Option<GlobalState>>>                  │
│    None → Some on C_Initialize, Some → None on C_Finalize            │
│    ck_try! macro: Pkcs11Error → CK_RV at every return site           │
│                                                                      │
│  Orchestration order for all C_* ops:                                │
│    1. check_init() / require_rw_session()                            │
│    2. mechanisms.rs  — tier gate (Standard / Legacy)                 │
│    3. session.rs     — op context lookup, auth checks                │
│    4. attribute_policy.rs — ratchets, immutability, access control   │
│    5. object_store.rs — handle → KeyObject resolution                │
│    6. backend/       — crypto dispatch  (crypto ops only)            │
│    7. storage/       — persist if token object  (mutating ops only)  │
└──┬──────────┬────────────┬──────────────┬────────────┬──────────────┬┘
   │          │            │              │            │              │
   ▼          ▼            ▼              ▼            ▼              │
┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────────────────────┐ └──────┐
│session.rs│ │token.rs  │ │mechanisms  │ │attribute_policy.rs       │        │
│          │ │          │ │.rs         │ │                          │        │
│Per-sess. │ │Per-slot  │ │            │ │One-way ratchets:         │        │
│state:    │ │token     │ │Standard /  │ │  CKA_SENSITIVE ↑ only    │        │
│ SignCtx  │ │state:    │ │Legacy /    │ │  CKA_EXTRACTABLE ↓ only  │        │
│ CipherCtx│ │  label   │ │            │ │  CKA_WRAP_WITH_TRUSTED ↑ │        │
│ DigestCtx│ │  state   │ │RSA < 1024  │ │Immutable attrs:          │        │
│ FindCtx  │ │  machine │ │→ CKR_KEY_  │ │  class, key_type, modulus│        │
│ MsgCtx   │ │  Argon2id│ │SIZE_RANGE  │ │Derived attrs:            │        │
│          │ │  PIN     │ │            │ │  always_sensitive        │        │
│Login     │ │  hashes  │ │Legacy gate │ │  never_extractable       │        │
│state     │ │  PIN     │ │via env var │ │CKA_VALUE blocking        │        │
│always_   │ │  lockout │ │            │ │                          │        │
│auth      │ │  counters│ │            │ │                          │        │
└──────────┘ └──────────┘ └────────────┘ └──────────────────────────┘        │
                                                                             │
                                                  (ffi_api_* → object_store)
                                                                             │
                                                                             ▼
                                    ┌───────────────────────────────────────────────────┐
                                    │  object_store.rs                                  │
                                    │                                                   │
                                    │  KeyObject {                                      │
                                    │    handle, slot_id, key_type: KeyType,            │
                                    │    key_ref: EngineKeyRef,   ← Zeroizing<Vec<u8>>  │
                                    │    attributes: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>│
                                    │    local, always_sensitive, never_extractable,    │
                                    │    always_authenticate, key_gen_mechanism         │
                                    │  }                                                │
                                    │                                                   │
                                    │  Session objects: tagged by creating_session,     │
                                    │    destroyed on CloseSession                      │
                                    │  Token objects: auto-persisted, survive Finalize  │
                                    │  Profile objects: token lifetime, never to disk   │
                                    └──────────────┬────────────────────────────────────┘
                                                   │
                                    ┌──────────────┴──────────────┐
                                    │                             │
                                    ▼                             ▼
                     ┌──────────────────────────┐    ┌───────────────────────────────────┐
                     │ storage/                 │    │ backend/                          │
                     │                          │    │                                   │
                     │ JSON persistence:        │    │ Crypto dispatch (no OpenSSL):     │
                     │  • NamedTempFile → fsync │    │  sign / verify / digest           │
                     │    → rename (atomic)     │    │  encrypt / decrypt (sym + asym)   │
                     │  • flock on .lock sidecar│    │  wrap / unwrap (AES Key Wrap)     │
                     │  • dir 0700, file 0600   │    │  message-based AEAD               │
                     │  • Argon2id PIN hashes   │    │  HKDF derive                      │
                     │  • LOCK_FILE_FD: AtomicI32    │  attribute extraction             │
                     │    for atfork safety     │    │                                   │
                     └──────────────────────────┘    └─────────────────┬─────────────────┘
                                                                       │
                                                                       ▼
                                                   ┌─────────────────────────────────┐
                                                   │ registry.rs                     │
                                                   │                                 │
                                                   │ global_slot_id →                │
                                                   │   (Arc<dyn CryptoProvider>,     │
                                                   │    internal_slot_id)            │
                                                   │                                 │
                                                   │ for_each_engine(f): iterates    │
                                                   │   all engines (atfork handler)  │
                                                   └──────────────┬──────────────────┘
                                                                  │
                                                                  ▼
                                                   ┌─────────────────────────────────┐
                                                   │ traits.rs — CryptoProvider      │
                                                   │                                 │
                                                   │ Object-safe. No generics.       │
                                                   │ No PKCS#11 knowledge.           │
                                                   │                                 │
                                                   │ serialize_key / deserialize_key │
                                                   │ key_value_for_digest (fail-safe)│
                                                   │ post_fork_child() default no-op │
                                                   │ mechanism_info() per mechanism  │
                                                   └──────────────┬──────────────────┘
                                                                  │
                                                                  ▼
                                                   ┌─────────────────────────────────┐
                                                   │ your_backend.rs                 │
                                                   │                                 │
                                                   │ Implements CryptoProvider.      │
                                                   │ Could be OpenSSL, a TPM, an     │
                                                   │ HSM — anything you plug in.     │
                                                   └─────────────────────────────────┘
```


```text
src/pkcs11/
├── mod.rs                         # top-level exports + function tables + shared state/helpers
├── ffi_api_core/                  # hub
│   ├── lifecycle_and_slot_token.rs
│   ├── session_and_login.rs
│   └── keys_objects_attributes_find.rs
├── ffi_api_crypto/                # hub
│   ├── sign_verify.rs
│   ├── encrypt_decrypt.rs
│   ├── digest.rs
│   ├── key_wrap_derive.rs
│   ├── misc_v240.rs
│   └── helpers.rs
├── ffi_api_v3/                    # hub
│   ├── session_user.rs
│   ├── message_encrypt_decrypt.rs
│   ├── message_sign_verify.rs
│   └── interface_discovery.rs
├── attribute_policy.rs            # ratchets / immutability / access checks
├── backend/                       # hub
│   ├── keygen.rs
│   ├── sign_verify.rs
│   ├── symmetric.rs
│   ├── message_aead.rs
│   ├── digest_random.rs
│   ├── rsa_wrap_derive.rs
│   └── attributes.rs
├── object_store.rs                # object model + handles + persistence hooks
├── session.rs                     # session contexts and login state
├── storage/                       # hub
│   ├── models.rs
│   ├── path.rs
│   ├── locks.rs
│   ├── io.rs
│   └── helpers.rs
├── token.rs                       # token metadata + PIN state
└── mechanisms.rs                  # mechanism allow/block policy
```

Operational flow for most `C_*` functions:

1. Validate init/session state in the FFI API module (`check_init`, `require_rw_session`, session lookup).
2. Enforce mechanism and attribute policy (`mechanisms.rs`, `attribute_policy.rs`).
3. Resolve object handles (`object_store.rs`).
4. Dispatch crypto to the provider (`backend/*` + `traits.rs`).
5. Persist token-object mutations (`storage/io.rs` through `object_store.rs`).

This keeps each file focused while preserving one consistent ABI surface.

---

## Cryptographic Mechanisms Supported

| Mechanism | `CKM_*` constant | Key type | Tier |
| --- | --- | --- | --- |
| RSA key pair generation | `CKM_RSA_PKCS_KEY_PAIR_GEN` | RSA ≥ 1024 bits | Standard |
| EC key pair generation | `CKM_EC_KEY_PAIR_GEN` | P-256 | Standard |
| EdDSA key pair generation | `CKM_EC_EDWARDS_KEY_PAIR_GEN` | Ed25519 | Standard |
| AES key generation | `CKM_AES_KEY_GEN` | AES 128/192/256 | Standard |
| ChaCha20 key generation | `CKM_CHACHA20_KEY_GEN` | ChaCha20 256 bit | Standard |
| RSA PKCS#1 v1.5 encrypt/decrypt | `CKM_RSA_PKCS` | RSA | Standard |
| RSA OAEP encrypt/decrypt | `CKM_RSA_PKCS_OAEP` | RSA | Standard |
| AES-CBC with PKCS#7 padding | `CKM_AES_CBC_PAD` | AES | Standard |
| AES-GCM | `CKM_AES_GCM` | AES | Standard |
| AES-CTR | `CKM_AES_CTR` | AES | Standard |
| ChaCha20-Poly1305 | `CKM_CHACHA20_POLY1305` | ChaCha20 | Standard |
| RSA PKCS#1 v1.5 sign/verify (SHA-256/384/512) | `CKM_SHA***_RSA_PKCS` | RSA | Standard |
| RSA-PSS sign/verify (SHA-256/384/512) | `CKM_SHA***_RSA_PKCS_PSS` | RSA | Standard |
| ECDSA (prehashed, SHA256/384/512) | `CKM_ECDSA_*` | EC | Standard |
| EdDSA (Ed25519) | `CKM_EDDSA` | EdDSA | Standard |
| SHA-2 / SHA-3 digests | `CKM_SHA***` / `CKM_SHA3_***` | — | Standard |
| HKDF key derivation | `CKM_HKDF_DERIVE` | AES/generic | Standard |
| AES Key Wrap (RFC 3394) | `CKM_AES_KEY_WRAP` | AES | Standard |
| MD5 / SHA-1 digest | `CKM_MD5` / `CKM_SHA_1` | — | Legacy |
| RSA PKCS#1 v1.5 / PSS sign/verify (SHA-1) | `CKM_SHA1_RSA_*` | RSA | Legacy |
| RSA keygen < 1024 bits | — | RSA | Rejected (`CKR_KEY_SIZE_RANGE`) |

---

## Adding a Backend

This is the whole point of the architecture. Implement the `CryptoProvider` trait in `src/traits.rs` and the entire PKCS#11 stack works on top of it — sessions, objects, attribute policy, PIN management, all of it. Nothing else needs to change.

```rust
struct MyProvider { /* internal state */ }

impl CryptoProvider for MyProvider {
    // 1. Slot metadata
    fn slot_count(&self) -> u32 { 1 }
    fn slot_description(&self, _slot: u32) -> String { "My Provider".into() }
    fn token_model(&self, _slot: u32) -> String { "v1.0".into() }
    fn supported_mechanisms(&self, _slot: u32) -> Vec<CK_MECHANISM_TYPE> { vec![…] }

    // 2. Key serialization
    fn serialize_key(&self, key_ref: &EngineKeyRef) -> Result<Vec<u8>, CryptoError> { … }
    fn deserialize_key(&self, bytes: &[u8]) -> Result<EngineKeyRef, CryptoError> { … }

    // 3. Crypto operations (sign, verify, etc.)
    fn sign(&self, …) -> Result<Vec<u8>, CryptoError> { … }
    // ...
}
```

Register it in `C_Initialize` (currently wired in `src/pkcs11/ffi_api_core/lifecycle_and_slot_token.rs`):

```rust
let _ = crate::registry::register_engine(MyEngine::new());
```

Multiple engines coexist fine — each gets sequential global slot IDs.

---

## Parsec Integration

[Parsec](https://parallaxsecond.github.io/parsec-book/) is a platform-agnostic API for hardware security features. This repo ships a ready-made Parsec integration: the compiled `libcryptoki.so` acts as the PKCS#11 backend for the Parsec daemon, and a CLI client (`parsec_client`) talks to it over a Unix socket using the [parsec-client](https://crates.io/crates/parsec-client) Rust crate.

```text
 your app
    │  parsec-client (Rust crate)
    ▼
 parsec daemon  ──── libcryptoki.so  (this repo)
    │
 Unix socket
```

### Obtaining the Parsec daemon

Install with the features required for this setup:

```bash
cargo install parsec-service \
  --features 'pkcs11-provider,unix-peer-credentials-authenticator' \
  --locked
```

The binary lands at `~/.cargo/bin/parsec`.

### Daemon Configuration

`parsec/config.toml` is the ready-to-use config. It points the daemon at the compiled library and uses UID-based auth — no passwords.

Key fields:

```toml
[listener]
socket_path = "/home/omar/.pkcs11-engine/parsec/run/parsec.sock"

[[provider]]
provider_type = "Pkcs11"
library_path  = ".../target/release/libcryptoki.so"   # absolute path
slot_number   = 0
user_pin      = "1234"
```

See [`parsec/config.toml.example`](parsec/config.toml.example) for the full annotated reference covering every supported provider (MbedCrypto, PKCS#11, TPM, CryptoAuthLib, Trusted Service) and every tunable.

### Building libcryptoki.so

The daemon loads the library at runtime, so build it first:

```bash
# Cargo
cargo build --release          # → target/release/libcryptoki.so

# Bazel
bazel build //src:cryptoki_cdylib
```

### Running the daemon

```bash
# With the bundled config
parsec/scripts/start_parsec.sh

# With a custom config
parsec -c /path/to/your/config.toml

# Custom socket path — override in the config [listener] section, then:
PARSEC_BIN=/path/to/parsec parsec -c /path/to/config.toml
```

The socket path is set in `[listener] socket_path`. Clients pick it up via the `PARSEC_SERVICE_ENDPOINT` environment variable:

```bash
export PARSEC_SERVICE_ENDPOINT="unix:/home/omar/.pkcs11-engine/parsec/run/parsec.sock"
```

### Files in `parsec/`

The `parsec/` directory contains three distinct Rust files serving different purposes:

| File | Role | Build target |
| --- | --- | --- |
| [`parsec/client.rs`](parsec/client.rs) | CLI test harness — 7 subcommands to exercise every Parsec operation interactively | `cargo build --bin parsec_client` / `bazel build //parsec:parsec_client` |
| [`parsec/client_demo.rs`](parsec/client_demo.rs) | Minimal app example — the reference starting point for a client application | `cargo run --example parsec_client_demo` |
| [`parsec/basic_client.rs`](parsec/basic_client.rs) | Full `BasicClient` API reference with doc-comments for every operation | (library reference, not a runnable binary) |

**`client.rs` — CLI test harness**

A self-contained binary that exposes the full Parsec operation set as subcommands. Use it to verify the daemon is working correctly end-to-end before integrating into an application:

```bash
# Cargo
cargo build --bin parsec_client
./target/debug/parsec_client keygen mykey
./target/debug/parsec_client list
./target/debug/parsec_client sign   mykey "hello"
./target/debug/parsec_client verify mykey "hello" <hex-sig>
./target/debug/parsec_client export mykey
./target/debug/parsec_client random 32
./target/debug/parsec_client destroy mykey

# Bazel
bazel build //parsec:parsec_client
./bazel-bin/parsec/parsec_client keygen mykey

# Or use the wrapper script (resolves binary and sets PARSEC_SERVICE_ENDPOINT automatically)
parsec/scripts/start_client.sh keygen mykey
```

**`client_demo.rs` — minimal app example**

The reference starting point for building a Parsec client application. Covers the typical flow: connect → generate P-256 key → sign → verify → export public key → random bytes → destroy. Start here when writing your own client.

### Writing your own client

[`parsec/basic_client.rs`](parsec/basic_client.rs) is the full `BasicClient` source — the complete API surface with doc-comments and examples for every operation: key generation, import, export, sign/verify (hash and message variants), asymmetric and symmetric encrypt/decrypt, AEAD, hashing, key derivation, raw key agreement, and random generation.

The essential pattern:

```rust
use parsec_client::core::basic_client::BasicClient;
use parsec_client::core::interface::operations::psa_algorithm::{
    Algorithm, AsymmetricSignature, Hash, SignHash,
};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags,
};

// PARSEC_SERVICE_ENDPOINT must be set in the environment
let client = BasicClient::new(Some("my-app".to_string()))?;

let mut flags = UsageFlags::default();
flags.set_sign_hash().set_verify_hash();

client.psa_generate_key("my-key", Attributes {
    lifetime: Lifetime::Persistent,
    key_type: Type::EccKeyPair { curve_family: EccFamily::SecpR1 },
    bits: 256,
    policy: Policy {
        usage_flags: flags,
        permitted_algorithms: Algorithm::AsymmetricSignature(
            AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            }
        ),
    },
})?;
```

Add to `Cargo.toml`:

```toml
[dependencies]
parsec-client = "0.16"
openssl       = "0.10"   # for pre-hashing with MessageDigest::sha256()
```

---

## Cross-Compilation (QNX SDP 8.0)

This project supports cross-compilation for QNX SDP 8.0 (aarch64) while maintaining default compatibility with Linux x86_64 hosts.

**Build Configuration:**
QNX SDP 8.0 uses the `qcc` compiler wrapper, which interprets standard `gcc` flags differently (e.g., `-V`). The `.cargo/config.toml` is pre-configured to use the `qcc` linker, and a specialized `build_qnx.sh` script is provided to correctly invoke the QNX toolchain.

### 1. Building the Rust Library
To cross-compile the PKCS#11 library and Rust examples for QNX, use the provided helper script:
```bash
# Build library for QNX
./build_qnx.sh build

# Build tests for QNX
./build_qnx.sh test --no-run

# Build demos for QNX
./build_qnx.sh examples <example-name>
```
*Artifacts:* `target/aarch64-unknown-nto-qnx800/release/libcryptoki.so` and `target/aarch64-unknown-nto-qnx800/release/examples/pkcs11_demo`

### 2. Building the C++ Tests and Demo
The C++ frontend (tests and demo) interacts with the compiled library via `dlopen`.
```bash
mkdir -p cpp/build_qnx && cd cpp/build_qnx
source ~/qnx800/qnxsdp-env.sh # Source the QNX environment

cmake .. \
  -DCMAKE_SYSTEM_NAME=QNX \
  -DCMAKE_SYSTEM_VERSION=8.0.0 \
  -DCMAKE_C_COMPILER=qcc \
  -DCMAKE_C_COMPILER_TARGET=gcc_ntoaarch64le \
  -DCMAKE_CXX_COMPILER=qcc \
  -DCMAKE_CXX_COMPILER_TARGET=gcc_ntoaarch64le_cxx

make
```
*Artifacts:* `cpp/build_qnx/demo` and `cpp/build_qnx/test_cpp`

### 3. Deployment and Execution
Transfer the compiled artifacts (`libcryptoki.so`, `pkcs11_demo`, and `demo`) to your QNX target (e.g., `/tmp/pkcs11`).

Configure the environment and run:
```bash
# Set the library search path
export LD_LIBRARY_PATH=/tmp/pkcs11:$LD_LIBRARY_PATH

# Optional configurations
export CRYPTOKI_STORE=/tmp/pkcs11/token.json
export CRYPTOKI_LEGACY=1

# Run the demos
chmod +x pkcs11_demo demo
./pkcs11_demo
./demo
```

### 4. Testing on QNX
Since `cargo test` cannot automatically run binaries on the QNX target, you must compile them on the host and run them manually on the target.

```bash
# 1. Compile test binaries without running them
./build_qnx.sh test --no-run
```
Transfer the compiled test binaries from `target/aarch64-unknown-nto-qnx800/release/deps/` (e.g., `signing-<hash>`) to your QNX target and execute them directly, ensuring `LD_LIBRARY_PATH` is set.

> **Note:** The default Cargo target remains the host. Always use `--target aarch64-unknown-nto-qnx800` or the provided `build_qnx.sh` script when targeting QNX. If you add C library dependencies, update the `rustflags` in `.cargo/config.toml` or your `build.rs` accordingly.

---

## Test Coverage

### Rust Integration Tests

Every test goes through the C ABI function pointers (`fn_list()` / `fn_list_3_0()`) — the same path a real PKCS#11 consumer would take. No shortcuts.

Current Status: 198 tests — 0 failures (last verified on April 30, 2026 via `cargo test`)

```text
[████████████████████]  197 / 197  100%
```

| Suite | Focus Area |
| --- | --- |
| `pkcs11_integration` | Full `C_*` path, session lifecycle, key generation, fallback, error casing. |
| `pkcs11_v3_integration` | v3.0 specific features (EdDSA, ChaCha20, SHA-3, discovery, session cancels). |
| `attribute_policy` | Ratchet enforcement, immutable attributes, secure keygen defaults. |
| `storage_atomic_writes` | Cross-process serialization, atomic temp-to-rename writes, permission sets. |
| `ro_session` | Ensures mutating ops strictly return `CKR_SESSION_READ_ONLY` on read-only sessions. |
| `engine_integration` | Direct `CryptoProvider` stress testing, tamper detection, error codes. |
| `always_authenticate` | Validates per-operation context logins and auth ticket consumption. |

*(For full coverage details, see the inline module docs within the test suite).*

### Google Test Conformance Suite

On top of the Rust tests, we run a C++ Google Test suite (`cpp/pkcs11test/`) that loads the compiled `.so` as a black box and drives it through the public C ABI — no Rust internals, just raw `C_*` calls. It's the closest thing to a third-party integration test we have.

Current Status: 206 tests from 15 suites — 0 failures

```text
[████████████████████]  206 / 206  100%
```

| Suite | Count | Focus Area |
| --- | --- | --- |
| `PKCS11Test` | 32 | Token lifecycle: `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_Login`/`C_Logout`. |
| `ReadOnlySessionTest` | 23 | Session state machine, R/O vs R/W enforcement, `C_GetSessionInfo`. |
| `ReadWriteSessionTest` | 21 | Object creation, copy, destroy, and attribute reads on R/W sessions. |
| `Digests/DigestTest` | 75 | All supported hash algorithms via single and multi-part `C_Digest`. |
| `Signatures/SignTest` | 18 | Sign/verify across RSA PKCS#1, RSA-PSS, ECDSA, and EdDSA. |
| `ROUserSessionTest` | 6 | User-login gate: operations requiring `CKU_USER` on R/O sessions. |
| `RWUserSessionTest` | 3 | User-login gate on R/W sessions. |
| `DataObjectTest` | 7 | `CKO_DATA` objects: create, set attributes, retrieve, destroy. |
| `RWSOSessionTest` | 2 | SO-login operations on R/W sessions. |
| `Init` | 11 | `C_Initialize` / `C_Finalize` sequencing and error codes. |
| `RNG` | 2 | `C_GenerateRandom` correctness and length contracts. |
| `BERDecode` | 3 | ASN.1/BER decode helpers used internally by the test harness. |

> The `Ciphers*`, `HMACs*`, `Duals*`, `DES`, `MD5-RSA`, and `SHA1-RSA` suites are excluded from the standard run — they cover operations not yet in scope for this release.

#### Fetching and Running the Conformance Suite

Follow these steps to initialize the submodule, compile the libraries, and execute the tests:

```bash
# 1. Fetch the Google Test Conformance Suite submodule
git submodule update --init --recursive

# 2. Build the Rust shared library
cargo build

# 3. Build the C++ test binary
cd cpp && mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug && make

# 4. Clear the token storage to start fresh
rm -rf ~/.cryptoki/token.json

# 5. Run the conformance suite against the Rust library
./pkcs11test -m libcryptoki.so -l ../../target/debug -s 0 -u 1234 -o so-pin -I --gtest_filter=-Ciphers*:HMACs*:Duals*:*DES*:*MD5-RSA*:*SHA1-RSA*
```

Optional flags:

| Flag | Description |
| --- | --- |
| `-u <pin>` | Override the User PIN (default: `1234`) |
| `-o <pin>` | Override the SO PIN (default: `so-pin`) |
| `-s <slot>` | Target a specific slot ID |
| `-v` | Verbose output |
| `-I` | Run `C_InitToken` at startup (reinitializes the token) |

---

## Security

Key material handling was a first-class concern from the start, not an afterthought. Here's how the main pieces fit together:

### 1. The PKCS#11 layer never sees key bytes

All key material is an opaque `EngineKeyRef` (`Zeroizing<Vec<u8>>`). The PKCS#11 FFI/API modules pass handles around without interpreting key internals — only the Provider (`openssl_provider.rs`) knows what the bytes mean. If a backend can't digest an opaque handle, `key_value_for_digest` fails closed with `CKR_MECHANISM_INVALID`.

### 2. Buffers are zeroed on drop

We use the `zeroize` crate throughout the call stack:

* `KeyObject.key_ref`
* Decrypt outputs, HKDF derives, AES key unwraps
* Intermediate buffers inside the crypto backend

### 3. PINs are Argon2id hashes, not passwords

PIN management is entirely separate from the crypto backend — the `argon2` crate handles it directly. Parameters: 64 MiB memory, 3 iterations, 4 parallelism, 32-byte output. SO and User PINs are hashed independently; the PHC strings live in the token state.

### 4. Writes are atomic

Torn writes would corrupt the token state permanently. We use a 6-step sequence to prevent that:

1. Serialize to JSON in memory.
2. Write to a `NamedTempFile` in the same directory as the target.
3. `chmod 0o600` the temp file.
4. `fsync` the file data.
5. `rename(2)` into place — atomic on POSIX.
6. `fsync` the parent directory.

Cross-process exclusion is a `flock(LOCK_EX)` on a `.lock` sidecar. The FD lives in an `AtomicI32` (not a Mutex) so it's safe to close inside an `atfork` handler.

### 5. Attribute ratchets

Some attribute transitions are one-way and we enforce that strictly in `C_SetAttributeValue` and `C_CopyObject`:

* `CKA_SENSITIVE` can only go `FALSE → TRUE`
* `CKA_EXTRACTABLE` can only go `TRUE → FALSE`
* Key type, modulus, and class are immutable once set
* `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_KEY_GEN_MECHANISM` are computed by us — we never trust the caller's value

### 6. Fork safety

`C_Initialize` registers a `pthread_atfork` child handler. On fork, the child:

1. Closes inherited lock FDs.
2. Reseeds the CSPRNG (`openssl::rand::rand_bytes`) — parent and child must not share RNG state.
3. Calls `post_fork_child()` on every registered Provider.

### 7. Per-operation authentication

Keys with `CKA_ALWAYS_AUTHENTICATE=TRUE` need a fresh `C_Login(CKU_CONTEXT_SPECIFIC)` before every crypto operation — not just at session open. `C_WrapKey` also enforces `CKA_WRAP=TRUE`, checks extractability, and honours `CKA_TRUSTED` / `CKA_WRAP_WITH_TRUSTED` ACLs.

---

## Threat Model

### What we protect against

| Threat | Mitigation |
| --- | --- |
| Concurrent writes from multiple processes | `flock(LOCK_EX)` on `.lock` sidecar serializes all writers |
| Torn writes / crash during storage update | Atomic `NamedTempFile → rename(2)` — partial writes never visible |
| Weak RSA keys | Minimum 1024 bits enforced |
| Broken cryptography (MD5, SHA-1) | Legacy tier explicitly gated behind `CRYPTOKI_LEGACY=1` |
| Key material leakage via process memory | `Zeroizing<Vec<u8>>` zeros buffers on drop throughout the call stack |
| Fork without CSPRNG reseed | `pthread_atfork` child handler forces `rand_bytes` reseed |
| Unauthorized key extraction | `CKA_SENSITIVE` / `CKA_EXTRACTABLE` ratchets; `CKA_VALUE` returns `CKR_ATTRIBUTE_SENSITIVE` |
| Key attribute downgrade | One-way ratchets enforced on `C_SetAttributeValue` and `C_CopyObject` |
| Unattended operations on privileged keys | `CKA_ALWAYS_AUTHENTICATE` one-shot context login required per operation |
| Untrusted key wrapping | `CKA_WRAP_WITH_TRUSTED` / `CKA_TRUSTED` ACL on `C_WrapKey` |
| Session objects leaking to disk | `CKA_TOKEN=FALSE` objects are never written to storage |

### Out of scope

* **Malicious callers.** PKCS#11 loads into the caller's process — we can't protect against the process itself.
* **Physical memory attacks.** We don't `mlock()` yet, so keys can be paged to disk. This is on the roadmap.
* **Encryption at rest.** The token file is plaintext JSON today. Argon2id covers the PINs but not the key material. See Roadmap.

---

## PKCS#11 v3.0 Compliance

All PKCS#11 v2.40 + v3.0 entry points are present. Some flows are intentionally not implemented yet and return standard PKCS#11 status codes (for example `CKR_FUNCTION_NOT_SUPPORTED`). RW session enforcement is strict — anything that mutates persistent state requires a session opened with `CKF_RW_SESSION`.

A few honest deviations:

* `C_MessageSignInit` / `C_MessageVerifyInit` → `CKR_FUNCTION_NOT_SUPPORTED` (message-based signing is not yet implemented).
* Multi-part digest+crypto combinators (`C_DigestEncryptUpdate`, etc.) → `CKR_FUNCTION_NOT_SUPPORTED`.
* `C_OpenSession` without `CKF_SERIAL_SESSION` → rejected. Parallel sessions are not supported.
* `C_SeedRandom` → `CKR_RANDOM_SEED_NOT_SUPPORTED`. We use the OS entropy source directly.

---

## Development Guidelines

To preserve the architecture and readability:

1. **Size Limits:** Prefer adding a new focused module over growing an existing file past ~500-600 LOC.
2. **Thin Hubs:** Keep hub modules (`ffi_api_*`, `backend/`, `storage/`) thin. Re-export through the relevant hub module instead of importing deep internals externally.
3. **Documentation:** Add a short module-level `//!` ownership header for every new module.
4. **Dependencies:** Keep cross-module dependencies one-directional where possible.
5. **CI Checks:** Keep `cargo clippy --all-targets --all-features -- -D warnings` and full `cargo test` green for every structural change.

---

## Contributor Map

Use this table to decide where new code should go:

| Concern | Primary module |
| --- | --- |
| Init/finalize, slots, token info | `ffi_api_core/lifecycle_and_slot_token.rs` |
| Session open/close, login state | `ffi_api_core/session_and_login.rs` |
| Key/object create/destroy/attributes/find | `ffi_api_core/keys_objects_attributes_find.rs` |
| Sign/verify C APIs | `ffi_api_crypto/sign_verify.rs` |
| Encrypt/decrypt C APIs | `ffi_api_crypto/encrypt_decrypt.rs` |
| Digest C APIs | `ffi_api_crypto/digest.rs` |
| Wrap/unwrap/derive C APIs | `ffi_api_crypto/key_wrap_derive.rs` |
| v2.40 misc/unsupported C APIs | `ffi_api_crypto/misc_v240.rs` |
| v3 session/user extensions | `ffi_api_v3/session_user.rs` |
| v3 message encrypt/decrypt | `ffi_api_v3/message_encrypt_decrypt.rs` |
| v3 message sign/verify | `ffi_api_v3/message_sign_verify.rs` |
| v3 interface discovery | `ffi_api_v3/interface_discovery.rs` |
| Provider key generation adapters | `backend/keygen.rs` |
| Provider sign/verify adapters | `backend/sign_verify.rs` |
| Provider symmetric cipher adapters | `backend/symmetric.rs` |
| Provider message AEAD adapters | `backend/message_aead.rs` |
| Provider digest/random adapters | `backend/digest_random.rs` |
| Provider RSA/wrap/derive adapters | `backend/rsa_wrap_derive.rs` |
| Provider attribute fallback | `backend/attributes.rs` |
| Persistent storage models | `storage/models.rs` |
| Persistent storage I/O + atomic writes | `storage/io.rs` |
| Storage lock/fork helpers | `storage/locks.rs` |
| Storage path config | `storage/path.rs` |

---

## Known Limitations & Roadmap

Honest status of what's missing and what's next:

1. **Encryption at rest.** `token.json` stores key bytes as plaintext. PINs are Argon2id hashes so they're safe, but the key material itself is not encrypted. The plan is envelope encryption — a random DEK wrapped by PIN-derived KEKs for both SO and User.
2. **Page locking.** Keys can be paged to disk because we don't call `mlock(2)` yet. It's on the list.
3. **Algorithm gaps.** Missing: P-384/P-521, Ed448, HMAC keygen, PBKDF2, and raw RSA PKCS#8 import via `C_CreateObject`.
4. **Tooling validation.** We haven't run against `pkcs11-tool` or `p11-kit` yet. Probably fine, but it needs to be verified.

---

## Requirements Traceability

**Coverage** `[████████████░░░░░░░░]  25 / 42  60%`

| Requirement ID | Title | Type | Security | Safety | Status | Covered | Details |
|---|---|---|---|---|---|---|---|
| feat_req__sec_crypt__sym_symmetric_encrypt | Symmetric Encryption and Decryption | Functional | YES | QM | valid | YES | `C_Encrypt`, `C_Decrypt`, `src/pkcs11/backend.rs` |
| feat_req__sec_crypt__sym_symm_algo_aes_cbc | AES-CBC Support | Functional | YES | QM | valid | YES | `CKM_AES_CBC_PAD` |
| feat_req__sec_crypt__sym_sym_algo_aes_gcm | AES-GCM Support | Functional | YES | QM | valid | YES | `CKM_AES_GCM` |
| feat_req__sec_crypt__sym_sym_algo_aes_ccm | AES-CCM Support | Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__sym_algo_chacha20 | ChaCha20-Poly1305 Support | Functional | YES | QM | valid | YES | `CKM_CHACHA20_POLY1305` |
| feat_req__sec_crypt__asym_encryption | Asymmetric Encryption/Decryption | Functional | YES | QM | valid | YES | `C_Encrypt`, `C_Decrypt`, `CryptoProvider` |
| feat_req__sec_crypt__asym_algo_ecdh | ECDH Support | Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__sig_creation | Signature Creation | Functional | YES | QM | valid | YES | `C_Sign`, `CryptoProvider` |
| feat_req__sec_crypt__sig_verification | Signature Verification | Functional | YES | QM | valid | YES | `C_Verify`, `CryptoProvider` |
| feat_req__sec_crypt__sig_algo_ecdsa | ECDSA Support | Functional | YES | QM | valid | YES | `CKM_ECDSA` |
| feat_req__sec_crypt__mac | Message Authentication Code | Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__hashing | Hashing Functionality | Functional | YES | QM | valid | YES | `C_Digest`, `CryptoProvider` |
| feat_req__sec_crypt__hashing_algo_sha2 | SHA-2 Support | Functional | YES | QM | valid | YES | `CKM_SHA256`, etc. |
| feat_req__sec_crypt__hashing_algo_sha3 | SHA-3 Support | Functional | YES | QM | valid | YES | `CKM_SHA3_256`, etc. |
| feat_req__sec_crypt__kdf | Key Derivation | Functional | YES | QM | valid | YES | `C_DeriveKey`, `hkdf_derive` |
| feat_req__sec_crypt__rng | Entropy Source | Functional | YES | QM | valid | YES | `C_GenerateRandom`, `rand_bytes` |
| feat_req__sec_crypt__rng_algo_chacha20rng | ChaCha20Rng Support | Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__cert_management | Certificate Management | Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__key_generation | Secure Key Generation | Functional | YES | QM | valid | YES | `C_GenerateKey`, `C_GenerateKeyPair` |
| feat_req__sec_crypt__key_import | Secure Key Import | Functional | YES | QM | valid | YES | `C_CreateObject`: AES/secret via `CKA_VALUE`, EC public via `CKA_EC_PARAMS`+`CKA_EC_POINT`, RSA public/private and EC private by key type |
| feat_req__sec_crypt__key_storage | Secure Key Storage | Functional | YES | QM | valid | YES | `storage.rs`, `object_store.rs` |
| feat_req__sec_crypt__key_deletion | Secure Key Deletion | Functional | YES | QM | valid | YES | `C_DestroyObject`, `storage.rs` |
| feat_req__sec_crypt__flexible_api | API Algorithm Selection | Functional | YES | QM | valid | YES | `CryptoProvider`, `registry.rs` |
| feat_req__sec_crypt__tls_support | TLS Support | Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__performance_tooling | Benchmark tooling | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__algo_naming | Standardized Algorithm Naming | Non-Functional | YES | QM | valid | YES | `CKM_*` mappings |
| feat_req__sec_crypt__no_key_exposure | No Key Material Exposure | Non-Functional | YES | QM | valid | YES | `EngineKeyRef`, `attribute_policy.rs` |
| feat_req__sec_crypt__side_channel_mitigation| Side-Channel Attack Mitigation | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__api_lifecycle | API Lifecycle Management | Non-Functional | YES | QM | valid | YES | `C_Initialize`, `C_Finalize`, etc. |
| feat_req__sec_crypt__error_handling | Structured Error Handling | Non-Functional | YES | QM | valid | YES | `ck_try!`, `error.rs` |
| feat_req__sec_crypt__security_concept | Security Concept | Non-Functional | YES | QM | valid | YES | Security Architecture Documented |
| feat_req__sec_crypt__algo_updates | Crypto Algorithm Update Strategy | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__reverse_eng_protection | Reverse Engineering Protection | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__production_keys | Initial Production Key Handling | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__pqc_readiness | Post-Quantum Readiness | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__hw_acceleration | Hardware Acceleration Support | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__sw_fallback | Software Fallback | Non-Functional | YES | QM | valid | YES | Pluggable `CryptoProvider` (reference: `openssl_provider.rs`) |
| feat_req__sec_crypt__trusted_time | Trusted Time Source | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__os_protection | OS-Level Protection | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__access_control | Access Control | Non-Functional | YES | QM | valid | YES | `C_Login`, `attribute_policy.rs` |
| feat_req__sec_crypt__ids_integration | IDS Integration | Non-Functional | YES | QM | valid | NO | N/A |
| feat_req__sec_crypt__dos_mitigation | DoS Mitigation | Non-Functional | YES | QM | valid | NO | N/A |

---

## License

This project is licensed under the Apache License, Version 2.0. See the `NOTICE` file(s) distributed with this work for additional information regarding copyright ownership.
