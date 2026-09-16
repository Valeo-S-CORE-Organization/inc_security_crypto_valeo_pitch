# @score_openssl: Architectural Rationale

This dedicated Bazel repository handles the download, isolation, and hermetic compilation of the C++ OpenSSL dependency suite. It sits at the bottom of the project's dependency graph, providing a clean, unidirectional cross-language (C++/Rust FFI) build path that decouples Bazel Bzlmod module releases.

---

## 1. The Core Issue: Bzlmod Module Release Coupling

In a centralized Bazel workspace setup, the `@score_crates` repository serves as the single registry for Rust packages and FFI bindings.

Compiling Rust FFI bindings (such as `openssl-sys` inside `@score_crates`) requires linking against compiled C++ OpenSSL shared binaries. Hosting OpenSSL build logic inside `score_crypto` or `@score_baselibs` introduces circular module-level dependencies:

### Hosting OpenSSL in `score_crypto`:
`score_crypto` depends on `@score_crates` to fetch Rust dependencies (`libc`, `serde`, `parking_lot`). If `@score_crates` also depends on `score_crypto` to resolve C++ OpenSSL targets for `openssl-sys`, a circular module relationship is created:

> **`score_crypto`** &harr; **`@score_crates`**

### Hosting OpenSSL in `@score_baselibs`:
`@score_baselibs` consumes Rust packages from `@score_crates`. Storing OpenSSL in `@score_baselibs` creates a bidirectional module relationship:

> **`@score_baselibs`** &harr; **`@score_crates`**

### The "Chicken-and-Egg" Release Problem:
Circular module loops create a fatal **"chicken-and-egg" release deadlock**:
*   You cannot publish or version `@score_crates` without releasing `score_crypto` first.
*   You cannot publish or version `score_crypto` without releasing `@score_crates` first.

Isolating OpenSSL into its own separate `@score_openssl` module breaks this loop completely. It allows us to tag, version, and release each repository independently, making our release pipeline clean and simple.

---

## 2. Architectural Solution & Dependency Graph

Extracting OpenSSL compilation into a standalone leaf-node module (`@score_openssl`) ensures a unidirectional dependency flow:

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                        USER / CI PIPELINE                               │
 └────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                        score_crypto Repo                                │
 │               (Main Cryptographic Provider Library)                     │
 └─────────────┬─────────────────────────────────────────┬─────────────────┘
               │                                         │
               ▼ (Depends on Rust crates)                 ▼ (Depends on C++ FFI)
 ┌───────────────────────────┐             ┌───────────────────────────┐
 │ @score_crates             │             │ @score_openssl            │
 │ (Central Rust Registry)   │             │ (C++ Build Rules/Patches) │
 │                           │             │                           │
 │ * Central Rust crates     │             │ * Zero external deps!     │
 │ * Pre-patched openssl-sys │             │ * Owns build rules/patch  │
 └─────────────┬─────────────┘             └───────────────────────────┘
               │                                         │
               └─────────────────────────────────────────┘
          (@score_crates links down to @score_openssl//:openssl_shared)
```

### Key Architectural Benefits:
*   **Unidirectional Graph**: `@score_openssl` acts as a clean leaf module. Both `score_crypto` and `@score_crates` consume it without creating circular release loops.
*   **Independent Release Lifecycle**: `@score_openssl` can be tagged, versioned, and updated independently of Rust crates or higher-level crypto daemons.
*   **Workspace Cleanliness**: `score_crypto` remains free of C++ OpenSSL target build rules, genrules, and platform patch files.

---

## 3. Design Alternatives Considered

### Option A: Centralized Source Compilation via `http_archive` (Selected)
*   **Approach**: `@score_openssl` uses Bazel's `http_archive` rule to pull pristine, official OpenSSL release archives at build time, applying target-compilation patches on the fly.
*   **Rationale**: This is currently the only mechanism that allows both Linux and QNX binaries to be built from source with exact, deterministic `OPENSSL_NO_*` feature flag configurations. It guarantees strict feature control and identical `cryptoki` FFI contracts across all target architectures.

### Option B: Bazel Central Registry (BCR) OpenSSL Module
*   **Approach**: Import OpenSSL via Bzlmod using the standard BCR repository (`bazel_dep(name = "openssl")`).
*   **Why Discarded**: The default BCR OpenSSL module lacks out-of-the-box support for QNX target platforms and toolchains. Adapting it for QNX would require extensive local patching and Bazel module overrides, negating the benefits of an off-the-shelf BCR package.

### Option C: Linking Pre-Built QNX SDP OpenSSL Binaries
*   **Approach**: Link directly against pre-compiled OpenSSL libraries shipped inside the QNX Software Development Platform (SDP).
*   **Why Discarded**: QNX SDP binaries do not expose the exact `OPENSSL_NO_*` feature set required by our security policies, leading to ABI mismatch risks during Rust FFI compilation.

*(Note: If the platform strategy later transitions to standardized OS/BCR modules across all target platforms, `@score_openssl` can be evaluated for consolidation into `@score_crates`.)*
