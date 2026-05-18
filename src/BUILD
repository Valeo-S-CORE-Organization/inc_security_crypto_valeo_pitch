load("@rules_rust//rust:defs.bzl", "rust_library", "rust_shared_library")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "src",
    srcs = glob(["**/*.rs"]),
)

DEPS = [
    # --- Company Approved (Score Ecosystem) ---
    "@score_crates//:libc",
    "@score_crates//:serde",
    "@score_crates//:serde_json",

    # --- Community Fallback (Crate Universe) ---
    "@crates//:argon2",
    "@crates//:dirs",
    "@crates//:once_cell",
    "@crates//:parking_lot",
    "@crates//:parsec-client",
    "@crates//:tempfile",
    "@crates//:toml",
    "@crates//:zeroize",
    "@crates//:openssl",
]

rust_library(
    name = "cryptoki_lib",
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    srcs = glob(["**/*.rs"]),
    deps = DEPS,
)

rust_shared_library(
    name = "cryptoki_cdylib",
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    srcs = glob(["**/*.rs"]),
    deps = DEPS,
)
