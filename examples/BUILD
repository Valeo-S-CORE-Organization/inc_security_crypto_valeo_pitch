load("@rules_rust//rust:defs.bzl", "rust_binary")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "examples",
    srcs = glob(["**/*.rs"]),
)

rust_binary(
    name = "pkcs11_demo",
    crate_root = "pkcs11_demo.rs",
    srcs = ["pkcs11_demo.rs"],
    deps = [
        "//src:cryptoki_lib",
        "@crates//:libc",
    ],
)

rust_binary(
    name = "pkcs11_business_demo",
    crate_root = "pkcs11_business_demo.rs",
    srcs = ["pkcs11_business_demo.rs"],
    deps = [
        "//src:cryptoki_lib",
        "@crates//:libc",
    ],
)
