load("@crates//:defs.bzl", "aliases", "all_crate_deps")
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
    aliases = aliases(package_name = ""),
    deps = ["//src:cryptoki_lib"] + all_crate_deps(normal = True, package_name = ""),
    proc_macro_deps = all_crate_deps(proc_macro = True, package_name = ""),
)

rust_binary(
    name = "pkcs11_business_demo",
    crate_root = "pkcs11_business_demo.rs",
    srcs = ["pkcs11_business_demo.rs"],
    aliases = aliases(package_name = ""),
    deps = ["//src:cryptoki_lib"] + all_crate_deps(normal = True, package_name = ""),
    proc_macro_deps = all_crate_deps(proc_macro = True, package_name = ""),
)
