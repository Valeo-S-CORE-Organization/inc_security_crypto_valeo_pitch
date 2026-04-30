load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_shared_library")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "src",
    srcs = glob(["**/*.rs"]),
)

rust_library(
    name = "cryptoki_lib",
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    srcs = glob(["**/*.rs"]),
    aliases = aliases(package_name = ""),
    deps = all_crate_deps(normal = True, package_name = ""),
    proc_macro_deps = all_crate_deps(proc_macro = True, package_name = ""),
)

rust_shared_library(
    name = "cryptoki_cdylib",
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    srcs = glob(["**/*.rs"]),
    aliases = aliases(package_name = ""),
    deps = all_crate_deps(normal = True, package_name = ""),
    proc_macro_deps = all_crate_deps(proc_macro = True, package_name = ""),
)
