load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "parsec_srcs",
    srcs = glob(["*.rs"]),
)

filegroup(
    name = "parsec_config",
    srcs = ["config.toml"],
)

rust_binary(
    name = "parsec_client",
    crate_root = "client.rs",
    srcs = ["client.rs"],
    aliases = aliases(package_name = ""),
    deps = all_crate_deps(normal = True, package_name = ""),
    proc_macro_deps = all_crate_deps(proc_macro = True, package_name = ""),
)

sh_binary(
    name = "start_parsec",
    srcs = ["scripts/start_parsec.sh"],
    data = [":parsec_config"],
)

sh_binary(
    name = "start_client",
    srcs = ["scripts/start_client.sh"],
    data = [":parsec_client"],
)
