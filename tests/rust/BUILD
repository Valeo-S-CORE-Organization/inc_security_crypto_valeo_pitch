load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_test")
load("@rules_shell//shell:sh_test.bzl", "sh_test")

package(default_visibility = ["//visibility:public"])

exports_files(["test_main.rs"])

rust_test(
    name = "rust_unit_smoke",
    crate_root = "test_main.rs",
    srcs = ["test_main.rs"],
    aliases = aliases(
        normal_dev = True,
        proc_macro_dev = True,
        package_name = "",
    ),
    deps = ["//src:cryptoki_lib"] + all_crate_deps(normal_dev = True, package_name = ""),
    proc_macro_deps = all_crate_deps(proc_macro_dev = True, package_name = ""),
)

sh_test(
    name = "rust_tests",
    srcs = ["run_rust_tests.sh"],
    data = [
        "//:rust_srcs",
    ],
    timeout = "long",
)
