load("@rules_shell//shell:sh_test.bzl", "sh_test")

package(default_visibility = ["//visibility:public"])

# Smoke scaffold (no dlopen needed)
cc_test(
    name = "cpp_test_main",
    srcs = ["test_main.cpp"],
)

# Native wrapper test: cpp/test_cpp.cpp via dlopen → libcryptoki.so
sh_test(
    name = "test_cpp",
    srcs = ["run_test_cpp.sh"],
    data = [
        "//cpp:test_cpp_bin",
        "//src:cryptoki_cdylib",
    ],
    timeout = "short",
)

# Legacy cmake-based wrapper (kept for reference)
sh_test(
    name = "cpp_tests",
    srcs = ["run_cpp_tests.sh"],
    data = [
        "//cpp:test_cpp_bin",
        "//src:cryptoki_cdylib",
        "//:cpp_srcs",
    ],
    timeout = "long",
)
