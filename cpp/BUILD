load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "cpp_srcs",
    srcs = glob(
        [
            "**/*.cpp",
            "**/*.h",
            "**/*.hpp",
            "CMakeLists.txt",
        ],
        exclude = [
            "build/**",
            "pkcs11test/**",  # Explicitly ignore the submodule directory
        ],
    ),
)

cc_library(
    name = "pkcs11_headers",
    hdrs = [
        "pkcs11.h",
        "pkcs11_cpp.hpp",
    ],
    includes = ["."],
)

cc_binary(
    name = "demo",
    srcs = ["demo.cpp"],
    deps = [":pkcs11_headers"],
    linkopts = ["-ldl"],
)

cc_binary(
    name = "test_cpp_bin",
    srcs = ["test_cpp.cpp"],
    deps = [":pkcs11_headers"],
    linkopts = ["-ldl"],
)
