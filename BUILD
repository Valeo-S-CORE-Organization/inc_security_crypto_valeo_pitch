# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("//:project_config.bzl", "PROJECT_CONFIG")

package(default_visibility = ["//visibility:public"])

exports_files([
    "Cargo.toml",
    "Cargo.lock",
    "README.md",
    "LICENSE",
    "NOTICE",
    "CONTRIBUTION.md",
    "MODULE.bazel",
    "project_config.bzl",
    "pyproject.toml",
])

filegroup(
    name = "rust_srcs",
    srcs = [
        "Cargo.toml",
        "Cargo.lock",
        "//src:src",
        "//examples:examples",
        "//tests/rust:test_main.rs",
    ] + glob([
        "tests/*.rs",
        "tests/common/**/*.rs",
    ], allow_empty = True),
)

filegroup(
    name = "cpp_srcs",
    srcs = glob([
        "cpp/**/*.cpp",
        "cpp/**/*.cc",
        "cpp/**/*.h",
        "cpp/**/*.hpp",
        "cpp/CMakeLists.txt",
    ]),
)

sh_binary(
    name = "cargo_build",
    srcs = ["tools/bazel/cargo_build.sh"],
    data = [":rust_srcs"],
)

sh_binary(
    name = "cargo_test",
    srcs = ["tools/bazel/cargo_test.sh"],
    data = [":rust_srcs"],
)

# Top-level aliases for ergonomic `bazel build/test //:foo` invocations
alias(
    name = "docs",
    actual = "//docs:docs",
)

alias(
    name = "rust_lib",
    actual = "//src:cryptoki_lib",
)

alias(
    name = "rust_unit_smoke",
    actual = "//tests/rust:rust_unit_smoke",
)

alias(
    name = "tests_rust",
    actual = "//tests:integration_tests",
)

alias(
    name = "tests_cpp",
    actual = "//tests/cpp:test_cpp",
)

alias(
    name = "tests_pkcs11_conformance",
    actual = "//tests/cpp:pkcs11test",
)

alias(
    name = "example_pkcs11_demo",
    actual = "//examples:pkcs11_demo",
)

alias(
    name = "example_pkcs11_business_demo",
    actual = "//examples:pkcs11_business_demo",
)
