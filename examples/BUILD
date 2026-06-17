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

load("@rules_cc//cc:defs.bzl", "cc_binary")
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

cc_binary(
    name = "hashing_example",
    srcs = ["hashing_example.cpp"],
    deps = [
        "//score/mw/crypto/api:crypto_stack",
        "//score/mw/crypto/api/config:context_configs",
        "//score/mw/crypto/api/contexts:crypto_contexts",
    ],
)

cc_binary(
    name = "memory_allocator_example",
    srcs = ["memory_allocator_example.cpp"],
    deps = [
        "//score/mw/crypto/api:crypto_stack",
        "//score/mw/crypto/api/common:crypto_common",
        "//score/mw/crypto/api/config:context_configs",
        "//score/mw/crypto/api/contexts:crypto_contexts",
    ],
)
