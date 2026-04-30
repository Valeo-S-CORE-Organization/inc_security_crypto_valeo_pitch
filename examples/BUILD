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
