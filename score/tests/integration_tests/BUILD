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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_test")
load("@score_itf//:defs.bzl", "py_itf_test")

cc_binary(
<<<<<<< HEAD:score/tests/integration_tests/BUILD
    name = "init_softhsm_token",
    srcs = ["init_softhsm_token.cpp"],
    deps = [
        "//third_party/soft_hsm:softhsm_shared",
    ],
=======
    name = "control_client_app",
    srcs = ["control_client_app.cpp"],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/api:operations",
        "//score/crypto/api/control_plane:control_plane_impl",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "init_pkcs11_token",
    srcs = ["init_pkcs11_token.cpp"],
    local_defines = select({
        "//score/crypto/daemon/provider/pkcs11:use_rust_pkcs11": ["USE_RUST_PKCS11=1"],
        "//conditions:default": [],
    }),
    deps = select({
        "//score/crypto/daemon/provider/pkcs11:use_rust_pkcs11": [
            "//score/cryptoki:cryptoki_cdylib",
            "//score/cryptoki:cryptoki_headers",
            "//third_party/openssl",
        ],
        "//conditions:default": [
            "//third_party/soft_hsm:libsofthsm_shared",
        ],
    }),
>>>>>>> a55e6c0 (Test: Rename init_softhsm_token to generic init_pkcs11_token):tests/integration_tests/BUILD
)

cc_binary(
    name = "score_api_hash_example",
    srcs = ["score_api_hash_example.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/hash:hash_test_vectors",
    ],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "score_api_mac_example",
    srcs = ["score_api_mac_example.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/mac:mac_test_vectors",
    ],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "hash_performance_test",
    srcs = ["hash_performance_test.cpp"],
    data = ["//score/tests/test_vectors/hash:hash_test_vectors"],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
        "@googletest//:gtest",
    ],
)

cc_binary(
    name = "score_demo",
    srcs = ["score_demo.cpp"],
    data = [
        "//score/tests/test_vectors/config:integration_test_config",
        "//score/tests/test_vectors/mac:mac_test_vectors",
    ],
    dynamic_deps = ["//third_party/grpc:libgrpc_shared"],
    deps = [
        "//score/crypto/src/api:crypto_stack",
        "//score/tests/utility",
    ],
)

py_itf_test(
    name = "integration_test_docker",
    size = "small",
    srcs = ["integration_test.py"],
    args = [
        "--docker-image=ubuntu:24.04",
        "--log-level=WARNING",
    ],
    data = [
<<<<<<< HEAD:score/tests/integration_tests/BUILD
        ":hash_performance_test",
        ":init_softhsm_token",
=======
        ":control_client_app",
        ":init_pkcs11_token",
>>>>>>> a55e6c0 (Test: Rename init_softhsm_token to generic init_pkcs11_token):tests/integration_tests/BUILD
        ":score_api_hash_example",
        ":score_api_mac_example",
        ":score_demo",
        "//score/crypto/src/api/control_plane",
        "//score/crypto/src/daemon:crypto_daemon",
        "//score/tests/config:logging.json",
        "//third_party/grpc:libgrpc_shared",
        "//third_party/openssl:openssl_so",
        "//third_party/soft_hsm:softhsm_so",
    ],
    plugins = [
        "itf.plugins.docker",
    ],
    target_compatible_with = select({
        "//score/crypto/src/backend:openssl_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }) + select({
        "//score/crypto/src/backend:pkcs11_backend_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
)
