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
load("@score_docs_as_code//:docs.bzl", "docs")
load("@score_tooling//:defs.bzl", "copyright_checker", "use_format_targets")
load("//:project_config.bzl", "PROJECT_CONFIG")

docs(
    data = [
        "@score_process//:needs_json",
    ],
    source_dir = ".",
)

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

copyright_checker(
    name = "copyright",
    srcs = [
        # ".github",
        "docs",
        "score",
        "third_party",
        "//:BUILD",
        "//:MODULE.bazel",
    ],
    config = "@score_tooling//cr_checker/resources:config",
    template = "@score_tooling//cr_checker/resources:templates",
    visibility = ["//visibility:public"],
)

# Top-level aliases for ergonomic `bazel build/test //:foo` invocations
use_format_targets()
