# Contribution Guide

## Development workflows

This repository supports both workflows:

1. Cargo-first (`cargo build`, `cargo test`)
2. Bazel-orchestrated (`bazel run //:cargo_build`, `bazel test //tests/rust:rust_tests`)

## Quality gates

Before submitting changes:

1. `cargo clippy --all-targets --all-features -- -D warnings`
2. `cargo test`
