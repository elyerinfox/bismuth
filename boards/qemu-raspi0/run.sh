#!/usr/bin/env bash
# Build + run the ARMv6 board in QEMU. Needs nightly (build-std) + rust-src.
set -e
cd "$(dirname "$0")"
RUSTUP_TOOLCHAIN=nightly cargo run
