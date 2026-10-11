#!/usr/bin/env bash
# Build the Bismuth x86-64 kernel, wrap it into a bootable BIOS image, and boot it in QEMU.
#
#   bash boards/qemu-x86_64/run.sh
#
# The kernel binary builds on stable; the `bootloader` image builder needs a nightly
# toolchain (it compiles the BIOS/UEFI stages with -Z build-std), so that one step runs
# under `nightly`. QEMU must be on PATH (or adjust QEMU below).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BOARD="$ROOT/boards/qemu-x86_64"
IMAGE="$ROOT/boards/qemu-x86_64-image"
KELF="$BOARD/target/x86_64-unknown-none/debug/bismuth-x86"
QEMU="${QEMU:-$HOME/scoop/apps/qemu/current/qemu-system-x86_64.exe}"

echo ">> building kernel (stable, x86_64-unknown-none)"
( cd "$BOARD" && cargo build )

echo ">> building bootable BIOS image (nightly: bootloader stages)"
( cd "$IMAGE" && RUSTUP_TOOLCHAIN=nightly cargo run --quiet -- "$KELF" "$IMAGE/bios.img" >/dev/null )

echo ">> booting in QEMU (serial on stdio; the demo halts QEMU when done, or Ctrl-A X)"
exec "$QEMU" -drive format=raw,file="$IMAGE/bios.img" -serial stdio -display none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
