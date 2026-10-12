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

# A scratch disk exposed as a virtio-blk-pci device, so the virtio-pci driver has something to
# probe and round-trip a sector through.
DISK="$IMAGE/virtio-disk.img"
[ -f "$DISK" ] || head -c $((16*1024*1024)) /dev/zero > "$DISK"

echo ">> booting in QEMU (serial on stdio; the demo halts QEMU when done, or Ctrl-A X)"
exec "$QEMU" -drive format=raw,file="$IMAGE/bios.img" -serial stdio -display none -no-reboot \
    -drive format=raw,file="$DISK",if=none,id=vd0 -device virtio-blk-pci,drive=vd0 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
