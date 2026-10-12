#!/usr/bin/env bash
# Build the Bismuth x86-64 kernel with the net-demo flow, wrap it into a bootable BIOS image, and
# boot it in QEMU with a virtio-net-pci NIC on QEMU's user/SLIRP network.
#
#   bash boards/qemu-x86_64/run-net.sh
#
# Kernel builds on stable; the `bootloader` image builder needs nightly. QEMU must be on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BOARD="$ROOT/boards/qemu-x86_64"
IMAGE="$ROOT/boards/qemu-x86_64-image"
KELF="$BOARD/target/x86_64-unknown-none/debug/bismuth-x86"
QEMU="${QEMU:-$HOME/scoop/apps/qemu/current/qemu-system-x86_64.exe}"

echo ">> building kernel (stable, --features net-demo)"
( cd "$BOARD" && cargo build --features net-demo )

echo ">> building bootable BIOS image (nightly: bootloader stages)"
( cd "$IMAGE" && RUSTUP_TOOLCHAIN=nightly cargo run --quiet -- "$KELF" "$IMAGE/bios-net.img" >/dev/null )

echo ">> booting in QEMU with a virtio-net-pci NIC on user/SLIRP"
# disable-modern=on,disable-legacy=off forces the transitional device's legacy I/O BAR, which the
# driver drives (the PFN queue interface). SLIRP gives the guest 10.0.2.15 and a gateway 10.0.2.2.
exec "$QEMU" -drive format=raw,file="$IMAGE/bios-net.img" -serial stdio -display none -no-reboot \
    -netdev user,id=n0 \
    -device virtio-net-pci,netdev=n0,disable-modern=on,disable-legacy=off \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
