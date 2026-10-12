#!/usr/bin/env bash
# Build and boot the Bismuth aarch64 hypervisor (stage 1): stay at EL2 and run a hand-assembled
# guest at EL1 that prints through an HVC hypercall.
#
#   bash boards/qemu-virt-aarch64/run-hv.sh
#
# Needs QEMU `-M virt,virtualization=on` so the VM enters at EL2 (plain `-M virt` enters at EL1).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
KELF="$ROOT/target/aarch64-unknown-none-softfloat/debug/bismuth-aarch64"
QEMU="${QEMU:-qemu-system-aarch64}"

echo ">> building (--features hypervisor)"
( cd "$ROOT" && cargo build --features hypervisor )

echo ">> booting at EL2 (virtualization=on)"
exec "$QEMU" -M virt,virtualization=on -cpu cortex-a53 -nographic -semihosting -kernel "$KELF"
