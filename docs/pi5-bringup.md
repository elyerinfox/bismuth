# Raspberry Pi 5 (BCM2712) bring-up notes

Bismuth's aarch64 Cortex-A port covers the Pi 3/4 and Jetson; the Pi 5 reuses that same port.
It is **not yet a board crate** because (a) QEMU has no `raspi5` machine (QEMU 11.1 provides
`raspi0/1ap/2b/3ap/3b/4b` only), so it cannot be verified in emulation, and (b) the BCM2712
peripheral layout is materially different and its bare-metal addresses must be taken from the
datasheet and confirmed on real hardware rather than guessed.

## What a `boards/rpi5` crate needs
- **Target:** `aarch64-unknown-none-softfloat`, load at `0x80000` (64-bit kernel), armstub
  enters at EL2 → the port's existing EL2→EL1 drop handles it.
- **CPU:** Cortex-A76 (ARMv8.2-A) — the port is CPU-agnostic above the GIC/timer.
- **`bismuth_board_map()`** with the BCM2712 values:
  - RAM base `0x0`, size per board (4/8/16 GiB).
  - Peripherals: BCM2712 uses a 40-bit map; most I/O is behind the **RP1** southbridge over
    PCIe, but the SoC debug UART (PL011) and the GIC are directly addressable. Fill
    `periph_base`/`periph_size` to cover both, and `gicd`/`gicc` for the GIC-400/GICv2 block.
  - `intc = KIND_GIC`.
- **Console:** a PL011 (the in-tree driver) at the BCM2712 debug-UART address, or an NS16550
  if the chosen UART is 16550-style (the `ns16550` driver already exists).
- The MMU builder (`arch/aarch64/paging.rs`) already classifies any 1 GiB region as RAM /
  peripheral / image from the board map, including the high (40-bit) peripheral window, so no
  port changes are expected — only the board addresses.

## Why not ship it now
Shipping a board with unverified, possibly-wrong addresses would violate the project's
"verified green" rule. Bring-up should be done against a real Pi 5 (serial console attached),
at which point this becomes a normal board-address exercise like `raspi4b`.

## Status update
A build-verified board crate now exists at `boards/rpi5/` using the tentative BCM2712
addresses above (RAM 0x0, GIC-400 at 0x10_7fff_9000/_a000, debug PL011 at 0x10_7d00_1000).
It compiles cleanly for `aarch64-unknown-none-softfloat` but is **unrun** — there is no QEMU
`raspi5` machine. Confirm the addresses against a real Pi 5 with a serial console attached,
then it joins the other QEMU-less-but-real boards (like the Jetson).
