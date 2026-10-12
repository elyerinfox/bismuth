# Bismuth as a type-1 hypervisor (aarch64)

Status: **stage 1 landed** (EL2 boot + a guest at EL1 + an HVC hypercall round-trip, QEMU-verified).
This doc records the architecture, the model decision, and the staged roadmap toward hosting a
real guest OS — the one remaining path to running an *unmodified* Linux/Docker distribution on
Bismuth (as opposed to the Linux-ABI personality, which runs Linux *binaries* at EL0 under the
Bismuth kernel).

## Why a hypervisor, and how it differs from the Linux-ABI path

Bismuth already runs Linux executables via two routes that do **not** need a hypervisor:

- the **Linux-ABI personality** (`linux-abi`): loads an aarch64 Linux ELF, runs it at EL0 under the
  Bismuth kernel, and emulates Linux syscalls (`openat`/`mmap`/`getdents64`/…). Good for a single
  static binary; it is *not* a whole distro and has no Linux kernel.
- the **native / WASM container runtimes**: Bismuth's own isolation model.

A *literal* `docker run ubuntu` boots a real **Linux kernel** plus a userland. The only faithful
way to host that on Bismuth is a **virtual machine**: Bismuth runs at **EL2** as a type-1
hypervisor, the guest Linux kernel runs at **EL1**, guest userland at **EL0**, and the guest's
own CPU/MMU/syscalls run natively while Bismuth mediates physical memory (stage-2 translation),
interrupts (vGIC), the timer, and I/O (virtio backends).

## Model decision: thin EL2 shim, Bismuth core stays EL1

Two shapes were considered:

1. **Move the whole Bismuth kernel to EL2** and run everything (RTOS tasks + guests) there.
2. **Keep the Bismuth RTOS at EL1; add a thin EL2 shim** that only does VM hosting, entered when
   a VM is created.

**Recommendation: (2) — a thin EL2 shim, Bismuth core stays EL1.** Rationale for an RTOS:

- The RTOS scheduler, drivers, and the whole verified EL0-isolation/stack machinery are written
  and tested against EL1/EL0. Hoisting them to EL2/EL1 would re-open every one of those seams for
  no RTOS benefit.
- Real-time guarantees: the hypervisor shim should be *small and bounded* (trap, service, return),
  not the home of the general scheduler. A fat EL2 is a worse-bounded TCB.
- An RTOS's job is determinism for its native tasks; VMs are an *add-on*. Keeping them to a narrow
  EL2 shim keeps the hot paths (RTOS) unchanged and the VM paths isolated and optional.

The `hypervisor` feature is therefore **off by default**: a normal build is byte-for-byte the EL1
kernel. Only a hypervisor build keeps EL2 and brings the shim up. (Stage 1, below, runs *only* the
shim at EL2 to prove the mechanism; stages 4–5 wire the EL1 RTOS and the EL2 shim to coexist, with
the RTOS owning the cores and the shim entered to run a guest time-slice.)

## EL exception model (aarch64, `virt,virtualization=on`)

```
EL2  Bismuth hypervisor shim  (VBAR_EL2, HCR_EL2, stage-2 tables, vGIC, virtio backends)
 |                 ^ traps: HVC, stage-2 faults, trapped sysreg/WFx, virtual IRQ inject
 v eret            |
EL1  guest OS kernel          (its own VBAR_EL1 / TTBR_EL1 / sctlr)
 |                 ^ guest syscalls stay within the guest (EL0<->EL1), Bismuth never sees them
 v                 |
EL0  guest userland
```

Bismuth only gets involved on the EL2 traps it configures in `HCR_EL2`: hypercalls (`HVC`),
stage-2 translation faults (guest physical not mapped / MMIO), the virtual timer, and virtual
interrupt injection. Guest EL0<->EL1 syscalls run natively and never trap to EL2.

## Staged roadmap

- **S1 — EL2 boot + guest trap round-trip (DONE).** Reset stays at EL2; install `VBAR_EL2`; load a
  guest blob; `eret` to EL1; service `HVC #0` hypercalls (print/exit). MMU off, no stage-2 — the
  guest shares the host's flat physical space and is trusted hand-assembled code. Proves the
  EL1-guest -> EL2-hypervisor mechanism. *(see `src/arch/aarch64/hyp.rs`, board `hypervisor`
  feature, `run-hv.sh`.)*
- **S2 — stage-2 translation (DONE).** Set up **stage-2** tables (`VTTBR_EL2`, `VTCR_EL2`, 4 KiB
  granule / 40-bit IPA / start level 1) and enable them with `HCR_EL2.VM`, so the guest sees a
  *guest-physical* RAM window at IPA `0x4000_0000` (2 MiB) that Bismuth maps to a bounded,
  2 MiB-aligned host-physical arena (`GUEST_RAM`). Nothing else is mapped, so any guest access
  outside the window takes a stage-2 abort to EL2 (`ESR_EL2.EC` 0x24/0x20), where the handler
  reads the faulting IPA from `HPFAR_EL2`+`FAR_EL2` and kills the guest. The `HVC_PRINT` path now
  translates the guest's IPA pointer to a host address (`gpa_to_hpa`) and bounds it to guest RAM
  before reading. This is the real memory isolation: a VM, not shared RAM. EL2 itself is left
  MMU-off (the guest's stage-1 is also off: VA=IPA, stage-2 does the real mapping), which is
  enough for S2; an EL2 identity map (Normal cacheable RAM + atomics at EL2) is deferred to when
  a later stage needs EL2-side cacheable state. **Verified in QEMU:** the guest R/W's its own
  stage-2 RAM, then a read of unmapped IPA `0x5000_0000` traps to EL2 ("stage-2 fault: guest
  read/write of unmapped IPA=0x50000000 — guest killed").
- **S3 — vGIC (DONE).** The hypervisor enables the GICv2 hypervisor interface (`GICH_HCR.En`),
  seeds `GICH_VMCR` (virtual group enables + priority mask), and injects a virtual interrupt by
  writing a **list register** (`GICH_LR0`: pending, Group 1, vINTID 27). Stage-2 maps the virtual
  CPU interface **GICV** into the guest at the standard GICC IPA (`0x0801_0000`), so the guest
  acknowledges/ends the interrupt through `GICV_AIAR`/`GICV_AEOIR` exactly as on real hardware;
  `HCR_EL2.IMO=1` routes the vGIC's virtual IRQ to EL1. The guest installs a `VBAR_EL1` table,
  unmasks (via `msr DAIF, xzr` — the immediate `daifclr` form was unreliable in this hand-assembly),
  takes the IRQ, and re-arms the next tick with an `HVC_TICK` hypercall. QEMU-verified: the guest
  takes four virtual-timer interrupts injected by the hypervisor, printing each via a hypercall.
  *Simplification:* the tick cadence is driven by the guest's `HVC_TICK` (the hypervisor injects on
  request) rather than a hardware `CNTV`/maintenance-interrupt loop at EL2 — that HW-timer-linked
  path (trap/offset `CNTVOFF_EL2`, refill LRs on the maintenance IRQ) is the S3b/S4 refinement.
  What is proven is the core vGIC mechanism: LR injection → GICV → guest IRQ handler → EOI.
- **S4 — virtio-mmio console backend (DONE).** Bismuth presents the guest a virtio-mmio device at
  guest IPA `0x0a00_0000` (the QEMU `virt` virtio slot), left *unmapped* in stage-2 so every guest
  access there faults to EL2. The abort handler decodes the trapped load/store from `ESR_EL2`
  (ISV/SAS/SRT/WnR), services it against a register-file emulator (`virtio_read`/`virtio_write` in
  `hyp.rs`), and advances the guest past the instruction (ELR_EL2 += 4) — a classic MMIO
  trap-and-emulate. On `QueueNotify` the backend walks the split virtqueue **in guest RAM**
  (descriptor table / avail ring / used ring, all guest IPAs translated via `gpa_to_hpa`) and
  drains each available buffer to the real PL011, then publishes the used ring. QEMU-verified: the
  S4 guest reads `DeviceID=3` back through the emulator, runs the ACKNOWLEDGE→DRIVER→FEATURES_OK→
  DRIVER_OK status handshake, programs queue 0's addresses + `QueueReady`, kicks `QueueNotify`, and
  its string emerges on the UART via the hypervisor's queue walk — paravirtual console output with
  no Bismuth-specific hypercall. Simplifications (deliberate, documented): one queue; modern-mmio
  register layout but a legacy-style zero-feature handshake; the descriptor + avail ring are static
  guest data (the guest drives the MMIO protocol + doorbell); polled single-shot drain with no
  used-buffer vIRQ injected back (the S3 vGIC path would carry that); block/net virtio backends
  (serving Bismuth's VFS/NIC to the guest) are the S4b extension.
- **S5 — a minimal guest OS (DONE).** One hand-assembled guest at EL1 that ties S2–S4 together:
  it sets `VBAR_EL1` + an EL1 vector table, runs the virtio-mmio console handshake and prints a
  boot banner through it, enables its vGIC CPU interface (`GICV_CTLR`/`PMR`) and unmasks IRQs, then
  WFI-loops. Each hypervisor-injected virtual-timer vIRQ (vINTID 27) enters the guest's IRQ vector
  (Current-EL-SPx slot), which acks via `GICV_AIAR`, prints `scheduler tick #N` **through the
  virtio-console** (not a raw hypercall), `GICV_AEOIR`s, and requests the next tick via `HVC_TICK`;
  after 5 ticks it prints a shutdown line and `HVC_EXIT`s. QEMU-verified end to end — banner, five
  ticks, clean shutdown — exercising stage-2 RAM + vGIC + virtio-console in one guest. (Originally
  the guest re-armed each tick with an `HVC_TICK` hypercall; S6 replaced that with a real hardware
  timer and PSCI shutdown.)
- **S6 — hardware-timer tick + PSCI/SMC (DONE).** Two refinements that make the guest behave like a
  real kernel rather than leaning on Bismuth-specific hypercalls:
  - *Hardware-timer-driven tick.* The hypervisor arms the **EL2 physical timer** (`CNTHP_*_EL2`,
    PPI INTID 26) and routes physical IRQs to EL2 (`HCR_EL2.IMO`). It fires on a free-running
    cadence while the guest runs at EL1; the EL2 IRQ vector (Lower-EL-AArch64 IRQ slot) re-arms the
    one-shot (`CNTHP_TVAL_EL2`) and injects the guest's virtual-timer vIRQ (27) through `GICH_LR0`.
    The guest no longer requests ticks — `HVC_TICK` is gone from the guest path.
  - *PSCI over SMC.* `HCR_EL2.TSC=1` traps the guest's `SMC` to EL2 (ESR_EL2 EC 0x17); the shim
    emulates a PSCI 1.1 subset — `PSCI_VERSION` (→ 0x00010001), `SYSTEM_OFF`/`SYSTEM_RESET` (stop
    the VM), `PSCI_FEATURES`, `MIGRATE_INFO_TYPE`, and `CPU_ON` (NOT_SUPPORTED for the single vCPU)
    — returning the result in `x0` and skipping the `smc`. The capstone guest now powers the VM off
    with a real `SYSTEM_OFF` SMC instead of an exit hypercall. QEMU-verified: banner, five
    hardware-timer ticks via the vGIC, PSCI power-off.
- **S7 — virtio-blk + virtio-net backends (DONE).** The S4 single-device console emulator is
  generalized to a small array of virtio-mmio devices at distinct IPA slots (console `0x0a00_0000`,
  block `0x0a00_0200`, net `0x0a00_0400`); the stage-2 abort handler picks the device by IPA and
  routes the decoded access to a shared register-file emulator.
  - *virtio-blk (DeviceID 2):* a host RAM disk (128 × 512-byte sectors, seeded). On `QueueNotify`
    the backend parses the request chain (16-byte header → data buffer(s) → 1-byte status) and
    serves `VIRTIO_BLK_T_IN`/`T_OUT` against the disk via `gpa_to_hpa`, writing the status and
    publishing the used ring.
  - *virtio-net (DeviceID 1):* RX(0)/TX(1) queues with a loopback backend — on a TX kick it reads
    the guest's frame, prints a summary, and copies it into a buffer the guest pre-posted on the RX
    queue, publishing both used rings (bidirectional path).
  - The S7 guest "OS" runs the console banner, then reads sector 0 of the block device and prints
    it, then transmits a frame and confirms the RX loopback, then takes the five hardware-timer
    ticks and powers off via PSCI. QEMU-verified end to end. Scope: polled (the guest reads the used
    ring; no used-buffer vIRQ yet), small queues, loopback net (no real link). These are the same
    device classes a Linux guest drives — the backing (a Bismuth VFS file as rootfs, the in-tree NIC
    as the link) is the remaining substitution, not new mechanism.

- **S8 — the aarch64 Linux boot protocol (DONE).** The hypervisor now loads a guest **`Image`** and
  hands it a generated **DTB**, exactly the contract a real Linux kernel expects:
  - *Image header:* `parse_image` validates the 64-byte arm64 header (`Documentation/arm64/booting.rst`)
    — magic `ARM\x64` (0x644d_5241) at offset 56 — and reads `text_offset`/`image_size`; `run_guest`
    loads the image at `GUEST_IPA_BASE + text_offset`.
  - *DTB generation:* `build_dtb` emits a flattened device tree (FDT v17, big-endian) into guest RAM
    at IPA `0x4010_0000` — `/` (`#address/#size-cells`), `/chosen` (`bootargs`, `stdout-path`),
    `/psci` (`arm,psci-1.0`, `method="smc"`), `/memory@40000000`, `/cpus/cpu@0` (`enable-method="psci"`),
    `/intc@8000000` (GICv2), and the three `/virtio_mmio@…` nodes matching the S4/S7 device IPAs.
  - *Boot entry:* `eret` to the image with `x0 = DTB IPA`, `x1=x2=x3=0`, EL1, MMU/caches off — the
    arm64 kernel boot protocol verbatim.
  - *Proof:* the hand-assembled `hv_kernel` carries a real Image header, is loaded through the
    header path, validates the FDT magic (`0xd00d_feed`), prints the FDT totalsize, scans the DTB
    for the `/chosen` `console=` bootargs and prints them, then powers off via a PSCI `SYSTEM_OFF`
    `smc`. QEMU-verified. Because the load/DTB/entry path is the real one, dropping an actual Linux
    `Image` in `hv_kernel` (on hardware, or QEMU with a larger `GUEST_RAM`) boots it.

- **S9 — GICv2 distributor emulation + initrd hand-off (DONE).** The guest's **distributor** (`GICD`
  @ IPA `0x0800_0000`, 64 KiB) is left unmapped in stage-2 and trap-and-emulated (`gicd_read`/
  `gicd_write`): `GICD_CTLR`, `GICD_TYPER`, `GICD_IIDR`, `GICD_IGROUPRn`, `GICD_ISENABLERn`/
  `ICENABLERn` (tracked enable mask), `GICD_ITARGETSRn`. The hardware-timer injection is now **gated
  on the distributor** — `gicd_irq_enabled(27)` — so the guest gets ticks only after it enables INTID
  27 in `GICD_ISENABLER0`, exactly as a real kernel programs the distributor at boot. An **initrd**
  blob is placed in guest RAM and advertised in the DTB `/chosen` props `linux,initrd-start`/`-end`.
  *Proof:* the `hv_kernel` stand-in programs `GICD_ISENABLER0 |= 1<<27`, reads back `ISENABLER0`
  (`0x0800_0000`) and `TYPER` (`0x1`), walks the DTB for `linux,initrd-start` (reads `0x4014_0000`
  and the first initramfs byte), then sets up its GICV CPU interface + `VBAR_EL1` and takes three
  hardware-timer ticks **gated by the GICD enable it set**, before PSCI `SYSTEM_OFF`. QEMU-verified.

## What the hypervisor can do today

A `--features hypervisor` Bismuth boot (QEMU `-M virt,virtualization=on`) is a working minimal
type-1 hypervisor: it runs at **EL2**, creates a guest VM with its own **stage-2-translated RAM**
(guest accesses outside it fault to EL2), a **vGIC** that injects virtual interrupts the guest
acks/EOIs through its own GICV, emulated **virtio-mmio devices** driven by the standard guest
virtio handshake + virtqueues (trap-and-emulate) — a **console** (drains to the UART), a **block**
device (host RAM disk, read/write requests), and a **network** device (TX/RX loopback) — a
**free-running hardware-timer tick** (the EL2 physical timer injecting the guest's virtual-timer
IRQ on its own cadence), **PSCI-over-SMC** power control
(`VERSION`/`SYSTEM_OFF`/`RESET`/`FEATURES`/`CPU_ON`), and a small **hypercall ABI**. It loads a
guest **`Image`** (arm64 header parse) and hands it a **generated DTB** in `x0` per the **Linux
aarch64 boot protocol**. The capstone guests use all of this together — one "OS" prints a banner,
reads a disk sector, round-trips a network frame, takes timer ticks and powers off via PSCI; the
`hv_kernel` stand-in is loaded as a real `Image`, validates the DTB hand-off, programs the emulated
GICD distributor, reads its `/chosen` bootargs + `linux,initrd-*`, takes GICD-gated hardware-timer
ticks, then PSCIs off. What a real Linux guest additionally needs (an actual kernel image, larger
device backing, multi-vCPU) is enumerated next.

## The honest blocker for *literal* Linux/Docker

Booting a real Linux kernel as the guest needs a Linux `Image` (and, for a distro, a rootfs), i.e. a
cross-compiled aarch64 Linux build. **This sandbox has no aarch64 Linux toolchain and no network to
fetch a prebuilt image**, so the entire hypervisor *mechanism* (S1–S9, including the Image-header
load + DTB generation + boot-protocol entry) is built and QEMU-verified here with hand-assembled
guests, but the final "unmodified Ubuntu" step requires that external `Image`/rootfs to be supplied.
The same ceiling the Linux-ABI path hit: Bismuth's side is implemented and testable; producing or
fetching a real distro image is an environment limit, not a kernel limit.

### To boot a real aarch64 Linux guest (concrete remaining work)

The hypervisor-side mechanism is now **complete** (S1–S8); the checklist below is all ✅ except the
one external artifact. With a Linux `Image` + DTB in hand (on real hardware or a networked build
host), a real guest boots through the same path the `hv_kernel` stand-in exercises:
- **Load + entry / DTB:** ✅ DONE (S8) — `parse_image` loads the `Image` at `GUEST_IPA_BASE +
  text_offset`, `build_dtb` generates the DTB in guest RAM, and entry is `x0` = DTB IPA per the
  arm64 boot protocol. For a real kernel: enlarge the `GUEST_RAM` arena (2 MiB → tens of MiB) and
  the stage-2 map to fit the kernel + initrd, and (if the image sets a non-zero `text_offset` or the
  2 MiB-anywhere flag) honour that placement — the parse already returns `text_offset`.
- **PSCI/SMC:** ✅ DONE (S6) — PSCI over `SMC` trapped via `HCR_EL2.TSC` (`VERSION`, `SYSTEM_OFF`,
  `SYSTEM_RESET`, `FEATURES`, `CPU_ON`→NOT_SUPPORTED single-vCPU). A real multi-vCPU guest would
  extend `CPU_ON` to actually start a second vCPU context.
- **Hardware timer:** ✅ DONE (S6) — the EL2 physical timer (`CNTHP_*_EL2`) drives ticks on a
  free-running cadence, injecting the guest's virtual-timer vIRQ with no guest hypercall. (A real
  guest that programs its *own* `CNTV` would also want `CNTVOFF_EL2` + trapping `CNTV` accesses; the
  injection/LR-refill mechanism is the same one proven here.)
- **vGIC distributor:** ✅ DONE (S9) — the GICv2 **distributor** (`GICD` @ IPA `0x0800_0000`) is now
  trap-and-emulated (left unmapped in stage-2; faults routed to `gicd_read`/`gicd_write`):
  `GICD_CTLR`, `GICD_TYPER` (ITLinesNumber → 64 INTIDs), `GICD_IIDR`, `GICD_IGROUPRn`,
  `GICD_ISENABLERn`/`ICENABLERn` (tracked enable mask), `GICD_ITARGETSRn`. Injection is now **gated
  on the distributor enable** — the guest receives its virtual-timer tick only after it sets INTID 27
  in `GICD_ISENABLER0`, exactly as a real kernel programs the distributor. (A full GICv3 `GICR`
  redistributor model is the only further refinement, for a GICv3 guest.)
- **initrd / rootfs hand-off:** ✅ DONE (S9) — the hypervisor places an initramfs blob in guest RAM
  and advertises it in the DTB `/chosen` props `linux,initrd-start` / `linux,initrd-end`, the exact
  mechanism a Linux kernel uses to find its initial rootfs. (A *real* distro rootfs image is the
  external artifact below; the hand-off path itself is complete and verified.)
- **virtio-blk / virtio-net backends:** ✅ DONE (S7) — the virtio-mmio emulator now presents a
  block device (host RAM disk) and a net device (loopback) alongside the console, driven by the
  standard guest handshake + virtqueues. For a real guest: back blk with a Bismuth VFS file / larger
  disk as the rootfs, bridge net to the in-tree NIC, and add used-buffer vIRQ injection (poll → IRQ).
- **Console:** the S4 virtio-console already serves guest output; add RX for input.

The hypervisor *mechanism* is now complete end-to-end (S1–S9): EL2 boot, stage-2 isolation,
PSCI/SMC, a hardware-timer-driven vGIC with a trap-emulated **distributor** that gates delivery,
virtio **console/blk/net** backends, the arm64 `Image`-header + **DTB** (with **initrd** hand-off)
boot protocol. The remaining items are **scale hardening** (used-buffer vIRQ injection instead of
polling, a VFS-file rootfs, a bridged NIC, a larger `GUEST_RAM`, multi-vCPU `CPU_ON`, GICv3 `GICR`)
— none blocked *in principle*, all more of the same trap-and-emulate — and then the one hard
**external** dependency: a real aarch64 Linux kernel `Image` + rootfs, which this sandbox cannot
build or fetch (no cross-toolchain, no network, no hardware). On real hardware, or on QEMU with
`-kernel <Image> -initrd <rootfs>`, a real Linux guest boots through the very path the `hv_kernel`
stand-in exercises; once it boots, `docker`/`k8s` inside it is ordinary, unmodified Linux userspace.

## Stage-1 implementation notes

- Reset: `src/arch/aarch64/boot.rs` has a `#[cfg(feature = "hypervisor")] _start` that parks
  secondaries, sets `SP_EL2`, zeroes `.bss`, and calls `rust_boot_hyp` -> the board `kernel_main`,
  all **without** the EL2->EL1 drop the normal `_start` does.
- Shim: `src/arch/aarch64/hyp.rs` (TCB). `hyp_vectors` (a 2 KiB-aligned `VBAR_EL2` table) routes
  the Lower-EL-AArch64 synchronous slot to `hvc_vector`, which saves the guest GPRs, calls
  `hvc_entry`, and `eret`s back. `run_guest(blob)` prints the EL (proving EL2), copies the guest
  into RAM, sets `HCR_EL2.RW`/`SP_EL1`/`ELR_EL2`/`SPSR_EL2`, and `eret`s to EL1. Hypercall ABI:
  `x0` = command (1 = print `[x1..x1+x2)`, 2 = exit `x1`).
- Guest: the live guest from S8 on is `boards/qemu-virt-aarch64/src/hv_kernel.rs` — a decode-verified
  blob with a **real arm64 Image header**, loaded through the boot-protocol path. At S9 it validates
  the DTB, programs the emulated GICD (enables INTID 27, reads back `ISENABLER0`/`TYPER`), reads
  `/chosen linux,initrd-start` + the handed-off initramfs, sets `VBAR_EL1` + its GICV CPU interface,
  takes GICD-gated hardware-timer ticks, then PSCI `SYSTEM_OFF`. (The earlier `hv_guest.rs` — the
  S5–S7 virtio/timer "guest OS" — remains on disk as a historical artifact, no longer compiled.)
  Hypercall ABI: `x0` = command (1 = print `[x1..x1+x2)`, 2 = exit `x1`, 4 = hex-print `x1`).
  Assemblers: `scratchpad/mkhvkernel2.py` (S9 kernel), `mkhvos.py` (S5–S7 guest).
- Run: `bash boards/qemu-virt-aarch64/run-hv.sh` (QEMU `-M virt,virtualization=on`).
