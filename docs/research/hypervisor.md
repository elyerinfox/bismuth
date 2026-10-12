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
- **S4 — virtio-mmio backends.** Bismuth presents the guest virtio-mmio devices (console, block,
  net) whose rings live in guest-physical RAM; trap the guest's doorbell writes (stage-2 MMIO
  faults) and service the queues against Bismuth's real drivers/VFS/NIC. This is how the guest
  does I/O without real device passthrough.
- **S5 — boot a minimal guest OS.** With S2–S4, load a guest `Image`+DTB at the guest-physical
  kernel address and boot it. Demonstrable here with a *hand-assembled* mini-guest that uses the
  vGIC/timer/virtio (same no-toolchain tactic as the Linux-ABI ELFs).

## The honest blocker for *literal* Linux/Docker

Booting a real Linux kernel as the guest needs a Linux `Image` (and a DTB), i.e. a cross-compiled
aarch64 Linux build. **This sandbox has no aarch64 Linux toolchain and no network to fetch a
prebuilt image**, so the *mechanism* (S1–S5) is buildable and verifiable here, but the final
"unmodified Ubuntu" step requires an external artifact that must be supplied. The same ceiling the
Linux-ABI path hit: Bismuth's side is implementable and testable with hand-assembled guests;
producing/fetching a real distro image is an environment limit, not a kernel limit.

## Stage-1 implementation notes

- Reset: `src/arch/aarch64/boot.rs` has a `#[cfg(feature = "hypervisor")] _start` that parks
  secondaries, sets `SP_EL2`, zeroes `.bss`, and calls `rust_boot_hyp` -> the board `kernel_main`,
  all **without** the EL2->EL1 drop the normal `_start` does.
- Shim: `src/arch/aarch64/hyp.rs` (TCB). `hyp_vectors` (a 2 KiB-aligned `VBAR_EL2` table) routes
  the Lower-EL-AArch64 synchronous slot to `hvc_vector`, which saves the guest GPRs, calls
  `hvc_entry`, and `eret`s back. `run_guest(blob)` prints the EL (proving EL2), copies the guest
  into RAM, sets `HCR_EL2.RW`/`SP_EL1`/`ELR_EL2`/`SPSR_EL2`, and `eret`s to EL1. Hypercall ABI:
  `x0` = command (1 = print `[x1..x1+x2)`, 2 = exit `x1`).
- Guest: `boards/qemu-virt-aarch64/src/hv_guest.rs` — a 108-byte decode-verified blob that prints
  via `HVC_PRINT` then `HVC_EXIT`.
- Run: `bash boards/qemu-virt-aarch64/run-hv.sh` (QEMU `-M virt,virtualization=on`).
