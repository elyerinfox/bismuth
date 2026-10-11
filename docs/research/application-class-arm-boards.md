# Bismuth Application-Class ARM Port: Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: porting Bismuth — a safe-Rust, `no_std`, no-heap RTOS — to **application-class ARM (Cortex-A)** boards: the **NVIDIA Jetson Nano** (Tegra X1, 4× Cortex-A57, AArch64) and the **whole Raspberry Pi family** (Pi 1 / Zero / Zero W = BCM2835, ARM1176JZF-S / ARMv6; Pi 2 = BCM2836, Cortex-A7 / ARMv7-A; Pi 3 / Zero 2 W = BCM2837, Cortex-A53 / ARMv8-A; Pi 4 = BCM2711, Cortex-A72; Pi 5 = BCM2712, Cortex-A76). The port is **AArch64 (ARMv8-A) primary**, bring-up **QEMU-first** on `-M virt` then `-M raspi3b`/`raspi4b`, with real silicon (Pi 3/4/5, Jetson) a documented follow-on and the 32-bit ARMv6/ARMv7-A models an explicit later split. Scope now = the **kernel port + a minimal board-driver set** (PL011 serial — already in-tree — ARM generic timer, GIC). Networking/USB/GPU/display are out of scope for this document.
>
> Current Bismuth baseline (read from the tree): the portable kernel talks to the CPU through a small fixed surface in `src/arch/mod.rs` — `critical(f)`, `request_switch()`, `in_isr()`, `init_task(k,i)`, `exit_current(c)`, `idle()`, plus a per-port `start()`, the tickless `sleep_until(deadline)`, and the user-task hooks `syscall()`/`supports_user_tasks()`. Two **real** bare-metal ports exist: `arch/cortex_m.rs` (ARMv7-M/ARMv8-M: PendSV switch, SysTick tick, MPU-confined unprivileged tasks, `svc` syscall gate) and `arch/x86_64/*` (long mode: GDT/TSS, IDT, PIT/PIC tick, paging-for-isolation, `int 0x80`/software-yield), plus `arch/host.rs` (the deterministic simulator). The crate is `#![deny(unsafe_code)]` with a per-file `#![allow(unsafe_code)]` opt-in confined to the TCB; `tests/structure.rs` already treats **any file under `src/arch/x86_64/`** as TCB by directory prefix. Boards are standalone crates: a `static BOARD: [DeviceDesc; _]` asserts hardware addresses via `unsafe { Mmio::new(..) }`, `driver::probe_all` binds drivers, and `bismuth::start(core_hz)` hands off. Both existing hardware ports are **hand-rolled on stable Rust** (no nightly, no `asm!`-only features) — the precedent this port follows.

---

## 0. TL;DR

- **This is a new architecture family, not an extension of the Cortex-M port.** Say it plainly up front: `arch/cortex_m.rs` (ARMv7-M/v8-M, an *M-profile microcontroller* with a NVIC, an MPU, a banked hardware exception frame, PendSV and SysTick) shares almost **no** register-level code with an *A-profile* core (exception levels EL0–EL3, a full MMU with translation tables, a GIC, the ARM generic timer, a 16-entry vector table and `ERET`). The "ARM" in the name is the only thing in common. The honest analog is the **x86-64 port**, not the ARM one: like x86-64, Cortex-A gives us an MMU (not an MPU), ring-like privilege (EL0/EL1 ≈ ring 3/0), a real interrupt controller to program, and a timer to calibrate. **The x86-64 port is the template; `cortex_m.rs` is only a reference for the shapes (critical-section nesting, the init-frame trick, the fault-kills-the-domain rule).**
- **The port is still additive. The portable kernel does not change.** Everything above the `src/arch/mod.rs` seam is reused verbatim: the O(1) scheduler, all sync primitives, the whole driver/middleware model and every device class, security domains + handles + rights, the keystore/entropy services, the net stack, and the POSIX/FreeRTOS/`embedded-hal` personalities. What is new is one `arch/aarch64/` module tree (TCB), three small board drivers (GIC + generic timer, plus the **already-written PL011** reused unchanged), and a handful of board crates and config knobs.
- **A huge free win: the PL011 serial driver already exists and is already AArch64-ready.** `src/driver/char/pl011.rs` declares `compatible: &["arm,pl011"]`, is 100% safe over `Mmio`, and is the exact UART on QEMU `virt`, on every Pi's UART0, and on the Jetson debug console. Stage-1 serial on a new board is **a `DeviceDesc` with the right base address and nothing else** — no new driver code.
- **Map the six-function contract onto EL1/EL0 + the generic timer + the GIC.** `critical()` masks IRQ via `PSTATE.DAIF`; the context switch runs at `ERET` from the generic-timer IRQ (preemptive) and from a self-targeted **SGI** (the PendSV analog — a software interrupt that `DAIF` masking naturally defers); `init_task` lays out a saved-GPR + `ELR_EL1`/`SPSR_EL1`/`SP_EL0` frame the first `ERET` "returns" into (the direct analog of the x86 `iretq` frame and the Cortex-M fake exception frame); the syscall gate is `SVC #0` → a synchronous exception at EL1 (the direct analog of Cortex-M `svc` and x86 `int 0x80`); `idle()` is `WFI`.
- **Tickless is *better* here than on Cortex-M.** The ARM generic timer is a 64-bit up-counter with a 64-bit compare (`CNTV_CVAL_EL0`), so `sleep_until(deadline)` programs a true one-shot at an arbitrary future tick — no 24-bit SysTick reload cap, no nap-chaining. This is strictly cleaner than `cortex_m.rs::sleep_until`.
- **Isolation: mirror the x86 single-address-space model first, then per-ASID/TTBR0 as the scale-up.** AArch64 translation tables give exactly the x86 `U/S` + `NX` story: `AP[2:1]` chooses EL0-vs-EL1 access, `UXN`/`PXN` choose execute permission. The recommended first cut copies `arch/x86_64/paging.rs` almost verbatim in spirit: boot on the firmware/early tables, mark kernel supervisor-only, **open** (set the EL0-access bit on) the kernel text/rodata and the running task's own stack, and a translation fault from EL0 outside the task's stack kills the domain. Per-domain `TTBR0_EL1` address spaces (tagged by ASID) are the documented scale-up, matching the security doc's ambition.
- **No heap, with an MMU — exactly as the x86 doc solved it.** A fixed-capacity static frame allocator over the board's usable RAM window and a **static pool of 4 KiB-aligned translation tables**. Paging is used for isolation, not allocation.
- **Hand-roll on stable, like both existing ports.** There is no `bootloader`-crate equivalent that hands us a running AArch64 EL1 with page tables; and the good Rust A-profile crates (`aarch64-cpu`, `arm-gic`, `tock-registers`) are thinner and less load-bearing than the x86 ecosystem. So this port is **more hand-written assembly than x86-64** (vector table, EL2→EL1 drop, MMU enable, context switch, SVC entry) — but it is the *same kind* of hand-rolling the shipping `arch/x86_64/{gdt,idt,paging,sw}.rs` already does on stable, and the `rust-raspberrypi-OS-tutorials` project proves every step (UART → timer → exceptions → MMU → EL0) is reachable in stable Rust on exactly these boards.[^rpitut]
- **The TCB grows, and SMP is the elephant — flag both (§10, §12).** The new `arch/aarch64/` tree is comparable in size to `arch/x86_64/`. Separately: **every one of these boards is multi-core** (Jetson 4× A57; Pi 2/3/4/5 are quad-core) and **Bismuth is single-core today** (one `IrqCell` kernel lock, a global `ISR_DEPTH`/`FIRST_SWITCH`). The first cut boots **one core** (`-smp 1` in QEMU; secondary cores parked in PSCI/holding-pen on silicon). SMP is a large, separate effort and is called out as out-of-scope.
- **Recommended board priority:** QEMU `-M virt` (cortex-a53) → QEMU `-M raspi3b` → real Pi 4/Pi 3 → Jetson Nano → QEMU `raspi4b`/Pi 5 → (later split) 32-bit Pi 2 then Pi 1/Zero.

---

## 1. Problem statement: why application-class ARM, and what actually changes

### 1.1 Why Cortex-A, and the honest magnitude

Bismuth's charter is edge IoT on MCUs, but application-class ARM boards are the natural next rung: a Raspberry Pi or Jetson is a cheap, ubiquitous, 64-bit multicore box with an MMU, a gigabyte of RAM, and a standard peripheral set. Booting Bismuth on one turns it into a small, auditable, security-domain-enforcing kernel on hardware people already own — and (as with the x86 thin-client port) it *de-risks the architecture*: if the six-function contract survives a move from an in-order MPU MCU to a superscalar MMU-backed A-profile core with four exception levels and a GIC, the layering is proven twice over.

The magnitude, stated without flinching: **this is the biggest port Bismuth will have attempted, and it is a genuinely new CPU architecture, not a variation of the existing ARM port.** A-profile and M-profile ARM differ at nearly every level the kernel touches:

| concern | Cortex-M (existing `cortex_m.rs`) | Cortex-A (this port) |
|---|---|---|
| privilege model | Thread/Handler mode + `CONTROL.nPRIV` | 4 exception levels EL0–EL3; we use **EL1 (kernel) / EL0 (user)** |
| isolation unit | MPU (≤ 8/16 regions, power-of-two) | **MMU** with multi-level translation tables, 4 KiB pages |
| exception entry | hardware stacks an 8-word frame; vectors are function pointers in a table | a **16-entry × 128-byte vector table** at `VBAR_EL1`; software saves all state |
| return-from-exception | `BX` to `EXC_RETURN` magic value | **`ERET`** using `ELR_EL1` + `SPSR_EL1` |
| deferred switch | **PendSV** (architected, auto-tail-chained) | **no PendSV** — synthesize it (timer IRQ + self-SGI) |
| tick | **SysTick** (24-bit, integral) | **ARM generic timer** (64-bit compare, system register) |
| interrupt controller | **NVIC** (integral, memory-mapped) | **GIC** (distributor + CPU interface) — or a legacy BCM controller on old Pis |
| syscall trap | `svc #n` → `SVCall` | `SVC #n` → synchronous exception, `ESR_EL1.EC = 0x15` |
| mask-all | `cpsid i` (PRIMASK) | `msr DAIFSet, #2` (`PSTATE.I`) |
| cores | single | **multi-core** (all target boards) |

The one-sentence summary for the user: **the closest existing analog is `arch/x86_64/`, not `arch/cortex_m.rs`.** Both this port and x86-64 need a privilege-transition trap, an MMU-for-isolation model with a static frame/table allocator, an interrupt controller to program, and a timer to calibrate. The Cortex-M port contributes *patterns* (the nestable `critical()`, the fake-initial-frame trick in `init_task`, the "a user fault kills the domain, a kernel fault panics" rule) but essentially no register-level code.

### 1.2 What reuses unchanged — the six-function seam

The contract in `src/arch/mod.rs` is the entire boundary. Its AArch64 realization:

| function | AArch64 realization |
|---|---|
| `critical(f)` | read `DAIF`; `msr DAIFSet, #0b11` (mask IRQ+FIQ); run `f`; restore `DAIF` if it was unmasked (nestable) |
| `request_switch()` | set a pending flag; (final form) raise a **self-SGI** through the GIC — `DAIF` masking defers it, the PendSV analog |
| `in_isr()` | read a per-core interrupt-nesting counter (A-profile has no `IPSR`) — identical to the x86 port's `ISR_DEPTH` |
| `init_task(k,i)` | build an initial kernel-stack frame (saved GPRs + `ELR`/`SPSR`/`SP_EL0`) the first `ERET` "returns" into |
| `exit_current(c)` | `finish_current` + request switch + `WFI` loop |
| `idle()` | `WFI` |
| `sleep_until(d)` | program `CNTV_TVAL_EL0`/`CNTV_CVAL_EL0` one-shot to `d`, `WFI`, catch the tick up on wake (true tickless) |
| `start(core_hz)` | bring up vectors/MMU/GIC/generic-timer, arm the first switch, unmask, `WFI` loop |
| `syscall(n,args)` | `SVC #0` from EL0; dispatch directly when already at EL1 |
| `supports_user_tasks()` | `true` (the MMU provides EL0 isolation, as paging does on x86 and the MPU does on Cortex-M) |

Because that seam is unchanged, these are reused with **zero AArch64 code in them**: the L1 kernel (O(1) scheduler, ready bitmap, blocking/wakeup, software timers, memory pools, `IrqCell`); the `Tcb` fields the port needs (`sp`, `stack`, `kstack`, `user`, `user_entry`, `in_syscall`, `syscall`, `user_psp`/`user_exc_return` — all added generically for bare-metal ports and reusable here, reading `user_exc_return` as "saved `SPSR`/frame marker"); all L1 sync primitives; the L2 driver/middleware/registry/`probe_all` machinery and every device class; the L3 security domains/handles/rights, the syscall gate's *policy* half (`security/syscall.rs::dispatch`, architecture-independent), entropy/keystore, and the net core; and the L4 POSIX/FreeRTOS/`embedded-hal` personalities.

### 1.3 What is genuinely new

| new thing | layer | TCB? |
|---|---|---|
| `src/arch/aarch64/*` (port: vectors, EL-drop, MMU, GIC glue, generic timer, context switch, SVC entry, barriers) | L0 | **yes** |
| GIC (GICv2 / GIC-400) driver — distributor + CPU interface | L2 (or L0 glue) | the register poke is **TCB**; enable/EOI logic can be safe over `Mmio` |
| ARM generic-timer tick | L0 | **yes** (system-register access) |
| PL011 UART driver | L2 | **no — already exists, already safe, reused unchanged** |
| board crates (`qemu-virt-aarch64`, `qemu-raspi3b`, `rpi4`, `jetson-nano`) | board | the `unsafe { Mmio::new(..) }` assertions only |
| `config.rs` AArch64 knobs (frame bound, table pool, GIC/timer params, kstack sizes) | support | no |
| (later) `arch/aarch32/*` for ARMv7-A / ARMv6 | L0 | **yes** |

The hard, risky part is the `arch/aarch64/` L0 tree and its hand-written assembly; the TCB growth it represents is the central tension (§10). Everything else is small or free.

---

## 2. The AArch64 boot order, phase by phase

Bismuth's boot has three phases everywhere: **(1) reset/runtime bring-up** (reset vector → zero `.bss`, set up a stack, call the board `main`), **(2) board init** (`probe_all`, wire the console, register devices, spawn tasks, seal security), **(3) scheduler handoff** (`bismuth::start(core_hz)` → the port programs the tick and does the first switch). On AArch64 there is **no `bootloader` crate** to do phase 1 for us the way the x86 port gets long mode + page tables for free; the firmware (VideoCore on Pi, TegraBoot/CBoot/U-Boot on Jetson, or QEMU's internal loader) drops us at an entry label and we do phase 1 ourselves.

```
 ┌─ Phase 0: firmware (NOT our code) ──────────────────────────────────────────────┐
 │  Pi:   VideoCore GPU reads config.txt, loads kernelimage per arch (kernel8.img / │
 │        kernel7l.img / kernel7.img / kernel.img) to the load address, loads a     │
 │        DTB, parks secondary cores, enters the kernel (typically at EL2) with the │
 │        DTB pointer in x0.                                                         │
 │  Jetson: BootROM → TegraBoot(nvtboot, on the BPMP) → CPU-BL → ATF(EL3) → CBoot/  │
 │        U-Boot → kernel entry (EL2/EL1) with a DTB.                               │
 │  QEMU: -kernel loads our ELF/binary; -M virt enters at EL1 (or EL2 with          │
 │        virtualization=on); raspi machines mimic the Pi entry.                    │
 ├─ Phase 1: _start (new L0 TCB, hand-written asm) ────────────────────────────────┤
 │  1. read current EL; if EL2, drop to EL1 (set HCR_EL2.RW=1, SPSR_EL2=EL1h,        │
 │     ELR_EL2=1f, eret). If EL3 (rare on our targets), drop EL3->EL1.              │
 │  2. park all cores but core 0 (MPIDR_EL1 low bits != 0 -> WFE holding pen / PSCI)│
 │  3. set SP to the boot stack; zero .bss; (optionally stash the DTB ptr from x0)   │
 │  4. set VBAR_EL1 to the vector table                                             │
 │  5. set up MAIR_EL1/TCR_EL1, build/point TTBR0/TTBR1, enable the MMU+caches       │
 │     (SCTLR_EL1.M|C|I), with DSB/ISB barriers                                     │
 │  6. call into Rust (the board main)                                              │
 ├─ Phase 2: board main — same as every other board ───────────────────────────────┤
 │  probe_all(&BOARD, FACTORIES)  (PL011 at the board's base, GIC, timer)           │
 │  console::set_device(uart0); register devices; spawn tasks;                       │
 │  create security domains; security::seal()                                        │
 ├─ Phase 3: arch::aarch64::start(core_hz) ────────────────────────────────────────┤
 │  k.ensure_init(); k.started = true; init GIC + generic timer; arm first switch;   │
 │  unmask DAIF; WFI-idle loop  (first timer IRQ -> first task)                      │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

Phase 1 is the new work and is mostly assembly. Two deliberate simplifications for QEMU-first, mirroring the x86 doc's "adopt the bootloader's tables" and "hardcode QEMU addresses" pragmatism:

- **Identity-map first, refine later.** The very first MMU enable can use a single static L1 table that identity-maps RAM as Normal memory and the device window as Device-nGnRE — enough to run with caches on. The EL0-isolation refinement (open only kernel text/rodata + per-task stacks to EL0) layers on exactly as `arch/x86_64/paging.rs::open_kernel_text`/`open_user_range` do over the bootloader's tables.
- **Hardcode the board's MMIO** (GIC, timer config, UART) in the board crate's `BOARD` table and small per-board consts, instead of parsing the DTB. The firmware passes a DTB in `x0`; a minimal DTB reader is a documented later option (§9), but the board crate is the single place addresses are asserted — consistent with the existing pattern.

The "drop from EL2 to EL1" step (1) is real and load-bearing on the Pi (the default armstub enters 64-bit kernels at EL2) and on QEMU `virt` with virtualization enabled; it is a short, well-known sequence and belongs in `_start`.

---

## 3. Implementing the six port functions on AArch64

Mirroring `arch/x86_64/mod.rs` structure (which itself mirrors `cortex_m.rs`). All of this lives in `arch/aarch64/` (TCB). System-register and barrier primitives are hand-written `asm!`/`naked_asm!` on stable, exactly as the shipping x86 port hand-writes `lgdt`/`iretq`/`cli`/`sti` and as `cortex_m.rs` hand-writes `mrs`/`msr`/`wfi`.

### 3.1 `critical` — the PRIMASK / `RFLAGS.IF` analog is `PSTATE.DAIF`

```rust
#[inline(always)]
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    let daif: u64;
    // SAFETY: save DAIF and mask IRQ+FIQ; no memory operands.
    unsafe { core::arch::asm!("mrs {d}, DAIF", "msr DAIFSet, #0b11", d = out(reg) daif, options(nomem, nostack)) };
    let r = f();
    // Bit 7 (I) was clear ⇒ IRQs were enabled on entry ⇒ restore them.
    if daif & (1 << 7) == 0 {
        if SWITCH_PENDING.load(Ordering::Relaxed) && ISR_DEPTH.load(Ordering::Relaxed) == 0 {
            SWITCH_PENDING.store(false, Ordering::Relaxed);
            request_switch_now(); // raise the self-SGI (§3.2); it fires when we unmask
        }
        // SAFETY: re-enabling interrupts restores the entry state.
        unsafe { core::arch::asm!("msr DAIFClr, #0b11", options(nomem, nostack)) };
    }
    r
}
```

This is a line-for-line translation of the shipping x86 `critical()` (which does `pushfq`/`cli`/…/`int 0x81`/`sti`) and the Cortex-M one (`mrs PRIMASK`/`cpsid i`/…/`cpsie i`). As on both, a switch requested inside `f` is serviced at the outermost exit, before interrupts are re-enabled.[^armarm]

### 3.2 `request_switch` and the context-switch path — the PendSV analog

A-profile has **no PendSV** (no architected lowest-priority auto-tail-chained exception). Two mechanisms recreate it; recommend the second for the final design, the first for staging — exactly the staging the x86 doc uses.

**(a) Inline deferred switch (stage 2, pragmatic).** `request_switch()` sets an atomic flag; the tail of the outermost `critical()` and the timer IRQ perform the switch directly. This is precisely what `arch/host.rs::maybe_switch` and the current `arch/x86_64` yield path do.

```rust
pub(super) static SWITCH_PENDING: AtomicBool = AtomicBool::new(false);
pub(super) static ISR_DEPTH: AtomicUsize = AtomicUsize::new(0);
#[inline] pub fn request_switch() { SWITCH_PENDING.store(true, Ordering::Relaxed); }
```

**(b) Self-SGI reschedule (final form, the true PendSV analog).** `request_switch_now()` raises a **Software-Generated Interrupt** targeted at the current core through the GIC (`GICD_SGIR` on GICv2, or `ICC_SGI1R_EL1` on GICv3). An SGI is an ordinary IRQ, so `PSTATE.I` masking in `critical()` **defers** it until the section ends — exactly PendSV's "fires when unmasked, after other handlers" behavior. Give the SGI a low GIC priority so device IRQs preempt it. Its handler is the same context-switch stub the timer uses.

The one switch stub (save all GPRs + `ELR_EL1`/`SPSR_EL1`/`SP_EL0` below the frame, swap `SP`, restore, `ERET`), shared by the timer IRQ and the SGI — the direct analog of `arch/x86_64/sw.rs`'s `timer_isr`/`yield_isr`:

```rust
// save x0-x30, SP_EL0, ELR_EL1, SPSR_EL1 on the outgoing kernel stack; hand its
// SP to Rust, which stores it in the outgoing Tcb, schedules, applies the new
// address space, and returns the incoming Tcb's SP; restore and ERET.
extern "C" fn bismuth_switch_context(outgoing_sp: usize) -> usize {
    kernel::with(|k| {
        if !FIRST_SWITCH.swap(false, Ordering::Relaxed) {
            let cur = k.current as usize;
            k.tasks[cur].sp = outgoing_sp;
            check_stack_overflow(k, cur);          // same kill-the-domain logic as ARM/x86
        }
        let next = k.schedule();
        apply_address_space(&k.tasks[next as usize]); // reload TTBR0/ASID or open stack pages (§4)
        k.tasks[next as usize].sp
    })
}
```

Same shape as `cortex_m.rs::bismuth_switch_context` and `x86_64::sw::timer_entry`, including the overflow-kills-the-domain behavior and the per-task protection reload (MPU reprogram on ARM-M → `CR3`/page-perm update on x86 → `TTBR0`/ASID or page-perm update here).

### 3.3 `in_isr` — a nesting counter replaces `IPSR`

Identical to the x86 port: A-profile has no "am I in an interrupt" register, so the common exception prologue increments `ISR_DEPTH` and the epilogue decrements it.

```rust
#[inline] pub fn in_isr() -> bool { ISR_DEPTH.load(Ordering::Relaxed) > 0 }
```

(Single-core for now; a per-core variable keyed on `MPIDR_EL1` when SMP arrives — §12.)

### 3.4 `init_task` — the initial `ERET` frame

Mirrors both existing ports: lay out a fake frame so the first switch "returns" into the task. On AArch64 the switch restores GPRs and `ERET`s, so the initial frame is the saved-register set plus the three exception-return system-register values:

- **Kernel task (EL1):** saved `x0-x30 = 0` (with `x0 = arg`), `SP_EL0 = 0` (kernel tasks use `SP_EL1`), `SPSR_EL1 = EL1h` (use `SP_EL1`, `DAIF` clear so IRQs are on), `ELR_EL1 = task_trampoline` (which calls `kernel::task::run_entry(i)` then `exit_current(0)` — reading the index/arg from the `Tcb`, exactly as the ARM/x86 trampolines do).
- **User task (EL0):** `SPSR_EL1 = EL0t` (run at EL0 using `SP_EL0`, `DAIF` clear), `ELR_EL1 = user_entry`, `SP_EL0 = user stack top`, `x0 = arg`, and `x30 (LR) = user_task_return`. This is the exact analog of the x86 `iretq` frame `[SS|RSP|RFLAGS|CS|RIP]` and the Cortex-M "exception frame with `user_entry` as PC, `user_task_return` as LR, `EXC_RETURN` selecting unprivileged thread mode". `SPSR_EL1`'s mode field is the `U/S`-style privilege selector; `SP_EL0` is the private user stack.

Both frames are written into the task's own stack (kernel task) or its private **kernel** stack (`kstack`, user task) — the `kstack` field already exists in `Tcb` for exactly this and is allocated at `spawn_user` time. This is a faithful port of `x86_64::sw::init_task` (20 u64 slots: 15 GPRs + a 5-word `iretq` frame) with the AArch64 register set and `ERET` frame substituted.

### 3.5 `exit_current` and `idle`

```rust
pub(crate) fn exit_current(code: usize) -> ! {
    kernel::with(|k| kernel::task::finish_current(k, code)); // requests a switch
    loop { idle(); }  // the switch fires; we never return
}
pub(crate) fn idle() {
    // SAFETY: `wfi` only waits for an interrupt (interrupts enabled in the idle task).
    unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
}
```

Identical in spirit to the ARM `wfi` and x86 `hlt` versions.

### 3.6 `start`

```rust
pub(crate) fn start(core_hz: u32) -> ! {
    kernel::with(|k| { k.ensure_init(); k.started = true; });
    gic::init();                 // distributor + this core's CPU interface
    timer::init(core_hz);        // program CNTV periodic tick, route its PPI through the GIC
    arm_first_switch();
    request_switch();
    // SAFETY: vectors + GIC + timer are up; unmasking lets the first timer IRQ switch in.
    unsafe { core::arch::asm!("msr DAIFClr, #0b11", options(nomem, nostack)) };
    loop { idle(); }
}
```

Same structure as `cortex_m.rs::start` and `x86_64::mod::start`: initialize, program the tick, set `FIRST_SWITCH`, pend a switch, unmask, idle.

### 3.7 `sleep_until` — true tickless via the generic timer

This is where AArch64 beats Cortex-M. The generic timer is a **64-bit** up-counter (`CNTVCT_EL0`) with a **64-bit** compare (`CNTV_CVAL_EL0`); writing `CNTV_TVAL_EL0` sets the compare to "now + TVAL". So a one-shot at an arbitrary future deadline is two register writes — no 24-bit reload cap and no nap-chaining (the documented limitation `cortex_m.rs::sleep_until` carries). Frequency is `CNTFRQ_EL0` (Hz).[^cntv]

```rust
pub(crate) fn sleep_until(deadline: Option<u64>) {
    let now = kernel::with(|k| k.tick);
    let want = match deadline { Some(d) if d > now => d - now, Some(_) => return, None => u64::MAX };
    let clocks_per_tick = CNTFRQ / TICK_HZ;          // read once at start()
    // Program a one-shot `clocks_per_tick * want` ahead (saturate into the 64-bit compare),
    // disable the periodic compare, WFI, then read CNTVCT to learn the true elapsed ticks.
    // k.advance_to(now + elapsed) credits every timeout that came due, in order (as on ARM/x86).
}
```

On host this stays the virtual-time jump it already is; on Pi/Jetson the generic timer is always-on across a plain `WFI`, so (unlike a deep-sleep clock-off state) no external RTC is needed for the light-sleep case.

---

## 4. Memory and isolation: the MMU without a heap

### 4.1 Static frame allocator + translation-table pool (no general allocator)

The MMU and a gigabyte of DRAM do **not** buy a heap. Paging is used only for isolation, and the no-allocation invariant is kept by bounding every pool at build time — the `config.rs` style, and a direct copy of `arch/x86_64/paging.rs`'s approach:

```rust
// arch/aarch64/paging.rs (TCB). Capacities are config consts — no dynamic growth.
pub struct FrameStack { free: [u64; BISMUTH_MAX_FRAMES], len: usize } // physical frame numbers
static TT_POOL: [TableCell; BISMUTH_TT_POOL] = [...];                 // 4 KiB-aligned L1/L2/L3 tables
```

At init we walk the board's usable-RAM window (a per-board const pair, or the DTB's `/memory` node later) and push up to `BISMUTH_MAX_FRAMES` 4 KiB frames; `allocate`/`free` are O(1) stack ops. New tables for per-domain address spaces come from `TT_POOL`, returned on domain teardown. Sized for the working set (the kernel image, per-task kernel stacks, device windows), not all of RAM.

### 4.2 EL1 / EL0 and the isolation model — mirror the x86 single-AS, then scale up

The AArch64 permission bits give exactly the x86 `U/S` + `NX` story, so the recommended **first cut is `arch/x86_64/paging.rs` ported almost verbatim in spirit**: one address space, kernel supervisor-only, open only what EL0 needs.

| intent | x86-64 PTE bits | AArch64 descriptor bits |
|---|---|---|
| EL0 (user) may access | `U/S = 1` | `AP[1] = 1` (EL0 access; `AP[2]` = RO/RW) |
| EL1-only (kernel) | `U/S = 0` | `AP[1] = 0` |
| not executable | `NX = 1` | `UXN = 1` (EL0) / `PXN = 1` (EL1) |
| memory type | PAT/PCD/PWT | `AttrIndx` → `MAIR_EL1` (Normal WB vs Device-nGnRE) |

First cut (stage 3), copying `open_kernel_text`/`open_user_range`:

- the kernel (text/rodata/data, device windows) is mapped EL1-only (`AP[1]=0`), so EL0 code cannot touch it;
- the kernel's **executable** pages are opened EL0-RO-X (`AP[1]=1`, `AP[2]=1`, `UXN=0`) so an unprivileged task can run the shared kernel text and the `user::` syscall shims — the exact analog of the Cortex-M "RO-X flash" region and the x86 "open kernel text" pass;
- read-only kernel rodata the task passes to syscalls is opened EL0-RO (`AP[1]=1`, `AP[2]=1`, `UXN=1`);
- the running user task's **own stack** is opened EL0-RW-NX (`AP[1]=1`, `AP[2]=0`, `UXN=1`) at switch time and closed on the outgoing task;
- a **translation/permission fault** from EL0 outside the task's stack (a synchronous exception at EL1, `ESR_EL1.EC` = data/instruction abort from a lower EL) kills the domain — precisely as a MemManage fault does on Cortex-M and a `#PF` does on x86 (`security::kill` + `security::record_fault`, pending-kill handled after the handler).

`apply_address_space` at switch time flips the EL0-access bit on the incoming task's stack pages and clears it on the outgoing task's (a handful of descriptor writes + a TLB invalidate of those pages by VA — `TLBI VAE1`), mirroring the ARM MPU-region reprogram and the x86 page-perm flip.

The **documented scale-up** is **per-domain `TTBR0_EL1` address spaces tagged by ASID**: the kernel lives in the high half via `TTBR1_EL1` (shared, never reloaded), each domain gets its own low-half tables in `TTBR0_EL1` from `TT_POOL`, and `apply_address_space` becomes a `TTBR0_EL1` write with the domain's **ASID** (so the TLB need not be fully flushed — ASID-tagged entries coexist). This is strictly stronger isolation and matches the security doc's "per-domain address spaces" ambition; the TTBR0/TTBR1 split is the AArch64 feature that makes it *cleaner* than x86's single `CR3` (the kernel half never moves). Start single-AS; graduate deliberately.

### 4.3 The syscall gate: `SVC #0` → synchronous exception at EL1

EL0 reaches the kernel through `SVC`, the direct analog of Cortex-M `svc` and x86 `int 0x80`. The port provides `syscall()` with the same privileged-fast-path shortcut both existing ports have:

```rust
pub(crate) fn syscall(n: u32, args: [usize; 4]) -> isize {
    if current_el() == 1 && !in_isr() {
        return crate::security::syscall::dispatch(n, args); // already privileged: direct
    }
    let r: isize;
    // SAFETY: `svc #0` traps to the EL1 sync vector, which validates everything; args in
    // x0-x3, call number in x8 (the AArch64 Linux convention), result back in x0.
    unsafe {
        core::arch::asm!("svc #0",
            inlateout("x0") args[0] => r, in("x1") args[1], in("x2") args[2],
            in("x3") args[3], in("x8") n)
    };
    r
}
```

The synchronous EL1 vector entry reads `ESR_EL1` (`EC == 0x15` ⇒ SVC from AArch64; the 16-bit immediate is in `ESR_EL1.ISS`), saves the EL0 context (GPRs + `SP_EL0` + `ELR_EL1` + `SPSR_EL1`) onto the task's private kernel stack (`kstack`, published nowhere special — unlike x86's TSS `RSP0`, AArch64 has `SP_EL1` banked, so the handler simply runs on `SP_EL1` which we point at the task's kstack on each switch into a user task), calls `security::syscall::dispatch(n, args)` on that kernel stack (so it may block via the existing `block_current`/switch path), writes the result into the saved `x0`, and `ERET`s back to EL0. This is the closest structural match to the Cortex-M `SVCall` handler (which also moves the call onto the task's private kernel stack and can block) and the x86 `int 0x80` handler — and it needs **no** `EXC_RETURN` bookkeeping because `ERET` + `SPSR_EL1` carries the privilege transition for us.

A distinct immediate (e.g. `SVC #1`) can mark the "kernel trampoline returning" case if a two-step user→kernel→user handoff like `cortex_m.rs`'s `svc #1`/`svc #2` is wanted; whether that is needed depends on whether the dispatch runs on the kstack directly (simpler; recommended first) or trampolines.

### 4.4 User-pointer validation (`usermem.rs`, TCB)

The existing `usermem::validate` for `target_os = "none"` checks a user range lies inside the calling task's own stack, or is read-only below the code end. In the **single-address-space** model this is reused almost verbatim — the "own stack" check is identical (`Tcb::stack` bounds), and the code-end check is the EL0-readable window the board opens. For **per-domain `TTBR0`** later, `validate` additionally relies on the fact that an EL0-accessible mapping *is* the authorization, and on cores with **PAN** (Privileged Access Never, ARMv8.1) sets `PSTATE.PAN` so a stray EL1 access to an EL0 page faults — the direct analog of x86 SMAP/`AC`-flag discipline noted in the x86 doc. This maps onto `DomainSpec::sandboxed`/`spawn_user` unchanged; `supports_user_tasks()` returns `true`, and the power-of-two/size-aligned `UserStack*` requirement is kept (round stacks to 4 KiB for page-granular EL0 mappings).

### 4.5 MMU/cache enable sequence, barriers, and FPU/NEON policy

- **Enable sequence (in `_start`, TCB asm):** program `MAIR_EL1` (attribute indices: 0 = Normal WB, 1 = Device-nGnRE), `TCR_EL1` (4 KiB granule, 48-bit VA, TTBR0/TTBR1 split), load `TTBR0_EL1`/`TTBR1_EL1`, `ISB`, then `SCTLR_EL1 |= M|C|I` (MMU + data cache + instruction cache), `ISB`. Every table edit is followed by the right barrier: `DSB ISH` after writing descriptors, `TLBI` for the affected VAs, `DSB ISH`, `ISB` — the AArch64 memory-ordering discipline. These barriers are the subset that *must* be hand-rolled `asm!` on stable (there is no safe wrapper for `TLBI`/`DSB`/`ISB`); they are small, well-specified, and confined to `arch/aarch64/{boot,paging}.rs`.[^armarm]
- **FPU/NEON policy — recommend soft-float kernel, EL0 gets NEON.** The shipping x86 port builds the kernel **soft-float** (target `x86_64-unknown-none` disables SSE) precisely so a context switch saves only GPRs and the TCB stays small — and the x86 board crate documents dropping `crypto`/`tpm` because RustCrypto needs SIMD. AArch64 has the **same choice** and the same two targets: `aarch64-unknown-none` (NEON/FP on) vs `aarch64-unknown-none-softfloat` (off).[^rusttargets] **Recommendation: build the kernel on `aarch64-unknown-none-softfloat`** so the switch stub saves only `x0-x30` (no `q0-q31`), matching the x86 decision and keeping the switch small; give **user (EL0) tasks** NEON lazily if they need it (trap the first EL0 FP use via `CPACR_EL1.FPEN`, save/restore a per-task `q0-q31` area only for tasks that touched it — the direct analog of the Cortex-M lazy-FP `EXC_RETURN` bit-4 path and the x86 `CR0.TS`/`#NM` plan). Open question for the user: whether any in-kernel code we want on these boards (smoltcp, crypto) needs NEON in kernel context; if so, the kernel goes hardfloat and the switch grows (§12).

Caches on a plain `WFI` idle stay coherent (the generic timer and GIC are coherent with the core); the cache-maintenance-on-sleep concern only arises for deep sleep (out of scope here; see the power-management doc).

---

## 5. Interrupt and timer architecture

| concern | Cortex-M (reference) | x86-64 (reference) | AArch64 (this port) |
|---|---|---|---|
| mask-all | `cpsid i` (PRIMASK) | `cli` (`RFLAGS.IF`) | `msr DAIFSet,#0b11` (`PSTATE.I/F`) |
| controller | NVIC (integral) | 8259 PIC → Local APIC | **GIC** (GICv2/GIC-400; GICv3 on newer) — or legacy BCM on old Pis (§7) |
| per-line enable | NVIC ISER | PIC mask / IOAPIC RTE | `GICD_ISENABLER<n>` |
| system tick | SysTick | PIT → APIC timer | **ARM generic timer** (`CNTV`/`CNTP`), IRQ via a GIC PPI |
| switch trigger | PendSV | timer ISR + self-IPI | timer IRQ + **self-SGI** |
| end-of-interrupt | automatic | PIC/APIC EOI | `GICC_EOIR` write (GICv2) / `ICC_EOIR1_EL1` (GICv3) |

**The GIC (GICv2 / GIC-400).** Two blocks: the **distributor** (`GICD_*`, global — enable/priority/target/pending per interrupt) and the **CPU interface** (`GICC_*`, per-core — acknowledge via `GICC_IAR`, signal completion via `GICC_EOIR`, priority mask `GICC_PMR`). Interrupt IDs: **SGIs 0–15** (software-generated, our reschedule path), **PPIs 16–31** (per-core private — the generic timer lives here), **SPIs 32+** (shared peripherals — UART, etc.); GIC-400 supports up to 480 SPIs; priority `0xFF` disables a line.[^gicv2] Bring-up: `GICD_CTLR` enable, set `GICC_PMR = 0xFF` (accept all priorities), `GICC_CTLR` enable, then `GICD_ISENABLER` the timer PPI and the UART SPI. This is the exact role the NVIC plays integrally on Cortex-M and the PIC/APIC plays on x86; the register poke is TCB (an `Mmio` window), the enable/EOI/dispatch logic can be safe over it.

**The legacy wrinkle on old Pis (§7).** BCM2835/2836/2837 (Pi 1/2/3) do **not** present a GIC to the OS: they use a Broadcom `armctrl` interrupt controller plus a per-core "local" controller at physical `0x4000_0000` (ARM timer, four mailbox IPIs/core, PMU, cascaded GPU IRQ).[^qa7][^l1intc] **QEMU's `raspi3b` emulates exactly this — it has no GIC** (`bcm2836-armctrl-ic`), while **`raspi4b` (BCM2711) does have a GIC-400**, as do the Pi 5 (BCM2712) and the Jetson.[^sel4gic][^qemuraspi] Consequence for staging: the clean GIC path targets QEMU `-M virt` and `raspi4b`/Pi 4/Pi 5/Jetson; `raspi3b`/Pi 3 need a small *second* interrupt-controller driver for the legacy BCM controller (or we simply skip Pi 3 bare-metal interrupts and prioritize `virt` + Pi 4). Recommend: **do the GIC first (virt, Pi 4), treat the BCM legacy controller as an optional add-on**, not a blocker.

**The ARM generic timer as the tick.** `CNTFRQ_EL0` gives the fixed frequency; the EL1 virtual timer (`CNTV_CTL_EL0`/`CNTV_TVAL_EL0`/`CNTV_CVAL_EL0`) is programmed for a periodic interrupt that calls `kernel::tick()` and performs the switch — the exact SysTick role, but 64-bit and system-register-based rather than a 24-bit MMIO counter. Its interrupt is a **PPI** (per-core) routed through the GIC (or the legacy local controller on old Pis). Tickless `sleep_until` reprograms it to a one-shot (§3.7).[^cntv]

**Exceptions.** The 16-entry vector table at `VBAR_EL1` (2 KiB-aligned; 4 groups of 4 × 128-byte slots: *Current EL with SP0*, *Current EL with SPx*, *Lower EL using AArch64*, *Lower EL using AArch32*; each group has Synchronous/IRQ/FIQ/SError).[^osdevexc] We populate: the **Current-EL-SPx** group (IRQ → the switch/timer path; Sync → a kernel-fault reporter that panics, mirroring `x86_64/idt.rs::fault_report`), and the **Lower-EL-AArch64** group (Sync → the SVC gate *and* the EL0 abort-kills-the-domain path, distinguished by `ESR_EL1.EC`; IRQ → the same switch path). FIQ and SError get report-and-halt stubs initially. The "from EL0 ⇒ maybe kill the domain, from EL1 ⇒ panic" split is read from the exception's source EL in `SPSR_EL1`, the direct analog of the Cortex-M `EXC_RETURN`-from-user bit and the x86 CPL check.

---

## 6. The 32-bit variants (ARMv6 Pi 1/Zero, ARMv7-A Pi 2)

The newer Pis and the Jetson all boot AArch64, which is primary. The 32-bit models are a genuinely different architecture and should be a **documented later split**, not first-cut work. What differs:

| aspect | AArch64 (primary) | AArch32 (ARMv7-A Pi 2 / ARMv6 Pi 1·Zero) |
|---|---|---|
| privilege model | exception levels EL0/EL1 + `ERET` | processor **modes** (USR/SVC/IRQ/ABT/UND/SYS), `CPSR`, banked SP/LR per mode; no EL scheme |
| exception entry | 16-entry `VBAR_EL1` table | the classic 8-entry vector table (reset/undef/SVC/pabort/dabort/IRQ/FIQ) |
| MMU | `TTBR0/1_EL1`, `TCR`/`MAIR` system regs, 64-bit descriptors | **CP15** coprocessor (`TTBR0`, `TTBCR`, `DACR`, `SCTLR`), short/long-descriptor formats |
| syscall | `SVC #0` → sync exception | `SVC`/`SWI` → SVC mode |
| timer | generic timer (ARMv7-A Pi 2 has it; ARMv6 Pi 1 does **not**) | Pi 1/Zero: the BCM2835 **system timer** (free-running 1 MHz MMIO counter) instead |
| registers | 31× 64-bit GPRs | 16× 32-bit GPRs (smaller context frame) |
| Rust target | `aarch64-unknown-none[-softfloat]` (tier 2) | `armv7a-none-eabi[hf]` (tier 2) for Pi 2; **no built-in bare ARMv6** target for Pi 1/Zero — needs a **custom JSON target** |

**Pi 2 (ARMv7-A / Cortex-A7)** is the more tractable of the two: it has the generic timer, a GIC-less BCM controller like the Pi 3, and a supported bare target. **Pi 1 / Zero / Zero W (ARMv6 / ARM1176)** is the hardest: single-core (the one case where "Bismuth is single-core" is *free*), no generic timer (use the BCM system timer), CP15 MMU, and no built-in Rust target. Honest cost: an `arch/aarch32/` tree roughly as large as `arch/aarch64/`, shared with it only at the `src/arch/mod.rs` facade level. **Recommendation: ship AArch64 fully, document the AArch32 split, and only build Pi 2 if there is concrete demand; treat Pi 1/Zero as a research curiosity** (the custom target + CP15 + no-generic-timer combination is disproportionate effort for the oldest, slowest silicon).

---

## 7. Per-board specifics

The load-bearing table. Peripheral base addresses differ by SoC and are the single most important per-board fact — the board crate's `Mmio::new` assertions live or die on these. Pi UART0 is a **PL011** at `peripheral_base + 0x20_1000` (the already-in-tree driver); the generic-timer and GIC/legacy-controller columns drive §5.

| board | SoC | CPU / arch width | peripheral base | UART0 (PL011) | interrupt controller | timer | boot |
|---|---|---|---|---|---|---|---|
| **Pi 1 / Zero / Zero W** | BCM2835 | ARM1176JZF-S / **ARMv6** (1 core) | `0x2000_0000`[^bases] | `0x2020_1000` | BCM `armctrl` (legacy) | BCM system timer (1 MHz) | `kernel.img`, DTB from VideoCore |
| **Pi 2** | BCM2836 | Cortex-A7 / **ARMv7-A** (4) | `0x3F00_0000`[^bases] | `0x3F20_1000` | BCM `armctrl` + local intc `0x4000_0000` | generic timer | `kernel7.img` |
| **Pi 3 / Zero 2 W** | BCM2837 | Cortex-A53 / **ARMv8-A** (4) | `0x3F00_0000`[^bases] | `0x3F20_1000` | BCM `armctrl` + local intc `0x4000_0000` (**no GIC exposed**) | generic timer (PPIs via local intc) | `kernel8.img` (64-bit); `kernel7.img` (32-bit) |
| **Pi 4** | BCM2711 | Cortex-A72 / **ARMv8-A** (4) | `0xFE00_0000`[^bases] | `0xFE20_1000` | **GIC-400 (GICv2)** | generic timer (PPI via GIC) | `kernel8.img`; `kernel7l.img` (32-bit LPAE) |
| **Pi 5** | BCM2712 | Cortex-A76 / **ARMv8.2-A** (4) | BCM2712 core base; most I/O behind **RP1** over PCIe[^rp1] | debug PL011 on BCM2712 (RP1 for the rest) | **GIC-400** | generic timer | `kernel_2712.img` → `kernel8.img` fallback |
| **Jetson Nano** | Tegra X1 (T210) | Cortex-A57 / **ARMv8-A** (4) | Tegra MMIO map (per TRM) | Tegra UART (16550-style) / debug | **GIC-400 (GICv2)** | generic timer | BootROM → TegraBoot → CBoot/U-Boot → kernel |

Notes that matter for bring-up:

- **Pi boot protocol.** The VideoCore GPU (not the ARM) is the primary boot processor: it reads `config.txt` from the FAT boot partition, picks the kernel image by name per architecture (`kernel8.img` for AArch64, `kernel7l.img`/`kernel7.img` for ARMv7-A LPAE/non-LPAE, `kernel.img` for ARMv6), loads a DTB, and enters the ARM with the **DTB pointer in `x0`**. `config.txt` knobs: `arm_64bit=1` forces 64-bit and the `kernel8` default; `kernel=<name>` overrides the image name; model-filtered sections like `[pi4]` scope settings.[^piboot] Our board binary is produced as the appropriate `kernelN.img` (a flat binary via `objcopy`, load address per the DTB / `0x8000` legacy / `0x80000` for 64-bit).
- **The Pi UART gotcha (document it loudly).** On Pi 3/4/5 the PL011 (UART0) is wired to the **Bluetooth** module by default, and the *mini-UART* (a 16550-ish, not a PL011) is the GPIO-header console — with a baud rate that tracks the VPU core clock unless pinned. To use the stable PL011 on the GPIO header for our console, the board's `config.txt` sets `dtoverlay=disable-bt` (or `miniuart-bt`) and `enable_uart=1`; otherwise our PL011 driver is pointed at a UART that isn't on the pins.[^piuart] On QEMU `raspi*` and `virt` this is moot (PL011 is directly available).
- **QEMU `virt` UART** is a PL011 at `0x0900_0000` with its IRQ as an SPI through the GICv2 — the cleanest possible stage-1 target.
- **Jetson** requires a DTB and boots through NVIDIA's chain (TegraBoot on the BPMP → CPU bootloader → ARM Trusted Firmware at EL3 → CBoot or U-Boot → kernel). Flashing is via **USB recovery mode** (hold RECOVERY, pulse RESET) + `flash.sh`/SDK Manager; the Nano/TX1 chip id is `0x21`.[^jetsonboot][^jetsonflash] This is the most involved deployment of the set and is prioritized *after* QEMU and Pi.

---

## 8. QEMU-first bring-up and the board crates

Mirror how the repo already QEMU-tests `lm3s6965` (semihosting PASS/FAIL) and `x86_64` (serial + `isa-debug-exit`). On AArch64, **ARM semihosting** is the PASS/FAIL channel — the same `cortex_m_semihosting`-style mechanism the lm3s board uses, via `qemu-system-aarch64 ... -semihosting-config enable=on` and the `SYS_EXIT` call.

**Which machine does what:**

| QEMU machine | emulates | stage-1 use | caveats |
|---|---|---|---|
| `-M virt -cpu cortex-a53` | a clean, DT-described AArch64 board, **GICv2** (default; GICv3 optional), PL011 @ `0x0900_0000` | **primary bring-up target** | GICv2 limits to 8 CPUs; GICv3 ITS not modeled under TCG[^qemuvirt] |
| `-M raspi3b` | BCM2837, 4× A53, 1 GiB, PL011 + mini-UART, **legacy BCM intc (no GIC)** | Pi 3 parity | needs the legacy-controller driver; PWM unimplemented[^qemuraspi] |
| `-M raspi4b` | BCM2711, 4× A72, 2 GiB, **GIC-400** | Pi 4 parity | PCIe root port + GENET Ethernet unimplemented[^qemuraspi] |
| `-M raspi2b` | BCM2836, 4× A7 (ARMv7-A) | the 32-bit split (§6) | 32-bit only |
| `-M raspi0`/`raspi1ap` | BCM2835, ARM1176 (ARMv6) | the ARMv6 split (§6) | oldest; custom Rust target |

What boots in QEMU vs needs silicon: everything in this document's scope (EL1 boot, PL011 banner, GIC + generic-timer preemption, EL0 + SVC sandbox) runs fully in QEMU `virt` and largely in `raspi3b`/`raspi4b`. Real-silicon-only concerns — the VideoCore boot handoff and the UART muxing on the Pi, the full Tegra boot chain and flashing on the Jetson, and anything multicore — are explicitly deferred.

**Board crate layout** (standalone crates, one per target, mirroring `boards/qemu-lm3s6965/` and `boards/qemu-x86_64/`):

```
boards/qemu-virt-aarch64/           # primary
  Cargo.toml          # [workspace]; bismuth-kernel { default-features=false, features=[...] }
  rust-toolchain.toml # (optional) aarch64-unknown-none-softfloat
  .cargo/config.toml  # target = "aarch64-unknown-none-softfloat";
                      #   runner = "qemu-system-aarch64 -M virt -cpu cortex-a53 -nographic \
                      #             -semihosting-config enable=on -smp 1 -kernel"
                      #   rustflags = ["-C","link-arg=-Tlink.ld"]
  link.ld             # entry _start; load at the virt kernel base; .text/.rodata/.data/.bss
  src/main.rs         # _start (asm) -> board main; static BOARD; = the demo (mirrors lm3s/x86)
boards/qemu-raspi3b/   # as above, -M raspi3b, Pi peripheral base 0x3F00_0000, legacy intc
boards/rpi4/           # real Pi 4: produce kernel8.img (objcopy), base 0xFE00_0000, GIC-400
boards/jetson-nano/    # real Jetson: DTB + flash.sh packaging, Tegra MMIO map
```

Each `BOARD` table asserts the board's MMIO exactly as the lm3s board asserts `Mmio::new(0x4000_C000, pl011::REGISTER_SPAN)` — for `virt`:

```rust
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "uart0", compatible: "arm,pl011",
    // SAFETY: QEMU virt's PL011 is at 0x0900_0000 and is used only through this window.
    mmio: Some(unsafe { Mmio::new(0x0900_0000, pl011::REGISTER_SPAN) }),
    irq: 33, // SPI 1 (= GIC ID 32+1) on virt
    params: &[("baud", 115_200)],
}];
```

The GIC and generic timer are brought up by the port in `start()` (not as `DeviceDesc` entries), with their bases from small per-board consts; a `DeviceDesc` for the GIC is an option if we want it as a registered device, but the timer/GIC are port infrastructure, not application-visible devices.

**AArch64 linker script** (new vs `memory.x`): AArch64 bare-metal uses a GNU `ld` script (`link.ld`) with an `ENTRY(_start)`, a load address (`0x4008_0000` on `virt`, `0x8_0000` for a 64-bit Pi kernel), and `.text`/`.rodata`/`.data`/`.bss` sections — the board's `build.rs` places it on the link search path exactly as the lm3s `build.rs` places `memory.x`.

**The demo (PASS/FAIL)**, mirroring the lm3s and x86 demos: the same scenario (context switch, tick preemption, priority-inversion/inheritance, a device + middleware pipeline on a `SimSensor`, and an EL0 sandboxed task that reads an allowed device and is denied an unauthorized write), ending with a semihosting `SYS_EXIT(success/failure)`. The switch/preempt/PI/sandbox portion proves the six-function contract and the EL0 SVC gate on AArch64; the PL011 console portion is free (reused driver).

---

## 9. Device-tree vs hardcoded addresses

Bismuth's board-crate model hardcodes MMIO in `static BOARD` with no DT parser and no heap, and that is the right first cut here too: every address in §7 is a compile-time constant asserted once in the board crate. The firmware *does* hand us a DTB (in `x0` on the Pi, via the Tegra/U-Boot chain on the Jetson, and as the `virt` machine's own description), which a **minimal, bounded, no-heap DTB reader** could later consult for the `/memory` size and the UART/GIC/timer base addresses — a flattened-device-tree blob is a simple big-endian structure (a header + a token stream + a string block) that can be scanned with a fixed worklist, exactly as the littlefs/FAT research scans structures without recursion, and exactly the spirit of the x86 doc's "minimal RSDP/MADT parse" option. **Recommendation: hardcode per board now (consistent with the existing pattern and with both shipping ports), and keep the DTB reader as a documented later convenience** — the board crate remains the single auditable place addresses are asserted, and a DTB reader would only *cross-check* or *fill* a couple of fields, never become a general device enumerator.

---

## 10. Safe-Rust / TCB analysis (the central tension)

### 10.1 Every place `unsafe` is needed, and why

| # | unsafe operation | where | why unavoidable |
|---|---|---|---|
| 1 | system-register read/write (`mrs`/`msr`) | `boot.rs`, `mod.rs`, `timer.rs`, `paging.rs` | `DAIF`, `VBAR_EL1`, `SCTLR_EL1`, `TTBR*`/`TCR`/`MAIR_EL1`, `CNTV_*`, `CPACR_EL1`, `CurrentEL`, `MPIDR_EL1` |
| 2 | barriers + TLB/cache maintenance | `boot.rs`, `paging.rs` | `DSB`/`ISB`/`TLBI`/`DC`/`IC` — no safe wrapper exists on stable |
| 3 | the `_start` / EL2→EL1 drop / MMU-enable asm | `boot.rs` | the one-time bring-up before Rust can run with the MMU on |
| 4 | the vector table + exception entry stubs | `vectors.rs` | `naked_asm!`, save/restore all state, `ERET` |
| 5 | context-switch asm | `sw.rs` | saving/restoring the GPR set + `ELR`/`SPSR`/`SP_EL0`, swapping `SP` |
| 6 | translation-table edits | `paging.rs` | mapping the user stack / opening EL0 access / per-domain `TTBR0` |
| 7 | the SVC entry stub | `vectors.rs`/`syscall.rs` | EL0→EL1 trap, `ESR_EL1` decode, `ERET` back |
| 8 | GIC / generic-timer MMIO + sysreg | `gic.rs`, `timer.rs` | distributor/CPU-interface pokes; the timer PPI |
| 9 | forming register/RAM windows from phys addrs | `paging.rs`, the board `Mmio::new` | the "this address really is that memory" assertions (like `Mmio::new`) |

### 10.2 The vetted-crate strategy — honestly thinner than x86

The x86 doc leans hard on vetted crates (`bootloader`, `x86_64`, `uart_16550`, `pic8259`, `pc-keyboard`, `x2apic`, `virtio-drivers`) to shrink hand-written unsafe. **The A-profile Rust ecosystem is thinner and the equivalents are less load-bearing**, so this port is *more* hand-rolled — which is fine, because both shipping Bismuth hardware ports are already hand-rolled on stable (`cortex_m.rs`'s `mrs`/`msr`/`naked_asm!` and the entire `arch/x86_64/{gdt,idt,paging,pic,sw}.rs` tree). Candidates to evaluate, used only for their *types/wrappers*, never for boot or policy:

| crate | role | assessment |
|---|---|---|
| [`aarch64-cpu`][aarch64cpu] | safe-ish typed wrappers for system registers (`DAIF`, `SCTLR_EL1`, `TTBR*`, `CNTV_*`, `VBAR_EL1`) and barriers | **evaluate; likely adopt** — shrinks items 1–2 to typed accessors, the direct analog of using `x86_64` for MSR/instruction wrappers. Widely used (it is the successor to `cortex-a`). |
| [`tock-registers`][tock] | MMIO register bitfield DSL | optional for the GIC map; our own `Mmio` already covers the need |
| [`arm-gic`][armgic] (rust-embedded) | GICv2/GICv3 driver types | **evaluate** — if mature enough, it replaces hand-rolled GIC pokes; otherwise a ~150-line hand-rolled GICv2 over `Mmio` (the `pic8259` analog) |
| — (no `bootloader` equivalent) | — | **there is none** — we write `_start` and the MMU bring-up ourselves (the biggest delta vs the x86 port) |

Net: hand-write items 3–7 and 9 (the boot/vector/switch/SVC/table asm — irreducible), delegate items 1–2 and possibly 8 to `aarch64-cpu`/`arm-gic` if they vet out. The `rust-raspberrypi-OS-tutorials` project is the existence proof that all of this is reachable in stable Rust on exactly these boards, and a per-chapter reference for each piece.[^rpitut]

### 10.3 The TCB grows — flag it

State it plainly, as the x86 doc does: the new `arch/aarch64/` tree is comparable in size and risk to `arch/x86_64/` — roughly `boot.rs` + `mod.rs` + `vectors.rs` + `sw.rs` + `paging.rs` + `gic.rs` + `timer.rs`, each TCB — and the AArch32 split (§6) would add a second tree of similar size. The right response is the x86 doc's response: make the growth *visible and reviewed*, not hidden.

### 10.4 `tests/structure.rs` treatment

The test already generalizes the TCB check with a **directory-prefix rule**: `f.path.starts_with("src/arch/x86_64/")`. The AArch64 port adds one line in the same spirit:

1. Add `|| f.path.starts_with("src/arch/aarch64/")` (and later `src/arch/aarch32/`) to the `tcb` predicate in `unsafe_is_confined_to_the_trusted_computing_base`, so every file under the new port directory must carry a `Classification: … TCB (unsafe allowed) …` line and may use `unsafe`, and nothing outside may.
2. The GIC/timer/PL011 **drivers** stay `safe` and classify `L2 devices` (PL011 already does); the assertion that `unsafe` opt-in ⇔ TCB keeps them out of the TCB automatically.
3. Add an `arch/aarch64/mod.rs` with the cfg arm in `src/arch/mod.rs` (`#[cfg(all(target_arch = "aarch64", target_os = "none"))]`), and update the `compile_error!` fallback list to include aarch64.
4. The crate stays `#![deny(unsafe_code)]`; the per-file `#![allow(unsafe_code)]` opt-in stays per-file — unchanged.

---

## 11. Proposed module layout, config, Cargo, and staged order

### 11.1 `src/` module layout (with `//! Classification` lines)

```
src/arch/
  mod.rs            # add aarch64 (later aarch32) cfg arms + port re-export; extend compile_error!
  mmio.rs           # unchanged
  cortex_m.rs       # unchanged
  x86_64/*          # unchanged
  host.rs           # unchanged
  aarch64/
    mod.rs          # //! L0 port · aarch64 port · TCB · target_arch=aarch64,target_os=none
                    #   critical/request_switch/in_isr/init_task/exit_current/idle/sleep_until/start/
                    #   syscall/supports_user_tasks + current_el()
    boot.rs         # //! L0 port · aarch64 boot/EL-drop/MMU-enable · TCB · … (_start, barriers)
    vectors.rs      # //! L0 port · aarch64 exception vectors · TCB · … (VBAR table, IRQ/Sync/SVC/abort stubs)
    sw.rs           # //! L0 port · aarch64 context switch · TCB · … (switch stub, init_task frame)
    paging.rs       # //! L0 port · aarch64 translation tables · TCB · … (FrameStack, TT pool, open EL0, TTBR0/ASID)
    gic.rs          # //! L0 port · aarch64 GIC · TCB · … (distributor + CPU interface, SGI, EOI)
    timer.rs        # //! L0 port · aarch64 generic timer · TCB · … (CNTV tick + tickless one-shot)
src/driver/char/pl011.rs   # unchanged — reused as-is (compatible "arm,pl011")
boards/qemu-virt-aarch64/  # primary board crate (see §8)
boards/qemu-raspi3b/ ; boards/rpi4/ ; boards/jetson-nano/
```

### 11.2 `src/config.rs` additions (all statically bounded)

```rust
/// Physical 4 KiB frames the static frame allocator tracks (the working set: translation
/// tables, per-task kernel stacks, device windows — not all of RAM).
pub const BISMUTH_MAX_FRAMES: usize = parse_or(option_env!("BISMUTH_MAX_FRAMES"), 4096);   // 16 MiB
/// Translation tables available for per-domain TTBR0 address spaces and device mappings.
pub const BISMUTH_TT_POOL: usize = parse_or(option_env!("BISMUTH_TT_POOL"), 32);
/// Per-task EL1 (kernel) stack for the SVC/IRQ path (the `kstack`; SP_EL1 points here).
pub const AARCH64_KSTACK_SIZE: usize = parse_or(option_env!("BISMUTH_AARCH64_KSTACK_SIZE"), 4096);
```

(`TICK_HZ` already exists and is reused as the generic-timer divisor against `CNTFRQ_EL0`. GIC/timer/UART bases live as per-board consts in the board crates, not in `config.rs`, consistent with `DeviceDesc`.)

### 11.3 `Cargo.toml` targets, feature, deps

- **Targets**: `aarch64-unknown-none-softfloat` (tier 2, built-in, soft-float kernel — recommended) and/or `aarch64-unknown-none` (NEON on). `armv7a-none-eabi[hf]` for the later Pi 2 split; a **custom JSON target** for ARMv6 Pi 1/Zero.[^rusttargets]
- **Feature**: a new `aarch64` feature gating the port module (later a shared `arm-a`/`aarch32` split if the 32-bit tree lands). Boards build with `--no-default-features --features aarch64,...` as the lm3s/x86 boards do.
- **Kernel deps (optional, gated by `aarch64`)**:

  ```toml
  [target.'cfg(all(target_arch = "aarch64", target_os = "none"))'.dependencies]
  aarch64-cpu = { version = "10", optional = true }   # pin exact; evaluate first
  # arm-gic  = { version = "...", optional = true }    # only if it vets out; else hand-rolled

  [features]
  aarch64 = ["dep:aarch64-cpu"]
  ```

- **Board deps**: none mandatory — no `cortex-m-rt`/`bootloader` equivalent; `_start` and the linker script are in the board crate. ARM semihosting for the demo exit is a ~10-line hand-rolled `HLT #0xF000` + `SYS_EXIT` (or a small `semihosting` crate), kept in the board crate exactly as `cortex-m-semihosting` is for lm3s.

### 11.4 Staged implementation order (with the test per stage)

| stage | deliverable | test |
|---|---|---|
| **1** | `_start` (EL2→EL1 drop, zero `.bss`, stack), identity-map + MMU on, `VBAR_EL1`; reuse PL011 → `kprintln!` banner on QEMU `virt` | `qemu-system-aarch64 -M virt -nographic` prints the banner |
| **2** | GIC (distributor + CPU interface), generic-timer periodic tick, context switch (`sw.rs`) + `critical`/`request_switch`/`in_isr`/`init_task`/`idle`/`start` → **scheduler + preemption** | the lm3s switch/preempt/priority-inversion scenario reaches PASS on `virt` (via semihosting `SYS_EXIT`) |
| **3** | EL0 user tasks: translation-table EL0 perms (open kernel text/rodata + per-task stack), `SVC #0` gate, `usermem` validation, EL0-abort-kills-the-domain → **sandbox** | the lm3s sandboxed-task scenario (allowed read, denied write, no fault) passes at EL0 |
| **4** | tickless `sleep_until` via the generic-timer one-shot; the self-SGI reschedule path replaces the inline stage-2 switch | tickless idle test (host parity); a long `sleep_ticks` wakes exactly on time |
| **5** | QEMU `raspi4b` (GIC-400) + real Pi 4 (`kernel8.img`, `0xFE00_0000`); the Pi UART `config.txt` guidance | boots on `raspi4b`; banner + demo on real Pi 4 over the PL011 |
| **6** | QEMU `raspi3b` + Pi 3 (legacy BCM interrupt-controller driver) | boots on `raspi3b` |
| **7** | Jetson Nano (DTB + `flash.sh` packaging, Tegra MMIO) | banner + demo on real Jetson |
| later | the AArch32 split (Pi 2, then Pi 1/Zero); **SMP** (secondary cores via PSCI + per-core state + SGI IPIs); Pi 5 / RP1 peripherals | — |

(Out of this scope throughout: networking, USB, GPU/display, deep sleep — deferred to their own efforts.)

---

## 12. Open questions, risks, documented-limitation candidates

- **SMP is the biggest unlisted cost (and these are all multicore).** Jetson Nano is 4× A57; Pi 2/3/4/5 are quad-core. Bismuth is single-core today: one `IrqCell` kernel lock, a global `ISR_DEPTH`/`FIRST_SWITCH`/`SWITCH_PENDING`, one run queue. The first cut boots **one core** (`-smp 1` in QEMU; secondaries left parked in the PSCI/holding-pen state the firmware put them in). Real SMP means: starting secondary cores (PSCI `CPU_ON` on `virt`/Jetson/ATF, or the Pi spin-table), per-core state keyed on `MPIDR_EL1`, cross-core reschedule via SGI IPIs, and either a big kernel lock or per-core run queues with migration. **This is a large, separate project; call it out explicitly and keep it out of scope.** The GIC/SGI groundwork this port lays makes it reachable later.
- **Soft-float kernel vs lazy-NEON (decide before stage 2).** Recommendation is a soft-float kernel (small switch frame, matches the x86 decision) with lazy per-task EL0 NEON. Open: does any in-kernel code we want on these boards (smoltcp, crypto) need NEON in kernel context? If so, the kernel goes hardfloat (`aarch64-unknown-none`) and the switch stub must save `q0-q31` — verify before committing the switch layout.
- **Board priority — confirm with the user.** Proposed: QEMU `virt` → QEMU `raspi3b` → real Pi 4 / Pi 3 → Jetson Nano → `raspi4b`/Pi 5 → 32-bit split. Which physical boards does the user actually have and want first? (QEMU `virt` is the only no-hardware path to a full green demo.)
- **GIC generation.** GICv2/GIC-400 on Pi 4/5 and Jetson and QEMU `virt` (default); GICv3 is the option on `virt` and on newer silicon. First cut targets **GICv2** (simpler, MMIO CPU interface); GICv3 (system-register CPU interface, `ICC_*_EL1`) is a documented follow-on. Pi 3/`raspi3b` have **no GIC at all** (legacy BCM controller) — a separate small driver, deprioritized.
- **The EL2→EL1 drop and entry-EL variance.** The Pi armstub enters 64-bit kernels at EL2; QEMU `virt` enters at EL1 (or EL2 with `virtualization=on`); Jetson hands off through ATF. `_start` must read `CurrentEL` and drop to EL1 if needed — a real bring-up step, and a common source of "boots in QEMU, hangs on hardware" if the entry EL assumption is wrong.
- **Pi UART muxing on real hardware.** The PL011 is on Bluetooth by default on Pi 3/4/5; the board's `config.txt` must free it (`dtoverlay=disable-bt`, `enable_uart=1`) or the console points at the wrong UART. QEMU hides this; real hardware does not. Document it in the Pi board crates' READMEs.
- **Pi 5 / RP1 is a different shape.** On the Pi 5 most peripherals moved behind the RP1 southbridge over PCIe; only a debug PL011, the system timer, and the GIC remain directly on the BCM2712.[^rp1] A full Pi 5 port needs a PCIe + RP1 driver — out of scope; a Pi 5 "banner + timer + GIC" bring-up on the BCM2712 side is feasible, the rest is not without RP1.
- **No `bootloader`-crate equivalent.** Unlike x86-64, nothing hands us a running EL1 with page tables; `_start` + the MMU bring-up is ours. This is the single biggest effort delta versus the x86 port and the place most likely to burn time — the `rust-raspberrypi-OS-tutorials` chapters are the recommended reference to de-risk it.[^rpitut]
- **DTB reader scope creep.** Tempting to parse the DTB for addresses; resist beyond a minimal `/memory` + base-address cross-check (§9). Hardcode per board, as both shipping ports do.
- **Out of scope, say so:** networking, USB, GPU/display, deep sleep/ACPI-equivalent power states (the power-management doc already treats Cortex-A idle at the `idle()` seam), secure world / EL3 / TrustZone.

---

### References

- [Arm Architecture Reference Manual for A-profile (ARM ARM): exception model, `DAIF`, `VBAR_EL1`, `ERET`/`ELR`/`SPSR`/`ESR`, MMU/`TTBR`/`TCR`/`MAIR`/`SCTLR`, barriers][armarm]
- [Arm Generic Interrupt Controller v2 Architecture Specification + CoreLink GIC-400 TRM][gicv2]
- [Arm generic timer registers `CNTFRQ_EL0`/`CNTVCT_EL0`/`CNTV_CVAL_EL0`/`CNTV_TVAL_EL0`/`CNTV_CTL_EL0`][cntv]
- [OSDev Wiki: AArch64 Exceptions (vector table layout: 16 × 128-byte entries, 2 KiB-aligned)][osdevexc]
- [BCM2835 ARM Peripherals datasheet + BCM2711 peripherals (base addresses `0x2000_0000` / `0x3F00_0000` / `0xFE00_0000`)][bases]
- [BCM2836/2837 "QA7" quad-core doc + the `brcm,bcm2836-l1-intc` local interrupt controller at `0x4000_0000`][qa7] · [Zephyr `bcm2836-l1-intc` binding][l1intc]
- [Raspberry Pi boot/`config.txt` docs: `kernelN.img` naming, `arm_64bit`, `kernel=`, DTB handoff][piboot]
- [Raspberry Pi PL011-vs-mini-UART / Bluetooth muxing + `enable_uart` / `disable-bt`][piuart]
- [Raspberry Pi 5 / RP1 southbridge datasheet + Zephyr/Circle Pi 5 notes (GIC-400, debug PL011, RP1 over PCIe)][rp1]
- [NVIDIA Jetson Nano Boot Flow (TegraBoot → CPU-BL → ATF → CBoot/U-Boot)][jetsonboot] · [L4T flashing / recovery mode / `flash.sh`][jetsonflash]
- [QEMU `virt` machine docs (GICv2/GICv3, PL011, CPU limits)][qemuvirt] · [QEMU `raspi` machine docs (raspi0/1ap/2b/3ap/3b/4b; UARTs; unimplemented PWM/PCIe/GENET)][qemuraspi] · [seL4 note: raspi3b has no GIC (`bcm2836-armctrl-ic`), Pi 4 has GIC-400][sel4gic]
- [Rust platform support: `aarch64-unknown-none[-softfloat]`, `armv7a-none-eabi[hf]`, no bare ARMv6][rusttargets]
- [`rust-raspberrypi-OS-tutorials` (rust-embedded): stable-Rust AArch64 bring-up on Pi 3/4 — UART, timestamps, privilege level, exceptions, MMU (4 parts), peripheral IRQs, timer callbacks][rpitut]
- [`aarch64-cpu` crate (system-register + barrier wrappers)][aarch64cpu] · [`arm-gic` crate][armgic] · [`tock-registers`][tock]

[^armarm]: Arm Architecture Reference Manual for A-profile architecture — https://developer.arm.com/documentation/ddi0487/latest
[^gicv2]: Arm GICv2 Architecture Specification (IHI 0048) and CoreLink GIC-400 TRM (DDI 0471) — https://developer.arm.com/documentation/ihi0048/latest and https://developer.arm.com/documentation/ddi0471/latest ; GICv2 register offsets/ID ranges cross-checked against ARM Trusted Firmware `gic_v2.h` and Zephyr `gic-400.c`
[^cntv]: `CNTV_CVAL_EL0`/`CNTV_TVAL_EL0`/`CNTV_CTL_EL0`/`CNTFRQ_EL0` — Arm ARM system-register section; behavior cross-checked at https://df.lth.se/~getz/ARM/SysReg/AArch64-cntv_tval_el0.html and https://www.df.lth.se/~getz/ARM/SysReg/AArch64-cntv_cval_el0.html
[^osdevexc]: OSDev Wiki, AArch64 Exceptions — https://wiki.osdev.org/AArch64_Exceptions (16 entries × 128 bytes, 2 KiB-aligned table, 4 groups)
[^bases]: Peripheral base addresses: BCM2835 `0x2000_0000`, BCM2836/2837 `0x3F00_0000`, BCM2711 `0xFE00_0000` — BCM2835 ARM Peripherals (https://www.raspberrypi.com/documentation/hardware/raspberrypi/bcm2835/BCM2835-ARM-Peripherals.pdf) and BCM2711 peripherals (https://datasheets.raspberrypi.com/bcm2711/bcm2711-peripherals.pdf); cross-checked against RTEMS `raspberrypi.h` and the mipea peripheral docs
[^qa7]: BCM2836/2837 "QA7" quad-core ARM document (per-core local interrupt controller / timer / mailboxes at `0x4000_0000`) — https://datasheets.raspberrypi.com/bcm2836/bcm2836-peripherals.pdf
[^l1intc]: Zephyr `brcm,bcm2836-l1-intc` binding (local intc at `0x4000_0000`: per-core timer PPIs, 4 mailbox IPIs/core, PMU, cascaded GPU IRQ) — https://docs.zephyrproject.org/latest/build/dts/api/bindings/interrupt-controller/brcm%2Cbcm2836-l1-intc.html
[^piboot]: Raspberry Pi boot folder / kernel image naming / `config.txt` — https://www.raspberrypi.com/documentation/computers/config_txt.html and https://www.raspberrypi.com/documentation/computers/configuration.html
[^piuart]: Raspberry Pi UART (PL011 `/dev/ttyAMA0` vs mini-UART `/dev/ttyS0`, Bluetooth muxing, `enable_uart`/`dtoverlay=disable-bt`, mini-UART VPU-clock baud caveat) — https://www.raspberrypi.com/documentation/computers/configuration.html#configuring-uarts
[^rp1]: RP1 peripheral controller datasheet / Pi 5 notes — https://datasheets.raspberrypi.com/rp1/rp1-peripherals.pdf ; Zephyr Pi 5 board (GIC-400, PL011) https://docs.zephyrproject.org/boards/raspberrypi/rpi_5/doc/index.html ; Circle Pi 5 notes https://circle-rpi.readthedocs.io/en/latest/appendices/raspberry-pi-5.html
[^jetsonboot]: NVIDIA Jetson Nano Boot Flow — https://docs.nvidia.com/jetson/archives/l4t-archived/l4t-3251/Tegra%20Linux%20Driver%20Package%20Development%20Guide/bootflow_jetson_nano.html
[^jetsonflash]: NVIDIA L4T Flashing and Booting the Target Device (recovery mode, `flash.sh`, chip id `0x21`) — https://docs.nvidia.com/jetson/l4t/Tegra%20Linux%20Driver%20Package%20Development%20Guide/flashing.html
[^qemuvirt]: QEMU `virt` machine — https://www.qemu.org/docs/master/system/arm/virt.html (GICv2 default, 8-CPU cap; GICv3 optional; PL011)
[^qemuraspi]: QEMU `raspi` machines — https://www.qemu.org/docs/master/system/arm/raspi.html (raspi0/1ap/2b/3ap/3b/4b; PL011 + 16550-based AUX mini-UART; unimplemented: PWM all, PCIe + GENET on raspi4b)
[^sel4gic]: seL4 devel list: raspi3b uses `bcm2836-armctrl-ic` (no GIC); Pi 4 / BCM2711 has a GIC-400 — https://lists.sel4.systems/hyperkitty/list/devel@sel4.systems/
[^rusttargets]: Rust Platform Support — https://doc.rust-lang.org/rustc/platform-support.html (`aarch64-unknown-none`, `aarch64-unknown-none-softfloat`, `armv7a-none-eabi`, `armv7a-none-eabihf`; no built-in bare ARMv6 target)
[^rpitut]: `rust-raspberrypi-OS-tutorials` — https://github.com/rust-embedded/rust-raspberrypi-OS-tutorials (AArch64 on Pi 3/4 in Rust: GPIO/UART, timestamps, privilege level, exceptions, virtual memory ×4, peripheral IRQs, timer callbacks; QEMU + real hardware)

[armarm]: https://developer.arm.com/documentation/ddi0487/latest
[gicv2]: https://developer.arm.com/documentation/ihi0048/latest
[cntv]: https://df.lth.se/~getz/ARM/SysReg/AArch64-cntv_tval_el0.html
[osdevexc]: https://wiki.osdev.org/AArch64_Exceptions
[bases]: https://datasheets.raspberrypi.com/bcm2711/bcm2711-peripherals.pdf
[qa7]: https://datasheets.raspberrypi.com/bcm2836/bcm2836-peripherals.pdf
[l1intc]: https://docs.zephyrproject.org/latest/build/dts/api/bindings/interrupt-controller/brcm%2Cbcm2836-l1-intc.html
[piboot]: https://www.raspberrypi.com/documentation/computers/config_txt.html
[piuart]: https://www.raspberrypi.com/documentation/computers/configuration.html#configuring-uarts
[rp1]: https://datasheets.raspberrypi.com/rp1/rp1-peripherals.pdf
[jetsonboot]: https://docs.nvidia.com/jetson/archives/l4t-archived/l4t-3251/Tegra%20Linux%20Driver%20Package%20Development%20Guide/bootflow_jetson_nano.html
[jetsonflash]: https://docs.nvidia.com/jetson/l4t/Tegra%20Linux%20Driver%20Package%20Development%20Guide/flashing.html
[qemuvirt]: https://www.qemu.org/docs/master/system/arm/virt.html
[qemuraspi]: https://www.qemu.org/docs/master/system/arm/raspi.html
[sel4gic]: https://lists.sel4.systems/hyperkitty/list/devel@sel4.systems/
[rusttargets]: https://doc.rust-lang.org/rustc/platform-support.html
[rpitut]: https://github.com/rust-embedded/rust-raspberrypi-OS-tutorials
[aarch64cpu]: https://docs.rs/aarch64-cpu/
[armgic]: https://docs.rs/arm-gic/
[tock]: https://docs.rs/tock-registers/
