# Bismuth x86 Port: Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: porting Bismuth — a safe-Rust, `no_std`, no-heap RTOS — to x86 so it can run as a **thin client**. Target both widths with **x86-64 primary** and i686 (32-bit protected mode) kept as a documented later split. Boot **QEMU-first** through the rust-osdev [`bootloader`][bootloader] crate (it hands us long mode, page tables, a memory map and a linear framebuffer); UEFI/GOP on real hardware is a documented later step. Scope now = the **kernel port + PC-platform drivers only** (16550 serial, linear framebuffer, PS/2 keyboard + mouse, virtio-net, virtio-blk). The remote-desktop client app (VNC/RFB) is a separate later effort. USB HID is explicitly out.
>
> Current Bismuth baseline (read from the tree): the portable kernel talks to the CPU through exactly six functions (`src/arch/mod.rs`): `critical(f)`, `request_switch()`, `in_isr()`, `init_task(k,i)`, `exit_current(c)`, `idle()`, plus a per-port `start()` and the user-task hooks `syscall()`/`supports_user_tasks()`. Two ports exist: `arch/cortex_m.rs` (ARMv7-M/ARMv8-M: PendSV switch, SysTick tick, MPU + unprivileged ring-3-equivalent tasks, `svc` syscall gate) and `arch/host.rs` (the deterministic simulator). The crate is `#![deny(unsafe_code)]` with a **5-module TCB** (`arch/cortex_m.rs`, `arch/mmio.rs`, `kernel/cell.rs`, `kernel/stack.rs`, `kernel/usermem.rs`). Devices are `&'static dyn Driver` reached through a 3-stage `Middleware` chain; a board crate asserts hardware addresses in `static BOARD: [DeviceDesc; _]` and calls `probe_all` + `bismuth::start()`.

---

## 0. TL;DR

- **The port is additive, not invasive. The portable kernel does not change.** Everything above the six-function contract is reused verbatim: the O(1) scheduler (`kernel/mod.rs`), all sync primitives, the whole driver model and every device class (char/display/input/net/block/sensor/gpio/i2c), middleware, security domains + handles + rights, the keystore and entropy services, the net stack (smoltcp + `NetDevice`/`FrameDevice`), edge, and the POSIX/FreeRTOS/`embedded-hal` compat layers. What is genuinely new is one `arch/x86_64/` module tree, five PC drivers, one board crate, and a handful of static-sizing config knobs.
- **Honest magnitude.** In absolute terms this is the biggest port Bismuth has: Cortex-M needs the core *plus* an MPU and an SVC gate; x86-64 needs a GDT + TSS, an IDT with exception and IRQ vectors, paging, an interrupt controller (PIC → Local APIC), a timer, a context-switch path, a privilege-transition syscall gate, FPU policy, and PCI enumeration for virtio. Most of that is one-time platform bring-up, not per-feature work, and **the bootloader crate removes the hardest part** (real-mode → long-mode, initial page tables, memory map, framebuffer) from our own code.
- **Boot path: `bootloader` 0.11.17, QEMU-first.** The board is a `bootloader_api` kernel binary with `entry_point!(kernel_main, config = &CONFIG)`; a tiny builder uses `bootloader::BiosBoot`/`UefiBoot` to produce a FAT disk image, run with `qemu-system-x86_64 -drive format=raw,...`. `kernel_main(boot_info: &'static mut BootInfo)` receives the memory map, framebuffer and RSDP. BIOS boot first; UEFI image comes free from the same crate for later real hardware.
- **Lean on vetted crates to keep our *hand-written* unsafe minimal — the RustCrypto principle applied to the CPU.** Use [`x86_64`][x86_64] 0.15 for the GDT/IDT/TSS/paging *types* and instruction wrappers, [`uart_16550`][uart] 0.7, [`pic8259`][pic] 0.11, [`pc-keyboard`][pckbd] 0.8 (pure, zero-hardware-unsafe scancode decoding), [`x2apic`][x2apic] for the Local APIC/timer, and [`virtio-drivers`][virtio] 0.13 for virtio-net/blk ring management. Our own `unsafe` is then confined to a small set: the context-switch assembly, the trap/syscall entry stubs, a `PortIo` register-window type (the I/O-port analog of `Mmio`), the page-table edits, and a `virtio_drivers::Hal` implementation.
- **The TCB grows — flag this to the user explicitly (§9).** The ARM port is ~5 TCB files with a few hundred lines of asm. The x86-64 port is ~8 TCB files covering GDT/IDT/TSS/paging/syscall/context/port-I/O, and it adds trust in several crates' *internal* unsafe. The design keeps our audit surface bounded, but the TCB is materially larger than on the MCU ports, and `tests/structure.rs` must be updated to make that growth visible and reviewed.
- **Memory with an MMU but still no heap.** The frame allocator is a **fixed-capacity** static (a bounded free-stack of frame numbers over the bootloader's usable regions); page tables come from a **static pool** of 4 KiB-aligned `PageTable`s. Paging is used for *isolation*, not for dynamic allocation. First cut: one address space with per-page User/Supervisor + NX bits mirroring the MPU model (a user task reaches only its own stack; a page fault kills the domain exactly as a MemManage fault does). Per-domain `CR3` address spaces are the documented scale-up.
- **Syscall gate: `int 0x80` first, `SYSCALL`/`SYSRET` as the optimization.** A trap gate lets the CPU switch to the kernel stack from the TSS automatically, which mirrors the `svc` model most closely and is the simplest correct first cut. `SYSCALL`/`SYSRET` (EFER.SCE + STAR/LSTAR/SFMASK, manual stack switch, `swapgs`) is faster but trickier and comes second.
- **Context switch: the timer-ISR + deferred-reschedule model.** x86-64 has no PendSV. Preemption switches inside the APIC-timer ISR; voluntary switches go through a single `context_switch` routine called at the tail of the outermost `critical()` when a switch is pending — exactly the structure `arch/host.rs` already uses (`maybe_switch`). The clean final form raises a **self-IPI to a dedicated reschedule vector** (maskable by `IF`, so `critical()` defers it — a near-exact PendSV analog). Kernel code is built **soft-float / no-SSE**, so a switch saves only GPRs; FPU for user tasks is lazy (`CR0.TS` + `#NM`) and deferred.
- **Tick: Local APIC timer is the target; the legacy PIT is the bootstrap.** Start with PIT channel 0 + a remapped-and-masked 8259 PIC for the fastest bring-up (it is the directest SysTick analog and works in QEMU), then migrate to the Local APIC timer (periodic or TSC-deadline), which is also what UEFI and any future SMP require.
- **Drivers map 1:1 onto existing Bismuth traits, and stay 100% safe over the port.** 16550 → `DeviceClass::Char`/`Serial`; linear framebuffer from `BootInfo` → `DeviceClass::Display` (present a 32-bpp GOP/VESA buffer through the existing `Display`/`PixelFormat` API); PS/2 8042 keyboard+mouse → `DeviceClass::Input` evdev events; virtio-net → `NetDevice`/`FrameDevice`; virtio-blk → the `Block` class the filesystem research is defining. A minimal PCI config-space scan finds the virtio functions.

---

## 1. Problem statement: why x86, and what actually changes

### 1.1 Why x86 (thin clients)

Bismuth's charter is edge IoT on MCUs, but a *thin client* is a different and attractive target: a cheap x86-64 box (or a repurposed PC, or a QEMU VM) that boots straight into Bismuth, draws a remote desktop onto a framebuffer, takes keyboard/mouse input, and talks to a server over the network — with no general-purpose OS underneath, a tiny attack surface, and the same security-domain model Bismuth already enforces on MCUs. The hardware a thin client needs is exactly the five drivers in scope: a serial console for bring-up, a linear framebuffer for the display, PS/2 (or later USB) HID for input, virtio-net for the wire, and virtio-blk for local state/caching. The remote-desktop protocol itself (VNC/RFB) is a later user-space effort layered on sockets + the display + input classes; this document stops at the kernel and its PC drivers.

The port also *de-risks the architecture*: if the six-function contract and the whole stack above it survive a move from a 32-bit in-order MCU with an MPU to a 64-bit superscalar CPU with an MMU, four privilege rings and PCI, that is strong evidence the layering is right.

### 1.2 What reuses unchanged

Everything above `arch`. The contract in `src/arch/mod.rs` is the entire seam:

| function | x86-64 realisation |
|---|---|
| `critical(f)` | save `RFLAGS.IF`, `cli`; run `f`; `sti` if it was set (nestable) |
| `request_switch()` | set a pending flag; (final form) raise a self-IPI to the reschedule vector |
| `in_isr()` | read a per-CPU interrupt-nesting counter (x86 has no `IPSR`) |
| `init_task(k,i)` | build an initial kernel-stack frame the first switch "returns" into |
| `exit_current(c)` | `finish_current` + request switch + `hlt` loop |
| `idle()` | `hlt` |
| `start(core_hz)` | bring up GDT/IDT/TSS/paging/PIC/APIC/timer, first switch, `sti`, `hlt` loop |
| `syscall(n,args)` | `int 0x80` (later `syscall`) from ring 3; dispatch directly when already privileged |
| `supports_user_tasks()` | `true` (paging gives ring-3 isolation, as the MPU does on ARM) |

Because that seam is unchanged, the following are **reused verbatim** (no x86 code in them at all):

- **L1 kernel**: the fixed-priority O(1) scheduler and ready bitmap, blocking/wakeup, software timers, memory pools, `IrqCell`. `Tcb` already carries every field the x86 port needs (`sp`, `stack`, `kstack`, `user`, `user_entry`, `in_syscall`, `syscall`, `user_psp`/`user_exc_return`) — these were added generically for "bare-metal ports", and x86-64 reuses them (reading `user_exc_return` as "saved user `RFLAGS`/frame marker", for instance).
- **L1 sync**: mutex (with priority inheritance), semaphore, condvar, queue, event flags, notifications.
- **L2 devices**: the `Driver`/`Middleware`/`Request`/`Op` model, the registry, `probe_all`, and **every device class** including `Display`, `Input`, `Net` and the upcoming `Block`.
- **L3 services**: security domains, handle tables, rights, the syscall gate's *policy* half (`security/syscall.rs::dispatch` — architecture-independent), entropy + keystore (RustCrypto), the net core + smoltcp.
- **L4 personalities**: `user` (the syscall client), POSIX, FreeRTOS, `embedded-hal`/`embedded-io`.
- **Support**: `config`, `Error`, the host simulator.

### 1.3 What is genuinely new

| new thing | layer | TCB? |
|---|---|---|
| `src/arch/x86_64/*` (port: GDT/IDT/TSS, paging, interrupts, context switch, syscall entry, port I/O) | L0 | **yes** |
| `arch/x86_64/port_io.rs` (`PortIo`, the I/O-port analog of `Mmio`) | L0 | **yes** |
| 16550 UART driver | L2 | no (safe) |
| linear-framebuffer display driver | L2 | no (safe) |
| PS/2 (8042) keyboard + mouse driver | L2 | no (safe) |
| virtio-net driver + a `virtio_drivers::Hal` impl | L2/L3 | the `Hal` impl is **yes**; the driver is safe |
| virtio-blk driver | L2 | no (safe) |
| minimal PCI config-space scan | L2 | the config-space accessor is **yes** (port I/O); the scan is safe |
| `boards/qemu-x86_64/` board crate | board | the `unsafe` `DeviceDesc`/`PortIo::new` assertions only |
| `config.rs` x86 knobs (frame-allocator bound, page-table pool, IRQ vectors, kstack sizes) | support | no |

The magnitude, stated honestly: the *portable* kernel is untouched; the *new* code is one platform-bring-up module (large, one-time, mostly `x86_64`-crate glue), five drivers (small, safe), and a board crate. The hard, risky part is the ~8-file L0 module and its hand-written `unsafe`, and the TCB growth it represents (§9).

---

## 2. The x86-64 boot order, phase by phase

Bismuth's existing boot has three phases: **(1) reset/runtime bring-up** (the chip's reset vector → a runtime like `cortex-m-rt` zeroes `.bss`, copies `.data`, and calls the board `main`), **(2) board init** (`probe_all`, wire the console, register devices, spawn tasks, create + `seal()` security), and **(3) scheduler handoff** (`bismuth::start(core_hz)` → the port programs the tick and does the first switch). The x86-64 boot maps onto the same three phases; the bootloader crate performs most of phase 1 for us.

```
 ┌─ Phase 1a: firmware + bootloader (NOT our code) ───────────────────────────────┐
 │  BIOS/UEFI → bootloader 0.11: enters long mode, builds initial page tables,     │
 │  maps the kernel, (optionally) maps all physical RAM at physical_memory_offset, │
 │  sets up a stack and a linear framebuffer, collects the memory map + RSDP,      │
 │  jumps to our entry with a &'static mut BootInfo.                               │
 ├─ Phase 1b: kernel_main(boot_info) — early platform init (new L0 TCB) ───────────┤
 │  1. take the serial port (0x3F8) → kprintln works immediately (bring-up)        │
 │  2. install GDT + TSS (kernel/user code+data, RSP0, IST1 for #DF)               │
 │  3. install IDT (exceptions 0–31, IRQ vectors 32+, int 0x80, reschedule vec)    │
 │  4. frame allocator over boot_info.memory_regions; adopt the bootloader's       │
 │     page tables via physical_memory_offset (OffsetPageTable)                    │
 │  5. remap + mask the 8259 PIC; (bootstrap) program PIT ch0 for TICK_HZ          │
 │     (production) init Local APIC + APIC timer; enable NX (EFER.NXE), WP (CR0.WP) │
 ├─ Phase 2: board main — same as lm3s6965 ───────────────────────────────────────┤
 │  translate BootInfo → DeviceDescs (framebuffer window, serial, PS/2, PCI/virtio)│
 │  probe_all(&BOARD, FACTORIES); console::set_device(serial)                      │
 │  register framebuffer/input/net/blk devices; spawn tasks;                       │
 │  create security domains; security::seal()                                      │
 ├─ Phase 3: arch::x86_64::start(tick_hz) ────────────────────────────────────────┤
 │  k.ensure_init(); k.started = true; set FIRST_SWITCH;                            │
 │  request_switch(); sti; hlt-idle loop  (first timer tick → first task)          │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

Phase 1b is the new work. Note two deliberate simplifications for QEMU-first: we **adopt** the bootloader's page tables (via `OffsetPageTable` over `physical_memory_offset`) rather than building our own from scratch, and we can **hardcode QEMU's APIC/IOAPIC addresses** (or do a minimal RSDP/MADT parse from `boot_info.rsdp_addr`) instead of a full ACPI implementation. Real-hardware ACPI parsing is a later step.

The kernel entry, concretely ([`bootloader_api`][bootloader-api] 0.11.17):

```rust
// boards/qemu-x86_64/src/main.rs  (board crate, not the kernel lib)
#![no_std]
#![no_main]
use bootloader_api::{entry_point, BootInfo, BootloaderConfig, config::Mapping};

const CONFIG: BootloaderConfig = {
    let mut c = BootloaderConfig::new_default();
    c.mappings.physical_memory = Some(Mapping::Dynamic); // sets physical_memory_offset
    c
};
entry_point!(kernel_main, config = &CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    bismuth::arch::x86_64::early_init(boot_info); // phase 1b (TCB)
    board_main(boot_info)                          // phases 2 + 3
}
```

`BootInfo` (confirmed fields, `#[non_exhaustive]`): `memory_regions: MemoryRegions`, `framebuffer: Optional<FrameBuffer>`, `physical_memory_offset: Optional<u64>`, `rsdp_addr: Optional<u64>`, plus kernel image/stack bounds. `FrameBuffer` exposes `info() -> FrameBufferInfo { width, height, stride, bytes_per_pixel, pixel_format }` and `buffer_mut() -> &mut [u8]`; `PixelFormat` is `Rgb`/`Bgr`/`U8`/unknown. `MemoryRegions` derefs to `&[MemoryRegion { start, end, kind }]` where `kind` is `Usable`/`Bootloader`/`UnknownUefi`/… — the frame allocator consumes the `Usable` ranges.

---

## 3. Implementing the six port functions on x86-64

Mirroring `arch/cortex_m.rs` structure. All of this lives in `arch/x86_64/` (TCB). Register/instruction primitives come from the `x86_64` crate where it offers a safe wrapper, from a `naked_asm!`/`asm!` block where it does not.

### 3.1 `critical` — the PRIMASK analog is `RFLAGS.IF`

```rust
#[inline(always)]
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    use x86_64::instructions::interrupts;
    let enabled = interrupts::are_enabled();
    interrupts::disable();            // cli
    let r = f();
    if enabled { interrupts::enable(); } // sti only if we disabled it
    r
}
```

This is a direct translation of the Cortex-M `mrs PRIMASK; cpsid i; …; cpsie i` sequence. `x86_64::instructions::interrupts` wraps `cli`/`sti`, so no hand-written `unsafe` here. As on ARM, a switch requested inside `f` fires when the outermost section re-enables interrupts (§3.2).

### 3.2 `request_switch` and the context-switch path (the PendSV analog)

x86-64 has nothing like PendSV (a lowest-priority exception that auto-pends and fires when no handler is active). Two mechanisms recreate it; recommend the second for the final design, the first for staging.

**(a) Inline deferred switch (stage 2, pragmatic).** `request_switch()` sets an atomic flag. The *tail* of the outermost `critical()` checks it and, if set and we are in task context, calls `context_switch` directly — this is exactly what `arch/host.rs::maybe_switch` does today. The timer ISR performs the switch inline before `iretq`.

```rust
static SWITCH_PENDING: AtomicBool = AtomicBool::new(false);
pub fn request_switch() { SWITCH_PENDING.store(true, Ordering::Release); }
```

**(b) Self-IPI reschedule vector (final form, the true PendSV analog).** A dedicated IDT vector `RESCHED_VEC` performs the switch. `request_switch()` raises a self-IPI through the Local APIC. Because a Local APIC IPI is gated by `RFLAGS.IF`, masking interrupts in `critical()` *defers* it until the section ends — precisely PendSV's "fires when unmasked, after other handlers" behaviour. Give `RESCHED_VEC` a low priority (high vector number, low APIC priority class) so device IRQs preempt it. The handler is a naked stub that saves the GPR set, calls `bismuth_switch_context`, restores and `iretq`s.

The one switch routine (callee-saved GPRs + RSP swap), shared by both paths:

```rust
// save RBX, RBP, R12–R15 (System V callee-saved) on the outgoing stack,
// store RSP into the outgoing Tcb, load RSP from the incoming Tcb, restore, ret.
extern "C" fn bismuth_switch_context(outgoing_rsp: usize) -> usize {
    kernel::with(|k| {
        if !FIRST_SWITCH.swap(false, Ordering::Relaxed) {
            let cur = k.current as usize;
            k.tasks[cur].sp = outgoing_rsp;
            check_stack_overflow(k, cur);          // same kill-the-domain logic as ARM
        }
        let next = k.schedule();
        apply_address_space(&k.tasks[next as usize]); // reload CR3 / user-stack page perms
        k.tasks[next as usize].sp
    })
}
```

This is the same shape as `cortex_m.rs::bismuth_switch_context`, including the overflow-detection-kills-the-domain behaviour and the per-task protection reload (MPU reprogram on ARM → `CR3`/page-permission update on x86, §4).

### 3.3 `in_isr` — a nesting counter replaces `IPSR`

x86 has no "am I in an interrupt" register, so every interrupt/trap entry increments a per-CPU counter and every exit decrements it:

```rust
static ISR_DEPTH: AtomicU32 = AtomicU32::new(0);
pub fn in_isr() -> bool { ISR_DEPTH.load(Ordering::Relaxed) != 0 }
```

(Single-core for now; a per-CPU variable when SMP arrives.) The counter is bumped in the common ISR prologue and dropped in the epilogue, both in the TCB entry stubs.

### 3.4 `init_task` — the initial stack frame

Mirrors `cortex_m.rs::init_task`, which lays out a fake exception frame so the first PendSV "returns" into the task. On x86-64 the first switch is a `ret` out of `bismuth_switch_context`, so the initial frame is the callee-saved set plus a return address:

- **Kernel task**: push `[R15,R14,R13,R12,RBP,RBX] = 0` then a return address of a `task_trampoline` that calls `kernel::task::run_entry(i)` and then `exit_current(0)`. The trampoline reads the task index/arg from the `Tcb` (as the ARM trampoline does).
- **User (ring-3) task**: the switch returns into a short stub whose job is a single `iretq` into ring 3. The initial kernel-stack top is therefore an **`iretq` frame**: `[SS=user_data|3][RSP=user stack top][RFLAGS=0x202 (IF set)][CS=user_code|3][RIP=entry]`, with `RDI=arg` (System V first argument). This is the exact x86 analog of the ARM "exception frame with `user_entry` as PC and `user_task_return` as LR, EXC_RETURN selecting unprivileged thread mode". The return stub drops privilege the way `EXC_RETURN_THREAD_PSP` does.

Both frames are written into the task's own stack (kernel task) or its private **kernel** stack (`kstack`, user task) — the `kstack` field already exists in `Tcb` for exactly this and is allocated at `spawn_user` time on bare-metal targets.

### 3.5 `exit_current` and `idle`

```rust
pub(crate) fn exit_current(code: usize) -> ! {
    kernel::with(|k| kernel::task::finish_current(k, code)); // requests a switch
    loop { x86_64::instructions::hlt(); }  // the switch fires; we never return
}
pub(crate) fn idle() { x86_64::instructions::hlt(); } // the WFI analog
```

Identical in spirit to the ARM `wfi` versions.

### 3.6 `start`

```rust
pub(crate) fn start(tick_hz: u32) -> ! {
    kernel::with(|k| { k.ensure_init(); k.started = true; });
    interrupts::program_tick(tick_hz);   // PIT (bootstrap) or APIC timer (final)
    FIRST_SWITCH.store(true, Ordering::Relaxed);
    request_switch();
    x86_64::instructions::interrupts::enable(); // sti → first tick switches to the first task
    loop { x86_64::instructions::hlt(); }
}
```

Same structure as `cortex_m.rs::start`: initialise, program the tick, set `FIRST_SWITCH`, pend a switch, enable interrupts, idle. GDT/IDT/TSS/paging/PIC are already up from phase 1b.

---

## 4. Memory and isolation: paging without a heap

### 4.1 Static frame allocator (no general allocator)

The MMU and real DRAM do **not** buy us a heap. We use paging only for isolation, and we keep the no-allocation invariant by bounding every pool at build time (the `config.rs` style).

```rust
// arch/x86_64/paging.rs (TCB). Capacity is a config const — no dynamic growth.
pub struct FrameStack {
    free: [u64; BISMUTH_MAX_FRAMES], // physical frame numbers
    len: usize,
}
// implements x86_64::structures::paging::FrameAllocator<Size4KiB>:
//   allocate_frame() pops; a matching push() frees. O(1), bounded, no heap.
```

At init we walk `boot_info.memory_regions`, and for each `Usable` region push its 4 KiB frames (up to `BISMUTH_MAX_FRAMES`) onto the stack. `BISMUTH_MAX_FRAMES` is sized for the thin-client working set (framebuffer backbuffer if any, virtio DMA frames, page tables, per-task kernel stacks), not for all of RAM — a thin client does not need gigabytes mapped.

### 4.2 Page-table pool

```rust
static PT_POOL: [PageTableCell; BISMUTH_PAGE_TABLE_POOL] = [...]; // 4 KiB-aligned PageTables
```

New page tables (for per-domain address spaces, or for mapping virtio DMA / the framebuffer) come from this fixed pool, returned when a domain is torn down. We **adopt** the bootloader's existing tables through `OffsetPageTable::new(level_4_table, VirtAddr::new(physical_memory_offset))` rather than building the kernel map ourselves.

### 4.3 Ring 0 / ring 3 and the isolation model — mirror the MPU, then scale up

The ARM port confines a user task to "its own stack plus read-only flash" with the MPU and kills the domain on a fault. The directest x86 analog, and the recommended **first cut (stage 5)**, is a **single address space** in which:

- the kernel (text/rodata/data, device windows, the framebuffer) is mapped **Supervisor-only** (`U/S = 0`), so ring-3 code cannot touch it;
- the running user task's **own stack** is mapped **User** (`U/S = 1`), `NX` for data; all RAM is `NX` except kernel/user text;
- read-only user-reachable rodata (string literals the task passes to syscalls) is mapped User read-only — the exact analog of ARM's "read-only flash" region;
- a **page fault** (`#PF`) from ring 3 outside the task's stack kills the domain, precisely as a MemManage fault does on ARM (`security::kill` + `record_fault`, pending-kill handled after the handler).

`apply_address_space` at switch time sets the User bit on the incoming task's stack pages and clears it on the outgoing task's (a handful of PTE writes + a TLB flush of those pages), mirroring the ARM MPU-region reprogram in `apply_protection`. No per-domain `CR3` is needed for the thin-client scope, and `usermem.rs` stays almost unchanged (see §4.5).

The **documented scale-up** is **per-domain `CR3`**: each domain gets its own PML4 from `PT_POOL` sharing the kernel's upper-half mapping; `apply_address_space` becomes a `CR3` write; user-pointer validation walks the domain's tables. This matches the security doc's "per-domain address spaces" ambition and is strictly stronger isolation, at the cost of more page-table memory and TLB pressure. Start single-AS; graduate to per-domain `CR3` once the model is proven.

### 4.4 The syscall gate: `int 0x80` first, `SYSCALL`/`SYSRET` second

Ring 3 reaches the kernel through a trap, exactly as ARM uses `svc`. The port provides `syscall()` with the same privileged-fast-path shortcut the ARM port has:

```rust
pub(crate) fn syscall(n: u32, args: [usize; 4]) -> isize {
    if !in_ring3() && !in_isr() {
        return crate::security::syscall::dispatch(n, args); // privileged caller: direct
    }
    // ring 3: trap into the kernel (int 0x80 first cut; syscall later)
    let r: isize;
    unsafe { asm!("int 0x80",
        inlateout("rax") n as isize => r, // n in, result out
        in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3]) };
    r
}
```

**`int 0x80` (stage 5, recommended first).** A ring-3 interrupt gate: the CPU automatically loads `RSP0` from the TSS (the task's private kernel stack) and pushes `SS:RSP, RFLAGS, CS:RIP`. The handler saves the rest of the GPRs, reads `n` + args, calls `security::syscall::dispatch(n, args)` on the task's kernel stack (so it may block, using the existing `block_current`/switch path), writes the result into the saved `RAX`, restores and `iretq`s. This is the closest structural match to the ARM `SVCall` handler (which also moves the call onto the task's private kernel stack and can block), minus the EXC_RETURN bookkeeping — the CPU's `iretq` frame carries the user context for us.

**`SYSCALL`/`SYSRET` (optimization, later).** Set `EFER.SCE`, `STAR` (kernel/user selector bases), `LSTAR` (the entry RIP), `SFMASK` (RFLAGS bits to clear, notably `IF`). The entry stub must itself `swapgs` to a per-CPU data block, switch from the user stack to the kernel stack (the CPU does **not** do it), preserve `RCX` (user return RIP) and `R11` (user RFLAGS) for `SYSRET`, and `swapgs` back before returning ([SYSCALL semantics][syscall], [OSDev fast syscalls][fastsyscall]). Faster, but every one of those steps is a footgun (the well-known NMI-on-user-stack race among them), so it comes only after `int 0x80` works.

### 4.5 User-pointer validation (`usermem.rs`, TCB)

The existing `usermem::validate` for `target_os = "none"` checks that a user range lies entirely inside the calling task's own stack, or is read-only below `CODE_END`. In the **single-address-space** model this is reused almost verbatim: the "own stack" check is identical (the `Tcb::stack` bounds), and `CODE_END` becomes "the user-readable rodata window" the board maps. The confused-deputy protection is the same property (the kernel, running privileged, will not read/write kernel or another task's memory on a user's behalf). For **per-domain `CR3`** later, `validate` additionally walks the domain's page tables (or relies on the fact that a user-accessible mapping *is* the authorization) and on CPUs with SMAP uses `AC`-flag discipline so stray kernel accesses to user pages fault. This is the x86 analog of ARMv8-M's `TT`/`TTT` pointer check noted in the security doc.

This maps directly onto `DomainSpec::sandboxed` and `spawn_user`: `supports_user_tasks()` returns `true` (paging is present), and the existing power-of-two / size-aligned stack requirement for `UserStack*` is kept (it maps cleanly to page-granular User mappings — round stacks to 4 KiB).

---

## 5. The five PC drivers

Each is an ordinary Bismuth `Driver` (or `NetDevice`) implementing an **existing** class. The pattern from the lm3s6965 board holds: the board asserts the hardware window in an `unsafe` `DeviceDesc`, and the driver is 100% safe over it. The new wrinkle is **port I/O**, which needs its own TCB register-window type.

### 5.0 `PortIo` — the I/O-port analog of `Mmio`

```rust
// arch/x86_64/port_io.rs (TCB). The I/O-space twin of arch/mmio.rs::Mmio.
pub struct PortIo { base: u16, len: u16 }
impl PortIo {
    /// # Safety: base..base+len must be the I/O-port window of one device, used only here.
    pub const unsafe fn new(base: u16, len: u16) -> Self { /* assert, store */ }
    pub fn read8(&self, off: u16) -> u8  { /* in al, dx — bounds-checked off */ }
    pub fn write8(&self, off: u16, v: u8) { /* out dx, al */ }
    // read16/write16/read32/write32 likewise
}
```

Exactly like `Mmio`, *creating* a `PortIo` is the one `unsafe` point (the board asserting "0x3F8 really is COM1"), and every access afterward is safe and bounds-checked. `DeviceDesc` gains one additive optional field — `pio: Option<PortIo>` — alongside the existing `mmio: Option<Mmio>`; a legacy PC device is described with `pio: Some(...)`, a PCI/MMIO device with `mmio: Some(...)`. PCI config space (0xCF8/0xCFC) is itself a `PortIo` window owned by the PCI scanner.

### 5.1 16550 UART → `DeviceClass::Char` / `Serial`

- **Crate**: [`uart_16550`][uart] 0.7 (`SerialPort` over port I/O; `no_std`, allocation-free). Its `SerialPort::new(base)` is `unsafe` (it is another "this port is a UART" assertion), so the board constructs it in the `unsafe` `DeviceDesc`, or the driver takes a `PortIo` and drives the registers directly (THR/RBR/IER/LCR/LSR) — either keeps the driver body safe.
- **Bismuth trait**: `Serial` (`DeviceClass::Char`). Implements `handle` for `Op::Read`/`Op::Write`/`SERIAL_SET_BAUD`/`SERIAL_RX_AVAILABLE`, exactly as the PL011 driver does. The TTY line discipline middleware (`char::tty`) layers on unchanged.
- **Unsafe hidden**: port I/O (in the crate / `PortIo`).
- **Test**: host — a `pipe`/loopback test of the `Serial` API already exists; on QEMU, `-serial stdio` routes the console out, and `kprintln!` over the registered `uart0` is the first bring-up signal.
- **This is stage 1**: serial + `kprintln` before anything else, so later stages have an output channel.

### 5.2 Linear framebuffer → `DeviceClass::Display`

- **Source**: `boot_info.framebuffer` — a `&mut [u8]` plus `FrameBufferInfo { width, height, stride, bytes_per_pixel, pixel_format }`. The board turns this into a `DeviceDesc` whose "window" is the framebuffer slice (asserted once), and registers a `fbcon` display driver.
- **Bismuth trait**: `Display` (`DeviceClass::Display`). The existing API is a near-perfect fit: `DISPLAY_GET_GEOMETRY` returns `(width,height)`, `DISPLAY_GET_FORMAT` returns a `PixelFormat`, `DISPLAY_SET_COL`/`DISPLAY_SET_ROW` set the damage window, `Op::Write` streams pixels, `DISPLAY_FLUSH` is a no-op for a directly-mapped framebuffer (nothing to push). The GOP/VESA format is 32-bpp `Rgb`/`Bgr`; add a `PixelFormat::Xrgb8888`/`Bgrx8888` variant (the enum already has `Rgb565`/`Rgb888`; adding a 32-bpp little-endian variant is additive and matches what the hardware gives). `blit(rect, pixels)` writes row-by-row respecting `stride`.
- **Unsafe hidden**: forming the framebuffer slice from the physical address + length (one assertion in the board, like `Mmio`). The driver's blit/clear/scroll logic is pure safe slice writes.
- **Test**: host — `SimDisplay` already implements the full `Display` protocol into a RAM buffer and lets tests read back pixels; the fbcon driver can be tested identically. On QEMU, draw a test pattern + a text console and verify visually (or screenshot); the automated PASS/FAIL can checksum a region it drew by reading it back (the framebuffer is readable).

### 5.3 PS/2 8042 keyboard + mouse → `DeviceClass::Input`

- **Crates**: [`pc-keyboard`][pckbd] 0.8 for scancode→keycode→Unicode decoding (`ScancodeSet1`, `DecodedKey`; **pure, zero hardware `unsafe`** — a big safety win, it is just a state machine); the 8042 controller itself (data port 0x60, status/command 0x64) is driven through `PortIo`. A small `ps2` controller helper (or hand-rolled over `PortIo`) initialises the controller, enables both ports, and routes IRQ1 (keyboard) / IRQ12 (mouse).
- **Bismuth trait**: `Input` (`DeviceClass::Input`). The 8042 keyboard ISR reads a scancode, feeds `pc-keyboard`, and emits `InputEvent::new(EventKind::Key, code, value)` + a `Syn`; the mouse ISR decodes 3-/4-byte PS/2 packets into `Rel` X/Y + button `Key` events + `Syn`. These land in the same evdev-style 16-byte-event ring the `SimInput`/`Input` API already reads, so blocking reads, `available()`, timeouts and autorepeat all work through the existing machinery. The HID-usage keycode space in `input::code` is already the native keycode space `pc-keyboard` maps to.
- **Unsafe hidden**: port I/O (the controller) + enabling IRQ1/IRQ12. Decoding is safe.
- **Test**: host — `SimInput` exercises the `Input` API; the decode path (scancode bytes → `InputEvent`s) is a pure unit test with no hardware. On QEMU, PS/2 input is interactive (type in the QEMU window); the automated demo treats input as a manual/interactive check and does not gate PASS/FAIL on it (QEMU can also inject events via the monitor `sendkey` for a scripted smoke test).

### 5.4 Minimal PCI scan (for virtio)

virtio devices in QEMU are PCI functions. A full PCI subsystem is out of scope; a **minimal config-space scan** suffices:

- A `PciConfig` TCB accessor over the 0xCF8/0xCFC `PortIo` window (legacy mechanism #1 — enough for QEMU; ECAM/MMIO config is a later addition). `read32(bus, dev, func, off)` / `write32`.
- Enumerate bus 0 (QEMU puts virtio on bus 0): for each `(dev, func)`, read vendor/device ID; `virtio_drivers::transport::pci::virtio_device_type(vendor, device)` identifies virtio functions and their type (Net/Block/…). For each, read the BARs, enable bus-mastering + memory space in the command register, and hand the function to `PciTransport::new`.
- The scan *logic* is safe (it uses the `PciConfig` wrapper); only the config-space accessor is TCB (port I/O).

### 5.5 virtio-net → `NetDevice` / `FrameDevice`, and virtio-blk → `Block`

- **Crate**: [`virtio-drivers`][virtio] 0.13 (`no_std`, rcore-os). It owns the virtqueue mechanics; we provide a `virtio_drivers::Hal` implementation (TCB — it is an **`unsafe trait`**) that allocates DMA frames from our static frame allocator and translates physical↔virtual using the bootloader's `physical_memory_offset`:

  ```rust
  // arch/x86_64/virtio_hal.rs (TCB): the only new unsafe for virtio.
  unsafe impl virtio_drivers::Hal for BismuthHal {
      fn dma_alloc(pages, dir) -> (PhysAddr, NonNull<u8>) { /* pop frames; zeroed; id-map */ }
      unsafe fn dma_dealloc(...) -> i32 { /* push frames back */ }
      unsafe fn mmio_phys_to_virt(paddr, size) -> NonNull<u8> { /* + physical_memory_offset */ }
      unsafe fn share(buf, dir) -> PhysAddr { /* no IOMMU: virt→phys of a kernel buffer */ }
      unsafe fn unshare(...) {}
  }
  ```
  Because there is **no IOMMU** in the QEMU-first setup, `share`/`unshare` are just address translation (the device can DMA anywhere); this is noted as a risk in §11 and is why DMA-capable devices must stay in the kernel domain (the security doc's rule).

- **virtio-net → `NetDevice`/`FrameDevice`.** `VirtIONet` exposes `receive()`/`send()`/`mac_address()`. The simplest integration implements the existing `FrameDevice` trait (`recv(&mut [u8]) -> Option<usize>`, `send(&[u8])`, `hw_addr`) and wraps it in the existing `SoftRing<F, N>` adapter to get a `NetDevice` — the net research explicitly designed `FrameDevice` + `SoftRing` for exactly this class of "frame-at-a-time" driver. A later ring-native `NetDevice` impl can expose virtio's rings directly for zero-copy, but `FrameDevice` is the right first cut. Transport is **PCI** (`PciTransport`); virtio-MMIO is the aarch64/`-M virt` style and is noted as an alternative but not used on PC.
- **virtio-blk → `Block`.** `VirtIOBlk::read_blocks(sector, &mut buf)` / `write_blocks(sector, &buf)` map onto whatever `Block` trait the filesystem research is defining (block size, `read_block`/`write_block`/`flush`/capacity). *Coordination*: this document does not define `Block`; it commits that the virtio-blk driver will implement the FS doc's trait. The driver stays safe over the `virtio-drivers` + `Hal` boundary.
- **Unsafe hidden**: the `Hal` impl (DMA frames + address translation) and the PCI config accessor. The net/blk drivers themselves are safe.
- **Test**: host — the net stack already has a `loopback` `NetDevice` and the `FrameDevice`/`SoftRing` path is unit-tested; a virtio-blk `Block` test runs against the FS layer's in-RAM block device. On QEMU, `-netdev user,... -device virtio-net-pci,...` gives a slirp NAT the demo can ARP/ping/UDP-echo against; `-drive ...,if=none -device virtio-blk-pci,...` gives a backing file to read/write sectors.

---

## 6. Interrupt and timer architecture

| concern | ARM (reference) | x86-64 (this port) |
|---|---|---|
| mask-all | `cpsid i` (PRIMASK) | `cli` (`RFLAGS.IF`) |
| controller | NVIC (integral) | legacy **8259 PIC** (remap + mask), then **Local APIC + I/O APIC** |
| per-line enable | NVIC ISER | PIC mask bits (bootstrap) / I/O APIC redirection entries (final) |
| system tick | SysTick | **PIT ch0** (bootstrap) → **Local APIC timer** (final) |
| switch trigger | PendSV (auto-defer) | timer-ISR inline switch + reschedule vector / self-IPI |
| end-of-interrupt | automatic | PIC EOI to 0x20/0xA0 (bootstrap) / APIC EOI register (final) |

**PIC handling.** The legacy 8259s power up mapping IRQ0–15 onto vectors 8–15, which collide with CPU exceptions. Remap them to 0x20–0x2F with [`pic8259`][pic] 0.11 (`ChainedPics::new(0x20, 0x28)`), then **mask everything** and unmask only what the thin client uses: IRQ0 (PIT, if used), IRQ1 (keyboard), IRQ4 (COM1, if interrupt-driven serial), IRQ12 (mouse). The bootstrap path can run entirely on the PIC. The UEFI image **cannot** use the PIC (firmware leaves it in an incompatible state), so the Local APIC is mandatory for real hardware — another reason the APIC is the target.

**Local APIC + timer (final).** Use [`x2apic`][x2apic] (or a small hand-rolled Local APIC over the MMIO window at `0xFEE00000`, mapped through our page tables). Mask the PIC entirely, route the PS/2/serial lines through the **I/O APIC** redirection table, and drive the tick from the **Local APIC timer** in periodic mode, calibrated against the PIT (or use **TSC-deadline** mode for jitter-free ticks on modern CPUs). This is the exact role SysTick plays on ARM: a periodic interrupt calling `kernel::tick()` and, when a slice expires or a higher-priority task is ready, performing the switch. Recommend the Local APIC timer as the production tick and the PIT only as a bootstrap stepping-stone in stage 2.

**Exception vectors.** The IDT installs handlers for the architectural exceptions, at minimum `#DF` (double fault, vector 8 — on its own **IST1** stack so a kernel stack overflow still produces a clean fault, not a triple-fault reboot), `#GP` (13) and `#PF` (14, the isolation workhorse — a ring-3 fault outside the task's stack kills the domain; a ring-0 fault panics with `CR2`/error-code, mirroring the ARM `bismuth_fault` split on the EXC_RETURN "from user" bit). Device IRQs and `int 0x80` fill the rest.

---

## 7. The `boards/qemu-x86_64` board crate + image build + QEMU run

Mirror `boards/qemu-lm3s6965/`: a standalone crate with its own `[workspace]`, a `.cargo/config.toml` setting the target + a `runner`, and a dependency on `bismuth-kernel` with `default-features = false`.

```
boards/qemu-x86_64/
  Cargo.toml          # [workspace]; deps: bismuth-kernel (feature "x86"), bootloader_api
  rust-toolchain.toml # nightly + llvm-tools + x86_64-unknown-none [+ x86_64-unknown-uefi]
  .cargo/config.toml  # target = "x86_64-unknown-none"; runner = the builder+qemu script
  build.rs            # (or a builder bin) link the kernel into a BIOS+UEFI image
  src/main.rs         # entry_point!(kernel_main); = the demo (mirrors lm3s main.rs)
```

**Image build (`bootloader` 0.11).** The 0.11 crate dropped the external `bootimage` tool; image creation is in our own code. Pattern: a top-level builder with an **artifact dependency** on the kernel binary (`CARGO_BIN_FILE_...` gives its path) calls `bootloader::BiosBoot::new(kernel_path).create_disk_image(out)` (and `UefiBoot` likewise) to emit FAT-formatted bootable images. BIOS first (QEMU default, simplest); the UEFI image is produced from the same kernel for later.

**QEMU run command** (the `.cargo` runner, concretely):

```
qemu-system-x86_64 \
  -drive format=raw,file=bismuth-bios.img \
  -serial stdio \
  -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -drive id=d0,file=disk.img,format=raw,if=none -device virtio-blk-pci,drive=d0 \
  -no-reboot -no-shutdown
```

`-serial stdio` routes `kprintln!`/the console to the terminal (the semihosting analog for text). `isa-debug-exit` at port 0xF4 is the **PASS/FAIL exit channel** (the analog of `cortex_m_semihosting::debug::exit`): the demo writes a code to 0xF4 and QEMU exits with `(code<<1)|1`, which the runner maps to success/failure. `-display none` runs headless for CI; drop it to watch the framebuffer/PS/2 interactively.

> QEMU note: the user's QEMU is at `~/scoop/apps/qemu/current` (currently exercised via `qemu-system-arm`). The scoop `qemu` package ships all system binaries, so `qemu-system-x86_64` should be present in the same directory; confirm, and if the install is ARM-only, add the x86_64 system target.

**The demo (PASS/FAIL), mirroring the lm3s6965 one.** Reuse the existing scenario (context switch, tick preemption, a genuine priority-inversion test exercising priority inheritance, a device + middleware pipeline on a `SimSensor`, and a sandboxed ring-3 task that reads an allowed device and is denied an unauthorized write) and add the PC hardware:

- **switch / preempt / PI / sandbox**: identical to `boards/qemu-lm3s6965/src/main.rs` — proves the six-function contract and the ring-3 syscall gate on x86-64.
- **framebuffer**: draw a known pattern, read it back, checksum — a self-checking display test.
- **virtio-net**: bring up a UDP socket over slirp and echo a datagram (or ARP + ping the gateway); assert a round-trip.
- **virtio-blk**: write then read a sector, assert equality.
- **PS/2 input**: interactive (or `sendkey` via the monitor for a scripted smoke test); not a PASS/FAIL gate in headless CI.

`kprintln!("BISMUTH X86_64 DEMO: PASS/FAIL")` + write the code to 0xF4, exactly as the ARM demo does.

---

## 8. The i686 (32-bit) later split

Design x86-64 first, keep the split small and documented. What must be **generic** (shared `arch/x86/common.rs`): GDT/TSS *concept*, IDT *concept*, PIC/APIC setup, the frame allocator and page-table pool, the `PortIo` type, the PCI scan, and the six-function *shape*. What **differs** on i686, kept as a future `arch/x86/` + `arch/i686/` split:

| aspect | x86-64 | i686 (32-bit protected mode) |
|---|---|---|
| CPU mode | long mode (bootloader enters it) | 32-bit protected mode; a different (or custom) bootloader path |
| registers | 16 GPRs (R8–R15) | 8 GPRs — a smaller context frame in `init_task`/`context_switch` |
| paging | 4-level, NX in PTEs, all-RAM offset map | 2-level 32-bit or **PAE** (NX needs PAE); smaller address space |
| privilege transition | `iretq` frame, `int 0x80`/`SYSCALL` | `iret` frame, `int 0x80`/**`SYSENTER`** (no `SYSCALL` in 32-bit) |
| calling convention | System V (args in registers) | cdecl (args on the stack) — changes the trampoline/arg plumbing |
| target | `x86_64-unknown-none` (tier-2, built-in) | **no built-in `i686-unknown-none`** → a custom JSON target is required |

The split abstraction goes in `arch/x86/`: `common.rs` (safe-ish shared setup) + a width module (`x86_64.rs` / `i686.rs`) holding `context.rs`, the trap/syscall entry stubs, and the `init_task` frame layout. The port facade (`critical`/`request_switch`/`in_isr`/…) is identical in signature; only the width module's asm and frame layout change. This is a documented future step, not current work.

---

## 9. Safe-Rust / TCB analysis (the central tension)

### 9.1 Every place `unsafe` is needed, and why

| # | unsafe operation | where | why it is unavoidable |
|---|---|---|---|
| 1 | port I/O (`in`/`out`) | `port_io.rs`, UART, PIC, PS/2, PCI config | the only way to reach legacy/PCI-config registers |
| 2 | MSR read/write (`rdmsr`/`wrmsr`) | `interrupts.rs`, `syscall.rs` | `EFER` (NXE/SCE), `STAR`/`LSTAR`/`SFMASK`, APIC base, `GS` base |
| 3 | control registers | `early_init`, `paging.rs` | `CR0.WP`/`CR0.TS`, `CR3` (address space), `CR4` (PAE/OSFXSR) |
| 4 | descriptor-table load | `gdt.rs`, `idt.rs` | `lgdt`/`lidt`/`ltr`, `set_cs`, `load_tss` |
| 5 | page-table edits + TLB flush + `CR3` | `paging.rs` | mapping the user stack / framebuffer / DMA frames, switching AS |
| 6 | context-switch asm | `context.rs` | saving/restoring the GPR set and swapping `RSP` |
| 7 | trap/syscall entry stubs | `idt.rs`, `syscall.rs` | `naked_asm!`, `swapgs`, `iretq`/`sysretq` |
| 8 | `cli`/`sti` | `mod.rs` (`critical`) | masking interrupts (wrapped by the `x86_64` crate) |
| 9 | forming register/DMA/framebuffer slices from phys addrs | `port_io.rs`, framebuffer desc, `virtio_hal.rs` | the "this address really is that memory" assertion points (like `Mmio::new`) |
| 10 | `virtio_drivers::Hal` impl | `virtio_hal.rs` | the trait is `unsafe`; DMA alloc + phys↔virt translation |

### 9.2 The vetted-crate strategy (RustCrypto, for the CPU)

The security doc establishes the principle: *never hand-roll a primitive when a reviewed crate exists*. Applied here, the heavy, error-prone machinery is delegated to crates whose internal `unsafe` is widely exercised, and **our** hand-written `unsafe` shrinks to items 5, 6, 7, 9, 10 above (and the thin register pokes the `x86_64` crate does not wrap):

- the entire **real-mode → long-mode bring-up, initial page tables, memory map and framebuffer discovery** → the `bootloader` crate (we write *none* of it);
- GDT/IDT/TSS **types**, paging **types** (`OffsetPageTable`, `Mapper`, `FrameAllocator`, `PhysFrame`, `Page`), instruction and MSR **wrappers** → `x86_64`;
- 16550 register sequencing → `uart_16550`; 8259 remap → `pic8259`; scancode decoding → `pc-keyboard` (**no hardware unsafe at all**); Local APIC/timer → `x2apic`; virtqueue mechanics → `virtio-drivers`.

### 9.3 Per-crate trust assessment

| crate | version | maintainer | its own unsafe | assessment |
|---|---|---|---|---|
| [`bootloader`][bootloader] / `bootloader_api` | 0.11.17 | rust-osdev | extensive (it *is* the boot asm/paging) | the de-facto Rust OS bootloader; widely used; isolates all early-boot unsafe from us. **Trust: high.** |
| [`x86_64`][x86_64] | 0.15.5 | rust-osdev | yes (instruction/MSR/table wrappers) | the standard Rust x86-64 systems crate; huge ecosystem use; safe wrappers around the dangerous bits. **Trust: high.** |
| [`uart_16550`][uart] | 0.7 | rust-osdev | small (port I/O) | tiny, obvious. **Trust: high.** |
| [`pic8259`][pic] | 0.11 | Phil Oppermann | trivial (port I/O) | ~100 lines, trivially auditable. **Trust: high.** |
| [`pc-keyboard`][pckbd] | 0.8 | rust-embedded-community | **none relevant** (pure decode) | a state machine over bytes; no hardware access. **Trust: high; lowest-risk of all.** |
| [`x2apic`][x2apic] | 0.4 | community | yes (MSR/MMIO) | smaller user base and less activity than the rust-osdev crates — **assess before committing**; a hand-rolled Local APIC over our `Mmio` is a fallback. |
| [`virtio-drivers`][virtio] | 0.13 | rcore-os (Google-contributed) | yes; exposes an **`unsafe trait Hal`** we must implement | used by aarch64 Rust-in-Linux / rCore / hypervisor efforts; actively maintained. The `Hal` impl is **our** highest-risk new unsafe (DMA, no IOMMU). **Trust: medium-high; audit our `Hal`.** |

### 9.4 Flag to the user: the TCB grows

**This is the single biggest design tension and it must be stated plainly.** The MCU ports are a ~5-file TCB with a few hundred lines of ARM assembly. The x86-64 port roughly doubles the TCB file count (GDT, IDT, interrupts, context, paging, syscall, port I/O, virtio-Hal) and introduces trust in the *internal* unsafe of six external crates. Even with the vetted-crate strategy keeping our hand-written unsafe bounded (items 5–7, 9–10), the **total** trusted surface is materially larger than on Cortex-M. That is inherent to the platform — x86-64 simply requires more privileged machinery than an MPU-only MCU — and the right response is to make the growth *visible and reviewed*, not to pretend it away.

### 9.5 `tests/structure.rs` treatment

The current test hardcodes a 5-entry `TCB` list and asserts each file's `unsafe` opt-in and classification match it. Proposed changes:

1. **Add the x86 port files** to the TCB allow-list. Prefer a **directory-prefix rule** — treat any file under `src/arch/x86_64/` (and later `src/arch/x86/`) as TCB — rather than listing eight paths, so new port files cannot be silently added without a `Classification: … TCB (unsafe allowed) …` line.
2. **Keep every driver out of the TCB.** The framebuffer, PS/2, virtio-net and virtio-blk drivers must classify as `safe`; a test assertion (`unsafe` opt-in ⇔ TCB) already enforces this, and it is the property that guarantees "all driver and higher logic is 100% safe over the port".
3. **Make TCB growth reviewable.** Add a test asserting the x86 TCB file set matches an expected list (so adding a TCB file is a deliberate, diffable change), echoing the existing `assert!(files.len() > 50)` style of "the shape of the tree is itself tested".
4. The `#![allow(unsafe_code)]` opt-in stays per-file, and `src/lib.rs` keeps `#![deny(unsafe_code)]` crate-wide — unchanged.

---

## 10. Proposed module layout, config, Cargo, and staged order

### 10.1 `src/` module layout (with `//! Classification` lines)

```
src/arch/
  mod.rs            # add x86_64 (and later x86) cfg arms + port re-export
  mmio.rs           # unchanged
  cortex_m.rs       # unchanged
  host.rs           # unchanged
  x86_64/
    mod.rs          # //! L0 port · x86-64 port · TCB (unsafe allowed) · target_arch=x86_64,target_os=none
                    #   critical/request_switch/in_isr/init_task/exit_current/idle/start/syscall/
                    #   supports_user_tasks + early_init(boot_info)
    gdt.rs          # //! L0 port · x86-64 GDT/TSS · TCB · … (kernel/user segs, RSP0, IST1)
    idt.rs          # //! L0 port · x86-64 IDT · TCB · … (exceptions, IRQ vectors, int 0x80, resched)
    interrupts.rs   # //! L0 port · x86-64 interrupt controller + tick · TCB · … (PIC, APIC, timer, ISR_DEPTH)
    context.rs      # //! L0 port · x86-64 context switch · TCB · … (switch asm, init frames)
    paging.rs       # //! L0 port · x86-64 paging · TCB · … (FrameStack, PT pool, map user stack, CR3)
    syscall.rs      # //! L0 port · x86-64 syscall entry · TCB · … (int 0x80 / SYSCALL stub, swapgs)
    port_io.rs      # //! L0 port · x86-64 port I/O · TCB · … (PortIo — the I/O-space Mmio)
    virtio_hal.rs   # //! L0 port · x86-64 virtio HAL · TCB · … (virtio_drivers::Hal impl)
src/driver/
  char/uart16550.rs # //! L2 devices · driver: 16550 UART · safe · x86
  display/fbcon.rs  # //! L2 devices · driver: linear framebuffer · safe · x86
  input/ps2.rs      # //! L2 devices · driver: PS/2 8042 kbd+mouse · safe · x86
  pci.rs            # //! L2 devices · PCI config scan · safe · x86   (uses the TCB PortIo accessor)
src/net/drivers/
  virtio_net.rs     # //! L3 services · net driver: virtio-net · safe · net,x86
src/driver/block/
  virtio_blk.rs     # //! L2 devices · driver: virtio-blk · safe · x86   (impl the FS doc's Block trait)
boards/qemu-x86_64/ # the board crate (see §7)
```

### 10.2 `src/config.rs` additions (all statically bounded)

```rust
/// Physical 4 KiB frames the static frame allocator tracks (not all of RAM; the
/// thin-client working set: page tables, kernel stacks, virtio DMA, framebuffer backbuffer).
pub const BISMUTH_MAX_FRAMES: usize   = parse_or(option_env!("BISMUTH_MAX_FRAMES"), 4096);   // 16 MiB
/// Page tables available for per-domain address spaces and device mappings.
pub const BISMUTH_PAGE_TABLE_POOL: usize = parse_or(option_env!("BISMUTH_PAGE_TABLE_POOL"), 32);
/// IDT IRQ vectors the port tracks above the 32 architectural exceptions.
pub const BISMUTH_MAX_IRQS: usize     = parse_or(option_env!("BISMUTH_MAX_IRQS"), 32);
/// Per-task ring-0 (kernel) stack size for privilege transitions (the `kstack`).
pub const X86_KSTACK_SIZE: usize      = parse_or(option_env!("BISMUTH_X86_KSTACK_SIZE"), 4096);
/// Dedicated IST stack for #DF (double fault), so a kstack overflow faults cleanly.
pub const X86_IST_STACK_SIZE: usize   = parse_or(option_env!("BISMUTH_X86_IST_STACK_SIZE"), 4096);
```

(`TICK_HZ` already exists and is reused for the PIT/APIC timer divisor.)

### 10.3 `Cargo.toml` targets, feature, deps

- **Targets**: `x86_64-unknown-none` (tier-2, built-in — no JSON needed). i686 later needs a **custom `i686-unknown-none.json`** (there is no built-in bare-metal i686 target).
- **Feature**: a new `x86` feature (later split into `x86_64` / `x86-32` if the widths diverge enough) gating the port module and the PC-driver deps. The board builds the kernel with `--no-default-features --features x86[,net,crypto,…]`, as the lm3s board does with `edge`.
- **Kernel deps (optional, gated by `x86`)** — the CPU-level crates used in `arch/x86_64` (TCB) and the safe PC drivers:

  ```toml
  [target.'cfg(all(target_arch = "x86_64", target_os = "none"))'.dependencies]
  x86_64       = { version = "0.15", optional = true }
  uart_16550   = { version = "0.7", optional = true }
  pic8259      = { version = "0.11", optional = true }
  pc-keyboard  = { version = "0.8", optional = true }
  x2apic       = { version = "0.4", optional = true }  # or hand-rolled Local APIC
  virtio-drivers = { version = "0.13", optional = true, default-features = false }

  [features]
  x86 = ["dep:x86_64", "dep:uart_16550", "dep:pic8259", "dep:pc-keyboard", "dep:x2apic", "dep:virtio-drivers"]
  ```

- **Board deps**: `bootloader_api = "0.11"` (for the `BootInfo` type + `entry_point!`) and, in the builder, `bootloader = "0.11"` as a build/host dependency. These stay **in the board crate**, exactly as `cortex-m-rt`/`cortex-m-semihosting` do for the lm3s board — the kernel lib never depends on the image builder.

### 10.4 Staged implementation order (with the test per stage)

| stage | deliverable | test |
|---|---|---|
| **1** | boot via `bootloader`; `early_init` takes serial (0x3F8); `kprintln!` works | QEMU `-serial stdio` prints a banner; builder+runner produce a bootable BIOS image |
| **2** | GDT/IDT/TSS; frame allocator + adopt page tables; PIC remap+mask; PIT tick; `context.rs` + `critical`/`request_switch`/`in_isr`/`init_task`/`idle`/`start` → **scheduler running, preemption** | the lm3s switch/preempt/priority-inversion scenario reaches PASS on x86-64 (via `isa-debug-exit`) |
| **3** | linear-framebuffer `Display` driver (`fbcon`) | draw a pattern, read it back, checksum; host `SimDisplay` parity test |
| **4** | PS/2 8042 keyboard+mouse `Input` driver | host decode unit tests (scancode→`InputEvent`); QEMU `sendkey`/interactive smoke |
| **5** | ring-3 user tasks: paging User/NX perms, `int 0x80` gate, `usermem` validation, `#PF`-kills-domain → **sandbox** | the lm3s sandboxed-task scenario (allowed read, denied write, no fault) passes in ring 3 |
| **6** | minimal PCI scan; `virtio_drivers::Hal`; virtio-net via `FrameDevice`+`SoftRing` | UDP echo / ARP+ping over QEMU slirp; host loopback `NetDevice` parity |
| **7** | virtio-blk implementing the FS doc's `Block` trait; (opt.) Local APIC timer replaces PIT; (opt.) `SYSCALL`/`SYSRET` replaces `int 0x80` | sector write/read-back; FS layer mounts on the block device |

(Later, out of this scope: UEFI/GOP on real hardware, ACPI parsing, i686 split, USB HID, the VNC/RFB client app.)

---

## 11. Open questions, risks, documented-limitation candidates

- **DMA without an IOMMU (biggest risk).** virtio devices bus-master into physical RAM, and the QEMU-first setup has no IOMMU, so the `Hal::share` path cannot *confine* a device — a buggy/compromised device descriptor could DMA anywhere. Consequence (adopt the security doc's rule): DMA-capable devices (virtio-net/blk) stay in the **kernel domain**; they are never granted as raw resources to isolated domains. Document as a limitation; a later step maps virtio DMA through a bounded, dedicated region and/or uses the VT-d IOMMU.
- **Context-switch model choice.** The staged "inline switch at `critical()` tail + in the timer ISR" is simplest; the self-IPI reschedule vector is cleaner but needs the Local APIC. Decide when stage 7 lands the APIC. Risk: getting the "defer until interrupts re-enabled" semantics exactly right so a switch requested in an ISR fires at a safe point (the `in_isr`/nesting discipline must be airtight).
- **FPU/SSE policy.** Recommendation: build the kernel **soft-float / `-sse`** so switches save only GPRs and the TCB stays small; give user tasks lazy FPU (`CR0.TS` + `#NM`, an `FXSAVE`/`XSAVE` area per task) only if/when they need float. Open: whether any in-tree code (smoltcp, edge DSP) needs SSE in kernel context — if so, eager save/restore of the SSE state is required and the switch grows. Verify before stage 2.
- **ACPI / APIC discovery.** QEMU-first can hardcode the Local APIC (0xFEE00000) and I/O APIC (0xFEC00000) addresses or do a minimal RSDP→MADT parse from `boot_info.rsdp_addr`. Real hardware needs a fuller ACPI parse (the [`acpi`][acpi] crate) — a later step.
- **SMP.** Assume uniprocessor for the thin client. The Local APIC is still needed (timer, EOI). `in_isr`'s global counter and the single `IrqCell` kernel lock become per-CPU / contended under SMP — out of scope now, but the APIC groundwork makes it reachable.
- **Single address space vs per-domain `CR3`.** Stage 5 ships single-AS (MPU-analog page permissions). Per-domain `CR3` is stronger and matches the security doc's ambition but costs page-table memory from the static pool and TLB flushes on switch. Graduate deliberately.
- **`uart_16550`/`x2apic` version drift.** `uart_16550` "latest" caches to 0.6 on docs.rs while 0.7 exists; pin the exact version and verify the `SerialPort`/`MmioSerialPort` API. `x2apic` has a smaller user base — assess, or fall back to a hand-rolled Local APIC over `Mmio`.
- **Interactive-only drivers in CI.** Framebuffer output and PS/2 input are best verified with a human (or QEMU monitor `sendkey`/screenshot); the headless PASS/FAIL gate rests on switch/preempt/PI/sandbox/virtio-net/virtio-blk. Document that the visual/input paths have a manual verification step.
- **`DeviceDesc` gains `pio`.** Adding an optional `pio: Option<PortIo>` field to `DeviceDesc` (L2) is additive and small, but it is a shared struct — confirm it does not perturb the ARM board (it defaults to `None`). Alternatively drivers take a port base parameter and the board asserts it; the `pio` field is cleaner and symmetric with `mmio`.

---

### References

- [`bootloader` crate (rust-osdev), 0.11.17][bootloader] · [`bootloader_api` docs][bootloader-api]
- [`x86_64` crate (rust-osdev), 0.15.5][x86_64]
- [`uart_16550` crate (rust-osdev)][uart] · [`pic8259` crate (Phil Oppermann)][pic] · [`pc-keyboard` crate (rust-embedded-community)][pckbd] · [`x2apic` crate][x2apic]
- [`virtio-drivers` crate (rcore-os), 0.13][virtio] · [`Hal` trait (unsafe) docs][virtio-hal] · [PCI transport docs][virtio-pci]
- [`acpi` crate (rust-osdev)][acpi]
- Philipp Oppermann, *Writing an OS in Rust* (blog_os): the canonical reference for the GDT/TSS/IST, IDT + double-fault, PIC remap, and `bootloader`-based image build in Rust — [os.phil-opp.com][philopp]
- [OSDev Wiki: Fast System Calls (SYSCALL/SYSENTER)][fastsyscall] · [SYSCALL instruction reference][syscall]

[bootloader]: https://docs.rs/crate/bootloader/latest
[bootloader-api]: https://docs.rs/bootloader_api/latest/bootloader_api/
[x86_64]: https://docs.rs/x86_64/latest/x86_64/
[uart]: https://docs.rs/uart_16550/
[pic]: https://docs.rs/pic8259/
[pckbd]: https://docs.rs/pc-keyboard/
[x2apic]: https://docs.rs/x2apic/
[virtio]: https://docs.rs/virtio-drivers/latest/virtio_drivers/
[virtio-hal]: https://docs.rs/virtio-drivers/latest/virtio_drivers/trait.Hal.html
[virtio-pci]: https://docs.rs/virtio-drivers/latest/virtio_drivers/transport/pci/index.html
[acpi]: https://docs.rs/acpi/
[philopp]: https://os.phil-opp.com/
[fastsyscall]: https://wiki.osdev.org/SYSENTER
[syscall]: https://www.felixcloutier.com/x86/syscall
