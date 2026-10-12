//! AArch64 (ARMv8-A) port, for application-class ARM: QEMU `virt`, Raspberry Pi 3/4/5,
//! Jetson Nano. The third real bare-metal port; its template is the x86-64 port (an MMU for
//! isolation, EL0/EL1 ≈ ring 3/0, a real interrupt controller and timer), not the Cortex-M
//! microcontroller port — only the *shapes* (nestable `critical`, the init-frame trick, the
//! fault-kills-the-domain rule) carry over from there.
//!
//! Built in stages, mirroring how the x86-64 port grew:
//!
//! * **Stage 1 (this file's current form):** `_start` + EL2→EL1 drop + a minimal identity
//!   MMU (see [`boot`]), so a board boots to a PL011 serial banner at EL1 with caches on.
//!   `critical` masks IRQ via `DAIF`; `in_isr` is a nesting counter; `idle` is `WFI`.
//! * **Stage 2 (next):** the GIC + the ARM generic-timer tick + the context switch (saved at
//!   `ERET` from the timer IRQ and a self-SGI — the PendSV analog), after which the scheduler
//!   preempts for real.
//! * **Stage 3:** EL0 user tasks via per-page translation-table permissions + an `SVC #0`
//!   gate, with an EL0 abort killing the domain.
//!
//! Part of the trusted computing base: inline assembly and system registers.
//!
//! Classification: L0 port · aarch64 port · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::kernel::{self, Kernel};

pub mod bcm;
pub mod boot;
pub mod exceptions;
#[doc(inline)]
pub use boot::BoardMap;

pub mod gic;
pub mod intc;
pub mod paging;
pub mod sw;
pub mod timer;

/// `DAIF.I` (IRQ mask) bit position in the `DAIF` system register read.
const DAIF_I: u64 = 1 << 7;

/// Nestable critical section via `PSTATE.I` (IRQ masking). On the outermost exit — when IRQs
/// were enabled on entry — a context switch requested while inside is serviced before IRQs
/// come back (the PendSV analog; the real self-SGI path is wired in stage 2).
#[inline]
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    let daif: u64;
    // SAFETY: read DAIF then mask IRQ (set the I bit).
    unsafe {
        asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack, preserves_flags));
        asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
    }
    let r = f();
    if daif & DAIF_I == 0 {
        // IRQs were on: unmask them again (stage 2 adds the deferred-switch SGI here).
        // SAFETY: restoring the entry interrupt state.
        unsafe { asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)) };
    }
    r
}

pub(super) static SWITCH_PENDING: AtomicBool = AtomicBool::new(false);
pub(super) static ISR_DEPTH: AtomicUsize = AtomicUsize::new(0);

/// Request a context switch by raising the reschedule SGI. `DAIF` masking inside `critical`
/// defers it until the section ends — the PendSV analog.
#[inline]
pub fn request_switch() {
    SWITCH_PENDING.store(true, Ordering::Relaxed);
    intc::resched();
}

/// The incoming task's saved stack pointer (stage 3 will also publish its kernel stack as
/// `SP_EL1` and its address space before `ERET`ing to EL0).
fn enter(k: &mut Kernel, n: u8) -> u64 {
    k.tasks[n as usize].sp as u64
}

/// EL1 entry trampoline for a freshly-scheduled kernel task: run its entry, then exit.
pub(super) extern "C" fn task_trampoline() -> ! {
    let i = kernel::with(|k| k.current);
    kernel::task::run_entry(i);
    exit_current(0)
}

/// Whether we are in interrupt context (AArch64 has no IPSR; we count nesting).
#[inline]
pub fn in_isr() -> bool {
    ISR_DEPTH.load(Ordering::Relaxed) > 0
}

/// Idle: wait for an interrupt.
pub(crate) fn idle() {
    // SAFETY: `wfi` only waits for an interrupt.
    unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
}

/// Tickless light sleep. Until the generic-timer one-shot is wired in (stage 2 tickless), a
/// plain `WFI`; the always-on generic timer wakes it, so no time is lost.
pub(crate) fn sleep_until(deadline: Option<u64>) {
    match deadline {
        // Tickless: program the generic timer for a single interrupt at the next event and sleep
        // through the intermediate periodic ticks, reconciling the kernel clock from the
        // free-running counter on wake (the timer IRQ restores the periodic cadence via `rearm`).
        Some(d) => {
            let now = kernel::time::ticks();
            if d <= now {
                return;
            }
            let start = timer::arm_oneshot(d - now);
            // SAFETY: `wfi` only waits for an interrupt.
            unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
            let elapsed = timer::elapsed_ticks(start);
            kernel::with(|k| k.advance_to(now + elapsed));
        }
        // SAFETY: `wfi` only waits for an interrupt.
        None => unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) },
    }
}

/// Lay out a fresh task's initial exception frame (see [`sw::init_task`]).
pub(crate) fn init_task(k: &mut Kernel, i: u8) {
    sw::init_task(k, i);
}

pub(crate) fn exit_current(code: usize) -> ! {
    kernel::with(|k| kernel::task::finish_current(k, code));
    loop {
        idle();
    }
}

/// User (EL0) tasks are supported once the per-page isolation tables are up (`paging::build`
/// runs in `_start`).
pub fn supports_user_tasks() -> bool {
    paging::ready()
}

/// Open a loaded Linux image's EL0 pages: its code region read-execute and its stack region
/// read-write (both inside the kernel-image GiB buffer the `compat::linux` loader prepared).
/// Returns whether every page was opened (fails closed otherwise).
#[cfg(feature = "linux-abi")]
pub fn open_linux_image(code: (u64, u64), stack: (u64, u64)) -> bool {
    let a = paging::open_user_exec(code.0, code.1);
    let b = paging::open_user_range(stack.0, stack.1);
    a && b
}

/// Whether an unprivileged task may have the kernel read `[addr, end)` as read-only data:
/// the kernel's EL0-readable, non-writable pages (text + rodata).
pub(crate) fn user_readable(addr: usize, end: usize) -> bool {
    paging::is_user_ro(addr, end)
}

/// System call from a task. [`crate::user`] (the EL0 client) is the only caller on bare metal,
/// so we always trap via `SVC #0`: x8 = number, x0–x3 = arguments, result in x0. The gate
/// switches to the task's kernel stack (`SP_EL1`, banked) and dispatches there.
pub(crate) fn syscall(n: u32, args: [usize; 4]) -> isize {
    let r: i64;
    // SAFETY: trap to the EL1 sync vector, which validates everything. Our handler preserves
    // all registers except x0 (the result); arguments are read from x0–x3 and x8.
    unsafe {
        asm!(
            "svc #0",
            in("x8") n as u64,
            inlateout("x0") args[0] as u64 => r,
            in("x1") args[1] as u64,
            in("x2") args[2] as u64,
            in("x3") args[3] as u64,
        );
    }
    r as isize
}

/// Start the scheduler: install the vector table, bring up the GIC and the generic-timer
/// tick, then enable interrupts. The first timer tick performs the first context switch into
/// the highest-priority ready task; this `start` context is then abandoned.
pub(crate) fn start(_core_hz: u32) -> ! {
    kernel::with(|k| {
        k.ensure_init();
        k.started = true;
    });
    exceptions::init();
    intc::init();
    timer::init(crate::config::TICK_HZ);
    sw::arm_first_switch();
    // SAFETY: the vector table and GIC are up; unmask IRQs so the first timer tick switches
    // into the first task.
    unsafe { asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)) };
    loop {
        idle();
    }
}

/// Exit QEMU via the ARM semihosting `SYS_EXIT` call (used by the demo boards to end a run).
/// On real hardware with no semihosting host this simply parks the CPU.
pub fn qemu_exit(code: u32) -> ! {
    // ADP_Stopped_ApplicationExit; the second field is the exit status.
    let block = [0x2_0026usize, code as usize];
    // SAFETY: `hlt #0xf000` is the AArch64 semihosting trap; x0 = SYS_EXIT (0x18), x1 = &block.
    unsafe {
        asm!(
            "hlt #0xf000",
            in("x0") 0x18,
            in("x1") block.as_ptr(),
            options(nostack, preserves_flags),
        );
    }
    loop {
        idle();
    }
}
