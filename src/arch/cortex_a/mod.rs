//! AArch32 Cortex-A (ARMv7-A) port, for 32-bit application-class ARM: Raspberry Pi 2
//! (BCM2836, Cortex-A7) and — with an ARMv6 variant — Pi 1 / Zero (BCM2835). Distinct from
//! the Cortex-M (ARMv7-**M** microcontroller) port: a full MMU, processor modes (SVC kernel /
//! USR user ≈ EL1/EL0), a vector table, and the generic timer via CP15. Selected by the
//! `cortex-a` cargo feature (both profiles are `target_arch = "arm"`).
//!
//! Built in stages, mirroring the aarch64 port:
//! * **Stage 1 (this file's current form):** `_start` + HYP→SVC drop + a minimal identity MMU
//!   (see [`boot`]); a board boots to a PL011 serial banner in SVC mode with caches on.
//! * **Stage 2 (next):** the BCM local interrupt controller + the generic-timer tick + the
//!   context switch, so the scheduler preempts.
//! * **Stage 3:** USR-mode user tasks via per-page MMU permissions + an `SVC` gate.
//!
//! Part of the trusted computing base: inline assembly and CP15 system registers.
//!
//! Classification: L0 port · cortex-a port · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::kernel::{self, Kernel};

pub mod boot;
pub mod paging;
pub mod sw;
pub mod vectors;

// The interrupt controller and tick source differ by SoC generation: ARMv7-A (Pi 2) has the
// per-core local controller + the ARM generic timer; ARMv6 (Pi 1 / Zero) has the legacy
// ARMCTRL + the BCM system timer.
#[cfg(not(feature = "armv6"))]
pub mod intc;
#[cfg(feature = "armv6")]
#[path = "intc_armctrl.rs"]
pub mod intc;
#[cfg(not(feature = "armv6"))]
pub mod timer;
#[cfg(feature = "armv6")]
#[path = "timer_systimer.rs"]
pub mod timer;

/// Nestable critical section via `CPSR.I` (IRQ masking).
#[inline]
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    let cpsr: u32;
    // SAFETY: read CPSR then mask IRQ.
    unsafe {
        asm!("mrs {}, cpsr", out(reg) cpsr, options(nomem, nostack, preserves_flags));
        asm!("cpsid i", options(nomem, nostack, preserves_flags));
    }
    let r = f();
    if cpsr & (1 << 7) == 0 {
        // On ARMv6 there is no IPI, so a reschedule requested inside the section is serviced
        // here, before IRQs come back, via a software interrupt (the PendSV analog). On
        // ARMv7-A the reschedule is a mailbox IRQ that simply fires when IRQs are unmasked.
        #[cfg(feature = "armv6")]
        if SWITCH_PENDING.load(Ordering::Relaxed) && ISR_DEPTH.load(Ordering::Relaxed) == 0 {
            SWITCH_PENDING.store(false, Ordering::Relaxed);
            // SAFETY: `svc #0` traps to the reschedule vector, which switches tasks.
            unsafe { asm!("svc #0", options(nomem, nostack)) };
        }
        // SAFETY: IRQs were enabled on entry; restore them.
        unsafe { asm!("cpsie i", options(nomem, nostack, preserves_flags)) };
    }
    r
}

pub(super) static SWITCH_PENDING: AtomicBool = AtomicBool::new(false);
pub(super) static ISR_DEPTH: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub fn request_switch() {
    SWITCH_PENDING.store(true, Ordering::Relaxed);
    // ARMv7-A: raise the mailbox IPI (deferred by the I bit). ARMv6: the flag is serviced by
    // the software interrupt on the outermost `critical` exit (no IPI available).
    #[cfg(not(feature = "armv6"))]
    intc::resched();
}

fn enter(k: &mut Kernel, n: u8) -> u32 {
    k.tasks[n as usize].sp as u32
}

pub(super) extern "C" fn task_trampoline() -> ! {
    let i = kernel::with(|k| k.current);
    kernel::task::run_entry(i);
    exit_current(0)
}

#[inline]
pub fn in_isr() -> bool {
    ISR_DEPTH.load(Ordering::Relaxed) > 0
}

/// Wait for an interrupt. ARMv7-A has the `wfi` instruction; ARMv6 (ARM1176) uses the CP15
/// "wait for interrupt" operation instead.
#[cfg(not(feature = "armv6"))]
pub(super) fn wait_for_interrupt() {
    // SAFETY: `wfi` only waits for an interrupt.
    unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
}
#[cfg(feature = "armv6")]
pub(super) fn wait_for_interrupt() {
    // SAFETY: CP15 c7,c0,4 is the ARMv6 "wait for interrupt" (the register value is ignored).
    unsafe { asm!("mcr p15, 0, {t}, c7, c0, 4", t = out(reg) _, options(nomem, nostack, preserves_flags)) };
}

pub(crate) fn idle() {
    wait_for_interrupt();
}

pub(crate) fn sleep_until(_deadline: Option<u64>) {
    // The timer keeps running; waiting for any interrupt loses no time.
    wait_for_interrupt();
}

pub(crate) fn init_task(k: &mut Kernel, i: u8) {
    sw::init_task(k, i);
}

pub(crate) fn exit_current(code: usize) -> ! {
    kernel::with(|k| kernel::task::finish_current(k, code));
    loop {
        idle();
    }
}

pub fn supports_user_tasks() -> bool {
    paging::ready()
}

pub(crate) fn user_readable(addr: usize, end: usize) -> bool {
    paging::is_user_ro(addr, end)
}

/// System call from a task. [`crate::user`] (the USR-mode client) is the only caller on bare
/// metal, so we always trap via `SVC`: r7 = number, r0–r3 = arguments, result in r0. The
/// handler runs on the task's kernel stack and dispatches there.
pub(crate) fn syscall(n: u32, args: [usize; 4]) -> isize {
    let r: i32;
    // SAFETY: trap to the SVC vector, which validates everything. The handler preserves every
    // register except r0 (the result).
    unsafe {
        core::arch::asm!(
            "svc #1",
            in("r7") n,
            inlateout("r0") args[0] as u32 => r,
            in("r1") args[1] as u32,
            in("r2") args[2] as u32,
            in("r3") args[3] as u32,
        );
    }
    r as isize
}

/// A small IRQ-mode stack (`SP_irq`), set up before interrupts are enabled.
#[repr(C, align(8))]
struct IrqStack([u8; 4096]);
static mut IRQ_STACK: IrqStack = IrqStack([0; 4096]);

pub(crate) fn start(_core_hz: u32) -> ! {
    kernel::with(|k| {
        k.ensure_init();
        k.started = true;
    });
    vectors::init();
    // Point SP_irq at our IRQ stack (used briefly on exception entry), then back to SVC.
    let irq_top = (&raw const IRQ_STACK as u32) + 4096;
    // SAFETY: set the banked IRQ-mode stack pointer, returning to SVC mode.
    unsafe {
        asm!(
            "cps #0x12",
            "mov sp, {top}",
            "cps #0x13",
            top = in(reg) irq_top,
            options(nostack, preserves_flags),
        );
    }
    intc::init();
    timer::init(crate::config::TICK_HZ);
    sw::arm_first_switch();
    // SAFETY: vectors + controller are up; enable IRQs so the first timer tick switches in.
    unsafe { asm!("cpsie i", options(nomem, nostack, preserves_flags)) };
    loop {
        idle();
    }
}

/// Exit QEMU via ARM semihosting `SYS_EXIT` (used by the demo boards). Parks on real hardware.
pub fn qemu_exit(_code: u32) -> ! {
    // SAFETY: `svc 0x123456` is the ARM-state semihosting trap; r0 = SYS_EXIT (0x18),
    // r1 = ADP_Stopped_ApplicationExit.
    unsafe {
        asm!(
            "svc 0x123456",
            in("r0") 0x18,
            in("r1") 0x20026,
            options(nostack, preserves_flags),
        );
    }
    loop {
        idle();
    }
}
