//! The ARM generic timer as the kernel tick.
//!
//! The virtual timer (`CNTV_*_EL0`) is programmed for a periodic interrupt that calls
//! `kernel::tick()` and drives the context switch — the exact SysTick role on Cortex-M, but
//! 64-bit and system-register-based rather than a 24-bit MMIO counter. Its interrupt is a PPI
//! (per-core, ID 27 on QEMU `virt` and the Pi/Jetson), routed through the GIC. Tickless
//! `sleep_until` later reprograms it to an arbitrary one-shot (no 24-bit cap).
//!
//! Classification: L0 port · aarch64 generic timer · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

/// Virtual-timer PPI (interrupt ID 27 = PPI 11).
pub const TIMER_PPI: u32 = 27;

/// Ticks of the generic timer's fixed clock per kernel tick.
static INTERVAL: AtomicU64 = AtomicU64::new(0);

fn cntfrq() -> u64 {
    let f: u64;
    // SAFETY: reading the counter-timer frequency register is side-effect free.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack, preserves_flags)) };
    f
}

fn set_tval(ticks: u64) {
    // SAFETY: programming the virtual timer's down-counter.
    unsafe { asm!("msr cntv_tval_el0, {}", in(reg) ticks, options(nomem, nostack, preserves_flags)) };
}

fn enable() {
    // CNTV_CTL_EL0: ENABLE = 1, IMASK = 0 (bit1 clear).
    // SAFETY: enabling the virtual timer and unmasking its interrupt.
    unsafe { asm!("msr cntv_ctl_el0, {}", in(reg) 1u64, options(nomem, nostack, preserves_flags)) };
}

/// Start the periodic tick at `tick_hz` and enable its PPI in the GIC.
pub fn init(tick_hz: u32) {
    let interval = (cntfrq() / tick_hz as u64).max(1);
    INTERVAL.store(interval, Ordering::Relaxed);
    set_tval(interval);
    enable();
    super::intc::enable_timer();
}

/// Reprogram the timer for the next periodic tick (called from the timer IRQ).
pub fn rearm() {
    set_tval(INTERVAL.load(Ordering::Relaxed));
}
