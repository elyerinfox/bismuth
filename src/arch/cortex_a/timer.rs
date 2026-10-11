//! The ARM generic timer as the kernel tick, accessed through CP15 (ARMv7-A). The virtual
//! timer (`CNTV_*`) is programmed for a periodic interrupt that calls `kernel::tick()` and
//! drives the switch — the SysTick role, but off the always-on generic timer. Its interrupt
//! is a per-core line routed by the BCM local controller.
//!
//! Classification: L0 port · cortex-a generic timer · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Virtual-timer interrupt in the BCM local controller's source bits (CNTV).
pub const TIMER_SRC: u32 = 1 << 3;

static INTERVAL: AtomicUsize = AtomicUsize::new(0);

fn cntfrq() -> u32 {
    let f: u32;
    // SAFETY: reading CNTFRQ (CP15 c14) is side-effect free.
    unsafe { asm!("mrc p15, 0, {}, c14, c0, 0", out(reg) f, options(nomem, nostack, preserves_flags)) };
    f
}

fn set_tval(ticks: u32) {
    // SAFETY: programming CNTV_TVAL (CP15 c14, op2 0).
    unsafe { asm!("mcr p15, 0, {}, c14, c3, 0", in(reg) ticks, options(nomem, nostack, preserves_flags)) };
}

/// Start the periodic tick at `tick_hz` and route its interrupt via the local controller.
pub fn init(tick_hz: u32) {
    let interval = (cntfrq() / tick_hz).max(1);
    INTERVAL.store(interval as usize, Ordering::Relaxed);
    set_tval(interval);
    // CNTV_CTL = 1 (enable, interrupt unmasked).
    // SAFETY: enabling the virtual timer.
    unsafe { asm!("mcr p15, 0, {}, c14, c3, 1", in(reg) 1u32, options(nomem, nostack, preserves_flags)) };
    super::intc::route_timer();
}

/// Reprogram for the next periodic tick (from the timer IRQ).
pub fn rearm() {
    set_tval(INTERVAL.load(Ordering::Relaxed) as u32);
}
