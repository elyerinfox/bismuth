//! BCM2835 system timer (Raspberry Pi 1 / Zero, ARMv6), the tick source where there is no
//! ARM generic timer. A free-running 1 MHz counter with four compare registers; we use
//! compare 1 (match → IRQ 1 via the ARMCTRL controller), reprogramming it each tick.
//!
//! Classification: L0 port · cortex-a BCM system timer · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicUsize, Ordering};

const BASE: usize = 0x2000_3000;
const CS: usize = 0x00; // control/status (match flags)
const CLO: usize = 0x04; // counter low (1 MHz)
const C1: usize = 0x10; // compare 1
const MATCH1: u32 = 1 << 1;

/// Timer-source bit (for API parity with the generic-timer variant; unused by the ARMCTRL).
pub const TIMER_SRC: u32 = MATCH1;

static INTERVAL: AtomicUsize = AtomicUsize::new(0);

fn wr(off: usize, val: u32) {
    // SAFETY: `BASE + off` is a system-timer register in Device memory.
    unsafe { ((BASE + off) as *mut u32).write_volatile(val) };
}
fn rd(off: usize) -> u32 {
    // SAFETY: as `wr`.
    unsafe { ((BASE + off) as *const u32).read_volatile() }
}

/// Program the first tick (counter runs at 1 MHz) and enable its IRQ via the controller.
pub fn init(tick_hz: u32) {
    let interval = (1_000_000 / tick_hz).max(1);
    INTERVAL.store(interval as usize, Ordering::Relaxed);
    wr(CS, MATCH1); // clear any stale match
    wr(C1, rd(CLO).wrapping_add(interval));
    super::intc::route_timer();
}

/// Clear the match and schedule the next tick.
pub fn rearm() {
    wr(CS, MATCH1);
    let interval = INTERVAL.load(Ordering::Relaxed) as u32;
    wr(C1, rd(CLO).wrapping_add(interval));
}
