//! BCM2835 legacy ARMCTRL interrupt controller (Raspberry Pi 1 / Zero, ARMv6). The SoC is
//! single-core with no per-core local controller and no GIC, so this is the only controller.
//! We use the one line the scheduler needs: the BCM system-timer match (IRQ 1). The ARMv6
//! reschedule is a software interrupt (`SVC`), not an IPI, so there is no mailbox here.
//!
//! Classification: L0 port · cortex-a ARMCTRL intc · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

const BASE: usize = 0x2000_B200;
const IRQ_PENDING1: usize = 0x04;
const ENABLE_IRQ1: usize = 0x10;
/// System-timer compare 1 is IRQ 1 in bank 1.
const TIMER_IRQ_BIT: u32 = 1 << 1;

/// Normalised IDs shared with the switch path.
pub const TIMER_ID: u32 = 27;
pub const RESCHED_ID: u32 = 0;

fn wr(off: usize, val: u32) {
    // SAFETY: `BASE + off` is an ARMCTRL register in Device memory.
    unsafe { ((BASE + off) as *mut u32).write_volatile(val) };
}
fn rd(off: usize) -> u32 {
    // SAFETY: as `wr`.
    unsafe { ((BASE + off) as *const u32).read_volatile() }
}

/// Nothing to enable globally (no mailbox/IPI on this controller).
pub fn init() {}

/// Enable the system-timer match interrupt (IRQ 1) for the core.
pub fn route_timer() {
    wr(ENABLE_IRQ1, TIMER_IRQ_BIT);
}

/// Identify the pending interrupt.
pub fn acknowledge() -> u32 {
    if rd(IRQ_PENDING1) & TIMER_IRQ_BIT != 0 {
        TIMER_ID
    } else {
        1023
    }
}

/// End-of-interrupt: the system-timer match is cleared by `timer::rearm`; nothing to do here.
pub fn end(_id: u32) {}
