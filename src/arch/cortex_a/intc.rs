//! BCM2836 per-core local interrupt controller (Raspberry Pi 2), which this SoC presents
//! instead of a GIC. Same block as the BCM2837 (Pi 3); we use the virtual-timer routing and a
//! mailbox IPI for the reschedule. Register logic is safe over raw pointers (TCB file).
//!
//! Classification: L0 port · cortex-a BCM intc · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

const BASE: usize = 0x4000_0000;
const CORE0_TIMER_IRQCNTL: usize = 0x40;
const CORE0_MBOX_IRQCNTL: usize = 0x50;
const CORE0_IRQ_SOURCE: usize = 0x60;
const CORE0_MBOX0_SET: usize = 0x80;
const CORE0_MBOX0_RDCLR: usize = 0xC0;

const SRC_MBOX0: u32 = 1 << 4;
/// Normalised reschedule ID.
pub const RESCHED_ID: u32 = 0;
/// Normalised timer ID.
pub const TIMER_ID: u32 = 27;

fn wr(off: usize, val: u32) {
    // SAFETY: `BASE + off` is a local-controller register in Device memory.
    unsafe { ((BASE + off) as *mut u32).write_volatile(val) };
}
fn rd(off: usize) -> u32 {
    // SAFETY: as `wr`.
    unsafe { ((BASE + off) as *const u32).read_volatile() }
}

/// Enable the mailbox-0 IPI line for core 0 (the reschedule path).
pub fn init() {
    wr(CORE0_MBOX_IRQCNTL, 1);
}

/// Route the virtual-timer interrupt to core 0's IRQ.
pub fn route_timer() {
    wr(CORE0_TIMER_IRQCNTL, super::timer::TIMER_SRC);
}

/// Identify the pending interrupt.
pub fn acknowledge() -> u32 {
    let src = rd(CORE0_IRQ_SOURCE);
    if src & super::timer::TIMER_SRC != 0 {
        TIMER_ID
    } else if src & SRC_MBOX0 != 0 {
        RESCHED_ID
    } else {
        1023
    }
}

/// End-of-interrupt: the timer self-clears on rearm; the mailbox is write-cleared.
pub fn end(id: u32) {
    if id == RESCHED_ID {
        wr(CORE0_MBOX0_RDCLR, 0xFFFF_FFFF);
    }
}

/// Raise the mailbox-0 IPI on this core (the reschedule).
pub fn resched() {
    wr(CORE0_MBOX0_SET, 1);
}
