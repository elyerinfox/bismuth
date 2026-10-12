//! BCM2836/2837 local interrupt controller (Raspberry Pi 2/3), which these SoCs present
//! instead of a GIC. We use only what the scheduler needs: routing the generic virtual-timer
//! interrupt to core 0, and a mailbox IPI as the self-targeted reschedule (the GIC-SGI analog).
//! Peripheral IRQs (UART, etc.) would go through the separate ARMCTRL block, which the polled
//! console does not need.
//!
//! Classification: L0 port · aarch64 BCM intc · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

/// Base of the per-core local controller (physical, identity-mapped Device memory).
const BASE: usize = 0x4000_0000;
const CORE0_TIMER_IRQCNTL: usize = 0x40;
const CORE0_MBOX_IRQCNTL: usize = 0x50;
const CORE0_IRQ_SOURCE: usize = 0x60;
const CORE0_MBOX0_SET: usize = 0x80;
const CORE0_MBOX0_RDCLR: usize = 0xC0;

/// IRQ-source bits: CNTV (virtual timer) and mailbox 0 (our reschedule IPI).
const SRC_CNTV: u32 = 1 << 3;
const SRC_MBOX0: u32 = 1 << 4;

/// Normalised reschedule ID (matches the GIC SGI 0 the switch path expects).
const RESCHED_ID: u32 = 0;

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
    wr(CORE0_MBOX_IRQCNTL, 1); // mailbox 0 → IRQ
}

/// Route the virtual-timer interrupt (nCNTVIRQ) to core 0's IRQ.
pub fn route_timer() {
    wr(CORE0_TIMER_IRQCNTL, SRC_CNTV);
}

/// Identify the pending interrupt for core 0.
pub fn acknowledge() -> u32 {
    let src = rd(CORE0_IRQ_SOURCE);
    if src & SRC_CNTV != 0 {
        super::timer::TIMER_PPI
    } else if src & SRC_MBOX0 != 0 {
        RESCHED_ID
    } else {
        1023 // spurious
    }
}

/// End-of-interrupt: the timer self-clears on rearm; the mailbox must be write-cleared.
pub fn end(id: u32) {
    if id == RESCHED_ID {
        wr(CORE0_MBOX0_RDCLR, 0xFFFF_FFFF);
    }
}

/// Raise the mailbox-0 IPI on this core (the reschedule, deferred by `DAIF` like a GIC SGI).
pub fn resched() {
    wr(CORE0_MBOX0_SET, 1);
}
