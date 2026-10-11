//! GICv2 (GIC-400) interrupt controller: the distributor (global) + CPU interface (per-core).
//!
//! The role the NVIC plays integrally on Cortex-M and the PIC/APIC plays on x86: it routes
//! and prioritises interrupts and does acknowledge/EOI. Interrupt IDs are SGIs 0–15
//! (software-generated — our self-targeted reschedule), PPIs 16–31 (per-core private — the
//! generic timer), and SPIs 32+ (shared peripherals — the UART). The register pokes go
//! through an `Mmio`-style window (TCB); the dispatch logic above is ordinary code.
//!
//! Addresses here are QEMU `virt`'s GICv2 (GICD @ 0x0800_0000, GICC @ 0x0801_0000); a board
//! with a different GIC base sets them via [`init_at`] (Pi 4 / Jetson differ).
//!
//! Classification: L0 port · aarch64 GIC · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static GICD: AtomicUsize = AtomicUsize::new(0);
static GICC: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);

// Distributor register offsets.
const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_SGIR: usize = 0xF00;
// CPU-interface register offsets.
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;

/// The reschedule SGI (a software-generated interrupt targeted at this core).
pub const SGI_RESCHED: u32 = 0;

fn wr(base: usize, off: usize, val: u32) {
    // SAFETY: `base + off` is a GIC MMIO register in the Device-mapped low region.
    unsafe { ((base + off) as *mut u32).write_volatile(val) };
}
fn rd(base: usize, off: usize) -> u32 {
    // SAFETY: as `wr`.
    unsafe { ((base + off) as *const u32).read_volatile() }
}

/// Record the distributor/CPU-interface base addresses (from the board memory map), before
/// the GIC is enabled.
pub fn set_bases(gicd: usize, gicc: usize) {
    GICD.store(gicd, Ordering::Relaxed);
    GICC.store(gicc, Ordering::Relaxed);
}

/// Enable the GIC (distributor + CPU interface) at the recorded bases.
pub fn init() {
    let gicd = GICD.load(Ordering::Relaxed);
    let gicc = GICC.load(Ordering::Relaxed);
    wr(gicd, GICD_CTLR, 1); // enable the distributor (group 0)
    wr(gicc, GICC_PMR, 0xFF); // accept all priorities
    wr(gicc, GICC_CTLR, 1); // enable the CPU interface
    READY.store(true, Ordering::Release);
}

/// Enable interrupt `id` and route it (SPIs) to this core at a mid priority.
pub fn enable(id: u32) {
    let gicd = GICD.load(Ordering::Relaxed);
    // Priority (one byte per IRQ); lower = higher priority. Give the reschedule SGI a low
    // priority so device IRQs preempt it.
    let prio = if id == SGI_RESCHED { 0xF0u32 } else { 0xA0 };
    let praddr = GICD_IPRIORITYR + (id as usize & !0x3);
    let shift = (id as usize & 0x3) * 8;
    let mut p = rd(gicd, praddr);
    p = (p & !(0xFF << shift)) | (prio << shift);
    wr(gicd, praddr, p);
    if id >= 32 {
        // Target SPIs at CPU 0 (one byte per IRQ in ITARGETSR).
        let taddr = GICD_ITARGETSR + (id as usize & !0x3);
        let mut t = rd(gicd, taddr);
        t = (t & !(0xFF << shift)) | (0x01 << shift);
        wr(gicd, taddr, t);
    }
    wr(gicd, GICD_ISENABLER + (id as usize / 32) * 4, 1 << (id % 32));
}

/// Acknowledge the pending interrupt; returns its ID (≥ 1020 means spurious — do not EOI).
pub fn acknowledge() -> u32 {
    rd(GICC.load(Ordering::Relaxed), GICC_IAR) & 0x3FF
}

/// Signal end-of-interrupt for `id`.
pub fn end(id: u32) {
    wr(GICC.load(Ordering::Relaxed), GICC_EOIR, id);
}

/// Raise the reschedule SGI targeted at the current core (the PendSV analog). Masked by
/// `PSTATE.I`, so `critical()` naturally defers it until the section ends.
pub fn resched() {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    // GICD_SGIR: TargetListFilter = 0b10 (this PE only) in bits [25:24], SGI ID in [3:0].
    wr(GICD.load(Ordering::Relaxed), GICD_SGIR, (0b10 << 24) | SGI_RESCHED);
}
