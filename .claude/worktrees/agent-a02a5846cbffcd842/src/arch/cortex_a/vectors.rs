//! The ARMv7-A / ARMv6 exception vector table (8 entries at `VBAR`): reset, undefined, SVC,
//! prefetch abort, data abort, (reserved), IRQ, FIQ. SVC is the syscall gate (and the ARMv6
//! reschedule); the aborts kill a faulting USR-mode domain; IRQ is the context-switch path.
//!
//! Classification: L0 port · cortex-a vectors · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::{asm, naked_asm};

/// The vector table (eight branch instructions). 32-byte aligned via the board linker's
/// `.text.vectors` placement; `VBAR` points at it.
#[unsafe(naked)]
#[unsafe(link_section = ".text.vectors")]
pub extern "C" fn vectors() {
    naked_asm!(
        "b {bad}",    // 0x00 reset
        "b {bad}",    // 0x04 undefined instruction
        "b {svc}",    // 0x08 supervisor call → syscall gate / reschedule
        "b {abort}",  // 0x0C prefetch abort
        "b {abort}",  // 0x10 data abort
        "nop",        // 0x14 reserved
        "b {irq}",    // 0x18 IRQ
        "b {bad}",    // 0x1C FIQ
        svc = sym super::sw::svc_vector,
        abort = sym super::sw::abort_vector,
        irq = sym super::sw::irq_vector,
        bad = sym fault,
    )
}

/// Install the vector table into `VBAR`.
pub fn init() {
    let base = vectors as *const () as u32;
    #[cfg(not(feature = "armv6"))]
    // SAFETY: set VBAR (CP15 c12) and synchronise.
    unsafe {
        asm!("mcr p15, 0, {b}, c12, c0, 0", "isb", b = in(reg) base, options(nostack, preserves_flags));
    }
    #[cfg(feature = "armv6")]
    // SAFETY: set VBAR, then the CP15 prefetch flush (ARMv6 has no `isb`).
    unsafe {
        asm!("mcr p15, 0, {b}, c12, c0, 0", "mcr p15, 0, {b}, c7, c5, 4", b = in(reg) base, options(nostack, preserves_flags));
    }
}

extern "C" fn fault() -> ! {
    let (dfsr, dfar): (u32, u32);
    // SAFETY: reading the data fault status/address registers is side-effect free.
    unsafe {
        asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) dfsr, options(nomem, nostack, preserves_flags));
        asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) dfar, options(nomem, nostack, preserves_flags));
    }
    crate::kprintln!("\n*** Cortex-A exception: DFSR={dfsr:#x} DFAR={dfar:#x} — halted ***");
    loop {
        super::wait_for_interrupt();
    }
}
