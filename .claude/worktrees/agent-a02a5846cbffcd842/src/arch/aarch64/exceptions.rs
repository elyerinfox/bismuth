//! The EL1 exception vector table (`VBAR_EL1`): 16 entries × 128 bytes, in four groups
//! (Current-EL-SP0, Current-EL-SPx, Lower-EL-AArch64, Lower-EL-AArch32), each with
//! Synchronous/IRQ/FIQ/SError.
//!
//! We run on `SPx`, so the live group is **Current-EL-SPx** (IRQ → the context-switch path,
//! Sync → a kernel-fault reporter that halts). The **Lower-EL-AArch64** group's Sync slot is
//! where the `SVC` gate and the EL0-abort-kills-the-domain path land in stage 3; its IRQ slot
//! shares the switch path. FIQ/SError and the unused groups report-and-halt.
//!
//! The table must be 2 KiB-aligned; the board linker script places `.text.vectors` on that
//! boundary (`ALIGN(2048)`).
//!
//! Classification: L0 port · aarch64 exceptions · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::{asm, naked_asm};

/// The vector table. Each 128-byte slot branches to a handler. IRQ slots enter the shared
/// context-switch vector in [`super::sw`]; synchronous/unexpected slots report and halt.
#[unsafe(naked)]
#[unsafe(link_section = ".text.vectors")]
pub extern "C" fn vectors() {
    naked_asm!(
        // --- Current EL with SP0 (unused: we always run on SPx) ---
        ".balign 0x80", "b {bad}", // Synchronous
        ".balign 0x80", "b {bad}", // IRQ
        ".balign 0x80", "b {bad}", // FIQ
        ".balign 0x80", "b {bad}", // SError
        // --- Current EL with SPx (kernel) ---
        ".balign 0x80", "b {sync}",
        ".balign 0x80", "b {irq}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // --- Lower EL using AArch64 (EL0 user tasks: SVC gate + aborts-kill-the-domain) ---
        ".balign 0x80", "b {svc}",
        ".balign 0x80", "b {irq}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // --- Lower EL using AArch32 (unused) ---
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        sync = sym sync_report,
        irq = sym super::sw::irq_vector,
        svc = sym super::sw::svc_vector,
        bad = sym bad_report,
    )
}

/// Install the vector table into `VBAR_EL1`.
pub fn init() {
    let base = vectors as *const () as u64;
    // SAFETY: setting the exception vector base to our 2 KiB-aligned table.
    unsafe { asm!("msr vbar_el1, {}", "isb", in(reg) base, options(nostack, preserves_flags)) };
}

fn report(kind: &str) -> ! {
    let (esr, elr, far, spsr): (u64, u64, u64, u64);
    // SAFETY: reading exception syndrome/address/return registers is side-effect free.
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, elr_el1", out(reg) elr, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, far_el1", out(reg) far, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, spsr_el1", out(reg) spsr, options(nomem, nostack, preserves_flags));
    }
    crate::kprintln!("\n*** aarch64 {kind} exception: ESR={esr:#x} ELR={elr:#x} FAR={far:#x} SPSR={spsr:#x} — halted ***");
    loop {
        // SAFETY: parking the CPU after an unrecoverable exception.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

extern "C" fn sync_report() -> ! {
    report("synchronous")
}

extern "C" fn bad_report() -> ! {
    report("unexpected")
}
