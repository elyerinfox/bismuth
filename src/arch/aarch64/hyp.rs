//! A type-1 hypervisor shim at **EL2** (`hypervisor` feature) — stage 1 of hosting guest VMs.
//!
//! When the `hypervisor` feature is on, the aarch64 reset path stays at EL2 (instead of dropping
//! to EL1) and hands control here. This stage boots EL2, installs an EL2 exception vector table
//! (`VBAR_EL2`), loads a small guest blob into RAM, and `eret`s into it at **EL1**. The guest
//! reaches the hypervisor through a tiny hypercall ABI: `HVC #0` with a command in `x0`
//! (1 = print a string the guest owns, 2 = exit). The guest's output therefore appears *through*
//! the hypervisor, proving the EL1→EL2 trap round-trip.
//!
//! Stage-1 scope (deliberately minimal — see `docs/research/hypervisor.md` for the roadmap):
//! the MMU is left **off** at both EL2 and the guest's EL1, so there is no stage-2 translation
//! yet: the guest shares the host's flat physical address space and is trusted hand-assembled
//! code, not an isolated VM. Printing is direct PL011 MMIO (no kernel console/locks, so no
//! atomics are needed with the MMU off). Stage 2 adds the EL2 MMU + stage-2 guest isolation.
//!
//! Classification: L0 port · aarch64 hypervisor · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::{asm, naked_asm};
use core::ptr::addr_of_mut;

/// QEMU `virt` PL011 UART0. Stage 1 targets QEMU `virt` only; stage 2+ takes this from the
/// board map. The hypervisor owns the UART directly (the guest prints only via hypercalls).
const UART: usize = 0x0900_0000;
const UART_DR: usize = 0x00; // data register
const UART_FR: usize = 0x18; // flag register; TXFF = bit 5

/// Hypercall numbers (the stage-1 ABI).
const HVC_PRINT: u64 = 1;
const HVC_EXIT: u64 = 2;

/// Guest image RAM (the blob is copied here and executed at EL1) and the guest's EL1 stack.
static mut GUEST_BUF: [u8; 8192] = [0; 8192];
static mut GUEST_STACK: [u8; 8192] = [0; 8192];

/// Write one byte to the PL011, spinning while the TX FIFO is full.
fn put(b: u8) {
    // SAFETY: MMIO on the QEMU `virt` PL011; the hypervisor owns the UART.
    unsafe {
        while core::ptr::read_volatile((UART + UART_FR) as *const u32) & (1 << 5) != 0 {}
        core::ptr::write_volatile((UART + UART_DR) as *mut u32, b as u32);
    }
}

/// Write a byte string to the PL011.
fn puts(s: &[u8]) {
    for &b in s {
        put(b);
    }
}

/// Print a small unsigned decimal.
fn put_dec(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    puts(&buf[i..]);
}

/// Current exception level (`CurrentEL[3:2]`).
fn current_el() -> u64 {
    let el: u64;
    // SAFETY: reading CurrentEL is side-effect free.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack, preserves_flags)) };
    el >> 2
}

/// Exit QEMU via semihosting (works from EL2).
fn hyp_exit(code: u64) -> ! {
    let block = [0x2_0026usize, code as usize];
    // SAFETY: `hlt #0xf000` is the AArch64 semihosting trap; x0 = SYS_EXIT, x1 = &block.
    unsafe {
        asm!("hlt #0xf000", in("x0") 0x18, in("x1") block.as_ptr(), options(nostack, preserves_flags));
    }
    loop {
        // SAFETY: parking if the semihosting host is absent.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

/// The EL2 exception vector table (`VBAR_EL2`): 16 entries × 128 bytes, 2 KiB-aligned. Only the
/// Lower-EL-AArch64 Synchronous slot (the guest's `HVC`/faults) is live; the rest report + halt.
#[unsafe(naked)]
#[unsafe(link_section = ".text.vectors")]
pub extern "C" fn hyp_vectors() {
    naked_asm!(
        ".balign 0x800",
        // Current EL with SP0.
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // Current EL with SPx (EL2 itself).
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // Lower EL using AArch64 (the guest at EL1): Sync = HVC gate.
        ".balign 0x80", "b {sync}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // Lower EL using AArch32 (unused).
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        sync = sym hvc_vector,
        bad = sym hyp_bad,
    )
}

/// Guest synchronous exception from EL1: save the guest GPRs, service the hypercall, restore, and
/// `eret` back to the guest (for a `print`; `exit` never returns).
#[unsafe(naked)]
extern "C" fn hvc_vector() {
    naked_asm!(
        "sub sp, sp, #256",
        "stp x0, x1, [sp, #0]",
        "stp x2, x3, [sp, #16]",
        "stp x4, x5, [sp, #32]",
        "stp x6, x7, [sp, #48]",
        "stp x8, x9, [sp, #64]",
        "stp x10, x11, [sp, #80]",
        "stp x12, x13, [sp, #96]",
        "stp x14, x15, [sp, #112]",
        "stp x16, x17, [sp, #128]",
        "stp x18, x19, [sp, #144]",
        "stp x20, x21, [sp, #160]",
        "stp x22, x23, [sp, #176]",
        "stp x24, x25, [sp, #192]",
        "stp x26, x27, [sp, #208]",
        "stp x28, x29, [sp, #224]",
        "str x30, [sp, #240]",
        "mov x0, sp",
        "bl {entry}",
        "ldp x0, x1, [sp, #0]",
        "ldp x2, x3, [sp, #16]",
        "ldp x4, x5, [sp, #32]",
        "ldp x6, x7, [sp, #48]",
        "ldp x8, x9, [sp, #64]",
        "ldp x10, x11, [sp, #80]",
        "ldp x12, x13, [sp, #96]",
        "ldp x14, x15, [sp, #112]",
        "ldp x16, x17, [sp, #128]",
        "ldp x18, x19, [sp, #144]",
        "ldp x20, x21, [sp, #160]",
        "ldp x22, x23, [sp, #176]",
        "ldp x24, x25, [sp, #192]",
        "ldp x26, x27, [sp, #208]",
        "ldp x28, x29, [sp, #224]",
        "ldr x30, [sp, #240]",
        "add sp, sp, #256",
        "eret",
        entry = sym hvc_entry,
    )
}

/// Service one guest synchronous trap. `frame` points at the saved GPR image (`x0..x30`).
extern "C" fn hvc_entry(frame: *const u64) {
    let esr: u64;
    // SAFETY: reading the EL2 syndrome register is side-effect free.
    unsafe { asm!("mrs {}, esr_el2", out(reg) esr, options(nomem, nostack, preserves_flags)) };
    let ec = esr >> 26;
    if ec != 0x16 {
        // Not an HVC — a genuine guest fault. Report and stop the VM.
        let (elr, far): (u64, u64);
        // SAFETY: reading EL2 fault registers is side-effect free.
        unsafe {
            asm!("mrs {}, elr_el2", out(reg) elr, options(nomem, nostack, preserves_flags));
            asm!("mrs {}, far_el2", out(reg) far, options(nomem, nostack, preserves_flags));
        }
        puts(b"[hyp] guest fault: ESR_EL2=");
        put_hex(esr);
        puts(b" ELR_EL2=");
        put_hex(elr);
        puts(b" FAR_EL2=");
        put_hex(far);
        puts(b" -- stopping VM
");
        hyp_exit(1);
    }
    // SAFETY: `frame` is the GPR image the vector just pushed; x0..x2 are the hypercall args.
    let (cmd, a1, a2) = unsafe { (*frame, *frame.add(1), *frame.add(2)) };
    match cmd {
        HVC_PRINT => {
            // The guest owns the string in the shared physical space (stage 1 has no stage-2).
            // SAFETY: MMU off → flat physical; the trusted guest passes a valid (ptr, len).
            let s = unsafe { core::slice::from_raw_parts(a1 as *const u8, a2 as usize) };
            puts(s);
        }
        HVC_EXIT => {
            puts(b"[hyp] guest requested exit, code ");
            put_dec(a1);
            put(b'\n');
            hyp_exit(a1);
        }
        other => {
            puts(b"[hyp] unknown hypercall ");
            put_dec(other);
            put(b'\n');
        }
    }
}

fn put_hex(mut v: u64) {
    puts(b"0x");
    let mut started = false;
    for i in (0..16).rev() {
        let nyb = ((v >> (i * 4)) & 0xf) as u8;
        if nyb != 0 || started || i == 0 {
            started = true;
            put(if nyb < 10 { b'0' + nyb } else { b'a' + nyb - 10 });
        }
    }
    let _ = &mut v;
}

extern "C" fn hyp_bad() -> ! {
    puts(b"[hyp] unexpected EL2 exception -- halted
");
    hyp_exit(2);
}

/// Load `blob` as a guest and run it at EL1, servicing its hypercalls. Never returns: the guest's
/// `HVC_EXIT` ends the run. Called from the board's `hypervisor` flow (at EL2).
pub fn run_guest(blob: &[u8]) -> ! {
    puts(b"\n[hyp] Bismuth hypervisor up at EL");
    put_dec(current_el());
    puts(b" (QEMU virt)\n");
    if current_el() != 2 {
        puts(b"[hyp] not at EL2 (need -M virt,virtualization=on) -- halting
");
        hyp_exit(3);
    }

    // Copy the guest into executable RAM and compute its entry + stack top.
    let n = blob.len().min(8192);
    // SAFETY: single-threaded EL2 bring-up; GUEST_BUF/STACK are ours alone.
    let (entry, gsp) = unsafe {
        let buf = addr_of_mut!(GUEST_BUF) as *mut u8;
        for i in 0..n {
            core::ptr::write_volatile(buf.add(i), blob[i]);
        }
        let stack_top = (addr_of_mut!(GUEST_STACK) as *mut u8).add(8192) as u64 & !0xf;
        (buf as u64, stack_top)
    };

    puts(b"[hyp] launching guest at EL1, entry=");
    put_hex(entry);
    put(b'\n');

    let vbar = hyp_vectors as *const () as u64;
    // SAFETY: install the EL2 vectors, make the guest AArch64 (HCR_EL2.RW), set its stack and
    // return state, and `eret` into it at EL1. Control re-enters only via `VBAR_EL2` on a trap.
    // (No asm outputs/scratch: `noreturn` forbids them, and the guest sets its own GPRs.)
    unsafe {
        asm!(
            "msr vbar_el2, {vbar}",
            "isb",
            "msr hcr_el2, {hcr}",     // HCR_EL2.RW = 1 -> EL1 is AArch64
            "msr sp_el1, {gsp}",
            "msr elr_el2, {entry}",
            "msr spsr_el2, {spsr}",   // EL1h, DAIF masked
            "eret",
            vbar = in(reg) vbar,
            hcr = in(reg) 0x8000_0000u64,
            gsp = in(reg) gsp,
            entry = in(reg) entry,
            spsr = in(reg) 0x3c5u64,
            options(noreturn),
        )
    }
}
