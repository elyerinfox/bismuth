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

// ---- Stage 2: the guest's own guest-physical (IPA) address space ----
//
// The guest sees a 2 MiB RAM window at IPA `GUEST_IPA_BASE` (0x4000_0000, like a real `virt`
// board), which stage-2 translation maps to the host-physical [`GUEST_RAM`] arena. Nothing else
// is mapped, so any guest access outside that window faults to EL2. The guest runs at its IPA
// base with its stack at the top of the window; the hypervisor converts a guest pointer back to
// a host address with [`gpa_to_hpa`] before touching it.
const GUEST_IPA_BASE: u64 = 0x4000_0000;
const GUEST_RAM_SIZE: u64 = 0x20_0000; // 2 MiB

/// A 2 MiB-aligned host-physical arena backing the guest's RAM (the blob is copied in at offset 0,
/// the guest runs there at EL1, and its stack lives at the top).
#[repr(C, align(0x200000))]
struct GuestRam([u8; GUEST_RAM_SIZE as usize]);
static mut GUEST_RAM: GuestRam = GuestRam([0; GUEST_RAM_SIZE as usize]);

/// A page-aligned stage-2 translation table (512 × 8-byte descriptors).
#[repr(C, align(4096))]
struct S2Table([u64; 512]);
static mut S2_L1: S2Table = S2Table([0; 512]); // level 1 (1 GiB per entry)
static mut S2_L2: S2Table = S2Table([0; 512]); // level 2 (2 MiB per entry)

/// Host-physical base of the guest RAM arena (stable: it is a static).
fn guest_ram_hpa() -> u64 {
    addr_of_mut!(GUEST_RAM) as u64
}

/// Translate a guest-physical address (IPA) to a host-physical address, if it falls in the guest's
/// mapped RAM window. The hypervisor uses this to read/write guest memory a hypercall points at.
fn gpa_to_hpa(ipa: u64) -> Option<u64> {
    if (GUEST_IPA_BASE..GUEST_IPA_BASE + GUEST_RAM_SIZE).contains(&ipa) {
        Some(guest_ram_hpa() + (ipa - GUEST_IPA_BASE))
    } else {
        None
    }
}

/// Build the stage-2 tables mapping `[GUEST_IPA_BASE, +GUEST_RAM_SIZE)` → the guest RAM arena, and
/// program `VTCR_EL2`/`VTTBR_EL2`, enabling stage-2 in `HCR_EL2.VM`. 4 KiB granule, 40-bit IPA,
/// start level 1; the window is a single 2 MiB Normal-WB, read/write/exec block.
fn setup_stage2() {
    let arena = guest_ram_hpa();
    // SAFETY: single-threaded EL2 bring-up; the tables and arena are ours alone.
    unsafe {
        let l1 = addr_of_mut!(S2_L1) as *mut u64;
        let l2 = addr_of_mut!(S2_L2) as *mut u64;
        for i in 0..512 {
            l1.add(i).write_volatile(0);
            l2.add(i).write_volatile(0);
        }
        // L2[0] = 2 MiB block → arena. Lower attrs: valid(1) | MemAttr=0b1111 Normal-WB(<<2) |
        // S2AP=0b11 RW(<<6) | SH=0b11 inner(<<8) | AF(<<10) = 0x7FD; XN=0 (executable).
        l2.add(0).write_volatile(arena | 0x7FD);
        // L1[1] = table descriptor → L2 (IPA 0x4000_0000 has level-1 index 1).
        l1.add(1).write_volatile((l2 as u64) | 0x3);

        // VTCR_EL2: T0SZ=24 (40-bit IPA), SL0=1 (start L1), IRGN0/ORGN0=WB, SH0=inner, TG0=4KiB,
        // PS=40-bit, bit31 RES1.
        let vtcr: u64 = 0x8000_0000 | 24 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
        let vttbr = addr_of_mut!(S2_L1) as u64; // VMID 0
        asm!(
            "dsb ish",
            "msr vtcr_el2, {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "tlbi alle1is",
            "dsb ish",
            "isb",
            vtcr = in(reg) vtcr,
            vttbr = in(reg) vttbr,
            options(nostack, preserves_flags),
        );
    }
}

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
        // Not an HVC — a genuine guest fault. A stage-2 abort (EC 0x24 data / 0x20 instruction
        // from a lower EL) carries the faulting guest-physical address in HPFAR_EL2; report it
        // specifically to prove the guest was confined to its mapped RAM, then stop the VM.
        let (elr, far, hpfar): (u64, u64, u64);
        // SAFETY: reading EL2 fault registers is side-effect free.
        unsafe {
            asm!("mrs {}, elr_el2", out(reg) elr, options(nomem, nostack, preserves_flags));
            asm!("mrs {}, far_el2", out(reg) far, options(nomem, nostack, preserves_flags));
            asm!("mrs {}, hpfar_el2", out(reg) hpfar, options(nomem, nostack, preserves_flags));
        }
        if ec == 0x24 || ec == 0x20 {
            // Faulting IPA: HPFAR_EL2[43:4] = IPA[51:12]; combine with FAR_EL2's page offset.
            let ipa = ((hpfar & 0xF_FFFF_FFF0) << 8) | (far & 0xFFF);
            puts(b"[hyp] stage-2 fault: guest ");
            puts(if ec == 0x24 { b"read/write" } else { b"exec" });
            puts(b" of unmapped IPA=");
            put_hex(ipa);
            puts(b" (ELR_EL2=");
            put_hex(elr);
            puts(b") -- guest killed
");
            hyp_exit(1);
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
            // `a1` is a guest-physical address (IPA); translate it to a host address through the
            // stage-2 window before reading, and bound the length to the guest's RAM.
            match gpa_to_hpa(a1) {
                Some(hpa) if a1 + a2 <= GUEST_IPA_BASE + GUEST_RAM_SIZE => {
                    // SAFETY: [hpa, hpa+a2) lies within the guest RAM arena (bounds checked above).
                    let s = unsafe { core::slice::from_raw_parts(hpa as *const u8, a2 as usize) };
                    puts(s);
                }
                _ => puts(b"[hyp] rejected print: pointer outside guest RAM\n"),
            }
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

    // Copy the guest into the host-physical arena (at offset 0); the guest runs at its IPA base
    // under stage-2, with its stack at the top of the IPA window.
    let n = blob.len().min(GUEST_RAM_SIZE as usize);
    // SAFETY: single-threaded EL2 bring-up; the arena is ours alone.
    unsafe {
        let buf = addr_of_mut!(GUEST_RAM) as *mut u8;
        for i in 0..n {
            core::ptr::write_volatile(buf.add(i), blob[i]);
        }
        asm!("dsb ish", options(nostack, preserves_flags));
    }
    let entry = GUEST_IPA_BASE; // guest-physical (IPA) entry
    let gsp = (GUEST_IPA_BASE + GUEST_RAM_SIZE) & !0xf; // guest stack top (IPA)

    // Build and enable the guest's stage-2 address space before entering it.
    setup_stage2();

    puts(b"[hyp] stage-2 on: guest RAM IPA=");
    put_hex(GUEST_IPA_BASE);
    puts(b"..+2MiB -> HPA=");
    put_hex(guest_ram_hpa());
    put(b'\n');
    puts(b"[hyp] launching guest at EL1, entry IPA=");
    put_hex(entry);
    put(b'\n');

    let vbar = hyp_vectors as *const () as u64;
    // SAFETY: install the EL2 vectors, make the guest AArch64 + enable stage-2 (HCR_EL2.RW|VM),
    // set its stack and return state, and `eret` into it at EL1. Control re-enters only via
    // `VBAR_EL2` on a trap. (No asm outputs/scratch: `noreturn` forbids them.)
    unsafe {
        asm!(
            "msr vbar_el2, {vbar}",
            "isb",
            "msr hcr_el2, {hcr}",     // HCR_EL2.RW=1 (EL1 AArch64) | VM=1 (stage-2 enabled)
            "msr sp_el1, {gsp}",
            "msr elr_el2, {entry}",
            "msr spsr_el2, {spsr}",   // EL1h, DAIF masked
            "isb",
            "eret",
            vbar = in(reg) vbar,
            hcr = in(reg) 0x8000_0001u64,
            gsp = in(reg) gsp,
            entry = in(reg) entry,
            spsr = in(reg) 0x3c5u64,
            options(noreturn),
        )
    }
}
