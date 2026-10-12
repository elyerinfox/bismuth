//! AArch64 reset path: `_start`, the EL2→EL1 drop, and the minimal identity MMU.
//!
//! There is no `bootloader` crate here (unlike x86-64): the firmware/QEMU drops us at
//! `_start` and we do phase-1 bring-up ourselves. `_start` parks secondary cores, drops to
//! EL1 if we entered at EL2 (the default on QEMU `virt` with virtualization and on the Pi
//! armstub), sets the stack, zeroes `.bss`, enables a small identity-mapped MMU (so Normal
//! cacheable memory — and therefore the exclusive loads/stores the kernel's atomics need —
//! works), then calls the board's `kernel_main`.
//!
//! The identity map is deliberately coarse: 1 GiB block descriptors at level 1 — the low
//! 1 GiB as Device memory (covering the GIC and the PL011 UART on QEMU `virt`) and the next
//! 4 GiB as Normal write-back (RAM). Per-page EL0 isolation tables come later (stage 3).
//!
//! Classification: L0 port · aarch64 boot · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::naked_asm;

/// Reset entry. Placed first in `.text.boot` by the board linker script; `ENTRY(_start)`.
#[cfg(not(feature = "hypervisor"))]
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        // Only core 0 proceeds; park the rest (SMP is a later effort).
        "mrs x0, mpidr_el1",
        "and x0, x0, #0xff",
        "cbnz x0, 9f",
        // Drop to EL1 from whatever EL the firmware entered at. QEMU `virt` enters at EL1
        // (nothing to do), the Pi/Jetson armstub at EL2, and QEMU `raspi*` at EL3.
        "mrs x0, CurrentEL",
        "lsr x0, x0, #2",
        "cmp x0, #3",
        "b.ne 4f",
        // EL3 → EL1: non-secure, lower EL AArch64 (SCR_EL3 = NS | RW | RES1[5:4]). With EL2
        // implemented, EL1's execution state is set by HCR_EL2.RW, so set that to AArch64 too
        // (EL3 may write EL2 registers) before returning straight to EL1.
        "mov x0, #0x431",
        "msr scr_el3, x0",
        "mov x0, #0x80000000", // HCR_EL2.RW = 1
        "msr hcr_el2, x0",
        "mov x0, #0x3c5", // SPSR_EL3 = EL1h, DAIF masked
        "msr spsr_el3, x0",
        "adr x0, 1f",
        "msr elr_el3, x0",
        "eret",
        "4:",
        "cmp x0, #2",
        "b.ne 1f",
        // EL2 → EL1.
        "mov x0, #0x80000000", // HCR_EL2.RW = 1 → EL1 is AArch64
        "msr hcr_el2, x0",
        "mov x0, #0x3c5", // SPSR_EL2 = EL1h, DAIF masked
        "msr spsr_el2, x0",
        "adr x0, 1f",
        "msr elr_el2, x0",
        "eret",
        "1:",
        // Stack (EL1), then zero .bss.
        "adrp x0, __stack_top",
        "add x0, x0, :lo12:__stack_top",
        "mov sp, x0",
        "adrp x0, __bss_start",
        "add x0, x0, :lo12:__bss_start",
        "adrp x1, __bss_end",
        "add x1, x1, :lo12:__bss_end",
        "2:",
        "cmp x0, x1",
        "b.hs 3f",
        "str xzr, [x0], #8",
        "b 2b",
        "3:",
        "bl {boot}",
        "9:",
        "wfe",
        "b 9b",
        boot = sym rust_boot,
    )
}

/// A board's physical memory layout, returned by its `bismuth_board_map` so the port can set
/// up the MMU and the GIC without hardcoding one board's addresses. `ram`/`periph` are
/// `(base, size)`; peripherals are mapped Device, RAM Normal write-back.
#[repr(C)]
pub struct BoardMap {
    pub ram_base: u64,
    pub ram_size: u64,
    pub periph_base: u64,
    pub periph_size: u64,
    /// Interrupt controller: [`super::intc::KIND_GIC`] (GIC — `gicd`/`gicc` used) or
    /// [`super::intc::KIND_BCM`] (BCM2836/7 local controller — `gicd`/`gicc` ignored).
    pub intc: u64,
    pub gicd: u64,
    pub gicc: u64,
}

unsafe extern "C" {
    /// The board's entry, run at EL1 with the MMU on. Provided with `#[no_mangle]`.
    fn kernel_main() -> !;
    /// The board's memory layout, read before the MMU/GIC are set up. `#[no_mangle]`.
    /// (Unused in the `hypervisor` build, which stays at EL2 and skips MMU/GIC bring-up.)
    #[cfg(not(feature = "hypervisor"))]
    fn bismuth_board_map() -> BoardMap;
}

#[cfg(not(feature = "hypervisor"))]
extern "C" fn rust_boot() -> ! {
    // SAFETY: the board provides `bismuth_board_map`.
    let m = unsafe { bismuth_board_map() };
    super::intc::set_kind(m.intc as u32);
    super::gic::set_bases(m.gicd as usize, m.gicc as usize);
    super::paging::build((m.ram_base, m.ram_size), (m.periph_base, m.periph_size));
    // SAFETY: the board provides `kernel_main`; we never return from it.
    unsafe { kernel_main() }
}

/// Reset entry for the `hypervisor` feature: **stay at EL2** (do not drop to EL1) and hand off to
/// the board's `kernel_main`, which runs the EL2 hypervisor shim ([`super::hyp`]). QEMU `virt`
/// with `virtualization=on` enters here at EL2. The MMU is left off in stage 1 (see `hyp`).
#[cfg(feature = "hypervisor")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        // Only core 0 proceeds; park the rest.
        "mrs x0, mpidr_el1",
        "and x0, x0, #0xff",
        "cbnz x0, 9f",
        // Stay at the entry EL (EL2 on QEMU `virt,virtualization=on`): set SP, zero .bss, go.
        "adrp x0, __stack_top",
        "add x0, x0, :lo12:__stack_top",
        "mov sp, x0",
        "adrp x0, __bss_start",
        "add x0, x0, :lo12:__bss_start",
        "adrp x1, __bss_end",
        "add x1, x1, :lo12:__bss_end",
        "2:",
        "cmp x0, x1",
        "b.hs 3f",
        "str xzr, [x0], #8",
        "b 2b",
        "3:",
        "bl {boot}",
        "9:",
        "wfe",
        "b 9b",
        boot = sym rust_boot_hyp,
    )
}

/// EL2 Rust entry for the hypervisor build: hand off to the board's `kernel_main` (which calls
/// the EL2 shim). No MMU/GIC bring-up here — stage 1 runs with the MMU off.
#[cfg(feature = "hypervisor")]
extern "C" fn rust_boot_hyp() -> ! {
    // SAFETY: the board provides `kernel_main`; we never return from it.
    unsafe { kernel_main() }
}
