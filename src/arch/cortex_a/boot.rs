//! AArch32 Cortex-A (ARMv7-A) reset path: `_start`, the HYP→SVC drop, and a minimal
//! identity MMU via CP15 short descriptors (1 MiB sections).
//!
//! QEMU `raspi2b` (Cortex-A7, which has the virtualisation extensions) enters in **HYP**
//! mode; we drop to **SVC** (the kernel's privileged mode; USR is unprivileged — the EL1/EL0
//! analog on AArch32). We set the SVC stack, zero `.bss`, enable the MMU + caches (so the
//! `LDREX`/`STREX` the kernel's atomics use work on Normal memory), then call `kernel_main`.
//!
//! Classification: L0 port · cortex-a boot · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::naked_asm;

/// The HYP→SVC drop, needed on ARMv7-A cores that boot in HYP mode (Cortex-A7 on QEMU
/// `raspi2b`). ARMv6 (ARM1176) has no HYP mode / virt extensions, so the fragment is empty
/// there (and `.arch_extension virt` must not be emitted, as ARMv6 cannot assemble it).
#[cfg(not(feature = "armv6"))]
macro_rules! hyp_drop {
    () => {
        concat!(
            ".arch_extension virt\n",
            "mrs r0, cpsr\n",
            "and r1, r0, #0x1f\n",
            "cmp r1, #0x1a\n",
            "bne 1f\n",
            "mov r0, #0xd3\n", // SVC mode, IRQ+FIQ masked
            "msr spsr_hyp, r0\n",
            "adr r0, 1f\n",
            "msr elr_hyp, r0\n",
            "eret\n",
        )
    };
}
#[cfg(feature = "armv6")]
macro_rules! hyp_drop {
    () => {
        ""
    };
}

/// Park secondary cores. ARMv7-A reads MPIDR and parks affinity != 0. ARMv6 (ARM1176) is
/// single-core and its MPIDR may be unimplemented, so the check is omitted.
#[cfg(not(feature = "armv6"))]
macro_rules! core_gate {
    () => {
        "mrc p15, 0, r0, c0, c0, 5\nands r0, r0, #3\nbne 9f"
    };
}
#[cfg(feature = "armv6")]
macro_rules! core_gate {
    () => {
        ""
    };
}

/// Reset entry (ARM state). Placed first in `.text.boot`; `ENTRY(_start)`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        // Only core 0 proceeds (secondary cores park at 9:).
        core_gate!(),
        hyp_drop!(),
        "1:",
        // Force SVC mode with interrupts masked, then set the stack.
        "cpsid if, #0x13",
        "ldr sp, =__stack_top",
        // Zero .bss.
        "ldr r0, =__bss_start",
        "ldr r1, =__bss_end",
        "mov r2, #0",
        "2:",
        "cmp r0, r1",
        "bhs 3f",
        "str r2, [r0], #4",
        "b 2b",
        "3:",
        "bl {boot}",
        // Park any secondary core (none on single-core ARMv6; `wfe` is ARMv7-only, so busy-loop).
        "9:",
        "b 9b",
        boot = sym rust_boot,
    )
}

unsafe extern "C" {
    fn kernel_main() -> !;
}

extern "C" fn rust_boot() -> ! {
    super::paging::build();
    // SAFETY: the board provides `kernel_main`; we never return from it.
    unsafe { kernel_main() }
}
