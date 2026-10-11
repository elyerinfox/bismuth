//! Interrupt Descriptor Table for the x86-64 port, hand-rolled on stable (no external
//! crate). We reuse the bootloader's long-mode code segment (read from `CS`) for the gate
//! selectors, install generic "report and halt" stubs for CPU exceptions (so a fault is
//! visible on the serial console instead of a silent triple-fault), and point the timer and
//! yield vectors at the context-switch stubs in [`super::sw`].
//!
//! Classification: L0 port · x86-64 IDT · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;

/// Page-fault vector (CPU exception 14), the timer IRQ (PIC IRQ0, remapped), the software
/// yield vector, and the `int 0x80` system-call gate (callable from ring 3).
pub const VEC_PF: usize = 14;
pub const VEC_TIMER: usize = 0x20;
pub const VEC_SYSCALL: usize = 0x80;
pub const VEC_YIELD: usize = 0x81;

#[derive(Copy, Clone)]
#[repr(C)]
struct GateDescriptor {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl GateDescriptor {
    const NULL: GateDescriptor =
        GateDescriptor { offset_low: 0, selector: 0, ist: 0, type_attr: 0, offset_mid: 0, offset_high: 0, zero: 0 };

    fn new(handler: usize, selector: u16) -> Self {
        Self::with_attr(handler, selector, 0x8E) // present, DPL=0, 64-bit interrupt gate
    }

    /// A gate with an explicit type/attribute byte: `0x8E` = interrupt gate DPL0,
    /// `0xEF` = trap gate DPL3 (leaves `IF` set and is reachable from ring 3 — the syscall
    /// gate, so a blocking syscall can still take interrupts and defer-switch like any
    /// kernel code).
    fn with_attr(handler: usize, selector: u16, type_attr: u8) -> Self {
        GateDescriptor {
            offset_low: handler as u16,
            selector,
            ist: 0,
            type_attr,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            zero: 0,
        }
    }
}

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

static mut IDT: [GateDescriptor; 256] = [GateDescriptor::NULL; 256];

/// Install the IDT: exception stubs on 0..32, the timer and yield context-switch stubs.
pub fn init() {
    let cs = super::gdt::KERNEL_CODE;
    // SAFETY: single-threaded boot setup; IDT is our static table.
    unsafe {
        let idt = &raw mut IDT;
        for v in 0..32 {
            (*idt)[v] = GateDescriptor::new(fault_stub as *const () as usize, cs);
        }
        (*idt)[VEC_PF] = GateDescriptor::new(super::sw::page_fault_isr as *const () as usize, cs);
        (*idt)[VEC_TIMER] = GateDescriptor::new(super::sw::timer_isr as *const () as usize, cs);
        (*idt)[VEC_YIELD] = GateDescriptor::new(super::sw::yield_isr as *const () as usize, cs);
        // Trap gate, DPL 3: ring-3 may `int 0x80`, and IF stays set so the syscall can block.
        (*idt)[VEC_SYSCALL] = GateDescriptor::with_attr(super::sw::syscall_isr as *const () as usize, cs, 0xEF);
        let idtr = Idtr { limit: (core::mem::size_of::<[GateDescriptor; 256]>() - 1) as u16, base: idt as u64 };
        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// Generic CPU-exception handler: report on the serial console and halt. We never resume a
/// faulted context (a kernel fault is fatal), so register preservation is unnecessary.
#[unsafe(naked)]
extern "C" fn fault_stub() {
    core::arch::naked_asm!("cli", "call {report}", "2:", "hlt", "jmp 2b", report = sym fault_report);
}

extern "C" fn fault_report() {
    super::console_sink("\n*** x86 CPU exception — kernel halted ***\n");
}
