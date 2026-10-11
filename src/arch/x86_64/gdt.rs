//! Global Descriptor Table + Task State Segment for the x86-64 port, hand-rolled on stable.
//!
//! The bootloader hands us a ring-0-only GDT; ring-3 user tasks need ring-3 code/data
//! segments and a TSS whose `RSP0` names the kernel stack the CPU switches to on a
//! privilege-raising trap (the `int 0x80` syscall gate and any interrupt taken while in
//! ring 3). `IST1` gives `#DF` (double fault) a known-good stack so a corrupted task stack
//! cannot turn a fault into a silent triple-fault.
//!
//! Layout (selector = table offset): null, kernel code, kernel data, user data, user code,
//! TSS (two 8-byte slots). The per-task kernel stack is published into `RSP0` on every
//! switch into a user task (see [`set_kernel_stack`]).
//!
//! Classification: L0 port · x86-64 GDT/TSS · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;

/// Selectors (offsets into the GDT). User selectors carry RPL 3.
pub const KERNEL_CODE: u16 = 0x08;
pub const KERNEL_DATA: u16 = 0x10;
pub const USER_DATA: u16 = 0x18 | 3;
pub const USER_CODE: u16 = 0x20 | 3;
pub const TSS_SEL: u16 = 0x28;

/// 64-bit Task State Segment. Only `rsp0` and `ist[0]` (IST1) are used; the rest stay zero.
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl Tss {
    const EMPTY: Tss = Tss {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        // No I/O permission bitmap: point past the segment limit.
        iomap_base: core::mem::size_of::<Tss>() as u16,
    };
}

/// The GDT: null + 4 segment descriptors + a 16-byte (two-slot) TSS descriptor.
static mut GDT: [u64; 7] = [0; 7];
static mut TSS: Tss = Tss::EMPTY;

/// A small boot/double-fault kernel stack: the default `RSP0` before any user task runs, and
/// the `#DF` IST1 stack. 16 KiB, 16-aligned.
#[repr(C, align(16))]
struct KStack([u8; 16 * 1024]);
static mut DF_STACK: KStack = KStack([0; 16 * 1024]);
static mut RSP0_STACK: KStack = KStack([0; 16 * 1024]);

#[repr(C, packed)]
struct Gdtr {
    limit: u16,
    base: u64,
}

/// A 64-bit code/data segment descriptor with the given access byte. Base and limit are
/// ignored in long mode; `L` (bit 53) marks a 64-bit code segment.
const fn segment(access: u8, long_code: bool) -> u64 {
    let mut d: u64 = 0;
    d |= (access as u64) << 40;
    d |= 1 << 47; // present
    if long_code {
        d |= 1 << 53; // L: 64-bit code segment
    }
    d
}

/// Build the GDT (including the TSS descriptor from the static TSS's address), load it,
/// reload all segment registers and `CS`, and load the task register. After this the port
/// runs on its own descriptors.
pub fn init() {
    // Access bytes: P|DPL|S|type. 0x9A = code r/x DPL0, 0x92 = data r/w DPL0,
    // 0xFA = code r/x DPL3, 0xF2 = data r/w DPL3.
    let tss_base = &raw const TSS as u64;
    let tss_limit = (core::mem::size_of::<Tss>() - 1) as u64;
    // 64-bit TSS (system) descriptor, type 0x9 (available), spread across two slots.
    let tss_low: u64 = (tss_limit & 0xFFFF)
        | ((tss_base & 0xFF_FFFF) << 16)
        | (0x9 << 40)
        | (1 << 47) // present
        | (((tss_limit >> 16) & 0xF) << 48)
        | (((tss_base >> 24) & 0xFF) << 56);
    let tss_high: u64 = tss_base >> 32;

    // SAFETY: single-threaded boot setup writing our own static tables, then loading them and
    // reloading the segment registers to the new descriptors.
    unsafe {
        TSS.rsp[0] = (&raw const RSP0_STACK as u64) + core::mem::size_of::<KStack>() as u64;
        TSS.ist[0] = (&raw const DF_STACK as u64) + core::mem::size_of::<KStack>() as u64;

        let gdt = &raw mut GDT;
        (*gdt)[0] = 0;
        (*gdt)[1] = segment(0x9A, true); // kernel code
        (*gdt)[2] = segment(0x92, false); // kernel data
        (*gdt)[3] = segment(0xF2, false); // user data
        (*gdt)[4] = segment(0xFA, true); // user code
        (*gdt)[5] = tss_low;
        (*gdt)[6] = tss_high;

        let gdtr = Gdtr { limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16, base: gdt as u64 };
        asm!("lgdt [{}]", in(reg) &gdtr, options(readonly, nostack, preserves_flags));

        // Reload data segment registers to the flat kernel-data selector (fs/gs to null).
        asm!(
            "mov ds, {d:x}",
            "mov es, {d:x}",
            "mov ss, {d:x}",
            "xor {z:e}, {z:e}",
            "mov fs, {z:x}",
            "mov gs, {z:x}",
            d = in(reg) KERNEL_DATA,
            z = out(reg) _,
            options(nostack, preserves_flags),
        );
        // Reload CS via a far return (`retfq`): push the new selector and a return target.
        asm!(
            "lea {tmp}, [rip + 2f]",
            "push {sel}",
            "push {tmp}",
            "retfq",
            "2:",
            sel = in(reg) KERNEL_CODE as u64,
            tmp = out(reg) _,
            options(preserves_flags),
        );
        // Load the task register with the TSS selector.
        asm!("ltr {0:x}", in(reg) TSS_SEL, options(nostack, preserves_flags));
    }
}

/// Publish `top` as `RSP0`: the kernel stack the CPU switches to on the next trap from ring 3.
/// Called on each switch into a user task with that task's private kernel-stack top.
pub fn set_kernel_stack(top: u64) {
    // SAFETY: a single aligned 64-bit write into our static TSS; `RSP0` is read by the CPU
    // only on a privilege-raising trap, which cannot occur mid-write on this core.
    unsafe {
        TSS.rsp[0] = top;
    }
}
