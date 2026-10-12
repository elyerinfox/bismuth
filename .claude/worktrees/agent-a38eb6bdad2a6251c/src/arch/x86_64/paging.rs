//! Page-table edits for ring-3 isolation, over the bootloader's existing long-mode tables.
//!
//! We do not build or own address spaces here (a single address space is the first cut; the
//! per-domain `CR3` model is the documented scale-up). We only **narrow** access: the
//! bootloader maps the whole kernel Supervisor-only, and we open exactly the pages a ring-3
//! task must reach — the kernel's code and read-only data (so an unprivileged task can
//! execute the shared kernel text and the `user::` syscall shims, exactly as an ARM
//! unprivileged task runs from shared RO-X flash), plus that task's own stack.
//!
//! Which kernel pages are code vs. read-only data vs. writable state is already encoded in
//! the page tables: the bootloader set `NX`/`RW` from each ELF segment's flags. So the
//! classification needs no linker symbols — we read those bits and flip only `U/S`:
//!
//! | existing bits        | section   | action              |
//! |----------------------|-----------|---------------------|
//! | executable (NX = 0)  | `.text`   | open User (RO-X)    |
//! | NX = 1, RW = 0       | `.rodata` | open User (RO)      |
//! | NX = 1, RW = 1       | `.data`/`.bss` | leave Supervisor (hidden from ring 3) |
//!
//! A task's own stack is `RW`/`NX` kernel `.bss`, so it is left Supervisor by the pass above
//! and opened per task with [`open_user_range`] when the task first runs.
//!
//! Classification: L0 port · x86-64 paging · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const PAGE: u64 = 4096;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
/// Physical frame address held in a page-table entry (bits 12..=51).
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Virtual-address base at which the bootloader direct-maps all physical memory, so a
/// physical page-table frame can be read and written. Recorded by [`init`].
static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Record the bootloader's physical-memory map offset. Must be called (with a real offset)
/// before any other function here; without it, `translate`/edits are no-ops that report
/// failure, so isolation set-up fails closed rather than scribbling on the wrong memory.
pub fn init(physical_memory_offset: u64) {
    PHYS_OFFSET.store(physical_memory_offset, Ordering::Relaxed);
}

/// Whether paging edits are available (the physical-memory map offset was recorded).
pub fn ready() -> bool {
    PHYS_OFFSET.load(Ordering::Relaxed) != 0
}

/// Pointer to a page-table frame through the physical-memory direct map.
fn table(phys: u64) -> *mut u64 {
    (PHYS_OFFSET.load(Ordering::Relaxed) + (phys & ADDR_MASK)) as *mut u64
}

fn cr3() -> u64 {
    let v: u64;
    // SAFETY: reading CR3 is side-effect free.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Invalidate the whole TLB by reloading CR3 (after a batch of edits).
fn flush_tlb() {
    // SAFETY: reloading CR3 with its current value only flushes the TLB.
    unsafe { asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _, options(nostack, preserves_flags)) };
}

/// The leaf entry (and its level: 1 = 4 KiB, 2 = 2 MiB huge, 3 = 1 GiB huge) mapping `vaddr`,
/// plus pointers to the intermediate entries walked to reach it. `None` if `vaddr` is
/// unmapped or the physical-memory map is not set up.
struct Walk {
    /// Entry pointers from the top level down to (and including) the leaf.
    chain: [*mut u64; 4],
    /// Number of valid entries in `chain`.
    depth: usize,
}

fn walk(vaddr: u64) -> Option<Walk> {
    if !ready() {
        return None;
    }
    let idx = [
        ((vaddr >> 39) & 0x1FF) as usize,
        ((vaddr >> 30) & 0x1FF) as usize,
        ((vaddr >> 21) & 0x1FF) as usize,
        ((vaddr >> 12) & 0x1FF) as usize,
    ];
    let mut frame = cr3() & ADDR_MASK;
    let mut chain = [core::ptr::null_mut(); 4];
    for level in 0..4 {
        let entry = unsafe { table(frame).add(idx[level]) };
        chain[level] = entry;
        // SAFETY: `entry` points into a present page-table frame via the direct map.
        let val = unsafe { entry.read_volatile() };
        if val & PRESENT == 0 {
            return None;
        }
        // A huge page at the PDPT (1 GiB) or PD (2 MiB) level is itself the leaf.
        if level >= 1 && level <= 2 && val & HUGE != 0 {
            return Some(Walk { chain, depth: level + 1 });
        }
        if level == 3 {
            return Some(Walk { chain, depth: 4 });
        }
        frame = val & ADDR_MASK;
    }
    None
}

/// Set the `U/S` bit on every entry of a walk, down to the leaf, so a ring-3 access reaches
/// the page (the effective permission is the AND of `U/S` across all levels). Intermediate
/// entries opened this way still gate on each leaf's own `U/S`, so pages we do not open under
/// the same table stay supervisor-only.
fn open(w: &Walk) {
    for &e in &w.chain[..w.depth] {
        // SAFETY: `e` is a present entry reached by `walk`; we set only the U/S bit.
        unsafe { e.write_volatile(e.read_volatile() | USER) };
    }
}

/// Open the kernel's executable and read-only pages to ring 3 (code so it can run the shared
/// kernel text, rodata so it can read constants), while leaving writable kernel state
/// supervisor-only. `start`/`len` bound the kernel image in virtual memory
/// (`boot_info.kernel_image_offset` / `kernel_len`). Flushes the TLB when done.
pub fn open_kernel_text(start: u64, len: u64) {
    let mut v = start & !(PAGE - 1);
    let end = start + len;
    while v < end {
        if let Some(w) = walk(v) {
            // SAFETY: leaf reached by `walk`.
            let leaf = unsafe { w.chain[w.depth - 1].read_volatile() };
            let executable = leaf & NO_EXECUTE == 0;
            let read_only = leaf & WRITABLE == 0;
            if executable || read_only {
                open(&w);
            }
        }
        v += PAGE;
    }
    flush_tlb();
}

/// Whether every page in `[addr, end)` is User-readable **and read-only** — i.e. the kernel's
/// text/rodata we opened to ring 3, never writable kernel state (which stays supervisor) and
/// never a task stack (User but writable). Used to validate read-only user pointers at the
/// syscall boundary (string literals, constants) without being tricked into reading kernel
/// RAM on a task's behalf.
pub fn is_user_ro(addr: usize, end: usize) -> bool {
    if !ready() || end <= addr {
        return false;
    }
    let mut v = (addr as u64) & !(PAGE - 1);
    let last = (end as u64 - 1) & !(PAGE - 1);
    loop {
        match walk(v) {
            Some(w) => {
                // SAFETY: leaf reached by `walk`.
                let leaf = unsafe { w.chain[w.depth - 1].read_volatile() };
                if leaf & USER == 0 || leaf & WRITABLE != 0 {
                    return false;
                }
            }
            None => return false,
        }
        if v == last {
            return true;
        }
        v += PAGE;
    }
}

/// Open a running task's own stack (`RW`/`NX` kernel `.bss`) to ring 3. Flushes the TLB.
/// Returns whether every page in the range was present and opened (fails closed otherwise).
pub fn open_user_range(start: u64, len: u64) -> bool {
    let mut v = start & !(PAGE - 1);
    let end = start + len;
    let mut ok = true;
    while v < end {
        match walk(v) {
            Some(w) => open(&w),
            None => ok = false,
        }
        v += PAGE;
    }
    flush_tlb();
    ok
}
