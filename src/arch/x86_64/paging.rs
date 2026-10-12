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
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::kernel::cell::IrqCell;

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

// ---- Per-domain ring-3 ownership ----------------------------------------------------------
//
// The kernel image's code/rodata are shared User-RO(-X) for every domain (so any ring-3 task
// can execute the shared kernel text + `user::` shims), but a task's own User pages (its stack)
// belong to ONE security domain. We record each opened range + its owner here, and on every
// context switch promote only the incoming domain's ranges to User while demoting the outgoing
// domain's to Supervisor-only. So two ring-3 domains can be live at once without either being
// able to read or write the other's memory — the stage-1 analog of per-domain `CR3`, done by
// flipping the leaf `U/S` bit in the single shared table (cheaper than per-domain tables here).
// Mirrors the aarch64 `OWNED`/`switch_el0` design.

/// Sentinel meaning "no ring-3 domain is currently promoted" (matches `kernel::NIL`).
const NO_DOMAIN: u8 = u8::MAX;
/// Maximum number of distinct owned User ranges (per-task stacks).
const MAX_OWNED: usize = 24;

#[derive(Copy, Clone)]
struct Owned {
    start: u64,
    len: u64,
    domain: u8,
    used: bool,
}

const EMPTY_OWNED: Owned = Owned { start: 0, len: 0, domain: NO_DOMAIN, used: false };

static OWNED: IrqCell<[Owned; MAX_OWNED]> = IrqCell::new([EMPTY_OWNED; MAX_OWNED]);
/// The domain whose User ranges are currently promoted (a switch to the same domain is a no-op).
static CURRENT_RING3: AtomicU8 = AtomicU8::new(NO_DOMAIN);

/// Set the leaf `U/S` bit across `[start, start+len)`: `user` opens each page to ring 3 (sets
/// `U/S` down the whole walk so the AND permits it), `!user` clears `U/S` on the **leaf only**
/// (so sibling pages sharing the intermediate tables keep their own state). No TLB flush.
fn set_user_pages(start: u64, len: u64, user: bool) {
    let mut v = start & !(PAGE - 1);
    let end = start + len;
    while v < end {
        if let Some(w) = walk(v) {
            if user {
                open(&w);
            } else {
                let leaf = w.chain[w.depth - 1];
                // SAFETY: `leaf` is a present entry reached by `walk`; we clear only the U/S bit.
                unsafe { leaf.write_volatile(leaf.read_volatile() & !USER) };
            }
        }
        v += PAGE;
    }
}

fn promote(o: &Owned) {
    set_user_pages(o.start, o.len, true);
}
fn demote(o: &Owned) {
    set_user_pages(o.start, o.len, false);
}

/// Record an owned User range for `domain` (replacing any existing record with the same start),
/// and set its pages now: promoted if its domain is the one currently running at ring 3, else
/// demoted (it becomes reachable only when the scheduler switches that domain in). Flushes.
fn record(start: u64, len: u64, domain: u8) {
    let o = Owned { start, len, domain, used: true };
    OWNED.lock(|t| {
        let slot = t.iter().position(|e| e.used && e.start == start).or_else(|| t.iter().position(|e| !e.used));
        if let Some(i) = slot {
            t[i] = o;
        }
    });
    if domain == CURRENT_RING3.load(Ordering::Relaxed) {
        promote(&o);
    } else {
        demote(&o);
    }
    flush_tlb();
}

/// Open a running task's own stack (`RW`/`NX` kernel `.bss`) to ring 3, owned by `domain`.
/// Flushes the TLB. Returns whether every page in the range was present (fails closed otherwise).
pub fn open_user_range(start: u64, len: u64, domain: u8) -> bool {
    let mut v = start & !(PAGE - 1);
    let end = start + len;
    let mut ok = true;
    while v < end {
        if walk(v).is_none() {
            ok = false;
        }
        v += PAGE;
    }
    record(start, len, domain);
    ok
}

/// Switch the promoted ring-3 domain to `next` on a context switch: demote the outgoing domain's
/// ranges and promote the incoming domain's, so only `next`'s User memory is reachable from ring
/// 3. A no-op when the domain is unchanged. Called from the x86 context-switch path.
pub fn switch_ring3(next: u8) {
    let prev = CURRENT_RING3.load(Ordering::Relaxed);
    if prev == next {
        return;
    }
    OWNED.lock(|t| {
        for e in t.iter() {
            if !e.used {
                continue;
            }
            if e.domain == prev {
                demote(e);
            }
            if e.domain == next {
                promote(e);
            }
        }
    });
    CURRENT_RING3.store(next, Ordering::Relaxed);
    flush_tlb();
}

/// Translate a kernel virtual address to its physical address by walking the page tables — the
/// physical (DMA) address a device must be given for a buffer in kernel memory (x86 does not
/// identity-map, unlike the aarch64 port). `None` if unmapped or the map offset is not set.
pub fn translate(vaddr: u64) -> Option<u64> {
    let w = walk(vaddr)?;
    // SAFETY: the leaf entry was reached by `walk` (present).
    let leaf = unsafe { w.chain[w.depth - 1].read_volatile() };
    let off_mask: u64 = match w.depth {
        4 => PAGE - 1,          // 4 KiB page
        3 => (1 << 21) - 1,     // 2 MiB huge page
        2 => (1 << 30) - 1,     // 1 GiB huge page
        _ => return None,
    };
    Some((leaf & ADDR_MASK & !off_mask) | (vaddr & off_mask))
}
