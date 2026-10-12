//! Translation tables for EL0 isolation (the aarch64 analog of `x86_64/paging.rs`).
//!
//! The stage-1 boot map used coarse 1 GiB blocks (everything EL1-only). For EL0 user tasks
//! we need per-page control over the kernel image region, so [`build`] lays out a three-level
//! identity map: a level-1 table (1 GiB entries), a level-2 table for the first 1 GiB of RAM
//! (2 MiB entries), and level-3 tables (4 KiB pages) covering the kernel image. AArch64
//! `AP[2:1]`/`UXN`/`PXN` give exactly the x86 `U/S`+`NX` story:
//!
//! | region            | access              | AP / XN                        |
//! |-------------------|---------------------|--------------------------------|
//! | kernel `.text`    | EL0 **RO + exec**   | `AP=11`, `UXN=0`, `PXN=0`      |
//! | kernel `.rodata`  | EL0 **RO**          | `AP=11`, `UXN=1`, `PXN=1`      |
//! | kernel data/bss   | **EL1-only** RW     | `AP=00`, `UXN=1`, `PXN=1`      |
//! | a task's own stack| EL0 **RW** (opened) | `AP=01`, `UXN=1`, `PXN=1`      |
//!
//! So an EL0 task runs the shared kernel text (like a Cortex-M unprivileged task runs from
//! RO-X flash), reads constants, uses its own stack — and an EL0 access to kernel data takes
//! a translation/permission abort, which kills the domain. Per-domain `TTBR0` + ASID is the
//! documented scale-up.
//!
//! Classification: L0 port · aarch64 paging · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::kernel::cell::IrqCell;

const PAGE: u64 = 4096;
const BLOCK_2M: u64 = 2 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;
/// Physical/virtual address bits [47:12] of a descriptor.
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// The 1 GiB that the kernel image occupies, recorded by [`build`] so the page-table walkers
/// know which level-1 entry leads to the 4 KiB-page (image) region.
static IMAGE_GIB_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// Descriptor bits.
const VALID: u64 = 1 << 0;
const TABLE_OR_PAGE: u64 = 1 << 1; // table (L1/L2) or page (L3): 0b11; block: 0b01
const AF: u64 = 1 << 10;
const SH_INNER: u64 = 0b11 << 8;
const AP_EL1_RW: u64 = 0b00 << 6;
const AP_EL0_RW: u64 = 0b01 << 6;
const AP_EL0_RO: u64 = 0b11 << 6;
const UXN: u64 = 1 << 54;
const PXN: u64 = 1 << 53;
const ATTR_NORMAL: u64 = 0 << 2;
const ATTR_DEVICE: u64 = 1 << 2;

#[repr(C, align(4096))]
struct Table([u64; 512]);

static mut L1: Table = Table([0; 512]);
static mut L2: Table = Table([0; 512]);
/// Level-3 tables for the kernel image region. 16 × 2 MiB = 32 MiB of 4 KiB-page coverage,
/// far more than any board image + its static stacks need.
const L3_COUNT: usize = 16;
static mut L3: [Table; L3_COUNT] = [const { Table([0; 512]) }; L3_COUNT];

static READY: AtomicBool = AtomicBool::new(false);

// ---- Per-domain EL0 ownership -------------------------------------------------------------
//
// The kernel image's text/rodata are shared EL0-RO(-X) for every domain, but a task's own
// EL0 pages (its stack, or a loaded Linux process's buffer) belong to ONE security domain.
// We record each opened range + its owner here, and on every context switch promote only the
// incoming domain's ranges to EL0 while demoting the outgoing domain's to EL1-only. So two
// EL0 domains can be live at once (e.g. concurrent Linux containers) without either being able
// to read or write the other's memory — the stage-1 analog of per-domain `TTBR0`, done by
// flipping `AP` bits in the single shared table (cheaper than per-domain tables for our scale).

/// Sentinel meaning "no EL0 domain is currently promoted" (matches `kernel::NIL`).
const NO_DOMAIN: u8 = u8::MAX;
/// Maximum number of distinct owned EL0 ranges (per-task stacks + Linux code/data regions).
const MAX_OWNED: usize = 24;

#[derive(Copy, Clone)]
struct Owned {
    start: u64,
    len: u64,
    domain: u8,
    /// `true` → promote as EL0 read + execute (loaded code); `false` → EL0 read-write (stack/data).
    exec: bool,
    used: bool,
}

const EMPTY_OWNED: Owned = Owned { start: 0, len: 0, domain: NO_DOMAIN, exec: false, used: false };

static OWNED: IrqCell<[Owned; MAX_OWNED]> = IrqCell::new([EMPTY_OWNED; MAX_OWNED]);
/// The domain whose EL0 ranges are currently promoted (so a switch to the same domain is a no-op).
static CURRENT_EL0: AtomicU8 = AtomicU8::new(NO_DOMAIN);

unsafe extern "C" {
    static __image_start: u8;
    static __image_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
}

/// A block descriptor (L1 1 GiB / L2 2 MiB): Device or Normal, EL1-only, non-exec.
const fn block(pa: u64, device: bool) -> u64 {
    let attr = if device { ATTR_DEVICE } else { ATTR_NORMAL };
    let sh = if device { 0 } else { SH_INNER };
    (pa & ADDR_MASK) | AF | sh | AP_EL1_RW | attr | UXN | PXN | VALID
}

/// A 4 KiB page descriptor with explicit access/exec permissions (Normal memory).
const fn page(pa: u64, ap: u64, exec_el0: bool, exec_el1: bool) -> u64 {
    let mut d = (pa & ADDR_MASK) | AF | SH_INNER | ap | ATTR_NORMAL | TABLE_OR_PAGE | VALID;
    if !exec_el0 {
        d |= UXN;
    }
    if !exec_el1 {
        d |= PXN;
    }
    d
}

/// A table descriptor pointing at the next-level table.
fn table(next: u64) -> u64 {
    (next & ADDR_MASK) | TABLE_OR_PAGE | VALID
}

/// Build the identity map from the board's memory layout and enable the MMU + caches. Called
/// once from `_start`'s Rust boot. `ram`/`periph` are `(base, size)`; RAM is mapped Normal
/// write-back, peripherals Device, and the 1 GiB holding the kernel image is refined to 4 KiB
/// pages for EL0 isolation. Works for both the `virt` layout (RAM high, peripherals low) and
/// the Pi layout (RAM low, peripherals high at 0xFE00_0000 / GIC 0xFF84_xxxx).
pub fn build(ram: (u64, u64), periph: (u64, u64)) {
    // Addresses of linker-defined symbols (taking the address reads nothing).
    let image_start = (&raw const __image_start) as u64;
    let image_end = (&raw const __image_end) as u64;
    let text_start = (&raw const __text_start) as u64;
    let text_end = (&raw const __text_end) as u64;
    let rodata_start = (&raw const __rodata_start) as u64;
    let rodata_end = (&raw const __rodata_end) as u64;

    let image_gib = image_start & !(GIB - 1);
    IMAGE_GIB_BASE.store(image_gib, Ordering::Relaxed);
    let fine_start = image_start & !(BLOCK_2M - 1);
    let fine_end = (image_end + BLOCK_2M - 1) & !(BLOCK_2M - 1);

    let in_ram = |a: u64| a >= ram.0 && a < ram.0 + ram.1;
    let in_periph = |a: u64| a >= periph.0 && a < periph.0 + periph.1;

    let l1 = &raw mut L1;
    let l2 = &raw mut L2;
    let l3 = &raw mut L3;
    // SAFETY: single-core boot, MMU off; we fill our own static tables, then enable the MMU.
    unsafe {
        // Level 1: 512 × 1 GiB. The image's GiB is refined through L2; every other GiB is a
        // Normal (RAM) or Device (peripheral) block, or left invalid.
        let mut g = 0usize;
        while g < 512 {
            let ga = g as u64 * GIB;
            if ga == image_gib {
                (*l1).0[g] = table(l2 as u64);
            } else if in_ram(ga) {
                (*l1).0[g] = block(ga, false);
            } else if in_periph(ga) {
                (*l1).0[g] = block(ga, true);
            } else {
                (*l1).0[g] = 0;
            }
            g += 1;
        }

        // Level 2 for the image's GiB: 512 × 2 MiB, with the image window refined to 4 KiB.
        let mut i = 0usize;
        while i < 512 {
            let va = image_gib + i as u64 * BLOCK_2M;
            if va >= fine_start && va < fine_end {
                let idx = ((va - fine_start) / BLOCK_2M) as usize;
                let l3t = &raw mut (*l3)[idx];
                fill_l3(&mut *l3t, va, text_start, text_end, rodata_start, rodata_end);
                (*l2).0[i] = table(l3t as u64);
            } else if in_ram(va) {
                (*l2).0[i] = block(va, false);
            } else if in_periph(va) {
                (*l2).0[i] = block(va, true);
            } else {
                (*l2).0[i] = 0;
            }
            i += 1;
        }

        program_and_enable(l1 as u64);
    }
    READY.store(true, Ordering::Release);
}

/// Fill one level-3 table (the 2 MiB window at `base`) page-by-page: kernel text as EL0 RO-X,
/// rodata as EL0 RO, everything else (data/bss/stacks, and any RAM below/above the image in
/// this window) as EL1-only RW.
fn fill_l3(t: &mut Table, base: u64, text_s: u64, text_e: u64, ro_s: u64, ro_e: u64) {
    let mut p = 0usize;
    while p < 512 {
        let va = base + p as u64 * PAGE;
        let d = if va >= text_s && va < text_e {
            page(va, AP_EL0_RO, true, true) // text: EL0 RO + exec
        } else if va >= ro_s && va < ro_e {
            page(va, AP_EL0_RO, false, false) // rodata: EL0 RO, no exec
        } else {
            page(va, AP_EL1_RW, false, false) // data/bss/stacks: EL1-only RW
        };
        t.0[p] = d;
        p += 1;
    }
}

fn program_and_enable(ttbr0: u64) {
    let mair: u64 = 0x04FF; // Attr0 = Normal WB, Attr1 = Device-nGnRE
    let tcr: u64 = 25 | (1 << 8) | (1 << 10) | (0b11 << 12) | (1 << 23) | (0b010 << 32);
    // SAFETY: program the translation registers, invalidate the TLB, and enable the MMU.
    unsafe {
        asm!(
            "msr mair_el1, {mair}",
            "msr tcr_el1, {tcr}",
            "msr ttbr0_el1, {ttbr}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            ttbr = in(reg) ttbr0,
            options(nostack, preserves_flags),
        );
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
        sctlr |= 1 | (1 << 2) | (1 << 12); // M | C | I
        asm!("msr sctlr_el1, {}", "isb", in(reg) sctlr, options(nostack, preserves_flags));
    }
}

/// Whether the per-page EL0 isolation tables are up (gates `supports_user_tasks`).
pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Pointer to the level-3 entry mapping `va`, if `va` is in the 4 KiB-page (image) region.
/// `None` if `va` falls in a 2 MiB block (outside the image) or is unmapped.
fn l3_entry(va: u64) -> Option<*mut u64> {
    let image_gib = IMAGE_GIB_BASE.load(Ordering::Relaxed);
    if va < image_gib || va >= image_gib + GIB {
        return None; // only the kernel-image GiB is refined to 4 KiB pages
    }
    // SAFETY: reading our own static tables.
    unsafe {
        let l2i = ((va - image_gib) / BLOCK_2M) as usize;
        let l2e = (*(&raw const L2)).0[l2i];
        if l2e & TABLE_OR_PAGE == 0 || l2e & VALID == 0 {
            return None; // a 2 MiB block, not a table
        }
        let l3t = (l2e & ADDR_MASK) as *mut u64;
        let l3i = ((va & (BLOCK_2M - 1)) / PAGE) as usize;
        Some(l3t.add(l3i))
    }
}

/// Flush the whole TLB after descriptor edits.
fn flush_tlb() {
    // SAFETY: TLB maintenance with the required barriers.
    unsafe {
        asm!("dsb ishst", "tlbi vmalle1", "dsb ish", "isb", options(nostack, preserves_flags));
    }
}

/// Set every 4 KiB page in `[start, start+len)` to `ap`, with EL0 execute per `exec_el0` (EL1
/// never executes user pages). Returns whether every page was a mapped 4 KiB page. Does not flush.
fn set_pages(start: u64, len: u64, ap: u64, exec_el0: bool) -> bool {
    let mut v = start & !(PAGE - 1);
    let end = start + len;
    let mut ok = true;
    while v < end {
        match l3_entry(v) {
            Some(e) => {
                // SAFETY: `e` is a level-3 entry in our tables.
                let d = unsafe { e.read_volatile() };
                let mut na = (d & !(0b11 << 6) & !UXN & !PXN) | ap | PXN; // EL1 never executes
                if !exec_el0 {
                    na |= UXN;
                }
                unsafe { e.write_volatile(na) };
            }
            None => ok = false,
        }
        v += PAGE;
    }
    ok
}

/// Promote one owned range to its owner-visible EL0 permissions.
fn promote(o: &Owned) {
    if o.exec {
        set_pages(o.start, o.len, AP_EL0_RO, true); // EL0 read + execute (loaded code)
    } else {
        set_pages(o.start, o.len, AP_EL0_RW, false); // EL0 read-write (stack/data)
    }
}

/// Demote one owned range to EL1-only RW (invisible + inaccessible to EL0).
fn demote(o: &Owned) {
    set_pages(o.start, o.len, AP_EL1_RW, false);
}

/// Record an owned EL0 range for `domain` (replacing any existing record for the same start),
/// and set its pages now: promoted if its domain is the one currently running at EL0, otherwise
/// demoted (it becomes visible only when the scheduler switches that domain in).
fn record(start: u64, len: u64, domain: u8, exec: bool) {
    let o = Owned { start, len, domain, exec, used: true };
    OWNED.lock(|t| {
        // Reuse a slot with the same start, else the first free slot.
        let slot = t.iter().position(|e| e.used && e.start == start).or_else(|| t.iter().position(|e| !e.used));
        if let Some(i) = slot {
            t[i] = o;
        }
    });
    if domain == CURRENT_EL0.load(Ordering::Relaxed) {
        promote(&o);
    } else {
        demote(&o);
    }
    flush_tlb();
}

/// Open a task's own stack to EL0 read-write, owned by `domain`. Returns whether every page was
/// a mapped 4 KiB page (fails closed otherwise).
pub fn open_user_range(start: u64, len: u64, domain: u8) -> bool {
    let ok = l3_entry(start).is_some() && l3_entry(start + len - 1).is_some();
    record(start, len, domain, false);
    ok
}

/// Open a range as EL0 **read + execute**, owned by `domain` — a loaded program's code placed in
/// a kernel-image `.bss` buffer (the Linux-ABI loader). The region must already hold the code
/// (written while EL1-RW). Fails closed off-image.
#[cfg(feature = "linux-abi")]
pub fn open_user_exec(start: u64, len: u64, domain: u8) -> bool {
    let ok = l3_entry(start).is_some() && l3_entry(start + len - 1).is_some();
    record(start, len, domain, true);
    ok
}

/// Release every owned range overlapping `[start, start+len)` and reset those pages to EL1-only
/// RW — so the kernel can rewrite the buffer (the Linux loader's wipe/copy) and a reused buffer
/// slot drops its previous owner. Fails-open (no-op) off-image.
#[cfg(feature = "linux-abi")]
pub fn release_el0_range(start: u64, len: u64) {
    let end = start + len;
    OWNED.lock(|t| {
        for e in t.iter_mut() {
            if e.used && e.start < end && e.start + e.len > start {
                *e = EMPTY_OWNED;
            }
        }
    });
    set_pages(start, len, AP_EL1_RW, false);
    flush_tlb();
}

/// Switch the promoted EL0 domain to `next` on a context switch: demote the outgoing domain's
/// ranges and promote the incoming domain's, so only `next`'s EL0 memory is reachable from EL0.
/// A no-op when the domain is unchanged. Called from the aarch64 context-switch path with the
/// kernel lock held.
pub fn switch_el0(next: u8) {
    let prev = CURRENT_EL0.load(Ordering::Relaxed);
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
    CURRENT_EL0.store(next, Ordering::Relaxed);
    flush_tlb();
}

/// Whether every page in `[addr, end)` is EL0 **read-only** (`AP = 11`) — kernel text/rodata,
/// never writable kernel state or a task stack. Validates read-only user pointers at the
/// syscall boundary.
pub fn is_user_ro(addr: usize, end: usize) -> bool {
    if end <= addr {
        return false;
    }
    let mut v = (addr as u64) & !(PAGE - 1);
    let last = (end as u64 - 1) & !(PAGE - 1);
    loop {
        match l3_entry(v) {
            Some(e) => {
                // SAFETY: `e` is a level-3 entry in our tables.
                let d = unsafe { e.read_volatile() };
                if d & VALID == 0 || (d & (0b11 << 6)) != AP_EL0_RO {
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
