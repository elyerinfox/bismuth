//! CP15 short-descriptor translation tables for USR-mode (EL0-equivalent) isolation — the
//! AArch32 analog of `aarch64/paging.rs`. Stage 1/2 used flat 1 MiB sections with the domain
//! as *manager* (no permission checks). Stage 3 switches domain 0 to *client* (so the
//! `AP`/`APX`/`XN` bits are enforced) and refines the kernel-image region to 4 KiB pages:
//!
//! | region          | access            | AP / APX / XN                 |
//! |-----------------|-------------------|-------------------------------|
//! | kernel `.text`  | USR **RO + exec** | AP=10, APX=1, XN=0 (priv+USR RO, executable) |
//! | kernel `.rodata`| USR **RO**        | AP=10, APX=1, XN=1            |
//! | kernel data/bss | **priv-only** RW  | AP=01, APX=0, XN=1            |
//! | a task's stack  | USR **RW** (opened)| AP=11, APX=0, XN=1           |
//!
//! So a USR-mode task runs the shared kernel text, reads constants, uses its own stack — and
//! any USR access to kernel data takes an abort that kills the domain (handled in `vectors`).
//!
//! Classification: L0 port · cortex-a paging · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MIB: u32 = 0x10_0000;
const PAGE: u32 = 0x1000;

/// Peripheral base: Normal RAM below, Device at/above. BCM2836/7 vs BCM2835 (ARMv6).
#[cfg(not(feature = "armv6"))]
const PERIPH_BASE: u32 = 0x3F00_0000;
#[cfg(feature = "armv6")]
const PERIPH_BASE: u32 = 0x2000_0000;

// Short-descriptor section bits.
const SEC_AP_PRIV_RW: u32 = 0b01 << 10;
const SEC_TEX_NORMAL: u32 = 0b001 << 12;
const SEC_C: u32 = 1 << 3;
const SEC_B: u32 = 1 << 2;
const SEC_S: u32 = 1 << 16;
const SEC_XN: u32 = 1 << 4;
const SEC_TYPE: u32 = 0b10;
// Small-page bits.
const PG_TYPE: u32 = 0b10; // bit1 set, bit0 = XN
const PG_C: u32 = 1 << 3;
const PG_B: u32 = 1 << 2;
const PG_TEX_NORMAL: u32 = 0b001 << 6;
const PG_S: u32 = 1 << 10;
const PG_APX: u32 = 1 << 9;
// AP[1:0] at bits[5:4].
const AP_PRIV_RW: u32 = 0b01 << 4; // priv RW, USR none
const AP_USR_RO: u32 = 0b10 << 4; // priv RW/RO, USR RO
const AP_USR_RW: u32 = 0b11 << 4; // priv RW, USR RW

#[repr(C, align(16384))]
struct L1Table([u32; 4096]);
#[repr(C, align(1024))]
struct L2Table([u32; 256]);

static mut L1: L1Table = L1Table([0; 4096]);
/// Level-2 tables for the kernel image (one per 1 MiB section it spans). 8 MiB of coverage.
const L2_COUNT: usize = 8;
static mut L2: [L2Table; L2_COUNT] = [const { L2Table([0; 256]) }; L2_COUNT];

static READY: AtomicBool = AtomicBool::new(false);
/// 1 MiB-aligned base of the kernel image's section range (for the page-table walkers).
static IMAGE_SEC_BASE: AtomicUsize = AtomicUsize::new(0);
static IMAGE_SEC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    static __image_start: u8;
    static __image_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
}

const fn section(base: u32, device: bool) -> u32 {
    if device {
        base | SEC_AP_PRIV_RW | SEC_B | SEC_XN | SEC_TYPE
    } else {
        base | SEC_TEX_NORMAL | SEC_AP_PRIV_RW | SEC_C | SEC_B | SEC_S | SEC_XN | SEC_TYPE
    }
}

/// A 4 KiB Normal small page with explicit access/exec permissions.
const fn page(base: u32, ap: u32, apx: bool, xn: bool) -> u32 {
    let mut d = (base & !(PAGE - 1)) | PG_S | PG_TEX_NORMAL | ap | PG_C | PG_B | PG_TYPE;
    if apx {
        d |= PG_APX;
    }
    if xn {
        d |= 1; // XN is bit 0 of a small page
    }
    d
}

fn barrier() {
    #[cfg(not(feature = "armv6"))]
    // SAFETY: ARMv7-A data + instruction synchronisation barriers.
    unsafe {
        asm!("dsb", "isb", options(nostack, preserves_flags));
    }
    #[cfg(feature = "armv6")]
    // SAFETY: ARMv6 CP15 DSB (c7,c10,4) + prefetch flush (c7,c5,4) — no dsb/isb mnemonics.
    unsafe {
        asm!("mcr p15, 0, {z}, c7, c10, 4", "mcr p15, 0, {z}, c7, c5, 4", z = in(reg) 0u32, options(nostack, preserves_flags));
    }
}

/// Build the two-level identity map and enable the MMU with domain 0 as *client* (so USR
/// permissions are enforced). Called from `_start`'s Rust boot.
pub fn build() {
    let image_start = (&raw const __image_start) as u32;
    let image_end = (&raw const __image_end) as u32;
    let text_start = (&raw const __text_start) as u32;
    let text_end = (&raw const __text_end) as u32;
    let rodata_start = (&raw const __rodata_start) as u32;
    let rodata_end = (&raw const __rodata_end) as u32;

    let sec_base = image_start & !(MIB - 1);
    let sec_end = (image_end + MIB - 1) & !(MIB - 1);
    let sec_count = ((sec_end - sec_base) / MIB) as usize;
    IMAGE_SEC_BASE.store(sec_base as usize, Ordering::Relaxed);
    IMAGE_SEC_COUNT.store(sec_count.min(L2_COUNT), Ordering::Relaxed);

    let l1 = &raw mut L1;
    let l2 = &raw mut L2;
    // SAFETY: single-core boot, MMU off; fill our own static tables, program CP15, enable MMU.
    unsafe {
        let mut i = 0usize;
        while i < 4096 {
            let va = (i as u32) * MIB;
            if va >= sec_base && va < sec_end && ((va - sec_base) / MIB) < (L2_COUNT as u32) {
                let idx = ((va - sec_base) / MIB) as usize;
                let l2t = &raw mut (*l2)[idx];
                fill_l2(&mut *l2t, va, text_start, text_end, rodata_start, rodata_end);
                // L1 coarse descriptor → L2 table, domain 0.
                (*l1).0[i] = (l2t as u32 & !0x3FF) | 0b01;
            } else {
                (*l1).0[i] = section(va, va >= PERIPH_BASE);
            }
            i += 1;
        }
        let ttbr0 = l1 as u32;
        asm!(
            "mcr p15, 0, {zero}, c2, c0, 2",  // TTBCR = 0
            "mcr p15, 0, {ttbr}, c2, c0, 0",  // TTBR0
            "mcr p15, 0, {dacr}, c3, c0, 0",  // DACR: domain 0 = client (enforce AP)
            "mcr p15, 0, {zero}, c8, c7, 0",  // invalidate TLB
            zero = in(reg) 0u32,
            ttbr = in(reg) ttbr0,
            dacr = in(reg) 0x1u32,
            options(nostack, preserves_flags),
        );
        barrier();
        let mut sctlr: u32;
        asm!("mrc p15, 0, {}, c1, c0, 0", out(reg) sctlr, options(nomem, nostack, preserves_flags));
        sctlr |= 1 | (1 << 2) | (1 << 12) | (1 << 23); // M | C | I | XP (ARMv7 short descriptors)
        asm!("mcr p15, 0, {}, c1, c0, 0", in(reg) sctlr, options(nostack, preserves_flags));
        barrier();
    }
    READY.store(true, Ordering::Release);
}

fn fill_l2(t: &mut L2Table, base: u32, text_s: u32, text_e: u32, ro_s: u32, ro_e: u32) {
    let mut p = 0usize;
    while p < 256 {
        let va = base + p as u32 * PAGE;
        let d = if va >= text_s && va < text_e {
            page(va, AP_USR_RO, true, false) // text: USR RO + exec
        } else if va >= ro_s && va < ro_e {
            page(va, AP_USR_RO, true, true) // rodata: USR RO
        } else {
            page(va, AP_PRIV_RW, false, true) // data/bss/stacks: priv-only RW
        };
        t.0[p] = d;
        p += 1;
    }
}

pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Pointer to the level-2 page entry mapping `va`, if `va` is in the kernel-image (4 KiB-page)
/// region; `None` otherwise.
fn l2_entry(va: u32) -> Option<*mut u32> {
    let base = IMAGE_SEC_BASE.load(Ordering::Relaxed) as u32;
    let count = IMAGE_SEC_COUNT.load(Ordering::Relaxed) as u32;
    if va < base || va >= base + count * MIB {
        return None;
    }
    let sec = ((va - base) / MIB) as usize;
    let pg = ((va & (MIB - 1)) / PAGE) as usize;
    // SAFETY: reading our own static L2 tables.
    unsafe { Some((&raw mut (*(&raw mut L2))[sec]).cast::<u32>().add(pg)) }
}

fn flush_tlb() {
    // SAFETY: invalidate the whole TLB + barriers.
    unsafe {
        asm!("mcr p15, 0, {z}, c8, c7, 0", z = in(reg) 0u32, options(nostack, preserves_flags));
    }
    barrier();
}

/// Open a task's own stack to USR mode (RW, no exec). Returns whether every page was mapped.
pub fn open_user_range(start: u32, len: u32) -> bool {
    let mut v = start & !(PAGE - 1);
    let end = start + len;
    let mut ok = true;
    while v < end {
        match l2_entry(v) {
            Some(e) => {
                // SAFETY: `e` is a level-2 entry in our tables; set AP = USR RW, clear APX.
                let d = unsafe { e.read_volatile() };
                let na = (d & !(0b11 << 4) & !PG_APX) | AP_USR_RW;
                unsafe { e.write_volatile(na) };
            }
            None => ok = false,
        }
        v += PAGE;
    }
    flush_tlb();
    ok
}

/// Whether every page in `[addr, end)` is USR **read-only** (AP[1:0] == 10) — kernel
/// text/rodata, never writable kernel state or a task stack. Validates read-only user
/// pointers at the syscall boundary.
pub fn is_user_ro(addr: usize, end: usize) -> bool {
    if end <= addr {
        return false;
    }
    let mut v = (addr as u32) & !(PAGE - 1);
    let last = (end as u32 - 1) & !(PAGE - 1);
    loop {
        match l2_entry(v) {
            Some(e) => {
                // SAFETY: `e` is a level-2 entry in our tables.
                let d = unsafe { e.read_volatile() };
                if d & 0b11 == 0 || (d & (0b11 << 4)) != AP_USR_RO {
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
