//! A Linux process's `brk`/`mmap` arena: brk grows a heap up, mmap bump-allocates down, and they
//! fail when they would meet.

#![cfg(feature = "linux-abi")]

use bismuth::compat::linux::load::Proc;

#[test]
fn brk_and_mmap_share_a_bounded_arena() {
    let start = 0x10_0000u64;
    let top = start + 0x10000; // 64 KiB arena
    let mut p = Proc::with_arena(start, top);

    // brk(0) queries the current break (the heap start); growing moves it.
    assert_eq!(p.brk(0), start as i64);
    assert_eq!(p.brk(start + 0x1000), (start + 0x1000) as i64);
    assert_eq!(p.brk(0), (start + 0x1000) as i64);

    // Anonymous mmap bump-allocates page-rounded chunks down from the top.
    let a = p.mmap(100, 0x22);
    assert_eq!(a as u64, top - 0x1000, "one page, from the top");
    let b = p.mmap(0x2000, 0x22);
    assert_eq!(b as u64, top - 0x3000, "two more pages below it");
    assert_ne!(a, b);

    // A non-anonymous map is refused.
    assert_eq!(p.mmap(0x1000, 0), -1);

    // Exhaust the arena, and brk cannot climb past the mmap cursor.
    assert_eq!(p.mmap(0x20000, 0x22), -1, "arena exhausted -> MAP_FAILED");
    let before = p.brk(0);
    assert_eq!(p.brk(top), before, "brk past the mmap region leaves the break unchanged");
}
