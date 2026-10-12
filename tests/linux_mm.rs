//! The Linux loader's `brk`/`mmap` arena: brk grows a heap up, mmap bump-allocates down, and they
//! fail when they would meet.

#![cfg(feature = "linux-abi")]

use bismuth::compat::linux::load::mm;
use bismuth::kernel::linuxabi::Outcome;

const BRK: u64 = 214;
const MMAP: u64 = 222;
const MUNMAP: u64 = 215;
const MAP_ANON_PRIV: u64 = 0x22;

fn mmap(len: u64) -> i64 {
    match mm::handle_mm(MMAP, [0, len, 3, MAP_ANON_PRIV, u64::MAX, 0]).unwrap() {
        Outcome::Return(v) => v,
        _ => panic!("mmap"),
    }
}
fn brk(req: u64) -> i64 {
    match mm::handle_mm(BRK, [req, 0, 0, 0, 0, 0]).unwrap() {
        Outcome::Return(v) => v,
        _ => panic!("brk"),
    }
}

#[test]
fn brk_and_mmap_share_a_bounded_arena() {
    let start = 0x10_0000u64;
    let top = start + 0x10000; // 64 KiB arena
    mm::init(start, top);

    // brk(0) queries the current break (the heap start).
    assert_eq!(brk(0), start as i64);
    // Grow the heap by 0x1000 and query again.
    assert_eq!(brk(start + 0x1000), (start + 0x1000) as i64);
    assert_eq!(brk(0), (start + 0x1000) as i64);

    // Anonymous mmap bump-allocates a page-rounded chunk down from the top.
    let a = mmap(100);
    assert_eq!(a as u64, top - 0x1000, "one page, from the top");
    let b = mmap(0x2000);
    assert_eq!(b as u64, top - 0x3000, "two more pages below it");
    assert_ne!(a, b);

    // A non-anonymous map is refused; munmap is accepted (no-op).
    assert_eq!(mm::handle_mm(MMAP, [0, 0x1000, 3, 0, u64::MAX, 0]).unwrap(), Outcome::Return(-1));
    assert_eq!(mm::handle_mm(MUNMAP, [a as u64, 0x1000, 0, 0, 0, 0]).unwrap(), Outcome::Return(0));

    // Exhaust the arena: a request larger than the gap between brk and the mmap cursor fails.
    assert_eq!(mmap(0x20000), -1, "arena exhausted -> MAP_FAILED");
    // brk cannot climb past the mmap cursor either; it stays put.
    let before = brk(0);
    assert_eq!(brk(top), before, "brk past the mmap region leaves the break unchanged");
}
