//! The opt-in bounded heap: with the `heap` feature, `alloc` types are available and the arena
//! API reports its fixed ceiling. (On the host the system allocator backs `alloc`; the fixed
//! arena itself is exercised on bare metal — this covers the feature plumbing and API.)

#![cfg(feature = "heap")]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

#[test]
fn alloc_types_are_available_under_the_heap_feature() {
    bismuth::kernel::heap::init(); // no-op on host; initialises the arena on bare metal

    let mut v: Vec<u32> = Vec::new();
    for i in 0..1000 {
        v.push(i);
    }
    assert_eq!(v.iter().copied().sum::<u32>(), (0..1000).sum());

    let b = Box::new([7u8; 64]);
    assert_eq!(b[0], 7);

    // The arena ceiling is a compile-time constant (static RAM footprint).
    assert_eq!(bismuth::kernel::heap::capacity(), 256 * 1024);
}
