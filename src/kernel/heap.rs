//! A bounded, opt-in heap (the `heap` feature): a single fixed static arena behind a vetted
//! free-list allocator ([`linked_list_allocator`]). It preserves the no-heap invariant's
//! guarantees — the arena is a compile-time [`HEAP_SIZE`] static, so total RAM stays statically
//! known; allocation **fails closed** (returns null → the standard `handle_alloc_error`) once the
//! arena is full; and nothing in the safety-critical kernel depends on it. Only subsystems that
//! genuinely need `alloc` (e.g. a Wasm container) pull the feature in.
//!
//! On a hosted build the system allocator is used instead (no `#[global_allocator]`), so
//! `alloc`-based code is still exercised by the host tests.
//!
//! Classification: L1 kernel · heap arena · TCB (unsafe allowed) · heap
#![allow(unsafe_code)]

use crate::config::HEAP_SIZE;

#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: linked_list_allocator::LockedHeap = linked_list_allocator::LockedHeap::empty();

// The one heap region. Its size is the heap's hard ceiling.
#[cfg(target_os = "none")]
static mut ARENA: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[cfg(target_os = "none")]
static READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Initialise the heap arena. Call once, early at boot, before any allocation. Idempotent.
#[cfg(target_os = "none")]
pub fn init() {
    if READY.swap(true, core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    // SAFETY: run once at boot; `ARENA` is a 'static region handed exclusively to the allocator.
    unsafe {
        ALLOCATOR.lock().init(&raw mut ARENA as *mut u8, HEAP_SIZE);
    }
}

/// Hosted builds use the system allocator; nothing to initialise.
#[cfg(not(target_os = "none"))]
pub fn init() {}

/// `(used, free)` bytes in the arena — for diagnostics and per-container accounting.
#[cfg(target_os = "none")]
pub fn stats() -> (usize, usize) {
    let h = ALLOCATOR.lock();
    (h.used(), h.free())
}

/// The arena's total capacity (its hard ceiling).
pub const fn capacity() -> usize {
    HEAP_SIZE
}
