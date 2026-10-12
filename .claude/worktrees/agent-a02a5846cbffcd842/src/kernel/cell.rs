//! Shared-state cells: part of the kernel's trusted computing base.
//!
//! Bismuth is `#![deny(unsafe_code)]`; the only `unsafe` outside the architecture ports
//! and raw stack handling is in this file. Every other kernel
//! object (scheduler, IPC, timers, drivers, middleware) builds on these cells in safe
//! Rust. Misuse (re-entrant access) panics instead of causing undefined behaviour,
//! because both cells check their borrow state.
//!
//! Classification: L1 kernel · shared-state cells · TCB (unsafe allowed) · always
#![allow(unsafe_code)]

use core::cell::{RefCell, UnsafeCell};
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::port;

/// Mutable state shared between tasks and interrupt handlers. Access happens only
/// inside [`IrqCell::lock`], which runs with interrupts masked.
///
/// Keep the closure short: interrupts are disabled while it runs. Re-entrant locking
/// of the same cell panics.
pub struct IrqCell<T> {
    inner: RefCell<T>,
}

// SAFETY: the RefCell is only ever borrowed inside `lock`, i.e. inside a critical
// section (interrupts masked on hardware; the global port lock held on the host), so
// borrow-flag updates and data accesses can never interleave between contexts. A
// nested borrow is caught by the RefCell and panics. `T: Send` because the data is
// effectively handed between execution contexts.
unsafe impl<T: Send> Sync for IrqCell<T> {}

impl<T> IrqCell<T> {
    pub const fn new(v: T) -> Self {
        IrqCell { inner: RefCell::new(v) }
    }

    /// Run `f` with exclusive access to the contents.
    #[inline]
    pub fn lock<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        port::critical(|| f(&mut self.inner.borrow_mut()))
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

/// A cell whose contents can be claimed by one context at a time for an extended
/// period (data protected by a kernel mutex, pool slots, packet blocks).
///
/// The claim is taken inside a critical section, so two contexts can never both
/// succeed; a conflicting claim panics. The resulting [`TaskRef`] is an exclusive
/// access token that may be sent to another task (e.g. a packet buffer travelling
/// through a queue).
pub struct TaskCell<T> {
    claimed: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: `value` is only reachable through a `TaskRef`, and at most one `TaskRef`
// exists at a time: `borrow_mut` checks and sets `claimed` inside a critical section
// (atomic with respect to every other context), and the flag is cleared only when that
// unique `TaskRef` is dropped. `T: Send` because the claim can move between contexts.
unsafe impl<T: Send> Sync for TaskCell<T> {}

impl<T> TaskCell<T> {
    pub const fn new(v: T) -> Self {
        TaskCell { claimed: AtomicBool::new(false), value: UnsafeCell::new(v) }
    }

    /// Exclusively claim the contents. Panics if already claimed.
    pub fn borrow_mut(&self) -> TaskRef<'_, T> {
        let ok = port::critical(|| {
            if self.claimed.load(Ordering::Acquire) {
                false
            } else {
                self.claimed.store(true, Ordering::Release);
                true
            }
        });
        assert!(ok, "TaskCell already claimed");
        TaskRef { cell: self }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

/// Exclusive access to the contents of a [`TaskCell`]; released on drop.
pub struct TaskRef<'a, T> {
    cell: &'a TaskCell<T>,
}

// SAFETY: a TaskRef is the unique access path to its value (see `TaskCell`), so moving
// it to another context moves exclusive ownership of `&mut T`, which requires `T: Send`;
// sharing `&TaskRef` only hands out `&T`, which requires `T: Sync`.
unsafe impl<T: Send> Send for TaskRef<'_, T> {}
unsafe impl<T: Sync> Sync for TaskRef<'_, T> {}

impl<T> Deref for TaskRef<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this TaskRef holds the unique claim on the cell.
        unsafe { &*self.cell.value.get() }
    }
}

impl<T> DerefMut for TaskRef<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this TaskRef holds the unique claim on the cell.
        unsafe { &mut *self.cell.value.get() }
    }
}

impl<T> Drop for TaskRef<'_, T> {
    fn drop(&mut self) {
        self.cell.claimed.store(false, Ordering::Release);
    }
}
