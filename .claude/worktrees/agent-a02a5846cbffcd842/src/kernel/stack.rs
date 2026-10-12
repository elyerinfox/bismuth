//! Statically allocated task stacks and the shared stack pool.
//!
//! Part of the trusted computing base: stack memory is handed to the CPU as raw memory
//! by the architecture port, so ownership is tracked here with raw pointers.
//!
//! Classification: L1 kernel · task stacks · TCB (unsafe allowed) · always
#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::port;
use crate::config::{IDLE_STACK_SIZE, POOL_STACKS, POOL_STACK_SIZE};

/// Byte pattern used to paint unused stack, for high-water-mark measurement.
pub(crate) const STACK_PAINT: u8 = 0xA5;

#[repr(C, align(8))]
struct Aligned<const N: usize>([u8; N]);

/// A task stack of `N` bytes, meant to be declared as a `static`.
///
/// ```ignore
/// static SENSOR_STACK: Stack<2048> = Stack::new();
/// ```
pub struct Stack<const N: usize> {
    taken: AtomicBool,
    mem: UnsafeCell<Aligned<N>>,
}

// SAFETY: the memory is handed out to at most one task at a time, guarded by `taken`.
unsafe impl<const N: usize> Sync for Stack<N> {}

impl<const N: usize> Default for Stack<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Stack<N> {
    pub const fn new() -> Self {
        Self { taken: AtomicBool::new(false), mem: UnsafeCell::new(Aligned([0; N])) }
    }

    /// Claim this stack for a task. Returns `None` if it is already in use.
    pub fn take(&'static self) -> Option<StackRef> {
        let claimed = port::critical(|| {
            if self.taken.load(Ordering::Relaxed) {
                false
            } else {
                self.taken.store(true, Ordering::Relaxed);
                true
            }
        });
        claimed.then(|| StackRef { ptr: self.mem.get() as *mut u8, len: N, owner: &self.taken })
    }
}

/// Anything a task stack can be claimed from (`Stack<N>`, `UserStack*`).
pub trait StackSource: Sync {
    fn claim(&'static self) -> Option<StackRef>;
}

impl<const N: usize> StackSource for Stack<N> {
    fn claim(&'static self) -> Option<StackRef> {
        self.take()
    }
}

/// An exclusive claim on a stack region, returned to its owner when the task is reaped.
pub struct StackRef {
    ptr: *mut u8,
    len: usize,
    owner: &'static AtomicBool,
}

// SAFETY: a StackRef is a unique claim on its memory region.
unsafe impl Send for StackRef {}

impl StackRef {
    pub fn base(&self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Address one past the highest usable byte, aligned down to 8 bytes.
    pub fn top(&self) -> usize {
        (self.ptr as usize + self.len) & !7
    }

    /// Fill the stack with the paint pattern.
    pub fn paint(&self) {
        // SAFETY: we own the region exclusively and nothing runs on it yet.
        unsafe { core::ptr::write_bytes(self.ptr, STACK_PAINT, self.len) };
    }

    /// Bytes at the bottom of the stack that have never been written.
    pub fn unused(&self) -> usize {
        let mut n = 0;
        while n < self.len {
            // SAFETY: in bounds; volatile because another context may be using the stack.
            if unsafe { self.ptr.add(n).read_volatile() } != STACK_PAINT {
                break;
            }
            n += 1;
        }
        n
    }

    /// Whether the guard word at the very bottom has been overwritten.
    pub fn overflowed(&self) -> bool {
        // SAFETY: the stack is at least 4 bytes long (checked at spawn).
        let guard = unsafe { (self.ptr as *const u32).read_volatile() };
        guard != u32::from_ne_bytes([STACK_PAINT; 4])
    }

    pub(crate) fn release(self) {
        self.owner.store(false, Ordering::Release);
    }
}

static POOL: [Stack<POOL_STACK_SIZE>; POOL_STACKS] = [const { Stack::new() }; POOL_STACKS];
static IDLE_STACK: Stack<IDLE_STACK_SIZE> = Stack::new();

/// Claim a stack from the shared pool used by dynamically created tasks.
pub fn pool_take() -> Option<StackRef> {
    POOL.iter().find_map(|s| s.take())
}

pub(crate) fn idle_stack() -> StackRef {
    IDLE_STACK.take().expect("idle stack already in use")
}

/// Defines a stack type whose memory is aligned to its own (power-of-two) size, as
/// required for an ARMv7-M MPU region. Used by hardware-isolated (unprivileged) tasks.
macro_rules! user_stack {
    ($name:ident, $aligned:ident, $size:literal) => {
        #[repr(C, align($size))]
        struct $aligned([u8; $size]);

        #[doc = concat!("An MPU-mappable task stack of ", stringify!($size), " bytes (aligned to its size).")]
        pub struct $name {
            taken: AtomicBool,
            mem: UnsafeCell<$aligned>,
        }

        // SAFETY: the memory is handed out to at most one task at a time, guarded by `taken`.
        unsafe impl Sync for $name {}

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl StackSource for $name {
            fn claim(&'static self) -> Option<StackRef> {
                self.take()
            }
        }

        impl $name {
            pub const SIZE: usize = $size;

            pub const fn new() -> Self {
                Self { taken: AtomicBool::new(false), mem: UnsafeCell::new($aligned([0; $size])) }
            }

            /// Claim this stack for a task. Returns `None` if it is already in use.
            pub fn take(&'static self) -> Option<StackRef> {
                let claimed = port::critical(|| {
                    if self.taken.load(Ordering::Relaxed) {
                        false
                    } else {
                        self.taken.store(true, Ordering::Relaxed);
                        true
                    }
                });
                claimed.then(|| StackRef { ptr: self.mem.get() as *mut u8, len: $size, owner: &self.taken })
            }
        }
    };
}

user_stack!(UserStack1K, AlignedUser1K, 1024);
user_stack!(UserStack2K, AlignedUser2K, 2048);
user_stack!(UserStack4K, AlignedUser4K, 4096);
