//! Memory-mapped I/O: part of the kernel's trusted computing base.
//!
//! An [`Mmio`] region is the *only* way drivers touch hardware registers. Creating one
//! is `unsafe` — it is the point where the board asserts "this address range really is
//! that peripheral" — but every register access afterwards is safe, bounds-checked
//! and alignment-checked.
//!
//! Classification: L0 port · memory-mapped I/O · TCB (unsafe allowed) · always
#![allow(unsafe_code)]

/// A validated window of device registers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mmio {
    base: usize,
    len: usize,
}

impl Mmio {
    /// # Safety
    /// `base..base + len` must be the register block of a peripheral that is valid for
    /// volatile 32-bit access and is not accessed through any other `Mmio` or pointer.
    pub const unsafe fn new(base: usize, len: usize) -> Self {
        assert!(base % 4 == 0, "MMIO base must be 4-byte aligned");
        Mmio { base, len }
    }

    pub const fn base(&self) -> usize {
        self.base
    }

    fn addr(&self, offset: usize) -> *mut u32 {
        assert!(offset % 4 == 0 && offset + 4 <= self.len, "MMIO offset {offset:#x} out of range");
        (self.base + offset) as *mut u32
    }

    #[inline]
    pub fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `new`'s contract makes every in-range, aligned offset a valid register.
        unsafe { self.addr(offset).read_volatile() }
    }

    #[inline]
    pub fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as for `read32`.
        unsafe { self.addr(offset).write_volatile(value) }
    }

    #[inline]
    pub fn modify32(&self, offset: usize, f: impl FnOnce(u32) -> u32) {
        let v = self.read32(offset);
        self.write32(offset, f(v));
    }
}
