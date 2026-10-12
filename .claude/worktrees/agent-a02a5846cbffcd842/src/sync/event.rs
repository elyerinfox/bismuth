//! Event flag groups.
//!
//! Classification: L1 kernel · synchronization · safe · always
use crate::Error;
use crate::kernel::cell::IrqCell;
use crate::kernel::time::Timeout;
use crate::kernel::{WakeReason, block_on, with};

/// Whether a waiter needs any or all of the requested bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WaitMode {
    Any,
    All,
}

/// A 32-bit group of event flags. Tasks wait for combinations of bits; anyone
/// (including interrupt handlers) may set them.
pub struct EventFlags {
    bits: IrqCell<u32>,
}

impl Default for EventFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl EventFlags {
    pub const fn new() -> Self {
        EventFlags { bits: IrqCell::new(0) }
    }

    fn key(&self) -> usize {
        self as *const _ as usize
    }

    /// Set bits and wake every waiter so it can re-evaluate. Returns the new value.
    pub fn set(&self, bits: u32) -> u32 {
        with(|k| {
            let v = self.bits.lock(|b| {
                *b |= bits;
                *b
            });
            k.wake_all(self.key(), WakeReason::Signaled);
            v
        })
    }

    pub fn clear(&self, bits: u32) -> u32 {
        self.bits.lock(|b| {
            *b &= !bits;
            *b
        })
    }

    pub fn get(&self) -> u32 {
        self.bits.lock(|b| *b)
    }

    /// Wait until the bits in `mask` satisfy `mode`. Returns the flag value that
    /// satisfied the wait; with `clear` the matched bits are consumed.
    pub fn wait(&self, mask: u32, mode: WaitMode, clear: bool, timeout: Timeout) -> Result<u32, Error> {
        if mask == 0 {
            return Err(Error::Invalid);
        }
        block_on(
            self.key(),
            timeout,
            |_| {
                self.bits.lock(|b| {
                let ok = match mode {
                    WaitMode::Any => *b & mask != 0,
                    WaitMode::All => *b & mask == mask,
                };
                if !ok {
                    return None;
                }
                let v = *b;
                if clear {
                    *b &= !mask;
                }
                Some(v)
                })
            },
            |_| unreachable!("event flags never hand off"),
            |_| {},
        )
    }
}
