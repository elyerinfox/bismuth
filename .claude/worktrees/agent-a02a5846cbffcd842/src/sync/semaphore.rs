//! Counting and binary semaphores.
//!
//! Classification: L1 kernel · synchronization · safe · always
use crate::Error;
use crate::kernel::cell::IrqCell;
use crate::kernel::time::Timeout;
use crate::kernel::{WakeReason, block_on, with};

/// Counting semaphore. `give` is safe to call from interrupt handlers, which makes a
/// binary semaphore the classic way for an ISR to wake a driver task.
pub struct Semaphore {
    count: IrqCell<u32>,
    max: u32,
}

impl Semaphore {
    pub const fn new(initial: u32, max: u32) -> Self {
        Semaphore { count: IrqCell::new(initial), max }
    }

    /// A binary semaphore, initially empty.
    pub const fn binary() -> Self {
        Self::new(0, 1)
    }

    fn key(&self) -> usize {
        self as *const _ as usize
    }

    pub fn take(&self, timeout: Timeout) -> Result<(), Error> {
        block_on(
            self.key(),
            timeout,
            |_| {
                self.count.lock(|c| {
                    if *c > 0 {
                        *c -= 1;
                        Some(())
                    } else {
                        None
                    }
                })
            },
            |_| (),
            |_| {},
        )
    }

    pub fn try_take(&self) -> Result<(), Error> {
        self.take(Timeout::NoWait)
    }

    /// Release one unit. A waiting task receives it directly (no barging).
    pub fn give(&self) -> Result<(), Error> {
        with(|k| {
            if let Some(w) = k.highest_waiter(self.key()) {
                k.wake(w, WakeReason::Handoff);
                return Ok(());
            }
            self.count.lock(|c| {
                if *c >= self.max {
                    return Err(Error::Overflow);
                }
                *c += 1;
                Ok(())
            })
        })
    }

    /// Reset the count (only meaningful while nobody waits).
    pub fn reset(&self, count: u32) -> Result<(), Error> {
        if count > self.max {
            return Err(Error::Invalid);
        }
        self.count.lock(|c| *c = count);
        Ok(())
    }

    /// Atomically release one unit only if the count is below `max` (one critical
    /// section, so an ISR cannot race the check against the increment).
    pub fn give_bounded(&self, max: u32) -> Result<(), Error> {
        with(|k| {
            if let Some(w) = k.highest_waiter(self.key()) {
                k.wake(w, WakeReason::Handoff);
                return Ok(());
            }
            self.count.lock(|c| {
                if *c >= max {
                    return Err(Error::Overflow);
                }
                *c += 1;
                Ok(())
            })
        })
    }

    pub fn count(&self) -> u32 {
        self.count.lock(|c| *c)
    }
}
