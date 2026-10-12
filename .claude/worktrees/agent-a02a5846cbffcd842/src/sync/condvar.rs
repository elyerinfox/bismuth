//! Condition variables.
//!
//! Classification: L1 kernel · synchronization · safe · always
use crate::Error;
use crate::kernel::time::{Deadline, Timeout};
use crate::kernel::{WakeReason, with};

use super::mutex::{MutexGuard, RawMutex};

/// Condition variable, used together with a [`super::Mutex`].
pub struct CondVar {
    _anchor: u8,
}

impl Default for CondVar {
    fn default() -> Self {
        Self::new()
    }
}

impl CondVar {
    pub const fn new() -> Self {
        CondVar { _anchor: 0 }
    }

    fn key(&self) -> usize {
        self as *const _ as usize
    }

    /// Atomically release `m`, wait for a notification (or timeout), then re-acquire `m`.
    pub fn wait_raw(&self, m: &RawMutex, timeout: Timeout) -> Result<(), Error> {
        let ticks = match timeout.deadline(0) {
            Deadline::Now => return Err(Error::Timeout),
            Deadline::At(t) => Some(t),
            Deadline::Never => None,
        };
        with(|k| {
            if !k.can_block() {
                return Err(Error::WouldBlock);
            }
            if m.depth_in(k) != 1 {
                return Err(Error::NotOwner);
            }
            m.unlock_in(k)?;
            k.block_current(self.key(), ticks);
            Ok(())
        })?;
        let reason = with(|k| k.cur().wake_reason);
        let relock = m.lock(Timeout::Forever);
        match reason {
            WakeReason::Timeout => Err(Error::Timeout),
            WakeReason::Aborted => Err(Error::Interrupted),
            _ => relock,
        }
    }

    /// Wait on a guard; returns the guard (re-locked) and whether we were notified.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>, timeout: Timeout) -> (MutexGuard<'a, T>, Result<(), Error>) {
        let m = guard.into_locked_mutex();
        let r = self.wait_raw(m.raw(), timeout);
        (MutexGuard::from_locked(m), r)
    }

    /// Wait until `cond` returns false.
    pub fn wait_while<'a, T>(
        &self,
        mut guard: MutexGuard<'a, T>,
        mut cond: impl FnMut(&mut T) -> bool,
    ) -> Result<MutexGuard<'a, T>, Error> {
        while cond(&mut guard) {
            let (g, r) = self.wait(guard, Timeout::Forever);
            guard = g;
            r?;
        }
        Ok(guard)
    }

    pub fn notify_one(&self) {
        with(|k| {
            k.wake_one(self.key(), WakeReason::Signaled);
        });
    }

    pub fn notify_all(&self) {
        with(|k| {
            k.wake_all(self.key(), WakeReason::Signaled);
        });
    }
}
