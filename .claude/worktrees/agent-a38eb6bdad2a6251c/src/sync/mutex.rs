//! Priority-inheritance mutexes ([`RawMutex`] and data-owning [`Mutex`]).
//!
//! Classification: L1 kernel · synchronization · safe · always
use core::ops::{Deref, DerefMut};

use crate::Error;
use crate::kernel::cell::{IrqCell, TaskCell, TaskRef};
use crate::kernel::time::Timeout;
use crate::kernel::{Kernel, NIL, WakeReason, block_on, with};

struct State {
    owner: u8,
    count: u32,
    recursive: bool,
}

/// A priority-inheritance mutex without associated data.
///
/// While a higher-priority task waits, the owner runs at the waiter's priority so a
/// medium-priority task cannot starve it (bounded priority inversion). On unlock,
/// ownership is handed directly to the highest-priority waiter.
pub struct RawMutex {
    state: IrqCell<State>,
}

impl Default for RawMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl RawMutex {
    pub const fn new() -> Self {
        RawMutex { state: IrqCell::new(State { owner: NIL, count: 0, recursive: false }) }
    }

    /// A mutex the owner may lock again; it must be unlocked as many times.
    pub const fn new_recursive() -> Self {
        RawMutex { state: IrqCell::new(State { owner: NIL, count: 0, recursive: true }) }
    }

    /// Change the mutex type (only while unlocked).
    pub fn set_recursive(&self, recursive: bool) -> Result<(), Error> {
        self.state.lock(|s| {
            if s.owner != NIL {
                return Err(Error::Busy);
            }
            s.recursive = recursive;
            Ok(())
        })
    }

    fn key(&self) -> usize {
        self as *const _ as usize
    }

    fn try_acquire(&self, k: &mut Kernel) -> Option<Result<(), Error>> {
        let me = k.current;
        let r = self.state.lock(|s| {
            if s.owner == NIL {
                s.owner = me;
                s.count = 1;
                Some(Ok(true))
            } else if s.owner == me {
                if s.recursive {
                    s.count += 1;
                    Some(Ok(false))
                } else {
                    Some(Err(Error::Deadlock))
                }
            } else {
                None
            }
        });
        r.map(|r| {
            r.map(|first| {
                if first {
                    k.cur().mutexes_held += 1;
                }
            })
        })
    }

    pub fn lock(&self, timeout: Timeout) -> Result<(), Error> {
        if crate::arch::port::in_isr() {
            return Err(Error::WouldBlock); // a mutex has no owner in interrupt context
        }
        block_on(
            self.key(),
            timeout,
            |k| self.try_acquire(k),
            |_| Ok(()),
            |k| {
                // Priority inheritance: boost the owner to our priority.
                let owner = self.state.lock(|s| s.owner);
                let mine = k.cur().prio;
                if owner != NIL && k.tasks[owner as usize].prio < mine {
                    k.set_effective_prio(owner, mine);
                }
            },
        )?
    }

    pub fn try_lock(&self) -> Result<(), Error> {
        self.lock(Timeout::NoWait)
    }

    pub fn unlock(&self) -> Result<(), Error> {
        with(|k| self.unlock_in(k))
    }

    /// Unlock from inside an existing kernel critical section.
    pub(crate) fn unlock_in(&self, k: &mut Kernel) -> Result<(), Error> {
        let me = k.current;
        let key = self.key();
        let released = self.state.lock(|s| {
            if s.owner != me || s.count == 0 {
                return Err(Error::NotOwner);
            }
            s.count -= 1;
            Ok(s.count == 0)
        })?;
        if !released {
            return Ok(());
        }
        let t = &mut k.tasks[me as usize];
        t.mutexes_held = t.mutexes_held.saturating_sub(1);
        if t.mutexes_held == 0 && t.prio != t.base_prio {
            let base = t.base_prio;
            k.set_effective_prio(me, base);
        }
        match k.highest_waiter(key) {
            Some(w) => {
                self.state.lock(|s| {
                    s.owner = w;
                    s.count = 1;
                });
                k.tasks[w as usize].mutexes_held += 1;
                k.wake(w, WakeReason::Handoff);
                // The new owner inherits from whoever is still waiting.
                if let Some(w2) = k.highest_waiter(key) {
                    let p2 = k.tasks[w2 as usize].prio;
                    if p2 > k.tasks[w as usize].prio {
                        k.set_effective_prio(w, p2);
                    }
                }
            }
            None => self.state.lock(|s| s.owner = NIL),
        }
        Ok(())
    }

    /// Recursion depth if held by the caller (used by condition variables).
    pub(crate) fn depth_in(&self, k: &Kernel) -> u32 {
        self.state.lock(|s| if s.owner == k.current { s.count } else { 0 })
    }

    pub fn is_locked(&self) -> bool {
        self.state.lock(|s| s.owner != NIL)
    }
}

/// A priority-inheritance mutex protecting a value of type `T`.
pub struct Mutex<T> {
    raw: RawMutex,
    data: TaskCell<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Mutex { raw: RawMutex::new(), data: TaskCell::new(value) }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }

    /// Lock, waiting as long as necessary.
    pub fn lock(&self) -> Result<MutexGuard<'_, T>, Error> {
        self.lock_timeout(Timeout::Forever)
    }

    pub fn lock_timeout(&self, timeout: Timeout) -> Result<MutexGuard<'_, T>, Error> {
        self.raw.lock(timeout)?;
        Ok(MutexGuard::from_locked(self))
    }

    pub fn try_lock(&self) -> Result<MutexGuard<'_, T>, Error> {
        self.lock_timeout(Timeout::NoWait)
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    pub(crate) fn raw(&self) -> &RawMutex {
        &self.raw
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
    data: Option<TaskRef<'a, T>>,
}

impl<'a, T> MutexGuard<'a, T> {
    /// Wrap a mutex the caller has just locked.
    pub(crate) fn from_locked(mutex: &'a Mutex<T>) -> Self {
        MutexGuard { mutex, data: Some(mutex.data.borrow_mut()) }
    }

    /// Release the data borrow but keep the mutex locked; returns the mutex.
    pub(crate) fn into_locked_mutex(mut self) -> &'a Mutex<T> {
        self.data = None;
        let m = self.mutex;
        core::mem::forget(self);
        m
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data.as_deref().expect("guard always holds its borrow")
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data.as_deref_mut().expect("guard always holds its borrow")
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // Release the data borrow before handing the lock to another task.
        self.data = None;
        let _ = self.mutex.raw.unlock();
    }
}
