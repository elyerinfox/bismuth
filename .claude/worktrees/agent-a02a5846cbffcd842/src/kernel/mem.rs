//! Deterministic memory management: fixed-block pools.
//!
//! A [`Pool<T, N>`] hands out up to `N` values of type `T` from static storage with no
//! fragmentation. Allocation can wait for a block to be freed, which makes pools a
//! natural way to bound memory use between producer and consumer tasks (e.g. sensor
//! frames flowing through an edge pipeline).
//!
//! Classification: L1 kernel · memory pools · safe · always

use core::ops::{Deref, DerefMut};

use crate::Error;
use crate::kernel::cell::{IrqCell, TaskCell, TaskRef};
use crate::kernel::time::Timeout;
use crate::kernel::{WakeReason, block_on, with};

pub struct Pool<T, const N: usize> {
    slots: [TaskCell<Option<T>>; N],
    used: IrqCell<[bool; N]>,
}

impl<T, const N: usize> Default for Pool<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Pool<T, N> {
    pub const fn new() -> Self {
        Pool { slots: [const { TaskCell::new(None) }; N], used: IrqCell::new([false; N]) }
    }

    fn key(&self) -> usize {
        self as *const _ as usize
    }

    /// Allocate a block holding `value`, waiting up to `timeout` for one to be free.
    /// On failure the value is returned.
    pub fn alloc(&self, value: T, timeout: Timeout) -> Result<PoolBox<'_, T, N>, (Error, T)> {
        let r = block_on(
            self.key(),
            timeout,
            |_| {
                self.used.lock(|u| {
                    let i = u.iter().position(|b| !*b)?;
                    u[i] = true;
                    Some(i)
                })
            },
            |_| unreachable!("pools never hand off"),
            |_| {},
        );
        match r {
            Ok(index) => {
                let mut slot = self.slots[index].borrow_mut();
                *slot = Some(value);
                Ok(PoolBox { pool: self, index, slot: Some(slot) })
            }
            Err(e) => Err((e, value)),
        }
    }

    pub fn try_alloc(&self, value: T) -> Result<PoolBox<'_, T, N>, (Error, T)> {
        self.alloc(value, Timeout::NoWait)
    }

    pub fn available(&self) -> usize {
        self.used.lock(|u| u.iter().filter(|b| !**b).count())
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    fn free(&self, i: usize) {
        with(|k| {
            self.used.lock(|u| u[i] = false);
            k.wake_one(self.key(), WakeReason::Signaled);
        });
    }
}

/// An owned block from a [`Pool`]; returned to the pool on drop.
pub struct PoolBox<'a, T, const N: usize> {
    pool: &'a Pool<T, N>,
    index: usize,
    slot: Option<TaskRef<'a, Option<T>>>,
}

impl<T, const N: usize> PoolBox<'_, T, N> {
    /// Take the value out, returning the block to the pool.
    pub fn into_inner(mut self) -> T {
        self.slot.as_mut().and_then(|s| s.take()).expect("pool slot holds a value")
    }
}

impl<T, const N: usize> Deref for PoolBox<'_, T, N> {
    type Target = T;
    fn deref(&self) -> &T {
        self.slot.as_ref().and_then(|s| s.as_ref()).expect("pool slot holds a value")
    }
}

impl<T, const N: usize> DerefMut for PoolBox<'_, T, N> {
    fn deref_mut(&mut self) -> &mut T {
        self.slot.as_mut().and_then(|s| s.as_mut()).expect("pool slot holds a value")
    }
}

impl<T, const N: usize> Drop for PoolBox<'_, T, N> {
    fn drop(&mut self) {
        if let Some(mut s) = self.slot.take() {
            *s = None;
        }
        self.pool.free(self.index);
    }
}
