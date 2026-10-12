//! Bounded FIFO message queues.
//!
//! Classification: L1 kernel · inter-task communication · safe · always
use crate::Error;
use crate::kernel::cell::IrqCell;
use crate::kernel::time::Timeout;
use crate::kernel::{WakeReason, block_on};

/// A failed send, returning the item to the caller.
#[derive(Debug, PartialEq, Eq)]
pub struct SendError<T> {
    pub error: Error,
    pub item: T,
}

struct Ring<T, const N: usize> {
    buf: [Option<T>; N],
    head: usize,
    len: usize,
}

/// Bounded FIFO message queue holding up to `N` items of type `T`, stored inline.
///
/// `try_send` / `try_recv` never block and are safe from interrupt handlers.
pub struct Queue<T, const N: usize> {
    ring: IrqCell<Ring<T, N>>,
}

impl<T, const N: usize> Default for Queue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Queue { ring: IrqCell::new(Ring { buf: [const { None }; N], head: 0, len: 0 }) }
    }

    fn key_not_empty(&self) -> usize {
        self as *const _ as usize
    }

    fn key_not_full(&self) -> usize {
        self as *const _ as usize + 1
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        self.ring.lock(|r| r.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.len() == N
    }

    /// Send `item`, waiting up to `timeout` for space.
    pub fn send(&self, item: T, timeout: Timeout) -> Result<(), SendError<T>> {
        self.send_impl(item, timeout, false)
    }

    /// Send to the front of the queue (urgent message).
    pub fn send_front(&self, item: T, timeout: Timeout) -> Result<(), SendError<T>> {
        self.send_impl(item, timeout, true)
    }

    pub fn try_send(&self, item: T) -> Result<(), SendError<T>> {
        self.send(item, Timeout::NoWait)
    }

    fn send_impl(&self, item: T, timeout: Timeout, front: bool) -> Result<(), SendError<T>> {
        let mut slot = Some(item);
        let res = block_on(
            self.key_not_full(),
            timeout,
            |k| {
                let sent = self.ring.lock(|r| {
                    if r.len == N {
                        return false;
                    }
                    let idx = if front {
                        r.head = (r.head + N - 1) % N;
                        r.head
                    } else {
                        (r.head + r.len) % N
                    };
                    r.buf[idx] = slot.take();
                    r.len += 1;
                    true
                });
                if !sent {
                    return None;
                }
                k.wake_one(self.key_not_empty(), WakeReason::Signaled);
                Some(())
            },
            |_| (),
            |_| {},
        );
        match (res, slot) {
            (Ok(()), _) => Ok(()),
            (Err(error), Some(item)) => Err(SendError { error, item }),
            (Err(_), None) => unreachable!("a failed send keeps its item"),
        }
    }

    /// Receive the oldest item, waiting up to `timeout`.
    pub fn recv(&self, timeout: Timeout) -> Result<T, Error> {
        block_on(
            self.key_not_empty(),
            timeout,
            |k| {
                let v = self.ring.lock(|r| {
                    if r.len == 0 {
                        return None;
                    }
                    let v = r.buf[r.head].take();
                    r.head = (r.head + 1) % N;
                    r.len -= 1;
                    v
                })?;
                k.wake_one(self.key_not_full(), WakeReason::Signaled);
                Some(v)
            },
            |_| unreachable!("queues never hand off"),
            |_| {},
        )
    }

    pub fn try_recv(&self) -> Result<T, Error> {
        self.recv(Timeout::NoWait)
    }
}
