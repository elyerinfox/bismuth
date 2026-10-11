//! In-memory byte pipe: a character device that loops writes back to readers.
//! Useful for inter-task byte streams and as a stand-in for a UART in tests.
//!
//! Classification: L2 devices · driver: char (pipe) · safe · always

use crate::Error;
use crate::driver::ioctl;
use crate::driver::middleware::{Middleware, NonBlocking};
use crate::driver::{DeviceClass, DeviceCtx, DeviceDesc, Driver, DriverInfo, IoResult, Op, Request};
use crate::kernel::cell::IrqCell;
use crate::kernel::{WakeReason, block_on};

struct Ring<const N: usize> {
    buf: [u8; N],
    head: usize,
    len: usize,
}

/// A bounded byte pipe of capacity `N`. Reads block until data arrives; writes block
/// until there is room (partial writes return the count written).
pub struct Pipe<const N: usize> {
    ring: IrqCell<Ring<N>>,
}

static NONBLOCKING: NonBlocking = NonBlocking;
static MIDDLEWARE: [&dyn Middleware; 1] = [&NONBLOCKING];

impl<const N: usize> Default for Pipe<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Pipe<N> {
    pub const fn new() -> Self {
        Pipe { ring: IrqCell::new(Ring { buf: [0; N], head: 0, len: 0 }) }
    }

    fn key_data(&self) -> usize {
        self as *const _ as usize
    }

    fn key_space(&self) -> usize {
        self as *const _ as usize + 1
    }
}

impl<const N: usize> Driver for Pipe<N> {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "pipe", class: DeviceClass::Char, version: (1, 0, 0), compatible: &["bismuth,pipe"] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let timeout = req.timeout;
        match &mut req.op {
            Op::Read(buf) => {
                if buf.is_empty() {
                    return Ok(0);
                }
                block_on(
                    self.key_data(),
                    timeout,
                    |k| {
                        let n = self.ring.lock(|r| {
                            let n = r.len.min(buf.len());
                            for b in buf[..n].iter_mut() {
                                *b = r.buf[r.head];
                                r.head = (r.head + 1) % N;
                            }
                            r.len -= n;
                            n
                        });
                        if n == 0 {
                            return None;
                        }
                        k.wake_all(self.key_space(), WakeReason::Signaled);
                        Some(n)
                    },
                    |_| 0,
                    |_| {},
                )
            }
            Op::Write(data) => {
                if data.is_empty() {
                    return Ok(0);
                }
                block_on(
                    self.key_space(),
                    timeout,
                    |k| {
                        let n = self.ring.lock(|r| {
                            let n = (N - r.len).min(data.len());
                            for &b in &data[..n] {
                                r.buf[(r.head + r.len) % N] = b;
                                r.len += 1;
                            }
                            n
                        });
                        if n == 0 {
                            return None;
                        }
                        k.wake_all(self.key_data(), WakeReason::Signaled);
                        Some(n)
                    },
                    |_| 0,
                    |_| {},
                )
            }
            Op::Ioctl { cmd: ioctl::SERIAL_RX_AVAILABLE, .. } => Ok(self.ring.lock(|r| r.len)),
            Op::Ioctl { cmd: ioctl::SERIAL_FLUSH, .. } => {
                crate::kernel::with(|k| {
                    self.ring.lock(|r| r.len = 0);
                    k.wake_all(self.key_space(), WakeReason::Signaled);
                });
                Ok(0)
            }
            Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::Char as usize),
            _ => Err(Error::Unsupported),
        }
    }
}

const SLOTS: usize = 4;
static INSTANCES: [Pipe<256>; SLOTS] = [const { Pipe::new() }; SLOTS];
static NEXT: crate::sync::IrqCell<usize> = crate::sync::IrqCell::new(0);

pub(crate) fn create(_desc: &'static DeviceDesc) -> Result<&'static dyn Driver, Error> {
    let i = NEXT.lock(|n| {
        let i = *n;
        if i < SLOTS {
            *n += 1;
        }
        i
    });
    INSTANCES.get(i).map(|p| p as &dyn Driver).ok_or(Error::NoResources)
}
