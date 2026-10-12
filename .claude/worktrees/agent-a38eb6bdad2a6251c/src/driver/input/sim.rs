//! A simulated input device: tests (or simulated hardware on another thread) inject
//! [`InputEvent`]s with [`SimInput::inject`]; a `Read` drains them as 16-byte records.
//!
//! This is the generic event-queue backend every real input driver (GPIO matrix
//! keyboard, PS/2, I2C touch, encoder) reduces to — it owns a bounded
//! [`Queue`] with drop-newest-and-count overflow, interrupt-safe
//! producers, and a blocking consumer, exactly like the net stack's rings.
//!
//! Classification: L2 devices · driver: sim-input · safe · always

use core::sync::atomic::{AtomicU32, Ordering};

use crate::Error;
use crate::driver::ioctl;
use crate::driver::input::{EVENT_BYTES, EventKind, InputEvent};
use crate::driver::middleware::Middleware;
use crate::driver::{DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Op, Request};
use crate::sync::Queue;

static MW: [&dyn Middleware; 0] = [];

/// A simulated input device with an event queue of depth `N`.
pub struct SimInput<const N: usize> {
    queue: Queue<InputEvent, N>,
    caps: u32,
    overruns: AtomicU32,
}

impl<const N: usize> SimInput<N> {
    /// `caps` is an OR of [`EventKind::bit`] values the device reports.
    pub const fn new(caps: u32) -> Self {
        SimInput { queue: Queue::new(), caps, overruns: AtomicU32::new(0) }
    }

    /// A keyboard: reports Key and Syn events.
    pub const fn keyboard() -> Self {
        Self::new(EventKind::Key.bit() | EventKind::Syn.bit())
    }

    /// A mouse: Rel + Key (buttons) + Syn.
    pub const fn mouse() -> Self {
        Self::new(EventKind::Rel.bit() | EventKind::Key.bit() | EventKind::Syn.bit())
    }

    /// Inject one event (interrupt-safe). Drops the event (and counts an overrun) if the
    /// queue is full, so a stalled reader never blocks the producer. `try_send` wakes a
    /// blocked reader on its own.
    pub fn inject(&self, ev: InputEvent) {
        if self.queue.try_send(ev).is_err() {
            self.overruns.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Inject a key press + release (down, up), each followed by a SYN.
    pub fn tap(&self, code: u16) {
        self.inject(InputEvent::new(EventKind::Key, code, 1));
        self.inject(InputEvent::syn());
        self.inject(InputEvent::new(EventKind::Key, code, 0));
        self.inject(InputEvent::syn());
    }

    pub fn overruns(&self) -> u32 {
        self.overruns.load(Ordering::Relaxed)
    }
}

impl<const N: usize> Driver for SimInput<N> {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "sim-input", class: DeviceClass::Input, version: (1, 0, 0), compatible: &["bismuth,sim-input"] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MW
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let timeout = req.effective_timeout();
        match &mut req.op {
            Op::Read(buf) => {
                let max = buf.len() / EVENT_BYTES;
                if max == 0 {
                    return Ok(0);
                }
                // Block for the first event (honouring the timeout), then drain without
                // waiting, so a read returns a batch atomically.
                let first = self.queue.recv(timeout)?;
                buf[..EVENT_BYTES].copy_from_slice(&first.to_bytes());
                let mut n = 1;
                while n < max {
                    match self.queue.try_recv() {
                        Ok(ev) => {
                            buf[n * EVENT_BYTES..(n + 1) * EVENT_BYTES].copy_from_slice(&ev.to_bytes());
                            n += 1;
                        }
                        Err(_) => break,
                    }
                }
                Ok(n * EVENT_BYTES)
            }
            Op::Ioctl { cmd, arg } => Ok(match *cmd {
                ioctl::INPUT_GET_CAPS => self.caps as usize,
                ioctl::INPUT_EVENTS_AVAILABLE => self.queue.len(),
                ioctl::INPUT_FLUSH => {
                    while self.queue.try_recv().is_ok() {}
                    0
                }
                ioctl::INPUT_GET_ID => 0,
                ioctl::INPUT_SET_REPEAT => {
                    let _ = arg; // autorepeat config accepted but not simulated
                    0
                }
                ioctl::GET_CLASS => DeviceClass::Input as usize,
                _ => return Err(Error::Unsupported),
            }),
            _ => Err(Error::Unsupported),
        }
    }
}
