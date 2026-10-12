//! Pseudo-terminal: a master/slave character pair, built from two [`Pipe`]s.
//!
//! Bytes written to the master appear as input on the slave and vice-versa. Attach a
//! [`Tty`](crate::driver::char::tty::Tty) over the slave to get a full terminal with no
//! hardware, which is how a shell/CLI or a test harness drives a TTY. A PTY is exactly
//! "the top two terminal layers over a pipe instead of a UART".
//!
//! ```ignore
//! static PTY: Pty<128> = Pty::new();
//! static MASTER: PtyMaster<128> = Pty::master(&PTY);
//! static SLAVE: PtySlave<128> = Pty::slave(&PTY);
//! static TTY: Tty = Tty::new();
//! // register("ptm", &MASTER); register("pts", &SLAVE); Device::find("pts")?.attach(&TTY)?;
//! ```
//!
//! Classification: L2 devices · driver: pty · safe · always

use super::Pipe;
use crate::Error;
use crate::driver::ioctl;
use crate::driver::middleware::{Middleware, NonBlocking};
use crate::driver::{DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Op, Request};

/// A pseudo-terminal: two one-directional byte lanes.
pub struct Pty<const N: usize> {
    /// master → slave.
    m2s: Pipe<N>,
    /// slave → master.
    s2m: Pipe<N>,
}

impl<const N: usize> Default for Pty<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Pty<N> {
    pub const fn new() -> Self {
        Pty { m2s: Pipe::new(), s2m: Pipe::new() }
    }

    /// The master end: writes to `m2s`, reads from `s2m`.
    pub const fn master(pty: &'static Pty<N>) -> PtyMaster<N> {
        PtyMaster { tx: &pty.m2s, rx: &pty.s2m }
    }

    /// The slave end: writes to `s2m`, reads from `m2s`.
    pub const fn slave(pty: &'static Pty<N>) -> PtySlave<N> {
        PtySlave { tx: &pty.s2m, rx: &pty.m2s }
    }
}

static NONBLOCKING: NonBlocking = NonBlocking;
static MIDDLEWARE: [&dyn Middleware; 1] = [&NONBLOCKING];

/// Route a char request to the right lane: reads come from `rx`, writes go to `tx`.
fn relay<const N: usize>(rx: &Pipe<N>, tx: &Pipe<N>, ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
    match &req.op {
        Op::Read(_) => rx.handle(ctx, req),
        Op::Write(_) => tx.handle(ctx, req),
        Op::Ioctl { cmd: ioctl::SERIAL_RX_AVAILABLE | ioctl::SERIAL_FLUSH, .. } => rx.handle(ctx, req),
        Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::Char as usize),
        _ => Err(Error::Unsupported),
    }
}

fn info() -> DriverInfo {
    DriverInfo { name: "pty", class: DeviceClass::Char, version: (1, 0, 0), compatible: &["bismuth,pty"] }
}

/// Master end of a [`Pty`].
pub struct PtyMaster<const N: usize> {
    tx: &'static Pipe<N>,
    rx: &'static Pipe<N>,
}

impl<const N: usize> Driver for PtyMaster<N> {
    fn info(&self) -> DriverInfo {
        info()
    }
    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }
    fn handle(&self, ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        relay(self.rx, self.tx, ctx, req)
    }
}

/// Slave end of a [`Pty`] (attach a [`Tty`](crate::driver::char::tty::Tty) here).
pub struct PtySlave<const N: usize> {
    tx: &'static Pipe<N>,
    rx: &'static Pipe<N>,
}

impl<const N: usize> Driver for PtySlave<N> {
    fn info(&self) -> DriverInfo {
        info()
    }
    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }
    fn handle(&self, ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        relay(self.rx, self.tx, ctx, req)
    }
}
