//! TTY line discipline, as device-independent [`Middleware`].
//!
//! Attach a [`Tty`] over any character device — a UART, a [`Pipe`](super::Pipe),
//! a PTY slave, or a keyboard-backed stream — and it provides the UNIX "cooked" terminal:
//! canonical line editing with echo, output post-processing, raw mode with `VMIN`/`VTIME`,
//! and `Ctrl-C`/`Ctrl-\`/`Ctrl-Z` handling. It is a generalization of the PL011
//! `LineDiscipline`, and like it only ever calls `next.run` with `Op::Read`/`Op::Write`,
//! so it never cares what the underlying device is.
//!
//! Configuration is a [`Termios`] value reached through the typed [`TtyControl`]
//! interface (and the POSIX `tcgetattr`/`tcsetattr` layer), not through raw pointers in
//! an ioctl argument — which keeps the whole discipline in safe Rust.
//!
//! Bismuth has no asynchronous UNIX signals, so `ISIG` maps a signal character to a
//! [task notification](crate::kernel::task::notify) on a bound controlling task, an
//! [`EventFlags`] set, and interruption of the in-progress `read` (which returns
//! [`Error::Interrupted`], i.e. `EINTR`). The application is in charge — this is not job
//! control.
//!
//! Classification: L2 devices · tty line discipline · safe · always

use crate::Error;
use crate::config::MAX_DEVICES;
use crate::driver::ioctl;
use crate::driver::middleware::Middleware;
use crate::driver::{DeviceCtx, IoResult, Next, Op, Request};
use crate::kernel::cell::IrqCell;
use crate::kernel::task::{self, TaskId};
use crate::sync::EventFlags;

// ----- termios -----

// c_iflag
pub const ISTRIP: u32 = 1 << 0;
pub const INLCR: u32 = 1 << 1;
pub const IGNCR: u32 = 1 << 2;
pub const ICRNL: u32 = 1 << 3;
pub const IXON: u32 = 1 << 4;
// c_oflag
pub const OPOST: u32 = 1 << 0;
pub const ONLCR: u32 = 1 << 1;
pub const OCRNL: u32 = 1 << 2;
// c_lflag
pub const ISIG: u32 = 1 << 0;
pub const ICANON: u32 = 1 << 1;
pub const ECHO: u32 = 1 << 2;
pub const ECHOE: u32 = 1 << 3;
pub const ECHOK: u32 = 1 << 4;
pub const ECHONL: u32 = 1 << 5;
pub const NOFLSH: u32 = 1 << 6;

// c_cc indices
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VMIN: usize = 5;
pub const VTIME: usize = 6;
pub const VSUSP: usize = 7;
pub const NCCS: usize = 8;

/// The POSIX General Terminal Interface configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_lflag: u32,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Default for Termios {
    fn default() -> Self {
        Self::cooked()
    }
}

impl Termios {
    /// A sensible interactive default (like a fresh terminal): canonical mode, echo,
    /// CR→NL on input, NL→CRNL on output, signals enabled.
    pub const fn cooked() -> Self {
        let mut c_cc = [0u8; NCCS];
        c_cc[VINTR] = 0x03; // ^C
        c_cc[VQUIT] = 0x1C; // ^\
        c_cc[VERASE] = 0x7F; // DEL
        c_cc[VKILL] = 0x15; // ^U
        c_cc[VEOF] = 0x04; // ^D
        c_cc[VSUSP] = 0x1A; // ^Z
        c_cc[VMIN] = 1;
        c_cc[VTIME] = 0;
        Termios {
            c_iflag: ICRNL,
            c_oflag: OPOST | ONLCR,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK,
            c_cc,
            c_ispeed: 115_200,
            c_ospeed: 115_200,
        }
    }

    /// Raw mode (`cfmakeraw`): no canonical processing, echo, signals or translation.
    pub const fn raw() -> Self {
        let mut t = Self::cooked();
        t.c_iflag = 0;
        t.c_oflag = 0;
        t.c_lflag = 0;
        t.c_cc[VMIN] = 1;
        t.c_cc[VTIME] = 0;
        t
    }
}

/// When a termios change takes effect.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Apply {
    /// TCSANOW: immediately.
    Now,
    /// TCSADRAIN: after queued output drains.
    Drain,
    /// TCSAFLUSH: after draining, and discard pending input.
    Flush,
}

/// A terminal signal, raised by the matching `c_cc` control character under `ISIG`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TtySig {
    Int = 0,
    Quit = 1,
    Susp = 2,
}

/// Typed control interface for a [`Tty`], used by POSIX `tcgetattr`/`tcsetattr` and by
/// applications holding the `&'static Tty`. Avoids raw-pointer ioctl arguments.
pub trait TtyControl: Sync {
    fn get_termios(&self) -> Termios;
    fn set_termios(&self, t: &Termios, when: Apply);
    /// Bind the task that receives terminal-signal notifications, and the bit it gets
    /// for each [`TtySig`] (`bits[sig as usize]`).
    fn set_signal_target(&self, task: TaskId, bits: [u32; 3]);
    /// Event-flag group that also reflects raised signals (`1 << sig`).
    fn signals(&self) -> &EventFlags;
}

const LINE_MAX: usize = 128;

struct LineBuf {
    buf: [u8; LINE_MAX],
    len: usize,
    ready: bool,
}

impl LineBuf {
    const fn new() -> Self {
        LineBuf { buf: [0; LINE_MAX], len: 0, ready: false }
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len < LINE_MAX {
            self.buf[self.len] = b;
            self.len += 1;
            true
        } else {
            false
        }
    }

    fn take(&mut self, out: &mut [u8]) -> Option<usize> {
        if !self.ready {
            return None;
        }
        let n = self.len.min(out.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.buf.copy_within(n..self.len, 0);
        self.len -= n;
        if self.len == 0 {
            self.ready = false;
        }
        Some(n)
    }
}

/// A TTY line discipline. Declare it as a `static` and attach it to a char device.
pub struct Tty {
    termios: IrqCell<Termios>,
    line: IrqCell<LineBuf>,
    /// Raw device bytes read but not yet cooked into a returned line. Preserving these
    /// across reads is what makes a canonical read return exactly one line without
    /// losing the bytes that followed a newline, `VEOF`, or a signal character.
    pending: IrqCell<([u8; 64], usize, usize)>,
    sigtarget: IrqCell<Option<(TaskId, [u32; 3])>>,
    sigs: EventFlags,
    index: IrqCell<Option<u8>>,
}

impl Default for Tty {
    fn default() -> Self {
        Self::new()
    }
}

impl Tty {
    pub const fn new() -> Self {
        Tty {
            termios: IrqCell::new(Termios::cooked()),
            line: IrqCell::new(LineBuf::new()),
            pending: IrqCell::new(([0; 64], 0, 0)),
            sigtarget: IrqCell::new(None),
            sigs: EventFlags::new(),
            index: IrqCell::new(None),
        }
    }

    fn raise(&self, sig: TtySig, t: &Termios) {
        if t.c_lflag & NOFLSH == 0 {
            self.line.lock(|l| {
                l.len = 0;
                l.ready = false;
            });
        }
        if let Some((task, bits)) = self.sigtarget.lock(|s| *s) {
            let _ = task::notify(task, bits[sig as usize]);
        }
        self.sigs.set(1 << sig as u32);
    }

    /// Output post-processing (OPOST/ONLCR/OCRNL): emit `data` through `next`.
    fn write_cooked(&self, data: &[u8], t: &Termios, req: &Request<'_>, next: Next<'_>) -> IoResult {
        if t.c_oflag & OPOST == 0 {
            return next.run(&mut req.derive(Op::Write(data)));
        }
        for chunk in data.split_inclusive(|&b| b == b'\n' || b == b'\r') {
            let (body, last) = match chunk.split_last() {
                Some((&c, body)) if c == b'\n' || c == b'\r' => (body, Some(c)),
                _ => (chunk, None),
            };
            if !body.is_empty() {
                next.run(&mut req.derive(Op::Write(body)))?;
            }
            match last {
                Some(b'\n') if t.c_oflag & ONLCR != 0 => {
                    next.run(&mut req.derive(Op::Write(b"\r\n")))?;
                }
                Some(b'\r') if t.c_oflag & OCRNL != 0 => {
                    next.run(&mut req.derive(Op::Write(b"\n")))?;
                }
                Some(c) => {
                    next.run(&mut req.derive(Op::Write(&[c])))?;
                }
                None => {}
            }
        }
        Ok(data.len())
    }

    fn echo(&self, bytes: &[u8], req: &Request<'_>, next: Next<'_>) {
        let _ = next.run(&mut req.derive(Op::Write(bytes)));
    }

    /// Pop one pending raw byte, or `None` if the buffer is empty.
    fn pending_pop(&self) -> Option<u8> {
        self.pending.lock(|(buf, head, len)| {
            if *len == 0 {
                return None;
            }
            let b = buf[*head];
            *head = (*head + 1) % buf.len();
            *len -= 1;
            Some(b)
        })
    }

    /// Stash raw bytes to be cooked on this or a later read.
    fn pending_push(&self, bytes: &[u8]) {
        self.pending.lock(|(buf, head, len)| {
            let cap = buf.len();
            for &b in bytes {
                if *len == cap {
                    break;
                }
                buf[(*head + *len) % cap] = b;
                *len += 1;
            }
        });
    }

    /// Canonical-mode read: return exactly one completed line. Bytes that arrive after
    /// the terminating newline (or after `VEOF` / a signal) stay in `pending` for the
    /// next read, so none are lost.
    fn read_canonical(&self, buf: &mut [u8], t: &Termios, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        loop {
            if let Some(n) = self.line.lock(|l| l.take(buf)) {
                return Ok(n);
            }
            // Next raw byte: from the pending buffer, else read one chunk and stash the
            // remainder so only one byte is consumed per cooking step.
            let b0 = match self.pending_pop() {
                Some(b) => b,
                None => {
                    let mut raw = [0u8; 32];
                    let got = next.run(&mut req.derive(Op::Read(&mut raw)))?;
                    if got == 0 {
                        return Ok(0);
                    }
                    self.pending_push(&raw[1..got]);
                    raw[0]
                }
            };
            let mut b = b0;
            if t.c_iflag & ISTRIP != 0 {
                b &= 0x7F;
            }
            b = match b {
                b'\r' if t.c_iflag & IGNCR != 0 => continue,
                b'\r' if t.c_iflag & ICRNL != 0 => b'\n',
                b'\n' if t.c_iflag & INLCR != 0 => b'\r',
                _ => b,
            };
            if t.c_lflag & ISIG != 0 {
                let sig = if b == t.c_cc[VINTR] {
                    Some(TtySig::Int)
                } else if b == t.c_cc[VQUIT] {
                    Some(TtySig::Quit)
                } else if b == t.c_cc[VSUSP] {
                    Some(TtySig::Susp)
                } else {
                    None
                };
                if let Some(sig) = sig {
                    self.raise(sig, t); // leftover bytes remain in `pending`
                    return Err(Error::Interrupted);
                }
            }
            if b == t.c_cc[VERASE] {
                let erased = self.line.lock(|l| {
                    if l.len > 0 {
                        l.len -= 1;
                        true
                    } else {
                        false
                    }
                });
                if erased && t.c_lflag & (ECHO | ECHOE) == (ECHO | ECHOE) {
                    self.echo(b"\x08 \x08", req, next);
                }
                continue;
            }
            if b == t.c_cc[VKILL] {
                self.line.lock(|l| l.len = 0);
                if t.c_lflag & ECHOK != 0 {
                    self.echo(b"\r\n", req, next);
                }
                continue;
            }
            if b == t.c_cc[VEOF] {
                // End the line now; on an empty line this is EOF.
                let empty = self.line.lock(|l| l.len == 0);
                if empty {
                    return Ok(0);
                }
                self.line.lock(|l| l.ready = true);
                continue; // outer loop returns the one completed line
            }
            let newline = b == b'\n';
            self.line.lock(|l| {
                l.push(b);
                if newline {
                    l.ready = true;
                }
            });
            if t.c_lflag & ECHO != 0 || (newline && t.c_lflag & ECHONL != 0) {
                if newline {
                    self.echo(b"\r\n", req, next);
                } else {
                    self.echo(&[b], req, next);
                }
            }
        }
    
    }
}

impl Middleware for Tty {
    fn name(&self) -> &'static str {
        "tty"
    }

    fn on_attach(&'static self, ctx: &DeviceCtx) {
        self.index.lock(|i| *i = Some(ctx.device.index() as u8));
        register(ctx.device.index(), self);
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let t = self.termios.lock(|t| *t);
        match &mut req.op {
            Op::Write(data) => {
                let data: &[u8] = data;
                self.write_cooked(data, &t, req, next)
            }
            Op::Read(_) => {
                if t.c_lflag & ICANON == 0 {
                    // Raw mode: pass the read straight through (VMIN/VTIME handled by the
                    // device timeout the caller set).
                    return next.run(req);
                }
                self.read_canonical_dispatch(req, next, &t)
            }
            Op::Ioctl { cmd, .. } => match *cmd {
                ioctl::TTY_FLUSH => {
                    self.line.lock(|l| {
                        l.len = 0;
                        l.ready = false;
                    });
                    self.pending.lock(|(_, head, len)| {
                        *head = 0;
                        *len = 0;
                    });
                    // Also flush the device's own buffer if it supports it; the TTY has
                    // handled the request either way.
                    let _ = next.run(req);
                    Ok(0)
                }
                ioctl::TTY_DRAIN => {
                    let _ = next.run(req);
                    Ok(0)
                }
                _ => next.run(req),
            },
            _ => next.run(req),
        }
    }
}

impl Tty {
    /// Move the read buffer out of `req` so the cooker can own it while still passing
    /// `req` down the chain for echo/raw reads, then restore it. Fully safe.
    fn read_canonical_dispatch(&self, req: &mut Request<'_>, next: Next<'_>, t: &Termios) -> IoResult {
        let Op::Read(buf) = &mut req.op else { return next.run(req) };
        let taken: &mut [u8] = core::mem::take(buf);
        let r = self.read_canonical(taken, t, req, next);
        if let Op::Read(slot) = &mut req.op {
            *slot = taken;
        }
        r
    }
}

impl TtyControl for Tty {
    fn get_termios(&self) -> Termios {
        self.termios.lock(|t| *t)
    }

    fn set_termios(&self, t: &Termios, _when: Apply) {
        self.termios.lock(|cur| *cur = *t);
    }

    fn set_signal_target(&self, task: TaskId, bits: [u32; 3]) {
        self.sigtarget.lock(|s| *s = Some((task, bits)));
    }

    fn signals(&self) -> &EventFlags {
        &self.sigs
    }
}

// ----- registry: map a device index to its Tty control interface -----

static CONTROLS: IrqCell<[Option<&'static dyn TtyControl>; MAX_DEVICES]> = IrqCell::new([None; MAX_DEVICES]);

fn register(index: usize, tty: &'static dyn TtyControl) {
    CONTROLS.lock(|c| {
        if index < MAX_DEVICES {
            c[index] = Some(tty);
        }
    });
}

/// The TTY control interface attached to a device, if any.
///
/// Changing a terminal's settings or its signal target is a privileged operation
/// (it can redirect another task's `Ctrl-C`), so this is available only to trusted
/// (kernel-domain) callers; an isolated domain gets `None`. POSIX `tcgetattr`/
/// `tcsetattr` go through here, so they too are kernel-domain only.
pub fn control(dev: crate::driver::Device) -> Option<&'static dyn TtyControl> {
    if !crate::security::current_is_trusted() {
        return None;
    }
    CONTROLS.lock(|c| c.get(dev.index()).copied().flatten())
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    CONTROLS.lock(|c| *c = [None; MAX_DEVICES]);
}
