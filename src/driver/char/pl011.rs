//! ARM PrimeCell PL011 UART (found on QEMU `lm3s6965evb`, `virt`, many SoCs).
//!
//! Polled implementation: transmit spins on the FIFO-full flag; blocking reads poll the
//! receive FIFO and sleep one tick between polls so other tasks keep running.
//! All register access goes through a safe [`Mmio`] window.
//!
//! Classification: L2 devices · driver: char (PL011 UART) · safe · always

use core::sync::atomic::{AtomicU32, Ordering};

use crate::Error;
use crate::arch::mmio::Mmio;
use crate::driver::ioctl;
use crate::driver::middleware::Middleware;
use crate::driver::{DeviceClass, DeviceCtx, DeviceDesc, Driver, DriverInfo, IoResult, Next, Op, Request};
use crate::kernel::cell::IrqCell;
use crate::kernel::task;
use crate::kernel::time::Deadline;

const DR: usize = 0x00;
const FR: usize = 0x18;
const FR_RXFE: u32 = 1 << 4;
const FR_TXFF: u32 = 1 << 5;
/// Size of the PL011 register block.
pub const REGISTER_SPAN: usize = 0x1000;

/// Built-in middleware: terminal line discipline. Output `\n` becomes `\r\n`; input
/// `\r` becomes `\n`.
pub struct LineDiscipline;

impl Middleware for LineDiscipline {
    fn name(&self) -> &'static str {
        "line-discipline"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        match &req.op {
            Op::Write(data) => {
                let data: &[u8] = data;
                let mut written = 0;
                for chunk in data.split_inclusive(|&b| b == b'\n') {
                    let (body, nl) = match chunk.split_last() {
                        Some((b'\n', body)) => (body, true),
                        _ => (chunk, false),
                    };
                    if !body.is_empty() {
                        next.run(&mut req.derive(Op::Write(body)))?;
                    }
                    if nl {
                        next.run(&mut req.derive(Op::Write(b"\r\n")))?;
                    }
                    written += chunk.len();
                }
                Ok(written)
            }
            Op::Read(_) => {
                let n = next.run(req)?;
                if let Op::Read(buf) = &mut req.op {
                    for b in buf[..n].iter_mut() {
                        if *b == b'\r' {
                            *b = b'\n';
                        }
                    }
                }
                Ok(n)
            }
            _ => next.run(req),
        }
    }
}

static LINE_DISCIPLINE: LineDiscipline = LineDiscipline;
static MIDDLEWARE: [&dyn Middleware; 1] = [&LINE_DISCIPLINE];

pub struct Pl011 {
    regs: IrqCell<Option<Mmio>>,
    baud: AtomicU32,
}

impl Pl011 {
    pub const fn new(regs: Mmio) -> Self {
        Pl011 { regs: IrqCell::new(Some(regs)), baud: AtomicU32::new(115_200) }
    }

    const fn unbound() -> Self {
        Pl011 { regs: IrqCell::new(None), baud: AtomicU32::new(115_200) }
    }

    fn regs(&self) -> Result<Mmio, Error> {
        self.regs.lock(|r| *r).ok_or(Error::NotReady)
    }

    fn put(&self, m: &Mmio, b: u8) {
        while m.read32(FR) & FR_TXFF != 0 {}
        m.write32(DR, b as u32);
    }

    fn get(&self, m: &Mmio) -> Option<u8> {
        if m.read32(FR) & FR_RXFE != 0 { None } else { Some(m.read32(DR) as u8) }
    }
}

impl Driver for Pl011 {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "pl011", class: DeviceClass::Char, version: (1, 0, 0), compatible: &["arm,pl011"] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let timeout = req.timeout;
        let m = self.regs()?;
        match &mut req.op {
            Op::Write(data) => {
                for &b in data.iter() {
                    self.put(&m, b);
                }
                Ok(data.len())
            }
            Op::Read(buf) => {
                if buf.is_empty() {
                    return Ok(0);
                }
                let deadline = timeout.deadline(crate::kernel::time::ticks());
                loop {
                    let mut n = 0;
                    while n < buf.len() {
                        match self.get(&m) {
                            Some(b) => {
                                buf[n] = b;
                                n += 1;
                            }
                            None => break,
                        }
                    }
                    if n > 0 {
                        return Ok(n);
                    }
                    match deadline {
                        Deadline::Now => return Err(Error::WouldBlock),
                        Deadline::At(t) if crate::kernel::time::ticks() >= t => return Err(Error::Timeout),
                        _ => task::sleep_ticks(1),
                    }
                }
            }
            Op::Ioctl { cmd: ioctl::SERIAL_SET_BAUD, arg } => {
                // The baud divisor depends on the board clock; record the request.
                self.baud.store(*arg as u32, Ordering::Relaxed);
                Ok(0)
            }
            Op::Ioctl { cmd: ioctl::SERIAL_GET_BAUD, .. } => Ok(self.baud.load(Ordering::Relaxed) as usize),
            Op::Ioctl { cmd: ioctl::SERIAL_RX_AVAILABLE, .. } => Ok((m.read32(FR) & FR_RXFE == 0) as usize),
            Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::Char as usize),
            _ => Err(Error::Unsupported),
        }
    }
}

const SLOTS: usize = 4;
static INSTANCES: [Pl011; SLOTS] = [const { Pl011::unbound() }; SLOTS];

pub(crate) fn create(desc: &'static DeviceDesc) -> Result<&'static dyn Driver, Error> {
    let mmio = desc.mmio.ok_or(Error::Invalid)?;
    let uart = INSTANCES
        .iter()
        .find(|u| {
            u.regs.lock(|r| {
                if r.is_none() {
                    *r = Some(mmio);
                    true
                } else {
                    false
                }
            })
        })
        .ok_or(Error::NoResources)?;
    if let Some(b) = desc.param("baud") {
        uart.baud.store(b, Ordering::Relaxed);
    }
    Ok(uart)
}
