//! NS16550(A)-compatible UART with 32-bit-spaced registers (Tegra/Jetson, DesignWare APB,
//! many ARM SoCs). Polled, like the PL011 driver: transmit spins on the THR-empty flag;
//! blocking reads poll the receive register and sleep one tick between polls. All register
//! access goes through a safe [`Mmio`] window — no `unsafe` here.
//!
//! Classification: L2 devices · driver: char (NS16550 UART) · safe · always

use core::sync::atomic::{AtomicU32, Ordering};

use crate::Error;
use crate::arch::mmio::Mmio;
use crate::driver::char::pl011::LineDiscipline;
use crate::driver::ioctl;
use crate::driver::middleware::Middleware;
use crate::driver::{DeviceClass, DeviceCtx, DeviceDesc, Driver, DriverInfo, IoResult, Op, Request};
use crate::kernel::cell::IrqCell;
use crate::kernel::task;
use crate::kernel::time::Deadline;

// 32-bit-spaced registers (register index × 4), the common ARM-SoC layout.
const THR: usize = 0x00; // transmit holding / receive buffer
const LSR: usize = 0x14; // line status register (index 5)
const LSR_DR: u32 = 1 << 0; // receive data ready
const LSR_THRE: u32 = 1 << 5; // transmit holding register empty
/// Size of the register block.
pub const REGISTER_SPAN: usize = 0x100;

static LINE_DISCIPLINE: LineDiscipline = LineDiscipline;
static MIDDLEWARE: [&dyn Middleware; 1] = [&LINE_DISCIPLINE];

pub struct Ns16550 {
    regs: IrqCell<Option<Mmio>>,
    baud: AtomicU32,
}

impl Ns16550 {
    const fn unbound() -> Self {
        Ns16550 { regs: IrqCell::new(None), baud: AtomicU32::new(115_200) }
    }

    fn regs(&self) -> Result<Mmio, Error> {
        self.regs.lock(|r| *r).ok_or(Error::NotReady)
    }

    fn put(&self, m: &Mmio, b: u8) {
        while m.read32(LSR) & LSR_THRE == 0 {}
        m.write32(THR, b as u32);
    }

    fn get(&self, m: &Mmio) -> Option<u8> {
        if m.read32(LSR) & LSR_DR == 0 { None } else { Some(m.read32(THR) as u8) }
    }
}

impl Driver for Ns16550 {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "ns16550", class: DeviceClass::Char, version: (1, 0, 0), compatible: &["ns16550", "ns16550a", "snps,dw-apb-uart"] }
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
                self.baud.store(*arg as u32, Ordering::Relaxed);
                Ok(0)
            }
            Op::Ioctl { cmd: ioctl::SERIAL_GET_BAUD, .. } => Ok(self.baud.load(Ordering::Relaxed) as usize),
            Op::Ioctl { cmd: ioctl::SERIAL_RX_AVAILABLE, .. } => Ok((m.read32(LSR) & LSR_DR != 0) as usize),
            Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::Char as usize),
            _ => Err(Error::Unsupported),
        }
    }
}

const SLOTS: usize = 2;
static INSTANCES: [Ns16550; SLOTS] = [const { Ns16550::unbound() }; SLOTS];

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
