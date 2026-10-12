//! Character devices: byte streams (UART, pipe, PTY) and the TTY line discipline.
//!
//! Holds the [`Serial`] typed wrapper, the [`tty`] line-discipline middleware, and the
//! bundled char drivers ([`Pipe`], [`Pl011`], [`Pty`]).
//!
//! Classification: L2 devices · char class · safe · always

pub mod ns16550;
pub mod pipe;
pub mod pl011;
pub mod pty;
pub mod tty;

pub use pipe::Pipe;
pub use pl011::{LineDiscipline, Pl011};
pub use pty::{Pty, PtyMaster, PtySlave};
pub use tty::{Apply, Termios, Tty, TtyControl, TtySig, control};

use crate::Error;
use crate::driver::ioctl;
use crate::driver::{Device, DeviceClass, expect};
use crate::kernel::time::Timeout;

/// Byte-stream device (UART, pipe, ...).
#[derive(Copy, Clone, Debug)]
pub struct Serial(pub Device);

impl Serial {
    pub fn open(name: &str) -> Result<Self, Error> {
        Ok(Serial(expect(Device::find(name)?, DeviceClass::Char)?))
    }

    pub fn read(&self, buf: &mut [u8], timeout: Timeout) -> Result<usize, Error> {
        self.0.read_timeout(buf, timeout)
    }

    pub fn write(&self, buf: &[u8]) -> Result<(), Error> {
        self.0.write_all(buf)
    }

    pub fn set_baud(&self, baud: u32) -> Result<(), Error> {
        self.0.ioctl(ioctl::SERIAL_SET_BAUD, baud as usize).map(|_| ())
    }

    pub fn available(&self) -> Result<usize, Error> {
        self.0.ioctl(ioctl::SERIAL_RX_AVAILABLE, 0)
    }
}
