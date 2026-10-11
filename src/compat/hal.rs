//! `embedded-hal` 1.0 / `embedded-io` compatibility, in both directions.
//!
//! **Bismuth devices → ecosystem traits.** Existing `embedded-hal` device drivers (a
//! BME280 crate, an SSD1306 crate, ...) can run on top of Bismuth devices, and their
//! traffic still flows through the device's middleware chain:
//!
//! | Bismuth view            | implements                                        |
//! |-------------------------|---------------------------------------------------|
//! | [`Serial`]              | `embedded_io::{Read, Write, ReadReady}`           |
//! | [`I2cBus`]              | `embedded_hal::i2c::I2c`                          |
//! | [`Pin`]                 | `embedded_hal::digital::{InputPin, OutputPin, StatefulOutputPin}` |
//! | [`Delay`]               | `embedded_hal::delay::DelayNs` (sleeps, never spins) |
//!
//! **Ecosystem HAL peripherals → Bismuth drivers.** Vendor HAL types can be
//! registered as Bismuth devices, gaining `/dev/*` access, POSIX fds and middleware:
//! [`HalSerialDriver`], [`HalI2cDriver`], [`HalOutputPinDriver`].
//!
//! Classification: L4 personalities · embedded-hal / embedded-io · safe · hal-compat

use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{self, InputPin, OutputPin, StatefulOutputPin};
use embedded_hal::i2c::{self, I2c, Operation};
use embedded_io::{Read, ReadReady, Write};

use crate::Error;
use crate::driver::{gpio::Gpio, i2c::I2cBus, char::Serial, ioctl};
use crate::driver::i2c::AddressCheck;
use crate::driver::middleware::{Middleware, NonBlocking};
use crate::driver::{DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Op, Request};
use crate::kernel::task;
use crate::kernel::time::{Timeout, ms_to_ticks};
use crate::sync::Mutex;

// ----- error mapping -----

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        use embedded_io::ErrorKind as K;
        match self {
            Error::Timeout => K::TimedOut,
            Error::Interrupted => K::Interrupted,
            Error::Invalid | Error::BadHandle | Error::Overflow => K::InvalidInput,
            Error::NotFound | Error::NotReady => K::NotFound,
            Error::PermissionDenied | Error::NotOwner => K::PermissionDenied,
            Error::Exists => K::AlreadyExists,
            Error::NoMemory | Error::NoResources => K::OutOfMemory,
            Error::Unsupported => K::Unsupported,
            _ => K::Other,
        }
    }
}

impl i2c::Error for Error {
    fn kind(&self) -> i2c::ErrorKind {
        match self {
            Error::Io => i2c::ErrorKind::NoAcknowledge(i2c::NoAcknowledgeSource::Unknown),
            Error::Busy => i2c::ErrorKind::ArbitrationLoss,
            _ => i2c::ErrorKind::Other,
        }
    }
}

impl digital::Error for Error {
    fn kind(&self) -> digital::ErrorKind {
        digital::ErrorKind::Other
    }
}

// ----- Bismuth devices as ecosystem traits -----

impl embedded_io::ErrorType for Serial {
    type Error = Error;
}

impl Read for Serial {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        Serial::read(self, buf, Timeout::Forever)
    }
}

impl Write for Serial {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl ReadReady for Serial {
    fn read_ready(&mut self) -> Result<bool, Error> {
        Ok(self.available()? > 0)
    }
}

impl i2c::ErrorType for I2cBus {
    type Error = Error;
}

impl I2c for I2cBus {
    fn transaction(&mut self, address: u8, operations: &mut [Operation<'_>]) -> Result<(), Error> {
        // A write immediately followed by a read is issued as one combined transfer
        // (repeated start); everything else is issued operation by operation.
        let mut i = 0;
        while i < operations.len() {
            let (head, tail) = operations.split_at_mut(i + 1);
            match (&mut head[i], tail.first_mut()) {
                (Operation::Write(tx), Some(Operation::Read(rx))) => {
                    self.0.transfer(address as u16, tx, rx)?;
                    i += 2;
                }
                (Operation::Write(tx), _) => {
                    self.0.transfer(address as u16, tx, &mut [])?;
                    i += 1;
                }
                (Operation::Read(rx), _) => {
                    self.0.transfer(address as u16, &[], rx)?;
                    i += 1;
                }
            }
        }
        Ok(())
    }
}

/// A single pin of a Bismuth GPIO port.
#[derive(Copy, Clone, Debug)]
pub struct Pin {
    port: Gpio,
    mask: u32,
}

impl Pin {
    pub fn new(port: Gpio, pin: u8) -> Self {
        Pin { port, mask: 1 << pin }
    }

    pub fn into_output(self) -> Result<Self, Error> {
        self.port.configure_output(self.mask)?;
        Ok(self)
    }

    pub fn into_input(self) -> Result<Self, Error> {
        self.port.configure_input(self.mask)?;
        Ok(self)
    }
}

impl digital::ErrorType for Pin {
    type Error = Error;
}

impl OutputPin for Pin {
    fn set_low(&mut self) -> Result<(), Error> {
        self.port.clear(self.mask)
    }

    fn set_high(&mut self) -> Result<(), Error> {
        self.port.set(self.mask)
    }
}

impl StatefulOutputPin for Pin {
    fn is_set_high(&mut self) -> Result<bool, Error> {
        Ok(self.port.get()? & self.mask != 0)
    }

    fn is_set_low(&mut self) -> Result<bool, Error> {
        Ok(self.port.get()? & self.mask == 0)
    }

    fn toggle(&mut self) -> Result<(), Error> {
        self.port.toggle(self.mask)
    }
}

impl InputPin for Pin {
    fn is_high(&mut self) -> Result<bool, Error> {
        Ok(self.port.get()? & self.mask != 0)
    }

    fn is_low(&mut self) -> Result<bool, Error> {
        Ok(self.port.get()? & self.mask == 0)
    }
}

/// `DelayNs` backed by the scheduler: the calling task sleeps instead of spinning,
/// so other tasks run during the delay. Delays shorter than a tick just yield.
#[derive(Copy, Clone, Debug, Default)]
pub struct Delay;

impl DelayNs for Delay {
    fn delay_ns(&mut self, ns: u32) {
        let ms = (ns as u64).div_ceil(1_000_000);
        if ms_to_ticks(ms) == 0 || ns < 1_000_000 {
            task::yield_now();
        } else {
            task::sleep_ms(ms);
        }
    }

    fn delay_ms(&mut self, ms: u32) {
        task::sleep_ms(ms as u64);
    }
}

// ----- ecosystem HAL peripherals as Bismuth drivers -----

static NONBLOCKING: NonBlocking = NonBlocking;
static SERIAL_MW: [&dyn Middleware; 1] = [&NONBLOCKING];
static ADDRESS_CHECK: AddressCheck = AddressCheck;
static I2C_MW: [&dyn Middleware; 1] = [&ADDRESS_CHECK];
static PIN_MW: [&dyn Middleware; 0] = [];

/// Registers any `embedded-io` serial port (e.g. a vendor HAL UART) as a Bismuth
/// character device. Reads honour the request timeout by polling `read_ready`.
pub struct HalSerialDriver<T> {
    inner: Mutex<T>,
}

impl<T> HalSerialDriver<T> {
    pub const fn new(inner: T) -> Self {
        HalSerialDriver { inner: Mutex::new(inner) }
    }
}

impl<T> Driver for HalSerialDriver<T>
where
    T: Read + Write + ReadReady + Send,
{
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "hal-serial", class: DeviceClass::Char, version: (1, 0, 0), compatible: &[] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &SERIAL_MW
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let timeout = req.timeout;
        match &mut req.op {
            Op::Write(data) => {
                let mut io = self.inner.lock()?;
                io.write_all(data).map_err(|_| Error::Io)?;
                Ok(data.len())
            }
            Op::Read(buf) => {
                let deadline = crate::kernel::time::ticks().saturating_add(match timeout {
                    Timeout::NoWait => 0,
                    Timeout::Ticks(t) => t,
                    Timeout::Forever => u64::MAX,
                });
                loop {
                    {
                        let mut io = self.inner.lock()?;
                        if io.read_ready().map_err(|_| Error::Io)? {
                            return io.read(buf).map_err(|_| Error::Io);
                        }
                    }
                    if crate::kernel::time::ticks() >= deadline {
                        return Err(if timeout == Timeout::NoWait { Error::WouldBlock } else { Error::Timeout });
                    }
                    task::sleep_ticks(1);
                }
            }
            Op::Ioctl { cmd: ioctl::SERIAL_RX_AVAILABLE, .. } => {
                Ok(self.inner.lock()?.read_ready().map_err(|_| Error::Io)? as usize)
            }
            Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::Char as usize),
            _ => Err(Error::Unsupported),
        }
    }
}

/// Registers any `embedded-hal` I2C controller as a Bismuth I2C bus device.
pub struct HalI2cDriver<T> {
    inner: Mutex<T>,
}

impl<T> HalI2cDriver<T> {
    pub const fn new(inner: T) -> Self {
        HalI2cDriver { inner: Mutex::new(inner) }
    }
}

impl<T: I2c + Send> Driver for HalI2cDriver<T> {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "hal-i2c", class: DeviceClass::I2c, version: (1, 0, 0), compatible: &[] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &I2C_MW
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        match &mut req.op {
            Op::Transfer { addr, tx, rx } => {
                let mut bus = self.inner.lock()?;
                let addr = *addr as u8;
                let r = match (tx.is_empty(), rx.is_empty()) {
                    (false, false) => bus.write_read(addr, tx, rx),
                    (false, true) => bus.write(addr, tx),
                    (true, _) => bus.read(addr, rx),
                };
                r.map_err(|e| match i2c::Error::kind(&e) {
                    i2c::ErrorKind::NoAcknowledge(_) => Error::Io,
                    i2c::ErrorKind::ArbitrationLoss => Error::Busy,
                    _ => Error::Io,
                })?;
                Ok(rx.len())
            }
            Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::I2c as usize),
            _ => Err(Error::Unsupported),
        }
    }
}

/// Registers an `embedded-hal` output pin as a one-pin GPIO device (pin 0).
pub struct HalOutputPinDriver<P> {
    inner: Mutex<(P, bool)>,
}

impl<P> HalOutputPinDriver<P> {
    pub const fn new(pin: P) -> Self {
        HalOutputPinDriver { inner: Mutex::new((pin, false)) }
    }
}

impl<P: OutputPin + Send> Driver for HalOutputPinDriver<P> {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "hal-output-pin", class: DeviceClass::Gpio, version: (1, 0, 0), compatible: &[] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &PIN_MW
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let Op::Ioctl { cmd, arg } = req.op else { return Err(Error::Unsupported) };
        let mut g = self.inner.lock()?;
        let (pin, level) = &mut *g;
        let hit = arg & 1 != 0;
        let new = match cmd {
            ioctl::GPIO_SET if hit => true,
            ioctl::GPIO_CLEAR if hit => false,
            ioctl::GPIO_TOGGLE if hit => !*level,
            ioctl::GPIO_GET => return Ok(*level as usize),
            ioctl::GPIO_CONFIG_OUTPUT => return Ok(0),
            ioctl::GET_CLASS => return Ok(DeviceClass::Gpio as usize),
            ioctl::GPIO_SET | ioctl::GPIO_CLEAR | ioctl::GPIO_TOGGLE => return Ok(0),
            _ => return Err(Error::Unsupported),
        };
        if new { pin.set_high() } else { pin.set_low() }.map_err(|_| Error::Io)?;
        *level = new;
        Ok(0)
    }
}
