//! Simulated I2C bus with pluggable emulated targets.
//!
//! Classification: L2 devices · driver: i2c (simulated) · safe · always

use crate::Error;
use crate::driver::ioctl;
use crate::driver::middleware::Middleware;
use crate::driver::{DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Next, Op, Request};
use crate::sync::IrqCell;

/// An emulated I2C peripheral living on a [`SimI2c`] bus.
pub trait I2cTarget: Sync {
    fn address(&self) -> u8;
    /// Handle a write-then-read transaction. Returns `Err(Error::Io)` to NACK.
    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), Error>;
}

/// Built-in middleware: rejects reserved 7-bit addresses (0x00–0x07, 0x78–0x7F) and
/// empty transactions before they reach the bus.
pub struct AddressCheck;

impl Middleware for AddressCheck {
    fn name(&self) -> &'static str {
        "i2c-address-check"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        if let Op::Transfer { addr, tx, rx } = &req.op {
            if !(0x08..=0x77).contains(addr) || (tx.is_empty() && rx.is_empty()) {
                return Err(Error::Invalid);
            }
        }
        next.run(req)
    }
}

static ADDRESS_CHECK: AddressCheck = AddressCheck;
static MIDDLEWARE: [&dyn Middleware; 1] = [&ADDRESS_CHECK];

const SLOTS: usize = 2;
static INSTANCES: [SimI2c; SLOTS] = [const { SimI2c::new() }; SLOTS];
static NEXT: crate::sync::IrqCell<usize> = crate::sync::IrqCell::new(0);

pub(crate) fn create(_desc: &'static DeviceDesc) -> Result<&'static dyn Driver, Error> {
    let i = NEXT.lock(|n| {
        let i = *n;
        if i < SLOTS {
            *n += 1;
        }
        i
    });
    INSTANCES.get(i).map(|x| x as &dyn Driver).ok_or(Error::NoResources)
}

/// Factory binding `bismuth,sim-i2c`.
pub const FACTORY: DriverFactory = DriverFactory { compatible: &["bismuth,sim-i2c"], create };

use crate::driver::{DeviceDesc, DriverFactory};

/// A simulated I2C controller with up to 8 targets.
pub struct SimI2c {
    targets: IrqCell<[Option<&'static dyn I2cTarget>; 8]>,
    speed: IrqCell<u32>,
}

impl Default for SimI2c {
    fn default() -> Self {
        Self::new()
    }
}

impl SimI2c {
    pub const fn new() -> Self {
        SimI2c { targets: IrqCell::new([None; 8]), speed: IrqCell::new(100_000) }
    }

    pub fn attach(&self, t: &'static dyn I2cTarget) -> Result<(), Error> {
        self.targets.lock(|ts| {
            if ts.iter().flatten().any(|x| x.address() == t.address()) {
                return Err(Error::Exists);
            }
            let slot = ts.iter_mut().find(|s| s.is_none()).ok_or(Error::NoResources)?;
            *slot = Some(t);
            Ok(())
        })
    }
}

impl Driver for SimI2c {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "sim-i2c", class: DeviceClass::I2c, version: (1, 0, 0), compatible: &["bismuth,sim-i2c"] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        match &mut req.op {
            Op::Transfer { addr, tx, rx } => {
                let t = self
                    .targets
                    .lock(|ts| ts.iter().flatten().find(|t| t.address() as u16 == *addr).copied())
                    .ok_or(Error::Io)?; // no ACK
                t.transfer(tx, rx)?;
                Ok(rx.len())
            }
            Op::Ioctl { cmd: ioctl::BUS_SET_SPEED_HZ, arg } => {
                let hz = *arg as u32;
                self.speed.lock(|s| *s = hz);
                Ok(0)
            }
            Op::Ioctl { cmd: ioctl::BUS_GET_SPEED_HZ, .. } => Ok(self.speed.lock(|s| *s) as usize),
            Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::I2c as usize),
            _ => Err(Error::Unsupported),
        }
    }
}

/// Emulated TMP102-style temperature sensor: register 0 holds the temperature as a
/// 12-bit left-aligned value in 1/16 °C steps.
pub struct Tmp102 {
    addr: u8,
    centi_c: IrqCell<i32>,
}

impl Tmp102 {
    pub const fn new(addr: u8, centi_c: i32) -> Self {
        Tmp102 { addr, centi_c: IrqCell::new(centi_c) }
    }

    pub fn set_temperature(&self, centi_c: i32) {
        self.centi_c.lock(|t| *t = centi_c);
    }
}

impl I2cTarget for Tmp102 {
    fn address(&self) -> u8 {
        self.addr
    }

    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), Error> {
        if tx.first().copied().unwrap_or(0) != 0 {
            return Err(Error::Io);
        }
        let raw = (self.centi_c.lock(|t| *t) * 16 / 100) as i16;
        let reg = (raw << 4).to_be_bytes();
        for (d, s) in rx.iter_mut().zip(reg) {
            *d = s;
        }
        Ok(())
    }
}
