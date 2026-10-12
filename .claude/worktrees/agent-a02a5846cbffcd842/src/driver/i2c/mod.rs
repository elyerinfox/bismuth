//! I2C bus controllers and emulated targets.
//!
//! Classification: L2 devices · i2c class · safe · always

pub mod sim;

pub use sim::{AddressCheck, I2cTarget, SimI2c, Tmp102};

use crate::Error;
use crate::driver::{Device, DeviceClass, expect};

/// I2C bus controller.
#[derive(Copy, Clone, Debug)]
pub struct I2cBus(pub Device);

impl I2cBus {
    pub fn open(name: &str) -> Result<Self, Error> {
        Ok(I2cBus(expect(Device::find(name)?, DeviceClass::I2c)?))
    }

    pub fn write(&self, addr: u8, bytes: &[u8]) -> Result<(), Error> {
        self.0.transfer(addr as u16, bytes, &mut []).map(|_| ())
    }

    pub fn read(&self, addr: u8, buf: &mut [u8]) -> Result<(), Error> {
        self.0.transfer(addr as u16, &[], buf).map(|_| ())
    }

    pub fn write_read(&self, addr: u8, tx: &[u8], rx: &mut [u8]) -> Result<(), Error> {
        self.0.transfer(addr as u16, tx, rx).map(|_| ())
    }
}
