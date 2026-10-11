//! GPIO devices: digital I/O ports.
//!
//! Classification: L2 devices · gpio class · safe · always

pub mod sim;

pub use sim::{Debounce, SimGpio};

use crate::Error;
use crate::driver::ioctl;
use crate::driver::{Device, DeviceClass, expect};

/// GPIO port of up to 32 pins.
#[derive(Copy, Clone, Debug)]
pub struct Gpio(pub Device);

impl Gpio {
    pub fn open(name: &str) -> Result<Self, Error> {
        Ok(Gpio(expect(Device::find(name)?, DeviceClass::Gpio)?))
    }

    pub fn configure_output(&self, mask: u32) -> Result<(), Error> {
        self.0.ioctl(ioctl::GPIO_CONFIG_OUTPUT, mask as usize).map(|_| ())
    }

    pub fn configure_input(&self, mask: u32) -> Result<(), Error> {
        self.0.ioctl(ioctl::GPIO_CONFIG_INPUT, mask as usize).map(|_| ())
    }

    pub fn set(&self, mask: u32) -> Result<(), Error> {
        self.0.ioctl(ioctl::GPIO_SET, mask as usize).map(|_| ())
    }

    pub fn clear(&self, mask: u32) -> Result<(), Error> {
        self.0.ioctl(ioctl::GPIO_CLEAR, mask as usize).map(|_| ())
    }

    pub fn toggle(&self, mask: u32) -> Result<(), Error> {
        self.0.ioctl(ioctl::GPIO_TOGGLE, mask as usize).map(|_| ())
    }

    pub fn get(&self) -> Result<u32, Error> {
        self.0.ioctl(ioctl::GPIO_GET, 0).map(|v| v as u32)
    }

    pub fn is_high(&self, pin: u8) -> Result<bool, Error> {
        Ok(self.get()? & (1 << pin) != 0)
    }
}
