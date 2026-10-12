//! Sampled sensor devices.
//!
//! Classification: L2 devices · sensor class · safe · always

pub mod sim;

pub use sim::SimSensor;

use crate::Error;
use crate::driver::ioctl;
use crate::driver::{Device, DeviceClass, expect};

/// Sampled sensor. Each sample is one little-endian `i32` per channel.
#[derive(Copy, Clone, Debug)]
pub struct Sensor(pub Device);

impl Sensor {
    pub fn open(name: &str) -> Result<Self, Error> {
        Ok(Sensor(expect(Device::find(name)?, DeviceClass::Sensor)?))
    }

    pub fn channels(&self) -> Result<usize, Error> {
        self.0.ioctl(ioctl::SENSOR_CHANNELS, 0)
    }

    /// Read one sample into `out` (one value per channel). Returns the number of
    /// channels filled; `0` means the middleware suppressed the reading (e.g. deadband).
    pub fn read(&self, out: &mut [i32]) -> Result<usize, Error> {
        let mut raw = [0u8; 4 * 8];
        let want = (out.len().min(8)) * 4;
        let n = self.0.read(&mut raw[..want])?;
        for (i, c) in raw[..n].chunks_exact(4).enumerate() {
            out[i] = i32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }
        Ok(n / 4)
    }

    pub fn set_rate_hz(&self, hz: u32) -> Result<(), Error> {
        self.0.ioctl(ioctl::SENSOR_SET_RATE_HZ, hz as usize).map(|_| ())
    }
}
