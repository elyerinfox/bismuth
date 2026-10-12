//! Simulated environmental sensor.
//!
//! The raw driver produces 12-bit ADC counts the way a real thermistor/ADC front end
//! would; the driver's built-in [`Calibrate`] middleware converts counts to
//! centi-degrees Celsius. Readings follow a deterministic slow wave plus pseudo-random
//! noise, which makes it ideal for exercising edge-compute pipelines in the simulator.
//!
//! Classification: L2 devices · driver: sensor (simulated) · safe · always

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::Error;
use crate::driver::ioctl;
use crate::driver::middleware::{Calibrate, Middleware};
use crate::driver::{DeviceClass, DeviceCtx, DeviceDesc, Driver, DriverInfo, IoResult, Op, PowerState, Request};
use crate::kernel::time;
use crate::sync::IrqCell;

/// counts → centi-°C: 0 counts = -40.00 °C, 4095 counts = +125.00 °C.
static CALIBRATION: Calibrate = Calibrate::named("adc-to-centi-celsius", 16500, 4095, -4000);
static MIDDLEWARE: [&dyn Middleware; 1] = [&CALIBRATION];

pub struct SimSensor {
    channels: AtomicU32,
    rate_hz: AtomicU32,
    suspended: AtomicBool,
    seed: IrqCell<u32>,
    /// Counts injected by tests (`u32::MAX` = use the waveform).
    forced: AtomicU32,
}

impl Default for SimSensor {
    fn default() -> Self {
        Self::new(1)
    }
}

impl SimSensor {
    pub const fn new(channels: u32) -> Self {
        SimSensor {
            channels: AtomicU32::new(channels),
            rate_hz: AtomicU32::new(10),
            suspended: AtomicBool::new(false),
            seed: IrqCell::new(0x1234_5678),
            forced: AtomicU32::new(u32::MAX),
        }
    }

    /// Force the raw ADC output (for tests); `None` returns to the waveform.
    pub fn force_counts(&self, counts: Option<u16>) {
        self.forced.store(counts.map_or(u32::MAX, |c| c as u32), Ordering::Relaxed);
    }

    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::Relaxed)
    }

    fn sample(&self, ch: u32) -> i32 {
        let forced = self.forced.load(Ordering::Relaxed);
        if forced != u32::MAX {
            return forced as i32;
        }
        let t = time::ticks();
        // Triangle wave around ~22 °C (≈1534 counts) with ±40 counts amplitude.
        let period = 2000u64;
        let phase = (t + ch as u64 * 300) % period;
        let tri = if phase < period / 2 { phase } else { period - phase } as i32;
        let wave = tri * 80 / (period as i32 / 2) - 40;
        let noise = self.seed.lock(|s| {
            *s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((*s >> 16) % 9) as i32 - 4
        });
        (1534 + wave + noise).clamp(0, 4095)
    }
}

impl Driver for SimSensor {
    fn info(&self) -> DriverInfo {
        DriverInfo {
            name: "sim-sensor",
            class: DeviceClass::Sensor,
            version: (1, 0, 0),
            compatible: &["bismuth,sim-sensor"],
        }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        match &mut req.op {
            Op::Read(buf) => {
                if self.is_suspended() {
                    return Err(Error::NotReady);
                }
                let ch = self.channels.load(Ordering::Relaxed) as usize;
                let n = ch.min(buf.len() / 4);
                for i in 0..n {
                    buf[i * 4..i * 4 + 4].copy_from_slice(&self.sample(i as u32).to_le_bytes());
                }
                Ok(n * 4)
            }
            Op::Ioctl { cmd: ioctl::SENSOR_CHANNELS, .. } => Ok(self.channels.load(Ordering::Relaxed) as usize),
            Op::Ioctl { cmd: ioctl::SENSOR_SET_RATE_HZ, arg } => {
                if *arg == 0 {
                    return Err(Error::Invalid);
                }
                self.rate_hz.store(*arg as u32, Ordering::Relaxed);
                Ok(0)
            }
            Op::Ioctl { cmd: ioctl::SENSOR_GET_RATE_HZ, .. } => Ok(self.rate_hz.load(Ordering::Relaxed) as usize),
            Op::Ioctl { cmd: ioctl::GET_CLASS, .. } => Ok(DeviceClass::Sensor as usize),
            _ => Err(Error::Unsupported),
        }
    }

    fn power(&self, _ctx: &DeviceCtx, state: PowerState) -> Result<(), Error> {
        self.suspended.store(state != PowerState::On, Ordering::Relaxed);
        Ok(())
    }
}

const SLOTS: usize = 4;
static INSTANCES: [SimSensor; SLOTS] = [const { SimSensor::new(1) }; SLOTS];
static NEXT: IrqCell<usize> = IrqCell::new(0);

pub(crate) fn create(desc: &'static DeviceDesc) -> Result<&'static dyn Driver, Error> {
    let i = NEXT.lock(|n| {
        let i = *n;
        if i < SLOTS {
            *n += 1;
        }
        i
    });
    let s = INSTANCES.get(i).ok_or(Error::NoResources)?;
    if let Some(ch) = desc.param("channels") {
        s.channels.store(ch.clamp(1, 8), Ordering::Relaxed);
    }
    Ok(s)
}
