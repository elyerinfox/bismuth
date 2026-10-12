//! Simulated GPIO port with a built-in debouncing middleware.
//!
//! Classification: L2 devices · driver: gpio (simulated) · safe · always

use core::sync::atomic::{AtomicU32, Ordering};

use crate::Error;
use crate::driver::ioctl;
use crate::driver::middleware::Middleware;
use crate::driver::{DeviceClass, DeviceCtx, DeviceDesc, Driver, DriverInfo, IoResult, Next, Op, Request};
use crate::kernel::time;
use crate::sync::IrqCell;

/// Debounces input pins: a pin's reported level only changes once the raw level has
/// been stable for `ticks` ticks. Output pins pass through unchanged.
pub struct Debounce {
    ticks: u64,
    /// (stable value, last raw value, tick when the raw value last changed)
    state: IrqCell<(u32, u32, u64, bool)>,
    input_mask: AtomicU32,
}

impl Debounce {
    pub const fn new(ticks: u64) -> Self {
        Debounce { ticks, state: IrqCell::new((0, 0, 0, false)), input_mask: AtomicU32::new(u32::MAX) }
    }
}

impl Middleware for Debounce {
    fn name(&self) -> &'static str {
        "debounce"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let r = next.run(req)?;
        match req.op {
            Op::Ioctl { cmd: ioctl::GPIO_CONFIG_INPUT, arg } => {
                self.input_mask.fetch_or(arg as u32, Ordering::Relaxed);
                Ok(r)
            }
            Op::Ioctl { cmd: ioctl::GPIO_CONFIG_OUTPUT, arg } => {
                self.input_mask.fetch_and(!(arg as u32), Ordering::Relaxed);
                Ok(r)
            }
            Op::Ioctl { cmd: ioctl::GPIO_GET, .. } => {
                let raw = r as u32;
                let inputs = self.input_mask.load(Ordering::Relaxed);
                let now = time::ticks();
                let stable = self.state.lock(|(stable, last, since, init)| {
                    if !*init {
                        *stable = raw;
                        *last = raw;
                        *since = now;
                        *init = true;
                    }
                    if raw != *last {
                        *last = raw;
                        *since = now;
                    }
                    if now.saturating_sub(*since) >= self.ticks {
                        *stable = raw;
                    }
                    *stable
                });
                Ok(((stable & inputs) | (raw & !inputs)) as usize)
            }
            _ => Ok(r),
        }
    }
}

/// A 32-pin GPIO port held in memory. Tests drive inputs with [`SimGpio::drive_inputs`].
pub struct SimGpio {
    out: AtomicU32,
    inputs: AtomicU32,
    dir_out: AtomicU32,
}

static DEBOUNCE: Debounce = Debounce::new(5);
static MIDDLEWARE: [&dyn Middleware; 1] = [&DEBOUNCE];

impl Default for SimGpio {
    fn default() -> Self {
        Self::new()
    }
}

impl SimGpio {
    pub const fn new() -> Self {
        SimGpio { out: AtomicU32::new(0), inputs: AtomicU32::new(0), dir_out: AtomicU32::new(0) }
    }

    /// Set the externally driven level of the input pins (simulated hardware).
    pub fn drive_inputs(&self, levels: u32) {
        self.inputs.store(levels, Ordering::Relaxed);
    }

    /// Current output latch (what an external observer would see on output pins).
    pub fn outputs(&self) -> u32 {
        self.out.load(Ordering::Relaxed) & self.dir_out.load(Ordering::Relaxed)
    }
}

impl Driver for SimGpio {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "sim-gpio", class: DeviceClass::Gpio, version: (1, 0, 0), compatible: &["bismuth,sim-gpio"] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let Op::Ioctl { cmd, arg } = req.op else { return Err(Error::Unsupported) };
        let m = arg as u32;
        match cmd {
            ioctl::GPIO_SET => self.out.fetch_or(m, Ordering::Relaxed),
            ioctl::GPIO_CLEAR => self.out.fetch_and(!m, Ordering::Relaxed),
            ioctl::GPIO_TOGGLE => self.out.fetch_xor(m, Ordering::Relaxed),
            ioctl::GPIO_CONFIG_OUTPUT => self.dir_out.fetch_or(m, Ordering::Relaxed),
            ioctl::GPIO_CONFIG_INPUT => self.dir_out.fetch_and(!m, Ordering::Relaxed),
            ioctl::GPIO_GET => {
                let dir = self.dir_out.load(Ordering::Relaxed);
                return Ok(((self.out.load(Ordering::Relaxed) & dir) | (self.inputs.load(Ordering::Relaxed) & !dir))
                    as usize);
            }
            ioctl::GET_CLASS => return Ok(DeviceClass::Gpio as usize),
            _ => return Err(Error::Unsupported),
        };
        Ok(0)
    }
}

static INSTANCE: SimGpio = SimGpio::new();

pub(crate) fn create(_desc: &'static DeviceDesc) -> Result<&'static dyn Driver, Error> {
    Ok(&INSTANCE)
}
