//! A simulated RGB565 framebuffer display for host tests and the simulator.
//!
//! Implements the full `Display` protocol (geometry/format/caps, address window,
//! `Write`, flush, backlight, blank) into a static RAM framebuffer, and exposes
//! [`SimDisplay::pixel`] so tests can verify what was drawn.
//!
//! Classification: L2 devices · driver: sim-display · safe · always

use crate::Error;
use crate::driver::ioctl;
use crate::driver::display::{DisplayCaps, PixelFormat};
use crate::driver::middleware::Middleware;
use crate::driver::{DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Op, PowerState, Request};
use crate::kernel::cell::IrqCell;

/// A `W × H` RGB565 framebuffer display. `W*H` pixels are stored in a static array.
pub struct SimDisplay<const W: usize, const H: usize, const PIXELS: usize> {
    fb: IrqCell<[u16; PIXELS]>,
    win: IrqCell<Window>,
    backlight: IrqCell<u8>,
    blanked: IrqCell<bool>,
    flushes: IrqCell<u32>,
}

#[derive(Copy, Clone)]
struct Window {
    x0: u16,
    x1: u16,
    y0: u16,
    y1: u16,
    cx: u16,
    cy: u16,
}

static MW: [&dyn Middleware; 0] = [];

impl<const W: usize, const H: usize, const PIXELS: usize> Default for SimDisplay<W, H, PIXELS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const W: usize, const H: usize, const PIXELS: usize> SimDisplay<W, H, PIXELS> {
    pub const fn new() -> Self {
        assert!(PIXELS == W * H, "PIXELS must equal W*H");
        SimDisplay {
            fb: IrqCell::new([0; PIXELS]),
            win: IrqCell::new(Window { x0: 0, x1: W as u16 - 1, y0: 0, y1: H as u16 - 1, cx: 0, cy: 0 }),
            backlight: IrqCell::new(255),
            blanked: IrqCell::new(false),
            flushes: IrqCell::new(0),
        }
    }

    /// The RGB565 value at `(x, y)` (for tests).
    pub fn pixel(&self, x: u16, y: u16) -> u16 {
        self.fb.lock(|fb| fb.get(y as usize * W + x as usize).copied().unwrap_or(0))
    }

    pub fn backlight(&self) -> u8 {
        self.backlight.lock(|b| *b)
    }

    pub fn flush_count(&self) -> u32 {
        self.flushes.lock(|f| *f)
    }

    fn put(&self, px: u16) {
        self.win.lock(|w| {
            if w.cx <= w.x1 && w.cy <= w.y1 && (w.cx as usize) < W && (w.cy as usize) < H {
                self.fb.lock(|fb| fb[w.cy as usize * W + w.cx as usize] = px);
            }
            if w.cx >= w.x1 {
                w.cx = w.x0;
                w.cy = w.cy.saturating_add(1);
            } else {
                w.cx += 1;
            }
        });
    }
}

impl<const W: usize, const H: usize, const PIXELS: usize> Driver for SimDisplay<W, H, PIXELS> {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "sim-display", class: DeviceClass::Display, version: (1, 0, 0), compatible: &["bismuth,sim-display"] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MW
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        match &mut req.op {
            Op::Write(data) => {
                // RGB565, big-endian on the wire.
                let mut n = 0;
                for px in data.chunks_exact(2) {
                    self.put(u16::from_be_bytes([px[0], px[1]]));
                    n += 2;
                }
                Ok(n)
            }
            Op::Ioctl { cmd, arg } => {
                let a = *arg;
                Ok(match *cmd {
                    ioctl::DISPLAY_GET_GEOMETRY => W | (H << 16),
                    ioctl::DISPLAY_GET_FORMAT => PixelFormat::Rgb565.code() as usize,
                    ioctl::DISPLAY_GET_CAPS => DisplayCaps::BACKLIGHT.with(DisplayCaps::READBACK).0 as usize,
                    ioctl::DISPLAY_SET_COL => {
                        self.win.lock(|w| {
                            w.x0 = a as u16;
                            w.x1 = (a >> 16) as u16;
                            w.cx = w.x0;
                        });
                        0
                    }
                    ioctl::DISPLAY_SET_ROW => {
                        self.win.lock(|w| {
                            w.y0 = a as u16;
                            w.y1 = (a >> 16) as u16;
                            w.cy = w.y0;
                        });
                        0
                    }
                    ioctl::DISPLAY_FLUSH => {
                        self.flushes.lock(|f| *f += 1);
                        0
                    }
                    ioctl::DISPLAY_WAIT_VSYNC => 0,
                    ioctl::DISPLAY_SET_BACKLIGHT => {
                        self.backlight.lock(|b| *b = a as u8);
                        0
                    }
                    ioctl::DISPLAY_BLANK => {
                        self.blanked.lock(|x| *x = a != 0);
                        0
                    }
                    ioctl::GET_CLASS => DeviceClass::Display as usize,
                    _ => return Err(Error::Unsupported),
                })
            }
            _ => Err(Error::Unsupported),
        }
    }

    fn power(&self, _ctx: &DeviceCtx, state: PowerState) -> Result<(), Error> {
        self.blanked.lock(|b| *b = state != PowerState::On);
        Ok(())
    }
}
