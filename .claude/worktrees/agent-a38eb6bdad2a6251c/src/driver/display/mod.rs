//! Display device class: framebuffers and small panels.
//!
//! A display is an ordinary [`Driver`](crate::driver::Driver) in
//! [`DeviceClass::Display`](crate::driver::DeviceClass): geometry/format/caps are
//! queried with ioctls, a damage window is set with `DISPLAY_SET_COL`/`DISPLAY_SET_ROW`
//! (the controller's `CASET`/`RASET`), pixels are streamed with `Op::Write` (`RAMWR`),
//! and `DISPLAY_FLUSH` pushes a buffered/e-paper frame to the glass. No new `Op` variant
//! is added, so the whole driver/middleware stack applies unchanged.
//!
//! Classification: L2 devices · display class · safe · always

use crate::Error;
use crate::driver::ioctl;
use crate::driver::{Device, DeviceClass, Op, Request};
use crate::kernel::time::Timeout;

pub mod sim;
pub use sim::SimDisplay;

/// In-memory pixel layout a display reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// 1 bpp. `page_major` = 8 vertical pixels per byte (SSD1306); else 8 horizontal.
    Mono1 { page_major: bool },
    /// 4 bpp grayscale, 2 pixels per byte.
    Gray4,
    /// 16 bpp 5-6-5, big-endian on the wire (most color TFT).
    Rgb565,
    /// 24 bpp.
    Rgb888,
}

impl PixelFormat {
    pub const fn bits_per_pixel(self) -> u8 {
        match self {
            PixelFormat::Mono1 { .. } => 1,
            PixelFormat::Gray4 => 4,
            PixelFormat::Rgb565 => 16,
            PixelFormat::Rgb888 => 24,
        }
    }

    /// Bytes for a `w × h` region in this format.
    pub const fn region_bytes(self, w: u16, h: u16) -> usize {
        let (w, h) = (w as usize, h as usize);
        match self {
            PixelFormat::Mono1 { .. } => w * h.div_ceil(8),
            PixelFormat::Gray4 => (w * h).div_ceil(2),
            PixelFormat::Rgb565 => w * h * 2,
            PixelFormat::Rgb888 => w * h * 3,
        }
    }

    /// Discriminant used by `DISPLAY_GET_FORMAT`.
    pub const fn code(self) -> u32 {
        match self {
            PixelFormat::Mono1 { page_major: false } => 0,
            PixelFormat::Mono1 { page_major: true } => 1,
            PixelFormat::Gray4 => 2,
            PixelFormat::Rgb565 => 3,
            PixelFormat::Rgb888 => 4,
        }
    }

    pub const fn from_code(v: u32) -> Option<PixelFormat> {
        Some(match v {
            0 => PixelFormat::Mono1 { page_major: false },
            1 => PixelFormat::Mono1 { page_major: true },
            2 => PixelFormat::Gray4,
            3 => PixelFormat::Rgb565,
            4 => PixelFormat::Rgb888,
            _ => return None,
        })
    }
}

/// A rectangle in pixels.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Rect { x, y, w, h }
    }
}

/// Display capability flags (advertised; the core/typed API falls back in software).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DisplayCaps(pub u32);

impl DisplayCaps {
    pub const NONE: DisplayCaps = DisplayCaps(0);
    pub const PARTIAL_REFRESH: DisplayCaps = DisplayCaps(1 << 0);
    pub const BACKLIGHT: DisplayCaps = DisplayCaps(1 << 1);
    pub const VSYNC_TE: DisplayCaps = DisplayCaps(1 << 2);
    pub const READBACK: DisplayCaps = DisplayCaps(1 << 5);

    pub const fn contains(self, other: DisplayCaps) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn with(self, other: DisplayCaps) -> DisplayCaps {
        DisplayCaps(self.0 | other.0)
    }
}

/// Frame flush mode for buffered / e-paper displays.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RefreshMode {
    Full = 0,
    Partial = 1,
    Fast = 2,
}

/// Typed view of a display device (like [`Serial`](crate::driver::char::Serial)).
#[derive(Copy, Clone, Debug)]
pub struct Display(pub Device);

impl Display {
    pub fn open(name: &str) -> Result<Self, Error> {
        let dev = Device::find(name)?;
        if dev.class()? == DeviceClass::Display {
            Ok(Display(dev))
        } else {
            Err(Error::Unsupported)
        }
    }

    /// `(width, height)` in pixels, after any driver rotation.
    pub fn geometry(&self) -> Result<(u16, u16), Error> {
        let v = self.0.ioctl(ioctl::DISPLAY_GET_GEOMETRY, 0)?;
        Ok((v as u16, (v >> 16) as u16))
    }

    pub fn format(&self) -> Result<PixelFormat, Error> {
        let v = self.0.ioctl(ioctl::DISPLAY_GET_FORMAT, 0)?;
        PixelFormat::from_code(v as u32).ok_or(Error::Io)
    }

    pub fn caps(&self) -> Result<DisplayCaps, Error> {
        Ok(DisplayCaps(self.0.ioctl(ioctl::DISPLAY_GET_CAPS, 0)? as u32))
    }

    /// Set the address window, then stream `pixels` (length must match the window in the
    /// display's format).
    pub fn blit(&self, r: Rect, pixels: &[u8]) -> Result<(), Error> {
        if r.w == 0 || r.h == 0 {
            return Err(Error::Invalid);
        }
        // Compute the inclusive window edges in u32 to avoid a u16 overflow panic.
        let x1 = r.x as u32 + r.w as u32 - 1;
        let y1 = r.y as u32 + r.h as u32 - 1;
        if x1 > u16::MAX as u32 || y1 > u16::MAX as u32 {
            return Err(Error::Invalid);
        }
        self.0.ioctl(ioctl::DISPLAY_SET_COL, (r.x as usize) | ((x1 as usize) << 16))?;
        self.0.ioctl(ioctl::DISPLAY_SET_ROW, (r.y as usize) | ((y1 as usize) << 16))?;
        self.0.write_all(pixels)
    }

    pub fn flush(&self, mode: RefreshMode) -> Result<(), Error> {
        self.0.ioctl(ioctl::DISPLAY_FLUSH, mode as usize).map(|_| ())
    }

    pub fn wait_vsync(&self, timeout: Timeout) -> Result<(), Error> {
        self.0
            .request(&mut Request::new(Op::Ioctl { cmd: ioctl::DISPLAY_WAIT_VSYNC, arg: 0 }).with_timeout(timeout))
            .map(|_| ())
    }

    pub fn set_backlight(&self, level: u8) -> Result<(), Error> {
        self.0.ioctl(ioctl::DISPLAY_SET_BACKLIGHT, level as usize).map(|_| ())
    }

    pub fn blank(&self, on: bool) -> Result<(), Error> {
        self.0.ioctl(ioctl::DISPLAY_BLANK, on as usize).map(|_| ())
    }
}
