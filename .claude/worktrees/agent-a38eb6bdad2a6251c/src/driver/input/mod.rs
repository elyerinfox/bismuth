//! Input device class: keyboards, mice, touch, buttons, encoders.
//!
//! An input device is a `Read`-source of [`InputEvent`]s plus ioctls, in
//! [`DeviceClass::Input`](crate::driver::DeviceClass) — an evdev-style model. A `Read`
//! fills the caller's buffer with whole 16-byte events, exactly as
//! [`Sensor`](crate::driver::sensor::Sensor) fills `i32` samples, so blocking reads,
//! `poll`, and timeouts all work through the existing driver machinery. A packet of
//! related events (e.g. a touch's Abs X / Abs Y / pressure) ends with a `Syn` event so
//! it is read atomically.
//!
//! Classification: L2 devices · input class · safe · always

use crate::Error;
use crate::driver::ioctl;
use crate::driver::{Device, DeviceClass};
use crate::kernel::time::Timeout;

pub mod sim;
pub use sim::SimInput;

/// Event category (mirrors evdev `EV_*`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// Packet boundary.
    Syn = 0,
    /// Key/button: value 1 = down, 0 = up, 2 = repeat.
    Key = 1,
    /// Relative axis (mouse/wheel): value = delta.
    Rel = 2,
    /// Absolute axis (touch/joystick): value = position.
    Abs = 3,
}

impl EventKind {
    pub const fn from_u8(v: u8) -> Option<EventKind> {
        Some(match v {
            0 => EventKind::Syn,
            1 => EventKind::Key,
            2 => EventKind::Rel,
            3 => EventKind::Abs,
            _ => return None,
        })
    }

    pub const fn bit(self) -> u32 {
        1 << self as u32
    }
}

/// The wire size of one event.
pub const EVENT_BYTES: usize = 16;

/// A single input event (16 bytes, little-endian on the wire).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InputEvent {
    pub tick: u64,
    pub value: i32,
    pub code: u16,
    pub kind: u8,
    pub _pad: u8,
}

impl InputEvent {
    pub fn new(kind: EventKind, code: u16, value: i32) -> Self {
        InputEvent { tick: crate::kernel::time::ticks(), value, code, kind: kind as u8, _pad: 0 }
    }

    /// A SYN packet terminator.
    pub fn syn() -> Self {
        Self::new(EventKind::Syn, 0, 0)
    }

    pub fn kind(&self) -> Option<EventKind> {
        EventKind::from_u8(self.kind)
    }

    pub fn to_bytes(&self) -> [u8; EVENT_BYTES] {
        let mut b = [0u8; EVENT_BYTES];
        b[0..8].copy_from_slice(&self.tick.to_le_bytes());
        b[8..12].copy_from_slice(&self.value.to_le_bytes());
        b[12..14].copy_from_slice(&self.code.to_le_bytes());
        b[14] = self.kind;
        b[15] = self._pad;
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<InputEvent> {
        if b.len() < EVENT_BYTES {
            return None;
        }
        Some(InputEvent {
            tick: u64::from_le_bytes(b[0..8].try_into().ok()?),
            value: i32::from_le_bytes(b[8..12].try_into().ok()?),
            code: u16::from_le_bytes(b[12..14].try_into().ok()?),
            kind: b[14],
            _pad: b[15],
        })
    }
}

/// A subset of HID-usage / evdev key and axis codes (the native keycode space).
pub mod code {
    // keys (HID usage IDs)
    pub const KEY_A: u16 = 0x04;
    pub const KEY_Z: u16 = 0x1D;
    pub const KEY_1: u16 = 0x1E;
    pub const KEY_ENTER: u16 = 0x28;
    pub const KEY_ESC: u16 = 0x29;
    pub const KEY_BACKSPACE: u16 = 0x2A;
    pub const KEY_SPACE: u16 = 0x2C;
    pub const KEY_RIGHT: u16 = 0x4F;
    pub const KEY_LEFT: u16 = 0x50;
    pub const KEY_DOWN: u16 = 0x51;
    pub const KEY_UP: u16 = 0x52;
    // buttons
    pub const BTN_LEFT: u16 = 0x110;
    pub const BTN_RIGHT: u16 = 0x111;
    pub const BTN_MIDDLE: u16 = 0x112;
    // relative axes
    pub const REL_X: u16 = 0x00;
    pub const REL_Y: u16 = 0x01;
    pub const REL_WHEEL: u16 = 0x08;
    // absolute axes
    pub const ABS_X: u16 = 0x00;
    pub const ABS_Y: u16 = 0x01;
    pub const ABS_PRESSURE: u16 = 0x18;
}

/// Typed view of an input device.
#[derive(Copy, Clone, Debug)]
pub struct Input(pub Device);

impl Input {
    pub fn open(name: &str) -> Result<Self, Error> {
        let dev = Device::find(name)?;
        if dev.class()? == DeviceClass::Input {
            Ok(Input(dev))
        } else {
            Err(Error::Unsupported)
        }
    }

    /// Read up to `out.len()` events, waiting up to `timeout` for at least one.
    pub fn read(&self, out: &mut [InputEvent], timeout: Timeout) -> Result<usize, Error> {
        let mut raw = [0u8; EVENT_BYTES * 16];
        let want = out.len().min(16) * EVENT_BYTES;
        let n = self.0.read_timeout(&mut raw[..want], timeout)?;
        let count = n / EVENT_BYTES;
        for (i, slot) in out[..count].iter_mut().enumerate() {
            *slot = InputEvent::from_bytes(&raw[i * EVENT_BYTES..]).ok_or(Error::Io)?;
        }
        Ok(count)
    }

    /// Number of events currently queued (for polling).
    pub fn available(&self) -> Result<usize, Error> {
        self.0.ioctl(ioctl::INPUT_EVENTS_AVAILABLE, 0)
    }

    /// Supported event kinds, as an [`EventKind::bit`] mask.
    pub fn caps(&self) -> Result<u32, Error> {
        Ok(self.0.ioctl(ioctl::INPUT_GET_CAPS, 0)? as u32)
    }

    pub fn flush(&self) -> Result<(), Error> {
        self.0.ioctl(ioctl::INPUT_FLUSH, 0).map(|_| ())
    }

    /// Configure autorepeat: `delay_ms` before the first repeat, then every `rate_ms`.
    pub fn set_repeat(&self, delay_ms: u16, rate_ms: u16) -> Result<(), Error> {
        self.0.ioctl(ioctl::INPUT_SET_REPEAT, (delay_ms as usize) | ((rate_ms as usize) << 16)).map(|_| ())
    }
}
