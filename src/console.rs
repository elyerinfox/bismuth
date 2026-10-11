//! Kernel console: `kprint!` / `kprintln!`.
//!
//! Output goes to a sink function (default: stdout on the host, discarded on bare
//! metal) or to a registered device, in which case it flows through that device's
//! middleware chain like any other write.
//!
//! Classification: L2 devices · kernel console · safe · always

use core::fmt::{self, Write};
use crate::driver::Device;
use crate::kernel::cell::IrqCell;

static SINK: IrqCell<Option<fn(&str)>> = IrqCell::new(None);
static DEVICE: IrqCell<Option<Device>> = IrqCell::new(None);

/// Send console output to a function.
pub fn set_sink(f: fn(&str)) {
    SINK.lock(|s| *s = Some(f));
}

/// Send console output to a device (e.g. a UART).
pub fn set_device(dev: Device) {
    DEVICE.lock(|d| *d = Some(dev));
}

/// Write a string straight to the console device or sink, with no timestamping.
fn emit_raw(s: &str) {
    if let Some(d) = DEVICE.lock(|d| *d) {
        if !crate::security::console_allowed() {
            return;
        }
        if d.console_write(s.as_bytes()).is_ok() {
            return;
        }
    }
    match SINK.lock(|f| *f) {
        Some(f) => f(s),
        None => default_sink(s),
    }
}

/// Emit to the console. On real hardware every log line is prefixed with a `[sec.mmm]`
/// timestamp since boot (dmesg-style); the host simulator's stdout is left unprefixed so it
/// interleaves cleanly with test output.
fn emit(s: &str) {
    #[cfg(not(target_os = "none"))]
    emit_raw(s);
    #[cfg(target_os = "none")]
    emit_timestamped(s);
}

/// Whether the next emitted character begins a new line (and so wants a timestamp prefix).
#[cfg(target_os = "none")]
static AT_LINE_START: IrqCell<bool> = IrqCell::new(true);

/// Emit `s`, inserting a `[sec.mmm]` boot timestamp at the start of each line.
#[cfg(target_os = "none")]
fn emit_timestamped(s: &str) {
    AT_LINE_START.lock(|at| {
        let mut start = 0;
        let bytes = s.as_bytes();
        for i in 0..bytes.len() {
            if bytes[i] == b'\n' {
                if *at {
                    emit_timestamp();
                }
                emit_raw(&s[start..=i]);
                start = i + 1;
                *at = true;
            }
        }
        if start < bytes.len() {
            if *at {
                emit_timestamp();
                *at = false;
            }
            emit_raw(&s[start..]);
        }
    });
}

/// Write one `[    sec.mmm] ` boot timestamp to the console (no recursion: via `emit_raw`).
#[cfg(target_os = "none")]
fn emit_timestamp() {
    let ms = crate::kernel::time::ms_since_boot();
    let mut c = Console { buf: [0; 128], len: 0 };
    let _ = write!(c, "[{:>5}.{:03}] ", ms / 1000, ms % 1000);
    // Flush straight through `emit_raw` so the timestamp itself is not re-timestamped.
    if c.len > 0 {
        emit_raw(core::str::from_utf8(&c.buf[..c.len]).unwrap_or("?"));
    }
}

#[cfg(not(target_os = "none"))]
fn default_sink(s: &str) {
    #[allow(unused_extern_crates)] // rust_2018_idioms; required to pull std into this no_std crate for host builds
extern crate std;
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(s.as_bytes());
}

#[cfg(target_os = "none")]
fn default_sink(_s: &str) {}

struct Console {
    buf: [u8; 128],
    len: usize,
}

impl Console {
    fn flush(&mut self) {
        if self.len > 0 {
            // Only whole UTF-8 sequences are ever appended (see write_str).
            emit(core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?"));
            self.len = 0;
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut rest = s;
        while !rest.is_empty() {
            let room = self.buf.len() - self.len;
            if room == 0 {
                self.flush();
                continue;
            }
            let mut take = rest.len().min(room);
            while !rest.is_char_boundary(take) {
                take -= 1;
            }
            if take == 0 {
                self.flush();
                continue;
            }
            self.buf[self.len..self.len + take].copy_from_slice(&rest.as_bytes()[..take]);
            self.len += take;
            rest = &rest[take..];
        }
        Ok(())
    }
}

/// Write raw bytes to the console (invalid UTF-8 is replaced by U+FFFD).
pub fn write_bytes(bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(s) => {
                emit(s);
                return;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                if let Ok(g) = core::str::from_utf8(good) {
                    if !g.is_empty() {
                        emit(g);
                    }
                }
                emit("\u{FFFD}");
                let skip = e.error_len().unwrap_or(bad.len()).min(bad.len());
                rest = &bad[skip..];
            }
        }
    }
}

/// The console device, if one is set.
pub fn device() -> Option<Device> {
    DEVICE.lock(|d| *d)
}

/// Print Bismuth's boot logo in 24-bit ANSI colour — a bismuth-crystal iridescence gradient
/// (gold → pink → violet → blue → teal), echoing the element's rainbow oxide. On a terminal
/// without truecolour support the escape sequences are inert and the plain ASCII still shows.
pub fn boot_logo() {
    const RESET: &str = "\x1b[0m";
    // (24-bit colour escape, art line). The art is pure ASCII; colours run down the lines.
    const LINES: [(&str, &str); 5] = [
        ("\x1b[38;2;255;208;64m", r" ____  _                     _   _ "),
        ("\x1b[38;2;255;96;176m", r"| __ )(_)___ _ __ ___  _   _| |_| |__ "),
        ("\x1b[38;2;166;110;255m", r"|  _ \| / __| '_ ` _ \| | | | __| '_ \ "),
        ("\x1b[38;2;80;168;255m", r"| |_) | \__ \ | | | | | |_| | |_| | | |"),
        ("\x1b[38;2;64;224;176m", r"|____/|_|___/_| |_| |_|\__,_|\__|_| |_|"),
    ];
    write_bytes(b"\n");
    for (color, art) in LINES {
        write_bytes(color.as_bytes());
        write_bytes(art.as_bytes());
        write_bytes(RESET.as_bytes());
        write_bytes(b"\n");
    }
    write_bytes(b"\n");
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let mut c = Console { buf: [0; 128], len: 0 };
    let _ = c.write_fmt(args);
    c.flush();
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { $crate::console::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::console::_print(format_args!("\n")) };
    ($($arg:tt)*) => { $crate::console::_print(format_args!("{}\n", format_args!($($arg)*))) };
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    SINK.lock(|s| *s = None);
    DEVICE.lock(|d| *d = None);
}
