//! A minimal interactive serial shell — a line-edited console with a small set of built-in
//! commands, usable over any registered character device.
//!
//! It is the control-plane counterpart to the container runtime: `con ls` / `con start` /
//! `con stop` / `con status` drive workloads exactly as `docker`/`kubectl` would, but over a
//! serial line and backed by security domains. The shell reads raw bytes through the safe
//! [`Serial`](crate::driver::char::Serial) wrapper, does its own canonical line editing
//! (echo + backspace), and writes replies straight to the device (bypassing the timestamped
//! console so output stays clean).
//!
//! 100% safe Rust, no heap: the line buffer is a fixed array and commands are matched by
//! `split_whitespace` over it.
//!
//! Classification: L4 personalities · shell: interactive console · safe · shell

use core::fmt::{self, Write};

use crate::driver::char::Serial;
use crate::kernel::time::ms_since_boot;
use crate::{Error, Timeout};

/// Largest command line the shell accepts; longer input is truncated.
const LINE_MAX: usize = 128;

/// A `core::fmt::Write` sink that writes to a serial device, translating `\n` into `\r\n` so a
/// terminal shows proper line breaks.
struct Out(Serial);

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for chunk in s.split_inclusive('\n') {
            if let Some(body) = chunk.strip_suffix('\n') {
                let _ = self.0.write(body.as_bytes());
                let _ = self.0.write(b"\r\n");
            } else {
                let _ = self.0.write(chunk.as_bytes());
            }
        }
        Ok(())
    }
}

/// Open the named character device and run the shell on it forever. Returns an error only if
/// the device cannot be opened; once running it never returns.
pub fn run(device: &str) -> Result<core::convert::Infallible, Error> {
    let serial = Serial::open(device)?;
    Ok(run_on(serial))
}

/// Run the shell on an already-opened serial device. Never returns.
pub fn run_on(serial: Serial) -> core::convert::Infallible {
    let mut out = Out(serial);
    let _ = writeln!(out, "\nBismuth shell. Type 'help' for commands.");
    let mut buf = [0u8; LINE_MAX];
    loop {
        let _ = out.0.write(b"bismuth> ");
        let n = read_line(&serial, &mut buf);
        // SAFETY of str::from_utf8: the editor only stored printable ASCII (0x20..=0x7e).
        let line = core::str::from_utf8(&buf[..n]).unwrap_or("");
        exec(&mut out, line);
    }
}

/// Read one line with echo and backspace handling; returns its length in `buf`.
fn read_line(serial: &Serial, buf: &mut [u8]) -> usize {
    let mut len = 0;
    loop {
        let mut b = [0u8; 1];
        if serial.read(&mut b, Timeout::Forever) != Ok(1) {
            continue;
        }
        match b[0] {
            b'\r' | b'\n' => {
                let _ = serial.write(b"\r\n");
                return len;
            }
            0x08 | 0x7f => {
                if len > 0 {
                    len -= 1;
                    let _ = serial.write(b"\x08 \x08"); // erase the echoed char
                }
            }
            c @ 0x20..=0x7e => {
                if len < buf.len() {
                    buf[len] = c;
                    len += 1;
                    let _ = serial.write(&[c]); // echo
                }
            }
            _ => {}
        }
    }
}

/// Parse and run one command line, writing all output to `out`. Pure (no device I/O), so it
/// is exercised directly by the host tests.
pub fn exec<W: Write>(out: &mut W, line: &str) {
    let mut words = line.split_whitespace();
    let Some(cmd) = words.next() else { return };
    let rest = line[cmd.len()..].trim_start();
    match cmd {
        "help" => help(out),
        "echo" => {
            let _ = writeln!(out, "{rest}");
        }
        "uptime" => {
            let ms = ms_since_boot();
            let _ = writeln!(out, "up {}.{:03} s", ms / 1000, ms % 1000);
        }
        "ver" => {
            let _ = writeln!(out, "Bismuth {} ({})", env!("CARGO_PKG_VERSION"), arch_name());
        }
        "clear" => {
            let _ = write!(out, "\x1b[2J\x1b[H");
        }
        #[cfg(feature = "containers")]
        "con" => con(out, &mut words),
        other => {
            let _ = writeln!(out, "unknown command: {other} (try 'help')");
        }
    }
}

fn help<W: Write>(out: &mut W) {
    let _ = writeln!(out, "commands:");
    let _ = writeln!(out, "  help              this list");
    let _ = writeln!(out, "  echo <text>       print <text>");
    let _ = writeln!(out, "  uptime            time since boot");
    let _ = writeln!(out, "  ver               version and architecture");
    let _ = writeln!(out, "  clear             clear the screen");
    #[cfg(feature = "containers")]
    {
        let _ = writeln!(out, "  con ls            list containers");
        let _ = writeln!(out, "  con status <name> show one container's health");
        let _ = writeln!(out, "  con start  <name> start a container");
        let _ = writeln!(out, "  con stop   <name> stop a container");
        let _ = writeln!(out, "  con restart <name> restart a container");
    }
}

#[cfg(feature = "containers")]
fn con<W: Write>(out: &mut W, words: &mut core::str::SplitWhitespace<'_>) {
    use crate::security::container;
    match words.next() {
        Some("ls") => {
            let mut any = false;
            container::for_each(|id, decl| {
                any = true;
                let running = container::health(id).map(|h| h.running).unwrap_or(false);
                let _ = writeln!(out, "  {:<16} v{}  {}  restarts={}", decl.name(), decl.version, if running { "running" } else { "stopped" }, container::restart_count(id));
            });
            if !any {
                let _ = writeln!(out, "  (no containers installed)");
            }
        }
        Some("status") => match words.next() {
            Some(name) => match container::find(name) {
                Some(id) => match container::health(id) {
                    Ok(h) => {
                        let _ = writeln!(out, "{name}: {}", if h.running { "running" } else { "stopped" });
                        let _ = writeln!(out, "  gen={} faults={} violations={} cpu_ticks={}", h.generation, h.faults, h.violations, h.cpu_ticks);
                    }
                    Err(e) => report(out, name, Err(e)),
                },
                None => no_such(out, name),
            },
            None => usage(out, "con status <name>"),
        },
        Some("start") => act(out, words, container::start),
        Some("stop") => act(out, words, container::stop),
        Some("restart") => act(out, words, container::restart),
        Some(other) => {
            let _ = writeln!(out, "con: unknown subcommand '{other}' (ls|status|start|stop|restart)");
        }
        None => usage(out, "con ls|status|start|stop|restart <name>"),
    }
}

#[cfg(feature = "containers")]
fn act<W: Write>(out: &mut W, words: &mut core::str::SplitWhitespace<'_>, f: fn(crate::security::container::ContainerId) -> Result<(), Error>) {
    use crate::security::container;
    match words.next() {
        Some(name) => match container::find(name) {
            Some(id) => report(out, name, f(id)),
            None => no_such(out, name),
        },
        None => usage(out, "<name> required"),
    }
}

#[cfg(feature = "containers")]
fn report<W: Write>(out: &mut W, name: &str, r: Result<(), Error>) {
    match r {
        Ok(()) => {
            let _ = writeln!(out, "{name}: ok");
        }
        Err(e) => {
            let _ = writeln!(out, "{name}: error {e:?}");
        }
    }
}

#[cfg(feature = "containers")]
fn no_such<W: Write>(out: &mut W, name: &str) {
    let _ = writeln!(out, "no such container: {name}");
}

#[cfg(feature = "containers")]
fn usage<W: Write>(out: &mut W, u: &str) {
    let _ = writeln!(out, "usage: {u}");
}

const fn arch_name() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86-64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(all(target_arch = "arm", feature = "cortex-a")) {
        "aarch32 cortex-a"
    } else if cfg!(target_arch = "arm") {
        "cortex-m"
    } else {
        "host"
    }
}
