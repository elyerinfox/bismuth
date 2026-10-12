# Terminals: TTY, PTY and termios

This guide adds an interactive terminal to a device and tests it without hardware. The
code follows `tests/tty.rs`. For how the line discipline works, and its current
limitations, read [design/tty.md](../design/tty.md).

## 1. A terminal on a UART

Attach a `Tty` to the console UART (any `Char` device works):

```rust
use bismuth::driver::{self, Device};
use bismuth::driver::char::Tty;

static TTY0: Tty = Tty::new();

driver::probe_all(&BOARD, FACTORIES);          // registers "uart0" (PL011)
let uart = Device::find("uart0")?;
uart.attach(&TTY0)?;                            // cooked mode by default
```

The PL011 driver already has its own `LineDiscipline`, which does the same
`\n`→`\r\n` translation. With both in the chain, output newlines are translated twice
(`\r\r\n`). Either turn off `ONLCR` in the `Tty`, or put the `Tty` on a device without
its own translation.

A task can now read edited lines:

```rust
let mut line = [0u8; 128];
match uart.read(&mut line) {
    Ok(0) => { /* ^D on an empty line: EOF */ }
    Ok(n) => handle(&line[..n]),                // includes the trailing '\n'
    Err(bismuth::Error::Interrupted) => { /* ^C, ^\ or ^Z was typed */ }
    Err(e) => return Err(e),
}
```

## 2. A terminal without hardware: PTY

```rust
use bismuth::driver::char::{Pty, PtyMaster, PtySlave};

static PTY: Pty<256> = Pty::new();
static MASTER: PtyMaster<256> = Pty::master(&PTY);
static SLAVE: PtySlave<256> = Pty::slave(&PTY);
static TTY: Tty = Tty::new();

let m = driver::register("ptm", &MASTER)?;     // the "keyboard and screen" side
let s = driver::register("pts", &SLAVE)?;      // the application side
s.attach(&TTY)?;
```

Bytes written to `ptm` arrive as typed input on `pts`. The application's output and
echo come back out of `ptm`. Use this for a CLI reachable over the network or a pipe,
and for tests.

## 3. Raw mode, speeds and flags from POSIX code

```rust
use bismuth::compat::posix::*;

let fd = open("/dev/pts", O_RDWR);
let mut t = Termios::default();       // cooked defaults
tcgetattr(fd, &mut t);
cfmakeraw(&mut t);                     // no echo, no line editing, no signals
cfsetspeed(&mut t, 921_600);           // recorded in termios; not applied to hardware yet
tcsetattr(fd, TCSANOW, &t);
```

The type is `Termios`; there is no lowercase `termios` alias. The `tc*` functions only
work from **trusted** code (kernel domain). Isolated domains get `ENOTTY` by design: see
the [design page](../design/tty.md#posix-termiosh-compatposixtermios).

In raw mode, `VMIN`/`VTIME` are not interpreted. Use a read timeout or `O_NONBLOCK`
instead. To turn only echo off (for a password prompt), clear `ECHO` in `t.c_lflag` and
call `tcsetattr` again.

From Rust you can skip the fd and use the typed interface:

```rust
use bismuth::driver::char::tty::{self, Apply, Termios, TtyControl, ECHO};

let mut t = TTY.get_termios();         // or tty::control(dev).unwrap().get_termios()
t.c_lflag &= !ECHO;
TTY.set_termios(&t, Apply::Now);
```

## 4. Handling Ctrl-C

Bind the task that should hear about terminal signals, with one notification bit per
signal:

```rust
use bismuth::task;

const SIG_INT: u32 = 1 << 0;
const SIG_QUIT: u32 = 1 << 1;
const SIG_SUSP: u32 = 1 << 2;

TTY.set_signal_target(task::current(), [SIG_INT, SIG_QUIT, SIG_SUSP]);

// in the controlling task's loop:
if let Ok(bits) = task::notify_wait(bismuth::Timeout::NoWait) {
    if bits & SIG_INT != 0 { /* cancel the current command */ }
}
```

The read that was in progress when `^C` arrived returns `Error::Interrupted`.
`TTY.signals()` is an `EventFlags` that other tasks can wait on (bit 0 = INT,
1 = QUIT, 2 = SUSP).

## 5. Test it in the simulator

```rust
#[test]
fn line_editing() {
    sim::run_to_completion(|| {
        let m = driver::register("ptm", &MASTER).unwrap();
        let s = driver::register("pts", &SLAVE).unwrap();
        s.attach(&TTY).unwrap();
        task::Builder::new("shell").priority(4).spawn(|i| {
            let s = Device::from_index(i).unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ac\n");          // "ab", DEL, "c", CR
        }, s.index()).unwrap();
        task::Builder::new("term").priority(3).spawn(|i| {
            let m = Device::from_index(i).unwrap();
            task::sleep_ticks(1);
            m.write(b"ab\x7fc\r").unwrap();
        }, m.index()).unwrap();
    });
}
```

`Device::from_index(i)` turns the `usize` task argument back into a live `Device`
handle; it checks the generation.

## Caveats

These come from the current source; see the [design page](../design/tty.md#limitations-and-known-gaps).

- Each canonical `read` returns exactly one line, or the partial line ended by `^D`.
  Input typed ahead is kept for the next read.
- `tcsetattr(TCSAFLUSH)` does not discard input. `tcflush` only clears the TTY's line
  buffer.
- `tty::control` and the POSIX `tc*` calls work from trusted code only. Give
  isolated tasks a pre-configured TTY instead of letting them change it.
