# TTY, PTY and termios

Source: `src/driver/char/tty.rs` (line discipline), `src/driver/char/pty.rs`
(pseudo-terminals) and `src/compat/posix/termios.rs` (POSIX `<termios.h>`). Tests:
`tests/tty.rs`. Research input: [research/serial-and-tty.md](../research/serial-and-tty.md).

```text
 application ── read/write ── POSIX fd / Serial / Device      tcgetattr/tcsetattr
                                     │                               │ typed, no pointers
                       ┌─────────────▼──────────────┐          tty::control(dev)
                       │ Tty  (user middleware)      │◄─────────── TtyControl
                       │  canonical/raw, echo, OPOST,│
                       │  ISIG → notify + EventFlags │
                       └─────────────┬──────────────┘
                       driver middleware (e.g. NonBlocking, LineDiscipline)
                                     ▼
            any char device: PL011 UART · Pipe · PtySlave · keyboard stream
```

## The line discipline is middleware

`driver::char::Tty` (module `driver::char::tty`) is an ordinary [`Middleware`](drivers-and-middleware.md). Declare a
`static Tty` and attach it to **any** character device with `Device::attach`. It only
ever passes `Op::Read` and `Op::Write` down the chain, so it does not care what the
device is. It generalises the PL011 `LineDiscipline`.

When attached, it registers itself in a device-index → `TtyControl` table so that
`tty::control(dev)` can find it.

### Termios

```rust
pub struct Termios { pub c_iflag: u32, pub c_oflag: u32, pub c_lflag: u32,
                     pub c_cc: [u8; NCCS /* 8 */], pub c_ispeed: u32, pub c_ospeed: u32 }
Termios::cooked()   // default: ICRNL; OPOST|ONLCR; ISIG|ICANON|ECHO|ECHOE|ECHOK; 115200
Termios::raw()      // cfmakeraw: all flags off, VMIN = 1, VTIME = 0
```

| field | flags implemented |
|-------|-------------------|
| `c_iflag` | `ISTRIP` (strip bit 7), `INLCR` (NL→CR), `IGNCR` (drop CR), `ICRNL` (CR→NL). `IXON` is defined but **not implemented** (no XON/XOFF). |
| `c_oflag` | `OPOST` (enable processing), `ONLCR` (NL→CRNL), `OCRNL` (CR→NL) |
| `c_lflag` | `ISIG`, `ICANON`, `ECHO`, `ECHOE`, `ECHOK`, `ECHONL`, `NOFLSH` |

| `c_cc` index | default | meaning |
|--------------|---------|---------|
| `VINTR` 0 | `^C` (0x03) | interrupt signal |
| `VQUIT` 1 | `^\` (0x1C) | quit signal |
| `VERASE` 2 | DEL (0x7F) | erase one character |
| `VKILL` 3 | `^U` (0x15) | erase the line |
| `VEOF` 4 | `^D` (0x04) | end of file / flush the line |
| `VMIN` 5 | 1 | stored only (see raw mode) |
| `VTIME` 6 | 0 | stored only (see raw mode) |
| `VSUSP` 7 | `^Z` (0x1A) | suspend signal |

The speed fields are stored only. Nothing projects them onto hardware yet; see
[Planned](#planned).

### Canonical mode (`ICANON`)

Raw bytes read from the device go into a persistent 64-byte `pending` buffer. The cooker
then processes **one byte at a time** into a 128-byte line buffer, and a `read` returns
**exactly one line**. Bytes that follow the end of a line stay in `pending` for the next
read, so nothing is lost. Each byte goes through these rules:

1. Input translation (`ISTRIP`, `IGNCR`, `ICRNL`, `INLCR`).
2. With `ISIG`, `VINTR`/`VQUIT`/`VSUSP` raise a terminal signal (below).
3. `VERASE` deletes the last character. With `ECHO|ECHOE`, it echoes `\b \b`.
4. `VKILL` clears the line. With `ECHOK`, it echoes `\r\n`.
5. `VEOF` on an empty line returns `Ok(0)` (EOF). On a non-empty line, it delivers the
   line immediately, without a newline. For example, input `"ab\ncd\nxy\x04zz\n"` reads
   as `"ab\n"`, `"cd\n"`, `"xy"`, `"zz\n"`.
6. `\n` completes the line. Other bytes are appended (bytes past 128 are dropped) and
   echoed with `ECHO`. A newline echoes as `\r\n` with `ECHO` or `ECHONL`.

Echo is written back down the same device's chain.

### Raw mode (`!ICANON`)

Reads pass straight through to the device. **`VMIN`/`VTIME` are not interpreted.** A
raw read returns whatever the device returns within the request's timeout, so set the
timeout on the read (`Serial::read(buf, timeout)`, `SO_RCVTIMEO`-style) or open the fd
with `O_NONBLOCK`.

### Output

With `OPOST`, writes are split at `\n` and `\r` and translated (`ONLCR`, `OCRNL`),
using `req.derive` so the caller identity is kept. Without `OPOST`, writes pass
through unchanged.

### Terminal signals without UNIX signals

Bismuth has no asynchronous signals and no job control. Under `ISIG`, `VINTR`, `VQUIT`
and `VSUSP` do four things:

1. Unless `NOFLSH` is set, they discard the pending line.
2. They send `task::notify(target, bits[sig])` to the bound controlling task, if one
   was set with `TtyControl::set_signal_target(task, [int, quit, susp])`.
3. They set bit `1 << sig` in the TTY's `EventFlags` (`TtyControl::signals()`):
   `Int` = 0, `Quit` = 1, `Susp` = 2.
4. They make the in-progress `read` return `Error::Interrupted` (`EINTR` through POSIX).

The application decides what to do; nothing is killed or stopped by the kernel.

## Configuration without raw pointers

POSIX passes a `struct termios *` through `ioctl`. Dereferencing such an `arg` would
need `unsafe`, which the safe-Rust rule forbids. Configuration therefore uses a
**typed** interface instead:

```rust
pub trait TtyControl: Sync {
    fn get_termios(&self) -> Termios;
    fn set_termios(&self, t: &Termios, when: Apply);   // Apply::Now | Drain | Flush
    fn set_signal_target(&self, task: TaskId, bits: [u32; 3]);
    fn signals(&self) -> &EventFlags;
}
tty::control(dev: Device) -> Option<&'static dyn TtyControl>
```

The `Tty` itself implements `TtyControl`, so code that holds the `&'static Tty` can call
it directly. Only scalar ioctls exist (the 0x06xx block):

| ioctl | value | right | handled |
|-------|-------|-------|---------|
| `TTY_FLUSH` | `0x0605` | CONTROL | Discards the TTY's line buffer and pending raw input, and forwards the command to the device. The queue argument is ignored. Bundled drivers do not implement `TTY_FLUSH`, so the device's own buffer is **not** flushed. |
| `TTY_DRAIN` | `0x0606` | CONTROL | Forwards to the device and returns 0 (effectively a no-op today). |
| `TTY_SET_SIGTARGET` | `0x0609` | CONFIG | **Defined only.** No component handles it; use `TtyControl::set_signal_target`. |

## PTY (`driver::char::pty`)

`Pty<N>` is two `Pipe<N>`s cross-wired: master→slave and slave→master. It adds no
buffering logic of its own; requests are delegated to `Pipe::handle`.

```rust
static PTY: Pty<256> = Pty::new();
static MASTER: PtyMaster<256> = Pty::master(&PTY);   // writes → slave input, reads ← slave output
static SLAVE: PtySlave<256> = Pty::slave(&PTY);      // attach the Tty here
```

Both ends are `DeviceClass::Char` drivers (compatible `bismuth,pty`) with the
`NonBlocking` middleware. They support read, write, `SERIAL_RX_AVAILABLE` and
`SERIAL_FLUSH` (on the receive lane), and `GET_CLASS`. A PTY is how a shell or CLI, or a
test, drives a terminal without hardware. There is no probe factory: register the
static ends directly.

## POSIX `<termios.h>` (`compat::posix::termios`)

| function | notes |
|----------|-------|
| `tcgetattr(fd, &mut termios)` / `tcsetattr(fd, TCSANOW \| TCSADRAIN \| TCSAFLUSH, &termios)` | resolves fd → device (`unistd::fd_device`) → `tty::control`. `ENOTTY` if there is no `Tty`. **`TCSADRAIN`/`TCSAFLUSH` behave like `TCSANOW`**: the `Apply` value is ignored and no input is discarded. |
| `cfgetispeed`, `cfgetospeed`, `cfsetispeed`, `cfsetospeed`, `cfsetspeed` | field accessors only |
| `cfmakeraw(&mut termios)` | `Termios::raw()` |
| `tcflush(fd, TCIFLUSH \| TCOFLUSH \| TCIOFLUSH)` | issues `TTY_FLUSH` (see the table above) |
| `tcdrain(fd)` | issues `TTY_DRAIN` |

The type is `Termios`, re-exported together with the flag and `V*` constants, and also
reachable as `compat::posix::termios::Termios`. There is no lowercase `termios` type
alias, because it clashed with the module name.

**Access control (deliberate trade-off).** `tty::control(dev)` returns `None` unless the
caller is **trusted** (the kernel domain or a trusted domain). So
`tcgetattr`/`tcsetattr`/`tcflush`'s lookup only work from trusted code; isolated domains
get `ENOTTY`. This stops an isolated domain from reconfiguring any TTY or redirecting
another task's Ctrl-C notifications. Code that holds the `&'static Tty` itself can still
call `TtyControl` directly; holding the reference *is* the authority.

## Limitations and known gaps

- The registry is keyed by device index without the generation, so a re-registered
  device in the same slot inherits the old `Tty`. One `Tty` attached to two devices
  serves both, with a shared line buffer.
- No `IXON` flow control, no `VMIN`/`VTIME`, no `ECHOCTL` (control characters echo
  raw), and no `TCSADRAIN`/`TCSAFLUSH` semantics.

## Planned

- An interrupt-driven UART driver with RX/TX rings.
- Projecting termios speeds and character size onto UART hardware (`SerialConfig`).
- Real `TTY_DRAIN`.
- `VMIN`/`VTIME` timing in raw mode.
- XON/XOFF.
- A probe factory for PTYs.
- Per-handle (rights-based) `TtyControl` access, so isolated domains can configure TTYs they were granted.

All of these come from [research/serial-and-tty.md](../research/serial-and-tty.md).
