# Bismuth Serial & TTY Subsystem: Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: how UNIX/Linux structure the serial (UART), TTY line-discipline, and PTY layers;
> what belongs on an MCU (Cortex-M / RISC-V, tens–hundreds of KB RAM, MPU-not-MMU, static
> allocation, `#![deny(unsafe_code)]` with unsafe confined to a tiny TCB); and a concrete
> design that fits Bismuth's existing `Driver` / `Op` / `Middleware` / ioctl model and its
> ISR-safe wakeup primitives. Nothing here requires a heap, UNIX signals, or `fork`/`exec`.

---

## 0. TL;DR

- **Three layers, one request pipeline.** (1) An *interrupt-driven UART driver* (`Driver`,
  `DeviceClass::Char`) replaces the polled PL011 with RX/TX ring buffers filled/drained by
  an ISR that hands off to the reader/writer task through a **binary `Semaphore`** —
  exactly the mechanism `src/sync/semaphore.rs` documents ("the classic way for an ISR to
  wake a driver task"). (2) A `Tty` *middleware* layer (`Middleware`) generalizes the
  existing `pl011::LineDiscipline` into a full canonical/raw line discipline over *any*
  char device. (3) A `Pty` *loopback* pair built from two `Pipe`-style rings (the
  `net::drivers::Wire` pattern) so a shell/CLI or test harness can drive a TTY with no
  hardware.
- **termios is data behind two ioctls, not a syscall zoo.** A `Termios { c_iflag, c_oflag,
  c_cflag, c_lflag, c_cc, c_ispeed, c_ospeed }` struct is read/written with
  `TTY_GET_TERMIOS` / `TTY_SET_TERMIOS` (TCGETS/TCSETS analogues), `arg` carrying the
  struct address. The `Tty` owns the `i/o/l`-flag behaviour; it translates the `c_cflag` +
  speed bits *downward* into a hardware `SerialConfig` via `SERIAL_SET_CONFIG`. Over a PTY
  the hardware bits are simply ignored.
- **Signals become notifications + EINTR, because Bismuth has no UNIX signals.** On
  recognizing `VINTR`/`VQUIT`/`VSUSP` in `ISIG` mode the `Tty` (a) sets an `EventFlags`
  group / `task::notify`s the bound *controlling task*, and (b) aborts the task currently
  blocked in `read()` so it returns `Error::Interrupted` (EINTR). Delivery is cooperative,
  which is the honest model for a kernel with no asynchronous signal frames.
- **Controlling terminal = one bound task (or domain), not a session.** No process groups,
  no job control. A `Tty` holds an `Option<TaskId>` set via `TTY_SET_SIGTARGET`
  (TIOCSCTTY-ish); signal chars post there. That is the whole concept.
- **Offload the high-rate path.** Hardware RTS/CTS flow control and (where the silicon has
  it) **DMA RX with idle-line detection** live in the driver behind the same ring +
  semaphore interface, so per-byte interrupts disappear at high baud. XON/XOFF (software
  flow control) lives in the `Tty` because it must both suppress bytes on input and inject
  them on output. **RS-485 DE** direction control uses the TX-complete interrupt.
- **Error reporting is first-class.** Framing / parity / overrun / break are latched
  per-byte in the ISR, counted, and read back with `SERIAL_GET_ERRORS`; `BRKINT`/`IGNBRK`/
  `PARMRK` decide what the line discipline does with them.
- **Host-simulator-testable from day one.** A `MockUart` (`FrameDevice`-style, driven by a
  std thread via `sim::interrupt`) and the `Pty` pair let `cargo test` exercise canonical
  editing, echo, flow control, EINTR-on-Ctrl-C, and termios round-trips with zero hardware,
  the same way `tests/net.rs` drives two IP stacks over a simulated `Wire`.
- **Do NOT build:** job control (sessions/process groups/`SIGHUP` on carrier loss beyond a
  simple hook), multiple sessions per TTY, pluggable N_* line disciplines as a runtime
  stack, `TIOCSTI` input injection (security), terminfo/termcap, locale/multibyte cooking,
  or packet-mode PTYs. Keep one canonical discipline with a termios config.

---

## 1. How UNIX/Linux structure terminals

### 1.1 The three-layer stack (and why it exists)

A UNIX terminal is historically three stacked pieces ([tty demystified][ttydem],
[Linux tty internals][linuxtty]):

```
 application ── read()/write()/ioctl() on an fd
      │
   ┌──▼─────────────────────────────┐
   │ line discipline (N_TTY)        │  cooking: canonical line editing, echo, CR/LF
   │  src: drivers/tty/n_tty.c      │  translation, ISIG → signals, IXON/IXOFF
   ├────────────────────────────────┤
   │ tty core (tty_io.c, ldisc mux) │  fd glue, termios store, ctty/session/pgrp
   ├────────────────────────────────┤
   │ tty driver (uart/serial_core)  │  hardware: FIFO, baud, IRQ, DMA, modem lines
   └────────────────────────────────┘
```

- **The line discipline is the "cooking" layer.** `N_TTY` (`n_tty.c`) turns a raw byte
  stream into cooked lines: it buffers input until a line delimiter, handles `ERASE`
  (backspace), `WERASE`, `KILL` (kill-line), `REPRINT`, echoes typed characters back,
  translates `CR`↔`NL` on the way in (`ICRNL`/`INLCR`/`IGNCR`) and out (`ONLCR`/`OCRNL`/
  `OPOST`), recognizes the signal characters (`INTR`/`QUIT`/`SUSP`) under `ISIG`, and does
  software flow control (`IXON`/`IXOFF`). Other disciplines exist (`N_SLIP`, `N_PPP`,
  `N_HDLC`) — a tty can swap its discipline at runtime (`TIOCSETD`).
- **The tty core** owns the fd, the `struct termios`, and the session / controlling
  terminal / foreground process group machinery. This is where job control lives:
  `SIGINT`/`SIGQUIT`/`SIGTSTP` go to the **foreground process group** of the session that
  owns the tty; background reads/writes get `SIGTTIN`/`SIGTTOU`; carrier loss sends
  `SIGHUP`.
- **The tty driver** (`uart_ops` / `serial_core` for UARTs) touches hardware: it fills the
  `tty_buffer` (flip buffer) from the RX ISR, drains the output buffer to the TX FIFO, and
  implements baud/bits/parity/stop, modem control (RTS/CTS/DTR/DSR/DCD), break, and DMA.

### 1.2 termios — the General Terminal Interface

`struct termios` ([termios(3)][termios3], [POSIX GTI][posixgti]) is the one configuration
object for all three layers:

| field | controls | representative flags |
|---|---|---|
| `c_iflag` | **input** processing (line disc.) | `IGNBRK BRKINT IGNPAR PARMRK INPCK ISTRIP INLCR IGNCR ICRNL IXON IXOFF IXANY IMAXBEL` |
| `c_oflag` | **output** processing (line disc.) | `OPOST ONLCR OCRNL ONOCR ONLRET` |
| `c_cflag` | **hardware** line settings (driver) | `CSIZE(CS5..CS8) CSTOPB PARENB PARODD CREAD CLOCAL CRTSCTS HUPCL` + baud |
| `c_lflag` | **local**/editing modes (line disc.) | `ISIG ICANON ECHO ECHOE ECHOK ECHONL NOFLSH IEXTEN TOSTOP` |
| `c_cc[]` | **control characters** | `VINTR VQUIT VERASE VKILL VEOF VEOL VMIN VTIME VSTART VSTOP VSUSP VWERASE VREPRINT` |

Key behaviours that matter even on an MCU:

- **Canonical vs raw.** `ICANON` on → input is line-buffered and editable, `read()` returns
  at a line boundary. `ICANON` off (raw) → `read()` returns after `VMIN` bytes or `VTIME`
  deciseconds, whichever the mode selects (the classic `VMIN`/`VTIME` four-case table).
  `cfmakeraw()` clears `ICANON ECHO ISIG IEXTEN`, `ICRNL IXON`, `OPOST`, sets `VMIN=1
  VTIME=0`.
- **Echo.** `ECHO` echoes input; `ECHOE` renders `ERASE` as backspace-space-backspace;
  `ECHOK`/`ECHONL` govern line kill and newline echo.
- **Signals.** Under `ISIG`, `c_cc[VINTR]` (Ctrl-C) → `SIGINT`, `VQUIT` (Ctrl-\) →
  `SIGQUIT`, `VSUSP` (Ctrl-Z) → `SIGTSTP`. `NOFLSH` keeps the queues; otherwise they are
  flushed.
- **Apply timing.** `tcsetattr(fd, when, &t)`: `TCSANOW` (immediately), `TCSADRAIN` (after
  output drains — for baud changes), `TCSAFLUSH` (drain + flush input).
- **Speed is separate.** `cfsetospeed`/`cfsetispeed` write `c_ospeed`/`c_ispeed`
  (historically encoded in `c_cflag`); `tcflush`, `tcdrain`, `tcsendbreak`, `tcflow` round
  out the API.

### 1.3 PTYs

A pseudo-terminal ([pty(7)][pty7], [openpty(3)][openpty]) is a **master/slave char pair**.
Bytes written to the master appear as input on the slave and vice-versa; the slave behaves
exactly like a real terminal (it has a line discipline and termios), while the master is
the program pretending to be the hardware (a terminal emulator, `sshd`, `screen`,
`expect`). On Linux the master is `/dev/ptmx` (which mints a new slave `/dev/pts/N`), with
`grantpt`/`unlockpt`/`ptsname`. Crucially: a PTY is **just the top two layers with the
hardware layer replaced by an in-memory pipe**. There is no UART. This is why it is the
right primitive for driving a TTY in tests and for a software console.

### 1.4 What this costs, and what an MCU keeps

The full Linux stack is large because of job control, dynamic ldisc multiplexing, locale
cooking, and the flip-buffer/work-queue plumbing for SMP. An MCU keeps the *shapes* — a
cooking layer, a termios config object, modem/flow control, a PTY = pipe-backed terminal —
and drops sessions, process groups, runtime-swappable disciplines, and locale. FreeBSD's
`ttydisc` ([tty(4)][freebsdtty]) is a useful second reference: it folded the line
discipline back into the tty layer (no N_* mux by default), which is closer to what we
want.

---

## 2. What Bismuth already has to build on

| Existing piece | File | Role in this design |
|---|---|---|
| `Driver` + `Op::{Read,Write,Ioctl,Power}` + `Next` chain | `src/driver/mod.rs` | The UART is a `Driver`; every layer is a request on this pipeline. |
| `Middleware` (global → user → driver ordering) | `src/driver/middleware.rs` | The `Tty` is a `Middleware`, like `pl011::LineDiscipline` but complete. |
| `pl011::LineDiscipline` | `src/driver/drivers/pl011.rs` | The seed: already does `\n`→`\r\n` out and `\r`→`\n` in as middleware. |
| `Pipe<N>` bounded ring w/ `block_on` + `wake_all(key)` | `src/driver/drivers/pipe.rs` | The PTY lane primitive; already a `Char` device with `SERIAL_*` ioctls. |
| `net::drivers::Wire` (two cross-wired lanes + `schedule()`) | `src/net/drivers/wire.rs` | The exact template for a two-ended PTY. |
| `Semaphore` / `EventFlags` / `task::notify` — **all ISR-safe** | `src/sync/*`, `src/kernel/task.rs` | ISR → driver-task handoff; signal delivery. |
| `block_on(key, timeout, attempt, on_handoff, before_block)` | `src/kernel/mod.rs` | How a blocking read waits without a busy loop. |
| `WakeReason::Aborted → Error::Interrupted` | `src/kernel/mod.rs`, `src/error.rs` | Maps directly to EINTR for Ctrl-C-interrupted reads. |
| `ioctl` numbering + `required_right(cmd)` | `src/driver/class.rs` | We extend the serial (`0x01xx`) block and add a tty (`0x06xx`) block. |
| POSIX fd table, `ioctl()`, `isatty()`, `poll()` | `src/compat/posix/unistd.rs` | Where `tcgetattr`/`tcsetattr` plug in; `isatty` already keys on `DeviceClass::Char`. |
| `kernel/usermem.rs` | `src/kernel/usermem.rs` | Validates/copies a termios pointer for isolated (MPU) domains. |
| `sim::run` / `sim::interrupt` host harness | `src/sim.rs`, `src/arch/host.rs` | Deterministic tests; a std thread plays "UART hardware". |

The design adds **no new core trait**: a serial device is a `Driver` with a richer internal
state and an inherent `on_irq()` the board's vector calls; the `Tty` and `Pty` are a
`Middleware` and a pair of `Driver`s respectively.

---

## 3. Layer 1 — Serial/UART done properly

### 3.0 From polled to interrupt-driven

The current `Pl011` (`src/driver/drivers/pl011.rs`) spins on `FR_TXFF` for TX and
polls+`sleep_ticks(1)` for RX. That wastes a tick of latency per read and a core-second per
character at low baud. The redesign keeps the same `Driver`/`Op` surface but drives both
directions from the UART interrupt, with ring buffers between ISR and task.

```rust
// src/driver/drivers/uart.rs  (generalizes pl011.rs; still safe Rust + safe Mmio)
pub struct Uart {
    regs:     IrqCell<Option<Mmio>>,
    rx:       IrqCell<ByteRing<RX_CAP>>,   // ISR producer, reader-task consumer
    tx:       IrqCell<ByteRing<TX_CAP>>,   // writer-task producer, ISR consumer
    rx_ready: Semaphore,                   // binary: given by ISR after pushing RX bytes
    tx_space: Semaphore,                   // binary: given by ISR after draining TX
    errors:   IrqCell<SerialErrors>,       // framing/parity/overrun/break counters
    cfg:      IrqCell<SerialConfig>,       // baud/bits/parity/stop/flow (mirror of HW)
    flow:     IrqCell<FlowState>,          // RTS asserted?, remote-XOFF?, local-XOFF-sent?
}

#[derive(Copy, Clone, Default)]
pub struct SerialErrors { pub framing: u32, pub parity: u32, pub overrun: u32, pub brk: u32 }
```

**Reader** — `handle(Op::Read(buf))` (drain-then-wait avoids lost wakeups, because the ISR
gives `rx_ready` *after* pushing under the `IrqCell` critical section):

```rust
Op::Read(buf) => {
    if buf.is_empty() { return Ok(0); }
    loop {
        let n = self.rx.lock(|r| r.drain_into(buf));   // copy out what the ISR produced
        if n > 0 {
            self.update_rts_xon();                     // ring drained → re-assert flow
            return Ok(n);
        }
        self.rx_ready.take(req.timeout)?;              // blocks; NoWait → WouldBlock; else Timeout
    }
}
```

**Writer** — `handle(Op::Write(data))`: push into the TX ring, enable the TX interrupt,
block on `tx_space` when full. Short writes return the count, exactly like `Pipe`.

```rust
Op::Write(data) => {
    let mut off = 0;
    while off < data.len() {
        let pushed = self.tx.lock(|t| t.push_from(&data[off..]));
        if pushed > 0 { self.enable_txim(); off += pushed; continue; }
        if off > 0 { return Ok(off); }                 // partial write, like Pipe
        self.tx_space.take(req.timeout)?;              // ring full: wait for the ISR
    }
    Ok(off)
}
```

**The ISR** — a safe method the board's vector calls. No `block_on`, only ISR-safe
`Semaphore::give`:

```rust
impl Uart {
    pub fn on_irq(&self) {
        let Ok(m) = self.regs() else { return };
        let status = m.read32(MIS);
        if status & (RX | RX_TIMEOUT) != 0 {           // RX FIFO or idle/receive-timeout
            let mut woke = false;
            self.rx.lock(|r| while let Some((b, err)) = read_dr(&m) {
                if let Some(e) = err { self.errors.lock(|c| e.count_into(c)); }
                if r.push(b).is_err() { self.errors.lock(|c| c.overrun += 1); }
                woke = true;
            });
            if self.rx_high_water() { self.deassert_rts_or_send_xoff(&m); }
            if woke { let _ = self.rx_ready.give(); }   // ISR-safe wake of the reader
        }
        if status & TX != 0 {                           // TX FIFO wants more
            let empty = self.tx.lock(|t| refill_fifo(&m, t));
            if empty { self.disable_txim(); } else { let _ = self.tx_space.give(); }
        }
        m.write32(ICR, status);                         // clear
    }
}
```

Board wiring is the *only* unsafe part, confined to the port/vector table (cortex-m-rt):

```rust
// boards/<board>/src/main.rs
#[interrupt] fn UART0() { bismuth::driver::drivers::uart::irq::<0>(); }  // dispatch to INSTANCES[0]
```

This mirrors `net::drivers::Wire`, where `carry()` calls `net::schedule()` (→
`task::notify`) after enqueuing a frame. Here the "schedule" is a per-direction binary
semaphore, which is lighter and lets `block_on` inside `Semaphore::take` do the waiting.

### 3.1 termios-adjacent hardware config (`SerialConfig`)

The driver owns only the *hardware* line settings. termios' `c_cflag` + speeds are
projected onto this struct by the `Tty` (§4.4); a bare serial user can also set it directly.

```rust
#[derive(Copy, Clone)]
pub struct SerialConfig {
    pub baud: u32,
    pub data_bits: u8,              // 5..=8
    pub parity: Parity,             // None | Even | Odd  (maps PARENB/PARODD)
    pub stop_bits: StopBits,        // One | Two          (maps CSTOPB)
    pub flow: FlowControl,          // None | RtsCts | XonXoff
}
pub enum FlowControl { None, RtsCts, XonXoff }
```

- **`SERIAL_SET_CONFIG`** (`arg` = `&SerialConfig as *const _ as usize`) reprograms the
  divisor/LCR and the RTS/CTS hardware enable (PL011 `CR.RTSEn`/`CTSEn`), applied after the
  TX ring drains if requested (TCSADRAIN semantics).
- **`SERIAL_GET_CONFIG`** copies the current config out.
- Baud that the clock cannot hit exactly returns `Error::Invalid` (do not silently round).

### 3.2 Hardware vs software flow control

- **Hardware RTS/CTS** lives entirely in the driver. The ISR de-asserts RTS when the RX
  ring crosses a high-water mark and re-asserts it in the reader once drained
  (`update_rts_xon`). TX consults CTS (or lets the PL011 gate TX on CTS automatically when
  `CTSEn` is set). Enabled by `FlowControl::RtsCts` / termios `CRTSCTS`.
- **Software XON/XOFF** spans both directions, so it is better placed where both are
  visible. Two valid homes: (a) the driver, byte-level, for maximum throughput on a raw
  link; (b) the `Tty`, driven by `IXON` (honour remote XOFF to pause our TX) / `IXOFF`
  (send XOFF/XON to pause the remote) / `IXANY`. Recommendation: implement the mechanism in
  the driver (it must inject `0x13`/`0x11` into the TX ring ahead of data and strip them
  from RX before the ring), and let the `Tty`'s termios bits *enable* it via
  `SERIAL_SET_CONFIG`. This keeps the flow bytes off the cooked stream.

### 3.3 Break detection and error reporting

PL011 reports per-byte status in the high bits of `DR` (FE framing, PE parity, BE break, OE
overrun) and in `RSR/ECR`. The ISR latches each into `SerialErrors`. A received **break**
(`BE`) becomes, per termios: discarded (`IGNBRK`), a signal (`BRKINT` → `VINTR` path), a
`\0` (default), or a quoted `\377 \0 \0` (`PARMRK`). Parity errors follow
`INPCK`/`IGNPAR`/`PARMRK`.

- **`SERIAL_GET_ERRORS`** returns a packed snapshot and clears the counters (so a monitor
  task can poll rates). It is a *query* → `Rights::CONTROL`.
- **`SERIAL_SEND_BREAK`** (`arg` = milliseconds) transmits a break condition (TCSBRK /
  `tcsendbreak`).

### 3.4 DMA RX with idle-line detection (high baud)

Per-byte RX interrupts collapse a core at 1–3 Mbaud. On MCUs whose UART+DMA support it
(STM32 USART, NXP LPUART, many others — *not* QEMU's PL011), the preferred RX backend is a
**circular DMA buffer + IDLE-line interrupt**:

```
HW RX → DMA ring (circular, in a DMA-capable, non-cacheable region)
   IDLE-line IRQ  ─┐   (line went quiet: a burst ended)
   DMA half/full  ─┼─► on_irq: read DMA NDTR to learn how far it wrote,
   IRQ            ─┘   copy [last_pos .. cur_pos) into the RX ByteRing, give rx_ready
```

The DMA path presents the *same* `rx` ring + `rx_ready` semaphore to the reader, so §3.0's
`Op::Read` is unchanged. A driver advertises its RX style in `SerialErrors`-adjacent caps
(`SerialCaps { DMA_RX, IDLE_DETECT, RS485, AUTO_RTS }`). This is the serial analogue of the
networking doc's NAPI budget: amortize interrupts over a burst instead of per byte.

### 3.5 RS-485 direction control

Half-duplex RS-485 needs the driver-enable (DE) line asserted *before* the first TX bit and
de-asserted only *after the last bit is shifted out* — which is the TX-**complete**
interrupt, not FIFO-empty. Config:

```rust
pub struct Rs485Config {
    pub enable: bool,
    pub de_active_high: bool,
    pub delay_before: u16,   // bit-times from DE assert to first bit
    pub delay_after:  u16,   // bit-times from last bit to DE release
}
```

Set via **`SERIAL_SET_RS485`**. The writer asserts DE (UART-integrated DE where available,
else a GPIO via a `Gpio` handle held by the driver), and the TX-complete ISR releases it.
In half-duplex the driver also masks its own echo from RX.

### 3.6 ioctl additions for the serial block (`0x01xx`)

```rust
// serial (0x01xx) — existing: SET_BAUD 0x0101, GET_BAUD 0x0102, RX_AVAILABLE 0x0103, FLUSH 0x0104
pub const SERIAL_GET_CONFIG: u32 = 0x0105;  // arg: *mut  SerialConfig
pub const SERIAL_SET_CONFIG: u32 = 0x0106;  // arg: *const SerialConfig
pub const SERIAL_GET_ERRORS: u32 = 0x0107;  // returns packed counts, clears them
pub const SERIAL_SET_RS485:  u32 = 0x0108;  // arg: *const Rs485Config
pub const SERIAL_SEND_BREAK: u32 = 0x0109;  // arg: duration in ms
pub const SERIAL_DRAIN:      u32 = 0x010A;  // block until TX ring + FIFO empty (tcdrain)
pub const SERIAL_TX_SPACE:   u32 = 0x010B;  // bytes free in the TX ring
```

---

## 4. Layer 2 — the `Tty` line discipline (middleware)

### 4.1 Why middleware, and how it generalizes `LineDiscipline`

The existing `pl011::LineDiscipline` is already a `Middleware` that rewrites `Op::Write`
(`\n`→`\r\n`) and `Op::Read` (`\r`→`\n`). The `Tty` is the same idea taken to completion,
and — critically — it is **device-independent**: attach it over a UART, a `Pipe`, a PTY
slave, or a keyboard-backed char device and it behaves identically, because it only ever
calls `next.run(req)` with `Op::Read`/`Op::Write`. It is attached like any layer
(`dev.attach(&TTY)`), so it sits in the *driver-adjacent* position of the global → user →
driver chain, below user policy layers.

```rust
pub struct Tty {
    name:   &'static str,
    t:      IrqCell<Termios>,
    cook:   IrqCell<LineBuf>,          // canonical line being edited
    sigtgt: IrqCell<Option<(TaskId, SigMap)>>,  // controlling task + notify bits
    sigs:   EventFlags,                // alternative/parallel delivery
}
```

### 4.2 Output path (`c_oflag`, `OPOST`)

`handle`-time, on `Op::Write`: if `OPOST` is clear, pass through unchanged. Otherwise walk
the buffer and emit derived writes exactly as `LineDiscipline` does today
(`req.derive(Op::Write(...))` + `next.run`), applying `ONLCR` (`\n`→`\r\n`), `OCRNL`
(`\r`→`\n`), `ONOCR`, `ONLRET`, and tab/BS expansion if ever needed. Returning the
caller-visible byte count (not the expanded count) matches the current implementation.

### 4.3 Input path (`c_iflag`, `c_lflag`, canonical vs raw)

This is the substantive part. The `Tty` loops pulling *raw* bytes from the device and
cooks them:

```rust
Op::Read(buf) => {
    let t = self.t.lock(|t| *t);
    if t.lflag & ICANON == 0 {
        return self.read_raw(buf, &t, req, next);      // VMIN/VTIME semantics
    }
    loop {
        // 1. Is a completed line already buffered? copy it out and return.
        if let Some(n) = self.cook.lock(|c| c.take_line(buf)) { return Ok(n); }
        // 2. Otherwise read a chunk of raw bytes from the device (respecting timeout).
        let mut raw = [0u8; 32];
        let got = next.run(&mut req.derive(Op::Read(&mut raw)))?;
        // 3. Feed each byte through input processing + editing + echo.
        for &b in &raw[..got] {
            match self.input_byte(b, &t, &next, req) {  // may echo via next.run(Write)
                LineEvent::Char | LineEvent::Edit => {}
                LineEvent::LineReady => {}               // loop back, step 1 returns it
                LineEvent::Signal(sig) => self.raise(sig, req),  // §4.5
                LineEvent::Eof => return Ok(0),          // Ctrl-D on empty line
            }
        }
    }
}
```

`input_byte` implements, in order: `ISTRIP` (8→7 bit), `IGNCR`/`ICRNL`/`INLCR` CR/NL
translation, `IXON`/`IXOFF` flow bytes (consumed, not buffered), then in canonical mode the
editing set:

| key (c_cc) | default | action |
|---|---|---|
| `VERASE` | `0x7F`/`^H` | delete last char in `cook`; if `ECHOE`, emit `\b \b` |
| `VWERASE` | `^W` | delete back to previous word boundary |
| `VKILL` | `^U` | clear the line; if `ECHOK`, newline or re-prompt |
| `VEOF` | `^D` | end line now; on an empty line → `read()` returns 0 (EOF) |
| `VEOL`/`\n` | `\n` | terminate the line (include the delimiter, as POSIX requires) |
| `VINTR` `VQUIT` `VSUSP` | `^C ^\ ^Z` | under `ISIG`, raise the mapped signal (§4.5) |

Echo (`ECHO`/`ECHOE`/`ECHOK`/`ECHONL`/`ECHOCTL`) is just `next.run(Op::Write(..))` back to
the same device — which is why the `Tty` must be *below* any output-rewriting user layer
but is itself the discipline. Line length is bounded (`LineBuf` is a fixed array, e.g.
256 B); overflow rings the bell (`IMAXBEL`) or drops, never allocates.

**Raw mode** (`read_raw`) implements the `VMIN`/`VTIME` four-case table:

| VMIN | VTIME | behaviour |
|---|---|---|
| 0 | 0 | return immediately with whatever is available (polling) |
| >0 | 0 | block until at least `VMIN` bytes (no timer) |
| 0 | >0 | read timer: return as soon as any byte arrives, else after `VTIME` ds |
| >0 | >0 | interbyte timer: `VTIME` ds *between* bytes, up to `VMIN` |

These map onto `req` timeouts and the device's own `read_timeout`, so no new kernel
timer is needed for the common cases.

### 4.4 termios store and the hardware projection

`TTY_SET_TERMIOS` writes `self.t` and then projects the *hardware* subset downward:

```rust
fn apply(&self, new: &Termios, when: Apply, next: &Next) -> IoResult {
    if when != Apply::Now { next.run(&mut Request::new(Op::Ioctl{cmd:SERIAL_DRAIN,arg:0}))?; }
    let cfg = SerialConfig {
        baud: new.c_ospeed,
        data_bits: match new.c_cflag & CSIZE { CS5=>5, CS6=>6, CS7=>7, _=>8 },
        parity: if new.c_cflag & PARENB == 0 { Parity::None }
                else if new.c_cflag & PARODD != 0 { Parity::Odd } else { Parity::Even },
        stop_bits: if new.c_cflag & CSTOPB != 0 { StopBits::Two } else { StopBits::One },
        flow: if new.c_cflag & CRTSCTS != 0 { FlowControl::RtsCts }
              else if new.c_iflag & (IXON|IXOFF) != 0 { FlowControl::XonXoff }
              else { FlowControl::None },
    };
    // Downward to the hardware driver; a PTY/Pipe returns Unsupported, which we ignore.
    let _ = next.run(&mut Request::new(Op::Ioctl{cmd:SERIAL_SET_CONFIG, arg:&cfg as *const _ as usize}));
    self.t.lock(|t| *t = *new);
    if when == Apply::Flush { next.run(&mut Request::new(Op::Ioctl{cmd:TTY_FLUSH,arg:TCIFLUSH}))?; }
    Ok(0)
}
```

Over a PTY the `c_cflag`/speed bits are inert (the `Pipe` returns `Error::Unsupported` for
`SERIAL_SET_CONFIG`, which `apply` tolerates) — exactly as a real PTY ignores baud. This is
the whole trick that lets one `Tty` sit over hardware or software unchanged.

### 4.5 Signals without UNIX signals

Bismuth has no asynchronous signal frames, so "deliver `SIGINT`" becomes a two-part,
*cooperative* action defined entirely in terms of existing primitives:

```rust
pub enum TtySig { Int, Quit, Susp }   // VINTR, VQUIT, VSUSP

fn raise(&self, sig: TtySig, req: &Request) {
    if self.t.lock(|t| t.lflag & NOFLSH == 0) { self.cook.lock(|c| c.clear()); }
    // (a) notify the bound controlling task (ISR-safe path reused here in task ctx)
    if let Some((task, map)) = self.sigtgt.lock(|s| *s) {
        let _ = task::notify(task, map.bit(sig));
    }
    self.sigs.set(1 << sig as u32);         // (b) parallel EventFlags delivery
    // (c) interrupt the in-progress blocking read so read() returns EINTR
    //     (the reader task is this task; the kernel surfaces WakeReason::Aborted)
}
```

| termios | char | Bismuth mapping |
|---|---|---|
| `SIGINT` (`VINTR`) | `^C` | `task::notify(ctty, INT_bit)` + `EventFlags` set + current `read` → `Error::Interrupted` (EINTR) |
| `SIGQUIT` (`VQUIT`) | `^\` | `task::notify(ctty, QUIT_bit)` + EventFlags |
| `SIGTSTP` (`VSUSP`) | `^Z` | `task::notify(ctty, SUSP_bit)`; app decides whether to self-`suspend` (no kernel job control) |
| break w/ `BRKINT` | — | treated as `VINTR` |

An app "handles a signal" by waiting on its notification word (`task::notify_wait`) or the
`EventFlags` group, or simply by observing that `read()` returned `EINTR` and checking the
notification bits. There is no preemptive handler and no default-action table — the app is
in charge, which suits a cooperative RTOS. This is explicitly *not* job control: there is no
`SIGTTIN`/`SIGTTOU`, no stop/continue of groups, no `SIGHUP` cascade (a carrier-loss hook is
offered as an optional callback, §7).

### 4.6 Controlling terminal adapted to tasks/domains

A `Tty` holds **one** controlling target `(TaskId, SigMap)`, set by `TTY_SET_SIGTARGET`
(the TIOCSCTTY analogue). Default: the first task to issue it, or the task the board binds
at setup. Signal chars post only there. For isolated domains the target may be recorded as a
`DomainId` instead, and notifications fan out to that domain's tasks — but a single task is
the common, sufficient case. No sessions, no foreground/background distinction, no
orphaned-pgrp rules.

### 4.7 Input subsystem and console integration

- **Keyboard as a TTY input source.** The input/HID subsystem (see the parallel HID
  research) exposes a keyboard as a `Char` device that yields a decoded byte stream (keysyms
  → bytes, e.g. arrow keys → CSI sequences). A `Tty` attached over *that* device gives line
  editing and echo for a local keyboard+screen console with zero changes — the discipline
  never knew it wasn't a UART.
- **Console.** `src/console.rs` currently writes to a raw device through its middleware
  chain. An interactive console is a `Tty` over the console device: `kprintln!` output flows
  through `OPOST`/`ONLCR`, and a shell task reads cooked lines from the same device. The
  console's `console_write` fast-path (which stamps `Caller::KERNEL`) is unaffected — it is
  still just `Op::Write` down the chain.

### 4.8 ioctl block for the tty (`0x06xx`)

```rust
pub const TTY_GET_TERMIOS:       u32 = 0x0601;  // *mut  Termios     (TCGETS)
pub const TTY_SET_TERMIOS:       u32 = 0x0602;  // *const Termios     (TCSETS  / TCSANOW)
pub const TTY_SET_TERMIOS_DRAIN: u32 = 0x0603;  // *const Termios     (TCSETSW / TCSADRAIN)
pub const TTY_SET_TERMIOS_FLUSH: u32 = 0x0604;  // *const Termios     (TCSETSF / TCSAFLUSH)
pub const TTY_FLUSH:             u32 = 0x0605;  // arg = TCIFLUSH|TCOFLUSH|TCIOFLUSH (TCFLSH)
pub const TTY_DRAIN:             u32 = 0x0606;  // block until output drained (tcdrain)
pub const TTY_GET_WINSIZE:       u32 = 0x0607;  // *mut  WinSize       (TIOCGWINSZ)
pub const TTY_SET_WINSIZE:       u32 = 0x0608;  // *const WinSize       (TIOCSWINSZ)
pub const TTY_SET_SIGTARGET:     u32 = 0x0609;  // bind controlling task (TIOCSCTTY-ish)
```

### 4.9 Extending `required_right` in `class.rs`

Queries and routine operation need `CONTROL`; anything that reconfigures the device (or is
unknown) needs `CONFIG`. The new GET/operational commands join the `CONTROL` arm; the SET
commands fall through to the existing `_ => Rights::CONFIG` default. `TTY_SET_SIGTARGET` is
deliberately `CONFIG`: binding who receives signals is a privileged change, not routine I/O.

```rust
GET_CLASS | SERIAL_GET_BAUD | SERIAL_RX_AVAILABLE | SERIAL_FLUSH
| SERIAL_GET_CONFIG | SERIAL_GET_ERRORS | SERIAL_SEND_BREAK | SERIAL_DRAIN | SERIAL_TX_SPACE
| TTY_GET_TERMIOS | TTY_FLUSH | TTY_DRAIN | TTY_GET_WINSIZE
| GPIO_SET | /* ... existing ... */ NET_GET_RX_DROPPED => Rights::CONTROL,
// SERIAL_SET_CONFIG, SERIAL_SET_RS485, TTY_SET_TERMIOS*, TTY_SET_WINSIZE,
// TTY_SET_SIGTARGET, SERIAL_SET_BAUD → Rights::CONFIG (default arm)
_ => Rights::CONFIG,
```

**Pointer args and isolation.** `SERIAL_*_CONFIG` and `TTY_*_TERMIOS` pass a struct address
in `arg`. For trusted (kernel-domain) callers this is a direct `&T`. For isolated MPU
domains the value arrives through `DeviceCap::ioctl`; the POSIX/cap layer must bounce it
through `kernel/usermem.rs` (validate the pointer lies in the caller's region, copy in/out),
never dereference a raw user pointer in the driver. The driver sees only a kernel-validated
`&Termios`.

---

## 5. Layer 3 — PTY-like loopback

### 5.1 A PTY is two cross-wired pipes

`src/net/drivers/wire.rs` already demonstrates the exact pattern: two lanes, each a
`Queue<_, DEPTH>`, side 0 writing lane 0 / reading lane 1 and side 1 the opposite. A PTY is
the byte-stream version, reusing `Pipe`'s ring + `block_on` instead of a packet queue:

```rust
// src/driver/drivers/pty.rs
pub struct PtyPair { m2s: Pipe<BUF>, s2m: Pipe<BUF> }  // master→slave, slave→master

pub struct PtyEnd { pair: &'static PtyPair, master: bool }

impl Driver for PtyEnd {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: if self.master {"ptm"} else {"pts"},
                     class: DeviceClass::Char, version: (1,0,0),
                     compatible: &["bismuth,pty"] }
    }
    fn middleware(&self) -> &'static [&'static dyn Middleware] { &[] }  // slave gets a Tty attached
    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let (rd, wr) = if self.master { (&self.pair.s2m, &self.pair.m2s) }
                       else           { (&self.pair.m2s, &self.pair.s2m) };
        match &mut req.op {
            Op::Read(b)  => rd.handle_read(b, req.timeout),   // reuse Pipe's block_on read
            Op::Write(d) => wr.handle_write(d, req.timeout),  // reuse Pipe's block_on write
            Op::Ioctl{cmd: SERIAL_SET_CONFIG, ..} => Err(Error::Unsupported), // no baud on a PTY
            Op::Ioctl{cmd: ioctl::SERIAL_RX_AVAILABLE, ..} => Ok(rd.available()),
            Op::Ioctl{cmd: ioctl::GET_CLASS, ..} => Ok(DeviceClass::Char as usize),
            _ => Err(Error::Unsupported),
        }
    }
}
```

Registration mints two devices (`/dev/ptmN`, `/dev/ptsN`); the slave gets a `Tty` attached
(`pts.attach(&TTY_N)`) so it cooks, while the master stays raw. A shell/CLI task opens the
slave as its console; a test harness, a USB-CDC bridge, or a network-console task drives the
master.

### 5.2 Relation to UNIX, and the honest differences

- Same shape as `openpty`/`ptmx` + `pts`: master is the emulator side, slave is the
  terminal with the discipline.
- **No `fork`/`exec`, no `login`/`getty`, no session leader.** The "slave session" is simply
  a task that reads/writes the slave device; "controlling terminal" is the §4.6 bound task.
- No `grantpt`/`unlockpt`/`ptsname` permission dance — device creation is a privileged,
  static/board-time act (`register` already requires a trusted domain), and access is
  mediated by the normal `DeviceCap` rights for isolated domains.
- No packet mode (`TIOCPKT`), no `TIOCSTI` injection (an input-spoofing hazard we refuse by
  omission).

### 5.3 Why this is the test linchpin

Because the discipline and termios are device-independent, every TTY behaviour — canonical
editing, echo, `VMIN`/`VTIME`, `OPOST`, XON/XOFF, Ctrl-C → EINTR — is testable by writing
bytes to the master and asserting what the slave's cooked `read()` returns, with no UART and
no board. This is the direct analogue of `tests/net.rs` running two IP stacks over `Wire`.

---

## 6. Layer 4 — POSIX termios compatibility

A new `src/compat/posix/termios.rs` adds the `<termios.h>` surface on top of the existing fd
table. Every call is a thin wrapper over `ioctl(fd, ...)` (already in
`src/compat/posix/unistd.rs`), so it works uniformly on a UART fd, a PTY-slave fd, or the
console fd, and respects the `DeviceCap` rights of isolated domains.

```rust
#[repr(C)] pub struct termios {
    pub c_iflag: tcflag_t, pub c_oflag: tcflag_t, pub c_cflag: tcflag_t, pub c_lflag: tcflag_t,
    pub c_cc: [cc_t; NCCS], pub c_ispeed: speed_t, pub c_ospeed: speed_t,
}

pub fn tcgetattr(fd: c_int, t: &mut termios) -> c_int {
    to_ret(ioctl(fd, TTY_GET_TERMIOS, t as *mut _ as usize))
}
pub fn tcsetattr(fd: c_int, when: c_int, t: &termios) -> c_int {
    let cmd = match when { TCSANOW => TTY_SET_TERMIOS,
                           TCSADRAIN => TTY_SET_TERMIOS_DRAIN,
                           TCSAFLUSH => TTY_SET_TERMIOS_FLUSH, _ => return einval() };
    to_ret(ioctl(fd, cmd, t as *const _ as usize))
}
pub fn cfsetospeed(t: &mut termios, s: speed_t) -> c_int { t.c_ospeed = s; 0 }
pub fn cfsetispeed(t: &mut termios, s: speed_t) -> c_int { t.c_ispeed = s; 0 }
pub fn cfgetospeed(t: &termios) -> speed_t { t.c_ospeed }
pub fn cfgetispeed(t: &termios) -> speed_t { t.c_ispeed }
pub fn cfmakeraw(t: &mut termios) { /* clear ICANON ECHO ISIG IEXTEN, ICRNL IXON, OPOST; VMIN=1 VTIME=0 */ }
pub fn tcflush(fd: c_int, q: c_int)  -> c_int { to_ret(ioctl(fd, TTY_FLUSH, q as usize)) }
pub fn tcdrain(fd: c_int)            -> c_int { to_ret(ioctl(fd, TTY_DRAIN, 0)) }
pub fn tcsendbreak(fd: c_int, d: c_int) -> c_int { to_ret(ioctl(fd, SERIAL_SEND_BREAK, d as usize)) }
pub fn tcflow(fd: c_int, action: c_int) -> c_int { /* TCOOFF/TCOON/TCIOFF/TCION → XON/XOFF ioctl */ }
```

- **Speeds as integers.** `c_ispeed`/`c_ospeed` hold the raw baud (e.g. `115200`), so
  `cfsetospeed` is a field write and the `B115200`-style macros are just those integers.
  This drops the historical speed-table indirection, which buys nothing on an MCU.
- **`isatty`/`ttyname`.** `isatty` already returns 1 for a `DeviceClass::Char` device
  (`src/compat/posix/unistd.rs:252`); `ttyname_r` can return the device's registry name.
- **`poll`.** The existing `poll_one` keys readiness off `SERIAL_RX_AVAILABLE` for char
  devices; over a `Tty` that count should reflect *cooked* availability in canonical mode
  (a line ready), so the `Tty` answers `SERIAL_RX_AVAILABLE` from its own line buffer, not
  the raw device.
- **Struct marshalling.** Trusted callers pass `&termios` directly; isolated-domain calls go
  through `usermem` as in §4.9.

---

## 7. Phased, host-simulator-testable plan

| Phase | Deliverable | Testable on host how |
|---|---|---|
| **P0: termios types + ioctls** | `Termios`/`SerialConfig`/`Rs485Config`/`WinSize`; extend `class.rs` ioctl block (`0x0105..`, `0x06xx`) and `required_right`; `cfmakeraw` and flag/`c_cc` constants. | Pure unit tests: flag round-trips, `required_right` classification, `cfmakeraw` result. No tasks. |
| **P1: `Tty` middleware over `Pipe`** | Canonical cook loop, editing (`VERASE/VWERASE/VKILL/VEOF`), echo (`ECHO/ECHOE/ECHOK`), CR/NL xlate, `OPOST/ONLCR`, raw `VMIN/VTIME`. Attach over a `Pipe`. | `sim::run`: a writer task feeds bytes into the pipe, a reader task asserts cooked lines; table-driven over termios variants. Mirrors `tests/drivers.rs`. |
| **P2: `Pty` pair** | `PtyPair` + two `PtyEnd` devices reusing `Pipe` read/write; register `/dev/ptm0`,`/dev/pts0`; attach `Tty` to the slave. | Write to master fd, assert slave cooked `read()`; echo visible back on master. The TTY linchpin test (§5.3). |
| **P3: Signals + EINTR** | `TtySig` mapping, `TTY_SET_SIGTARGET`, `raise()` → `task::notify` + `EventFlags` + abort-blocked-read. | Slave task blocks in `read()`; master sends `^C`; assert `read()` → `Error::Interrupted` and the notify bit is set; `NOFLSH` behaviour. |
| **P4: Interrupt-driven `Uart` core** | `uart.rs` with RX/TX `ByteRing`, `rx_ready`/`tx_space` semaphores, `on_irq()`, `SerialConfig`, error counters; replace `pl011.rs` internals (keep `LineDiscipline`/`Tty` on top). | `MockUart`: a std thread plays hardware and calls `on_irq` via `sim::interrupt`; assert reads wake promptly, partial writes, overrun counting. Realtime `sim::Config`. |
| **P5: Flow control + break/errors** | HW RTS/CTS + XON/XOFF (`IXON/IXOFF/IXANY`), `SERIAL_GET_ERRORS`, `SERIAL_SEND_BREAK`, `BRKINT/IGNBRK/PARMRK`. | MockUart injects XOFF / framing errors / break; assert TX pauses, counters increment, break → `VINTR` under `BRKINT`. |
| **P6: POSIX `<termios.h>`** | `compat/posix/termios.rs` (`tcgetattr/tcsetattr/cfset*speed/tcflush/tcdrain/tcsendbreak/cfmakeraw/tcflow`) over the fd ioctls; `ttyname_r`; cooked `poll` readiness. | `tests/posix.rs`-style: a "C programmer" opens `/dev/pts0`, `cfmakeraw`, round-trips termios, reads/writes; `poll` on a cooked line. |
| **P7: Hardware backends** | Real DMA-RX + idle-line backend for one MCU USART (e.g. STM32), RS-485 DE via TX-complete, on a board under QEMU where feasible. | QEMU board smoke test; on-host the DMA path is exercised through MockUart's "burst then idle" injection. |
| **P8: Console + keyboard source** | Interactive console = `Tty` over the console device; keyboard char-device (HID) as an alternate input source under the same `Tty`. | `sim` console test: feed keystrokes, assert cooked line + echo; integrate with HID research deliverable. |

Test strategy throughout mirrors the existing suite: deterministic `sim::run`
(`src/sim.rs`), one std thread as "hardware" via `sim::interrupt` + realtime config for the
UART ISR tests, per-file `SERIAL` mutex for shared logs, and property tests for the
`VMIN`/`VTIME` table and termios flag independence.

---

## 8. What NOT to build (and why)

| Feature | Origin | Why not for Bismuth |
|---|---|---|
| Job control: sessions, process groups, `SIGTTIN/SIGTTOU`, stop/cont of groups | POSIX job control | No process groups on an MCU; one bound controlling task (§4.6) is enough. A shell runs tasks, not pipelines of jobs. |
| Multiple sessions / `TIOCSCTTY` steal semantics, orphaned-pgrp rules | UNIX tty core | No sessions. One `Tty` → one controlling task. |
| Runtime-swappable N_* line disciplines as a stack (`TIOCSETD`, N_SLIP/N_PPP/N_HDLC) | Linux ldisc mux | One canonical discipline configured by termios. SLIP/PPP, if needed, are *char→net adapters* (own driver), not a tty ldisc — see `docs/research/networking.md` nodes. |
| Full asynchronous UNIX signals (handlers, masks, default actions, `SIGHUP` cascade) | UNIX signals | No signal frames. Cooperative notify + EINTR (§4.5). A single optional carrier-loss callback covers the real `SIGHUP` need. |
| `TIOCSTI` terminal input injection | Linux | Input-spoofing security hazard; refuse by omission. |
| Packet-mode PTY (`TIOCPKT`), `grantpt`/`unlockpt`/`ptsname` | UNIX pty | No `sshd`/`screen` multiplexers; PTYs are created at board/privileged time. |
| terminfo / termcap, locale/multibyte cooking, `iconv` | UNIX userland | No locale layer; bytes in, bytes out. Apps that want UTF-8 editing do it themselves. |
| Flip-buffer / work-queue RX plumbing, per-CPU tty_buffer | Linux SMP | Single-owner reader task + one RX ring; no SMP contention to amortize. |
| Historical baud-code table (`B9600` as an index) | termios legacy | Store raw integer baud in `c_ispeed`/`c_ospeed`; reject unachievable rates. |
| `readline`-class history/completion in the kernel | — | That is an application library above cooked `read()`, not a kernel discipline. |

---

## 9. Key takeaways mapped to sources

1. *Cooking belongs in a swappable layer over raw bytes* → Linux `n_tty.c`, FreeBSD
   `ttydisc` → Bismuth `Tty` **middleware** generalizing `pl011::LineDiscipline`.
2. *One termios object configures all three layers; hardware bits project to the driver* →
   termios(3) / POSIX GTI → `Termios` + downward `SERIAL_SET_CONFIG`.
3. *A PTY is the top two layers over an in-memory pipe* → pty(7), openpty(3) → `PtyPair` on
   two `Pipe` rings, the `net::Wire` pattern.
4. *ISR fills a buffer and wakes the reader; never process in ISR* → Linux `serial_core`
   RX path → RX/TX `ByteRing` + binary `Semaphore::give` (ISR-safe) + `block_on`.
5. *Amortize interrupts at high rate* → DMA + IDLE line (STM32 USART) → §3.4, the serial
   NAPI.
6. *Signals go to the controlling terminal's foreground target* → POSIX job control →
   reduced to one bound task + `task::notify`/`EventFlags`/EINTR, no job control.
7. *Flow control and error status are first-class* → RTS/CTS, XON/XOFF, FE/PE/OE/BE →
   `SerialConfig.flow`, `SERIAL_GET_ERRORS`, `BRKINT/PARMRK`.
8. *The compat layer is thin shims over one request pipeline* → the existing POSIX/fd model
   → `tcgetattr`/`tcsetattr`/... as `ioctl` wrappers.

---

## References

**POSIX / man pages**
- [termios3]: termios(3) — General Terminal Interface. https://man7.org/linux/man-pages/man3/termios.3.html
- [posixgti]: POSIX.1-2017 Ch. 11, General Terminal Interface. https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/termios.h.html
- [pty7]: pty(7). https://man7.org/linux/man-pages/man7/pty.7.html
- [openpty]: openpty(3) / forkpty(3). https://man7.org/linux/man-pages/man3/openpty.3.html
- tcsetattr(3) / tcflush / tcdrain / tcsendbreak / tcflow. https://man7.org/linux/man-pages/man3/tcsetattr.3.html
- ioctl_tty(2) — TCGETS/TCSETS/TCFLSH/TIOCGWINSZ/TIOCSCTTY/TIOCPKT. https://man7.org/linux/man-pages/man2/ioctl_tty.2.html

**Linux internals**
- TTY subsystem overview. https://docs.kernel.org/driver-api/tty/index.html
- N_TTY line discipline — `drivers/tty/n_tty.c`. https://elixir.bootlin.com/linux/latest/source/drivers/tty/n_tty.c
- Serial core (`uart_ops`, flip buffers) — `drivers/tty/serial/serial_core.c`. https://docs.kernel.org/driver-api/serial/driver.html
- tty buffering / flip buffers. https://docs.kernel.org/driver-api/tty/tty_buffer.html

**Background / other kernels**
- [ttydem]: L. Åkesson, "The TTY demystified". https://www.linusakesson.net/programming/tty/
- [linuxtty]: "The Linux keyboard and console HOWTO" / tty line settings. https://tldp.org/HOWTO/Text-Terminal-HOWTO.html
- [freebsdtty]: FreeBSD tty(4) and the `ttydisc` discipline. https://man.freebsd.org/cgi/man.cgi?query=tty&sektion=4
- FreeBSD `ttydisc` source. https://cgit.freebsd.org/src/tree/sys/kern/tty_ttydisc.c

**Hardware references**
- ARM PrimeCell PL011 UART TRM (DR error bits FE/PE/BE/OE, RSR/ECR, RTS/CTS, FIFO/RT IRQ). https://developer.arm.com/documentation/ddi0183/
- STM32 USART (DMA circular RX + IDLE-line interrupt; RS-485 DE, TX-complete). STM32F4/H7 Reference Manuals, USART chapter. https://www.st.com/resource/en/reference_manual/
- TIA/EIA-485 (RS-485) driver-enable direction control (application notes, e.g. MAX3485). https://www.ti.com/lit/an/slla070d/slla070d.pdf

**Rust `no_std` prior art**
- `embedded-hal` / `embedded-io` serial traits (Read/Write, nb). https://docs.rs/embedded-hal , https://docs.rs/embedded-io
- `embedded-hal-nb` serial, `nb` non-blocking model. https://docs.rs/embedded-hal-nb
