# Human interface: display and input

Source:

- `src/driver/display/mod.rs`: display class and the typed `Display` API;
- `src/driver/input/mod.rs`: input class, `InputEvent` and the typed `Input` API;
- `src/driver/display/sim.rs` and `src/driver/input/sim.rs`: simulator drivers;
- ioctls in `src/driver/ioctl.rs`.

Tests: `tests/hid.rs`. Research input:
[research/human-interface.md](../research/human-interface.md).

Display and input are **not a new subsystem**. They are two more `DeviceClass`
variants, `Display` and `Input`, served by ordinary `Driver`s through the existing
`Op::Read`/`Op::Write`/`Op::Ioctl` requests. No new `Op` variant was added, so the whole
stack applies unchanged:

- middleware (`Stats`, `Trace`, `PowerGate`, `AccessPolicy`, ...);
- `DeviceCap` rights;
- POSIX fds;
- power states.

> **ioctl numbering differs from the research.** The research proposed display at
> `0x06xx` and input at `0x07xx`, but `0x06xx` was already the TTY block. The code uses
> **display = `0x07xx`** and **input = `0x08xx`**.

Adding the two classes shifted `DeviceClass::Other` from 7 to **9** in `GET_CLASS`
results. The order is `Char` 0, `Gpio` 1, `I2c` 2, `Spi` 3, `Sensor` 4, `Block` 5,
`Net` 6, `Display` 7, `Input` 8, `Other` 9.

## Display

### Protocol

The protocol mirrors the `CASET`/`RASET`/`RAMWR` command set of MIPI-DCS panel
controllers:

```text
ioctl DISPLAY_SET_COL  arg = x0 | x1 << 16      (inclusive column range)
ioctl DISPLAY_SET_ROW  arg = y0 | y1 << 16      (inclusive row range)
Op::Write(pixels)      stream pixels into the window, row-major, wrapping at x1
ioctl DISPLAY_FLUSH    arg = RefreshMode         (buffered / e-paper panels: push to glass)
```

| ioctl | value | arg → result | right |
|-------|-------|--------------|-------|
| `DISPLAY_GET_GEOMETRY` | `0x0701` | → `width \| height << 16` | CONTROL |
| `DISPLAY_GET_FORMAT` | `0x0702` | → `PixelFormat::code()` | CONTROL |
| `DISPLAY_GET_CAPS` | `0x0703` | → `DisplayCaps` bits | CONTROL |
| `DISPLAY_SET_COL` | `0x0704` | `x0 \| x1 << 16` | CONTROL |
| `DISPLAY_SET_ROW` | `0x0705` | `y0 \| y1 << 16` | CONTROL |
| `DISPLAY_FLUSH` | `0x0706` | `RefreshMode` (0 full, 1 partial, 2 fast) | CONTROL |
| `DISPLAY_WAIT_VSYNC` | `0x0707` | honours the request timeout | CONTROL |
| `DISPLAY_SET_BACKLIGHT` | `0x0708` | level 0–255 | CONTROL |
| `DISPLAY_BLANK` | `0x0709` | 1 = blank, 0 = unblank | CONTROL |
| `DISPLAY_SET_ORIENTATION` | `0x070A` | driver-defined | **CONFIG** |
| `DISPLAY_SET_FORMAT` | `0x070B` | format code | **CONFIG** |

Pixel writes need `WRITE`. For example, a domain that holds only `CONTROL` can query
the panel and adjust the backlight, but cannot draw.

### Types

| type | contents |
|------|----------|
| `PixelFormat` | `Mono1 { page_major }` (codes 0/1; `page_major` = SSD1306-style 8 vertical pixels per byte), `Gray4` (2), `Rgb565` (3, **big-endian on the wire**), `Rgb888` (4). Methods: `bits_per_pixel()`, `region_bytes(w, h)`, `code()`, `from_code()`. |
| `Rect` | `{ x, y, w, h }` and `Rect::new` |
| `DisplayCaps` | `PARTIAL_REFRESH` (bit 0), `BACKLIGHT` (1), `VSYNC_TE` (2), `READBACK` (5); `contains`, `with` |
| `RefreshMode` | `Full`, `Partial`, `Fast` |

### Typed API: `driver::display::Display(Device)`

| method | notes |
|--------|-------|
| `open(name)` | `Unsupported` if the device is not `Display` class |
| `geometry()`, `format()`, `caps()` | |
| `blit(Rect, &[u8])` | Sets the window, then `write_all`s the pixels. The length must match `format.region_bytes(w, h)`. `Invalid` for an empty rect or a window beyond the `u16` coordinate range. |
| `flush(RefreshMode)` | |
| `wait_vsync(timeout)` | |
| `set_backlight(u8)` | |
| `blank(bool)` | |

`blit` is **three requests**: two window ioctls and a write. Another task's blit can
interleave between them. `Exclusive` middleware does not help, because it serialises
single requests only. Give the display a single owner task, or wrap the `Display` in a
`sync::Mutex`.

Attach `Stats` to a display and `bytes_out` counts the bytes pushed to the panel, with
no extra code.

### `SimDisplay<W, H, PIXELS>`

- An RGB565 RAM framebuffer, where `PIXELS` must equal `W × H` (asserted at compile
  time).
- Implements geometry, format, caps (`BACKLIGHT | READBACK`), window, write, flush
  (counted), vsync (returns immediately), backlight and blank.
- `Op::Power(off)` blanks it.
- Test hooks: `pixel(x, y)`, `backlight()` and `flush_count()`.
- `SET_ORIENTATION` and `SET_FORMAT` return `Unsupported`.
- Compatible string `bismuth,sim-display`, but **no probe factory**: register it
  directly.

## Input

### Model (evdev-style)

An input device is a `Read` source of fixed-size events, just as a `Sensor` is a
source of `i32` samples. Blocking reads and timeouts work through the existing
machinery.

```rust
pub struct InputEvent { pub tick: u64, pub value: i32, pub code: u16, pub kind: u8, pub _pad: u8 }
// 16 bytes, little-endian on the wire: tick[0..8] value[8..12] code[12..14] kind[14] pad[15]
pub enum EventKind { Syn = 0, Key = 1, Rel = 2, Abs = 3 }
```

- `Key` values are 1 = down, 0 = up, 2 = repeat.
- `Rel` values are deltas; `Abs` values are positions.
- A packet of related events ends with a `Syn` event.
- `InputEvent::new(kind, code, value)` stamps the current tick, and `InputEvent::syn()`
  makes a terminator. `to_bytes` and `from_bytes` convert to and from the wire layout.
- `input::code` holds a subset of HID usage IDs and evdev codes:
  - keys: `KEY_A` (0x04) … `KEY_Z`, `KEY_1`, `KEY_ENTER`, `KEY_ESC`, `KEY_BACKSPACE`,
    `KEY_SPACE`, arrows;
  - buttons: `BTN_LEFT`/`RIGHT`/`MIDDLE` (0x110–0x112);
  - axes: `REL_X`/`REL_Y`/`REL_WHEEL`, `ABS_X`/`ABS_Y`/`ABS_PRESSURE`.

| ioctl | value | arg → result | right |
|-------|-------|--------------|-------|
| `INPUT_GET_CAPS` | `0x0801` | → `EventKind::bit()` mask | CONTROL |
| `INPUT_EVENTS_AVAILABLE` | `0x0802` | → queued events | CONTROL |
| `INPUT_FLUSH` | `0x0803` | discard queued events | CONTROL |
| `INPUT_GET_ID` | `0x0804` | → device id (driver-defined) | CONTROL |
| `INPUT_GET_ABS_INFO` | `0x0805` | driver-defined | CONTROL |
| `INPUT_GRAB` | `0x0806` | driver-defined | CONTROL |
| `INPUT_SET_REPEAT` | `0x0807` | `delay_ms \| rate_ms << 16` | **CONFIG** |

Reading events needs `READ`.

### Typed API: `driver::input::Input(Device)`

| method | notes |
|--------|-------|
| `open(name)` | |
| `read(&mut [InputEvent], timeout)` | Waits up to `timeout` for the first event, then returns what is queued, **at most 16 events per call**. Returns the count. |
| `available()` | |
| `caps()` | |
| `flush()` | |
| `set_repeat(delay_ms, rate_ms)` | |

POSIX `poll` reports an `Input` fd as readable only when `INPUT_EVENTS_AVAILABLE > 0`,
and never as writable.

### `SimInput<N>`

The generic backend that every real input driver reduces to:

- a bounded `Queue<InputEvent, N>`;
- `inject(ev)` is ISR-safe and never blocks. When the queue is full it drops the
  **newest** event and counts it in `overruns()`;
- `tap(code)` injects a key down + `Syn` + key up + `Syn`;
- constructors `SimInput::keyboard()` (Key, Syn) and `SimInput::mouse()` (Rel, Key,
  Syn), or `new(caps)`;
- a read blocks for the first event (honouring the timeout and `FLAG_NONBLOCK`), then
  drains without waiting;
- supports `GET_CAPS`, `EVENTS_AVAILABLE`, `FLUSH`, `GET_ID` (returns 0) and
  `SET_REPEAT` (accepted, not simulated). `GET_ABS_INFO` and `GRAB` return
  `Unsupported`;
- compatible string `bismuth,sim-input`, no probe factory.

## Limitations and known gaps

- **Packets are not read atomically.** The module docs say a `Syn`-terminated packet
  "is read atomically". In fact a read fills the caller's buffer, up to 16 events in
  `Input::read`, and can split a packet across two reads. Consumers should accumulate
  events until they see `Syn`.
- `SimDisplay` and `SimInput` provide **no driver middleware**, against the "every
  driver provides middleware" rule. The same is true of `HalOutputPinDriver`.
- There are no probe factories for the simulator display and input drivers.

## Planned

From the research, not built yet:

- real panel drivers (SPI ST7789/ILI9341, SSD1306, e-paper) and real input drivers
  (GPIO matrix, PS/2, I2C touch, rotary encoder);
- `embedded-graphics` `DrawTarget` support and a `Canvas`/framebuffer helper;
- a keymap/text layer that turns key events into TTY input;
- a compositor or windowing;
- DMA-driven blits and vsync via the tearing-effect pin.
