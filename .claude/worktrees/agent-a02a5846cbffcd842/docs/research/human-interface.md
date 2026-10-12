# Bismuth Human-Interface Subsystem: Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: two new device classes for Bismuth — **`Display`** (small SPI/I2C OLEDs, memory
> LCDs, parallel RGB TFTs, e-paper) and **`Input`** (keyboards, mice, touch, buttons,
> rotary encoders) — designed to *extend* the existing `Driver` / `Op` / `DeviceClass` /
> `Middleware` model rather than fork it, for Cortex-M / RISC-V MCUs with tens to hundreds
> of KB of RAM, static allocation, an MPU but no MMU, and `#![deny(unsafe_code)]` outside a
> tiny TCB. It studies Linux (fbdev, DRM/KMS, evdev, USB HID), the Rust embedded ecosystem
> (`embedded-graphics`, `embedded-hal`), and MCU stacks (Zephyr, LVGL), then recommends a
> concrete design, new ioctl numbers, how reads deliver frames/events, a sim-testable
> phased plan, and what to leave out.

---

## 0. TL;DR

- **No parallel universe, and no new `Op`.** Unlike `net` (whose packet data plane justified
  its own subsystem), displays and input fit the existing request pipeline directly. A
  display is a `Write`-target with ioctls; an input device is a `Read`-source of events with
  ioctls. Both are ordinary [`Driver`]s of a new [`DeviceClass`], so they get `/dev/<name>`,
  the POSIX/embedded-hal shims, power management, rights checks, and the global → user →
  driver [`Middleware`] chain for free. We add `DeviceClass::Display` and `DeviceClass::Input`
  and two ioctl pages; we do **not** add an `Op::Blit` variant (it would touch the core,
  `OpKind`, every middleware, and `rights_for`).
- **Blit = address-window ioctls + `Write`.** This is exactly how real controllers work
  (SSD1306/ST7789 `CASET`/`RASET` then `RAMWR`). `DISPLAY_SET_COL` + `DISPLAY_SET_ROW` define
  the damage rectangle; `Op::Write` streams pixels into it; `DISPLAY_FLUSH` pushes it to the
  glass. Each ioctl argument is a packed `u32` that fits a 32-bit `usize`.
- **Damage/dirty-rect model is the core bandwidth lever.** On an SPI OLED the cost *is* the
  bytes clocked out, so the whole API is organized around writing the smallest rectangle that
  changed. A `damage-coalesce` middleware merges adjacent small rects; `Stats` already counts
  `bytes_out`, which is precisely "bytes pushed to the panel".
- **Buffering: prefer none.** The tiny-RAM sweet spot is a *bus-attached* panel whose own
  GDDRAM is the framebuffer (SSD1306, ST7789) — Bismuth keeps no local copy. A 1bpp shadow
  (128×64 = 1 KiB) is cheap when readback/diffing is needed (e-paper). Full double-buffering
  (RGB565 240×240 = 2×112.5 KiB) is only for parts with external PSRAM/SDRAM.
- **Two display driver tiers, mirroring `net`'s `NetDevice`/`FrameDevice` split.** *Bus
  displays* are clients of an existing SPI/I2C `Device` (like `Tmp102` is an `I2cTarget`) and
  touch no `Mmio`. *Scanout displays* (parallel RGB via an LTDC-class controller) own an
  `Mmio` register window plus a framebuffer that lives in a DMA-capable, non-cacheable linker
  section as a static `Pool` block; cache clean/invalidate is centralized, gated by a caps flag.
- **Input: an evdev-style event model, delivered like sensor samples.** `InputEvent { tick,
  kind, code, value }` is a fixed 16-byte record; a `Read` fills the caller's buffer with whole
  events the way a `Sensor` read fills LE `i32`s. A bounded `Queue<InputEvent, N>` per device
  buffers between the producer (ISR/scan/poll) and the consumer; reads block/poll exactly like
  the `pipe` and `pl011` drivers.
- **Raw-hardware → events is driver work; translation is middleware.** GPIO matrix scan +
  per-key debounce (reusing the `Debounce` idea), PS/2 and USB-HID boot-protocol decoders, I2C
  touch controllers, and quadrature encoders each live in a driver that pushes events. A
  `Keymap` middleware rewrites `Key` codes on `Read` (post-processing like `Calibrate`); an
  `Autorepeat` middleware synthesizes repeats.
- **Consumption: blocking read, poll, or an event ring.** `INPUT_EVENTS_AVAILABLE` is the
  `poll()` analogue; an `EventRing` (a `Queue<InputEvent,N>` + `EventFlags`) is the
  readiness/zero-copy fan-out path, reusing the kernel's existing `EventFlags` the way `net`
  reuses them for socket readiness. A `TtyBridge` turns a keyboard into a byte stream feeding
  the existing `console`/`Pipe`.
- **Ecosystem compat as a thin layer, like the embedded-hal adapters.** An
  `embedded-graphics` `DrawTarget` adapter over the `Display` class unlocks the entire Rust
  graphics ecosystem (fonts, shapes, images); a tiny immediate-mode `Canvas` (lines/rects/1bpp
  text/bitmaps) covers the no-dependency case.
- **Do not build:** a GPU/3D or shader path, DRM/KMS modesetting, multi-plane compositing with
  alpha, framebuffer `mmap` to "userspace", EV_FF force-feedback / `uinput`, complex text
  shaping, runtime-loadable keymap bytecode, or a generic 2D-accel abstraction beyond
  fill/copy. A single surface per display and const scancode tables are enough.

---

## 1. What desktop / server systems do, and what to borrow

### 1.1 Linux framebuffer (fbdev) and DRM/KMS

The legacy **fbdev** API ([fb/api.rst][fbdev]) is a single linear framebuffer at `/dev/fbN`
with three ioctls that carry everything: `FBIOGET_VSCREENINFO` / `FBIOPUT_VSCREENINFO` (a
`fb_var_screeninfo`: `xres`, `yres`, `bits_per_pixel`, the per-channel `fb_bitfield`s,
`rotate`), `FBIOGET_FSCREENINFO` (`fb_fix_screeninfo`: physical address, `line_length`), plus
`FBIOPAN_DISPLAY` (pan/page-flip) and `FBIO_WAITFORVSYNC`. Userspace `mmap`s the buffer and
writes pixels directly; `FBIOPUTCMAP` handles palettes. There is no damage concept — the whole
buffer is scanned out continuously.

**DRM/KMS** ([drm-kms][drmkms]) is the modern stack: *framebuffers* (a buffer + pixel format
via `DRM_FORMAT_*` fourcc), *planes* (primary/overlay/cursor), *CRTCs* (scanout engines), and
*connectors/encoders* (the physical output). Atomic modesetting commits a whole display state
at once. Crucially for us, DRM added **`DRM_IOCTL_MODE_DIRTYFB`** / damage clips
(`drm_mode_fb_dirty_cmd`) *specifically* for "self-refresh" panels (DSI command-mode, USB
displays) where the controller holds its own memory and you only push the changed rectangle —
exactly the SPI-OLED situation at MCU scale.

**What to borrow:** fbdev's "geometry + format + one simple ioctl surface" ergonomics, and
DRM's **damage-clip** idea (push only dirty rectangles to self-refresh panels). **What to cut:**
planes/CRTCs/connectors/atomic modeset, fourcc's hundreds of formats, `mmap`, palettes beyond a
trivial mono/gray case, and page-flip/pan (no scanout to pan on bus displays).

### 1.2 Linux input: evdev and the input core

The Linux input subsystem ([input/input.rst][linput]) normalizes every device to a stream of
`struct input_event { time, type, code, value }` read from `/dev/input/eventN`. Types are
`EV_SYN`, `EV_KEY`, `EV_REL`, `EV_ABS`, `EV_MSC`, `EV_LED`, `EV_FF`; codes come from the shared
`input-event-codes.h` (`KEY_*`, `BTN_*`, `REL_X/Y/WHEEL`, `ABS_X/Y/PRESSURE/MT_*`). A
`EV_SYN`/`SYN_REPORT` terminates each atomic packet (e.g. a touch sample is `ABS_X`, `ABS_Y`,
`ABS_PRESSURE`, `SYN_REPORT`). `EVIOCGABS` reports an axis's min/max/flat/fuzz for calibration;
`EVIOCGRAB` grabs a device exclusively; keymaps live in-kernel (`EVIOCGKEYCODE`).

**What to borrow:** the entire `{type, code, value}` + `SYN_REPORT` model — it is compact,
self-describing, and already the lingua franca of Rust input crates. **What to cut:** multitouch
protocol B slots, `EV_FF`, `uinput`, and the full `input-event-codes.h` (keep a small const
subset).

### 1.3 USB HID and PS/2

USB **HID** ([HID 1.11][hid]) describes devices with a *report descriptor* (a byte program of
usages and bit-field sizes) that a host parses to lay out variable report formats. That parser
is large; the saving grace for MCUs is **boot protocol**: a fixed 8-byte keyboard report
(`[modifiers, reserved, keycode[6]]`, usages from HID Usage Table "Keyboard/Keypad" page 0x07)
and a fixed 3–4-byte mouse report (`[buttons, dx, dy, wheel]`). **PS/2** is a scancode serial
protocol (set 2) with a small decode state machine (`0xF0` = break, `0xE0` = extended).

**What to borrow:** decode **boot-protocol** HID reports and PS/2 set-2 directly into
`InputEvent`s; adopt HID Usage IDs as the native keycode space (they map cleanly and are what a
USB stack already produces). **What to cut:** a general HID report-descriptor parser (optional,
far-future), HID++/vendor protocols, and USB enumeration itself (that belongs to a future USB
stack, not the input class).

---

## 2. What the MCU / embedded world does

### 2.1 `embedded-graphics` and the `DrawTarget` trait (Rust)

`embedded-graphics` ([crate][eg]) is the de-facto Rust embedded 2D library. Drivers implement
**`DrawTarget`** (`draw_iter(&mut self, pixels: impl Iterator<Item = Pixel<Color>>)`,
`fill_contiguous`, `fill_solid`, `clear`) plus `OriginDimensions`. The library ships primitives,
mono/bitmap fonts, images, and a `Framebuffer` type; the color types (`BinaryColor`, `Gray4`,
`Rgb565`, `Rgb888`) match exactly the formats small panels use. Hundreds of panel drivers
(`ssd1306`, `st7789`, `ssd1680` e-paper, `embedded-graphics-framebuf`) and UI crates build on
it. This is the single most important compatibility target — the analogue of `embedded-nal` for
`net`.

**Lesson:** make `DrawTarget` a thin adapter over the Bismuth `Display` class (batch the pixel
iterator into a damage rect, then window + `Write` + flush), exactly as the driver framework's
header diagram shows `embedded-hal` as a compatibility layer over `Device`.

### 2.2 `embedded-hal` display/input conventions

There is no single HAL display trait (the ecosystem settled on `DrawTarget`), but input-ish
peripherals use small `embedded-hal` traits: `InputPin`/`OutputPin` (buttons, matrix scan),
and community crates like `keypad` (matrix), `rotary-encoder-hal` (quadrature state machine),
and `debouncr`. Touch controllers (`ft6x06`, `cst816s`, `xpt2046`) are `embedded-hal` I2C/SPI
clients.

**Lesson:** Bismuth's input *drivers* are clients of the existing `Gpio`/`I2cBus`/`Serial`
`Device` wrappers — a matrix keypad opens a `Gpio` device and scans it; a touch driver opens an
`I2cBus` device and reads registers — precisely how `Tmp102` sits on `SimI2c`.

### 2.3 LVGL and Zephyr

**LVGL** is a C UI library ported widely to MCUs; its porting layer is one callback,
`flush_cb(area, color_p)` — "here is a dirty rectangle and its pixels, push them" — plus an
input `read_cb` returning `{point, state}` or key codes. It uses small *draw buffers* (one or
two partial-screen tiles), **not** a full framebuffer, and renders dirty areas into a tile then
flushes. This is the canonical tiny-RAM rendering model and validates the damage-rect design.

**Zephyr** splits the two concerns we do: a **display API**
([zephyr display][zdisplay]) with `display_write(dev, x, y, desc, buf)`,
`display_set_pixel_format`, `display_blanking_on/off`, `display_get_capabilities`
(`screen_info`, supported formats, `PIXEL_FORMAT_MONO01`/`RGB_565`/...), and a separate
**input subsystem** ([zephyr input][zinput]) that emits `struct input_event {type, code, value,
sync}` through a callback bus — essentially evdev in-kernel, which is where we land too.

**Lessons:** `display_write(x, y, w×h desc, buf)` ≈ our window-ioctls + `Write`;
`get_capabilities` ≈ `DISPLAY_GET_CAPS`; the input-event struct ≈ our `InputEvent`; "draw buffer
= one or two tiles" is the default, not a framebuffer.

### 2.4 QEMU `lm3s6965evb` (this board directory)

The board in the working directory, **`qemu-lm3s6965`**, is a QEMU Stellaris model that
*already emulates* an **SSD0323 OLED** (128×64, 4-bit grayscale) over SSI/SPI plus a GPIO
button matrix ([QEMU Stellaris][qemustellaris]). That gives Phase-3 real-driver work a
zero-hardware, in-tree QEMU target for *both* classes, alongside the pure host mocks.

---

## 3. Design: the `Display` class

### 3.0 Core decision — reuse `Op`, add a class

```rust
// src/driver/mod.rs
pub enum DeviceClass {
    Char, Gpio, I2c, Spi, Sensor, Block, Net,
    Display,   // NEW: a pixel surface (framebuffer / panel)
    Input,     // NEW: a source of InputEvents (§4)
    Other,
}
```

A display is driven entirely with the existing [`Op`] set:

| intent | mechanism |
|---|---|
| query geometry / format / caps | `Op::Ioctl` → `Ok(value)` |
| set the damage window | `Op::Ioctl { DISPLAY_SET_COL / SET_ROW }` |
| stream pixels into the window | `Op::Write(pixels)` |
| push the window to the glass | `Op::Ioctl { DISPLAY_FLUSH }` |
| backlight / blank / orientation | `Op::Ioctl` |
| wait for tear-free moment | `Op::Ioctl { DISPLAY_WAIT_VSYNC }` (blocks) |
| power down the panel | `Op::Power(Suspended)` |
| read back pixels (optional) | `Op::Read(buf)` from a shadow/controller |

This means **no change to `Op`, `OpKind`, `Next`, `rights_for`, or any existing middleware** —
rotation, stats, tracing, access policy, power-gating all apply unchanged. It also keeps the
blit model identical to real controller silicon (set an address window, then write RAM).

The device appears as `/dev/fb0`, `/dev/epd0`, etc.

### 3.1 ioctl page (0x06xx) and required rights

Following the `0x0Nxx` scheme in `class.rs` (net ended at `0x05xx`):

```rust
// src/driver/class.rs — pub mod ioctl
// display (0x06xx)
pub const DISPLAY_GET_GEOMETRY:    u32 = 0x0601; // -> width:16 | height:16
pub const DISPLAY_GET_FORMAT:      u32 = 0x0602; // -> PixelFormat discriminant
pub const DISPLAY_GET_CAPS:        u32 = 0x0603; // -> DisplayCaps bitmask
pub const DISPLAY_SET_COL:         u32 = 0x0604; // arg = x0:16 | x1:16  (inclusive window)
pub const DISPLAY_SET_ROW:         u32 = 0x0605; // arg = y0:16 | y1:16
pub const DISPLAY_FLUSH:           u32 = 0x0606; // arg = RefreshMode (full/partial/fast)
pub const DISPLAY_WAIT_VSYNC:      u32 = 0x0607; // blocks until TE / BUSY-clear; -> 0
pub const DISPLAY_SET_BACKLIGHT:   u32 = 0x0608; // arg = brightness 0..=255
pub const DISPLAY_BLANK:           u32 = 0x0609; // arg != 0 blanks (pixels off, state kept)
pub const DISPLAY_SET_ORIENTATION: u32 = 0x060A; // arg = rotation(0/90/180/270) | flip bits
pub const DISPLAY_SET_FORMAT:      u32 = 0x060B; // arg = PixelFormat (if panel supports several)
```

`required_right` (operation/queries → `CONTROL`; anything that reconfigures geometry/format/
orientation → `CONFIG`). Note `SET_COL`/`SET_ROW`/`FLUSH`/`WAIT_VSYNC`/`BLANK`/`BACKLIGHT` are
*operational* (they draw frames), so they stay `CONTROL`; only `SET_FORMAT` and
`SET_ORIENTATION` need `CONFIG`:

```rust
pub const fn required_right(cmd: u32) -> Rights {
    match cmd {
        // ... existing arms ...
        DISPLAY_GET_GEOMETRY | DISPLAY_GET_FORMAT | DISPLAY_GET_CAPS | DISPLAY_SET_COL
        | DISPLAY_SET_ROW | DISPLAY_FLUSH | DISPLAY_WAIT_VSYNC | DISPLAY_SET_BACKLIGHT
        | DISPLAY_BLANK => Rights::CONTROL,
        DISPLAY_SET_ORIENTATION | DISPLAY_SET_FORMAT => Rights::CONFIG,
        // input arms (§4.3) ...
        _ => Rights::CONFIG,
    }
}
```

`Op::Write` to the surface is gated by `Rights::WRITE` and `Op::Read` by `Rights::READ`
through the existing `rights_for`, so a logging dashboard can be granted a write-only display
handle, and a frame-grabber a read-only one, with no new machinery.

> Why window-as-two-ioctls instead of a packed rect or a struct pointer? A rect is 4×`u16`
> = 64 bits and will not fit a 32-bit `usize`; passing `&Rect` as `arg` drags in `usemem`
> pointer validation for isolated domains on the hottest path. Two 32-bit ioctls each fit
> `usize` cleanly, carry an inclusive `[start,end]` per axis (`x0..=x1`, `y0..=y1`), and are
> literally the `CASET`/`RASET` register pair. The typed wrapper (§3.8) hides the split.

### 3.2 Pixel formats and geometry

```rust
// src/driver/class.rs (or a small src/display/mod.rs if it grows)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// 1 bpp. Packing matters: SSD1306 is column-paged (8 vertical px per byte),
    /// e-paper is row-packed (8 horizontal px, MSB-left). The variant records which.
    Mono1 { page_major: bool },
    /// 4 bpp grayscale (SSD0323, some memory LCDs / e-paper), 2 px per byte.
    Gray4,
    /// 16 bpp, 5-6-5, big-endian on the wire (ST7789, ILI9341, most color TFT).
    Rgb565,
    /// 24 bpp (rare on MCUs; parallel RGB panels).
    Rgb888,
}

impl PixelFormat {
    pub const fn bits_per_pixel(self) -> u8 { /* 1, 4, 16, 24 */ }
    /// Bytes needed for a `w × h` region in this format (rounding packing).
    pub const fn region_bytes(self, w: u16, h: u16) -> usize { /* ... */ }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rect { pub x: u16, pub y: u16, pub w: u16, pub h: u16 }

#[derive(Copy, Clone, Debug)]
pub struct DisplayCaps(pub u32);
impl DisplayCaps {
    pub const PARTIAL_REFRESH: Self = Self(1 << 0); // e-paper fast window update
    pub const BACKLIGHT:       Self = Self(1 << 1);
    pub const VSYNC_TE:        Self = Self(1 << 2); // tearing-effect / TE line present
    pub const HW_FILL:         Self = Self(1 << 3); // controller/DMA2D solid fill
    pub const HW_COPY:         Self = Self(1 << 4); // DMA2D blit
    pub const READBACK:        Self = Self(1 << 5); // Op::Read returns pixels
    pub const SELF_REFRESH:    Self = Self(1 << 6); // panel holds its own RAM (bus displays)
}
```

The driver reports its canonical in-memory layout. The `Write` payload is pixels in that
format, laid out row-major within the currently-set window (SSD1306 column-paging is handled
*inside* its driver so callers always see a normal rect). `DISPLAY_GET_GEOMETRY` returns post-
orientation dimensions.

### 3.3 Damage / dirty-rect model (the bandwidth lever)

On a bus display the only cost that matters is bytes clocked over SPI/I2C, so the API is built
around writing the smallest changed rectangle:

```
set window (x0..x1, y0..y1)   // DISPLAY_SET_COL + DISPLAY_SET_ROW  (= CASET/RASET)
write pixels for that window  // Op::Write  (= RAMWR)
flush                         // DISPLAY_FLUSH, only needed for buffered/e-paper tiers
```

- The window **is** the damage rect; there is no separate dirty-tracking structure for the
  common direct-write tier. The driver validates that `Write` length matches
  `format.region_bytes(w, h)` for the current window and `Err(Error::Invalid)` otherwise.
- A reusable **`DamageCoalesce`** middleware (§3.7) batches a run of tiny windowed writes that
  touch adjacent rows into one larger window+write when that reduces per-command overhead
  (each `CASET`/`RASET` pair is ~6 bytes of overhead on SPI).
- For buffered tiers (a RAM shadow or e-paper), writes accumulate into the shadow and mark a
  union dirty rect; `DISPLAY_FLUSH` pushes just that rect and clears it. This matches DRM's
  `DIRTYFB` and LVGL's `flush_cb`.

### 3.4 Tear-free output (`WAIT_VSYNC`)

Bus displays usually expose a **Tearing-Effect (TE)** GPIO that pulses at the panel's internal
refresh; `DISPLAY_WAIT_VSYNC` blocks (via `block_on`, like `pl011` read) until TE, so a caller
can write between refreshes. Scanout controllers raise a line-/frame-sync IRQ; e-paper exposes
a `BUSY` line, and `WAIT_VSYNC` waits for it to clear (the panel is mid-refresh). The ioctl
returns `Ok(0)` and honors `req.timeout`, so `FLAG_NONBLOCK` turns it into a poll.

### 3.5 Buffering tradeoffs on tiny RAM

| strategy | RAM | when | notes |
|---|---|---|---|
| **No local buffer (direct)** | 0 | bus OLED/TFT whose GDDRAM is the framebuffer | the default; damage-write straight to the panel. SSD1306, ST7789. |
| **1 bpp / 4 bpp shadow** | 1–8 KiB | need readback, diffing, or e-paper | enables partial-refresh diffing and `Op::Read`; `128×64` mono = 1 KiB. |
| **Single full framebuffer** | 28–150 KiB | RGB565 on parts with spare SRAM | one surface; damage-flush the dirty rect. No page flip. |
| **Double buffer** | 2× above | only with PSRAM/SDRAM (e.g. STM32H7 + SDRAM) | tear-free page flip on scanout controllers; never on bare KB-scale SRAM. |
| **Tile / draw-buffer** | 2–16 KiB | rendering complex scenes to a small panel | LVGL model: render one dirty tile, flush, reuse. The immediate-mode `Canvas` (§3.9) uses this. |

Recommendation: default to **direct** for bus panels and **tile** for software rendering; make
a full framebuffer opt-in via a board param; reserve double-buffering for external-RAM parts.

### 3.6 Two driver tiers and the `Mmio` / pool / DMA interaction

Mirroring `net`'s `NetDevice` (ring) vs `FrameDevice` (simple) split:

**Tier A — bus-attached displays** (SSD1306, SSD0323, ST7789, SHARP memory LCD, SSD1680
e-paper). The driver holds a `Device` handle to an SPI or I2C bus (opened with the existing
`class::I2cBus` / an SPI analogue) and a few GPIOs (DC, RESET, CS, BUSY/TE) via a `Gpio`
device. It touches **no `Mmio`** — all hardware access goes through other devices, so it stays
fully in safe Rust and composes with those devices' own middleware (rate-limit the bus, etc.).
This is the `Tmp102`-on-`SimI2c` pattern and is the entire tiny-MCU story.

```rust
// Sketch: a bus-attached panel driver is a Driver that *owns handles* to buses.
pub struct Ssd1306 {
    bus: IrqCell<Option<Device>>,   // the I2C/SPI controller device
    dc: IrqCell<Option<Device>>,    // GPIO for data/command (SPI only)
    addr: u8, w: u16, h: u16,
    win: IrqCell<Rect>,             // current address window
}
impl Driver for Ssd1306 {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "ssd1306", class: DeviceClass::Display, version: (1,0,0),
                     compatible: &["solomon,ssd1306"] }
    }
    fn middleware(&self) -> &'static [&'static dyn Middleware] { &MIDDLEWARE } // stats, etc.
    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        match &mut req.op {
            Op::Write(px) => { /* RAMWR within self.win, paging-corrected */ Ok(px.len()) }
            Op::Ioctl { cmd: ioctl::DISPLAY_SET_COL, arg } => { /* record x0..x1 */ Ok(0) }
            Op::Ioctl { cmd: ioctl::DISPLAY_GET_GEOMETRY, .. } =>
                Ok((self.w as usize) | ((self.h as usize) << 16)),
            // ...
            _ => Err(Error::Unsupported),
        }
    }
}
```

**Tier B — scanout / memory-mapped controllers** (STM32 LTDC + DMA2D, parallel RGB). The
driver owns an `Mmio` register window (the TCB boundary: `unsafe` only at `Mmio::new`, every
access after is bounds/alignment-checked) **and** a framebuffer that is *RAM, not MMIO*:

- The framebuffer is a static `Pool`/buffer placed by the linker in a **DMA-capable,
  non-cacheable** section (e.g. STM32H7 D2 SRAM behind an MPU "device/non-cacheable" region).
  The `DeviceDesc` carries the `Mmio` window plus `params` (`("width",240)`, `("height",240)`,
  `("format", …)`, `("fb_addr", …)`), consumed by the factory like the existing drivers read
  `baud`/`channels`.
- **Cache maintenance lives in one place** — a `display::dma` helper calls clean/invalidate
  around `DISPLAY_FLUSH`/DMA2D ops, gated by a `DisplayCaps::COHERENT`-style flag, so no driver
  open-codes cache ops (the same discipline the net doc applies to RX/TX rings).
- `DISPLAY_FLUSH` kicks DMA2D to blit the dirty rect from the framebuffer to the panel region;
  `HW_FILL`/`HW_COPY` caps let the typed API (`fill_solid`) offload to DMA2D, with a software
  fallback when absent (same "advertise caps, fall back in core" rule as `NetCaps`).

### 3.7 E-paper partial refresh

E-paper needs occasional full refreshes (clear ghosting) but supports fast partial-window
updates. Model it on the shadow tier: keep a 1bpp *current* buffer and a *previous* buffer;
`DISPLAY_FLUSH { RefreshMode::Partial }` loads the fast LUT and pushes only the union dirty
rect; a driver-held counter forces `RefreshMode::Full` every *K* partials (configurable board
param). `WAIT_VSYNC` waits on `BUSY`. `Gray4`/multi-LUT grayscale is a driver concern hidden
behind the format.

### 3.8 Middleware (the composable layers displays get for free)

All of these are ordinary `Middleware` on the global/user/driver chain:

- **`Rotate` / `Flip`** — a reusable layer that remaps coordinates. On `DISPLAY_SET_COL`/
  `SET_ROW` it rewrites the window for the target orientation; for `Write` it transforms the
  pixel stream. 0°/180° are O(1) (byte-run reversal + window remap); 90°/270° require a tile
  transpose, so the layer carries a small scratch and is documented as "cheap for 0/180, needs
  a tile buffer for 90/270." This is the direct analogue of the net `Rotate`-style transforms
  and keeps orientation out of every driver.

  ```rust
  pub struct Rotate { quarter_turns: u8 }           // 0..=3
  impl Middleware for Rotate {
      fn name(&self) -> &'static str { "rotate" }
      fn call(&self, _c: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
          match &req.op {
              Op::Ioctl { cmd: ioctl::DISPLAY_SET_COL, .. } => { /* remap, re-emit */ }
              Op::Write(_) => { /* transform window pixels, then next.run */ }
              _ => {}
          }
          next.run(req)
      }
  }
  ```

- **`Stats`** — already exists and already counts `bytes_out` on `Write`; attached to a display
  it *is* the "bytes pushed to the panel" counter the brief asks for, plus write/ioctl counts
  and max latency. No new code.
- **`DamageCoalesce`** — merges adjacent small windowed writes into one (bandwidth).
- **`Gamma` / `Dither`** (optional) — map a richer caller format down to the panel format
  (e.g. dither RGB565 → Mono1), a post/pre-process layer like `Calibrate` for sensors.
- **`AccessPolicy::read_only()`** — already exists; makes a display write-only for an untrusted
  dashboard task, or read-only for a screenshotter.

### 3.9 Typed `Display` class wrapper

Matching the `Serial`/`Gpio`/`Sensor` wrappers in `class.rs`:

```rust
#[derive(Copy, Clone, Debug)]
pub struct Display(pub Device);

impl Display {
    pub fn open(name: &str) -> Result<Self, Error> {
        Ok(Display(expect(Device::find(name)?, DeviceClass::Display)?))
    }
    pub fn geometry(&self) -> Result<(u16, u16), Error> {
        let v = self.0.ioctl(ioctl::DISPLAY_GET_GEOMETRY, 0)?;
        Ok((v as u16, (v >> 16) as u16))
    }
    pub fn format(&self) -> Result<PixelFormat, Error> { /* decode discriminant */ }
    pub fn caps(&self) -> Result<DisplayCaps, Error> { /* ... */ }

    /// Set the address window, then stream `pixels` (len must match the window).
    pub fn blit(&self, r: Rect, pixels: &[u8]) -> Result<(), Error> {
        self.0.ioctl(ioctl::DISPLAY_SET_COL, (r.x as usize) | (((r.x + r.w - 1) as usize) << 16))?;
        self.0.ioctl(ioctl::DISPLAY_SET_ROW, (r.y as usize) | (((r.y + r.h - 1) as usize) << 16))?;
        self.0.write_all(pixels)
    }
    pub fn fill(&self, r: Rect, color: u32) -> Result<(), Error> { /* HW_FILL or sw loop */ }
    pub fn flush(&self, mode: RefreshMode) -> Result<(), Error> {
        self.0.ioctl(ioctl::DISPLAY_FLUSH, mode as usize).map(|_| ())
    }
    pub fn wait_vsync(&self, t: Timeout) -> Result<(), Error> {
        self.0.request(&mut Request::new(Op::Ioctl { cmd: ioctl::DISPLAY_WAIT_VSYNC, arg: 0 })
            .with_timeout(t)).map(|_| ())
    }
    pub fn set_backlight(&self, level: u8) -> Result<(), Error> {
        self.0.ioctl(ioctl::DISPLAY_SET_BACKLIGHT, level as usize).map(|_| ())
    }
    pub fn set_orientation(&self, o: Orientation) -> Result<(), Error> { /* CONFIG */ }
}
```

### 3.10 Immediate-mode `Canvas` and `embedded-graphics` compat

Two layers *above* the class (host-side libraries, not drivers), paralleling how `net` offers
both a native socket API and `embedded-nal`:

1. **Tiny immediate-mode `Canvas`** (no dependencies): draws into a small tile buffer and blits
   dirty tiles. Primitives: `hline`/`vline`/`line` (Bresenham), `rect`/`fill_rect`, `glyph`
   (1bpp fixed 6×8 font baked as a const table), `bitmap` (1bpp/`Gray4`/`Rgb565` blit). This
   covers status screens, meters, and the shell's TTY output without pulling a crate.

   ```rust
   pub struct Canvas<'a, const TILE: usize> { disp: &'a Display, buf: [u8; TILE], /* ... */ }
   impl<const TILE: usize> Canvas<'_, TILE> {
       pub fn text(&mut self, x: u16, y: u16, s: &str, fg: u32) -> Result<(), Error> { /* ... */ }
       pub fn fill_rect(&mut self, r: Rect, c: u32) { /* ... */ }
       pub fn present(&mut self) -> Result<(), Error> { /* blit dirty tiles */ }
   }
   ```

2. **`embedded-graphics` `DrawTarget` adapter** behind a cargo feature (`display-eg`), the way
   `embedded-hal` adapters wrap `Device`. It accumulates `draw_iter` pixels into a bounding
   damage rect (or per-tile), then `blit`s. This unlocks the whole ecosystem: `embedded-graphics`
   fonts/shapes/images and the panel-agnostic UI crates.

   ```rust
   #[cfg(feature = "display-eg")]
   pub struct EgTarget { disp: Display, /* color map, damage accumulator */ }
   #[cfg(feature = "display-eg")]
   impl embedded_graphics_core::draw_target::DrawTarget for EgTarget {
       type Color = embedded_graphics_core::pixelcolor::Rgb565;
       type Error = crate::Error;
       fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
           where I: IntoIterator<Item = embedded_graphics_core::Pixel<Self::Color>> { /* ... */ }
   }
   ```

---

## 4. Design: the `Input` class

### 4.0 Model

An input device is a `Read`-source of events plus ioctls, in `DeviceClass::Input`, exposed as
`/dev/input0` / `/dev/event0`. It reuses `Op` exactly:

| intent | mechanism |
|---|---|
| read the next events | `Op::Read(buf)` — buffer filled with whole `InputEvent` records |
| how many events are queued | `Op::Ioctl { INPUT_EVENTS_AVAILABLE }` (poll) |
| discard the queue | `Op::Ioctl { INPUT_FLUSH }` |
| axis calibration range | `Op::Ioctl { INPUT_GET_ABS_INFO }` |
| device id / caps | `Op::Ioctl { INPUT_GET_ID / INPUT_GET_CAPS }` |
| exclusive grab | `Op::Ioctl { INPUT_GRAB }` |
| autorepeat config | `Op::Ioctl { INPUT_SET_REPEAT }` |
| suspend the sensor | `Op::Power(Suspended)` |

### 4.1 Event encoding and how reads deliver events

```rust
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventKind { Syn = 0, Key = 1, Rel = 2, Abs = 3 }   // mirrors EV_SYN/KEY/REL/ABS

/// 16 bytes, naturally aligned; the on-wire layout is little-endian fields.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InputEvent {
    pub tick: u64,     // kernel ticks at sample time (crate::kernel::time::ticks())
    pub value: i32,    // Key: 1 down / 0 up / 2 repeat · Rel: delta · Abs: absolute
    pub code: u16,     // key / button / axis code (§4.6)
    pub kind: u8,      // EventKind
    pub _pad: u8,
}
pub const EVENT_BYTES: usize = 16;
```

A `Read` fills the caller buffer with whole 16-byte events, the exact pattern `Sensor::read`
uses for LE `i32`s: the driver writes `min(queued, buf.len() / 16)` events and returns the byte
count; the typed wrapper (§4.7) decodes. A packet of related events is terminated by a
`Syn`/`SYN_REPORT` so a touch sample (`Abs X`, `Abs Y`, `Abs PRESSURE`, `Syn`) is read
atomically, just like evdev.

Reads block/poll/time-out through the *same* `block_on` + `req.effective_timeout()` logic as
`pipe`/`pl011`, so `FLAG_NONBLOCK`, `read_timeout`, and `Timeout::Forever` all work unchanged.

### 4.2 ioctl page (0x07xx) and required rights

```rust
// input (0x07xx)
pub const INPUT_GET_CAPS:        u32 = 0x0701; // -> bitmask of EventKinds supported
pub const INPUT_EVENTS_AVAILABLE:u32 = 0x0702; // -> queued event count (poll)
pub const INPUT_FLUSH:           u32 = 0x0703; // discard queued events
pub const INPUT_GET_ID:          u32 = 0x0704; // -> bus:8|vendor:... packed id
pub const INPUT_GET_ABS_INFO:    u32 = 0x0705; // arg = axis code -> min:16|max:16
pub const INPUT_GRAB:            u32 = 0x0706; // arg != 0 grabs exclusively (EVIOCGRAB)
pub const INPUT_SET_REPEAT:      u32 = 0x0707; // arg = delay_ms:16 | rate_ms:16
```

`required_right`: queries + grab + flush are `CONTROL`; `SET_REPEAT` reconfigures the device, so
`CONFIG`:

```rust
INPUT_GET_CAPS | INPUT_EVENTS_AVAILABLE | INPUT_FLUSH | INPUT_GET_ID | INPUT_GET_ABS_INFO
| INPUT_GRAB => Rights::CONTROL,
INPUT_SET_REPEAT => Rights::CONFIG,
```

`Op::Read` of events needs `Rights::READ`, so an untrusted domain can be handed a read-only
input handle with no extra mechanism.

### 4.3 Bounded per-device event queue and consumption

The driver owns a bounded `Queue<InputEvent, N>` (the existing kernel FIFO, with blocking
`recv`/`try_recv` and overflow-returns-item semantics). Producers (`try_send` from ISR/scan/
poll) are interrupt-safe; the consumer `Read` drains it. Overflow policy = **drop newest and
count** (an `overruns` counter), so a stalled reader can never block the producer — the same
"drop rather than stall" rule `net`'s `Steer` uses for a full ring.

Three consumption styles, all built from existing primitives:

1. **Blocking read** — `Input::read(&mut [InputEvent], timeout)`; the common case.
2. **Poll** — `INPUT_EVENTS_AVAILABLE` then non-blocking reads; backs POSIX `poll()`/`select()`
   over input fds.
3. **Event ring with readiness** — an `EventRing` = `Queue<InputEvent,N>` + `EventFlags`
   (`EVENT_READY`), so one producer can fan out to several consumers and a task can
   `EventFlags::wait` on *any* of several input devices — the kqueue/`poll` analogue, reusing
   the identical `EventFlags` mechanism `net` uses for socket readiness. This is the
   "NetRing-style" path for input; events are 16 B so there is no copy worth eliminating, and
   the value is decoupling and multi-wait, not zero-copy.

### 4.4 Turning raw hardware into events

Each of these is a `Driver` in `DeviceClass::Input` that fills its event queue; several are
*clients of existing device classes*, so they are sim-testable today:

- **GPIO matrix keyboard** — opens a `Gpio` device, drives column outputs, reads row inputs on
  a timer tick, and emits `Key` down/up events. Per-key debounce reuses the `Debounce`
  *technique* (report a change only after it is stable for *N* ticks); either by scanning the
  already-debounced `SimGpio`/GPIO device (whose built-in `Debounce` middleware stabilizes the
  port) or via a small per-key `KeyDebounce` layer on the input chain. Matrix ghosting
  (2-key-rollover) is masked in the scan.
- **Single buttons / GPIO keys** — trivial case of the above (1×N), one `Key` event per edge.
- **Rotary / quadrature encoder** — two GPIO lines fed through the standard 16-entry Gray-code
  transition table into `Rel`/`REL_WHEEL` deltas; an optional push switch is a `Key`/`BTN_*`.
- **PS/2 keyboard/mouse** — a byte stream from a `Serial`-like device run through a set-2
  scancode state machine (`0xF0` break, `0xE0` extended) → `Key` events; mouse packets →
  `Rel`/`BTN_*`.
- **USB-HID boot protocol** — decode the fixed 8-byte keyboard report (diff against the previous
  report to synthesize down/up for the 6-key rollover array + modifier byte) and the 3–4-byte
  mouse report (`buttons`, `dx`, `dy`, `wheel`). Keycodes are HID Usage IDs. (The USB transport
  itself is a future stack; the decoder is just a function over report bytes, unit-testable in
  isolation.)
- **I2C capacitive touch** (FT6x06, CST816, GT911) — opens an `I2cBus` device, reads the
  touch registers on a data-ready GPIO IRQ, and emits `Abs X`/`Abs Y`/`Abs PRESSURE` + `Syn`.
  Calibration min/max is reported via `INPUT_GET_ABS_INFO`. This is the `Tmp102`-on-`SimI2c`
  pattern, so a mock touch target drops straight into the existing `SimI2c` for tests.

### 4.5 Keymap / scancode translation and modifiers as middleware

Translation is post-processing on `Read`, exactly like `Calibrate`/`Deadband` transform sensor
samples after `next.run`:

```rust
pub struct Keymap { table: &'static [(u16, u16)] }  // (raw code -> keycode), or a dense LUT
impl Middleware for Keymap {
    fn name(&self) -> &'static str { "keymap" }
    fn call(&self, _c: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let n = next.run(req)?;
        if let Op::Read(buf) = &mut req.op {
            for ev in buf[..n].chunks_exact_mut(EVENT_BYTES) {
                // decode kind/code, if Key remap code via self.table, re-encode
            }
        }
        Ok(n)
    }
}
```

Related layers, all const-configured (no runtime bytecode): **`Modifiers`** (track Shift/Ctrl/
Alt/Meta, optionally fold into a composed keycode or a separate modifier field), **`Autorepeat`**
(a `Timer`-driven layer synthesizing `value == 2` repeats using `INPUT_SET_REPEAT`'s delay/rate),
and reusing **`RateLimit`** to cap event floods from a chattering source.

### 4.6 Keycode space

Adopt a small, const keycode module (evdev-shaped names, HID-compatible values where a USB
source already yields them): `key::{A..Z, 0..9, ENTER, ESC, SPACE, arrows, F1..}`,
`btn::{LEFT, RIGHT, MIDDLE, TOUCH}`, `rel::{X, Y, WHEEL}`, `abs::{X, Y, PRESSURE}`. Keep it a few
dozen constants, not the whole `input-event-codes.h`; grow on demand.

### 4.7 Typed `Input` wrapper and the TTY bridge

```rust
#[derive(Copy, Clone, Debug)]
pub struct Input(pub Device);
impl Input {
    pub fn open(name: &str) -> Result<Self, Error> {
        Ok(Input(expect(Device::find(name)?, DeviceClass::Input)?))
    }
    /// Read whole events into `out`; returns how many were filled.
    pub fn read(&self, out: &mut [InputEvent], t: Timeout) -> Result<usize, Error> {
        let mut raw = [0u8; EVENT_BYTES * 16];
        let want = out.len().min(16) * EVENT_BYTES;
        let n = self.0.read_timeout(&mut raw[..want], t)?;
        for (dst, src) in out.iter_mut().zip(raw[..n].chunks_exact(EVENT_BYTES)) {
            *dst = InputEvent::from_bytes(src);
        }
        Ok(n / EVENT_BYTES)
    }
    pub fn available(&self) -> Result<usize, Error> { self.0.ioctl(ioctl::INPUT_EVENTS_AVAILABLE, 0) }
    pub fn grab(&self, on: bool) -> Result<(), Error> { self.0.ioctl(ioctl::INPUT_GRAB, on as usize).map(|_| ()) }
}
```

**TTY bridge** — a `TtyBridge` task reads a keyboard `Input` device, applies `Keymap` +
`Modifiers`, turns `Key`-down events into bytes (with CR/LF and control chars), and writes them
into a `Pipe` that a shell reads as stdin — reusing the `pipe` driver and `pl011`'s
`LineDiscipline` style. This wires input into the existing `console.rs` without new concepts,
and lets the shell run over a keyboard+display pair as a local console.

---

## 5. Phased implementation plan (every phase sim-testable)

The host simulator (`sim::run_to_completion`) and the mock-device pattern (`SimGpio::drive_inputs`,
`SimSensor::force_counts`, `Loopback`/`Wire`) make both classes testable with zero hardware. QEMU
`lm3s6965evb` (SSD0323 OLED + button matrix) is the in-tree hardware-ish target.

| Phase | Deliverable | Testable in sim with |
|---|---|---|
| **P0: Types & classes** | `DeviceClass::{Display,Input}`; ioctl pages `0x06xx`/`0x07xx` + `required_right` arms; `PixelFormat`, `Rect`, `DisplayCaps`, `RefreshMode`, `Orientation`, `InputEvent`, `EventKind`, keycode module; typed `Display`/`Input` wrappers. | pure unit tests (packing, `region_bytes`, `required_right`, `InputEvent` round-trip). |
| **P1: Display core + MockDisplay** | A `MockDisplay<W,H,FMT>` driver holding a RAM framebuffer the test inspects (like `SimGpio`), implementing `SET_COL/SET_ROW/Write/FLUSH/GET_GEOMETRY/GET_CAPS`; window validation; the `Stats` + `Rotate`/`Flip` + `DamageCoalesce` middleware. | `tests/display.rs`: blit a rect, read back the mock's buffer, assert pixels, dirty region, and `Stats.bytes_out`; assert `Rotate(180)` and `Rotate(90)` correctness; assert a short/long `Write` is rejected. |
| **P2: Input core + MockInput** | A `MockInput` driver (tests inject raw key states / events like `drive_inputs`) with a bounded `Queue<InputEvent,N>`; blocking/nonblocking/poll `Read`; `Keymap` + `KeyDebounce` + `Autorepeat` middleware; `EventRing` + `EventFlags` readiness; overflow counting. | `tests/input.rs`: inject presses, assert decoded events + `Syn`; assert keymap translation; assert queue overflow drops newest and counts; assert `available()`/poll and `EventFlags` wait. |
| **P3: Real-ish drivers on existing buses** | SSD1306 (I2C/SPI mono) and ST7789 (SPI RGB565) as clients of `I2cBus`/SPI `Device`; a GPIO matrix keypad + quadrature encoder over `SimGpio`; an I2C touch driver over `SimI2c` with a mock `FtTouch` `I2cTarget`; `probe_all` factories + `compatible` strings. | drive them over `SimI2c`/`SimGpio` in sim; assert the exact byte stream reaches a mock bus target and that injected touch registers yield `Abs` events. QEMU SSD0323 OLED for an end-to-end check. |
| **P4: Rendering compat** | immediate-mode `Canvas` (lines/rects/1bpp font/bitmaps, tile-flush) + `embedded-graphics` `DrawTarget` adapter behind a feature. | draw text/shapes to `MockDisplay`, assert the resulting framebuffer bytes; property-test `Canvas` vs `embedded-graphics` on a shared scene. |
| **P5: TTY bridge + poll/select** | `TtyBridge` (keyboard `Input` → `Keymap`/`Modifiers` → `Pipe` → `console`); POSIX `poll()`/`select()` over display/input fds; `INPUT_GET_ABS_INFO` calibration path. | sim: inject key events, assert the shell/pipe receives the right bytes; assert multi-device `poll` wakes on the ready one. |
| **P6: Scanout / DMA + e-paper** | Tier-B LTDC/DMA2D-class driver with an `Mmio` window + framebuffer in a DMA/non-cacheable pool section + centralized cache maintenance + `HW_FILL`/`HW_COPY` with software fallback; SSD1680 e-paper partial/full refresh with the previous-frame diff + forced-full counter. | a `MockScanout` exposing a fake `Mmio` (host-backed) + framebuffer so the DMA/flush/dirty-rect and fallback logic run in sim; e-paper refresh-mode selection and forced-full cadence unit-tested. |

Throughout: host `cargo test` with mocks + property tests (format packing, rotation
invertibility, keymap totality, queue overflow), QEMU `lm3s6965evb` for the OLED/buttons, and
pool-exhaustion / reader-stall tests mirroring the net flood tests.

---

## 6. What NOT to build (and why)

| Feature | Origin | Why not for Bismuth |
|---|---|---|
| GPU / 3D / shader pipeline | desktop GPUs | No GPU; MCUs do 2D blits at most (DMA2D fill/copy). |
| DRM/KMS modeset: planes, CRTCs, connectors, atomic commit | Linux DRM | One panel, one surface, fixed timing. The whole object graph is dead weight. |
| Multi-plane / overlay compositing with alpha | DRM / mobile SoCs | No compositor; draw order is the app's job. At most one cursor sprite, and only if a panel has hardware for it. |
| Framebuffer `mmap` to "userspace" | fbdev | No MMU. A single address space already shares the buffer; isolation uses handle rights + MPU windows, like `NetRing` lending. |
| `fb_bitfield`/fourcc format zoo, palettes | fbdev/DRM | Four formats (`Mono1`, `Gray4`, `RGB565`, `RGB888`) cover every MCU panel. |
| Page-flip / pan-display / VRR | fbdev/DRM | No spare framebuffer to flip on KB-scale SRAM; damage-flush instead. |
| Full HID report-descriptor parser, HID++ | USB HID | Large parser; boot protocol + fixed decoders suffice. Make a descriptor parser a far-future option. |
| Multitouch protocol B (slots), `EV_FF` force feedback, `uinput` | evdev | Rare on edge IoT; single-touch `Abs` + `SYN` is enough. |
| Full `input-event-codes.h`, in-kernel keymap editing ioctls | evdev | Keep a few dozen const codes and const keymaps; no runtime keymap bytecode. |
| Complex text shaping / Unicode / large vector fonts | desktop | 1bpp bitmap fonts via `embedded-graphics`; shaping is an app/library concern. |
| Generic 2D-accel abstraction beyond fill/copy | DRM / Vivante | Advertise `HW_FILL`/`HW_COPY` caps with software fallback; nothing larger. |
| A new `Op::Blit` variant | — | Would touch the core, `OpKind`, `rights_for`, and every middleware. Window-ioctls + `Write` is faithful to both the model and real silicon. |
| A separate display/input "subsystem" like `net` | this repo | Justified for packets (high-rate batched data plane); unjustified here — the request pipeline fits directly. |

---

## 7. Summary table

| Concern | Display | Input |
|---|---|---|
| `DeviceClass` | `Display` | `Input` |
| `/dev` node | `/dev/fb0`, `/dev/epd0` | `/dev/input0`, `/dev/event0` |
| ioctl page | `0x06xx` | `0x07xx` |
| primary data op | `Op::Write` (pixels into the set window) | `Op::Read` (whole `InputEvent` records) |
| "address window" | `DISPLAY_SET_COL` + `DISPLAY_SET_ROW` (= `CASET`/`RASET`) | n/a |
| push / commit | `DISPLAY_FLUSH` (buffered / e-paper tiers) | `Syn`/`SYN_REPORT` terminates a packet |
| readiness / poll | `DISPLAY_WAIT_VSYNC` (TE/BUSY) | `INPUT_EVENTS_AVAILABLE` + `EventFlags` |
| reconfigure (`CONFIG`) | `SET_ORIENTATION`, `SET_FORMAT` | `SET_REPEAT` |
| buffering default | none (panel GDDRAM is the buffer); shadow/full/double opt-in | bounded `Queue<InputEvent,N>`, drop-newest on overflow |
| driver tiers | bus-attached (SPI/I2C client) · scanout (`Mmio` + DMA framebuffer) | matrix/GPIO · PS/2 · USB-HID boot · I2C touch · encoder |
| reusable middleware | `Stats` (bytes pushed), `Rotate`/`Flip`, `DamageCoalesce`, `Gamma`/`Dither`, `AccessPolicy` | `Keymap`, `Modifiers`, `Autorepeat`, `KeyDebounce`, `RateLimit` |
| ecosystem compat | `embedded-graphics` `DrawTarget`; tiny `Canvas` | evdev-shaped events; HID Usage keycodes; `TtyBridge` → `console` |
| mock for sim | `MockDisplay` (inspectable RAM framebuffer) | `MockInput` (inject key states/events) |
| DMA / `Mmio` | registers via `Mmio` (TCB); framebuffer in DMA/non-cacheable pool section; cache maint. centralized | none (producers are ISR/scan/poll into the queue) |

---

## 8. References

**Linux**
- [fbdev]: Linux framebuffer API. https://docs.kernel.org/fb/api.html
- [drmkms]: Linux DRM/KMS (planes, CRTCs, atomic, DIRTYFB damage). https://docs.kernel.org/gpu/drm-kms.html
- DRM framebuffer damage clips. https://docs.kernel.org/gpu/drm-kms.html#drm-framebuffer-abstraction
- [linput]: Linux input subsystem & event protocol. https://docs.kernel.org/input/input.html
- Linux input event codes (`EV_*`, `KEY_*`, `ABS_*`). https://docs.kernel.org/input/event-codes.html
- evdev interface (`EVIOCGABS`, `EVIOCGRAB`). https://docs.kernel.org/input/uinput.html and https://www.kernel.org/doc/html/latest/input/event-codes.html

**USB HID / PS/2**
- [hid]: USB HID Specification 1.11. https://www.usb.org/document-library/device-class-definition-hid-111
- USB HID Usage Tables. https://www.usb.org/document-library/hid-usage-tables-15
- HID boot protocol (keyboard/mouse), Appendix B/E of the HID spec.
- PS/2 scancode sets (set 2). https://wiki.osdev.org/PS/2_Keyboard

**Rust embedded graphics / input**
- [eg]: `embedded-graphics` and `DrawTarget`. https://docs.rs/embedded-graphics , https://docs.rs/embedded-graphics-core/latest/embedded_graphics_core/draw_target/trait.DrawTarget.html
- `ssd1306` driver. https://docs.rs/ssd1306
- `mipidsi` (ST7789/ILI9341 etc.). https://docs.rs/mipidsi
- `ssd1680` / e-paper drivers; `epd-waveshare`. https://docs.rs/ssd1680 , https://docs.rs/epd-waveshare
- `embedded-hal` `InputPin`/`OutputPin`. https://docs.rs/embedded-hal
- `keypad` (matrix), `rotary-encoder-hal`, `debouncr`. https://docs.rs/keypad , https://docs.rs/rotary-encoder-hal , https://docs.rs/debouncr
- touch: `ft6x06`, `cst816s`, `xpt2046`. https://docs.rs/ft6x06 , https://docs.rs/cst816s

**MCU stacks**
- [zdisplay]: Zephyr display API. https://docs.zephyrproject.org/latest/hardware/peripherals/display/index.html
- [zinput]: Zephyr input subsystem. https://docs.zephyrproject.org/latest/services/input/index.html
- LVGL porting (display `flush_cb`, input `read_cb`). https://docs.lvgl.io/master/porting/display.html , https://docs.lvgl.io/master/porting/indev.html

**Controllers / panels referenced**
- SSD1306 (mono OLED) datasheet. https://cdn-shop.adafruit.com/datasheets/SSD1306.pdf
- ST7789 (RGB565 TFT) datasheet. https://newhavendisplay.com/content/datasheets/ST7789V.pdf
- Sharp memory LCD (LS013B7DH03). https://www.sharpsde.com/products/displays/
- SSD1680 (e-paper) datasheet. https://www.solomon-systech.com/product/ssd1680/

**QEMU**
- [qemustellaris]: QEMU Stellaris `lm3s6965evb` (SSD0323 OLED, GPIO buttons). https://www.qemu.org/docs/master/system/arm/stellaris.html

[fbdev]: https://docs.kernel.org/fb/api.html
[drmkms]: https://docs.kernel.org/gpu/drm-kms.html
[linput]: https://docs.kernel.org/input/input.html
[hid]: https://www.usb.org/document-library/device-class-definition-hid-111
[eg]: https://docs.rs/embedded-graphics
[zdisplay]: https://docs.zephyrproject.org/latest/hardware/peripherals/display/index.html
[zinput]: https://docs.zephyrproject.org/latest/services/input/index.html
[qemustellaris]: https://www.qemu.org/docs/master/system/arm/stellaris.html
