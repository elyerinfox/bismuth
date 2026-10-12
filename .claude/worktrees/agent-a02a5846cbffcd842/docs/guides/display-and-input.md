# Display and input

This guide draws on a panel and reacts to key presses, using the simulator drivers so
everything runs under `cargo test`. The code was compiled and run against the current
kernel. For the protocol and ioctl tables, read
[design/human-interface.md](../design/human-interface.md).

## 1. Register the devices

```rust
use bismuth::driver;
use bismuth::driver::display::SimDisplay;
use bismuth::driver::input::SimInput;
use bismuth::driver::middleware::Stats;

static LCD: SimDisplay<16, 8, 128> = SimDisplay::new();   // 16×8 RGB565; PIXELS = W*H
static KBD: SimInput<32> = SimInput::keyboard();          // 32-event queue
static LCD_STATS: Stats = Stats::new();                   // bytes_out = bytes sent to the panel

let lcd = driver::register("lcd", &LCD)?;
lcd.attach(&LCD_STATS)?;
driver::register("kbd", &KBD)?;
```

On real hardware you register a panel driver and an input driver here instead; the
application code below does not change.

## 2. Draw

Pixels go to a window. `Display::blit` sets the window and streams the bytes. For
`Rgb565`, each pixel is 2 bytes, **big-endian**.

```rust
use bismuth::driver::display::{Display, PixelFormat, Rect, RefreshMode};

/// Fill a rectangle with one RGB565 colour, one row at a time (bounded stack buffer).
fn fill(d: &Display, r: Rect, rgb565: u16) -> Result<(), bismuth::Error> {
    let px = rgb565.to_be_bytes();
    let mut row = [0u8; 2 * 64];
    for i in 0..r.w as usize {
        row[2 * i..2 * i + 2].copy_from_slice(&px);
    }
    for y in r.y..r.y + r.h {
        d.blit(Rect::new(r.x, y, r.w, 1), &row[..2 * r.w as usize])?;
    }
    Ok(())
}
```

Check `format()` before assuming RGB565. Monochrome and grayscale panels pack several
pixels per byte; use `PixelFormat::region_bytes(w, h)` to size buffers. Call
`flush(RefreshMode::…)` after drawing. It is a no-op on simple TFTs and required for
buffered or e-paper panels.

## 3. Read input

```rust
use bismuth::driver::input::{EventKind, Input, InputEvent, code};
use bismuth::Timeout;

fn ui(_: usize) {
    let lcd = Display::open("lcd").unwrap();
    let kbd = Input::open("kbd").unwrap();
    let (w, h) = lcd.geometry().unwrap();
    assert_eq!(lcd.format().unwrap(), PixelFormat::Rgb565);
    fill(&lcd, Rect::new(0, 0, w, h), 0x0000).unwrap();      // clear to black
    lcd.flush(RefreshMode::Full).unwrap();

    let mut evs = [InputEvent::syn(); 8];
    loop {
        let n = match kbd.read(&mut evs, Timeout::ms(100)) { Ok(n) => n, Err(_) => break };
        for e in &evs[..n] {
            if e.kind() == Some(EventKind::Key) && e.code == code::KEY_ENTER && e.value == 1 {
                fill(&lcd, Rect::new(0, 0, 4, 4), 0xF800).unwrap(); // red square on Enter
                lcd.flush(RefreshMode::Partial).unwrap();
            }
        }
    }
}
```

`Input::read` waits for the first event, then returns up to 16 queued events. A packet
can be split across reads, so if you combine events (for example a touch's X, Y and
pressure), accumulate them until you see an `EventKind::Syn` event.

## 4. Test it

```rust
#[test]
fn enter_paints_red() {
    sim::run_to_completion(|| {
        let lcd = driver::register("lcd", &LCD).unwrap();
        lcd.attach(&LCD_STATS).unwrap();
        driver::register("kbd", &KBD).unwrap();
        task::Builder::new("ui").priority(3).spawn(ui, 0).unwrap();
        task::Builder::new("keys").priority(2).spawn(|_| {
            task::sleep_ticks(10);
            KBD.tap(code::KEY_ENTER);                       // down + SYN + up + SYN
        }, 0).unwrap();
    });
    assert_eq!(LCD.pixel(1, 1), 0xF800);                    // framebuffer readback
    assert_eq!(LCD.pixel(10, 5), 0);
    assert_eq!(LCD_STATS.snapshot().bytes_out as usize, 16 * 8 * 2 + 4 * 4 * 2);
}
```

The `ui` loop ends when no key arrives for 100 ms, so the simulation completes. For a
mouse, use `SimInput::mouse()` and inject `InputEvent::new(EventKind::Rel,
code::REL_X, dx)`. Then follow with `InputEvent::syn()`. `KBD.overruns()` counts
events dropped because the queue was full.

## Tips

- **One owner per display.** `blit` is a window ioctl pair plus a write. Concurrent
  blits from two tasks can interleave, and `Exclusive` middleware does not prevent it.
  Route drawing through one UI task, or put the `Display` behind a `sync::Mutex`.
- **Rights.** For an isolated domain, grant `WRITE | CONTROL` on a display to let it
  draw, and `READ | CONTROL` on an input device to let it read events.
  `DISPLAY_SET_ORIENTATION`/`SET_FORMAT` and `INPUT_SET_REPEAT` also need `CONFIG`.
- **Power.** `Display::blank(true)` or `Device::set_power(PowerState::Off)` blanks the
  panel. Add `PowerGate` middleware to blank it automatically after inactivity.
- **Polling.** POSIX `poll` reports an input fd as readable when events are queued.
  From Rust, use `Input::available()` or a read with a timeout.
