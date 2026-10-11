//! Display (framebuffer) and input (keyboard/mouse) device classes.

use std::sync::Mutex as StdMutex;

use bismuth::driver::display::{Display, DisplayCaps, PixelFormat, Rect, RefreshMode};
use bismuth::driver::{display::SimDisplay, input::SimInput};
use bismuth::driver::input::{EventKind, Input, InputEvent, code};
use bismuth::driver::middleware::Stats;
use bismuth::driver::{self, PowerState};
use bismuth::{Timeout, sim, task};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

// 16x8 RGB565 panel.
static LCD: SimDisplay<16, 8, 128> = SimDisplay::new();
static LCD_STATS: Stats = Stats::new();

#[test]
fn display_blit_window_and_caps() {
    let _g = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("lcd", &LCD).unwrap();
        dev.attach(&LCD_STATS).unwrap(); // "bytes pushed to the panel" counter, for free
        task::Builder::new("ui").priority(3).spawn(|_| {
            let d = Display::open("lcd").unwrap();
            assert_eq!(d.geometry(), Ok((16, 8)));
            assert_eq!(d.format(), Ok(PixelFormat::Rgb565));
            assert!(d.caps().unwrap().contains(DisplayCaps::BACKLIGHT));
            // Fill a 2x2 red (0xF800) rectangle at (3,1).
            let red = 0xF800u16.to_be_bytes();
            let px = [red[0], red[1], red[0], red[1], red[0], red[1], red[0], red[1]];
            d.blit(Rect::new(3, 1, 2, 2), &px).unwrap();
            d.flush(RefreshMode::Full).unwrap();
            d.set_backlight(128).unwrap();
        }, 0).unwrap();
    });
    // Inspect the framebuffer the driver wrote.
    assert_eq!(LCD.pixel(3, 1), 0xF800);
    assert_eq!(LCD.pixel(4, 2), 0xF800);
    assert_eq!(LCD.pixel(0, 0), 0x0000);
    assert_eq!(LCD.pixel(5, 1), 0x0000); // outside the 2-wide window
    assert_eq!(LCD.backlight(), 128);
    assert_eq!(LCD.flush_count(), 1);
    let st = LCD_STATS.snapshot();
    assert_eq!(st.bytes_out, 8); // 4 pixels x 2 bytes pushed to the panel
}

static KBD: SimInput<16> = SimInput::keyboard();
static GOT: StdMutex<Vec<(u8, u16, i32)>> = StdMutex::new(Vec::new());

#[test]
fn input_keyboard_events_blocking_read() {
    let _g = serial();
    GOT.lock().unwrap().clear();
    sim::run_to_completion(|| {
        driver::register("kbd", &KBD).unwrap();
        task::Builder::new("app").priority(4).spawn(|_| {
            let k = Input::open("kbd").unwrap();
            assert_eq!(k.caps().unwrap(), EventKind::Key.bit() | EventKind::Syn.bit());
            let mut evs = [InputEvent::syn(); 8];
            let mut total = 0;
            // Expect: A down, syn, A up, syn, Enter down, syn, Enter up, syn.
            while total < 8 {
                let n = k.read(&mut evs, Timeout::ms(1000)).unwrap();
                for e in &evs[..n] {
                    GOT.lock().unwrap().push((e.kind, e.code, e.value));
                }
                total += n;
            }
        }, 0).unwrap();
        task::Builder::new("hw").priority(2).spawn(|_| {
            task::sleep_ticks(2);
            KBD.tap(code::KEY_A);
            task::sleep_ticks(2);
            KBD.tap(code::KEY_ENTER);
        }, 0).unwrap();
    });
    let got = GOT.lock().unwrap().clone();
    let keydown: Vec<_> = got.iter().filter(|(k, _, v)| *k == EventKind::Key as u8 && *v == 1).map(|(_, c, _)| *c).collect();
    assert_eq!(keydown, vec![code::KEY_A, code::KEY_ENTER]);
    // Each tap produced down+syn+up+syn.
    assert_eq!(got.len(), 8);
}

static MOUSE: SimInput<8> = SimInput::mouse();

#[test]
fn input_mouse_poll_and_overflow() {
    let _g = serial();
    sim::run_to_completion(|| {
        driver::register("mouse", &MOUSE).unwrap();
        task::Builder::new("t").priority(3).spawn(|_| {
            let m = Input::open("mouse").unwrap();
            // Nothing yet.
            assert_eq!(m.available(), Ok(0));
            // A movement packet: Rel X +4, Rel Y -2, button down, Syn.
            MOUSE.inject(InputEvent::new(EventKind::Rel, code::REL_X, 4));
            MOUSE.inject(InputEvent::new(EventKind::Rel, code::REL_Y, -2));
            MOUSE.inject(InputEvent::new(EventKind::Key, code::BTN_LEFT, 1));
            MOUSE.inject(InputEvent::syn());
            assert_eq!(m.available(), Ok(4));
            let mut evs = [InputEvent::syn(); 8];
            let n = m.read(&mut evs, Timeout::NoWait).unwrap();
            assert_eq!(n, 4);
            assert_eq!((evs[0].code, evs[0].value), (code::REL_X, 4));
            assert_eq!((evs[1].code, evs[1].value), (code::REL_Y, -2));
            // Overflow: queue depth is 8; inject 12, expect 4 dropped+counted.
            for i in 0..12 {
                MOUSE.inject(InputEvent::new(EventKind::Rel, code::REL_WHEEL, i));
            }
            assert_eq!(MOUSE.overruns(), 4);
            m.flush().unwrap();
            assert_eq!(m.available(), Ok(0));
        }, 0).unwrap();
    });
}

#[test]
fn display_power_blank() {
    let _g = serial();
    static OLED: SimDisplay<8, 8, 64> = SimDisplay::new();
    sim::run_to_completion(|| {
        let dev = driver::register("oled", &OLED).unwrap();
        task::Builder::new("t").priority(3).spawn(move |_| {
            let d = Display::open("oled").unwrap();
            d.blank(true).unwrap();
            d.0.set_power(PowerState::On).unwrap();
        }, 0).unwrap();
        let _ = dev;
    });
}
