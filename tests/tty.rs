//! TTY line discipline + PTY + POSIX termios, host-tested with no hardware.

use std::sync::Mutex as StdMutex;

use bismuth::compat::posix::{self, termios};
use bismuth::driver::char::Serial;
use bismuth::driver::char::{Pty, PtyMaster, PtySlave};
use bismuth::driver::char::tty::{self, Tty};
use bismuth::driver::{self, Device};
use bismuth::{Timeout, sim, task};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
fn log(s: impl Into<String>) {
    LOG.lock().unwrap().push(s.into());
}
fn take() -> Vec<String> {
    std::mem::take(&mut *LOG.lock().unwrap())
}

// One PTY: master "ptm", slave "pts" with a Tty line discipline.
static PTY: Pty<256> = Pty::new();
static MASTER: PtyMaster<256> = Pty::master(&PTY);
static SLAVE: PtySlave<256> = Pty::slave(&PTY);
static TTY: Tty = Tty::new();

fn setup_pty() -> (Device, Device) {
    let m = driver::register("ptm", &MASTER).unwrap();
    let s = driver::register("pts", &SLAVE).unwrap();
    s.attach(&TTY).unwrap();
    (m, s)
}

#[test]
fn canonical_mode_line_editing_and_echo() {
    let _g = serial();
    take();
    sim::run_to_completion(|| {
        let (m, s) = setup_pty();
        // Shell task: read one cooked line from the slave.
        task::Builder::new("shell").priority(4).spawn(move |arg| {
            let s = Device::from_index(arg).unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            log(format!("line={:?}", std::str::from_utf8(&buf[..n]).unwrap()));
        }, s.index()).unwrap();
        // Terminal task: type "ab", backspace, "c", newline at the master end.
        task::Builder::new("term").priority(3).spawn(move |arg| {
            let m = Device::from_index(arg).unwrap();
            task::sleep_ticks(1);
            m.write(b"ab").unwrap();
            m.write(b"\x7f").unwrap(); // DEL erases 'b'
            m.write(b"c\r").unwrap(); // CR, ICRNL -> NL terminates the line
            task::sleep_ticks(5);
            // The echo (with ECHOE) should have come back on the master.
            let mut echo = [0u8; 64];
            let n = m.read(&mut echo).unwrap();
            log(format!("echo={:?}", std::str::from_utf8(&echo[..n]).unwrap()));
        }, m.index()).unwrap();
    });
    let out = take();
    // Canonical line is "ac\n" (b erased); echo shows a, b, erase (\b \b), c, \r\n.
    assert!(out.contains(&"line=\"ac\\n\"".to_string()), "{out:?}");
    assert!(out.iter().any(|l| l.starts_with("echo=") && l.contains("ab") && l.contains("c")), "{out:?}");
}

static TTY2: Tty = Tty::new();
static PTY2: Pty<256> = Pty::new();
static MASTER2: PtyMaster<256> = Pty::master(&PTY2);
static SLAVE2: PtySlave<256> = Pty::slave(&PTY2);

#[test]
fn raw_mode_passes_bytes_through_untouched() {
    let _g = serial();
    take();
    sim::run_to_completion(|| {
        let m = driver::register("ptm2", &MASTER2).unwrap();
        let s = driver::register("pts2", &SLAVE2).unwrap();
        s.attach(&TTY2).unwrap();
        // Put the slave TTY into raw mode via POSIX termios on an fd.
        task::Builder::new("app").priority(4).spawn(move |arg| {
            let s = Device::from_index(arg).unwrap();
            let fd = posix::open(&format!("/dev/{}", s.name().unwrap()), posix::O_RDWR);
            let mut t = termios::Termios::cooked();
            assert_eq!(termios::tcgetattr(fd, &mut t), 0);
            termios::cfmakeraw(&mut t);
            assert_eq!(termios::tcsetattr(fd, termios::TCSANOW, &t), 0);
            // Raw read returns whatever arrives, no line buffering, no echo.
            let mut buf = [0u8; 8];
            let n = s.read_timeout(&mut buf, Timeout::ms(500)).unwrap();
            log(format!("raw={:?}", &buf[..n]));
        }, s.index()).unwrap();
        task::Builder::new("term").priority(3).spawn(move |arg| {
            let m = Device::from_index(arg).unwrap();
            task::sleep_ticks(2);
            m.write(&[0x01, 0x7f, 0x03]).unwrap(); // control bytes pass through in raw mode
            task::sleep_ticks(10);
            // No echo in raw mode: nothing waiting on the master.
            let s = Serial(m);
            log(format!("echo_avail={}", s.available().unwrap()));
        }, m.index()).unwrap();
    });
    let out = take();
    assert!(out.contains(&"raw=[1, 127, 3]".to_string()), "{out:?}");
    assert!(out.contains(&"echo_avail=0".to_string()), "{out:?}");
}

static TTY3: Tty = Tty::new();
static PTY3: Pty<256> = Pty::new();
static MASTER3: PtyMaster<256> = Pty::master(&PTY3);
static SLAVE3: PtySlave<256> = Pty::slave(&PTY3);
static SHELL_ID: StdMutex<Option<task::TaskId>> = StdMutex::new(None);

#[test]
fn ctrl_c_interrupts_read_and_notifies_controlling_task() {
    let _g = serial();
    take();
    sim::run_to_completion(|| {
        let m = driver::register("ptm3", &MASTER3).unwrap();
        let s = driver::register("pts3", &SLAVE3).unwrap();
        s.attach(&TTY3).unwrap();
        task::Builder::new("shell").priority(4).spawn(move |arg| {
            let s = Device::from_index(arg).unwrap();
            // Bind this task to receive terminal-signal notifications.
            tty::control(s).unwrap().set_signal_target(task::current(), [0b1, 0b10, 0b100]);
            let mut buf = [0u8; 32];
            // Blocking read is interrupted by ^C.
            let r = s.read(&mut buf);
            log(format!("read={:?}", r.err()));
            // The INT notification bit was delivered.
            let bits = task::notify_wait(Timeout::ms(100)).unwrap_or(0);
            log(format!("sig_bits={bits:#b}"));
        }, s.index()).unwrap();
        task::Builder::new("term").priority(3).spawn(move |arg| {
            let m = Device::from_index(arg).unwrap();
            task::sleep_ticks(3);
            m.write(&[0x03]).unwrap(); // ^C
        }, m.index()).unwrap();
    });
    let out = take();
    assert!(out.contains(&"read=Some(Interrupted)".to_string()), "{out:?}");
    assert!(out.contains(&"sig_bits=0b1".to_string()), "{out:?}");
    let _ = &SHELL_ID;
}

#[test]
fn termios_roundtrip_and_flag_edits() {
    let _g = serial();
    sim::run_to_completion(|| {
        static P: Pty<128> = Pty::new();
        static M: PtyMaster<128> = Pty::master(&P);
        static S: PtySlave<128> = Pty::slave(&P);
        static T: Tty = Tty::new();
        driver::register("ptm4", &M).unwrap();
        let s = driver::register("pts4", &S).unwrap();
        s.attach(&T).unwrap();
        task::Builder::new("app").priority(4).spawn(move |arg| {
            let s = Device::from_index(arg).unwrap();
            let fd = posix::open(&format!("/dev/{}", s.name().unwrap()), posix::O_RDWR);
            let mut t = termios::Termios::cooked();
            assert_eq!(termios::tcgetattr(fd, &mut t), 0);
            assert!(t.c_lflag & termios::ICANON != 0 && t.c_lflag & termios::ECHO != 0);
            // Turn off echo, keep canonical; round-trip through the device.
            t.c_lflag &= !termios::ECHO;
            termios::cfsetospeed(&mut t, 9600);
            assert_eq!(termios::tcsetattr(fd, termios::TCSANOW, &t), 0);
            let mut back = termios::Termios::cooked();
            termios::tcgetattr(fd, &mut back);
            assert_eq!(back.c_lflag & termios::ECHO, 0);
            assert_eq!(termios::cfgetospeed(&back), 9600);
            // tcflush on a tty succeeds.
            assert_eq!(termios::tcflush(fd, termios::TCIFLUSH), 0);
        }, s.index()).unwrap();
    });
}

static TTY_R: Tty = Tty::new();
static PTY_R: Pty<256> = Pty::new();
static MASTER_R: PtyMaster<256> = Pty::master(&PTY_R);
static SLAVE_R: PtySlave<256> = Pty::slave(&PTY_R);
static LINES: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

#[test]
fn canonical_returns_one_line_per_read_and_preserves_input() {
    let _g = serial();
    LINES.lock().unwrap().clear();
    sim::run_to_completion(|| {
        let m = driver::register("ptmR", &MASTER_R).unwrap();
        let s = driver::register("ptsR", &SLAVE_R).unwrap();
        s.attach(&TTY_R).unwrap();
        // Turn echo off so the master side only carries the typed bytes.
        bismuth::driver::char::tty::control(s).unwrap().set_termios(
            &{ let mut t = termios::Termios::cooked(); t.c_lflag &= !termios::ECHO; t },
            bismuth::driver::char::tty::Apply::Now,
        );
        task::Builder::new("reader").priority(4).spawn(move |arg| {
            let s = Device::from_index(arg).unwrap();
            let mut buf = [0u8; 64];
            // Four deliveries in one chunk; each read must return exactly one.
            for _ in 0..4 {
                let n = s.read(&mut buf).unwrap();
                LINES.lock().unwrap().push(std::str::from_utf8(&buf[..n]).unwrap().to_string());
            }
        }, s.index()).unwrap();
        task::Builder::new("term").priority(3).spawn(move |arg| {
            let m = Device::from_index(arg).unwrap();
            task::sleep_ticks(1);
            // "ab\ncd\nxy\x04zz\n": three deliveries (ab, cd, then xy+zz via ^D then newline)
            m.write(b"ab\ncd\nxy\x04zz\n").unwrap();
        }, m.index()).unwrap();
    });
    // Bug 1 fixed: one line per read (not "ab\ncd\nxy"). Bug 2 fixed: ^D delivers "xy"
    // immediately, and the following "zz\n" is NOT lost — it is simply the next line.
    assert_eq!(*LINES.lock().unwrap(), vec!["ab\n".to_string(), "cd\n".into(), "xy".into(), "zz\n".into()]);
}
