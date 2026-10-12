//! Driver framework and middleware pipeline.

use std::sync::Mutex as StdMutex;

use bismuth::driver::{gpio::Gpio, i2c::I2cBus, sensor::Sensor, char::Serial};
use bismuth::driver::i2c::Tmp102;
use bismuth::driver::{char::Pipe, gpio::SimGpio, i2c::SimI2c, sensor::SimSensor};
use bismuth::driver::middleware::*;
use bismuth::driver::{
    self, Device, DeviceCtx, DeviceDesc, IoResult, Next, OpKind, PowerState, Request, FACTORIES,
};
use bismuth::sim;
use bismuth::task;
use bismuth::{Error, Timeout, time};

/// Tests in this file share global logs; run them one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Middleware that records the order in which layers see a request.
struct Tag(&'static str);
static ORDER: StdMutex<Vec<&'static str>> = StdMutex::new(Vec::new());
impl Middleware for Tag {
    fn name(&self) -> &'static str {
        self.0
    }
    fn call(&self, _: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        ORDER.lock().unwrap().push(self.0);
        next.run(req)
    }
}

static PIPE_A: Pipe<64> = Pipe::new();
static TAG_GLOBAL: Tag = Tag("global");
static TAG_USER1: Tag = Tag("user1");
static TAG_USER2: Tag = Tag("user2");

#[test]
fn middleware_chain_order_global_user_driver() {
    let _serial = serial();
    sim::run_to_completion(|| {
        ORDER.lock().unwrap().clear();
        let dev = driver::register("pipe0", &PIPE_A).unwrap();
        driver::add_global_middleware(&TAG_GLOBAL).unwrap();
        dev.attach(&TAG_USER1).unwrap();
        dev.attach(&TAG_USER2).unwrap();
        let mut names = [""; 8];
        let n = dev.chain(&mut names).unwrap();
        assert_eq!(&names[..n], ["global", "user1", "user2", "nonblocking"]);
        assert_eq!(dev.write(b"hi"), Ok(2));
        assert_eq!(*ORDER.lock().unwrap(), ["global", "user1", "user2"]);
        dev.detach("user1").unwrap();
        assert_eq!(dev.detach("user1"), Err(Error::NotFound));
        let n = dev.chain(&mut names).unwrap();
        assert_eq!(&names[..n], ["global", "user2", "nonblocking"]);
    });
}

static PIPE_B: Pipe<8> = Pipe::new();
static PIPE_B_STATS: Stats = Stats::new();

#[test]
fn pipe_blocks_reader_and_counts_stats() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("pipe1", &PIPE_B).unwrap();
        dev.attach(&PIPE_B_STATS).unwrap();
        task::Builder::new("reader").priority(4).spawn(|_| {
            let s = Serial::open("/dev/pipe1").unwrap();
            let mut buf = [0u8; 32];
            let mut got = Vec::new();
            while got.len() < 20 {
                let n = s.read(&mut buf, Timeout::Forever).unwrap();
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, b"0123456789abcdefghij");
            // Non-blocking read on an empty pipe.
            let mut req = Request::new(driver::Op::Read(&mut buf)).with_flags(driver::FLAG_NONBLOCK);
            assert_eq!(s.0.request(&mut req), Err(Error::WouldBlock));
        }, 0).unwrap();
        task::Builder::new("writer").priority(2).spawn(|_| {
            let s = Serial::open("pipe1").unwrap();
            task::sleep_ticks(3);
            // 20 bytes through an 8-byte pipe: the writer blocks until the reader drains.
            s.write(b"0123456789abcdefghij").unwrap();
        }, 0).unwrap();
    });
    let st = PIPE_B_STATS.snapshot();
    assert_eq!(st.bytes_out, 20);
    assert_eq!(st.bytes_in, 20);
    assert_eq!(st.errors, 1);
}

static SENSOR: SimSensor = SimSensor::new(2);
static AVG: MovingAverage<4> = MovingAverage::new();
static DEADBAND: Deadband = Deadband::new(50);

#[test]
fn sensor_driver_middleware_calibrates_and_user_layers_filter() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("temp0", &SENSOR).unwrap();
        task::Builder::new("t").priority(3).spawn(move |_| {
            let s = Sensor::open("temp0").unwrap();
            assert_eq!(s.channels(), Ok(2));
            // Raw 2048 counts -> 2048 * 16500 / 4095 - 4000 = 4252 (42.52 °C)
            SENSOR.force_counts(Some(2048));
            let mut v = [0i32; 2];
            assert_eq!(s.read(&mut v), Ok(2));
            assert_eq!(v, [4252, 4252]);
            // Stack a moving average and a deadband on top of the driver's calibration.
            let dev = s.0;
            dev.attach(&DEADBAND).unwrap();
            dev.attach(&AVG).unwrap();
            assert_eq!(s.read(&mut v), Ok(2)); // first reading always reported
            SENSOR.force_counts(Some(2049)); // +0.04 °C: inside the deadband
            assert_eq!(s.read(&mut v), Ok(0));
            assert_eq!(DEADBAND.suppressed(), 1);
            SENSOR.force_counts(Some(4095)); // big jump, but averaged over 4 samples
            assert_eq!(s.read(&mut v), Ok(2));
            assert!(v[0] > 4252 && v[0] < 12500, "averaged value {}", v[0]);
            SENSOR.force_counts(None);
        }, 0).unwrap();
        let _ = dev;
    });
}

static SENSOR_PG: SimSensor = SimSensor::new(1);
static GATE: PowerGate = PowerGate::new(100);

#[test]
fn power_gate_suspends_idle_device_and_wakes_on_demand() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("temp1", &SENSOR_PG).unwrap();
        dev.attach(&GATE).unwrap();
        task::Builder::new("t").priority(3).spawn(|_| {
            let s = Sensor::open("temp1").unwrap();
            let mut v = [0i32; 1];
            assert_eq!(s.read(&mut v), Ok(1));
            assert!(!SENSOR_PG.is_suspended());
            task::sleep_ticks(150); // > idle timeout
            assert!(SENSOR_PG.is_suspended(), "gate should have suspended the device");
            assert_eq!(s.0.power(), Ok(PowerState::Suspended));
            assert_eq!(s.read(&mut v), Ok(1)); // transparently powered back on
            assert!(!SENSOR_PG.is_suspended());
            assert_eq!(GATE.wakeups(), 1);
        }, 0).unwrap();
    });
}

static PIPE_RO: Pipe<16> = Pipe::new();
static READ_ONLY: AccessPolicy = AccessPolicy::read_only();

#[test]
fn access_policy_denies_writes() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("ro", &PIPE_RO).unwrap();
        dev.attach(&READ_ONLY).unwrap();
        assert_eq!(dev.write(b"x"), Err(Error::PermissionDenied));
        assert_eq!(dev.ioctl(driver::ioctl::SERIAL_RX_AVAILABLE, 0), Ok(0));
        let _ = OpKind::Read;
    });
}

/// A flaky driver: fails the first `n` requests with `Io`.
struct Flaky(StdMutex<u32>);
static FLAKY_MW: [&dyn Middleware; 0] = [];
impl driver::Driver for Flaky {
    fn info(&self) -> driver::DriverInfo {
        driver::DriverInfo { name: "flaky", class: driver::DeviceClass::Other, version: (0, 1, 0), compatible: &[] }
    }
    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &FLAKY_MW
    }
    fn handle(&self, _: &DeviceCtx, _: &mut Request<'_>) -> IoResult {
        let mut n = self.0.lock().unwrap();
        if *n > 0 {
            *n -= 1;
            Err(Error::Io)
        } else {
            Ok(7)
        }
    }
}
static FLAKY: Flaky = Flaky(StdMutex::new(2));
static RETRY: Retry = Retry::new(3, 4);

#[test]
fn retry_recovers_transient_errors_with_backoff() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("flaky", &FLAKY).unwrap();
        dev.attach(&RETRY).unwrap();
        task::Builder::new("t").priority(3).spawn(|_| {
            let dev = Device::find("flaky").unwrap();
            let t0 = time::ticks();
            assert_eq!(dev.write(b"x"), Ok(7));
            assert_eq!(RETRY.retries(), 2);
            assert_eq!(time::ticks() - t0, 4 + 8); // exponential back-off
        }, 0).unwrap();
    });
}

static PIPE_RL: Pipe<64> = Pipe::new();
static LIMIT: RateLimit = RateLimit::new(2, 10, LimitMode::Delay);

#[test]
fn rate_limit_delays_excess_requests() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("rl", &PIPE_RL).unwrap();
        dev.attach(&LIMIT).unwrap();
        task::Builder::new("t").priority(3).spawn(|_| {
            let dev = Device::find("rl").unwrap();
            let mut stamps = Vec::new();
            for _ in 0..5 {
                dev.write(b"x").unwrap();
                stamps.push(time::ticks());
            }
            assert_eq!(stamps, [0, 0, 10, 10, 20]);
        }, 0).unwrap();
    });
}

static GPIO: SimGpio = SimGpio::new();

#[test]
fn gpio_outputs_and_debounced_inputs() {
    let _serial = serial();
    sim::run_to_completion(|| {
        driver::register("gpio0", &GPIO).unwrap();
        task::Builder::new("t").priority(3).spawn(|_| {
            let g = Gpio::open("gpio0").unwrap();
            g.configure_output(0b0011).unwrap();
            g.configure_input(0b1100).unwrap();
            g.set(0b0001).unwrap();
            g.toggle(0b0011).unwrap();
            assert_eq!(GPIO.outputs(), 0b0010);
            assert!(g.is_high(1).unwrap());
            // Input bounces high; the debouncer reports it only after 5 stable ticks.
            assert!(!g.is_high(2).unwrap());
            GPIO.drive_inputs(0b0100);
            assert!(!g.is_high(2).unwrap());
            task::sleep_ticks(2);
            GPIO.drive_inputs(0);
            assert!(!g.is_high(2).unwrap());
            GPIO.drive_inputs(0b0100);
            assert!(!g.is_high(2).unwrap());
            task::sleep_ticks(5);
            assert!(g.is_high(2).unwrap());
        }, 0).unwrap();
    });
}

static I2C: SimI2c = SimI2c::new();
static TMP: Tmp102 = Tmp102::new(0x48, 2350);

#[test]
fn i2c_bus_with_emulated_target() {
    let _serial = serial();
    sim::run_to_completion(|| {
        I2C.attach(&TMP).ok();
        driver::register("i2c0", &I2C).unwrap();
        let bus = I2cBus::open("i2c0").unwrap();
        let mut raw = [0u8; 2];
        bus.write_read(0x48, &[0], &mut raw).unwrap();
        let centi = (i16::from_be_bytes(raw) >> 4) as i32 * 100 / 16;
        assert_eq!(centi, 2350);
        assert_eq!(bus.read(0x49, &mut raw), Err(Error::Io)); // NACK
        assert_eq!(bus.read(0x03, &mut raw), Err(Error::Invalid)); // reserved address
    });
}

static BOARD: &[DeviceDesc] = &[
    DeviceDesc { name: "tty0", compatible: "bismuth,pipe", mmio: None, irq: u16::MAX, params: &[] },
    DeviceDesc { name: "env0", compatible: "bismuth,sim-sensor", mmio: None, irq: u16::MAX, params: &[("channels", 3)] },
    DeviceDesc { name: "mystery", compatible: "acme,widget", mmio: None, irq: u16::MAX, params: &[] },
];

#[test]
fn probe_binds_drivers_by_compatible_string() {
    let _serial = serial();
    sim::run_to_completion(|| {
        assert_eq!(driver::probe_all(BOARD, FACTORIES), 2);
        assert_eq!(Sensor::open("env0").unwrap().channels(), Ok(3));
        assert!(Serial::open("tty0").is_ok());
        assert_eq!(Device::find("mystery"), Err(Error::NotFound));
        assert_eq!(Sensor::open("tty0").unwrap_err(), Error::Unsupported);
        let mut list = [None; 8];
        assert_eq!(driver::list(&mut list), 2);
    });
}

#[test]
fn console_can_target_a_device() {
    let _serial = serial();
    static CONSOLE_PIPE: Pipe<128> = Pipe::new();
    sim::run_to_completion(|| {
        let dev = driver::register("console", &CONSOLE_PIPE).unwrap();
        bismuth::console::set_device(dev);
        bismuth::kprintln!("hello {}", 42);
        let mut buf = [0u8; 64];
        let n = dev.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello 42\n");
    });
}
