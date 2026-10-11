//! Bismuth on QEMU `lm3s6965evb` (Cortex-M3).
//!
//! Exercises the real ARMv7-M port: PendSV context switching, SysTick preemption,
//! priority inheritance under a genuine priority-inversion scenario, queues, software
//! timers, and the driver framework (PL011 UART console and a sensor with a middleware
//! pipeline). Exits QEMU through semihosting with success or failure.
#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::arch::mmio::Mmio;
use bismuth::driver::sensor::Sensor;
use bismuth::driver::{FACTORIES, char::pl011, sensor::SimSensor};
use bismuth::driver::middleware::{Deadband, MovingAverage, Stats};
use bismuth::driver::{self, Device, DeviceDesc};
use bismuth::sync::{EventFlags, Mutex, Queue, WaitMode};
use bismuth::task::{self, TaskInfo};
use bismuth::timer::Timer;
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskState, Timeout, UserStack2K, kprintln, time, user};
use cortex_m_rt::entry;
use cortex_m_semihosting::debug;

/// SysTick input clock of the emulated LM3S6965.
const CORE_HZ: u32 = 12_000_000;

/// Board description: the only place hardware addresses are asserted.
#[allow(unsafe_code)]
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "uart0",
    compatible: "arm,pl011",
    // SAFETY: UART0 of the LM3S6965 lives at 0x4000_C000 and is used only via this window.
    mmio: Some(unsafe { Mmio::new(0x4000_C000, pl011::REGISTER_SPAN) }),
    irq: 5,
    params: &[("baud", 115_200)],
}];

static SENSOR: SimSensor = SimSensor::new(1);
static SANDBOX_SENSOR: SimSensor = SimSensor::new(1);
static SENSOR_STATS: Stats = Stats::new();
static SMOOTH: MovingAverage<4> = MovingAverage::new();
static DEADBAND: Deadband = Deadband::new(15);

static SAMPLES: Queue<(u64, i32), 8> = Queue::new();
static DONE: EventFlags = EventFlags::new();
const DONE_PIPELINE: u32 = 1 << 0;
const DONE_INVERSION: u32 = 1 << 1;

static SHARED: Mutex<u32> = Mutex::new(0);
static HIGH_GOT_LOCK_AT: AtomicU32 = AtomicU32::new(0);
static MEDIUM_DONE_AT: AtomicU32 = AtomicU32::new(0);
static LOW_PRIO_SEEN: AtomicU32 = AtomicU32::new(0);
static HEARTBEATS: AtomicU32 = AtomicU32::new(0);
static HEARTBEAT: Timer = Timer::new(|_| { HEARTBEATS.fetch_add(1, Ordering::Relaxed); }, 0);

static S_SAMPLER: Stack<2048> = Stack::new();
static S_REPORTER: Stack<2048> = Stack::new();
static S_LOW: Stack<1536> = Stack::new();
static S_MED: Stack<1536> = Stack::new();
static S_HIGH: Stack<1536> = Stack::new();
static S_SUPER: Stack<3072> = Stack::new();
static S_SANDBOX: UserStack2K = UserStack2K::new();
static SANDBOX_DOMAIN: AtomicU32 = AtomicU32::new(0);
static SANDBOX_TASK: AtomicU32 = AtomicU32::new(0);

/// Sandboxed code: runs unprivileged under the MPU and may only use `bismuth::user`.
/// Its exit code reports which check (if any) failed.
extern "C-unwind" fn sandboxed(_: usize) {
    // Unprivileged code: it can touch only its own stack and call the kernel via `user`.
    user::log(b"[sandbox] running unprivileged
");
    let h = match user::open("env") {
        Ok(h) => h,
        Err(e) => user::exit(1000 + e.errno() as usize),
    };
    let mut raw = [0u8; 4];
    if user::read(h, &mut raw, Timeout::Forever) != Ok(4) {
        user::exit(2);
    }
    // The granted handle carries READ only; the kernel must refuse a write.
    if user::write(h, b"x") != Err(bismuth::Error::PermissionDenied) {
        user::exit(3);
    }
    user::log(b"[sandbox] sensor read ok; unauthorized write denied by the kernel
");
    user::exit(0)
}


/// Spin (without blocking) until `ticks` have elapsed: only SysTick preemption can
/// interrupt this.
fn busy_for(ticks: u64) {
    let end = time::ticks() + ticks;
    while time::ticks() < end {}
}

fn sampler(_: usize) {
    let sensor = Sensor::open("temp0").expect("sensor");
    let mut last = time::ticks();
    let mut v = [0i32; 1];
    for _ in 0..40 {
        task::sleep_until(&mut last, 10);
        if sensor.read(&mut v) == Ok(1) {
            let _ = SAMPLES.send((time::ticks(), v[0]), Timeout::Forever);
        }
    }
    let _ = SAMPLES.send((u64::MAX, 0), Timeout::Forever);
}

fn reporter(_: usize) {
    let mut n = 0;
    loop {
        let (t, centi) = SAMPLES.recv(Timeout::Forever).expect("queue");
        if t == u64::MAX {
            break;
        }
        n += 1;
        kprintln!("  t={:>4} temp0 = {}.{:02} C", t, centi / 100, (centi % 100).abs());
    }
    kprintln!("pipeline: {} reported readings", n);
    DONE.set(DONE_PIPELINE);
}

fn low(_: usize) {
    let mut g = SHARED.lock().unwrap();
    busy_for(5); // let medium and high arrive while we hold the lock
    busy_for(15);
    LOW_PRIO_SEEN.store(task::priority(task::current()).unwrap() as u32, Ordering::Relaxed);
    *g += 1;
}

fn medium(_: usize) {
    task::sleep_ticks(2);
    busy_for(60); // CPU hog: would starve `low` without priority inheritance
    MEDIUM_DONE_AT.store(time::ticks() as u32, Ordering::Relaxed);
}

fn high(_: usize) {
    task::sleep_ticks(4);
    let mut g = SHARED.lock().unwrap();
    HIGH_GOT_LOCK_AT.store(time::ticks() as u32, Ordering::Relaxed);
    *g += 10;
    drop(g);
    DONE.set(DONE_INVERSION);
}

fn supervisor(_: usize) {
    let ok = DONE.wait(DONE_PIPELINE | DONE_INVERSION, WaitMode::All, false, Timeout::ms(5000));
    task::sleep_ticks(2);
    let sandbox = DomainId(SANDBOX_DOMAIN.load(Ordering::Relaxed) as u8);
    let sandbox_exit = task::join(bismuth::TaskId::from_raw(SANDBOX_TASK.load(Ordering::Relaxed)), Timeout::ms(5000));
    let sandbox_ok = sandbox_exit == Ok(0) && !security::is_killed(sandbox) && security::faults(sandbox) == 0;
    kprintln!(
        "sandbox: exit={:?} killed={} mpu faults={}",
        sandbox_exit,
        security::is_killed(sandbox),
        security::faults(sandbox)
    );
    HEARTBEAT.stop();

    let high_at = HIGH_GOT_LOCK_AT.load(Ordering::Relaxed);
    let med_at = MEDIUM_DONE_AT.load(Ordering::Relaxed);
    let inherited = LOW_PRIO_SEEN.load(Ordering::Relaxed);
    kprintln!("priority inversion: high got lock at t={}, medium finished at t={}, low ran at prio {}", high_at, med_at, inherited);

    let st = SENSOR_STATS.snapshot();
    kprintln!("sensor stats: {} reads, {} bytes, {} suppressed by deadband", st.reads, st.bytes_in, DEADBAND.suppressed());
    kprintln!("heartbeat timer fired {} times", HEARTBEATS.load(Ordering::Relaxed));

    let mut infos = [TaskInfo {
        id: task::current(),
        name: "",
        state: TaskState::Free,
        priority: 0,
        base_priority: 0,
        run_ticks: 0,
        stack_size: 0,
        stack_free: 0,
    }; 16];
    let n = task::list(&mut infos);
    kprintln!("{:<10} {:>4} {:>10} {:>6} {:>6}", "task", "prio", "state", "stack", "free");
    for t in &infos[..n] {
        let st = match t.state {
            TaskState::Ready => "Ready",
            TaskState::Blocked => "Blocked",
            TaskState::Suspended => "Suspended",
            TaskState::Dead => "Dead",
            TaskState::Free => "Free",
        };
        kprintln!("{:<10} {:>4} {:>10} {:>6} {:>6}", t.name, t.priority, st, t.stack_size, t.stack_free);
    }

    let pass = ok.is_ok()
        && high_at != 0
        && high_at < med_at          // high was not blocked behind the CPU hog
        && inherited == 6            // low ran at high's priority while holding the lock
        && *SHARED.lock().unwrap() == 11
        && st.reads == 40
        && HEARTBEATS.load(Ordering::Relaxed) > 0
        && sandbox_ok;
    kprintln!("{}", if pass { "BISMUTH QEMU DEMO: PASS" } else { "BISMUTH QEMU DEMO: FAIL" });
    debug::exit(if pass { debug::EXIT_SUCCESS } else { debug::EXIT_FAILURE });
}

#[entry]
fn main() -> ! {
    driver::probe_all(&BOARD, FACTORIES);
    if let Ok(uart) = Device::find("uart0") {
        bismuth::console::set_device(uart);
    }
    bismuth::console::boot_logo();
    kprintln!("Bismuth {} on lm3s6965evb (Cortex-M3)", env!("CARGO_PKG_VERSION"));

    let temp = driver::register("temp0", &SENSOR).expect("register sensor");
    temp.attach(&SENSOR_STATS).unwrap();
    temp.attach(&DEADBAND).unwrap();
    temp.attach(&SMOOTH).unwrap();

    task::spawn("sampler", 4, &S_SAMPLER, sampler, 0).unwrap();
    task::spawn("reporter", 3, &S_REPORTER, reporter, 0).unwrap();
    task::spawn("low", 2, &S_LOW, low, 0).unwrap();
    task::spawn("medium", 5, &S_MED, medium, 0).unwrap();
    task::spawn("high", 6, &S_HIGH, high, 0).unwrap();
    task::spawn("super", 1, &S_SUPER, supervisor, 0).unwrap();
    HEARTBEAT.start(50, 50).unwrap();

    // A hardware-isolated domain holding only READ on the sensor.
    let sandbox = security::create_domain(DomainSpec::sandboxed("sandbox", 4, 1)).unwrap();
    let sandbox_dev = driver::register("temp1", &SANDBOX_SENSOR).expect("register sandbox sensor");
    security::grant_device(sandbox, sandbox_dev, Rights::READ, "env").unwrap();
    security::seal().unwrap();
    SANDBOX_DOMAIN.store(sandbox.0 as u32, Ordering::Relaxed);
    let sb = task::Builder::new("sandboxed").priority(1).domain(sandbox).stack(&S_SANDBOX).spawn_user(sandboxed, 0).unwrap();
    SANDBOX_TASK.store(sb.as_raw(), Ordering::Relaxed);

    bismuth::start(CORE_HZ)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    cortex_m_semihosting::hprintln!("PANIC: {}", info);
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}
