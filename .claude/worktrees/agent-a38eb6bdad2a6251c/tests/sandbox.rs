//! Hardware-isolated (sandboxed) tasks and the system-call gate, exercised in the host
//! simulator. (Memory isolation itself is enforced by the MPU on target hardware; see
//! the QEMU board demo.)

use std::sync::Mutex as StdMutex;

use bismuth::driver;
use bismuth::driver::ioctl;
use bismuth::driver::sensor::SimSensor;
use bismuth::security::entropy::{self, SimTrng};
use bismuth::security::syscall::{self, nr};
use bismuth::security::{self, BadHandlePolicy, DomainSpec, Rights};
use bismuth::{Stack, Timeout, UserStack1K, UserStack2K, sim, task, user};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
fn note(s: impl Into<String>) {
    LOG.lock().unwrap().push(s.into());
}
fn take() -> Vec<String> {
    std::mem::take(&mut *LOG.lock().unwrap())
}

static SENSOR: SimSensor = SimSensor::new(1);
static SECRET: SimSensor = SimSensor::new(1);
static TRNG: SimTrng = SimTrng::new(77, 4);
static US1: UserStack2K = UserStack2K::new();

extern "C-unwind" fn sandboxed_app(_: usize) {
    let h = user::open("temp").unwrap();
    let mut raw = [0u8; 4];
    note(format!("read: {:?}", user::read(h, &mut raw, Timeout::Forever)));
    note(format!("query: {:?}", user::ioctl(h, ioctl::SENSOR_CHANNELS, 0)));
    note(format!("write: {:?}", user::write(h, b"x")));
    note(format!("not granted: {:?}", user::open("secret").err()));
    let mut r = [0u8; 16];
    note(format!("random: {:?} nonzero={}", user::random(&mut r), r.iter().any(|b| *b != 0)));
    user::sleep_ticks(10);
    note(format!("ticks>=10: {}", user::ticks() >= 10));
    user::drop_rights(h, Rights::READ).unwrap();
    note(format!("read after drop: {:?}", user::read(h, &mut raw, Timeout::NoWait)));
    user::log(b"sandbox says hi\n");
    // Returning from the entry exits the task cleanly.
}

#[test]
fn sandboxed_task_uses_only_syscalls_with_full_policy_checks() {
    let _s = serial();
    take();
    sim::run_to_completion(|| {
        entropy::add_source(&TRNG).unwrap();
        entropy::seed(200).unwrap();
        let dev = driver::register("temp0", &SENSOR).unwrap();
        driver::register("secret", &SECRET).unwrap();
        let d = security::create_domain(DomainSpec { bad_handle: BadHandlePolicy::Deny, ..DomainSpec::sandboxed("app", 6, 2) }).unwrap();
        security::grant_device(d, dev, Rights::READ | Rights::CONTROL, "temp").unwrap();
        security::seal().unwrap();
        task::Builder::new("app").priority(4).domain(d).stack(&US1).spawn_user(sandboxed_app, 0).unwrap();
    });
    assert_eq!(
        take(),
        [
            "read: Ok(4)".to_string(),
            "query: Ok(1)".into(),
            "write: Err(PermissionDenied)".into(),
            "not granted: Some(NotFound)".into(),
            "random: Ok(()) nonzero=true".into(),
            "ticks>=10: true".into(),
            "read after drop: Err(PermissionDenied)".into(),
        ]
    );
}

static US2: UserStack1K = UserStack1K::new();
static PLAIN: Stack<1000> = Stack::new(); // not a power of two: never MPU-mappable

extern "C-unwind" fn rng_hungry(_: usize) {
    note("starting");
    let mut b = [0u8; 4];
    let _ = user::random(&mut b); // not on the allow-list: the domain is killed here
    note("survived");
}

#[test]
fn syscall_allow_list_and_spawn_rules() {
    let _s = serial();
    take();
    sim::run_to_completion(|| {
        let spec = DomainSpec {
            syscalls: syscall::bit(nr::LOG) | syscall::bit(nr::EXIT),
            ..DomainSpec::sandboxed("minimal", 6, 2)
        };
        let d = security::create_domain(spec).unwrap();
        // Sandboxed domains accept only user tasks.
        note(format!("plain spawn: {:?}", task::Builder::new("p").priority(3).domain(d).spawn(|_| {}, 0).err()));
        // User stacks must be MPU-mappable (power of two, aligned to their size).
        note(format!("unaligned stack: {:?}", task::Builder::new("u").priority(3).domain(d).stack(&PLAIN).spawn_user(rng_hungry, 0).err()));
        // The kernel domain itself never runs unprivileged.
        note(format!("kernel user task: {:?}", task::Builder::new("k").priority(3).stack(&US2).spawn_user(rng_hungry, 0).err()));
        task::Builder::new("observer").priority(2).spawn(|d| {
            task::sleep_ticks(5);
            let d = security::DomainId(d as u8);
            note(format!("killed={} violations={}", security::is_killed(d), security::violations(d)));
        }, d.0 as usize).unwrap();
        task::Builder::new("m").priority(3).domain(d).stack(&US2).spawn_user(rng_hungry, 0).unwrap();
    });
    assert_eq!(
        take(),
        [
            "plain spawn: Some(PermissionDenied)",
            "unaligned stack: Some(Invalid)",
            "kernel user task: Some(Invalid)",
            "starting",
            "killed=true violations=1",
        ]
    );
}
