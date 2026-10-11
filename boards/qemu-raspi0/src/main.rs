//! Bismuth on the Raspberry Pi 2 (BCM2835, ARM1176, ARMv6 32-bit), via QEMU `raspi2b`.
//!
//! The AArch32 Cortex-A port (`cortex-a` feature) at stage 3: USR-mode (EL0-equivalent) user
//! tasks confined by the CP15 MMU, an `SVC` syscall gate, and USR aborts that kill only the
//! offending domain. Demonstrates EL1 preemption, a sandboxed user task (granted a device,
//! unauthorized write denied), and a rogue user task whose kernel-memory read is killed.
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::arch::mmio::Mmio;
use bismuth::driver::sensor::SimSensor;
use bismuth::driver::{self, Device, DeviceDesc, FACTORIES, char::pl011};
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskId, Timeout, UserStack2K, kprintln, task, user};

/// BCM2835 PL011 UART0 at 0x2020_1000.
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "uart0",
    compatible: "arm,pl011",
    // SAFETY: UART0 of the BCM2835 lives at 0x2020_1000 and is used only via this window.
    mmio: Some(unsafe { Mmio::new(0x2020_1000, pl011::REGISTER_SPAN) }),
    irq: 57,
    params: &[("baud", 115_200)],
}];

static SA: Stack<16384> = Stack::new();
static SD: Stack<16384> = Stack::new();
static S_APP: UserStack2K = UserStack2K::new();
static S_ROGUE: UserStack2K = UserStack2K::new();

static SENSOR: SimSensor = SimSensor::new(1);
static APP_TASK: AtomicU32 = AtomicU32::new(0);
static APP_DOMAIN: AtomicU32 = AtomicU32::new(0);
static ROGUE_DOMAIN: AtomicU32 = AtomicU32::new(0);

fn worker_a(_: usize) {
    for i in 0..3 {
        kprintln!("[A] step {i}");
        task::sleep_ticks(60);
    }
}

extern "C-unwind" fn sandboxed(_: usize) {
    user::log(b"[usr] user task running unprivileged\n");
    let h = match user::open("env") {
        Ok(h) => h,
        Err(e) => user::exit(100 + e.errno() as usize),
    };
    let mut raw = [0u8; 4];
    if user::read(h, &mut raw, Timeout::Forever) != Ok(4) {
        user::exit(2);
    }
    if user::write(h, b"x") != Err(bismuth::Error::PermissionDenied) {
        user::exit(3);
    }
    user::log(b"[usr] sensor read ok; unauthorized write denied by the kernel\n");
    user::exit(0)
}

extern "C-unwind" fn rogue(_: usize) {
    user::log(b"[usr] rogue task attempts to read kernel memory...\n");
    let kernel_ptr = &SENSOR as *const SimSensor as *const u8;
    // SAFETY (demo): deliberately illegal from USR mode; the access must abort and not return.
    let _ = unsafe { core::ptr::read_volatile(kernel_ptr) };
    user::log(b"[usr] ERROR: rogue read succeeded - isolation is broken!\n");
    user::exit(0)
}

fn finisher(_: usize) {
    let app = TaskId::from_raw(APP_TASK.load(Ordering::Relaxed));
    let app_domain = DomainId(APP_DOMAIN.load(Ordering::Relaxed) as u8);
    let rogue_domain = DomainId(ROGUE_DOMAIN.load(Ordering::Relaxed) as u8);
    let app_exit = task::join(app, Timeout::ms(5000));
    let app_ok = app_exit == Ok(0) && !security::is_killed(app_domain) && security::faults(app_domain) == 0;
    let rogue_killed = security::is_killed(rogue_domain) && security::faults(rogue_domain) > 0;
    kprintln!("sandbox: exit={app_exit:?} killed={} faults={}", security::is_killed(app_domain), security::faults(app_domain));
    kprintln!("rogue:   killed={} faults={}", security::is_killed(rogue_domain), security::faults(rogue_domain));
    if app_ok && rogue_killed {
        kprintln!("Raspberry Pi Zero (ARMv6) stage 3 complete: USR tasks, syscalls, and abort-kills-domain verified. PASS");
        bismuth::arch::cortex_a::qemu_exit(0);
    } else {
        kprintln!("Raspberry Pi Zero stage 3 FAILED (app_ok={app_ok} rogue_killed={rogue_killed})");
        bismuth::arch::cortex_a::qemu_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    driver::probe_all(&BOARD, FACTORIES);
    if let Ok(uart) = Device::find("uart0") {
        bismuth::console::set_device(uart);
    }
    bismuth::console::boot_logo();
    kprintln!("Bismuth {} on Raspberry Pi 2 (BCM2835, ARM1176, ARMv6) — stage 3: USR tasks", env!("CARGO_PKG_VERSION"));

    let app_domain = security::create_domain(DomainSpec::sandboxed("app", 4, 1)).unwrap();
    let rogue_domain = security::create_domain(DomainSpec::sandboxed("rogue", 4, 1)).unwrap();
    let dev = driver::register("envx", &SENSOR).expect("register sensor");
    security::grant_device(app_domain, dev, Rights::READ, "env").unwrap();
    security::seal().unwrap();

    task::spawn("a", 3, &SA, worker_a, 0).unwrap();
    let app = task::Builder::new("sandboxed").priority(2).domain(app_domain).stack(&S_APP).spawn_user(sandboxed, 0).unwrap();
    task::Builder::new("rogue").priority(2).domain(rogue_domain).stack(&S_ROGUE).spawn_user(rogue, 0).unwrap();
    APP_TASK.store(app.as_raw(), Ordering::Relaxed);
    APP_DOMAIN.store(app_domain.0 as u32, Ordering::Relaxed);
    ROGUE_DOMAIN.store(rogue_domain.0 as u32, Ordering::Relaxed);
    task::spawn("done", 1, &SD, finisher, 0).unwrap();
    bismuth::start(0)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    kprintln!("PANIC: {info}");
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}
