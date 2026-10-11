//! Bismuth on the NVIDIA Jetson Nano (Tegra X1, 4× Cortex-A57, AArch64).
//!
//! Same AArch64 port as the Raspberry Pi / QEMU `virt` boards. Tegra differs in two ways the
//! board layer captures: the console is an **NS16550** UART (UART-A at 0x7000_6000), not a
//! PL011, and the GIC-400 lives at 0x5004_xxxx with RAM at 0x8000_0000. There is no QEMU
//! machine for the Jetson, so this board is **build-verified**; it runs on real hardware
//! loaded via U-Boot/CBoot. The demo is identical to the Pi boards (EL1 workers + an EL0
//! sandbox with fault-kills-domain).
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::arch::mmio::Mmio;
use bismuth::driver::sensor::SimSensor;
use bismuth::driver::{self, Device, DeviceDesc, FACTORIES, char::ns16550};
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskId, Timeout, UserStack2K, kprintln, task, user};

/// Tegra X1 UART-A (NS16550, 32-bit-spaced registers) at 0x7000_6000.
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "uart0",
    compatible: "ns16550",
    // SAFETY: UART-A of the Tegra X1 lives at 0x7000_6000 and is used only via this window.
    mmio: Some(unsafe { Mmio::new(0x7000_6000, ns16550::REGISTER_SPAN) }),
    irq: 68,
    params: &[("baud", 115_200)],
}];

static SA: Stack<16384> = Stack::new();
static SB: Stack<16384> = Stack::new();
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

fn worker_b(_: usize) {
    for i in 0..3 {
        kprintln!("[B] step {i}");
        task::sleep_ticks(60);
    }
}

extern "C-unwind" fn sandboxed(_: usize) {
    user::log(b"[el0] user task running unprivileged\n");
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
    user::log(b"[el0] sensor read ok; unauthorized write denied by the kernel\n");
    user::exit(0)
}

extern "C-unwind" fn rogue(_: usize) {
    user::log(b"[el0] rogue task attempts to read kernel memory...\n");
    let kernel_ptr = &SENSOR as *const SimSensor as *const u8;
    // SAFETY (demo): deliberately illegal from EL0; the access must abort and never return.
    let _ = unsafe { core::ptr::read_volatile(kernel_ptr) };
    user::log(b"[el0] ERROR: rogue read succeeded - isolation is broken!\n");
    user::exit(0)
}

fn finisher(_: usize) {
    let app = TaskId::from_raw(APP_TASK.load(Ordering::Relaxed));
    let app_domain = DomainId(APP_DOMAIN.load(Ordering::Relaxed) as u8);
    let rogue_domain = DomainId(ROGUE_DOMAIN.load(Ordering::Relaxed) as u8);
    let app_exit = task::join(app, Timeout::ms(5000));
    let app_ok = app_exit == Ok(0) && !security::is_killed(app_domain) && security::faults(app_domain) == 0;
    let rogue_killed = security::is_killed(rogue_domain) && security::faults(rogue_domain) > 0;
    kprintln!("sandbox: exit={app_exit:?} rogue_killed={rogue_killed}");
    if app_ok && rogue_killed {
        kprintln!("Jetson Nano (Tegra X1) demo complete. PASS");
        bismuth::arch::aarch64::qemu_exit(0);
    } else {
        bismuth::arch::aarch64::qemu_exit(1);
    }
}

/// Tegra X1 memory layout: RAM at 0x8000_0000, peripherals (GIC-400 @ 0x5004_xxxx, UART-A @
/// 0x7000_6000) in the 0x4000_0000–0x8000_0000 GiB, which we map as Device.
#[unsafe(no_mangle)]
pub extern "C" fn bismuth_board_map() -> bismuth::arch::aarch64::BoardMap {
    bismuth::arch::aarch64::BoardMap {
        ram_base: 0x8000_0000,
        ram_size: 0x8000_0000, // 2 GiB mapped
        periph_base: 0x4000_0000,
        periph_size: 0x4000_0000,
        intc: bismuth::arch::aarch64::intc::KIND_GIC as u64,
        gicd: 0x5004_1000,
        gicc: 0x5004_2000,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    driver::probe_all(&BOARD, FACTORIES);
    if let Ok(uart) = Device::find("uart0") {
        bismuth::console::set_device(uart);
    }
    bismuth::console::boot_logo();
    kprintln!("Bismuth {} on Jetson Nano (Tegra X1, Cortex-A57) — aarch64 EL0", env!("CARGO_PKG_VERSION"));

    let app_domain = security::create_domain(DomainSpec::sandboxed("app", 4, 1)).unwrap();
    let rogue_domain = security::create_domain(DomainSpec::sandboxed("rogue", 4, 1)).unwrap();
    let dev = driver::register("envx", &SENSOR).expect("register sensor");
    security::grant_device(app_domain, dev, Rights::READ, "env").unwrap();
    security::seal().unwrap();

    task::spawn("a", 3, &SA, worker_a, 0).unwrap();
    task::spawn("b", 3, &SB, worker_b, 0).unwrap();
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
