//! Bismuth on the Raspberry Pi 5 (BCM2712, Cortex-A76, AArch64).
//!
//! Reuses the aarch64 Cortex-A port (as the Pi 3/4 and Jetson do); only the board memory map
//! differs. BCM2712 is a 40-bit map: RAM low at 0x0, a GIC-400 and the debug PL011 (UART10)
//! in the SoC peripheral window at 0x10_7c00_0000+. **There is no QEMU `raspi5` machine, so
//! this board is build-verified only** — the addresses are taken from the BCM2712 device tree
//! and must be confirmed on real hardware (see `docs/pi5-bringup.md`). Most Pi 5 I/O lives
//! behind the RP1 southbridge over PCIe and is out of scope here; this brings up the core
//! kernel + serial console + the EL0 sandbox, as on the other aarch64 boards.
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::arch::mmio::Mmio;
use bismuth::driver::sensor::SimSensor;
use bismuth::driver::{self, Device, DeviceDesc, FACTORIES, char::pl011};
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskId, Timeout, UserStack2K, kprintln, task, user};

/// BCM2712 debug UART (UART10, PL011) at 0x10_7d00_1000 (SoC window 0x10_7c00_0000 + 0x1001000).
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "uart0",
    compatible: "arm,pl011",
    // SAFETY: the BCM2712 debug PL011 window per the device tree (tentative; verify on HW).
    mmio: Some(unsafe { Mmio::new(0x10_7d00_1000, pl011::REGISTER_SPAN) }),
    irq: 0,
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
    user::exit(0)
}

fn finisher(_: usize) {
    let app = TaskId::from_raw(APP_TASK.load(Ordering::Relaxed));
    let app_domain = DomainId(APP_DOMAIN.load(Ordering::Relaxed) as u8);
    let rogue_domain = DomainId(ROGUE_DOMAIN.load(Ordering::Relaxed) as u8);
    let app_exit = task::join(app, Timeout::ms(5000));
    let ok = app_exit == Ok(0) && !security::is_killed(app_domain) && security::is_killed(rogue_domain) && security::faults(rogue_domain) > 0;
    kprintln!("Raspberry Pi 5 (BCM2712) demo: app={app_exit:?} rogue_killed={}", security::is_killed(rogue_domain));
    bismuth::arch::aarch64::qemu_exit(if ok { 0 } else { 1 });
}

/// BCM2712 memory layout (tentative; from the device tree, verify on hardware): RAM at 0x0,
/// GIC-400 + debug PL011 in the SoC window near 0x10_7c00_0000 (GiB 65), mapped Device.
#[unsafe(no_mangle)]
pub extern "C" fn bismuth_board_map() -> bismuth::arch::aarch64::BoardMap {
    bismuth::arch::aarch64::BoardMap {
        ram_base: 0x0,
        ram_size: 0x2_0000_0000, // 8 GiB
        periph_base: 0x10_4000_0000, // GiB 65: covers 0x10_7c00_0000 peripherals + GIC
        periph_size: 0x4000_0000,
        intc: bismuth::arch::aarch64::intc::KIND_GIC as u64,
        gicd: 0x10_7fff_9000,
        gicc: 0x10_7fff_a000,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    driver::probe_all(&BOARD, FACTORIES);
    if let Ok(uart) = Device::find("uart0") {
        bismuth::console::set_device(uart);
    }
    bismuth::console::boot_logo();
    kprintln!("Bismuth {} on Raspberry Pi 5 (BCM2712, Cortex-A76) — aarch64 EL0 (build-verified)", env!("CARGO_PKG_VERSION"));

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
    let _ = (&SB, &SD);
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
