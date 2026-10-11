//! Bismuth on QEMU x86-64 (`qemu-system-x86_64`), booted via the rust-osdev `bootloader`
//! crate.
//!
//! The bootloader enters long mode and hands us a framebuffer + memory map; the x86-64 port
//! brings up the 16550 serial console, installs its own GDT/TSS + IDT, starts the PIT tick,
//! context-switches, and sets up ring-3 paging isolation. This demo shows: two equal-priority
//! workers preempted round-robin by the timer; a **sandboxed ring-3 task** that runs
//! unprivileged, reads a granted device and has an unauthorized write denied by the kernel;
//! and a **rogue ring-3 task** whose attempt to read kernel memory faults and kills only its
//! own domain — the kernel keeps running. Then it exits QEMU. All observable on serial.
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::driver::sensor::SimSensor;
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskId, Timeout, UserStack2K, kprintln, task, user};
use bootloader_api::config::Mapping;

// Ask the bootloader to direct-map all physical memory, so the kernel can walk and edit the
// page tables (needed to open ring-3 access to its code + each user task's stack).
static CONFIG: bootloader_api::BootloaderConfig = {
    let mut c = bootloader_api::BootloaderConfig::new_default();
    c.mappings.physical_memory = Some(Mapping::Dynamic);
    c
};

bootloader_api::entry_point!(kernel_main, config = &CONFIG);

static SA: Stack<4096> = Stack::new();
static SB: Stack<4096> = Stack::new();
static SD: Stack<4096> = Stack::new();
static S_APP: UserStack2K = UserStack2K::new();
static S_ROGUE: UserStack2K = UserStack2K::new();

// A device the sandboxed task is granted (read-only).
static SENSOR: SimSensor = SimSensor::new(1);

// Hand-off of the spawned IDs to the (non-capturing) finisher task.
static APP_TASK: AtomicU32 = AtomicU32::new(0);
static APP_DOMAIN: AtomicU32 = AtomicU32::new(0);
static ROGUE_DOMAIN: AtomicU32 = AtomicU32::new(0);

fn worker_a(_: usize) {
    for i in 0..4 {
        kprintln!("[A] step {i}");
        task::sleep_ticks(60);
    }
}

fn worker_b(_: usize) {
    for i in 0..4 {
        kprintln!("[B] step {i}");
        task::sleep_ticks(60);
    }
}

/// A well-behaved unprivileged (ring-3) task: it reaches the kernel only through syscalls.
extern "C-unwind" fn sandboxed(_: usize) {
    user::log(b"[ring3] user task running unprivileged\n");
    let h = match user::open("env") {
        Ok(h) => h,
        Err(e) => user::exit(100 + e.errno() as usize),
    };
    let mut raw = [0u8; 4];
    if user::read(h, &mut raw, Timeout::Forever) != Ok(4) {
        user::exit(2);
    }
    // The capability grants READ only; a write must be refused by the kernel.
    if user::write(h, b"x") != Err(bismuth::Error::PermissionDenied) {
        user::exit(3);
    }
    user::log(b"[ring3] sensor read ok; unauthorized write denied by the kernel\n");
    user::exit(0)
}

/// A misbehaving unprivileged task: it tries to read kernel memory. In ring 3 that address is
/// supervisor-only, so the read faults; the kernel kills this task's domain and carries on.
extern "C-unwind" fn rogue(_: usize) {
    user::log(b"[ring3] rogue task attempts to read kernel memory...\n");
    let kernel_ptr = &SENSOR as *const SimSensor as *const u8;
    // SAFETY (demo): this is deliberately illegal from ring 3. The access must page-fault and
    // never return here; if isolation were broken the line below would print.
    let _ = unsafe { core::ptr::read_volatile(kernel_ptr) };
    user::log(b"[ring3] ERROR: rogue read succeeded - isolation is broken!\n");
    user::exit(0)
}

fn finisher(_: usize) {
    let app = TaskId::from_raw(APP_TASK.load(Ordering::Relaxed));
    let app_domain = DomainId(APP_DOMAIN.load(Ordering::Relaxed) as u8);
    let rogue_domain = DomainId(ROGUE_DOMAIN.load(Ordering::Relaxed) as u8);
    kprintln!("[done] waiting for ring-3 tasks...");
    let app_exit = task::join(app, Timeout::ms(5000));
    let app_ok = app_exit == Ok(0) && !security::is_killed(app_domain) && security::faults(app_domain) == 0;
    // The rogue task never exits cleanly; its domain must be killed with a recorded fault.
    let rogue_killed = security::is_killed(rogue_domain) && security::faults(rogue_domain) > 0;

    kprintln!("sandbox: exit={app_exit:?} killed={} faults={}", security::is_killed(app_domain), security::faults(app_domain));
    kprintln!("rogue:   killed={} faults={}", security::is_killed(rogue_domain), security::faults(rogue_domain));

    if app_ok && rogue_killed {
        kprintln!("x86-64 ring-3 demo complete: preemption, sandboxed syscalls, and fault-kills-domain all verified. PASS");
        bismuth::arch::x86_64::debug_exit(0);
    } else {
        kprintln!("x86-64 ring-3 demo FAILED (app_ok={app_ok} rogue_killed={rogue_killed})");
        bismuth::arch::x86_64::debug_exit(1);
    }
}

fn kernel_main(boot_info: &'static mut bootloader_api::BootInfo) -> ! {
    bismuth::arch::x86_64::init_console();
    bismuth::console::boot_logo();
    kprintln!("Bismuth {} on x86-64 (QEMU) — stage 3: GDT/TSS + ring-3 user tasks", env!("CARGO_PKG_VERSION"));
    let phys_offset = boot_info.physical_memory_offset.into_option().expect("physical memory not mapped");
    bismuth::arch::x86_64::init_memory(phys_offset, boot_info.kernel_image_offset, boot_info.kernel_len);

    // Two sandboxed domains (so killing the rogue cannot touch the well-behaved task), set up
    // and sealed before any unprivileged task is spawned.
    let app_domain = security::create_domain(DomainSpec::sandboxed("app", 4, 1)).unwrap();
    let rogue_domain = security::create_domain(DomainSpec::sandboxed("rogue", 4, 1)).unwrap();
    let dev = bismuth::driver::register("envx", &SENSOR).expect("register sensor");
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
    bismuth::start(1_000_000)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    kprintln!("PANIC: {info}");
    loop {
        core::hint::spin_loop();
    }
}

// The kernel's user-task entry type uses the `C-unwind` ABI, which references the unwinding
// personality even under `panic = "abort"`; the bare x86 target provides none, so stub it.
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}
