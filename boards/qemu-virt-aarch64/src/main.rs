//! Bismuth on QEMU `-M virt` (aarch64 Cortex-A53) — the first application-class ARM board.
//!
//! The AArch64 port's `_start` drops to EL1 and builds the per-page translation tables; this
//! `kernel_main` brings up the PL011 console (the in-tree `arm,pl011` driver, unchanged) and
//! runs a demo: two EL1 workers preempted by the generic timer; a **sandboxed EL0 task** that
//! runs unprivileged, reads a granted device and has an unauthorized write denied; and a
//! **rogue EL0 task** whose read of kernel memory aborts and kills only its own domain while
//! the kernel keeps running. Then it exits QEMU via semihosting.
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::arch::mmio::Mmio;
use bismuth::driver::sensor::SimSensor;
use bismuth::driver::{self, Device, DeviceDesc, FACTORIES, char::pl011};
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskId, Timeout, UserStack2K, kprintln, task, user};

/// The one place hardware addresses are asserted. QEMU `virt`: PL011 UART0 at 0x0900_0000,
/// routed to GIC SPI 1 (interrupt 32 + 1).
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "uart0",
    compatible: "arm,pl011",
    // SAFETY: UART0 of QEMU `virt` lives at 0x0900_0000 and is used only via this window.
    mmio: Some(unsafe { Mmio::new(0x0900_0000, pl011::REGISTER_SPAN) }),
    irq: 33,
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

/// A well-behaved EL0 task: it reaches the kernel only through syscalls.
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

/// A misbehaving EL0 task: reading kernel memory aborts (EL1-only page) and kills its domain.
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
    kprintln!("[done] waiting for EL0 tasks...");
    let app_exit = task::join(app, Timeout::ms(5000));
    let app_ok = app_exit == Ok(0) && !security::is_killed(app_domain) && security::faults(app_domain) == 0;
    let rogue_killed = security::is_killed(rogue_domain) && security::faults(rogue_domain) > 0;
    kprintln!("sandbox: exit={app_exit:?} killed={} faults={}", security::is_killed(app_domain), security::faults(app_domain));
    kprintln!("rogue:   killed={} faults={}", security::is_killed(rogue_domain), security::faults(rogue_domain));
    if app_ok && rogue_killed {
        kprintln!("aarch64 EL0 demo complete: preemption, sandboxed syscalls, and fault-kills-domain verified. PASS");
        #[cfg(feature = "interactive")]
        {
            // Hand the console to the interactive shell instead of exiting.
            let _ = bismuth::shell::run("uart0");
        }
        #[cfg(not(feature = "interactive"))]
        bismuth::arch::aarch64::qemu_exit(0);
    } else {
        kprintln!("aarch64 EL0 demo FAILED (app_ok={app_ok} rogue_killed={rogue_killed})");
        bismuth::arch::aarch64::qemu_exit(1);
    }
}

/// QEMU `virt` memory layout: peripherals (GIC @ 0x0800_0000, PL011 @ 0x0900_0000) in the
/// low GiB, RAM at 0x4000_0000. GICv2: GICD @ 0x0800_0000, GICC @ 0x0801_0000.
#[unsafe(no_mangle)]
pub extern "C" fn bismuth_board_map() -> bismuth::arch::aarch64::BoardMap {
    bismuth::arch::aarch64::BoardMap {
        ram_base: 0x4000_0000,
        ram_size: 0x4000_0000, // 1 GiB (QEMU virt default)
        periph_base: 0x0000_0000,
        periph_size: 0x4000_0000,
        intc: 0, // GIC
        gicd: 0x0800_0000,
        gicc: 0x0801_0000,
    }
}

/// Entry from the port's `_start` (symbol fixed by the `_start` → `kernel_main` contract).
/// Scan the QEMU `virt` virtio-MMIO transport slots for a block device and round-trip a
/// sector through it (verifies the virtio-blk driver when run with `-drive`).
fn virtio_blk_test() {
    use bismuth::driver::block::BlockDevice;
    use bismuth::driver::block::virtio_mmio::VirtioBlk;
    for i in 0..32u64 {
        let base = 0x0a00_0000 + i * 0x200;
        // SAFETY: a QEMU `virt` virtio-MMIO transport window.
        let regs = unsafe { Mmio::new(base as usize, 0x200) };
        if let Ok(dev) = VirtioBlk::probe(regs) {
            kprintln!("virtio-blk: device at {base:#x}, {} sectors", dev.geometry().block_count);
            let mut pat = [0u8; 512];
            for (j, b) in pat.iter_mut().enumerate() {
                *b = (j as u8).wrapping_mul(7) ^ 0x5A;
            }
            let mut back = [0u8; 512];
            let ok = dev.prog(10, 0, &pat).is_ok() && dev.read(10, 0, &mut back).is_ok() && back == pat;
            kprintln!("virtio-blk: sector round-trip {}", if ok { "OK" } else { "FAILED" });
            return;
        }
    }
    kprintln!("virtio-blk: no device attached");
}

/// Scan the virtio-MMIO slots for a network device and do one real round-trip: broadcast an
/// ARP request for the QEMU SLIRP gateway (10.0.2.2) and wait for its reply — exercising both
/// the transmit and the receive virtqueues (verifies virtio-net when run with `-netdev user`).
fn virtio_net_test() {
    use bismuth::net::FrameDevice;
    use bismuth::net::drivers::VirtioNet;
    for i in 0..32u64 {
        let base = 0x0a00_0000 + i * 0x200;
        // SAFETY: a QEMU `virt` virtio-MMIO transport window.
        let regs = unsafe { Mmio::new(base as usize, 0x200) };
        let Ok(nic) = VirtioNet::probe(regs) else { continue };
        let mac = nic.mac().0;
        kprintln!(
            "virtio-net: device at {base:#x}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        // Ethernet (14) + ARP (28). who-has 10.0.2.2, tell 10.0.2.15.
        let mut f = [0u8; 42];
        f[0..6].copy_from_slice(&[0xFF; 6]); // dst: broadcast
        f[6..12].copy_from_slice(&mac); // src: us
        f[12..14].copy_from_slice(&[0x08, 0x06]); // ethertype ARP
        f[14..16].copy_from_slice(&[0x00, 0x01]); // htype Ethernet
        f[16..18].copy_from_slice(&[0x08, 0x00]); // ptype IPv4
        f[18] = 6; // hlen
        f[19] = 4; // plen
        f[20..22].copy_from_slice(&[0x00, 0x01]); // op request
        f[22..28].copy_from_slice(&mac); // sender hw
        f[28..32].copy_from_slice(&[10, 0, 2, 15]); // sender ip
        // target hw = 0; target ip:
        f[38..42].copy_from_slice(&[10, 0, 2, 2]);
        if nic.send(&f).is_err() {
            kprintln!("virtio-net: ARP transmit FAILED");
            return;
        }
        let mut rx = [0u8; 1536];
        for _ in 0..2_000_000 {
            if let Some(n) = nic.recv(&mut rx) {
                // An ARP reply (ethertype 0x0806, op 2) from the gateway.
                if n >= 42 && rx[12] == 0x08 && rx[13] == 0x06 && rx[21] == 0x02 {
                    kprintln!(
                        "virtio-net: ARP reply from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} — gateway 10.0.2.2 is at that MAC. OK",
                        rx[22], rx[23], rx[24], rx[25], rx[26], rx[27]
                    );
                    return;
                }
            }
            core::hint::spin_loop();
        }
        kprintln!("virtio-net: no ARP reply (link may be unconfigured)");
        return;
    }
    kprintln!("virtio-net: no device attached");
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    driver::probe_all(&BOARD, FACTORIES);
    if let Ok(uart) = Device::find("uart0") {
        bismuth::console::set_device(uart);
    }
    bismuth::console::boot_logo();
    virtio_blk_test();
    virtio_net_test();
    kprintln!("Bismuth {} on QEMU virt (aarch64 Cortex-A53) — stage 3: EL0 user tasks", env!("CARGO_PKG_VERSION"));

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
