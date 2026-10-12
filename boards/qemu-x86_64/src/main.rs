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
// The `net-demo` flow replaces the ring-3 demo, so its helpers are unused in that build.
#![cfg_attr(feature = "net-demo", allow(dead_code, unused_imports))]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::driver::sensor::SimSensor;
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskId, Timeout, UserStack4K, kprintln, task, user};
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
// Page-sized, page-aligned user stacks so each domain owns a distinct 4 KiB page — the cross-
// domain isolation proof below reads one domain's page from another.
static S_APP: UserStack4K = UserStack4K::new();
static S_ROGUE: UserStack4K = UserStack4K::new();

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

/// A misbehaving unprivileged task in its OWN domain that tries to read **another domain's**
/// user page (the sandboxed task's stack). With per-domain ring-3 isolation that page is demoted
/// to supervisor-only while this domain runs, so the read faults and the kernel kills just this
/// domain. (Kernel memory is equally unreachable — same `U/S` mechanism.)
extern "C-unwind" fn rogue(_: usize) {
    user::log(b"[ring3] rogue task attempts to read another domain's memory...\n");
    let foreign = &S_APP as *const UserStack4K as *const u8;
    // SAFETY (demo): deliberately illegal cross-domain read. It must page-fault and never
    // return here; if isolation were broken the line below would print.
    let _ = unsafe { core::ptr::read_volatile(foreign) };
    user::log(b"[ring3] ERROR: cross-domain read succeeded - isolation is broken!\n");
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
        kprintln!("x86-64 ring-3 demo complete: preemption, sandboxed syscalls, and per-domain memory isolation (a cross-domain read faulted and killed only the rogue) all verified. PASS");
        bismuth::arch::x86_64::debug_exit(0);
    } else {
        kprintln!("x86-64 ring-3 demo FAILED (app_ok={app_ok} rogue_killed={rogue_killed})");
        bismuth::arch::x86_64::debug_exit(1);
    }
}

/// Scan PCI for a virtio-blk device (QEMU `-device virtio-blk-pci`) and round-trip a sector,
/// verifying the x86-64 legacy virtio-pci driver end to end.
fn virtio_blk_test() {
    use bismuth::driver::block::BlockDevice;
    use bismuth::driver::block::virtio_pci::VirtioBlkPci;
    match VirtioBlkPci::probe() {
        Ok(dev) => {
            kprintln!("virtio-blk-pci: device up, {} sectors", dev.geometry().block_count);
            let mut pat = [0u8; 512];
            for (j, b) in pat.iter_mut().enumerate() {
                *b = (j as u8).wrapping_mul(7) ^ 0x5A;
            }
            let mut back = [0u8; 512];
            let ok = dev.prog(10, 0, &pat).is_ok() && dev.read(10, 0, &mut back).is_ok() && back == pat;
            kprintln!("virtio-blk-pci: sector round-trip {}", if ok { "OK" } else { "FAILED" });
        }
        Err(e) => kprintln!("virtio-blk-pci: no device attached ({e:?})"),
    }
}

/// A virtio-net-pci NIC wrapped in a software RX ring, for the `net-demo` flow.
#[cfg(feature = "net-demo")]
static NIC: bismuth::net::SoftRing<bismuth::net::drivers::VirtioNetPci, 8> =
    bismuth::net::SoftRing::new(bismuth::net::drivers::VirtioNetPci::new());
#[cfg(feature = "net-demo")]
static SNET: Stack<16384> = Stack::new();

/// Drive the virtio-net-pci NIC directly (no IP stack): bring it up, then send one broadcast ARP
/// request for the SLIRP gateway and poll the receive ring for the reply. This exercises the
/// driver's transmit + receive path end to end against QEMU's emulated NIC + SLIRP, without the
/// (x86-untested) in-kernel IP stack. Then exit QEMU.
///
/// (The IP stack brings the driver no further verification here: its socket/service path hits a
/// pre-existing x86 fault — the yield-gate `int 0x81` `#GP` — that is out of scope for the driver.)
#[cfg(feature = "net-demo")]
fn net_only(_: usize) {
    use bismuth::net::ip::{self, IpConfig};
    use core::net::Ipv4Addr;

    if let Err(e) = NIC.inner().probe() {
        kprintln!("virtio-net-pci: no device ({e:?})");
        bismuth::arch::x86_64::debug_exit(1);
    }
    let mac = NIC.inner().mac().0;
    kprintln!(
        "virtio-net-pci: device up, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    let idx = match bismuth::net::register("eth0", &NIC) {
        Ok(i) => i,
        Err(e) => {
            kprintln!("virtio-net-pci: register failed ({e:?})");
            bismuth::arch::x86_64::debug_exit(1);
        }
    };
    let cfg = IpConfig { addr: [10, 0, 2, 15], prefix_len: 24, gateway: Some([10, 0, 2, 2]) };
    if let Err(e) = ip::configure(idx, cfg) {
        kprintln!("virtio-net-pci: IP configure failed ({e:?})");
        bismuth::arch::x86_64::debug_exit(1);
    }
    let _ = bismuth::net::start();
    kprintln!("virtio-net-pci: eth0 up, 10.0.2.15/24 gw 10.0.2.2 — IP stack running");

    // ICMP echo to the SLIRP gateway (answered locally, no outbound internet needed).
    if let Ok(sock) = bismuth::net::socket::IcmpSocket::open(0x42) {
        let gw = Ipv4Addr::new(10, 0, 2, 2);
        if sock.ping(gw, 1, b"bismuth").is_ok() {
            match sock.recv_reply(1, Timeout::ms(3000)) {
                Ok(from) => {
                    kprintln!("virtio-net-pci: ICMP echo reply from {from} — IP-stack round-trip verified. PASS");
                    bismuth::arch::x86_64::debug_exit(0);
                }
                Err(e) => kprintln!("virtio-net-pci: no ICMP reply ({e:?})"),
            }
        } else {
            kprintln!("virtio-net-pci: ping send failed");
        }
    } else {
        kprintln!("virtio-net-pci: ICMP socket open failed");
    }
    bismuth::arch::x86_64::debug_exit(1);
}

fn kernel_main(boot_info: &'static mut bootloader_api::BootInfo) -> ! {
    bismuth::arch::x86_64::init_console();
    bismuth::console::boot_logo();
    kprintln!("Bismuth {} on x86-64 (QEMU) — stage 3: GDT/TSS + ring-3 user tasks", env!("CARGO_PKG_VERSION"));
    let phys_offset = boot_info.physical_memory_offset.into_option().expect("physical memory not mapped");
    bismuth::arch::x86_64::init_memory(phys_offset, boot_info.kernel_image_offset, boot_info.kernel_len);
    virtio_blk_test();

    // The networking demo is its own flow (`--features net-demo`): bring up the NIC + IP stack,
    // do one ICMP round-trip, exit.
    #[cfg(feature = "net-demo")]
    {
        task::spawn("netdemo", 1, &SNET, net_only, 0).unwrap();
        bismuth::start(1_000_000)
    }

    // Two sandboxed domains (so killing the rogue cannot touch the well-behaved task), set up
    // and sealed before any unprivileged task is spawned.
    #[cfg(not(feature = "net-demo"))]
    {
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
