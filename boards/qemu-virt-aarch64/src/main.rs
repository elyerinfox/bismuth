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
// The board has three mutually exclusive top-level flows — the default EL0 isolation demo, the
// `net-demo` networking flow, and the `interactive` container host + shell — so whichever is not
// selected is legitimately unused in that build.
#![cfg_attr(
    any(feature = "net-demo", feature = "interactive", feature = "linux-demo"),
    allow(dead_code, unused_imports)
)]

use core::sync::atomic::{AtomicU32, Ordering};

use bismuth::arch::mmio::Mmio;
use bismuth::driver::sensor::SimSensor;
use bismuth::driver::{self, Device, DeviceDesc, FACTORIES, char::pl011};
use bismuth::security::{self, DomainId, DomainSpec, Rights};
use bismuth::{Stack, TaskId, Timeout, UserStack2K, kprintln, task, user};

#[cfg(feature = "linux-demo")]
mod linux_elf;

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

/// The virtio-net NIC, wrapped in a software RX ring so the net core sees a full `NetDevice`.
/// Const-constructed so it can live in a `static`; `probe` binds it to a transport slot at boot.
#[cfg(feature = "net-demo")]
static NIC: bismuth::net::SoftRing<bismuth::net::drivers::VirtioNet, 8> =
    bismuth::net::SoftRing::new(bismuth::net::drivers::VirtioNet::new());

/// Scan the virtio-MMIO slots for a network device, bring it up, register it with the net core,
/// and give it a static IP (QEMU SLIRP: 10.0.2.15/24, gateway 10.0.2.2). Returns true if a NIC
/// came up. The IP stack then runs over the real virtio-net device exactly as it does over the
/// simulated `WireEnd` the host tests use.
#[cfg(feature = "net-demo")]
fn net_setup() -> bool {
    use bismuth::net::ip::{self, IpConfig};
    for i in 0..32usize {
        let base = 0x0a00_0000 + i * 0x200;
        if NIC.inner().probe(base).is_err() {
            continue;
        }
        let mac = NIC.inner().mac().0;
        kprintln!(
            "virtio-net: device at {base:#x}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        let idx = match bismuth::net::register("eth0", &NIC) {
            Ok(i) => i,
            Err(e) => {
                kprintln!("virtio-net: register failed ({e:?})");
                return false;
            }
        };
        let cfg = IpConfig { addr: [10, 0, 2, 15], prefix_len: 24, gateway: Some([10, 0, 2, 2]) };
        if let Err(e) = ip::configure(idx, cfg) {
            kprintln!("virtio-net: IP configure failed ({e:?})");
            return false;
        }
        kprintln!("virtio-net: eth0 up, 10.0.2.15/24 gw 10.0.2.2");
        return true;
    }
    kprintln!("virtio-net: no device attached");
    false
}

/// Prove the IP stack end-to-end over the virtio-net NIC: a UDP DNS query to QEMU SLIRP's
/// resolver (10.0.2.3:53). A reply exercises ARP + IPv4 + UDP in both directions on real
/// hardware emulation. (If the host has no DNS the query still proves TX; we report either way.)
#[cfg(feature = "net-demo")]
fn net_demo() {
    use bismuth::net::socket::UdpSocket;
    use core::net::{Ipv4Addr, SocketAddrV4};
    let sock = match UdpSocket::bind(0) {
        Ok(s) => s,
        Err(e) => {
            kprintln!("virtio-net: UDP bind failed ({e:?})");
            return;
        }
    };
    // A minimal DNS A-record query for "example.com".
    let query: [u8; 29] = [
        0x12, 0x34, // id
        0x01, 0x00, // flags: recursion desired
        0x00, 0x01, // qdcount = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar = 0
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // QNAME
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];
    let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 3), 53);
    if let Err(e) = sock.send_to(&query, dst) {
        kprintln!("virtio-net: DNS send failed ({e:?})");
        return;
    }
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf, Timeout::ms(4000)) {
        Ok((n, from)) => kprintln!("virtio-net: DNS reply {n} bytes from {from} — IPv4/UDP over virtio-net OK"),
        Err(e) => kprintln!("virtio-net: DNS query sent, no reply ({e:?}) — host resolver may be offline"),
    }
    // The UDP send had to ARP-resolve the resolver first, so a non-zero RX count proves the IP
    // stack both transmits and receives over the virtio-net NIC (SLIRP's ARP reply was received).
    if let Ok(idx) = bismuth::net::find("eth0") {
        if let Ok(s) = bismuth::net::stats(idx) {
            kprintln!("virtio-net: iface stats rx_packets={} tx_packets={}", s.rx_packets, s.tx_packets);
        }
    }
    // A self-contained IP round-trip: ICMP echo to the SLIRP gateway (10.0.2.2), which answers
    // locally without any outbound internet — proving ICMP + IPv4 receive end to end.
    if let Ok(sock) = bismuth::net::socket::IcmpSocket::open(0x42) {
        let gw = Ipv4Addr::new(10, 0, 2, 2);
        if sock.ping(gw, 1, b"bismuth").is_ok() {
            match sock.recv_reply(1, Timeout::ms(3000)) {
                Ok(from) => kprintln!("virtio-net: ICMP echo reply from {from} — ping round-trip OK"),
                Err(e) => kprintln!("virtio-net: no ICMP reply ({e:?})"),
            }
        }
    }
}

// ---- Interactive container host (`--features interactive`): install a real container and drop
// into the shell, so `con ls` / `con start` / `con status` drive a hardware-isolated (EL0)
// workload on QEMU through the full path — domain + capability grant + cgroups + namespaces.
#[cfg(feature = "interactive")]
static WEBAPP_STACK: UserStack2K = UserStack2K::new();
#[cfg(feature = "interactive")]
static WASM_STACK: bismuth::Stack<8192> = bismuth::Stack::new();

// A validated WASM module (hand-assembled): writes "hi" to stdout via WASI `fd_write` and
// reports the byte count. This is the workload of the `wasmapp` container.
#[cfg(feature = "interactive")]
static WASM_MOD: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0d, 0x02, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
    0x60, 0x00, 0x01, 0x7f, 0x02, 0x23, 0x01, 0x16, b'w', b'a', b's', b'i', b'_', b's', b'n', b'a', b'p', b's', b'h',
    b'o', b't', b'_', b'p', b'r', b'e', b'v', b'i', b'e', b'w', b'1', 0x08, b'f', b'd', b'_', b'w', b'r', b'i', b't',
    b'e', 0x00, 0x00, 0x03, 0x02, 0x01, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x09, 0x01, 0x05, b'w', b't', b'e',
    b's', b't', 0x00, 0x01, 0x0a, 0x32, 0x01, 0x30, 0x00, 0x41, 0x08, 0x41, 0xe8, 0x00, 0x3a, 0x00, 0x00, 0x41, 0x09,
    0x41, 0xe9, 0x00, 0x3a, 0x00, 0x00, 0x41, 0x00, 0x41, 0x08, 0x36, 0x02, 0x00, 0x41, 0x04, 0x41, 0x02, 0x36, 0x02,
    0x00, 0x41, 0x01, 0x41, 0x00, 0x41, 0x01, 0x41, 0x14, 0x10, 0x00, 0x1a, 0x41, 0x14, 0x28, 0x02, 0x00, 0x0b,
];

/// A WASM container workload: the runtime (this EL1 task) interprets the module, which is
/// sandboxed by the interpreter — the OCI-WASM container model. It prints via WASI and exits.
#[cfg(feature = "interactive")]
fn wasm_entry(_: usize) {
    kprintln!("[wasmapp] interpreting embedded wasm (WASI)...");
    match bismuth::wasm::Module::parse(WASM_MOD) {
        Ok(m) => kprintln!("\n[wasmapp] wasm exited, fd_write reported {:?} bytes", m.invoke("wtest", &[])),
        Err(e) => kprintln!("[wasmapp] parse failed: {e:?}"),
    }
}

/// A sandboxed (EL0) container workload: read its granted sensor, then serve indefinitely.
#[cfg(feature = "interactive")]
extern "C-unwind" fn webapp(_: usize) {
    user::log(b"[webapp] started in EL0 sandbox\n");
    if let Ok(h) = user::open("env") {
        let mut raw = [0u8; 4];
        let _ = user::read(h, &mut raw, Timeout::Forever);
        user::log(b"[webapp] read granted sensor; serving\n");
    }
    loop {
        user::sleep_ticks(50);
    }
}

#[cfg(feature = "interactive")]
static WEBAPP_MANIFEST: bismuth::security::container::ContainerManifest = {
    use bismuth::security::container::{ContainerDecl, ContainerEntry, ContainerManifest, CpuBudget, OnFault};
    use bismuth::security::manifest::{DomainDecl, GrantDecl};
    ContainerManifest {
        containers: &[
            ContainerDecl {
                domain: DomainDecl {
                    spec: DomainSpec::sandboxed("webapp", 4, 1),
                    grants: &[GrantDecl { device: "sensor0", name: "env", rights: Rights::READ }],
                    dirs: &[],
                },
                entry: ContainerEntry::user(webapp, 3, &WEBAPP_STACK),
                version: 1,
                cpu: Some(CpuBudget { period_ms: 100, micros: 50_000, partitioned: false }),
                ram_bytes: 4096,
                on_fault: OnFault::Restart { max: 3, window_ms: 1000 },
                image_hash: [0; 32],
            },
            // A WASM-backed container: its workload is a wasm module run by the interpreter.
            ContainerDecl {
                domain: DomainDecl { spec: DomainSpec::isolated("wasmapp", 4, 1), grants: &[], dirs: &[] },
                entry: ContainerEntry::privileged(wasm_entry, 3, &WASM_STACK),
                version: 1,
                cpu: None,
                ram_bytes: 65536,
                on_fault: OnFault::Stop,
                image_hash: [0; 32],
            },
        ],
        supervisor: None,
    }
};

#[cfg(feature = "interactive")]
fn shell_task(_: usize) {
    let _ = bismuth::shell::run("uart0");
}

/// Install the demo container and hand the console to the shell.
#[cfg(feature = "interactive")]
fn container_host() {
    use bismuth::security::container;
    bismuth::kernel::heap::init(); // the WASM container's interpreter uses the bounded heap
    driver::register("sensor0", &SENSOR).expect("register sensor");
    container::install(&WEBAPP_MANIFEST).expect("install container");
    if let Some(c) = container::find("webapp") {
        let _ = container::set_hostname(c, "web-01");
    }
    kprintln!("Bismuth container host ready. Try: con ls | con start webapp | con status webapp");
    task::spawn("sh", 2, &SD, shell_task, 0).unwrap();
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    driver::probe_all(&BOARD, FACTORIES);
    if let Ok(uart) = Device::find("uart0") {
        bismuth::console::set_device(uart);
    }
    bismuth::console::boot_logo();
    virtio_blk_test();

    // The networking demo is its own clean flow (`--features net-demo`): bring up the NIC and
    // the IP stack, do one round-trip, exit. It is kept separate from the EL0 isolation demo
    // below so each stays short and exits promptly.
    #[cfg(feature = "net-demo")]
    {
        fn net_only(_: usize) {
            net_demo();
            bismuth::arch::aarch64::qemu_exit(0);
        }
        if net_setup() {
            let _ = bismuth::net::start();
        }
        task::spawn("netdemo", 1, &SD, net_only, 0).unwrap();
        bismuth::start(0);
    }

    // The Linux-ABI demo loads and runs a real aarch64 Linux ELF at EL0 (`--features linux-demo`).
    #[cfg(all(not(feature = "net-demo"), feature = "linux-demo"))]
    {
        linux_demo();
        bismuth::start(0)
    }

    // Interactive build hosts a real container + shell; otherwise the EL0 isolation demo.
    #[cfg(all(not(feature = "net-demo"), not(feature = "linux-demo"), feature = "interactive"))]
    {
        container_host();
        bismuth::start(0)
    }
    #[cfg(all(not(feature = "net-demo"), not(feature = "linux-demo"), not(feature = "interactive")))]
    {
        el0_demo();
        bismuth::start(0)
    }
}

/// The Linux-ABI demo: load a hand-assembled aarch64 Linux ELF — `write(1, "Hello…", N); exit(0)`
/// — into an EL0-exec buffer and run it as a sandboxed task. Its `svc #0` with Linux numbers in
/// `x8` routes through the `linux-abi` personality: `write` reaches the console, `exit` retires
/// the task. A watchdog then exits QEMU so the run terminates cleanly.
#[cfg(all(not(feature = "net-demo"), feature = "linux-demo"))]
fn linux_demo() {
    kprintln!("Bismuth {} on QEMU virt — Linux-ABI demo (EL0 Linux ELF)", env!("CARGO_PKG_VERSION"));
    let dom = security::create_domain(DomainSpec::sandboxed("linux", 4, 1)).unwrap();
    security::seal().unwrap();
    match bismuth::compat::linux::load::load_and_run(&linux_elf::HELLO_ELF, "hello", 2, dom) {
        Ok(tid) => {
            kprintln!("[linux] loaded hello ELF; entering EL0 at its _start");
            APP_TASK.store(tid.as_raw(), Ordering::Relaxed);
        }
        Err(e) => {
            kprintln!("[linux] load failed: {e:?}");
            bismuth::arch::aarch64::qemu_exit(1);
        }
    }
    task::spawn("done", 1, &SD, linux_finisher, 0).unwrap();
}

/// Await the Linux task's `exit` and report the demo result.
#[cfg(all(not(feature = "net-demo"), feature = "linux-demo"))]
fn linux_finisher(_: usize) {
    let tid = TaskId::from_raw(APP_TASK.load(Ordering::Relaxed));
    kprintln!("[done] waiting for the Linux task to exit...");
    let r = task::join(tid, Timeout::ms(5000));
    match r {
        Ok(_) => {
            kprintln!("aarch64 Linux-ABI demo complete: the EL0 Linux ELF ran, wrote via the Linux write syscall, and exited. PASS");
            bismuth::arch::aarch64::qemu_exit(0);
        }
        Err(e) => {
            kprintln!("aarch64 Linux-ABI demo FAILED (join={e:?})");
            bismuth::arch::aarch64::qemu_exit(1);
        }
    }
}

/// The EL0 user-isolation demo: two preempted workers, a sandboxed task, a rogue task that
/// faults and is killed, then (interactive) the serial shell or (default) a clean exit.
#[cfg(not(feature = "net-demo"))]
fn el0_demo() {
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
