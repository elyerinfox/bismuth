//! Security contexts: domains, handles, rights, policy, entropy and the keystore.
//! Most tests act as an *attacker* inside an isolated domain.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex as StdMutex;

use bismuth::driver::ioctl;
use bismuth::driver::{char::Pipe, sensor::SimSensor};
use bismuth::driver::middleware::Stats;
use bismuth::driver::{self, Device, DeviceCtx, IoResult, Middleware, Next, Request};
use bismuth::net::drivers::{Wire, WireEnd};
use bismuth::net::ip::{self, IpConfig};
use bismuth::net::socket::{TcpListener, UdpSocket};
use bismuth::net::{self, SoftRing};
use bismuth::security::entropy::{self, Fault, FaultySource, SimTrng};
use bismuth::security::keystore::{self, KeyAttrs, KeyType};
use bismuth::security::manifest::{self, DomainDecl, GrantDecl, Manifest};
use bismuth::security::{self, BadHandlePolicy, DeviceCap, DomainId, DomainSpec, Handle, NetPolicy, Rights};
use bismuth::{TaskId, sim, task};
#[allow(unused_imports)]
use bismuth::{Error, Timeout};

/// Tests in this file share global logs; run them one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static RESULTS: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
fn note(s: impl Into<String>) {
    RESULTS.lock().unwrap().push(s.into());
}
fn take() -> Vec<String> {
    std::mem::take(&mut *RESULTS.lock().unwrap())
}

const fn deny_spec(name: &'static str) -> DomainSpec {
    DomainSpec { bad_handle: BadHandlePolicy::Deny, ..DomainSpec::isolated(name, 8, 4) }
}

/// Records the caller of every request.
struct WhoCalled;
static WHO: StdMutex<Vec<(u8, u32)>> = StdMutex::new(Vec::new());
impl Middleware for WhoCalled {
    fn name(&self) -> &'static str {
        "who-called"
    }
    fn call(&self, _: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let c = req.caller();
        WHO.lock().unwrap().push((c.domain.0, c.rights.0));
        next.run(req)
    }
}
static WHO_CALLED: WhoCalled = WhoCalled;

static SENSOR: SimSensor = SimSensor::new(1);
static TTY: Pipe<32> = Pipe::new();
static STATS: Stats = Stats::new();

#[test]
fn isolated_domain_has_no_ambient_authority_and_rights_gate_ops() {
    let _serial = serial();
    take();
    WHO.lock().unwrap().clear();
    sim::run_to_completion(|| {
        let sensor = driver::register("temp0", &SENSOR).unwrap();
        driver::register("tty0", &TTY).unwrap();
        sensor.attach(&WHO_CALLED).unwrap();
        let app = security::create_domain(deny_spec("app")).unwrap();
        security::grant_device(app, sensor, Rights::READ | Rights::CONTROL, "temp0").unwrap();
        task::Builder::new("app").priority(4).domain(app).spawn(|_| {
            // Raw device API: denied (no ambient authority).
            let raw = Device::find("temp0").unwrap();
            note(format!("raw read: {:?}", raw.read(&mut [0u8; 4])));
            note(format!("raw attach: {:?}", raw.attach(&STATS)));
            // Not in the namespace at all.
            note(format!("open tty0: {:?}", DeviceCap::open("tty0").map(|_| ())));
            let cap = DeviceCap::open("/dev/temp0").unwrap();
            note(format!("read: {:?}", cap.read(&mut [0u8; 4])));
            note(format!("query ioctl: {:?}", cap.ioctl(ioctl::SENSOR_CHANNELS, 0)));
            note(format!("config ioctl: {:?}", cap.ioctl(ioctl::SENSOR_SET_RATE_HZ, 50)));
            note(format!("write: {:?}", cap.write(b"x")));
            note(format!("power: {:?}", cap.set_power(bismuth::driver::PowerState::Off)));
            note(format!("attach: {:?}", cap.attach(&STATS)));
            note(format!("global mw: {:?}", driver::add_global_middleware(&STATS)));
        }, 0).unwrap();
    });
    assert_eq!(
        take(),
        [
            "raw read: Err(PermissionDenied)",
            "raw attach: Err(PermissionDenied)",
            "open tty0: Err(NotFound)",
            "read: Ok(4)",
            "query ioctl: Ok(1)",
            "config ioctl: Err(PermissionDenied)",
            "write: Err(PermissionDenied)",
            "power: Err(PermissionDenied)",
            "attach: Err(PermissionDenied)",
            "global mw: Err(PermissionDenied)",
        ]
    );
    // Middleware saw the real caller: domain 1 with exactly the granted rights.
    let rights = (Rights::READ | Rights::CONTROL).0;
    assert_eq!(*WHO.lock().unwrap(), [(1, rights), (1, rights)]);
}

static SENSOR2: SimSensor = SimSensor::new(1);

#[test]
fn forged_handle_kills_domain_under_kill_policy() {
    let _serial = serial();
    take();
    let mut killed = None;
    sim::run_to_completion(|| {
        let s = driver::register("temp1", &SENSOR2).unwrap();
        let d = security::create_domain(DomainSpec::isolated("attacker", 8, 4)).unwrap();
        security::grant_device(d, s, Rights::READ, "temp1").unwrap();
        task::Builder::new("sibling").priority(3).domain(d).spawn(|_| {
            task::sleep_ticks(100);
            note("sibling survived"); // must never run
        }, 0).unwrap();
        task::Builder::new("prober").priority(4).domain(d).spawn(|_| {
            let real = DeviceCap::open("temp1").unwrap();
            assert!(real.read(&mut [0u8; 4]).is_ok());
            note("probing");
            // Guess a handle value: any forged handle kills the whole domain.
            let forged = DeviceCap::from_handle(Handle::from_raw(0x7FFF));
            let _ = forged.read(&mut [0u8; 4]);
            note("prober survived"); // must never run
        }, 0).unwrap();
        task::Builder::new("observer").priority(2).spawn(|d| {
            task::sleep_ticks(200);
            let d = DomainId(d as u8);
            note(format!("killed={} violations={}", security::is_killed(d), security::violations(d)));
        }, d.0 as usize).unwrap();
        killed = Some(d);
    });
    assert_eq!(take(), ["probing", "killed=true violations=1"]);
    let _ = killed;
}

static SENSOR3: SimSensor = SimSensor::new(1);

#[test]
fn revocation_invalidates_outstanding_handles() {
    let _serial = serial();
    take();
    sim::run_to_completion(|| {
        let s = driver::register("temp2", &SENSOR3).unwrap();
        let d = security::create_domain(deny_spec("client")).unwrap();
        security::grant_device(d, s, Rights::READ, "temp2").unwrap();
        task::Builder::new("client").priority(4).domain(d).spawn(|_| {
            let cap = DeviceCap::open("temp2").unwrap();
            note(format!("before: {:?}", cap.read(&mut [0u8; 4])));
            task::sleep_ticks(10);
            note(format!("after: {:?}", cap.read(&mut [0u8; 4])));
        }, 0).unwrap();
        task::Builder::new("admin").priority(3).spawn(|_| {
            task::sleep_ticks(5);
            let dev = Device::find("temp2").unwrap();
            let fresh = security::revoke_device(dev).unwrap();
            note(format!("old handle: {:?}", dev.read(&mut [0u8; 4])));
            note(format!("new handle: {:?}", fresh.read(&mut [0u8; 4])));
        }, 0).unwrap();
    });
    assert_eq!(
        take(),
        ["before: Ok(4)", "old handle: Err(BadHandle)", "new handle: Ok(4)", "after: Err(BadHandle)"]
    );
}

#[test]
fn priority_ceiling_quotas_and_cross_domain_control() {
    let _serial = serial();
    take();
    sim::run_to_completion(|| {
        let d = security::create_domain(DomainSpec { max_tasks: 2, ..deny_spec("worker") }).unwrap();
        task::Builder::new("w").priority(5).domain(d).spawn(|_| {
            note(format!("above ceiling: {:?}", task::Builder::new("x").priority(9).spawn(|_| {}, 0).err()));
            note(format!("at ceiling: {:?}", task::Builder::new("y").priority(8).spawn(|_| task::sleep_ticks(50), 0).is_ok()));
            note(format!("quota: {:?}", task::Builder::new("z").priority(3).spawn(|_| {}, 0).err()));
            note(format!("other domain: {:?}", task::Builder::new("k").priority(3).domain(DomainId::KERNEL).spawn(|_| {}, 0).err()));
            note(format!("raise self: {:?}", task::set_priority(task::current(), 20).err()));
            let kernel_task = TaskId::from_raw(KERNEL_TASK.lock().unwrap().unwrap());
            note(format!("suspend kernel task: {:?}", task::suspend(kernel_task).err()));
        }, 0).unwrap();
        let k = task::Builder::new("kernel-task").priority(2).spawn(|_| task::sleep_ticks(100), 0).unwrap();
        *KERNEL_TASK.lock().unwrap() = Some(k.as_raw());
    });
    assert_eq!(
        take(),
        [
            "above ceiling: Some(PermissionDenied)",
            "at ceiling: true",
            "quota: Some(NoResources)",
            "other domain: Some(PermissionDenied)",
            "raise self: Some(PermissionDenied)",
            "suspend kernel task: Some(PermissionDenied)",
        ]
    );
}
static KERNEL_TASK: StdMutex<Option<u32>> = StdMutex::new(None);

static SENSOR4: SimSensor = SimSensor::new(1);

#[test]
fn seal_freezes_policy_and_rights_only_shrink() {
    let _serial = serial();
    take();
    sim::run_to_completion(|| {
        let s = driver::register("temp3", &SENSOR4).unwrap();
        let d = security::create_domain(deny_spec("app")).unwrap();
        security::grant_device(d, s, Rights::READ | Rights::CONTROL | Rights::DUPLICATE, "temp3").unwrap();
        security::seal().unwrap();
        note(format!("create after seal: {:?}", security::create_domain(deny_spec("late")).err()));
        note(format!("grant after seal: {:?}", security::grant_device(d, s, Rights::ALL, "x").err()));
        task::Builder::new("app").priority(4).domain(d).spawn(|_| {
            let cap = DeviceCap::open("temp3").unwrap();
            let h = cap.handle().unwrap();
            // Duplicate with a *superset* of rights: only the intersection survives.
            let dup = security::duplicate(h, Rights::ALL).unwrap();
            note(format!("dup rights == orig: {}", security::rights_of(dup).unwrap() == security::rights_of(h).unwrap()));
            security::drop_rights(h, Rights::READ).unwrap();
            note(format!("read after drop: {:?}", cap.read(&mut [0u8; 4]).err()));
            note(format!("query still ok: {:?}", cap.ioctl(ioctl::SENSOR_CHANNELS, 0)));
            // Duplicating a handle without DUPLICATE right fails.
            security::drop_rights(dup, Rights::DUPLICATE).unwrap();
            note(format!("dup of dup: {:?}", security::duplicate(dup, Rights::READ).err()));
        }, 0).unwrap();
    });
    assert_eq!(
        take(),
        [
            "create after seal: Some(PermissionDenied)",
            "grant after seal: Some(PermissionDenied)",
            "dup rights == orig: true",
            "read after drop: Some(PermissionDenied)",
            "query still ok: Ok(1)",
            "dup of dup: Some(PermissionDenied)",
        ]
    );
}

static WIRE: Wire = Wire::new();
static ETH_A: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 0, [2, 0, 0, 0, 0, 1]));
static ETH_B: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 1, [2, 0, 0, 0, 0, 2]));

#[test]
fn per_domain_network_policy() {
    let _serial = serial();
    take();
    sim::run_to_completion(|| {
        let a = net::register("eth0", &ETH_A).unwrap();
        let b = net::register("eth1", &ETH_B).unwrap();
        ip::configure(a, IpConfig { addr: [10, 0, 0, 1], prefix_len: 24, gateway: None }).unwrap();
        ip::configure(b, IpConfig { addr: [10, 0, 0, 2], prefix_len: 24, gateway: None }).unwrap();
        net::start().unwrap();
        let policy = NetPolicy { local_ports: (5000, 5100), peers: ([10, 0, 0, 0], 24), listen: false };
        let iot = security::create_domain(DomainSpec { net: Some(policy), ..deny_spec("iot") }).unwrap();
        let offline = security::create_domain(deny_spec("offline")).unwrap();
        task::Builder::new("iot").priority(4).domain(iot).spawn(|_| {
            note(format!("bind 6000: {:?}", UdpSocket::bind(6000).err()));
            let s = UdpSocket::bind(5050).unwrap();
            note(format!("send in-subnet: {:?}", s.send_to(b"ok", SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9)).is_ok()));
            note(format!("send off-subnet: {:?}", s.send_to(b"x", SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)).err()));
            note(format!("listen: {:?}", TcpListener::bind(5060).err()));
        }, 0).unwrap();
        task::Builder::new("offline").priority(3).domain(offline).spawn(|_| {
            note(format!("offline bind: {:?}", UdpSocket::bind(5050).err()));
        }, 0).unwrap();
    });
    assert_eq!(
        take(),
        [
            "bind 6000: Some(PermissionDenied)",
            "send in-subnet: true",
            "send off-subnet: Some(PermissionDenied)",
            "listen: Some(PermissionDenied)",
            "offline bind: Some(PermissionDenied)",
        ]
    );
}

static SENSOR5: SimSensor = SimSensor::new(1);
static TTY5: Pipe<32> = Pipe::new();

#[test]
fn posix_open_resolves_in_domain_namespace() {
    let _serial = serial();
    use bismuth::compat::posix::*;
    take();
    sim::run_to_completion(|| {
        let s = driver::register("bme280", &SENSOR5).unwrap();
        driver::register("secret-uart", &TTY5).unwrap();
        let d = security::create_domain(deny_spec("app")).unwrap();
        // The device is visible to the domain under an alias.
        security::grant_device(d, s, Rights::READ | Rights::CONTROL, "env").unwrap();
        task::Builder::new("app").priority(4).domain(d).spawn(|_| {
            let fd = open("/dev/env", O_RDONLY);
            let mut buf = [0u8; 4];
            note(format!("read: {}", read(fd, &mut buf)));
            note(format!("secret: {} errno={}", open("/dev/secret-uart", O_RDWR), errno()));
            note(format!("by real name: {}", open("/dev/bme280", O_RDONLY)));
        }, 0).unwrap();
    });
    assert_eq!(take(), ["read: 4", "secret: -1 errno=2", "by real name: -1"]);
}

static TRNG: SimTrng = SimTrng::new(0xC0FFEE, 4);
static STUCK: FaultySource = FaultySource::new(Fault::StuckAt(0xAA));
static OUT: StdMutex<Vec<[u8; 16]>> = StdMutex::new(Vec::new());

#[test]
fn entropy_health_seeding_and_per_domain_streams() {
    let _serial = serial();
    OUT.lock().unwrap().clear();
    take();
    sim::run_to_completion(|| {
        // No sources yet: everything refuses to produce output.
        note(format!("unseeded: {:?}", entropy::fill(&mut [0u8; 8]).err()));
        entropy::add_source(&STUCK).unwrap();
        note(format!("stuck only: {:?}", entropy::seed(200).err()));
        let st = entropy::status();
        note(format!("unhealthy: sources={} failures={}", st.healthy_sources, st.health_failures));
        entropy::add_source(&TRNG).unwrap();
        entropy::mix(b"device-serial-1234");
        entropy::seed(200).unwrap();
        note(format!("seeded: {}", entropy::status().seeded));
        let a = security::create_domain(deny_spec("a")).unwrap();
        let b = security::create_domain(deny_spec("b")).unwrap();
        for d in [a, b] {
            task::Builder::new("draw").priority(4).domain(d).spawn(|_| {
                let mut x = [0u8; 16];
                entropy::fill(&mut x).unwrap();
                OUT.lock().unwrap().push(x);
            }, 0).unwrap();
        }
        task::Builder::new("restart").priority(3).spawn(|a| {
            task::sleep_ticks(5);
            let a = DomainId(a as u8);
            security::kill(a).unwrap();
            task::Builder::new("draw2").priority(4).domain(a).spawn(|_| {
                let mut x = [0u8; 16];
                entropy::fill(&mut x).unwrap();
                OUT.lock().unwrap().push(x);
            }, 0).unwrap();
        }, a.0 as usize).unwrap();
    });
    assert_eq!(take(), ["unseeded: Some(NotReady)", "stuck only: Some(NotReady)", "unhealthy: sources=0 failures=1", "seeded: true"]);
    let out = OUT.lock().unwrap().clone();
    assert_eq!(out.len(), 3);
    assert_ne!(out[0], out[1], "domains have independent generators");
    assert_ne!(out[0], out[2], "a restarted domain never replays its stream");
    assert!(out.iter().all(|x| x.iter().any(|b| *b != 0)));
}

static TRNG2: SimTrng = SimTrng::new(0xBADC0DE, 4);
static KEYS_OUT: StdMutex<Option<u16>> = StdMutex::new(None);

#[test]
fn keystore_enforces_rights_policy_and_isolation() {
    let _serial = serial();
    take();
    sim::run_to_completion(|| {
        entropy::add_source(&TRNG2).unwrap();
        entropy::seed(200).unwrap();
        keystore::self_test().unwrap();
        let owner = security::create_domain(deny_spec("owner")).unwrap();
        let thief = security::create_domain(deny_spec("thief")).unwrap();
        task::Builder::new("owner").priority(5).domain(owner).spawn(|_| {
            let k = keystore::generate(KeyAttrs::aead()).unwrap();
            *KEYS_OUT.lock().unwrap() = Some(k.raw());
            let nonce = [7u8; 12];
            let mut msg = *b"telemetry: 21.5C";
            let tag = keystore::aead_seal(k, &nonce, b"hdr", &mut msg).unwrap();
            note(format!("ciphertext differs: {}", &msg != b"telemetry: 21.5C"));
            let mut tampered = msg;
            tampered[0] ^= 1;
            note(format!("tampered: {:?} wiped={}", keystore::aead_open(k, &nonce, b"hdr", &mut tampered, &tag).err(), tampered == [0; 16]));
            keystore::aead_open(k, &nonce, b"hdr", &mut msg, &tag).unwrap();
            note(format!("roundtrip: {}", &msg == b"telemetry: 21.5C"));
            note(format!("mac with aead key: {:?}", keystore::mac(k, b"x").err()));
            note(format!("export: {:?}", keystore::export(k, &mut [0u8; 32]).err()));
            security::drop_rights(k, Rights::K_DECRYPT).unwrap();
            note(format!("decrypt after drop: {:?}", keystore::aead_open(k, &nonce, b"hdr", &mut msg, &tag).err()));
            // Key derivation: derived keys stay inside the keystore.
            let root = keystore::import(KeyAttrs::kdf(), &[0x0b; 32]).unwrap();
            let mac_key = keystore::derive(root, b"bismuth/telemetry/mac", KeyAttrs::mac()).unwrap();
            let t = keystore::mac(mac_key, b"reading").unwrap();
            note(format!("mac verify: {:?}", keystore::mac_verify(mac_key, b"reading", &t)));
            note(format!("mac forged: {:?}", keystore::mac_verify(mac_key, b"reading!", &t).err()));
            note(format!("derive type: {:?}", keystore::key_type(mac_key)));
            keystore::destroy(k).unwrap();
            note(format!("after destroy: {:?}", keystore::aead_seal(k, &nonce, b"", &mut msg).err()));
            note(format!("zeroized: {}", !keystore::residual_material()));
        }, 0).unwrap();
        task::Builder::new("thief").priority(4).domain(thief).spawn(|_| {
            task::sleep_ticks(1);
            // Steal the owner's handle value: it means nothing in this domain's table.
            let stolen = Handle::from_raw(KEYS_OUT.lock().unwrap().unwrap());
            note(format!("stolen handle: {:?}", keystore::aead_seal(stolen, &[0; 12], b"", &mut [0u8; 4]).err()));
        }, 0).unwrap();
    });
    assert_eq!(
        take(),
        [
            "ciphertext differs: true",
            "tampered: Some(Integrity) wiped=true",
            "roundtrip: true",
            "mac with aead key: Some(PermissionDenied)",
            "export: Some(PermissionDenied)",
            "decrypt after drop: Some(PermissionDenied)",
            "mac verify: Ok(())",
            "mac forged: Some(Integrity)",
            "derive type: Ok(HmacSha256)",
            "after destroy: Some(BadHandle)",
            "zeroized: true",
            "stolen handle: Some(BadHandle)",
        ]
    );
    let _ = KeyType::ChaCha20Poly1305;
}

static TELEMETRY_MANIFEST: Manifest = Manifest {
    domains: &[
        DomainDecl {
            spec: DomainSpec::isolated("telemetry", 8, 2),
            grants: &[GrantDecl { device: "temp9", name: "temp", rights: Rights(Rights::READ.0 | Rights::CONTROL.0) }],
            dirs: &[],
        },
        DomainDecl { spec: DomainSpec::isolated("ota", 6, 1), grants: &[], dirs: &[] },
    ],
};
// Policy violations in the manifest fail the *build*.
const _: () = manifest::validate(&TELEMETRY_MANIFEST);

static SENSOR9: SimSensor = SimSensor::new(1);

#[test]
fn manifest_applies_and_seals() {
    let _serial = serial();
    take();
    sim::run_to_completion(|| {
        driver::register("temp9", &SENSOR9).unwrap();
        let ids = manifest::apply(&TELEMETRY_MANIFEST).unwrap();
        security::seal().unwrap();
        assert_eq!(security::find_domain("telemetry"), ids[0]);
        task::Builder::new("t").priority(5).domain(ids[0].unwrap()).spawn(|_| {
            let cap = DeviceCap::open("temp").unwrap();
            note(format!("read: {:?}", cap.read(&mut [0u8; 4])));
            note(format!("restrict: {:?}", security::restrict(true, Some(3))));
            note(format!("spawn above new ceiling: {:?}", task::Builder::new("x").priority(4).spawn(|_| {}, 0).err()));
        }, 0).unwrap();
    });
    assert_eq!(take(), ["read: Ok(4)", "restrict: Ok(())", "spawn above new ceiling: Some(PermissionDenied)"]);
}
