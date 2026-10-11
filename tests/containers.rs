//! Containers: the lifecycle bundle over security domains.

#![cfg(feature = "containers")]

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};

use bismuth::driver;
use bismuth::driver::sensor::SimSensor;
use bismuth::security::container::{
    self, ContainerDecl, ContainerEntry, ContainerManifest, CpuBudget, OnFault, validate_containers,
};
use bismuth::security::manifest::{DomainDecl, GrantDecl};
use bismuth::security::{self, DomainSpec, Rights};
use bismuth::{Timeout, UserStack1K, sim, task, user};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static TELEM_RUNS: AtomicU32 = AtomicU32::new(0);
static TELEM_STACK: UserStack1K = UserStack1K::new();

/// A sandboxed container workload: read its granted sensor, then exit.
extern "C-unwind" fn telemetry(_: usize) {
    TELEM_RUNS.fetch_add(1, Ordering::Relaxed);
    if let Ok(h) = user::open("sensor") {
        let mut raw = [0u8; 4];
        let _ = user::read(h, &mut raw, Timeout::Forever);
    }
    user::log(b"[telemetry] sampled\n");
    user::exit(0)
}

static SENSOR: SimSensor = SimSensor::new(1);

static MANIFEST: ContainerManifest = ContainerManifest {
    containers: &[ContainerDecl {
        domain: DomainDecl {
            spec: DomainSpec::sandboxed("telemetry", 8, 2),
            grants: &[GrantDecl {
                device: "temp",
                name: "sensor",
                rights: Rights(Rights::READ.0 | Rights::CONTROL.0),
            }],
            dirs: &[],
        },
        entry: ContainerEntry::user(telemetry, 5, &TELEM_STACK),
        version: 1,
        cpu: Some(CpuBudget { period_ms: 100, micros: 20_000, partitioned: false }),
        ram_bytes: 1024,
        on_fault: OnFault::Restart { max: 3, window_ms: 1000 },
        image_hash: [0; 32],
    }],
    supervisor: None,
};

// A policy violation in the manifest would fail the build.
const _: () = validate_containers(&MANIFEST);

#[test]
fn install_start_health_and_restart() {
    let _s = serial();
    TELEM_RUNS.store(0, Ordering::Relaxed);
    sim::run_to_completion(|| {
        driver::register("temp", &SENSOR).unwrap();
        container::install(&MANIFEST).unwrap();
        assert!(security::is_sealed());
        let c = container::find("telemetry").expect("installed");

        task::Builder::new("supervisor").priority(2).spawn(move |arg| {
            let c = container::ContainerId(security::DomainId(arg as u8));
            // Budget was recorded and validated.
            assert_eq!(container::budget(c).unwrap().unwrap().micros, 20_000);

            container::start(c).unwrap();
            task::sleep_ticks(5);
            let h = container::health(c).unwrap();
            assert_eq!(TELEM_RUNS.load(Ordering::Relaxed), 1);
            assert!(h.faults == 0 && h.violations == 0);

            // Restart: fresh generation, workload runs again.
            let gen0 = h.generation;
            container::restart(c).unwrap();
            task::sleep_ticks(5);
            let h2 = container::health(c).unwrap();
            assert!(h2.generation > gen0, "restart bumps the domain generation");
            assert_eq!(TELEM_RUNS.load(Ordering::Relaxed), 2);
        }, c.0.0 as usize).unwrap();
    });
    assert_eq!(TELEM_RUNS.load(Ordering::Relaxed), 2);
}

static OUTSIDER_STACK: UserStack1K = UserStack1K::new();
static DENIED: AtomicU32 = AtomicU32::new(0);

/// Privileged (but untrusted, isolated) container entry: exits immediately.
fn idle_entry(_: usize) {}

static SENSOR2: SimSensor = SimSensor::new(1);
static MANIFEST2: ContainerManifest = ContainerManifest {
    containers: &[
        ContainerDecl {
            domain: DomainDecl { spec: DomainSpec::isolated("victim", 8, 1), grants: &[], dirs: &[] },
            entry: ContainerEntry::privileged(idle_entry, 4, &OUTSIDER_STACK),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
        ContainerDecl {
            domain: DomainDecl {
                spec: DomainSpec::isolated("worker", 8, 2),
                grants: &[GrantDecl { device: "temp2", name: "s", rights: Rights::READ }],
                dirs: &[],
            },
            entry: ContainerEntry::privileged(idle_entry, 4, &OUTSIDER2_STACK),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
    ],
    supervisor: None,
};
static OUTSIDER2_STACK: UserStack1K = UserStack1K::new();
const _: () = validate_containers(&MANIFEST2);

#[test]
fn only_trusted_code_controls_containers() {
    let _s = serial();
    DENIED.store(0, Ordering::Relaxed);
    sim::run_to_completion(|| {
        driver::register("temp2", &SENSOR2).unwrap();
        container::install(&MANIFEST2).unwrap();
        let worker = container::find("worker").unwrap();
        let victim = container::find("victim").unwrap();
        // A task in the (isolated, untrusted) worker domain cannot stop the victim.
        task::Builder::new("w").priority(5).domain(worker.0).spawn(move |arg| {
            let victim = container::ContainerId(security::DomainId(arg as u8));
            if container::stop(victim) == Err(bismuth::Error::PermissionDenied) {
                DENIED.fetch_add(1, Ordering::Relaxed);
            }
            // install after seal is refused too.
            if container::install(&MANIFEST2) == Err(bismuth::Error::PermissionDenied) {
                DENIED.fetch_add(1, Ordering::Relaxed);
            }
        }, victim.0.0 as usize).unwrap();
    });
    assert_eq!(DENIED.load(Ordering::Relaxed), 2);
}

// --- C5: manifest attestation (the OCI-image-digest analog) ---

#[test]
fn manifest_hash_is_deterministic_and_change_sensitive() {
    let h1 = container::manifest_hash(&MANIFEST);
    let h2 = container::manifest_hash(&MANIFEST);
    assert_eq!(h1, h2, "same manifest → same measurement");
    assert_ne!(h1, [0u8; 32], "a real hash, not all-zero");
    // A different capability graph measures differently.
    assert_ne!(h1, container::manifest_hash(&MANIFEST2));
}

// --- C3: supervisor + fault/restart policy (the kubelet analog) ---

static WK_RUNS: AtomicU32 = AtomicU32::new(0);
static WK_STACK: UserStack1K = UserStack1K::new();
static SIB_STACK: UserStack1K = UserStack1K::new();
static FINAL_RESTARTS: AtomicU32 = AtomicU32::new(0);
static SIB_ALIVE: AtomicU32 = AtomicU32::new(0);
static SUP_STACK: bismuth::Stack<4096> = bismuth::Stack::new();

/// Crash-loops: run once and exit, so the supervisor keeps restarting it until `max`.
extern "C-unwind" fn crasher(_: usize) {
    WK_RUNS.fetch_add(1, Ordering::Relaxed);
    user::exit(0)
}

/// A well-behaved sibling that stays alive for the duration.
extern "C-unwind" fn long_runner(_: usize) {
    for _ in 0..100 {
        user::sleep_ticks(5);
    }
    user::exit(0)
}

static SUP_MANIFEST: ContainerManifest = ContainerManifest {
    containers: &[
        ContainerDecl {
            domain: DomainDecl { spec: DomainSpec::sandboxed("worker", 8, 2), grants: &[], dirs: &[] },
            entry: ContainerEntry::user(crasher, 5, &WK_STACK),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Restart { max: 2, window_ms: 100_000 },
            image_hash: [0; 32],
        },
        ContainerDecl {
            domain: DomainDecl { spec: DomainSpec::sandboxed("sibling", 8, 2), grants: &[], dirs: &[] },
            entry: ContainerEntry::user(long_runner, 4, &SIB_STACK),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
    ],
    supervisor: None,
};
const _: () = validate_containers(&SUP_MANIFEST);

/// Trusted supervisor: sweep repeatedly, then record the outcome.
fn supervisor_task(_: usize) {
    for _ in 0..30 {
        container::supervise();
        task::sleep_ticks(5);
    }
    let worker = container::find("worker").unwrap();
    FINAL_RESTARTS.store(container::restart_count(worker), Ordering::Relaxed);
    let sib = container::find("sibling").unwrap();
    SIB_ALIVE.store(container::health(sib).unwrap().running as u32, Ordering::Relaxed);
}

#[test]
fn supervisor_restarts_a_crash_looping_container_without_touching_a_sibling() {
    let _s = serial();
    WK_RUNS.store(0, Ordering::Relaxed);
    FINAL_RESTARTS.store(0, Ordering::Relaxed);
    SIB_ALIVE.store(0, Ordering::Relaxed);
    sim::run_to_completion(|| {
        container::install(&SUP_MANIFEST).unwrap();
        container::start(container::find("sibling").unwrap()).unwrap();
        container::start(container::find("worker").unwrap()).unwrap();
        task::spawn("sup", 6, &SUP_STACK, supervisor_task, 0).unwrap();
    });
    // Ran once, then restarted twice (max), then left stopped.
    assert_eq!(WK_RUNS.load(Ordering::Relaxed), 3, "initial run + 2 restarts");
    assert_eq!(FINAL_RESTARTS.load(Ordering::Relaxed), 2, "capped at max restarts");
    // The sibling kept running the whole time: blast radius = 1.
    assert_eq!(SIB_ALIVE.load(Ordering::Relaxed), 1, "sibling unaffected");
}

// --- C4: capability-gated inter-container IPC (containers talk over a granted pipe; a
// container without the grant cannot even open the channel). ---

static IPC_PIPE: bismuth::driver::char::pipe::Pipe<64> = bismuth::driver::char::pipe::Pipe::new();
static PROD_STACK: UserStack1K = UserStack1K::new();
static CONS_STACK: UserStack1K = UserStack1K::new();
static OUT_STACK: UserStack1K = UserStack1K::new();
static IPC_GOT: AtomicU32 = AtomicU32::new(0);
static IPC_DENIED: AtomicU32 = AtomicU32::new(0);

extern "C-unwind" fn producer(_: usize) {
    if let Ok(h) = user::open("ipc") {
        let _ = user::write(h, b"ping");
    }
    user::exit(0)
}

extern "C-unwind" fn consumer(_: usize) {
    if let Ok(h) = user::open("ipc") {
        let mut buf = [0u8; 8];
        if user::read(h, &mut buf, Timeout::ms(2000)) == Ok(4) && &buf[..4] == b"ping" {
            IPC_GOT.store(1, Ordering::Relaxed);
        }
    }
    user::exit(0)
}

extern "C-unwind" fn ipc_outsider(_: usize) {
    // No grant for "ipc": the channel is invisible to this container.
    if user::open("ipc").is_err() {
        IPC_DENIED.store(1, Ordering::Relaxed);
    }
    user::exit(0)
}

static IPC_MANIFEST: ContainerManifest = ContainerManifest {
    containers: &[
        ContainerDecl {
            domain: DomainDecl {
                spec: DomainSpec::sandboxed("consumer", 8, 2),
                grants: &[GrantDecl { device: "ipcpipe", name: "ipc", rights: Rights(Rights::READ.0 | Rights::WRITE.0) }],
                dirs: &[],
            },
            entry: ContainerEntry::user(consumer, 6, &CONS_STACK),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
        ContainerDecl {
            domain: DomainDecl {
                spec: DomainSpec::sandboxed("producer", 8, 2),
                grants: &[GrantDecl { device: "ipcpipe", name: "ipc", rights: Rights(Rights::READ.0 | Rights::WRITE.0) }],
                dirs: &[],
            },
            entry: ContainerEntry::user(producer, 5, &PROD_STACK),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
        ContainerDecl {
            domain: DomainDecl { spec: DomainSpec::sandboxed("ipc_outsider", 8, 2), grants: &[], dirs: &[] },
            entry: ContainerEntry::user(ipc_outsider, 4, &OUT_STACK),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
    ],
    supervisor: None,
};
const _: () = validate_containers(&IPC_MANIFEST);

#[test]
fn containers_communicate_over_a_granted_pipe_and_a_third_cannot() {
    let _s = serial();
    IPC_GOT.store(0, Ordering::Relaxed);
    IPC_DENIED.store(0, Ordering::Relaxed);
    sim::run_to_completion(|| {
        driver::register("ipcpipe", &IPC_PIPE).unwrap();
        container::install(&IPC_MANIFEST).unwrap();
        container::start(container::find("consumer").unwrap()).unwrap();
        container::start(container::find("producer").unwrap()).unwrap();
        container::start(container::find("ipc_outsider").unwrap()).unwrap();
    });
    assert_eq!(IPC_GOT.load(Ordering::Relaxed), 1, "consumer received the producer's message");
    assert_eq!(IPC_DENIED.load(Ordering::Relaxed), 1, "ungranted container cannot open the channel");
}

// --- C6: time-partition control — a suspended container makes no progress until resumed
// (the temporal-isolation primitive; a frame governor resumes one partition at a time). ---

static PART_COUNT: AtomicU32 = AtomicU32::new(0);
static PART_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PART_STACK: UserStack1K = UserStack1K::new();
static GOV_STACK: bismuth::Stack<4096> = bismuth::Stack::new();
static SNAP1: AtomicU32 = AtomicU32::new(0);
static SNAP2: AtomicU32 = AtomicU32::new(0);

extern "C-unwind" fn partition_worker(_: usize) {
    while !PART_DONE.load(Ordering::Relaxed) {
        PART_COUNT.fetch_add(1, Ordering::Relaxed);
        user::sleep_ticks(1);
    }
    user::exit(0)
}

static PART_MANIFEST: ContainerManifest = ContainerManifest {
    containers: &[ContainerDecl {
        domain: DomainDecl { spec: DomainSpec::sandboxed("part", 8, 2), grants: &[], dirs: &[] },
        entry: ContainerEntry::user(partition_worker, 5, &PART_STACK),
        version: 1,
        cpu: None,
        ram_bytes: 1024,
        on_fault: OnFault::Stop,
        image_hash: [0; 32],
    }],
    supervisor: None,
};
const _: () = validate_containers(&PART_MANIFEST);

fn partition_governor(_: usize) {
    let c = container::find("part").unwrap();
    task::sleep_ticks(20); // the partition's window: it runs
    SNAP1.store(PART_COUNT.load(Ordering::Relaxed), Ordering::Relaxed);
    container::suspend(c).unwrap(); // window closes
    task::sleep_ticks(20); // out of window: it must not advance
    SNAP2.store(PART_COUNT.load(Ordering::Relaxed), Ordering::Relaxed);
    PART_DONE.store(true, Ordering::Relaxed);
    container::resume(c).unwrap(); // let it observe DONE and exit
}

#[test]
fn a_suspended_partition_makes_no_progress_until_resumed() {
    let _s = serial();
    PART_COUNT.store(0, Ordering::Relaxed);
    PART_DONE.store(false, Ordering::Relaxed);
    SNAP1.store(0, Ordering::Relaxed);
    SNAP2.store(0, Ordering::Relaxed);
    sim::run_to_completion(|| {
        container::install(&PART_MANIFEST).unwrap();
        container::start(container::find("part").unwrap()).unwrap();
        task::spawn("gov", 6, &GOV_STACK, partition_governor, 0).unwrap();
    });
    assert!(SNAP1.load(Ordering::Relaxed) >= 1, "the partition ran inside its window");
    assert_eq!(SNAP2.load(Ordering::Relaxed), SNAP1.load(Ordering::Relaxed), "frozen while suspended");
}

// --- C5+: container PCR attestation — measuring the manifest into a PCR makes the quote
// attest which container graph is running. ---

#[test]
fn measuring_the_manifest_changes_the_attestation_quote() {
    use bismuth::security::trust::{RootOfTrust, SoftTpm};
    let nonce = [9u8; 16];
    // TPM A measures MANIFEST; TPM B measures MANIFEST2 (a different graph).
    let a = SoftTpm::new([7u8; 32]);
    let b = SoftTpm::new([7u8; 32]);
    container::measure_manifest(&MANIFEST, &a, 2).unwrap();
    container::measure_manifest(&MANIFEST2, &b, 2).unwrap();
    let (mut qa, mut qb) = ([0u8; 32], [0u8; 32]);
    a.quote(1 << 2, &nonce, &mut qa).unwrap();
    b.quote(1 << 2, &nonce, &mut qb).unwrap();
    assert_ne!(qa, qb, "different container manifests attest to different PCR states");
    // Same manifest into an identical device → identical quote (deterministic attestation).
    let c = SoftTpm::new([7u8; 32]);
    container::measure_manifest(&MANIFEST, &c, 2).unwrap();
    let mut qc = [0u8; 32];
    c.quote(1 << 2, &nonce, &mut qc).unwrap();
    assert_eq!(qa, qc);
}

// --- C7: signed app-bundle admission (sig + capability ceiling + anti-rollback). ---

#[test]
fn signed_bundle_admission_enforces_signature_ceiling_and_rollback() {
    use bismuth::security::Rights;
    use bismuth::security::bundle::{BundleHeader, Reject, Slot};

    let key = [0x42u8; 32];
    let code = b"the bundle code image".as_slice();
    let mk = |counter: u32, sc: u32, prio: u8| BundleHeader {
        magic: 0,
        abi: 0,
        counter,
        req_syscalls: sc,
        req_priority: prio,
        req_rights: Rights::READ,
        code_hash: [0; 32],
        signature: [0; 32],
    };

    // Good bundle: requests a subset of the slot's ceiling and a fresh counter.
    let slot = Slot::new(0b1111, 6, Rights::READ, key);
    let mut h = mk(5, 0b0011, 5);
    slot.sign(&mut h, code);
    assert_eq!(slot.admit(&h, code), Ok(()));
    // Replaying the same counter is refused (the floor advanced).
    assert_eq!(slot.admit(&h, code), Err(Reject::Rollback));

    // Tampered code → signature mismatch.
    let slot = Slot::new(0b1111, 6, Rights::READ, key);
    let mut h = mk(1, 0b0001, 1);
    slot.sign(&mut h, code);
    assert_eq!(slot.admit(&h, b"the bundle code imagX".as_slice()), Err(Reject::BadSignature));

    // Requests more syscall authority than the slot grants.
    let slot = Slot::new(0b1111, 6, Rights::READ, key);
    let mut h = mk(1, 0b1_1111, 5); // bit 4 exceeds the 0b1111 ceiling
    slot.sign(&mut h, code);
    assert_eq!(slot.admit(&h, code), Err(Reject::CapabilityExceeded));

    // Wrong signing key → rejected.
    let slot = Slot::new(0b1111, 6, Rights::READ, [0x11u8; 32]);
    let mut h = mk(1, 0b0001, 1);
    Slot::new(0b1111, 6, Rights::READ, key).sign(&mut h, code); // signed with a different key
    assert_eq!(slot.admit(&h, code), Err(Reject::BadSignature));
}

#[test]
fn placing_a_bundle_copies_the_signed_code_into_an_executable_region() {
    use bismuth::security::Rights;
    use bismuth::security::bundle::{BundleHeader, CodeRegion, Reject, Slot};

    let key = [0x7eu8; 32];
    let code = b"position-independent bundle image bytes".as_slice();
    let slot = Slot::new(0b1111, 6, Rights::READ, key);
    let mut h = BundleHeader {
        magic: 0,
        abi: 0,
        counter: 1,
        req_syscalls: 0b0001,
        req_priority: 3,
        req_rights: Rights::READ,
        code_hash: [0; 32],
        signature: [0; 32],
    };
    slot.sign(&mut h, code);

    // Placement copies the admitted bytes into the region and re-measures them in place.
    static REGION: CodeRegion<64> = CodeRegion::new();
    assert!(REGION.is_empty());
    slot.place(&REGION, &h, code).unwrap();
    assert_eq!(REGION.len(), code.len());
    REGION.with_code(|placed| assert_eq!(placed, code));

    // A region too small for the code is refused (and the floor did not advance).
    static SMALL: CodeRegion<8> = CodeRegion::new();
    assert_eq!(slot.place(&SMALL, &h, code), Err(Reject::Malformed));

    // The counter advanced on the successful placement, so a replay is refused.
    static R2: CodeRegion<64> = CodeRegion::new();
    assert_eq!(slot.place(&R2, &h, code), Err(Reject::Rollback));
    assert!(R2.is_empty(), "a rejected placement leaves the region empty");
}
