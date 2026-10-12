//! The ARINC-653 major-frame scheduler (`container::run_frames` / `run_major_frame`): a cyclic
//! schedule of time windows where each partition's tasks run only inside their window. Builds on
//! the suspend/resume temporal-isolation primitive; this checks the governor cycles through all
//! partitions and that nothing runs before the frame opens.

#![cfg(feature = "containers")]

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bismuth::security::container::{self, ContainerDecl, ContainerEntry, ContainerManifest, OnFault, Window, validate_containers};
use bismuth::security::manifest::DomainDecl;
use bismuth::security::DomainSpec;
use bismuth::{Stack, UserStack1K, sim, task, user};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static CNT_A: AtomicU32 = AtomicU32::new(0);
static CNT_B: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicBool = AtomicBool::new(false);
static SNAP_BEFORE: AtomicU32 = AtomicU32::new(0);

static SA: UserStack1K = UserStack1K::new();
static SB: UserStack1K = UserStack1K::new();
static GOV: Stack<4096> = Stack::new();

extern "C-unwind" fn part_a(_: usize) {
    while !DONE.load(Ordering::Relaxed) {
        CNT_A.fetch_add(1, Ordering::Relaxed);
        user::sleep_ticks(1);
    }
    user::exit(0)
}

extern "C-unwind" fn part_b(_: usize) {
    while !DONE.load(Ordering::Relaxed) {
        CNT_B.fetch_add(1, Ordering::Relaxed);
        user::sleep_ticks(1);
    }
    user::exit(0)
}

static MANIFEST: ContainerManifest = ContainerManifest {
    containers: &[
        ContainerDecl {
            domain: DomainDecl { spec: DomainSpec::sandboxed("part_a", 8, 2), grants: &[], dirs: &[] },
            entry: ContainerEntry::user(part_a, 5, &SA),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
        ContainerDecl {
            domain: DomainDecl { spec: DomainSpec::sandboxed("part_b", 8, 2), grants: &[], dirs: &[] },
            entry: ContainerEntry::user(part_b, 5, &SB),
            version: 1,
            cpu: None,
            ram_bytes: 1024,
            on_fault: OnFault::Stop,
            image_hash: [0; 32],
        },
    ],
    supervisor: None,
};
const _: () = validate_containers(&MANIFEST);

fn governor(_: usize) {
    let a = container::find("part_a").unwrap();
    let b = container::find("part_b").unwrap();
    let frame = [Window { container: a, ticks: 8 }, Window { container: b, ticks: 8 }];
    // run_frames suspends every partition first; give them a few ticks to prove that with all
    // partitions suspended nothing advances before the frame actually opens.
    container::suspend(a).unwrap();
    container::suspend(b).unwrap();
    task::sleep_ticks(6);
    SNAP_BEFORE.store(CNT_A.load(Ordering::Relaxed) + CNT_B.load(Ordering::Relaxed), Ordering::Relaxed);
    // Two major frames: each partition gets two windows.
    container::run_frames(&frame, 2).unwrap();
    // Tear down: let both workers observe DONE and exit so the sim completes.
    DONE.store(true, Ordering::Relaxed);
    container::resume(a).unwrap();
    container::resume(b).unwrap();
}

#[test]
fn the_major_frame_cycles_every_partition() {
    let _s = serial();
    CNT_A.store(0, Ordering::Relaxed);
    CNT_B.store(0, Ordering::Relaxed);
    DONE.store(false, Ordering::Relaxed);
    SNAP_BEFORE.store(0, Ordering::Relaxed);
    sim::run_to_completion(|| {
        container::install(&MANIFEST).unwrap();
        container::start(container::find("part_a").unwrap()).unwrap();
        container::start(container::find("part_b").unwrap()).unwrap();
        task::spawn("gov", 7, &GOV, governor, 0).unwrap();
    });
    assert_eq!(SNAP_BEFORE.load(Ordering::Relaxed), 0, "nothing runs while every partition is suspended");
    assert!(CNT_A.load(Ordering::Relaxed) >= 1, "partition A ran in its windows");
    assert!(CNT_B.load(Ordering::Relaxed) >= 1, "partition B ran in its windows");
}
