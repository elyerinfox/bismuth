//! A hardware-isolated (sandboxed) task reaching the filesystem through capabilities and
//! the FS_* syscalls: it names a granted directory capability, opens files within that
//! subtree, reads/writes under rights checks, and cannot escape the subtree or exceed the
//! rights it was granted. Host-tested in the simulator (the MPU enforces the memory side
//! on real hardware; see the QEMU board demo).

use std::sync::Mutex as StdMutex;

use bismuth::fs::{self, NodeKind, OpenMode, RamFs};
use bismuth::security::manifest::{self, DirGrantDecl, DomainDecl, Manifest};
use bismuth::security::{self, BadHandlePolicy, DomainSpec, Rights};
use bismuth::{UserStack2K, sim, task, user};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
fn note(s: impl Into<String>) {
    LOG.lock().unwrap().push(s.into());
}
fn take() -> Vec<String> {
    std::mem::take(&mut *LOG.lock().unwrap())
}

static FS: RamFs<32, 64, 64> = RamFs::new();
static US: UserStack2K = UserStack2K::new();

static FS3: RamFs<32, 64, 64> = RamFs::new();

#[test]
fn cap_opendir_lists_only_within_the_granted_subtree() {
    let _s = serial();
    FS3.format();
    sim::run_to_completion(|| {
        fs::mount("/ls", &FS3).unwrap();
        fs::mkdir("/ls/jail").unwrap();
        for name in ["a.txt", "b.txt"] {
            let mut p = String::from("/ls/jail/");
            p.push_str(name);
            fs::close(fs::open(&p, OpenMode::RDWR.with(OpenMode::CREATE)).unwrap());
        }
        fs::mkdir("/ls/jail/sub").unwrap();

        // Grant the current (trusted) domain a read capability over the jail, then list it
        // through that capability — the confined analogue of opendir.
        let h = fs::grant_dir(security::current(), "/ls/jail", Rights::READ, "lsjail").unwrap();
        let cap = fs::DirCap::from_handle(h);

        let d = fs::cap_opendir(&cap, ".").unwrap();
        let mut names: Vec<String> = Vec::new();
        let mut saw_subdir = false;
        let mut e = bismuth::fs::DirEntry::default();
        while fs::readdir(d, &mut e).unwrap() {
            if e.name() == "sub" {
                saw_subdir = e.kind == NodeKind::Dir;
            }
            names.push(e.name().to_string());
        }
        fs::closedir(d);
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".into(), "sub".into()]);
        assert!(saw_subdir, "'sub' reported as a directory");

        // A file path is not a directory.
        assert_eq!(fs::cap_opendir(&cap, "a.txt").err(), Some(bismuth::Error::NotADirectory));
        // A subdirectory within the jail opens fine; `..` is clamped at the jail root (no escape),
        // so it still resolves to a directory inside the subtree rather than the real parent.
        assert!(fs::cap_opendir(&cap, "sub").is_ok());
        assert!(fs::cap_opendir(&cap, "../..").is_ok());
    });
}

// OpenMode bits as the syscall ABI carries them (see `fs::OpenMode`).
const READ: u8 = OpenMode::READ.0;
const RDWR: u8 = OpenMode::RDWR.0;

extern "C-unwind" fn jailed_app(_: usize) {
    // Resolve the two directory caps the manifest granted us.
    let ro = user::fs_diropen("ro").unwrap();
    let rw = user::fs_diropen("rw").unwrap();
    note(format!("diropen missing: {:?}", user::fs_diropen("nope").err()));

    // Read a pre-seeded file through the read-only cap.
    let f = user::fs_open(ro, "ok.txt", READ).unwrap();
    let mut buf = [0u8; 16];
    let n = user::fs_read(f, &mut buf).unwrap();
    note(format!("read: {:?}", core::str::from_utf8(&buf[..n])));
    // Writing through a READ-only file handle is refused.
    note(format!("write via ro-handle: {:?}", user::fs_write(f, b"x").err()));
    user::fs_close(f).unwrap();

    // Opening for write through a READ-only *directory* cap is refused before any file opens.
    note(format!("open-write via ro-cap: {:?}", user::fs_open(ro, "ok.txt", RDWR).err()));

    // The subtree confines us: `..` cannot escape above the granted directory.
    note(format!("escape ../secret: {:?}", user::fs_open(ro, "../secret.txt", READ).err()));

    // Through the read-write cap we may modify a file, and the change is visible on re-read.
    let w = user::fs_open(rw, "ok.txt", RDWR).unwrap();
    note(format!("write via rw-cap: {:?}", user::fs_write(w, b"PATCHED")));
    user::fs_close(w).unwrap();
    let r = user::fs_open(ro, "ok.txt", READ).unwrap();
    let n = user::fs_read(r, &mut buf).unwrap();
    note(format!("reread: {:?}", core::str::from_utf8(&buf[..n])));
    user::fs_close(r).unwrap();
}

#[test]
fn sandboxed_task_uses_files_through_capabilities() {
    let _s = serial();
    take();
    FS.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS).unwrap();
        // Seed a jail subtree plus a secret sibling that must stay unreachable.
        fs::mkdir("/jail").unwrap();
        let seed = fs::open("/jail/ok.txt", OpenMode::RDWR.with(OpenMode::CREATE)).unwrap();
        fs::write(seed, b"hello").unwrap();
        fs::close(seed);
        let secret = fs::open("/secret.txt", OpenMode::RDWR.with(OpenMode::CREATE)).unwrap();
        fs::write(secret, b"TOPSECRET").unwrap();
        fs::close(secret);
        assert_eq!(fs::stat("/jail").unwrap().kind, NodeKind::Dir);

        let d = security::create_domain(DomainSpec { bad_handle: BadHandlePolicy::Deny, ..DomainSpec::sandboxed("jail", 6, 1) }).unwrap();
        fs::grant_dir(d, "/jail", Rights::READ, "ro").unwrap();
        fs::grant_dir(d, "/jail", Rights::READ | Rights::WRITE, "rw").unwrap();
        security::seal().unwrap();

        task::Builder::new("jail").priority(4).domain(d).stack(&US).spawn_user(jailed_app, 0).unwrap();
    });
    assert_eq!(
        take(),
        [
            "diropen missing: Some(NotFound)".to_string(),
            "read: Ok(\"hello\")".into(),
            "write via ro-handle: Some(PermissionDenied)".into(),
            "open-write via ro-cap: Some(PermissionDenied)".into(),
            "escape ../secret: Some(NotFound)".into(),
            "write via rw-cap: Ok(7)".into(),
            "reread: Ok(\"PATCHED\")".into(),
        ]
    );
}

static FS2: RamFs<32, 64, 64> = RamFs::new();
static US2: UserStack2K = UserStack2K::new();

// A manifest with a declarative directory grant (the `dirs` field), validated at compile time.
static MANIFEST: Manifest = Manifest {
    domains: &[DomainDecl {
        spec: DomainSpec::sandboxed("declapp", 6, 1),
        grants: &[],
        dirs: &[DirGrantDecl { path: "/data", name: "data", rights: Rights::READ }],
    }],
};
const _: () = manifest::validate(&MANIFEST);

extern "C-unwind" fn declarative_app(_: usize) {
    // The directory cap named in the manifest resolves without any imperative grant_dir call.
    let d = user::fs_diropen("data").unwrap();
    let f = user::fs_open(d, "report.txt", READ).unwrap();
    let mut buf = [0u8; 16];
    let n = user::fs_read(f, &mut buf).unwrap();
    note(format!("declarative read: {:?}", core::str::from_utf8(&buf[..n])));
    // The grant is read-only: opening for write is refused.
    note(format!("declarative write: {:?}", user::fs_open(d, "report.txt", RDWR).err()));
    user::fs_close(f).unwrap();
}

#[test]
fn a_manifest_directory_grant_is_applied_declaratively() {
    let _s = serial();
    take();
    FS2.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS2).unwrap();
        fs::mkdir("/data").unwrap();
        let seed = fs::open("/data/report.txt", OpenMode::RDWR.with(OpenMode::CREATE)).unwrap();
        fs::write(seed, b"metrics").unwrap();
        fs::close(seed);

        // `apply` creates the domain and its directory capability straight from the manifest.
        let ids = manifest::apply(&MANIFEST).unwrap();
        let d = ids[0].unwrap();
        security::seal().unwrap();

        task::Builder::new("declapp").priority(4).domain(d).stack(&US2).spawn_user(declarative_app, 0).unwrap();
    });
    assert_eq!(
        take(),
        ["declarative read: Ok(\"metrics\")".to_string(), "declarative write: Some(PermissionDenied)".into()]
    );
}
