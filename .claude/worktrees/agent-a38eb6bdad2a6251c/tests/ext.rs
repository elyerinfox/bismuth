//! Dynamic extension framework: register / load / unload lifecycle, reference-counted
//! unload refusal, and the BootOnly (pre-seal) gating.

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};

use bismuth::Error;
use bismuth::ext::{self, ExtKind, Extension};
use bismuth::security;
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static LOADS: AtomicU32 = AtomicU32::new(0);
static UNLOADS: AtomicU32 = AtomicU32::new(0);

struct Demo;
impl Extension for Demo {
    fn name(&self) -> &'static str {
        "demo"
    }
    fn kind(&self) -> ExtKind {
        ExtKind::Driver
    }
    fn load(&self) -> Result<(), Error> {
        LOADS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn unload(&self) -> Result<(), Error> {
        UNLOADS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

static DEMO: Demo = Demo;

#[test]
fn load_unload_lifecycle_and_refcount() {
    let _g = serial();
    LOADS.store(0, Ordering::Relaxed);
    UNLOADS.store(0, Ordering::Relaxed);
    sim::run_to_completion(|| {
        ext::register(&DEMO).unwrap();
        assert_eq!(ext::register(&DEMO), Err(Error::Exists)); // duplicate name
        assert!(!ext::is_loaded("demo"));

        ext::load("demo").unwrap();
        assert!(ext::is_loaded("demo"));
        assert_eq!(ext::loaded_count(), 1);
        assert_eq!(ext::load("demo"), Err(Error::Busy)); // already loaded

        // A use-reference blocks unload until dropped.
        let guard = ext::acquire("demo").unwrap();
        assert_eq!(ext::unload("demo"), Err(Error::Busy));
        drop(guard);
        ext::unload("demo").unwrap();
        assert!(!ext::is_loaded("demo"));

        // Acquiring an unloaded extension fails.
        assert_eq!(ext::acquire("demo").err(), Some(Error::NotReady));
    });
    assert_eq!(LOADS.load(Ordering::Relaxed), 1);
    assert_eq!(UNLOADS.load(Ordering::Relaxed), 1);
}

static DEMO2: Demo = Demo;

#[test]
fn load_is_refused_after_seal() {
    let _g = serial();
    sim::run_to_completion(|| {
        ext::register(&DEMO2).unwrap();
        security::seal().unwrap();
        // BootOnly policy: no load/unload once policy is sealed.
        assert_eq!(ext::load("demo"), Err(Error::PermissionDenied));
    });
}
