//! System power-state orchestration: ordered driver suspend/resume and the pre-sleep
//! residency flush, host-tested with recording and simulated devices.

use std::sync::Mutex as StdMutex;

use bismuth::driver::{self, DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Middleware, PowerState, Request};
use bismuth::fs::{self, OpenMode, RamFs};
use bismuth::power::{self, SystemPower};
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static LOG: StdMutex<Vec<(&'static str, PowerState)>> = StdMutex::new(Vec::new());

/// A driver that records every power transition and accepts all states.
struct Rec {
    name: &'static str,
}

impl Driver for Rec {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: self.name, class: DeviceClass::Other, version: (0, 0, 1), compatible: &[] }
    }
    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &[]
    }
    fn handle(&self, _ctx: &DeviceCtx, _req: &mut Request<'_>) -> IoResult {
        Err(bismuth::Error::Unsupported)
    }
    fn power(&self, _ctx: &DeviceCtx, state: PowerState) -> Result<(), bismuth::Error> {
        LOG.lock().unwrap().push((self.name, state));
        Ok(())
    }
}

static A: Rec = Rec { name: "a" };
static B: Rec = Rec { name: "b" };
static C: Rec = Rec { name: "c" };

#[test]
fn suspend_resume_orders_devices_leaf_to_bus_and_back() {
    let _g = serial();
    LOG.lock().unwrap().clear();
    sim::run_to_completion(|| {
        driver::register("a", &A).unwrap();
        driver::register("b", &B).unwrap();
        driver::register("c", &C).unwrap();
        assert_eq!(power::current(), SystemPower::Run);

        power::suspend_to(SystemPower::DeepSleep).unwrap();
        assert_eq!(power::current(), SystemPower::DeepSleep);

        power::resume().unwrap();
        assert_eq!(power::current(), SystemPower::Run);
    });
    let log = LOG.lock().unwrap().clone();
    // Suspend goes leaf → bus (reverse registration order), to Suspended.
    assert_eq!(
        &log[..3],
        &[("c", PowerState::Suspended), ("b", PowerState::Suspended), ("a", PowerState::Suspended)]
    );
    // Resume goes bus → leaf (registration order), back On.
    assert_eq!(&log[3..], &[("a", PowerState::On), ("b", PowerState::On), ("c", PowerState::On)]);
}

#[test]
fn suspend_is_trusted_only_and_maps_states() {
    let _g = serial();
    sim::run_to_completion(|| {
        // Standby maps devices to Suspended, Sleep to Idle, Off to Off.
        LOG.lock().unwrap().clear();
        driver::register("x", &A).unwrap();
        power::suspend_to(SystemPower::Sleep).unwrap();
        assert_eq!(LOG.lock().unwrap().last(), Some(&("a", PowerState::Idle)));
        power::suspend_to(SystemPower::Off).unwrap();
        assert_eq!(LOG.lock().unwrap().last(), Some(&("a", PowerState::Off)));
        power::resume().unwrap();
    });
}

static PFS: RamFs<16, 64, 64> = RamFs::new();

#[test]
fn suspend_flushes_hot_file_residency() {
    let _g = serial();
    PFS.format();
    sim::run_to_completion(|| {
        fs::mount("/", &PFS).unwrap();
        let f = fs::open("/k", OpenMode::RDWR.with(OpenMode::CREATE)).unwrap();
        fs::write(f, b"secret-ish").unwrap();
        fs::close(f);
        // Read it enough to promote it into the residency cache.
        for _ in 0..(bismuth::config::FS_RESIDENT_PROMOTE + 2) {
            let r = fs::open("/k", OpenMode::READ).unwrap();
            let mut b = [0u8; 16];
            let _ = fs::read(r, &mut b).unwrap();
            fs::close(r);
        }
        assert!(fs::resident::resident_count() >= 1);
        // Suspending zeroizes resident plaintext.
        power::suspend_to(SystemPower::DeepSleep).unwrap();
        assert_eq!(fs::resident::resident_count(), 0);
        power::resume().unwrap();
    });
}
