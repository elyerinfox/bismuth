//! Edge compute and hardware offload, end to end.

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};

use bismuth::accel::{self, CrcEngine, MacEngine};
use bismuth::driver;
use bismuth::driver::sensor::SimSensor;
use bismuth::edge::dsp::{Fir, Stage, ZScore};
use bismuth::edge::{Sample, Topic, run_pipeline};
use bismuth::security::{self, BadHandlePolicy, DeviceCap, DomainSpec, Rights};
use bismuth::{Error, Timeout, sim, task};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A "hardware" MAC engine: correct results, counts its invocations.
struct GoodMac(AtomicU32);
impl MacEngine for GoodMac {
    fn name(&self) -> &'static str {
        "sim-mac"
    }
    fn dot_q15(&self, a: &[i16], b: &[i16]) -> Result<i64, Error> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(accel::dot_q15_sw(a, b))
    }
}

/// A buggy engine (silicon erratum): saturates its accumulator at 32 bits.
struct BuggyMac;
impl MacEngine for BuggyMac {
    fn name(&self) -> &'static str {
        "buggy-mac"
    }
    fn dot_q15(&self, a: &[i16], b: &[i16]) -> Result<i64, Error> {
        Ok(accel::dot_q15_sw(a, b).clamp(i32::MIN as i64, i32::MAX as i64))
    }
}

/// A CRC engine that sometimes reports a bus error at run time.
struct FlakyCrc(AtomicU32);
impl CrcEngine for FlakyCrc {
    fn name(&self) -> &'static str {
        "flaky-crc"
    }
    fn crc32_update(&self, state: u32, data: &[u8]) -> Result<u32, Error> {
        if self.0.fetch_add(1, Ordering::Relaxed) >= 3 {
            return Err(Error::Io); // fails after the vetting vectors
        }
        Ok(accel::crc32_update_sw(state, data))
    }
}

static GOOD_MAC: GoodMac = GoodMac(AtomicU32::new(0));
static BUGGY_MAC: BuggyMac = BuggyMac;
static FLAKY_CRC: FlakyCrc = FlakyCrc(AtomicU32::new(0));

#[test]
fn accelerators_are_vetted_and_fall_back_to_software() {
    let _s = serial();
    sim::run_to_completion(|| {
        assert_eq!(accel::register_mac(&BUGGY_MAC), Err(Error::Integrity), "faulty engine rejected");
        accel::register_mac(&GOOD_MAC).unwrap();
        assert_eq!(accel::dot_q15(&[1000, 2000], &[3, 4]), 11_000);
        accel::register_crc(&FLAKY_CRC).unwrap();
        // The engine now errors at run time: results stay correct via software fallback.
        assert_eq!(accel::crc32(b"123456789"), 0xCBF4_3926);
        let st = accel::stats();
        assert_eq!((st.rejected_engines, st.fallbacks), (1, 1));
        assert!(st.offloaded >= 1);
    });
}

static SENSOR: SimSensor = SimSensor::new(1);
static ANOMALIES: Topic<Sample, 2, 8> = Topic::new();
static SEEN: StdMutex<Vec<i32>> = StdMutex::new(Vec::new());
static MAC2: GoodMac = GoodMac(AtomicU32::new(0));

#[test]
fn isolated_sensor_pipeline_publishes_only_anomalies() {
    let _s = serial();
    SEEN.lock().unwrap().clear();
    sim::run_to_completion(|| {
        accel::register_mac(&MAC2).unwrap();
        let dev = driver::register("vib0", &SENSOR).unwrap();
        let analytics = security::create_domain(DomainSpec {
            bad_handle: BadHandlePolicy::Deny,
            ..DomainSpec::isolated("analytics", 10, 2)
        })
        .unwrap();
        security::grant_device(analytics, dev, Rights::READ, "vib").unwrap();
        security::seal().unwrap();

        task::Builder::new("uplink").priority(6).spawn(|_| {
            let sub = ANOMALIES.subscribe().unwrap();
            while let Ok(s) = sub.recv(Timeout::ms(2000)) {
                SEEN.lock().unwrap().push(s.value);
            }
        }, 0).unwrap();

        task::Builder::new("analytics").priority(5).domain(analytics).spawn(|_| {
            let cap = DeviceCap::open("vib").unwrap();
            // Smooth with a 4-tap FIR (offloaded to the MAC engine), then report only
            // readings more than 4 standard deviations from the learned baseline.
            let mut stages = Fir::<4>::moving_average().then(ZScore::new(4, 32));
            let st = run_pipeline(cap, 10, Some(120), &mut stages, &ANOMALIES);
            assert_eq!(st.samples, 120);
            assert_eq!(st.read_errors, 0);
            // 4 spike samples plus FIR ramp-in/ramp-out samples that also exceed 4 sigma.
            assert!(st.published >= 1 && st.published <= 10, "{st:?}");
        }, 0).unwrap();

        task::Builder::new("fault-injector").priority(7).spawn(|_| {
            task::sleep_ticks(800);
            SENSOR.force_counts(Some(3900)); // a spike well outside the baseline
            task::sleep_ticks(40);
            SENSOR.force_counts(None);
        }, 0).unwrap();
    });
    let seen = SEEN.lock().unwrap().clone();
    assert!(!seen.is_empty(), "the spike must be reported");
    assert!(seen.iter().all(|v| *v > 4000), "only anomalous (hot) readings are published: {seen:?}");
    assert!(MAC2.0.load(Ordering::Relaxed) >= 120, "FIR used the MAC engine");
}
