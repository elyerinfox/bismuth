//! Deterministic host simulator: run a complete Bismuth system inside a test.
//!
//! ```ignore
//! let outcome = bismuth::sim::run(sim::Config::default(), || {
//!     task::spawn("worker", 3, &STACK, worker, 0).unwrap();
//! });
//! assert_eq!(outcome, sim::Outcome::Completed);
//! ```
//!
//! Runs are serialized through a global lock and all kernel state is reset in between,
//! so tests can be written as if each one owned a fresh device.
//!
//! Classification: support · host simulator · safe · host only

#[allow(unused_extern_crates)] // rust_2018_idioms; required to pull std into this no_std crate for host builds
extern crate std;

use std::sync::Mutex;

pub use crate::arch::host::{Outcome, interrupt, shutdown};

/// Simulator settings.
#[derive(Copy, Clone, Debug)]
pub struct Config {
    /// Stop after this many ticks (guards against systems that never finish).
    pub tick_limit: Option<u64>,
    /// Advance time with the wall clock instead of jumping to the next timeout.
    /// Use this when non-task threads (simulated hardware) inject events.
    pub realtime: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { tick_limit: Some(1_000_000), realtime: false }
    }
}

static RUN_LOCK: Mutex<()> = Mutex::new(());

/// Reset the kernel, call `setup` (which spawns tasks, registers devices, ...),
/// then run the scheduler until the system completes, deadlocks or hits a limit.
pub fn run(config: Config, setup: impl FnOnce()) -> Outcome {
    let _guard = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_all();
    crate::arch::host::configure(config.tick_limit, config.realtime);
    setup();
    let outcome = crate::arch::host::start();
    reset_all();
    outcome
}

/// Convenience wrapper: run with default settings and panic unless all tasks completed.
pub fn run_to_completion(setup: impl FnOnce()) {
    match run(Config::default(), setup) {
        Outcome::Completed => {}
        other => panic!("simulation did not complete: {other:?}"),
    }
}

fn reset_all() {
    crate::kernel::reset();
    crate::security::reset();
    crate::kernel::timer::reset();
    #[cfg(feature = "net")]
    crate::net::reset();
    crate::driver::reset();
    crate::driver::block::reset();
    #[cfg(feature = "fs")]
    crate::fs::reset();
    #[cfg(feature = "fs")]
    crate::fs::resident::reset();
    #[cfg(feature = "power")]
    crate::power::reset();
    #[cfg(feature = "extensions")]
    crate::ext::reset();
    crate::driver::char::tty::reset();
    crate::console::reset();
    #[cfg(feature = "posix")]
    crate::compat::posix::reset();
    #[cfg(feature = "freertos-compat")]
    crate::compat::freertos::reset();
    crate::accel::reset();
}
