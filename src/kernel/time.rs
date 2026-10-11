//! Kernel time: ticks, timeouts and conversions.
//!
//! Classification: L1 kernel · time · safe · always

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use crate::config::TICK_HZ;

/// A lock-free mirror of the kernel tick, updated by [`super::Kernel::tick`]/`advance_to`.
/// Readable without taking the kernel lock — so the console can timestamp log lines even
/// while the kernel lock is held (which `ticks()` could not do without re-entering it).
/// `usize` so it works on 32-bit MCU targets that lack 64-bit atomics (there the boot-time
/// stamp wraps after ~49 days at 1 kHz, which is acceptable for a log prefix).
pub(crate) static MONOTONIC: AtomicUsize = AtomicUsize::new(0);

/// Milliseconds since boot, read lock-free (for kernel-log timestamps).
pub fn ms_since_boot() -> u64 {
    ticks_to_ms(MONOTONIC.load(Ordering::Relaxed) as u64)
}

/// How long a blocking call may wait.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Timeout {
    /// Fail immediately with `WouldBlock` instead of waiting.
    NoWait,
    /// Wait at most this many ticks.
    Ticks(u64),
    /// Wait indefinitely.
    Forever,
}

pub(crate) enum Deadline {
    Now,
    At(u64),
    Never,
}

impl Timeout {
    /// A timeout of `ms` milliseconds, rounded up to whole ticks.
    pub const fn ms(ms: u64) -> Self {
        if ms == 0 { Timeout::NoWait } else { Timeout::Ticks(ms_to_ticks(ms)) }
    }

    pub fn from_duration(d: Duration) -> Self {
        Self::ms(d.as_millis().min(u64::MAX as u128) as u64)
    }

    pub(crate) fn deadline(self, now: u64) -> Deadline {
        match self {
            Timeout::NoWait | Timeout::Ticks(0) => Deadline::Now,
            Timeout::Ticks(t) => Deadline::At(now.saturating_add(t)),
            Timeout::Forever => Deadline::Never,
        }
    }
}

/// Convert milliseconds to ticks, rounding up so a delay is never shorter than asked.
pub const fn ms_to_ticks(ms: u64) -> u64 {
    (ms * TICK_HZ as u64).div_ceil(1000)
}

pub const fn ticks_to_ms(ticks: u64) -> u64 {
    ticks * 1000 / TICK_HZ as u64
}

/// Ticks since the scheduler started.
pub fn ticks() -> u64 {
    super::with(|k| k.tick)
}

/// Monotonic time since the scheduler started.
pub fn uptime() -> Duration {
    let t = ticks();
    Duration::from_secs(t / TICK_HZ as u64)
        + Duration::from_nanos((t % TICK_HZ as u64) * 1_000_000_000 / TICK_HZ as u64)
}

/// A point in kernel time, measured in ticks.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(pub u64);

impl Instant {
    pub fn now() -> Self {
        Instant(ticks())
    }

    pub fn elapsed_ticks(self) -> u64 {
        ticks().saturating_sub(self.0)
    }

    pub fn elapsed(self) -> Duration {
        Duration::from_millis(ticks_to_ms(self.elapsed_ticks()))
    }
}
