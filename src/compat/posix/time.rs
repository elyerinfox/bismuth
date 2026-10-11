//! `<time.h>`: clocks and sleeping.
//!
//! Classification: L4 personalities · POSIX clocks · safe · posix

use super::{c_int, fail};
use crate::Error;
use crate::config::TICK_HZ;
use crate::kernel::cell::IrqCell;
use crate::kernel::task;
use crate::kernel::time::{self, Timeout};

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[allow(non_camel_case_types)]
pub type clockid_t = c_int;
#[allow(non_camel_case_types)]
pub type time_t = i64;

pub const CLOCK_REALTIME: clockid_t = 0;
pub const CLOCK_MONOTONIC: clockid_t = 1;

const NS: i64 = 1_000_000_000;

/// Offset of CLOCK_REALTIME from CLOCK_MONOTONIC, in nanoseconds (set by clock_settime,
/// e.g. after an SNTP sync).
static REALTIME_OFFSET: IrqCell<i64> = IrqCell::new(0);

fn monotonic_ns() -> i64 {
    let t = time::ticks() as i128;
    (t * NS as i128 / TICK_HZ as i128) as i64
}

fn now_ns(clk: clockid_t) -> Result<i64, Error> {
    match clk {
        CLOCK_MONOTONIC => Ok(monotonic_ns()),
        CLOCK_REALTIME => Ok(monotonic_ns() + REALTIME_OFFSET.lock(|o| *o)),
        _ => Err(Error::Invalid),
    }
}

fn to_ts(ns: i64) -> timespec {
    timespec { tv_sec: ns.div_euclid(NS), tv_nsec: ns.rem_euclid(NS) }
}

fn from_ts(ts: &timespec) -> Result<i64, Error> {
    if !(0..NS).contains(&ts.tv_nsec) {
        return Err(Error::Invalid);
    }
    ts.tv_sec.checked_mul(NS).and_then(|s| s.checked_add(ts.tv_nsec)).ok_or(Error::Overflow)
}

fn ns_to_ticks_ceil(ns: i64) -> u64 {
    ((ns.max(0) as i128 * TICK_HZ as i128 + NS as i128 - 1) / NS as i128) as u64
}

pub fn clock_gettime(clk: clockid_t, tp: &mut timespec) -> c_int {
    match now_ns(clk) {
        Ok(ns) => {
            *tp = to_ts(ns);
            0
        }
        Err(e) => fail(e),
    }
}

pub fn clock_settime(clk: clockid_t, tp: &timespec) -> c_int {
    if clk != CLOCK_REALTIME {
        return fail(Error::Invalid);
    }
    match from_ts(tp) {
        Ok(ns) => {
            let off = ns - monotonic_ns();
            REALTIME_OFFSET.lock(|o| *o = off);
            0
        }
        Err(e) => fail(e),
    }
}

pub fn clock_getres(clk: clockid_t, res: &mut timespec) -> c_int {
    if now_ns(clk).is_err() {
        return fail(Error::Invalid);
    }
    *res = to_ts(NS / TICK_HZ as i64);
    0
}

/// Sleep for `req`. Bismuth sleeps are never interrupted by signals, so `rem` is
/// always set to zero.
pub fn nanosleep(req: &timespec, rem: Option<&mut timespec>) -> c_int {
    let ns = match from_ts(req) {
        Ok(ns) => ns,
        Err(e) => return fail(e),
    };
    task::sleep_ticks(ns_to_ticks_ceil(ns));
    if let Some(r) = rem {
        *r = timespec::default();
    }
    0
}

pub fn time(out: Option<&mut time_t>) -> time_t {
    let s = now_ns(CLOCK_REALTIME).unwrap_or(0) / NS;
    if let Some(o) = out {
        *o = s;
    }
    s
}

/// Convert an absolute CLOCK_REALTIME deadline into a kernel timeout.
pub(crate) fn timeout_from_abstime(abs: &timespec) -> Timeout {
    let Ok(target) = from_ts(abs) else { return Timeout::NoWait };
    let now = now_ns(CLOCK_REALTIME).unwrap_or(0);
    if target <= now { Timeout::NoWait } else { Timeout::Ticks(ns_to_ticks_ceil(target - now)) }
}
