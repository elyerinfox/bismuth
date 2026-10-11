//! Middleware: composable layers between device users and drivers.
//!
//! A middleware sees every request to the devices it is attached to, can inspect or
//! rewrite it, call [`Next::run`] zero or more times, and post-process the result.
//! This module provides the trait plus a library of generic, reusable layers:
//!
//! | layer             | purpose                                                    |
//! |-------------------|------------------------------------------------------------|
//! | [`Stats`]         | per-device operation/byte/error counters and latency       |
//! | [`Trace`]         | log every request and its result to the console           |
//! | [`Exclusive`]     | serialize access (priority-inheritance mutex)              |
//! | [`RateLimit`]     | cap operations per time window                             |
//! | [`Retry`]         | retry transient failures with back-off                     |
//! | [`PowerGate`]     | power up on demand, suspend after an idle period           |
//! | [`AccessPolicy`]  | allow only selected operation kinds                        |
//! | [`NonBlocking`]   | turn `FLAG_NONBLOCK` into a zero timeout                   |
//! | [`MovingAverage`] | smooth sensor samples                                      |
//! | [`Calibrate`]     | linear fixed-point calibration of sensor samples           |
//! | [`Deadband`]      | report-by-exception: suppress readings that barely changed |
//!
//! Classification: L2 devices · middleware library · safe · always

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::{DeviceCtx, IoResult, Next, Op, OpKind, PowerState, Request};
use crate::Error;
use crate::kernel::time::{self, Timeout};
use crate::kernel::task;
use crate::sync::{IrqCell, RawMutex};
use crate::kernel::timer::{Timer, TimerHandler};

/// A layer in a device's request pipeline.
pub trait Middleware: Sync {
    /// Unique (per chain) name, used for listing and detaching.
    fn name(&self) -> &'static str;

    /// Process `req`, typically by calling `next.run(req)`.
    fn call(&self, ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult;

    /// Called when the layer is attached to a device.
    fn on_attach(&'static self, _ctx: &DeviceCtx) {}
}

/// Decode little-endian `i32` samples in a sensor read buffer.
pub(crate) fn for_each_sample(buf: &mut [u8], mut f: impl FnMut(usize, i32) -> i32) {
    for (ch, chunk) in buf.chunks_exact_mut(4).enumerate() {
        let v = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        chunk.copy_from_slice(&f(ch, v).to_le_bytes());
    }
}

// ---------------------------------------------------------------------------------------

/// Per-device counters.
pub struct Stats {
    name: &'static str,
    reads: AtomicU32,
    writes: AtomicU32,
    transfers: AtomicU32,
    ioctls: AtomicU32,
    errors: AtomicU32,
    bytes_in: AtomicU32,
    bytes_out: AtomicU32,
    max_latency_ticks: AtomicU32,
}

/// A copy of [`Stats`] counters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub reads: u32,
    pub writes: u32,
    pub transfers: u32,
    pub ioctls: u32,
    pub errors: u32,
    pub bytes_in: u32,
    pub bytes_out: u32,
    pub max_latency_ticks: u32,
}

impl Stats {
    pub const fn new() -> Self {
        Self::named("stats")
    }

    pub const fn named(name: &'static str) -> Self {
        Stats {
            name,
            reads: AtomicU32::new(0),
            writes: AtomicU32::new(0),
            transfers: AtomicU32::new(0),
            ioctls: AtomicU32::new(0),
            errors: AtomicU32::new(0),
            bytes_in: AtomicU32::new(0),
            bytes_out: AtomicU32::new(0),
            max_latency_ticks: AtomicU32::new(0),
        }
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            reads: self.reads.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            transfers: self.transfers.load(Ordering::Relaxed),
            ioctls: self.ioctls.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            max_latency_ticks: self.max_latency_ticks.load(Ordering::Relaxed),
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for Stats {
    fn name(&self) -> &'static str {
        self.name
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let start = time::ticks();
        let kind = req.op.kind();
        let r = next.run(req);
        let lat = time::ticks().saturating_sub(start).min(u32::MAX as u64) as u32;
        self.max_latency_ticks.fetch_max(lat, Ordering::Relaxed);
        let counter = match kind {
            OpKind::Read => &self.reads,
            OpKind::Write => &self.writes,
            OpKind::Transfer => &self.transfers,
            OpKind::Ioctl | OpKind::Power => &self.ioctls,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        match (&r, &req.op) {
            (Err(_), _) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
            (Ok(n), Op::Read(_)) => {
                self.bytes_in.fetch_add(*n as u32, Ordering::Relaxed);
            }
            (Ok(n), Op::Write(_)) => {
                self.bytes_out.fetch_add(*n as u32, Ordering::Relaxed);
            }
            (Ok(n), Op::Transfer { tx, .. }) => {
                self.bytes_out.fetch_add(tx.len() as u32, Ordering::Relaxed);
                self.bytes_in.fetch_add(*n as u32, Ordering::Relaxed);
            }
            _ => {}
        }
        r
    }
}

// ---------------------------------------------------------------------------------------

/// Logs every request to the console. Re-entrant use (e.g. tracing the console device
/// itself) is suppressed rather than recursing.
pub struct Trace {
    busy: AtomicBool,
}

impl Trace {
    pub const fn new() -> Self {
        Trace { busy: AtomicBool::new(false) }
    }
}

impl Default for Trace {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for Trace {
    fn name(&self) -> &'static str {
        "trace"
    }

    fn call(&self, ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        if self.busy.swap(true, Ordering::Acquire) {
            return next.run(req);
        }
        struct Clear<'a>(&'a AtomicBool);
        impl Drop for Clear<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _c = Clear(&self.busy);
        let r = next.run(req);
        crate::kprintln!("[trace t={}] {}: {:?} -> {:?}", time::ticks(), ctx.name, req.op, r);
        r
    }
}

// ---------------------------------------------------------------------------------------

/// Serializes all requests to a device with a priority-inheritance mutex, so drivers
/// that are not re-entrant can be shared safely between tasks.
pub struct Exclusive {
    lock: RawMutex,
}

impl Exclusive {
    pub const fn new() -> Self {
        Exclusive { lock: RawMutex::new_recursive() }
    }
}

impl Default for Exclusive {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for Exclusive {
    fn name(&self) -> &'static str {
        "exclusive"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        self.lock.lock(req.effective_timeout())?;
        let r = next.run(req);
        let _ = self.lock.unlock();
        r
    }
}

// ---------------------------------------------------------------------------------------

/// Behaviour of [`RateLimit`] when the budget is exhausted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LimitMode {
    /// Fail with `WouldBlock`.
    Reject,
    /// Sleep until the next window opens.
    Delay,
}

/// Allows at most `max_ops` requests per `window` ticks (fixed window).
pub struct RateLimit {
    max_ops: u32,
    window: u64,
    mode: LimitMode,
    state: IrqCell<(u64, u32)>,
}

impl RateLimit {
    pub const fn new(max_ops: u32, window_ticks: u64, mode: LimitMode) -> Self {
        RateLimit { max_ops, window: window_ticks, mode, state: IrqCell::new((0, 0)) }
    }
}

impl Middleware for RateLimit {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        loop {
            let now = time::ticks();
            let wait = self.state.lock(|(start, count)| {
                if now >= *start + self.window {
                    *start = now - (now % self.window.max(1));
                    *count = 0;
                }
                if *count < self.max_ops {
                    *count += 1;
                    None
                } else {
                    Some(*start + self.window - now)
                }
            });
            match (wait, self.mode) {
                (None, _) => return next.run(req),
                (Some(_), LimitMode::Reject) => return Err(Error::WouldBlock),
                (Some(t), LimitMode::Delay) => {
                    if req.effective_timeout() == Timeout::NoWait {
                        return Err(Error::WouldBlock);
                    }
                    task::sleep_ticks(t)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------

/// Retries transient failures (`Io`, `Timeout`, `NotReady`, `Busy`).
pub struct Retry {
    attempts: u32,
    backoff_ticks: u64,
    retries: AtomicU32,
}

impl Retry {
    pub const fn new(attempts: u32, backoff_ticks: u64) -> Self {
        Retry { attempts, backoff_ticks, retries: AtomicU32::new(0) }
    }

    /// Total number of retries performed so far.
    pub fn retries(&self) -> u32 {
        self.retries.load(Ordering::Relaxed)
    }
}

impl Middleware for Retry {
    fn name(&self) -> &'static str {
        "retry"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let mut n = 0;
        loop {
            match next.run(req) {
                Err(Error::Io | Error::Timeout | Error::NotReady | Error::Busy) if n + 1 < self.attempts => {
                    n += 1;
                    self.retries.fetch_add(1, Ordering::Relaxed);
                    if self.backoff_ticks > 0 {
                        // Exponential back-off: backoff, 2*backoff, 4*backoff, ...
                        task::sleep_ticks(self.backoff_ticks << (n - 1).min(16));
                    }
                }
                r => return r,
            }
        }
    }
}

// ---------------------------------------------------------------------------------------

/// Power management for edge devices: powers the device on when a request arrives and
/// suspends it after `idle_ticks` without activity (via a software timer).
pub struct PowerGate {
    idle_ticks: u64,
    timer: Timer,
    /// The gate itself and the gated device, recorded when attached.
    attached: IrqCell<Option<(&'static PowerGate, super::Device)>>,
    powered: AtomicBool,
    last_use: IrqCell<u64>,
    wakeups: AtomicU32,
}

impl PowerGate {
    pub const fn new(idle_ticks: u64) -> Self {
        PowerGate {
            idle_ticks,
            timer: Timer::new(|_| {}, 0),
            attached: IrqCell::new(None),
            powered: AtomicBool::new(true),
            last_use: IrqCell::new(0),
            wakeups: AtomicU32::new(0),
        }
    }

    pub fn is_powered(&self) -> bool {
        self.powered.load(Ordering::Relaxed)
    }

    /// How many times the device had to be woken up.
    pub fn wakeups(&self) -> u32 {
        self.wakeups.load(Ordering::Relaxed)
    }

    fn arm(&self) {
        if let Some((gate, _)) = self.attached.lock(|a| *a) {
            if !gate.timer.is_active() {
                let _ = gate.timer.start(self.idle_ticks, 0);
            }
        }
    }
}

impl TimerHandler for PowerGate {
    fn expired(&'static self) {
        let last = self.last_use.lock(|t| *t);
        let now = time::ticks();
        if now < last + self.idle_ticks {
            let _ = self.timer.start(last + self.idle_ticks - now, 0);
            return;
        }
        if let Some((_, dev)) = self.attached.lock(|a| *a) {
            // Goes through the chain (including this gate, which records the state).
            let _ = dev.set_power(PowerState::Suspended);
        }
    }
}

impl Middleware for PowerGate {
    fn name(&self) -> &'static str {
        "power-gate"
    }

    fn on_attach(&'static self, ctx: &DeviceCtx) {
        self.attached.lock(|a| *a = Some((self, ctx.device)));
        self.timer.set_handler(self);
        self.last_use.lock(|t| *t = time::ticks());
        self.arm();
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        if let Op::Power(state) = req.op {
            let r = next.run(req);
            if r.is_ok() {
                self.powered.store(state == PowerState::On, Ordering::Relaxed);
            }
            return r;
        }
        if !self.is_powered() {
            next.run(&mut req.derive(Op::Power(PowerState::On)))?;
            self.powered.store(true, Ordering::Relaxed);
            self.wakeups.fetch_add(1, Ordering::Relaxed);
        }
        self.last_use.lock(|t| *t = time::ticks());
        let r = next.run(req);
        self.arm();
        r
    }
}

// ---------------------------------------------------------------------------------------

/// Permits only the operation kinds in `allowed` (an [`OpKind::bit`] mask).
pub struct AccessPolicy {
    allowed: u8,
}

impl AccessPolicy {
    pub const fn allow(kinds: &[OpKind]) -> Self {
        let mut allowed = 0;
        let mut i = 0;
        while i < kinds.len() {
            allowed |= kinds[i].bit();
            i += 1;
        }
        AccessPolicy { allowed }
    }

    pub const fn read_only() -> Self {
        Self::allow(&[OpKind::Read, OpKind::Ioctl, OpKind::Power])
    }
}

impl Middleware for AccessPolicy {
    fn name(&self) -> &'static str {
        "access-policy"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        if self.allowed & req.op.kind().bit() == 0 {
            return Err(Error::PermissionDenied);
        }
        next.run(req)
    }
}

// ---------------------------------------------------------------------------------------

/// Converts `FLAG_NONBLOCK` requests into zero-timeout requests so drivers only need to
/// look at `req.timeout`.
pub struct NonBlocking;

impl Middleware for NonBlocking {
    fn name(&self) -> &'static str {
        "nonblocking"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        req.timeout = req.effective_timeout();
        next.run(req)
    }
}

// ---------------------------------------------------------------------------------------

const FILTER_CHANNELS: usize = 4;

struct AvgState<const W: usize> {
    window: [[i32; W]; FILTER_CHANNELS],
    pos: [usize; FILTER_CHANNELS],
    filled: [usize; FILTER_CHANNELS],
}

/// Moving-average filter over the last `W` samples of each sensor channel (up to 4).
pub struct MovingAverage<const W: usize> {
    state: IrqCell<AvgState<W>>,
}

impl<const W: usize> MovingAverage<W> {
    pub const fn new() -> Self {
        MovingAverage {
            state: IrqCell::new(AvgState {
                window: [[0; W]; FILTER_CHANNELS],
                pos: [0; FILTER_CHANNELS],
                filled: [0; FILTER_CHANNELS],
            }),
        }
    }
}

impl<const W: usize> Default for MovingAverage<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const W: usize> Middleware for MovingAverage<W> {
    fn name(&self) -> &'static str {
        "moving-average"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let n = next.run(req)?;
        if let Op::Read(buf) = &mut req.op {
            self.state.lock(|s| {
                for_each_sample(&mut buf[..n], |ch, v| {
                    if ch >= FILTER_CHANNELS {
                        return v;
                    }
                    s.window[ch][s.pos[ch]] = v;
                    s.pos[ch] = (s.pos[ch] + 1) % W;
                    s.filled[ch] = (s.filled[ch] + 1).min(W);
                    let sum: i64 = s.window[ch][..s.filled[ch]].iter().map(|&x| x as i64).sum();
                    (sum / s.filled[ch] as i64) as i32
                });
            });
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------------------------

/// Linear calibration of sensor samples: `out = in * num / den + offset`.
pub struct Calibrate {
    name: &'static str,
    num: i32,
    den: i32,
    offset: i32,
}

impl Calibrate {
    pub const fn new(num: i32, den: i32, offset: i32) -> Self {
        Self::named("calibrate", num, den, offset)
    }

    pub const fn named(name: &'static str, num: i32, den: i32, offset: i32) -> Self {
        assert!(den != 0);
        Calibrate { name, num, den, offset }
    }
}

impl Middleware for Calibrate {
    fn name(&self) -> &'static str {
        self.name
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let n = next.run(req)?;
        if let Op::Read(buf) = &mut req.op {
            for_each_sample(&mut buf[..n], |_, v| {
                ((v as i64 * self.num as i64) / self.den as i64 + self.offset as i64) as i32
            });
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------------------------

/// Report-by-exception: a sensor read only returns data when some channel moved by more
/// than `delta` since the last reported reading; otherwise it returns `Ok(0)`.
/// This is the classic edge-computing trick for cutting uplink traffic and radio time.
pub struct Deadband {
    delta: i32,
    last: IrqCell<([i32; FILTER_CHANNELS], bool)>,
    suppressed: AtomicU32,
}

impl Deadband {
    pub const fn new(delta: i32) -> Self {
        Deadband { delta, last: IrqCell::new(([0; FILTER_CHANNELS], false)), suppressed: AtomicU32::new(0) }
    }

    /// Number of readings suppressed so far.
    pub fn suppressed(&self) -> u32 {
        self.suppressed.load(Ordering::Relaxed)
    }
}

impl Middleware for Deadband {
    fn name(&self) -> &'static str {
        "deadband"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let n = next.run(req)?;
        let Op::Read(buf) = &mut req.op else { return Ok(n) };
        let report = self.last.lock(|(last, valid)| {
            let mut changed = !*valid;
            let mut cur = *last;
            for_each_sample(&mut buf[..n], |ch, v| {
                if ch < FILTER_CHANNELS {
                    changed |= (v as i64 - last[ch] as i64).abs() > self.delta as i64;
                    cur[ch] = v;
                }
                v
            });
            if changed {
                *last = cur;
                *valid = true;
            }
            changed
        });
        if report {
            Ok(n)
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            Ok(0)
        }
    }
}
