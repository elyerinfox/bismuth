//! Software timers.
//!
//! Callbacks run in a dedicated high-priority *timer service* task (created on first
//! use), not in interrupt context, so they may use any non-blocking kernel API.
//! Keep them short; long work should be handed to another task via a queue.
//!
//! Classification: L1 kernel · software timers · safe · always

use core::sync::atomic::{AtomicBool, Ordering};

use crate::Error;
use crate::config::{MAX_TIMERS, TIMER_STACK_SIZE};
use crate::kernel::cell::IrqCell;
use crate::kernel::stack::Stack;
use crate::kernel::task::{self, MAX_PRIORITY};
use crate::kernel::time::Timeout;
use crate::kernel::{WakeReason, block_on, with};

/// An object that reacts to a timer expiring (an alternative to a plain `fn(usize)`).
pub trait TimerHandler: Sync {
    fn expired(&'static self);
}

#[derive(Copy, Clone)]
enum Action {
    Fn(fn(usize), usize),
    Handler(&'static dyn TimerHandler),
}

impl Action {
    fn fire(self) {
        match self {
            Action::Fn(f, arg) => f(arg),
            Action::Handler(h) => h.expired(),
        }
    }
}

struct TState {
    action: Action,
    expires: u64,
    period: u64,
    active: bool,
}

/// A one-shot or periodic software timer. Declare it as a `static`.
pub struct Timer {
    state: IrqCell<TState>,
}

struct Service {
    table: [Option<&'static Timer>; MAX_TIMERS],
    dirty: bool,
}

static SERVICE: IrqCell<Service> = IrqCell::new(Service { table: [None; MAX_TIMERS], dirty: false });
static SPAWNED: AtomicBool = AtomicBool::new(false);
static STACK: Stack<TIMER_STACK_SIZE> = Stack::new();
static WAKE_ANCHOR: u8 = 0;

fn wake_key() -> usize {
    &WAKE_ANCHOR as *const u8 as usize
}

impl Timer {
    /// A timer that calls `callback(arg)`.
    pub const fn new(callback: fn(usize), arg: usize) -> Self {
        Timer { state: IrqCell::new(TState { action: Action::Fn(callback, arg), expires: 0, period: 0, active: false }) }
    }

    /// Change the argument passed to a `fn(usize)` callback.
    pub fn set_arg(&self, arg: usize) {
        self.state.lock(|s| {
            if let Action::Fn(f, _) = s.action {
                s.action = Action::Fn(f, arg);
            }
        });
    }

    /// Deliver expirations to `handler` instead of the callback.
    pub fn set_handler(&self, handler: &'static dyn TimerHandler) {
        self.state.lock(|s| s.action = Action::Handler(handler));
    }

    /// Start (or restart) the timer: fire after `delay` ticks, then every `period` ticks
    /// (`period == 0` means one-shot).
    pub fn start(&'static self, delay: u64, period: u64) -> Result<(), Error> {
        ensure_service()?;
        with(|k| {
            SERVICE.lock(|svc| {
                let present = svc.table.iter().flatten().any(|t| core::ptr::eq(*t, self));
                if !present {
                    let slot = svc.table.iter_mut().find(|s| s.is_none()).ok_or(Error::NoResources)?;
                    *slot = Some(self);
                }
                svc.dirty = true;
                Ok(())
            })?;
            let now = k.tick;
            self.state.lock(|s| {
                s.expires = now + delay.max(1);
                s.period = period;
                s.active = true;
            });
            k.wake_all(wake_key(), WakeReason::Signaled);
            Ok(())
        })
    }

    pub fn start_ms(&'static self, delay_ms: u64, period_ms: u64) -> Result<(), Error> {
        use crate::kernel::time::ms_to_ticks;
        self.start(ms_to_ticks(delay_ms), ms_to_ticks(period_ms))
    }

    pub fn stop(&'static self) {
        self.state.lock(|s| s.active = false);
        SERVICE.lock(|svc| {
            for slot in svc.table.iter_mut() {
                if slot.is_some_and(|t| core::ptr::eq(t, self)) {
                    *slot = None;
                }
            }
        });
    }

    pub fn is_active(&self) -> bool {
        self.state.lock(|s| s.active)
    }
}

fn ensure_service() -> Result<(), Error> {
    let first = crate::arch::port::critical(|| !SPAWNED.swap(true, Ordering::Relaxed));
    if first {
        let r = task::Builder::new("timers")
            .priority(MAX_PRIORITY)
            .stack(&STACK)
            .daemon(true)
            .detached(true)
            .kernel_service()
            .spawn(service_main, 0);
        if let Err(e) = r {
            SPAWNED.store(false, Ordering::Relaxed);
            return Err(e);
        }
    }
    Ok(())
}

fn service_main(_: usize) {
    loop {
        let mut due: [Option<Action>; MAX_TIMERS] = [None; MAX_TIMERS];
        let now = crate::kernel::time::ticks();
        let next = SERVICE.lock(|svc| {
            let mut next = u64::MAX;
            for (n, slot) in svc.table.iter_mut().enumerate() {
                let Some(t) = *slot else { continue };
                let keep = t.state.lock(|s| {
                    if !s.active {
                        return None;
                    }
                    if s.expires <= now {
                        due[n] = Some(s.action);
                        if s.period == 0 {
                            s.active = false;
                            return None;
                        }
                        s.expires += s.period;
                        if s.expires <= now {
                            s.expires = now + s.period;
                        }
                    }
                    Some(s.expires)
                });
                match keep {
                    Some(e) => next = next.min(e),
                    None => *slot = None,
                }
            }
            next.checked_sub(now)
        });
        for action in due.into_iter().flatten() {
            action.fire();
        }
        let timeout = match next {
            Some(t) => Timeout::Ticks(t),
            None => Timeout::Forever,
        };
        let _ = block_on(
            wake_key(),
            timeout,
            |_| SERVICE.lock(|svc| svc.dirty.then(|| svc.dirty = false)),
            |_| (),
            |_| {},
        );
    }
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    SERVICE.lock(|svc| {
        svc.table = [None; MAX_TIMERS];
        svc.dirty = false;
    });
    SPAWNED.store(false, Ordering::Relaxed);
}
