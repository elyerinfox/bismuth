//! Host simulation port.
//!
//! Every task runs on its own OS thread, but a "baton" guarantees that exactly one task
//! thread executes at a time, so the kernel behaves exactly as on a single-core MCU.
//! Context switches happen when a critical section ends with a switch pending, which
//! mirrors how PendSV fires on Cortex-M when interrupts are re-enabled.
//!
//! Time is virtual by default: when every task is blocked, the idle task jumps the tick
//! counter straight to the next timeout. Tests therefore run instantly and
//! deterministically, and a system in which every task waits forever is reported as a
//! deadlock instead of hanging.
//!
//! Classification: L0 port · host simulator port · safe · host only

#[allow(unused_extern_crates)] // rust_2018_idioms; required to pull std into this no_std crate for host builds
extern crate std;

use std::any::Any;
use std::boxed::Box;
use std::cell::Cell;
use std::string::{String, ToString};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::vec::Vec;

use crate::kernel::{self, Kernel, NIL};

std::thread_local! {
    static ME: Cell<u8> = const { Cell::new(NIL) };
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    static EXITING: Cell<bool> = const { Cell::new(false) };
}

/// The global "interrupts disabled" lock.
static LOCKED: Mutex<bool> = Mutex::new(false);
static LOCK_CV: Condvar = Condvar::new();

struct Baton {
    running: u8,
    shutdown: bool,
    outcome: Option<Outcome>,
}

static BATON: Mutex<Baton> = Mutex::new(Baton { running: NIL, shutdown: false, outcome: None });
static BATON_CV: Condvar = Condvar::new();
static SWITCH_PENDING: AtomicBool = AtomicBool::new(false);
static THREADS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

/// How the simulated system ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every non-daemon task finished.
    Completed,
    /// Tasks remain but all are blocked with no timeout pending.
    Deadlock,
    /// The configured tick limit was reached.
    TickLimit,
    /// `shutdown` was called explicitly with this code.
    Shutdown(i32),
    /// A task panicked; the message is attached.
    Panic(String),
}

/// Unwind payload used to stop parked task threads during shutdown.
struct ShutdownSignal;
/// Unwind payload used by `task::exit` to leave the task's entry function.
struct TaskExit(usize);

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn acquire() {
    let mut l = lock(&LOCKED);
    while *l {
        l = LOCK_CV.wait(l).unwrap_or_else(|e| e.into_inner());
    }
    *l = true;
}

fn release() {
    *lock(&LOCKED) = false;
    LOCK_CV.notify_one();
}

/// Nestable critical section.
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    struct Guard(u32);
    impl Drop for Guard {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(self.0));
            if self.0 == 0 {
                release();
            }
        }
    }
    let depth = DEPTH.with(|d| d.get());
    if depth == 0 {
        acquire();
    }
    DEPTH.with(|d| d.set(depth + 1));
    let g = Guard(depth);
    let r = f();
    drop(g);
    if depth == 0 {
        maybe_switch();
    }
    r
}

pub fn request_switch() {
    SWITCH_PENDING.store(true, Ordering::SeqCst);
}

/// Threads that are not task threads behave like interrupt handlers.
pub fn in_isr() -> bool {
    ME.with(|m| m.get()) == NIL
}

fn shutting_down() -> bool {
    lock(&BATON).shutdown
}

fn maybe_switch() {
    if !SWITCH_PENDING.load(Ordering::SeqCst) {
        return;
    }
    let me = ME.with(|m| m.get());
    if me == NIL {
        // An "interrupt" asked for a switch; the running task performs it at its next
        // kernel call, just as a pended PendSV would fire on real hardware.
        return;
    }
    let exiting = EXITING.with(|e| e.get());
    if shutting_down() {
        if exiting || thread::panicking() {
            return;
        }
        std::panic::resume_unwind(Box::new(ShutdownSignal));
    }
    SWITCH_PENDING.store(false, Ordering::SeqCst);
    let next = kernel::with(|k| k.schedule());
    if next == me && !exiting {
        return;
    }
    {
        let mut b = lock(&BATON);
        b.running = next;
    }
    BATON_CV.notify_all();
    if !exiting {
        wait_for_baton(me);
    }
}

fn wait_for_baton(me: u8) {
    let mut b = lock(&BATON);
    loop {
        if b.shutdown {
            drop(b);
            if thread::panicking() {
                return;
            }
            std::panic::resume_unwind(Box::new(ShutdownSignal));
        }
        if b.running == me {
            return;
        }
        b = BATON_CV.wait(b).unwrap_or_else(|e| e.into_inner());
    }
}

/// Create the execution context for task `i`: on the host, a parked thread.
pub(crate) fn init_task(k: &mut Kernel, i: u8) {
    let name = k.tasks[i as usize].name;
    let h = thread::Builder::new()
        .name(std::format!("bismuth:{name}"))
        .stack_size(1 << 20)
        .spawn(move || thread_main(i))
        .expect("failed to spawn simulator thread");
    lock(&THREADS).push(h);
}

fn panic_message(p: &(dyn Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".to_string()
    }
}

fn thread_main(i: u8) {
    ME.with(|m| m.set(i));
    let r = std::panic::catch_unwind(|| {
        wait_for_baton(i);
        kernel::task::run_entry(i);
    });
    let code = match r {
        Ok(()) => 0,
        Err(p) if p.is::<TaskExit>() => p.downcast_ref::<TaskExit>().map_or(0, |e| e.0),
        Err(p) if p.is::<ShutdownSignal>() => return,
        Err(p) => {
            let msg = std::format!("task {i} panicked: {}", panic_message(&*p));
            finish(Outcome::Panic(msg));
            return;
        }
    };
    EXITING.with(|e| e.set(true));
    kernel::with(|k| kernel::task::finish_current(k, code));
}

pub(crate) fn exit_current(code: usize) -> ! {
    std::panic::resume_unwind(Box::new(TaskExit(code)))
}

fn finish(outcome: Outcome) {
    let mut b = lock(&BATON);
    if !b.shutdown {
        b.shutdown = true;
        b.outcome = Some(outcome);
    }
    drop(b);
    BATON_CV.notify_all();
}

/// Stop the simulated system from inside a task.
pub fn shutdown(code: i32) -> ! {
    finish(Outcome::Shutdown(code));
    std::panic::resume_unwind(Box::new(ShutdownSignal))
}

// ----- simulator configuration -----

static TICK_LIMIT: AtomicU64 = AtomicU64::new(u64::MAX);
static REALTIME: AtomicBool = AtomicBool::new(false);

pub(crate) fn configure(tick_limit: Option<u64>, realtime: bool) {
    TICK_LIMIT.store(tick_limit.unwrap_or(u64::MAX), Ordering::SeqCst);
    REALTIME.store(realtime, Ordering::SeqCst);
}

/// Idle-task body: advance virtual time or detect completion/deadlock.
pub(crate) fn idle() {
    enum Act {
        Continue,
        Sleep,
        Done(Outcome),
    }
    let limit = TICK_LIMIT.load(Ordering::SeqCst);
    let realtime = REALTIME.load(Ordering::SeqCst);
    let act = kernel::with(|k| {
        if k.has_ready_work() {
            request_switch();
            return Act::Continue;
        }
        if k.live_tasks() == 0 {
            return Act::Done(Outcome::Completed);
        }
        if k.tick >= limit {
            return Act::Done(Outcome::TickLimit);
        }
        if realtime {
            return Act::Sleep;
        }
        match k.next_timeout() {
            Some(t) => {
                k.advance_to(t.min(limit));
                Act::Continue
            }
            None => {
                for t in k.tasks.iter().filter(|t| t.state == kernel::TaskState::Blocked) {
                    std::eprintln!("bismuth sim deadlock: task '{}' blocked on key {:#x}", t.name, t.wait_key);
                }
                Act::Done(Outcome::Deadlock)
            }
        }
    });
    match act {
        Act::Continue => {}
        Act::Sleep => {
            thread::sleep(std::time::Duration::from_micros(1_000_000 / crate::config::TICK_HZ as u64));
            kernel::with(|k| k.tick());
        }
        Act::Done(o) => {
            finish(o);
            std::panic::resume_unwind(Box::new(ShutdownSignal));
        }
    }
}

/// Start the scheduler and block the calling (non-task) thread until the system ends.
pub(crate) fn start() -> Outcome {
    let first = kernel::with(|k| {
        k.ensure_init();
        k.started = true;
        k.schedule()
    });
    SWITCH_PENDING.store(false, Ordering::SeqCst);
    {
        let mut b = lock(&BATON);
        b.running = first;
    }
    BATON_CV.notify_all();
    let mut b = lock(&BATON);
    while !b.shutdown {
        b = BATON_CV.wait(b).unwrap_or_else(|e| e.into_inner());
    }
    let outcome = b.outcome.take().unwrap_or(Outcome::Completed);
    drop(b);
    let handles: Vec<_> = lock(&THREADS).drain(..).collect();
    for h in handles {
        let _ = h.join();
    }
    {
        let mut b = lock(&BATON);
        b.shutdown = false;
        b.running = NIL;
    }
    SWITCH_PENDING.store(false, Ordering::SeqCst);
    outcome
}

/// Run `f` as if inside an interrupt handler (from any non-task thread this is implied).
pub fn interrupt<R>(f: impl FnOnce() -> R) -> R {
    let me = ME.with(|m| m.replace(NIL));
    let r = f();
    ME.with(|m| m.set(me));
    r
}

/// System call from a (simulated) unprivileged task: the host has no privilege levels,
/// so this runs the kernel's dispatcher directly, with identical policy checks.
/// The host simulator enforces isolation in the kernel, so user tasks are supported.
pub fn supports_user_tasks() -> bool {
    true
}

pub(crate) fn syscall(n: u32, args: [usize; 4]) -> isize {
    crate::security::syscall::dispatch(n, args)
}
