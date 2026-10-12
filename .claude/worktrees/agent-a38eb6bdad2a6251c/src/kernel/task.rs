//! Task (thread) management: creation, sleeping, priorities, joining and notifications.
//!
//! Classification: L1 kernel · task management · safe · always

use super::stack::{self, Stack, StackRef, StackSource};
use super::time::Timeout;
use super::{IDLE, KEY_NOTIFY, KEY_SLEEP, Kernel, TaskState, WakeReason, block_on, with};
use crate::Error;
use crate::arch::port;
use crate::security::DomainId;
use crate::config::{MAX_TASKS, PRIORITIES};

/// Handle to a task: slot index plus a generation counter so stale handles are detected.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(u32);

impl TaskId {
    pub(crate) fn new(index: u8, generation: u16) -> Self {
        TaskId(((generation as u32) << 8) | index as u32)
    }

    pub fn index(self) -> usize {
        (self.0 & 0xFF) as usize
    }

    pub(crate) fn generation(self) -> u16 {
        (self.0 >> 8) as u16
    }

    pub fn as_raw(self) -> u32 {
        self.0
    }

    pub fn from_raw(raw: u32) -> Self {
        TaskId(raw)
    }
}

/// Highest priority a user task may have.
pub const MAX_PRIORITY: u8 = (PRIORITIES - 1) as u8;
/// Lowest priority a user task may have (0 is the idle task).
pub const MIN_PRIORITY: u8 = 1;

/// Configures and creates a task.
///
/// ```ignore
/// static STACK: Stack<2048> = Stack::new();
/// let id = task::Builder::new("sensor").priority(5).stack(&STACK).spawn(sensor_main, 0)?;
/// ```
pub struct Builder {
    name: &'static str,
    priority: u8,
    stack: Option<StackRef>,
    stack_taken: bool,
    detached: bool,
    daemon: bool,
    domain: Option<DomainId>,
    kernel_service: bool,
    /// A loaded Linux executable's `(entry, sp_el0)` — both addresses inside the EL0-exec image
    /// buffer the `compat::linux` loader prepared. Set via [`Builder::spawn_linux`].
    #[cfg(feature = "linux-abi")]
    linux: Option<(usize, usize)>,
}

impl Builder {
    pub fn new(name: &'static str) -> Self {
        Builder {
            name,
            priority: MIN_PRIORITY,
            stack: None,
            stack_taken: false,
            detached: false,
            daemon: false,
            domain: None,
            kernel_service: false,
            #[cfg(feature = "linux-abi")]
            linux: None,
        }
    }

    pub fn priority(mut self, p: u8) -> Self {
        self.priority = p;
        self
    }

    /// Run on a dedicated static stack (otherwise a pool stack is used).
    pub fn stack<S: StackSource>(mut self, s: &'static S) -> Self {
        if let Some(old) = self.stack.take() {
            old.release();
        }
        self.stack = s.claim();
        self.stack_taken = true;
        self
    }

    /// Run on an already claimed stack region.
    pub fn stack_ref(mut self, s: StackRef) -> Self {
        self.stack = Some(s);
        self.stack_taken = true;
        self
    }

    /// Detached tasks are reclaimed automatically when they exit and cannot be joined.
    pub fn detached(mut self, d: bool) -> Self {
        self.detached = d;
        self
    }

    /// System/background task: does not count as "live" work for the simulator.
    pub fn daemon(mut self, d: bool) -> Self {
        self.daemon = d;
        self
    }

    /// Run the task in security domain `d` (default: the creator's domain). Only trusted
    /// domains may create tasks in another domain; the target's priority ceiling and
    /// task quota apply.
    pub fn domain(mut self, d: DomainId) -> Self {
        self.domain = Some(d);
        self
    }

    /// Kernel-internal services always run in the kernel domain, whoever starts them.
    pub(crate) fn kernel_service(mut self) -> Self {
        self.kernel_service = true;
        self.domain = Some(DomainId::KERNEL);
        self
    }

    pub fn spawn(self, entry: fn(usize), arg: usize) -> Result<TaskId, Error> {
        self.spawn_impl(entry, None, arg)
    }

    /// Spawn a **hardware-isolated** task: it runs unprivileged under the MPU, can access
    /// only its own stack (plus read-only flash), and reaches the kernel exclusively
    /// through [`crate::user`] system calls. The stack must be a power-of-two size,
    /// aligned to its size (use [`UserStack1K`](super::stack::UserStack1K) and friends),
    /// and the target domain must not be trusted.
    pub fn spawn_user(self, entry: extern "C-unwind" fn(usize), arg: usize) -> Result<TaskId, Error> {
        if !port::supports_user_tasks() {
            return Err(Error::Unsupported); // no MPU: refuse rather than run unconfined
        }
        match self.stack.as_ref() {
            Some(s) if s.len().is_power_of_two() && s.len() >= 256 && (s.base() as usize) % s.len() == 0 => {}
            Some(_) => return Err(Error::Invalid),
            None if self.stack_taken => return Err(Error::Busy),
            None => return Err(Error::Invalid),
        }
        self.spawn_impl(idle_main, Some(entry), arg)
    }

    /// Spawn a **loaded Linux executable** as a hardware-isolated EL0 task (`linux-abi`): it
    /// enters at `entry` with `sp_el0` as its stack pointer (both addresses in the EL0-exec image
    /// buffer the loader prepared), its `svc` traps route to the Linux ABI, and its reads/writes
    /// are confined to the EL0 pages the loader opened. The pool stack claimed here is only the
    /// kernel-stack anchor and the slot's nominal user stack; the task runs on `sp_el0`.
    #[cfg(feature = "linux-abi")]
    pub fn spawn_linux(mut self, entry: usize, sp_el0: usize) -> Result<TaskId, Error> {
        if !port::supports_user_tasks() {
            return Err(Error::Unsupported);
        }
        self.linux = Some((entry, sp_el0));
        self.spawn_impl(idle_main, Some(linux_entry_stub), 0)
    }

    fn spawn_impl(mut self, entry: fn(usize), user: Option<extern "C-unwind" fn(usize)>, arg: usize) -> Result<TaskId, Error> {
        if !(MIN_PRIORITY..=MAX_PRIORITY).contains(&self.priority) {
            return Err(Error::Invalid);
        }
        let creator = crate::security::current();
        let target = self.domain.unwrap_or(creator);
        if !self.kernel_service {
            let live = with(|k| {
                k.tasks
                    .iter()
                    .filter(|t| t.domain == target.0 && !matches!(t.state, TaskState::Free | TaskState::Dead))
                    .count()
            });
            // On failure the builder's Drop returns any claimed stack.
            crate::security::check_spawn(creator, target, self.priority, live, user.is_some())?;
        }
        let stack = match self.stack.take() {
            Some(s) => s,
            None if self.stack_taken => return Err(Error::Busy),
            None => stack::pool_take().ok_or(Error::NoMemory)?,
        };
        if stack.len() < 256 {
            stack.release();
            return Err(Error::Invalid);
        }
        // Unprivileged tasks need a private kernel stack for syscalls (bare metal only).
        #[cfg(target_os = "none")]
        let kstack = match user {
            Some(_) => match stack::pool_take() {
                Some(k) => {
                    k.paint(); // overflow guard + high-water mark for the kernel stack
                    Some(k)
                }
                None => {
                    stack.release();
                    return Err(Error::NoMemory);
                }
            },
            None => None,
        };
        #[cfg(not(target_os = "none"))]
        let kstack: Option<StackRef> = None;
        let res = with(|k| {
            k.ensure_init();
            let Some(i) = k.alloc_slot() else {
                return Err((stack, kstack));
            };
            {
                let t = &mut k.tasks[i as usize];
                t.user = user.is_some();
                t.user_entry = user;
                t.kstack = kstack;
                t.domain = target.0;
                #[cfg(feature = "linux-abi")]
                if let Some((lentry, lsp)) = self.linux {
                    t.is_linux = true;
                    t.linux_entry = lentry;
                    t.linux_sp = lsp;
                }
            }
            k.install_task_user(i, self.name, self.priority, stack, entry, arg, target.0);
            let t = &mut k.tasks[i as usize];
            t.detached = self.detached;
            t.daemon = self.daemon;
            Ok(TaskId::new(i, t.generation))
        });
        res.map_err(|(stack, kstack)| {
            stack.release();
            if let Some(k) = kstack {
                k.release();
            }
            Error::NoResources
        })
    }
}

impl Drop for Builder {
    fn drop(&mut self) {
        // A builder that never spawned gives its claimed stack back.
        if let Some(s) = self.stack.take() {
            s.release();
        }
    }
}

/// Spawn a task on a static stack. Shorthand for [`Builder`].
pub fn spawn<const N: usize>(
    name: &'static str,
    priority: u8,
    stack: &'static Stack<N>,
    entry: fn(usize),
    arg: usize,
) -> Result<TaskId, Error> {
    Builder::new(name).priority(priority).stack(stack).spawn(entry, arg)
}

/// The calling task.
pub fn current() -> TaskId {
    with(|k| {
        let i = k.current;
        TaskId::new(i, k.tasks[i as usize].generation)
    })
}

/// Give up the CPU to other ready tasks of the same priority.
pub fn yield_now() {
    with(|k| {
        let i = k.current;
        if k.tasks[i as usize].state == TaskState::Ready && k.started {
            k.requeue_back(i);
            port::request_switch();
        }
    });
}

/// Block for at least `ticks` ticks.
pub fn sleep_ticks(ticks: u64) {
    if ticks == 0 {
        yield_now();
        return;
    }
    let _ = block_on(KEY_SLEEP, Timeout::Ticks(ticks), |_| None::<()>, |_| (), |_| {});
}

/// Block for at least `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    sleep_ticks(super::time::ms_to_ticks(ms));
}

/// Fixed-rate periodic delay: sleeps until `*last + period` and advances `*last`.
/// Unlike repeated `sleep_ticks(period)`, this does not accumulate drift.
pub fn sleep_until(last: &mut u64, period: u64) {
    *last += period;
    let now = super::time::ticks();
    if *last > now {
        sleep_ticks(*last - now);
    } else {
        // We overran the period; catch up without sleeping.
        *last = now;
    }
}

/// Whether the calling domain may control task `id` (and set it to `prio`).
fn authorize(id: TaskId, prio: Option<u8>) -> Result<(), Error> {
    let caller = crate::security::current();
    let target = with(|k| check(k, id).map(|i| DomainId(k.tasks[i as usize].domain)))?;
    crate::security::check_task_control(caller, target, prio)
}

fn check(k: &Kernel, id: TaskId) -> Result<u8, Error> {
    let i = id.index();
    if i >= MAX_TASKS || k.tasks[i].generation != id.generation() || k.tasks[i].state == TaskState::Free {
        return Err(Error::NotFound);
    }
    Ok(i as u8)
}

/// Suspend a task. A task suspended while blocked has its wait cancelled
/// (the blocking call returns `Error::Interrupted` once resumed).
pub fn suspend(id: TaskId) -> Result<(), Error> {
    authorize(id, None)?;
    with(|k| {
        let i = check(k, id)?;
        if i == IDLE {
            return Err(Error::Invalid);
        }
        match k.tasks[i as usize].state {
            TaskState::Ready => k.make_suspended(i, false),
            TaskState::Blocked => k.make_suspended(i, true),
            TaskState::Suspended => {}
            _ => return Err(Error::Invalid),
        }
        Ok(())
    })
}

pub fn resume(id: TaskId) -> Result<(), Error> {
    authorize(id, None)?;
    with(|k| {
        let i = check(k, id)?;
        if k.tasks[i as usize].state == TaskState::Suspended {
            k.make_ready(i);
        }
        Ok(())
    })
}

/// Change a task's base priority.
pub fn set_priority(id: TaskId, prio: u8) -> Result<(), Error> {
    if !(MIN_PRIORITY..=MAX_PRIORITY).contains(&prio) {
        return Err(Error::Invalid);
    }
    authorize(id, Some(prio))?;
    with(|k| {
        let i = check(k, id)?;
        let t = &mut k.tasks[i as usize];
        let boosted = t.prio > t.base_prio;
        t.base_prio = prio;
        // Keep any priority-inheritance boost that is still higher.
        let eff = if boosted && t.prio > prio { t.prio } else { prio };
        k.set_effective_prio(i, eff);
        Ok(())
    })
}

pub fn priority(id: TaskId) -> Result<u8, Error> {
    with(|k| check(k, id).map(|i| k.tasks[i as usize].prio))
}

pub(crate) fn join_key(i: u8) -> usize {
    static JOIN_KEYS: [u8; MAX_TASKS] = [0; MAX_TASKS];
    &JOIN_KEYS[i as usize] as *const u8 as usize
}

/// Wait for a task to finish and return its exit code.
pub fn join(id: TaskId, timeout: Timeout) -> Result<usize, Error> {
    authorize(id, None)?;
    let i = with(|k| check(k, id))?;
    if with(|k| k.tasks[i as usize].detached) {
        return Err(Error::Invalid);
    }
    if with(|k| k.current) == i {
        return Err(Error::Deadlock);
    }
    let r = block_on(
        join_key(i),
        timeout,
        |k| {
            let t = &k.tasks[i as usize];
            if t.generation != id.generation() || t.state == TaskState::Free {
                return Some(Err(Error::NotFound));
            }
            if t.state == TaskState::Dead {
                let code = t.exit_code;
                k.reap(i);
                return Some(Ok(code));
            }
            None
        },
        |_| Err(Error::Invalid),
        |_| {},
    )?;
    r
}

/// Mark a task as detached: it will be reclaimed as soon as it exits.
pub fn detach(id: TaskId) -> Result<(), Error> {
    authorize(id, None)?;
    with(|k| {
        let i = check(k, id)?;
        if k.tasks[i as usize].state == TaskState::Dead {
            k.reap(i);
        } else {
            k.tasks[i as usize].detached = true;
        }
        Ok(())
    })
}

/// Terminate the calling task with an exit code.
pub fn exit(code: usize) -> ! {
    port::exit_current(code)
}

/// Kernel-side bookkeeping for a finishing task. Runs inside a critical section.
pub(crate) fn finish_current(k: &mut Kernel, code: usize) {
    let i = k.current;
    k.retire(i, code);
    k.wake_all(join_key(i), WakeReason::Signaled);
    port::request_switch();
}

/// Entry point run by every task on its own stack/thread.
pub(crate) fn run_entry(i: u8) {
    let (entry, user, arg) =
        with(|k| (k.tasks[i as usize].entry, k.tasks[i as usize].user_entry, k.tasks[i as usize].arg));
    if let Some(u) = user {
        // Host simulator: user tasks run on their thread; hardware ports enter `u`
        // directly in unprivileged mode instead.
        u(arg);
    } else if let Some(f) = entry {
        f(arg);
    }
}

// ----- direct-to-task notifications -----

/// Send a notification to a task: ORs `bits` into its notification word and wakes it.
/// Safe to call from interrupt handlers.
pub fn notify(id: TaskId, bits: u32) -> Result<(), Error> {
    with(|k| {
        let i = check(k, id)?;
        let t = &mut k.tasks[i as usize];
        t.notify_value |= bits;
        t.notify_pending = true;
        if t.state == TaskState::Blocked && t.wait_key == KEY_NOTIFY {
            k.wake(i, WakeReason::Signaled);
        }
        Ok(())
    })
}

/// Wait for a notification; returns and clears the accumulated notification bits.
pub fn notify_wait(timeout: Timeout) -> Result<u32, Error> {
    block_on(
        KEY_NOTIFY,
        timeout,
        |k| {
            let t = k.cur();
            if t.notify_pending {
                t.notify_pending = false;
                Some(core::mem::take(&mut t.notify_value))
            } else {
                None
            }
        },
        |_| 0,
        |_| {},
    )
}

// ----- introspection -----

/// A snapshot of one task, for diagnostics (`ps`-style listings).
#[derive(Copy, Clone, Debug)]
pub struct TaskInfo {
    pub id: TaskId,
    pub name: &'static str,
    pub state: TaskState,
    pub priority: u8,
    pub base_priority: u8,
    pub run_ticks: u64,
    pub stack_size: usize,
    /// Bytes of stack never touched so far.
    pub stack_free: usize,
}

/// Fill `out` with info about live tasks; returns how many were written.
pub fn list(out: &mut [TaskInfo]) -> usize {
    with(|k| {
        let mut n = 0;
        for (i, t) in k.tasks.iter().enumerate() {
            if t.state == TaskState::Free || n >= out.len() {
                continue;
            }
            let (size, free) = t.stack.as_ref().map_or((0, 0), |s| (s.len(), s.unused()));
            out[n] = TaskInfo {
                id: TaskId::new(i as u8, t.generation),
                name: t.name,
                state: t.state,
                priority: t.prio,
                base_priority: t.base_prio,
                run_ticks: t.run_ticks,
                stack_size: size,
                stack_free: free,
            };
            n += 1;
        }
        n
    })
}

pub fn info(id: TaskId) -> Result<TaskInfo, Error> {
    let mut buf = [TaskInfo {
        id,
        name: "",
        state: TaskState::Free,
        priority: 0,
        base_priority: 0,
        run_ticks: 0,
        stack_size: 0,
        stack_free: 0,
    }; MAX_TASKS];
    let n = list(&mut buf);
    buf[..n].iter().find(|t| t.id == id).copied().ok_or(Error::NotFound)
}

/// Per-task error number (POSIX `errno`).
#[cfg_attr(not(feature = "posix"), allow(dead_code))]
pub(crate) fn set_errno(e: i32) {
    with(|k| k.cur().errno = e);
}

#[cfg_attr(not(feature = "posix"), allow(dead_code))]
pub(crate) fn errno() -> i32 {
    with(|k| k.cur().errno)
}

/// Per-task thread-local slot (backs `pthread_getspecific`).
#[cfg_attr(not(feature = "posix"), allow(dead_code))]
pub(crate) fn tls_get(slot: usize) -> usize {
    with(|k| k.cur().tls.get(slot).copied().unwrap_or(0))
}

#[cfg_attr(not(feature = "posix"), allow(dead_code))]
pub(crate) fn tls_set(slot: usize, v: usize) -> bool {
    with(|k| match k.cur().tls.get_mut(slot) {
        Some(s) => {
            *s = v;
            true
        }
        None => false,
    })
}

// ----- idle -----

static IDLE_HOOK: super::cell::IrqCell<Option<fn()>> = super::cell::IrqCell::new(None);

/// Install a function the idle task calls before sleeping the CPU
/// (e.g. to feed a watchdog or enter a deeper low-power mode).
pub fn set_idle_hook(f: fn()) {
    IDLE_HOOK.lock(|h| *h = Some(f));
}

/// Placeholder user entry for a loaded Linux task: the arch port overrides `ELR_EL1` with the
/// ELF entry in [`port::init_task`], so this is never executed. It exists only so the task takes
/// the EL0 (unprivileged) spawn path.
#[cfg(feature = "linux-abi")]
extern "C-unwind" fn linux_entry_stub(_: usize) {}

pub(crate) fn idle_main(_: usize) {
    loop {
        if let Some(f) = IDLE_HOOK.lock(|h| *h) {
            f();
        }
        // On hardware the tickless governor chooses how deep to sleep; the host simulator's
        // `idle()` already is a virtual-time jump (and detects completion/deadlock), so it
        // keeps that path.
        #[cfg(target_os = "none")]
        super::idle::govern_and_sleep();
        #[cfg(not(target_os = "none"))]
        port::idle();
    }
}
