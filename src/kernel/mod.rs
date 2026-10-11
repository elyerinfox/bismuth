//! The kernel core: task table, scheduler state, blocking/wakeup and tick processing.
//!
//! All kernel state lives in one statically allocated `Kernel` that is only ever touched
//! inside a critical section (see `with`). Kernel objects (mutexes, queues, ...) do not
//! keep intrusive wait lists; a blocked task instead records the *key* (the address of the
//! object) it waits on. With task counts in the tens this keeps every object `const`-
//! constructible and movable while idle, at the cost of an O(n) scan on wake-up.
//!
//! Classification: L1 kernel · scheduler core · safe · always

pub mod cell;
pub mod idle;
pub mod mem;
pub(crate) mod stack;
pub mod task;
pub mod time;
pub mod timer;
pub(crate) mod usermem;

use cell::IrqCell;

use crate::arch::port;
use crate::config::{MAX_TASKS, PRIORITIES, TIME_SLICE_TICKS};
use stack::StackRef;

pub(crate) const NIL: u8 = u8::MAX;
pub(crate) const IDLE: u8 = 0;
/// Key used by tasks that sleep without waiting on any object.
pub(crate) const KEY_SLEEP: usize = 1;
/// Key used by tasks blocked in [`task::notify_wait`].
pub(crate) const KEY_NOTIFY: usize = 2;

/// Lifecycle state of a task slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TaskState {
    /// Slot unused.
    Free,
    /// Runnable (the running task is also `Ready`).
    Ready,
    /// Waiting on an object and/or a timeout.
    Blocked,
    /// Explicitly suspended; will not run until resumed.
    Suspended,
    /// Finished; waiting to be joined (or reaped if detached).
    Dead,
}

/// Why a blocked task was made ready again.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum WakeReason {
    None,
    /// The object it waited on changed; re-check the condition.
    Signaled,
    /// The waker completed the operation on the task's behalf (e.g. passed mutex ownership).
    Handoff,
    /// The timeout expired.
    Timeout,
    /// The wait was cancelled (task suspended or object destroyed).
    Aborted,
}

pub(crate) struct Tcb {
    pub state: TaskState,
    pub name: &'static str,
    pub generation: u16,
    /// Priority assigned by the user.
    pub base_prio: u8,
    /// Effective priority (raised by priority inheritance).
    pub prio: u8,
    pub next: u8,
    pub prev: u8,
    pub wait_key: usize,
    pub wait_seq: u32,
    pub wake_at: u64,
    pub wake_reason: WakeReason,
    /// Saved stack pointer (used by bare-metal ports).
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub sp: usize,
    pub stack: Option<StackRef>,
    pub entry: Option<fn(usize)>,
    pub arg: usize,
    pub mutexes_held: u16,
    #[cfg_attr(not(feature = "posix"), allow(dead_code))]
    pub errno: i32,
    pub exit_code: usize,
    pub detached: bool,
    /// System tasks (idle, timer service) do not keep the simulator alive.
    pub daemon: bool,
    /// Security domain the task belongs to (0 = kernel domain).
    pub domain: u8,
    /// Runs unprivileged under the MPU and talks to the kernel only via syscalls.
    pub user: bool,
    /// Entry point of a user (unprivileged) task.
    pub user_entry: Option<extern "C-unwind" fn(usize)>,
    /// Private kernel stack used while a user task executes a syscall.
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub kstack: Option<StackRef>,
    // These carry the saved user context across a syscall on bare-metal ports that run user
    // tasks (Cortex-M, x86-64, aarch64). The AArch32 Cortex-A port is staged: it reaches
    // user (USR-mode) tasks in a later stage, so they are not yet read there.
    /// Saved user stack pointer while inside a syscall (bare-metal ports).
    #[cfg_attr(any(not(target_os = "none"), feature = "cortex-a"), allow(dead_code))]
    pub user_psp: usize,
    /// EXC_RETURN of the user frame saved at syscall entry (bare-metal ports).
    #[cfg_attr(any(not(target_os = "none"), feature = "cortex-a"), allow(dead_code))]
    pub user_exc_return: u32,
    /// Pending syscall number and arguments (bare-metal ports).
    #[cfg_attr(any(not(target_os = "none"), feature = "cortex-a"), allow(dead_code))]
    pub syscall: (u32, [usize; 4]),
    #[cfg_attr(any(not(target_os = "none"), feature = "cortex-a"), allow(dead_code))]
    pub in_syscall: bool,
    pub run_ticks: u64,
    pub notify_value: u32,
    pub notify_pending: bool,
    /// Thread-local slots (backing for `pthread_key_*`).
    #[cfg_attr(not(feature = "posix"), allow(dead_code))]
    pub tls: [usize; 4],
}

impl Tcb {
    pub const EMPTY: Tcb = Tcb {
        state: TaskState::Free,
        name: "",
        generation: 0,
        base_prio: 0,
        prio: 0,
        next: NIL,
        prev: NIL,
        wait_key: 0,
        wait_seq: 0,
        wake_at: u64::MAX,
        wake_reason: WakeReason::None,
        sp: 0,
        stack: None,
        entry: None,
        arg: 0,
        mutexes_held: 0,
        errno: 0,
        exit_code: 0,
        detached: false,
        daemon: false,
        domain: 0,
        user: false,
        user_entry: None,
        kstack: None,
        user_psp: 0,
        user_exc_return: 0,
        syscall: (0, [0; 4]),
        in_syscall: false,
        run_ticks: 0,
        notify_value: 0,
        notify_pending: false,
        tls: [0; 4],
    };
}

/// Per-domain CPU budgets the scheduler enforces (set from the L3 container layer via
/// [`Kernel::set_domain_budget`], so L1 never depends upward on it). Domains are small and
/// fixed; this table mirrors `security::MAX_DOMAINS`.
pub(crate) const MAX_BUDGET_DOMAINS: usize = 8;
/// Wait key for a task blocked because its domain exceeded its CPU budget this window.
const THROTTLE_KEY: usize = 0x6246_5544; // "bFED"

#[derive(Copy, Clone)]
struct DomainBudget {
    /// Ticks the domain may run per window (0 = unlimited / no budget).
    budget_ticks: u32,
    /// Window length in ticks (0 = no budget).
    window_ticks: u32,
    /// Ticks consumed in the current window.
    consumed: u32,
    /// Tick at which the current window started.
    window_start: u64,
}

impl DomainBudget {
    const NONE: Self = DomainBudget { budget_ticks: 0, window_ticks: 0, consumed: 0, window_start: 0 };
}

pub(crate) struct Kernel {
    pub tasks: [Tcb; MAX_TASKS],
    /// Bit `p` set when the ready list for priority `p` is non-empty.
    ready_bitmap: u32,
    ready_head: [u8; PRIORITIES],
    ready_tail: [u8; PRIORITIES],
    pub current: u8,
    pub tick: u64,
    /// Earliest `wake_at` among blocked tasks (may be stale-early, never stale-late).
    next_wake: u64,
    pub started: bool,
    initialized: bool,
    wait_seq: u32,
    slice_left: u32,
    pub context_switches: u64,
    pub idle_ticks: u64,
    budgets: [DomainBudget; MAX_BUDGET_DOMAINS],
}

static KERNEL: IrqCell<Kernel> = IrqCell::new(Kernel::new());

/// Run `f` with exclusive access to the kernel state, inside a critical section.
///
/// Any context switch requested inside `f` takes effect when the critical section ends.
#[inline]
pub(crate) fn with<R>(f: impl FnOnce(&mut Kernel) -> R) -> R {
    KERNEL.lock(f)
}

/// Reset all kernel state (used by the host simulator between runs).
#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    with(|k| {
        for t in k.tasks.iter_mut() {
            if let Some(s) = t.stack.take() {
                s.release();
            }
            if let Some(s) = t.kstack.take() {
                s.release();
            }
        }
        *k = Kernel::new();
    });
}

impl Kernel {
    const fn new() -> Self {
        Kernel {
            tasks: [const { Tcb::EMPTY }; MAX_TASKS],
            ready_bitmap: 0,
            ready_head: [NIL; PRIORITIES],
            ready_tail: [NIL; PRIORITIES],
            current: IDLE,
            tick: 0,
            next_wake: u64::MAX,
            started: false,
            initialized: false,
            wait_seq: 0,
            slice_left: TIME_SLICE_TICKS,
            context_switches: 0,
            idle_ticks: 0,
            budgets: [DomainBudget::NONE; MAX_BUDGET_DOMAINS],
        }
    }

    /// Register a per-domain CPU budget (ticks allowed per window). Called from the container
    /// layer. `budget_ticks == 0` clears it. Resets the window to now.
    #[cfg(feature = "containers")]
    pub fn set_domain_budget(&mut self, domain: u8, budget_ticks: u32, window_ticks: u32) {
        if (domain as usize) < MAX_BUDGET_DOMAINS {
            self.budgets[domain as usize] = DomainBudget { budget_ticks, window_ticks, consumed: 0, window_start: self.tick };
        }
    }

    /// Ticks the domain has consumed in its current CPU-budget window.
    #[cfg(feature = "containers")]
    pub fn domain_cpu_used(&self, domain: u8) -> u32 {
        if (domain as usize) < MAX_BUDGET_DOMAINS { self.budgets[domain as usize].consumed } else { 0 }
    }

    /// Block every ready task of `domain` until tick `until` (the budget-window refill), so an
    /// over-budget container yields the CPU to its peers without being killed. The tasks wake
    /// via the normal timeout path when the window refills.
    fn throttle_domain(&mut self, domain: u8, until: u64) {
        for i in 0..MAX_TASKS as u8 {
            if i == IDLE {
                continue;
            }
            if self.tasks[i as usize].domain == domain && self.tasks[i as usize].state == TaskState::Ready {
                self.ready_remove(i);
                let t = &mut self.tasks[i as usize];
                t.state = TaskState::Blocked;
                t.wait_key = THROTTLE_KEY;
                t.wake_at = until;
                t.wake_reason = WakeReason::None;
                if until < self.next_wake {
                    self.next_wake = until;
                }
            }
        }
        port::request_switch();
    }

    /// Create the idle task on first use.
    pub fn ensure_init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        let stack = stack::idle_stack();
        self.install_task(IDLE, "idle", 0, stack, task::idle_main, 0);
        self.tasks[IDLE as usize].daemon = true;
    }

    // ----- ready queue (O(1): bitmap + per-priority doubly linked lists) -----

    fn ready_push(&mut self, i: u8, front: bool) {
        let p = self.tasks[i as usize].prio as usize;
        let (head, tail) = (self.ready_head[p], self.ready_tail[p]);
        if head == NIL {
            self.tasks[i as usize].next = NIL;
            self.tasks[i as usize].prev = NIL;
            self.ready_head[p] = i;
            self.ready_tail[p] = i;
            self.ready_bitmap |= 1 << p;
        } else if front {
            self.tasks[i as usize].prev = NIL;
            self.tasks[i as usize].next = head;
            self.tasks[head as usize].prev = i;
            self.ready_head[p] = i;
        } else {
            self.tasks[i as usize].next = NIL;
            self.tasks[i as usize].prev = tail;
            self.tasks[tail as usize].next = i;
            self.ready_tail[p] = i;
        }
    }

    fn ready_remove(&mut self, i: u8) {
        let p = self.tasks[i as usize].prio as usize;
        let (prev, next) = (self.tasks[i as usize].prev, self.tasks[i as usize].next);
        if prev == NIL {
            self.ready_head[p] = next;
        } else {
            self.tasks[prev as usize].next = next;
        }
        if next == NIL {
            self.ready_tail[p] = prev;
        } else {
            self.tasks[next as usize].prev = prev;
        }
        if self.ready_head[p] == NIL {
            self.ready_bitmap &= !(1 << p);
        }
        self.tasks[i as usize].next = NIL;
        self.tasks[i as usize].prev = NIL;
    }

    /// Highest-priority ready task (head of the highest non-empty list).
    pub fn highest_ready(&self) -> u8 {
        debug_assert!(self.ready_bitmap != 0, "idle task must always be ready");
        let p = 31 - self.ready_bitmap.leading_zeros();
        self.ready_head[p as usize]
    }

    /// Whether any task other than the idle task is ready.
    pub fn has_ready_work(&self) -> bool {
        self.ready_bitmap & !1 != 0
    }

    /// Choose the next task to run and make it current. Called by ports at switch time.
    pub fn schedule(&mut self) -> u8 {
        let next = self.highest_ready();
        if next != self.current {
            self.context_switches += 1;
            self.slice_left = TIME_SLICE_TICKS;
        }
        self.current = next;
        next
    }

    /// Ask for a context switch if `i` should preempt the running task.
    fn preempt_check(&mut self, i: u8) {
        let cur = &self.tasks[self.current as usize];
        if !self.started {
            return;
        }
        if cur.state != TaskState::Ready || self.tasks[i as usize].prio > cur.prio {
            port::request_switch();
        }
    }

    // ----- task slots -----

    pub fn install_task(
        &mut self,
        i: u8,
        name: &'static str,
        prio: u8,
        stack: StackRef,
        entry: fn(usize),
        arg: usize,
    ) {
        self.install_task_in(i, name, prio, stack, entry, arg, 0)
    }

    /// Like [`Self::install_task_in`] but preserves the user-task fields the caller has
    /// already filled in on the (free) slot.
    #[allow(clippy::too_many_arguments)]
    pub fn install_task_user(
        &mut self,
        i: u8,
        name: &'static str,
        prio: u8,
        stack: StackRef,
        entry: fn(usize),
        arg: usize,
        domain: u8,
    ) {
        let t = &self.tasks[i as usize];
        let (user, user_entry, kstack) = (t.user, t.user_entry, self.tasks[i as usize].kstack.take());
        let generation = self.tasks[i as usize].generation.wrapping_add(1);
        stack.paint();
        self.tasks[i as usize] = Tcb {
            state: TaskState::Ready,
            name,
            generation,
            base_prio: prio,
            prio,
            stack: Some(stack),
            entry: Some(entry),
            arg,
            domain,
            user,
            user_entry,
            kstack,
            ..Tcb::EMPTY
        };
        port::init_task(self, i);
        self.ready_push(i, false);
        self.preempt_check(i);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_task_in(
        &mut self,
        i: u8,
        name: &'static str,
        prio: u8,
        stack: StackRef,
        entry: fn(usize),
        arg: usize,
        domain: u8,
    ) {
        let generation = self.tasks[i as usize].generation.wrapping_add(1);
        // Paint the whole stack so overflow guards and high-water marks work.
        stack.paint();
        self.tasks[i as usize] = Tcb {
            state: TaskState::Ready,
            name,
            generation,
            base_prio: prio,
            prio,
            stack: Some(stack),
            entry: Some(entry),
            arg,
            domain,
            ..Tcb::EMPTY
        };
        port::init_task(self, i);
        self.ready_push(i, false);
        self.preempt_check(i);
    }

    /// Find a free slot, reaping detached dead tasks on the way.
    pub fn alloc_slot(&mut self) -> Option<u8> {
        for i in 1..MAX_TASKS as u8 {
            let t = &self.tasks[i as usize];
            if t.state == TaskState::Dead && t.detached && i != self.current {
                self.reap(i);
            }
            if self.tasks[i as usize].state == TaskState::Free {
                return Some(i);
            }
        }
        None
    }

    /// Return a dead task's slot and stack to their pools.
    pub fn reap(&mut self, i: u8) {
        debug_assert_eq!(self.tasks[i as usize].state, TaskState::Dead);
        if let Some(s) = self.tasks[i as usize].stack.take() {
            s.release();
        }
        if let Some(s) = self.tasks[i as usize].kstack.take() {
            s.release();
        }
        let generation = self.tasks[i as usize].generation;
        self.tasks[i as usize] = Tcb { generation, ..Tcb::EMPTY };
    }

    pub fn cur(&mut self) -> &mut Tcb {
        &mut self.tasks[self.current as usize]
    }

    /// Move a ready task to the back of its priority level (round-robin).
    pub fn requeue_back(&mut self, i: u8) {
        self.ready_remove(i);
        self.ready_push(i, false);
    }

    pub fn make_suspended(&mut self, i: u8, was_blocked: bool) {
        if was_blocked {
            let t = &mut self.tasks[i as usize];
            t.wait_key = 0;
            t.wake_at = u64::MAX;
            t.wake_reason = WakeReason::Aborted;
        } else {
            self.ready_remove(i);
        }
        self.tasks[i as usize].state = TaskState::Suspended;
        if i == self.current && self.started {
            port::request_switch();
        }
    }

    pub fn make_ready(&mut self, i: u8) {
        self.tasks[i as usize].state = TaskState::Ready;
        self.ready_push(i, false);
        self.preempt_check(i);
    }

    /// Suspend every runnable/blocked task of a domain (a container time-partition going out
    /// of its window): they will not run until [`resume_domain`](Self::resume_domain).
    #[cfg(feature = "containers")]
    pub fn suspend_domain(&mut self, d: u8) {
        for i in 1..MAX_TASKS as u8 {
            let s = self.tasks[i as usize].state;
            if self.tasks[i as usize].domain == d && matches!(s, TaskState::Ready | TaskState::Blocked) {
                self.make_suspended(i, matches!(s, TaskState::Blocked));
            }
        }
        port::request_switch();
    }

    /// Make every suspended task of a domain runnable again (its partition window opens).
    #[cfg(feature = "containers")]
    pub fn resume_domain(&mut self, d: u8) {
        for i in 1..MAX_TASKS as u8 {
            if self.tasks[i as usize].domain == d && self.tasks[i as usize].state == TaskState::Suspended {
                self.make_ready(i);
            }
        }
    }

    /// Wake every task blocked in `join` on task `i` (used when a task dies abruptly).
    pub fn wake_joiners(&mut self, i: u8) {
        let key = super::task::join_key(i);
        self.wake_all(key, WakeReason::Signaled);
    }

    /// Mark a task as finished. Its stack is released when it is reaped.
    pub fn retire(&mut self, i: u8, code: usize) {
        match self.tasks[i as usize].state {
            TaskState::Ready => self.ready_remove(i),
            TaskState::Free | TaskState::Dead => return,
            _ => {}
        }
        let t = &mut self.tasks[i as usize];
        t.state = TaskState::Dead;
        t.exit_code = code;
        t.wait_key = 0;
        t.wake_at = u64::MAX;
    }

    // ----- blocking & waking -----

    /// Block the running task on `key` for at most `ticks` (`None` = forever).
    /// The switch happens when the enclosing critical section ends.
    pub fn block_current(&mut self, key: usize, ticks: Option<u64>) {
        let i = self.current;
        debug_assert_ne!(i, IDLE, "the idle task must never block");
        self.ready_remove(i);
        self.wait_seq = self.wait_seq.wrapping_add(1);
        let wake_at = match ticks {
            Some(t) => self.tick.saturating_add(t.max(1)),
            None => u64::MAX,
        };
        let seq = self.wait_seq;
        let t = &mut self.tasks[i as usize];
        t.state = TaskState::Blocked;
        t.wait_key = key;
        t.wait_seq = seq;
        t.wake_at = wake_at;
        t.wake_reason = WakeReason::None;
        if wake_at < self.next_wake {
            self.next_wake = wake_at;
        }
        port::request_switch();
    }

    /// Make a blocked task ready with the given reason.
    pub fn wake(&mut self, i: u8, reason: WakeReason) {
        let t = &mut self.tasks[i as usize];
        debug_assert_eq!(t.state, TaskState::Blocked);
        t.state = TaskState::Ready;
        t.wait_key = 0;
        t.wake_at = u64::MAX;
        t.wake_reason = reason;
        self.ready_push(i, false);
        self.preempt_check(i);
    }

    /// The task that should be woken first from `key`: highest priority, then FIFO.
    pub fn highest_waiter(&self, key: usize) -> Option<u8> {
        let mut best: Option<u8> = None;
        for (i, t) in self.tasks.iter().enumerate() {
            if t.state != TaskState::Blocked || t.wait_key != key {
                continue;
            }
            best = match best {
                None => Some(i as u8),
                Some(b) => {
                    let bt = &self.tasks[b as usize];
                    let earlier = (t.wait_seq.wrapping_sub(bt.wait_seq) as i32) < 0;
                    if t.prio > bt.prio || (t.prio == bt.prio && earlier) {
                        Some(i as u8)
                    } else {
                        Some(b)
                    }
                }
            };
        }
        best
    }

    pub fn wake_one(&mut self, key: usize, reason: WakeReason) -> Option<u8> {
        let i = self.highest_waiter(key)?;
        self.wake(i, reason);
        Some(i)
    }

    pub fn wake_all(&mut self, key: usize, reason: WakeReason) -> usize {
        let mut n = 0;
        for i in 0..MAX_TASKS as u8 {
            let t = &self.tasks[i as usize];
            if t.state == TaskState::Blocked && t.wait_key == key {
                self.wake(i, reason);
                n += 1;
            }
        }
        n
    }

    /// Change a task's effective priority, keeping the ready queue consistent.
    pub fn set_effective_prio(&mut self, i: u8, prio: u8) {
        let t = &self.tasks[i as usize];
        if t.prio == prio {
            return;
        }
        let ready = t.state == TaskState::Ready;
        let lowered = prio < t.prio;
        if ready {
            self.ready_remove(i);
        }
        self.tasks[i as usize].prio = prio;
        if ready {
            // A running task that is lowered keeps its turn at the head of its new level.
            let front = i == self.current;
            self.ready_push(i, front);
            if lowered && i == self.current {
                if self.started {
                    port::request_switch();
                }
            } else {
                self.preempt_check(i);
            }
        }
    }

    // ----- time -----

    /// Advance time by one tick. Called from the tick interrupt (or the simulator).
    pub fn tick(&mut self) {
        self.tick += 1;
        time::MONOTONIC.store(self.tick as usize, core::sync::atomic::Ordering::Relaxed);
        let cur = self.current;
        self.tasks[cur as usize].run_ticks += 1;
        if cur == IDLE {
            self.idle_ticks += 1;
        } else {
            // Charge the running container's CPU budget; throttle it if it overran this window.
            let d = self.tasks[cur as usize].domain as usize;
            let now = self.tick;
            if d < MAX_BUDGET_DOMAINS && self.budgets[d].window_ticks > 0 {
                let over = {
                    let b = &mut self.budgets[d];
                    if now.wrapping_sub(b.window_start) >= b.window_ticks as u64 {
                        b.consumed = 0;
                        b.window_start = now;
                    }
                    b.consumed += 1;
                    b.consumed >= b.budget_ticks
                };
                if over {
                    let until = self.budgets[d].window_start + self.budgets[d].window_ticks as u64;
                    self.throttle_domain(d as u8, until);
                }
            }
        }
        if self.tick >= self.next_wake {
            self.process_timeouts();
        }
        if TIME_SLICE_TICKS > 0 {
            self.slice_left = self.slice_left.saturating_sub(1);
            if self.slice_left == 0 {
                self.slice_left = TIME_SLICE_TICKS;
                let p = self.tasks[cur as usize].prio as usize;
                if self.tasks[cur as usize].state == TaskState::Ready
                    && self.ready_head[p] == cur
                    && self.ready_tail[p] != cur
                {
                    self.ready_remove(cur);
                    self.ready_push(cur, false);
                    port::request_switch();
                }
            }
        }
    }

    /// Jump straight to `tick` (used by tickless idle and the virtual-time simulator). The
    /// x86-64 and AArch32 Cortex-A ports keep their timer running during light sleep, so they
    /// never need the jump (only the Cortex-M SysTick-suppression path and the host sim do).
    #[cfg(any(not(target_os = "none"), all(target_arch = "arm", not(feature = "cortex-a"))))]
    pub fn advance_to(&mut self, tick: u64) {
        if tick > self.tick {
            self.idle_ticks += tick - self.tick;
            self.tick = tick;
            time::MONOTONIC.store(self.tick as usize, core::sync::atomic::Ordering::Relaxed);
            if self.tick >= self.next_wake {
                self.process_timeouts();
            }
        }
    }

    fn process_timeouts(&mut self) {
        let mut next = u64::MAX;
        for i in 0..MAX_TASKS as u8 {
            let t = &self.tasks[i as usize];
            if t.state != TaskState::Blocked || t.wake_at == u64::MAX {
                continue;
            }
            if t.wake_at <= self.tick {
                self.wake(i, WakeReason::Timeout);
            } else if t.wake_at < next {
                next = t.wake_at;
            }
        }
        self.next_wake = next;
    }

    /// Earliest pending timeout, if any (recomputed exactly).
    pub fn next_timeout(&mut self) -> Option<u64> {
        let next = self
            .tasks
            .iter()
            .filter(|t| t.state == TaskState::Blocked && t.wake_at != u64::MAX)
            .map(|t| t.wake_at)
            .min()
            .unwrap_or(u64::MAX);
        self.next_wake = next;
        (next != u64::MAX).then_some(next)
    }

    /// Number of tasks that are not free, dead, or the idle task.
    #[cfg(not(target_os = "none"))]
    pub fn live_tasks(&self) -> usize {
        self.tasks
            .iter()
            .enumerate()
            .filter(|(_, t)| !t.daemon && !matches!(t.state, TaskState::Free | TaskState::Dead))
            .count()
    }

    /// Whether the running context is allowed to block.
    pub fn can_block(&self) -> bool {
        self.started && !port::in_isr() && self.current != IDLE
    }
}

/// Generic blocking helper.
///
/// `attempt` runs inside a critical section; returning `Some` completes the operation.
/// Otherwise the task blocks on `key` until signalled or the timeout expires, and
/// `attempt` is retried. A [`WakeReason::Handoff`] wake completes with `on_handoff`.
pub(crate) fn block_on<R>(
    key: usize,
    timeout: time::Timeout,
    mut attempt: impl FnMut(&mut Kernel) -> Option<R>,
    mut on_handoff: impl FnMut(&mut Kernel) -> R,
    mut before_block: impl FnMut(&mut Kernel),
) -> Result<R, crate::Error> {
    let deadline = with(|k| timeout.deadline(k.tick));
    loop {
        enum Step<R> {
            Done(R),
            Fail(crate::Error),
            Blocked,
        }
        let step = with(|k| {
            if let Some(r) = attempt(k) {
                return Step::Done(r);
            }
            let remaining = match deadline {
                time::Deadline::Now => return Step::Fail(crate::Error::WouldBlock),
                time::Deadline::At(t) if t <= k.tick => return Step::Fail(crate::Error::Timeout),
                time::Deadline::At(t) => Some(t - k.tick),
                time::Deadline::Never => None,
            };
            if !k.can_block() {
                return Step::Fail(crate::Error::WouldBlock);
            }
            before_block(k);
            k.block_current(key, remaining);
            Step::Blocked
        });
        match step {
            Step::Done(r) => return Ok(r),
            Step::Fail(e) => return Err(e),
            Step::Blocked => {}
        }
        // We have been switched out and back in; find out why.
        let done = with(|k| match k.cur().wake_reason {
            WakeReason::Handoff => Some(Ok(on_handoff(k))),
            WakeReason::Aborted => Some(Err(crate::Error::Interrupted)),
            _ => None,
        });
        if let Some(r) = done {
            return r;
        }
    }
}
