//! `<pthread.h>` and `<sched.h>`.
//!
//! Classification: L4 personalities · POSIX threads · safe · posix

use super::{c_int, code};
use super::time::{timespec, timeout_from_abstime};
use crate::Error;
use crate::compat::errno::*;
use crate::config::{MAX_TASKS, POOL_STACK_SIZE};
use crate::kernel::cell::IrqCell;
use crate::kernel::task::{self, MAX_PRIORITY, MIN_PRIORITY, TaskId};
use crate::kernel::time::Timeout;
use crate::sync::{CondVar, RawMutex};

#[allow(non_camel_case_types)]
pub type pthread_t = u32;

/// A thread start routine: takes and returns a machine word (`void *` in C).
pub type StartRoutine = fn(usize) -> usize;

pub const PTHREAD_CREATE_JOINABLE: c_int = 0;
pub const PTHREAD_CREATE_DETACHED: c_int = 1;
pub const SCHED_FIFO: c_int = 1;
pub const SCHED_RR: c_int = 2;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct sched_param {
    pub sched_priority: c_int,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub struct pthread_attr_t {
    detach: c_int,
    stack_size: usize,
    priority: c_int,
    name: &'static str,
}

impl Default for pthread_attr_t {
    fn default() -> Self {
        pthread_attr_t { detach: PTHREAD_CREATE_JOINABLE, stack_size: POOL_STACK_SIZE, priority: 1, name: "pthread" }
    }
}

pub fn pthread_attr_init(attr: &mut pthread_attr_t) -> c_int {
    *attr = pthread_attr_t::default();
    0
}

pub fn pthread_attr_destroy(_attr: &mut pthread_attr_t) -> c_int {
    0
}

pub fn pthread_attr_setdetachstate(attr: &mut pthread_attr_t, state: c_int) -> c_int {
    if state != PTHREAD_CREATE_JOINABLE && state != PTHREAD_CREATE_DETACHED {
        return EINVAL;
    }
    attr.detach = state;
    0
}

pub fn pthread_attr_getdetachstate(attr: &pthread_attr_t, state: &mut c_int) -> c_int {
    *state = attr.detach;
    0
}

/// Threads run on pooled stacks of `POOL_STACK_SIZE`; larger requests fail with EINVAL.
pub fn pthread_attr_setstacksize(attr: &mut pthread_attr_t, size: usize) -> c_int {
    if size > POOL_STACK_SIZE || size < 256 {
        return EINVAL;
    }
    attr.stack_size = size;
    0
}

pub fn pthread_attr_getstacksize(attr: &pthread_attr_t, size: &mut usize) -> c_int {
    *size = attr.stack_size;
    0
}

pub fn pthread_attr_setschedparam(attr: &mut pthread_attr_t, param: &sched_param) -> c_int {
    if !(MIN_PRIORITY as c_int..=MAX_PRIORITY as c_int).contains(&param.sched_priority) {
        return EINVAL;
    }
    attr.priority = param.sched_priority;
    0
}

pub fn pthread_attr_getschedparam(attr: &pthread_attr_t, param: &mut sched_param) -> c_int {
    param.sched_priority = attr.priority;
    0
}

/// Non-standard (`pthread_attr_setname_np`-style): name the thread for diagnostics.
pub fn pthread_attr_setname_np(attr: &mut pthread_attr_t, name: &'static str) -> c_int {
    attr.name = name;
    0
}

/// Start records: a kernel task entry carries a single word, so the routine and its
/// argument are parked here and the record index is passed as that word.
static STARTS: IrqCell<[Option<(StartRoutine, usize)>; MAX_TASKS]> = IrqCell::new([None; MAX_TASKS]);

fn pthread_entry(record: usize) {
    if let Some((f, arg)) = STARTS.lock(|s| s[record].take()) {
        let ret = f(arg);
        task::exit(ret);
    }
}

pub fn pthread_create(thread: &mut pthread_t, attr: Option<&pthread_attr_t>, start: StartRoutine, arg: usize) -> c_int {
    let a = attr.copied().unwrap_or_default();
    let Some(record) = STARTS.lock(|s| {
        let i = s.iter().position(|r| r.is_none())?;
        s[i] = Some((start, arg));
        Some(i)
    }) else {
        return EAGAIN;
    };
    let r = task::Builder::new(a.name)
        .priority(a.priority as u8)
        .detached(a.detach == PTHREAD_CREATE_DETACHED)
        .spawn(pthread_entry, record);
    match r {
        Ok(id) => {
            *thread = id.as_raw();
            0
        }
        Err(e) => {
            STARTS.lock(|s| s[record] = None);
            e.errno()
        }
    }
}

pub fn pthread_join(thread: pthread_t, retval: Option<&mut usize>) -> c_int {
    match task::join(TaskId::from_raw(thread), Timeout::Forever) {
        Ok(v) => {
            if let Some(r) = retval {
                *r = v;
            }
            0
        }
        Err(Error::NotFound) => ESRCH,
        Err(e) => e.errno(),
    }
}

pub fn pthread_detach(thread: pthread_t) -> c_int {
    match task::detach(TaskId::from_raw(thread)) {
        Ok(()) => 0,
        Err(Error::NotFound) => ESRCH,
        Err(e) => e.errno(),
    }
}

pub fn pthread_self() -> pthread_t {
    task::current().as_raw()
}

pub fn pthread_equal(a: pthread_t, b: pthread_t) -> bool {
    a == b
}

pub fn pthread_exit(retval: usize) -> ! {
    task::exit(retval)
}

pub fn pthread_setschedparam(thread: pthread_t, _policy: c_int, param: &sched_param) -> c_int {
    if !(MIN_PRIORITY as c_int..=MAX_PRIORITY as c_int).contains(&param.sched_priority) {
        return EINVAL;
    }
    code(task::set_priority(TaskId::from_raw(thread), param.sched_priority as u8))
}

pub fn pthread_getschedparam(thread: pthread_t, policy: &mut c_int, param: &mut sched_param) -> c_int {
    match task::priority(TaskId::from_raw(thread)) {
        Ok(p) => {
            *policy = SCHED_FIFO;
            param.sched_priority = p as c_int;
            0
        }
        Err(_) => ESRCH,
    }
}

pub fn sched_yield() -> c_int {
    task::yield_now();
    0
}

pub fn sched_get_priority_max(_policy: c_int) -> c_int {
    MAX_PRIORITY as c_int
}

pub fn sched_get_priority_min(_policy: c_int) -> c_int {
    MIN_PRIORITY as c_int
}

// ----- mutexes -----

pub const PTHREAD_MUTEX_NORMAL: c_int = 0;
pub const PTHREAD_MUTEX_RECURSIVE: c_int = 1;
pub const PTHREAD_MUTEX_ERRORCHECK: c_int = 2;
pub const PTHREAD_MUTEX_DEFAULT: c_int = PTHREAD_MUTEX_NORMAL;
pub const PTHREAD_PRIO_INHERIT: c_int = 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default)]
pub struct pthread_mutexattr_t {
    kind: c_int,
}

pub fn pthread_mutexattr_init(a: &mut pthread_mutexattr_t) -> c_int {
    *a = pthread_mutexattr_t::default();
    0
}

pub fn pthread_mutexattr_settype(a: &mut pthread_mutexattr_t, kind: c_int) -> c_int {
    if !(0..=2).contains(&kind) {
        return EINVAL;
    }
    a.kind = kind;
    0
}

/// All Bismuth mutexes use priority inheritance; other protocols are rejected.
pub fn pthread_mutexattr_setprotocol(_a: &mut pthread_mutexattr_t, protocol: c_int) -> c_int {
    if protocol == PTHREAD_PRIO_INHERIT { 0 } else { ENOTSUP }
}

/// A POSIX mutex: always priority-inheriting. Declare statics with
/// [`PTHREAD_MUTEX_INITIALIZER`].
#[allow(non_camel_case_types)]
pub struct pthread_mutex_t {
    raw: RawMutex,
}

pub const PTHREAD_MUTEX_INITIALIZER: pthread_mutex_t = pthread_mutex_t { raw: RawMutex::new() };
pub const PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP: pthread_mutex_t = pthread_mutex_t { raw: RawMutex::new_recursive() };

pub fn pthread_mutex_init(m: &pthread_mutex_t, attr: Option<&pthread_mutexattr_t>) -> c_int {
    let kind = attr.map_or(PTHREAD_MUTEX_DEFAULT, |a| a.kind);
    code(m.raw.set_recursive(kind == PTHREAD_MUTEX_RECURSIVE))
}

pub fn pthread_mutex_destroy(m: &pthread_mutex_t) -> c_int {
    if m.raw.is_locked() { EBUSY } else { 0 }
}

pub fn pthread_mutex_lock(m: &pthread_mutex_t) -> c_int {
    code(m.raw.lock(Timeout::Forever))
}

pub fn pthread_mutex_trylock(m: &pthread_mutex_t) -> c_int {
    match m.raw.try_lock() {
        Ok(()) => 0,
        Err(Error::WouldBlock) => EBUSY,
        Err(e) => e.errno(),
    }
}

pub fn pthread_mutex_timedlock(m: &pthread_mutex_t, abstime: &timespec) -> c_int {
    let t = timeout_from_abstime(abstime);
    match m.raw.lock(t) {
        Ok(()) => 0,
        Err(Error::WouldBlock) if t == Timeout::NoWait => ETIMEDOUT,
        Err(e) => e.errno(),
    }
}

pub fn pthread_mutex_unlock(m: &pthread_mutex_t) -> c_int {
    code(m.raw.unlock())
}

// ----- condition variables -----

#[allow(non_camel_case_types)]
pub struct pthread_cond_t {
    cv: CondVar,
}

pub const PTHREAD_COND_INITIALIZER: pthread_cond_t = pthread_cond_t { cv: CondVar::new() };

pub fn pthread_cond_init(_c: &pthread_cond_t, _attr: Option<&()>) -> c_int {
    0
}

pub fn pthread_cond_destroy(_c: &pthread_cond_t) -> c_int {
    0
}

pub fn pthread_cond_wait(c: &pthread_cond_t, m: &pthread_mutex_t) -> c_int {
    code(c.cv.wait_raw(&m.raw, Timeout::Forever))
}

pub fn pthread_cond_timedwait(c: &pthread_cond_t, m: &pthread_mutex_t, abstime: &timespec) -> c_int {
    let t = timeout_from_abstime(abstime);
    if t == Timeout::NoWait {
        return ETIMEDOUT;
    }
    code(c.cv.wait_raw(&m.raw, t))
}

pub fn pthread_cond_signal(c: &pthread_cond_t) -> c_int {
    c.cv.notify_one();
    0
}

pub fn pthread_cond_broadcast(c: &pthread_cond_t) -> c_int {
    c.cv.notify_all();
    0
}

// ----- thread-specific data -----

#[allow(non_camel_case_types)]
pub type pthread_key_t = u32;

const KEYS: usize = 4;
static KEY_USED: IrqCell<[bool; KEYS]> = IrqCell::new([false; KEYS]);

pub fn pthread_key_create(key: &mut pthread_key_t, _destructor: Option<fn(usize)>) -> c_int {
    KEY_USED.lock(|u| match u.iter().position(|x| !*x) {
        Some(i) => {
            u[i] = true;
            *key = i as u32;
            0
        }
        None => EAGAIN,
    })
}

pub fn pthread_key_delete(key: pthread_key_t) -> c_int {
    KEY_USED.lock(|u| match u.get_mut(key as usize) {
        Some(x) if *x => {
            *x = false;
            0
        }
        _ => EINVAL,
    })
}

pub fn pthread_setspecific(key: pthread_key_t, value: usize) -> c_int {
    if !KEY_USED.lock(|u| u.get(key as usize).copied().unwrap_or(false)) {
        return EINVAL;
    }
    if task::tls_set(key as usize, value) { 0 } else { EINVAL }
}

pub fn pthread_getspecific(key: pthread_key_t) -> usize {
    task::tls_get(key as usize)
}

// ----- once -----

#[allow(non_camel_case_types)]
pub struct pthread_once_t {
    state: IrqCell<u8>, // 0 = new, 1 = running, 2 = done
    done: CondVar,
    lock: RawMutex,
}

pub const PTHREAD_ONCE_INIT: pthread_once_t =
    pthread_once_t { state: IrqCell::new(0), done: CondVar::new(), lock: RawMutex::new() };

pub fn pthread_once(once: &pthread_once_t, init: fn()) -> c_int {
    let run = once.state.lock(|s| {
        if *s == 0 {
            *s = 1;
            true
        } else {
            false
        }
    });
    if run {
        init();
        let _ = once.lock.lock(Timeout::Forever);
        once.state.lock(|s| *s = 2);
        once.done.notify_all();
        let _ = once.lock.unlock();
        return 0;
    }
    let _ = once.lock.lock(Timeout::Forever);
    while once.state.lock(|s| *s) != 2 {
        let _ = once.done.wait_raw(&once.lock, Timeout::Forever);
    }
    let _ = once.lock.unlock();
    0
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    STARTS.lock(|s| *s = [None; MAX_TASKS]);
    KEY_USED.lock(|u| *u = [false; KEYS]);
}
