//! `<semaphore.h>`: unnamed counting semaphores.
//!
//! Classification: L4 personalities · POSIX semaphores · safe · posix

use super::time::{timespec, timeout_from_abstime};
use super::{c_int, fail};
use crate::Error;
use crate::kernel::time::Timeout;
use crate::sync::Semaphore;

pub const SEM_VALUE_MAX: u32 = i32::MAX as u32;

#[allow(non_camel_case_types)]
pub struct sem_t {
    sem: Semaphore,
}

/// Static initializer (value 0); use [`sem_init`] to set a different initial value.
pub const SEM_INITIALIZER: sem_t = sem_t { sem: Semaphore::new(0, SEM_VALUE_MAX) };

/// `pshared` must be 0: there is a single address space.
pub fn sem_init(sem: &sem_t, pshared: c_int, value: u32) -> c_int {
    if pshared != 0 || value > SEM_VALUE_MAX {
        return fail(Error::Invalid);
    }
    match sem.sem.reset(value) {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

pub fn sem_destroy(_sem: &sem_t) -> c_int {
    0
}

pub fn sem_wait(sem: &sem_t) -> c_int {
    match sem.sem.take(Timeout::Forever) {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

pub fn sem_trywait(sem: &sem_t) -> c_int {
    match sem.sem.try_take() {
        Ok(()) => 0,
        Err(_) => fail(Error::WouldBlock),
    }
}

pub fn sem_timedwait(sem: &sem_t, abstime: &timespec) -> c_int {
    let t = timeout_from_abstime(abstime);
    let r = if t == Timeout::NoWait { sem.sem.try_take().map_err(|_| Error::Timeout) } else { sem.sem.take(t) };
    match r {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

pub fn sem_post(sem: &sem_t) -> c_int {
    match sem.sem.give() {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

pub fn sem_getvalue(sem: &sem_t, value: &mut c_int) -> c_int {
    *value = sem.sem.count() as c_int;
    0
}
