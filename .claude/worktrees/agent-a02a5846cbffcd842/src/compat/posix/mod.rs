//! POSIX compatibility layer (PSE51/PSE52-style subset for embedded systems).
//!
//! Names, argument order, error conventions and semantics follow POSIX, expressed in
//! safe Rust: out-parameters are `&mut`, buffers are slices, and strings are `&str`.
//! This keeps the whole layer free of `unsafe` (see the project's safe-Rust rule);
//! a C ABI shim would be a separate, audited FFI module.
//!
//! Conventions, as in POSIX:
//! * `pthread_*` functions return `0` or an error number.
//! * other functions return `-1` (or `None`) and set the calling task's [`errno`].
//!
//! | header         | provided                                                         |
//! |----------------|------------------------------------------------------------------|
//! | `<pthread.h>`  | create/join/detach/exit/self/equal, attrs, sched params, mutexes (normal/recursive/errorcheck, PI), condvars, keys, once |
//! | `<semaphore.h>`| sem_init/wait/trywait/timedwait/post/getvalue/destroy            |
//! | `<time.h>`     | clock_gettime/settime/getres, nanosleep, time                    |
//! | `<unistd.h>`   | open/close/read/write/ioctl/fcntl/isatty, sleep/usleep           |
//! | `<poll.h>`     | poll                                                             |
//! | `<mqueue.h>`   | mq_open/close/unlink/send/receive/timedsend/timedreceive/getattr  |
//! | `<sched.h>`    | sched_yield, sched_get_priority_min/max                          |
//! | `<sys/socket.h>` | socket/bind/listen/accept/connect/send/recv/sendto/recvfrom (with `net-ip`) |
//!
//! Classification: L4 personalities · POSIX · safe · posix

pub mod mqueue;
pub mod pthread;
pub mod termios;
pub mod semaphore;
pub mod time;
pub mod unistd;

pub use mqueue::*;
pub use pthread::*;
pub use termios::*;
pub use semaphore::*;
pub use time::*;
pub use unistd::*;

use crate::Error;

pub use crate::compat::errno::*;

#[allow(non_camel_case_types)]
pub type c_int = i32;

/// The calling task's `errno`.
pub fn errno() -> c_int {
    crate::kernel::task::errno()
}

pub fn set_errno(e: c_int) {
    crate::kernel::task::set_errno(e)
}

/// Record `e` as errno and return -1 (the POSIX failure convention).
pub(crate) fn fail(e: Error) -> c_int {
    set_errno(e.errno());
    -1
}

/// Map a kernel result to the `pthread_*` convention (0 or an error number).
pub(crate) fn code(r: Result<(), Error>) -> c_int {
    match r {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    pthread::reset();
    mqueue::reset();
    unistd::reset();
}
