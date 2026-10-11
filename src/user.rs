//! User runtime: the system-call client API for hardware-isolated tasks.
//!
//! Code running in a hardware-isolated (unprivileged) task may use **only** this module
//! (plus pure `core` code): every other kernel API touches kernel memory and would fault
//! under the MPU. Each function traps into the kernel with `SVC`; the kernel validates
//! the domain's syscall allow-list, handles and buffers before acting.
//!
//! ```ignore
//! extern "C-unwind" fn sensor_app(_: usize) {
//!     let temp = user::open("temp0").unwrap();
//!     let mut raw = [0u8; 4];
//!     user::read(temp, &mut raw, Timeout::Forever).unwrap();
//!     user::log(b"sampled\n");
//! }
//! ```
//!
//! Classification: L4 personalities · user runtime (syscall client) · safe · always

use crate::Error;
use crate::arch::port;
use crate::security::syscall::{encode_timeout, nr};
use crate::kernel::time::Timeout;
use crate::security::{Handle, Rights};

fn check(r: isize) -> Result<usize, Error> {
    if r >= 0 { Ok(r as usize) } else { Err(error_from_errno(-r as i32)) }
}

fn error_from_errno(e: i32) -> Error {
    use crate::compat::errno::*;
    match e {
        ETIMEDOUT => Error::Timeout,
        EAGAIN => Error::WouldBlock,
        EINVAL => Error::Invalid,
        ENOMEM => Error::NoMemory,
        ENOENT => Error::NotFound,
        EEXIST => Error::Exists,
        EBUSY => Error::Busy,
        EPERM => Error::NotOwner,
        EDEADLK => Error::Deadlock,
        EINTR => Error::Interrupted,
        ENOTSUP => Error::Unsupported,
        EACCES => Error::PermissionDenied,
        EIO => Error::Io,
        ENODEV => Error::NotReady,
        EOVERFLOW => Error::Overflow,
        EBADF => Error::BadHandle,
        EBADMSG => Error::Integrity,
        _ => Error::Io,
    }
}

pub fn yield_now() {
    let _ = port::syscall(nr::YIELD, [0; 4]);
}

pub fn sleep_ticks(ticks: u64) {
    let _ = port::syscall(nr::SLEEP, [ticks.min(usize::MAX as u64) as usize, 0, 0, 0]);
}

/// Terminate the calling task.
pub fn exit(code: usize) -> ! {
    let _ = port::syscall(nr::EXIT, [code, 0, 0, 0]);
    unreachable!("exit syscall returned")
}

/// Kernel tick counter (low bits on 32-bit targets).
pub fn ticks() -> usize {
    port::syscall(nr::TICKS, [0; 4]).max(0) as usize
}

/// Open a device in the domain's namespace; returns a handle.
pub fn open(name: &str) -> Result<Handle, Error> {
    check(port::syscall(nr::DEV_OPEN, [name.as_ptr() as usize, name.len(), 0, 0])).map(|h| Handle::from_raw(h as u16))
}

pub fn read(h: Handle, buf: &mut [u8], timeout: Timeout) -> Result<usize, Error> {
    check(port::syscall(nr::DEV_READ, [h.raw() as usize, buf.as_mut_ptr() as usize, buf.len(), encode_timeout(timeout)]))
}

pub fn write(h: Handle, buf: &[u8]) -> Result<usize, Error> {
    check(port::syscall(nr::DEV_WRITE, [h.raw() as usize, buf.as_ptr() as usize, buf.len(), 0]))
}

pub fn ioctl(h: Handle, cmd: u32, arg: usize) -> Result<usize, Error> {
    check(port::syscall(nr::DEV_IOCTL, [h.raw() as usize, cmd as usize, arg, 0]))
}

/// Fill `buf` from the domain's CSPRNG.
pub fn random(buf: &mut [u8]) -> Result<(), Error> {
    check(port::syscall(nr::RANDOM, [buf.as_mut_ptr() as usize, buf.len(), 0, 0])).map(|_| ())
}

pub fn notify_wait(timeout: Timeout) -> Result<u32, Error> {
    check(port::syscall(nr::NOTIFY_WAIT, [encode_timeout(timeout), 0, 0, 0])).map(|v| v as u32)
}

/// Permanently remove rights from one of the domain's handles.
pub fn drop_rights(h: Handle, mask: Rights) -> Result<(), Error> {
    check(port::syscall(nr::DROP_RIGHTS, [h.raw() as usize, mask.0 as usize, 0, 0])).map(|_| ())
}

/// Write to the kernel console (if the domain's policy allows logging).
pub fn log(msg: &[u8]) {
    let _ = port::syscall(nr::LOG, [msg.as_ptr() as usize, msg.len(), 0, 0]);
}

/// Open a directory capability (granted via the manifest / `fs::grant_dir`) by name,
/// returning a handle to resolve paths within that subtree. (feature `fs`)
#[cfg(feature = "fs")]
pub fn fs_diropen(name: &str) -> Result<Handle, Error> {
    check(port::syscall(nr::FS_DIROPEN, [name.as_ptr() as usize, name.len(), 0, 0])).map(|h| Handle::from_raw(h as u16))
}

/// Open a file at `path` relative to directory cap `dir`; `mode` is the `fs::OpenMode`
/// bits (`1`=read, `2`=write, `4`=create, `8`=trunc, `16`=append). Returns a file handle.
#[cfg(feature = "fs")]
pub fn fs_open(dir: Handle, path: &str, mode: u8) -> Result<Handle, Error> {
    check(port::syscall(nr::FS_OPEN, [dir.raw() as usize, path.as_ptr() as usize, path.len(), mode as usize]))
        .map(|h| Handle::from_raw(h as u16))
}

#[cfg(feature = "fs")]
pub fn fs_read(file: Handle, buf: &mut [u8]) -> Result<usize, Error> {
    check(port::syscall(nr::FS_READ, [file.raw() as usize, buf.as_mut_ptr() as usize, buf.len(), 0]))
}

#[cfg(feature = "fs")]
pub fn fs_write(file: Handle, buf: &[u8]) -> Result<usize, Error> {
    check(port::syscall(nr::FS_WRITE, [file.raw() as usize, buf.as_ptr() as usize, buf.len(), 0]))
}

#[cfg(feature = "fs")]
pub fn fs_close(file: Handle) -> Result<(), Error> {
    check(port::syscall(nr::FS_CLOSE, [file.raw() as usize, 0, 0, 0])).map(|_| ())
}

/// Raw system call, for the kernel's own argument-validation tests. Not public:
/// forging a pointer argument from safe code must never reach slice formation, and the
/// typed wrappers above always pass valid slices.
#[cfg(test)]
pub(crate) fn raw_syscall(n: u32, args: [usize; 4]) -> isize {
    port::syscall(n, args)
}

/// Return address for user task entry functions (exits the task via syscall).
#[cfg_attr(any(not(target_os = "none"), feature = "cortex-a"), allow(dead_code))]
pub(crate) extern "C" fn user_task_return() -> ! {
    exit(0)
}
