//! The system-call boundary for hardware-isolated (unprivileged) tasks.
//!
//! Unprivileged tasks cannot touch kernel memory, so they reach kernel services only
//! through `SVC` (see [`crate::user`] for the client side). Every call is checked
//! against the domain's syscall allow-list, every handle against the domain's handle
//! table, and every buffer by the kernel's user-memory validator. Results are returned as `isize`:
//! non-negative on success, `-errno` on failure.
//!
//! Classification: L3 services · security: system-call gate · safe · always

use crate::Error;
use crate::kernel::time::Timeout;
use crate::kernel::{task, usermem};
use crate::security::{self, DeviceCap, Handle, Rights};

/// System-call numbers (the ABI shared by the kernel and [`crate::user`]).
pub mod nr {
    pub const YIELD: u32 = 0;
    pub const SLEEP: u32 = 1;
    pub const EXIT: u32 = 2;
    pub const TICKS: u32 = 3;
    pub const DEV_OPEN: u32 = 4;
    pub const DEV_READ: u32 = 5;
    pub const DEV_WRITE: u32 = 6;
    pub const DEV_IOCTL: u32 = 7;
    pub const RANDOM: u32 = 8;
    pub const NOTIFY_WAIT: u32 = 9;
    pub const DROP_RIGHTS: u32 = 10;
    pub const LOG: u32 = 11;
    // Filesystem (feature `fs`): a sandboxed task names a granted directory cap, opens a
    // file within it, and reads/writes/closes it — all capability- and buffer-checked.
    pub const FS_DIROPEN: u32 = 12;
    pub const FS_OPEN: u32 = 13;
    pub const FS_READ: u32 = 14;
    pub const FS_WRITE: u32 = 15;
    pub const FS_CLOSE: u32 = 16;
    pub const COUNT: u32 = 17;
}

/// Allow-list bit for syscall `n`.
pub const fn bit(n: u32) -> u32 {
    1 << n
}

/// Every syscall.
pub const ALL: u32 = (1 << nr::COUNT) - 1;

fn ret(r: Result<usize, Error>) -> isize {
    match r {
        Ok(v) => v.min(isize::MAX as usize) as isize,
        Err(e) => -(e.errno() as isize),
    }
}

/// Execute syscall `n` for the current task. Runs in privileged mode (on hardware, on
/// the task's private kernel stack), so it may block.
pub(crate) fn dispatch(n: u32, a: [usize; 4]) -> isize {
    let d = security::current();
    if !security::syscall_allowed(d, n) {
        return ret(Err(security::syscall_violation(d)));
    }
    let r = match n {
        nr::YIELD => {
            task::yield_now();
            Ok(0)
        }
        nr::SLEEP => {
            task::sleep_ticks(a[0] as u64);
            Ok(0)
        }
        nr::EXIT => task::exit(a[0]),
        nr::TICKS => Ok(crate::kernel::time::ticks() as usize),
        nr::DEV_OPEN => usermem::with_bytes(a[0], a[1], |name| {
            let name = core::str::from_utf8(name).map_err(|_| Error::Invalid)?;
            let cap = DeviceCap::open(name)?;
            cap.handle().map(|h| h.raw() as usize).ok_or(Error::PermissionDenied)
        })
        .and_then(|r| r),
        nr::DEV_READ => {
            let cap = DeviceCap::from_handle(Handle::from_raw(a[0] as u16));
            usermem::with_bytes_mut(a[1], a[2], |buf| cap.read_timeout(buf, timeout(a[3]))).and_then(|r| r)
        }
        nr::DEV_WRITE => {
            let cap = DeviceCap::from_handle(Handle::from_raw(a[0] as u16));
            usermem::with_bytes(a[1], a[2], |buf| cap.write(buf)).and_then(|r| r)
        }
        nr::DEV_IOCTL => DeviceCap::from_handle(Handle::from_raw(a[0] as u16)).ioctl(a[1] as u32, a[2]),
        nr::RANDOM => random(a[0], a[1]),
        nr::NOTIFY_WAIT => task::notify_wait(timeout(a[0])).map(|v| v as usize),
        nr::DROP_RIGHTS => security::drop_rights(Handle::from_raw(a[0] as u16), Rights(a[1] as u32)).map(|_| 0),
        nr::LOG => usermem::with_bytes(a[0], a[1], |msg| {
            crate::console::write_bytes(msg);
            msg.len()
        }),
        #[cfg(feature = "fs")]
        nr::FS_DIROPEN => usermem::with_bytes(a[0], a[1], |name| {
            let name = core::str::from_utf8(name).map_err(|_| Error::Invalid)?;
            let cap = security::DirCap::open(name)?;
            cap.resolve(Rights::NONE)?; // confirm it is a directory capability
            Ok(cap.handle().raw() as usize)
        })
        .and_then(|r| r),
        #[cfg(feature = "fs")]
        nr::FS_OPEN => {
            let cap = security::DirCap::from_handle(Handle::from_raw(a[0] as u16));
            let mode = crate::fs::OpenMode(a[3] as u8);
            usermem::with_bytes(a[1], a[2], |path| {
                let path = core::str::from_utf8(path).map_err(|_| Error::Invalid)?;
                crate::fs::cap_open_handle(&cap, path, mode).map(|h| h.raw() as usize)
            })
            .and_then(|r| r)
        }
        #[cfg(feature = "fs")]
        nr::FS_READ => (|| {
            let (open, _) = security::FileCap::from_handle(Handle::from_raw(a[0] as u16)).resolve(Rights::READ)?;
            usermem::with_bytes_mut(a[1], a[2], |buf| crate::fs::read_at_handle(open, buf)).and_then(|r| r)
        })(),
        #[cfg(feature = "fs")]
        nr::FS_WRITE => (|| {
            let (open, _) = security::FileCap::from_handle(Handle::from_raw(a[0] as u16)).resolve(Rights::WRITE)?;
            usermem::with_bytes(a[1], a[2], |buf| crate::fs::write_at_handle(open, buf)).and_then(|r| r)
        })(),
        #[cfg(feature = "fs")]
        nr::FS_CLOSE => (|| {
            let cap = security::FileCap::from_handle(Handle::from_raw(a[0] as u16));
            let (open, _) = cap.resolve(Rights::NONE)?;
            crate::fs::close_handle(open);
            cap.close().map(|_| 0)
        })(),
        _ => Err(Error::Unsupported),
    };
    ret(r)
}

/// Encode a timeout for the ABI: `usize::MAX` = forever, 0 = no wait, else ticks.
pub const fn encode_timeout(t: Timeout) -> usize {
    match t {
        Timeout::NoWait => 0,
        Timeout::Ticks(n) => {
            if n >= usize::MAX as u64 { usize::MAX - 1 } else { n as usize }
        }
        Timeout::Forever => usize::MAX,
    }
}

fn timeout(v: usize) -> Timeout {
    match v {
        0 => Timeout::NoWait,
        usize::MAX => Timeout::Forever,
        n => Timeout::Ticks(n as u64),
    }
}

#[cfg(feature = "crypto")]
fn random(addr: usize, len: usize) -> Result<usize, Error> {
    usermem::with_bytes_mut(addr, len, |buf| security::entropy::fill(buf).map(|_| buf.len())).and_then(|r| r)
}

#[cfg(not(feature = "crypto"))]
fn random(_addr: usize, _len: usize) -> Result<usize, Error> {
    Err(Error::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver;
    use crate::driver::sensor::SimSensor;
    use crate::security::{self, BadHandlePolicy, DomainSpec, Rights};
    use crate::{sim, task};

    static SENSOR: SimSensor = SimSensor::new(1);
    static US: crate::kernel::stack::UserStack2K = crate::kernel::stack::UserStack2K::new();

    extern "C-unwind" fn probe(_: usize) {
        let h = crate::user::open("s").unwrap();
        // Null and wrapping buffers are rejected before any slice is formed.
        assert_eq!(crate::user::raw_syscall(nr::DEV_READ, [h.raw() as usize, 0, 4, 0]), -(crate::Error::Invalid.errno() as isize));
        assert_eq!(crate::user::raw_syscall(nr::DEV_READ, [h.raw() as usize, usize::MAX - 2, 8, 0]), -(crate::Error::Invalid.errno() as isize));
        crate::user::exit(0)
    }

    #[test]
    fn rejects_forged_buffer_pointers() {
        sim::run_to_completion(|| {
            let dev = driver::register("sforge", &SENSOR).unwrap();
            let d = security::create_domain(DomainSpec { bad_handle: BadHandlePolicy::Deny, ..DomainSpec::sandboxed("probe", 6, 1) }).unwrap();
            security::grant_device(d, dev, Rights::READ, "s").unwrap();
            security::seal().unwrap();
            task::Builder::new("probe").priority(4).domain(d).stack(&US).spawn_user(probe, 0).unwrap();
        });
    }
}
