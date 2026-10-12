//! Validated access to user memory at the syscall boundary.
//!
//! A hardware-isolated task passes buffers to the kernel as `(address, length)` pairs
//! in registers. This module is the only place those numbers become Rust slices, and
//! only after checking that:
//!
//! * the range is non-null and does not wrap around the address space;
//! * on hardware, it lies **entirely inside the calling task's own stack region** (the
//!   only RAM an unprivileged task can access under the MPU), so the kernel can never
//!   be tricked into reading or writing kernel memory or another task's memory on the
//!   task's behalf (confused-deputy protection).
//!
//! Kernel-domain (privileged) callers are not restricted. On the host simulator, user
//! buffers live on OS thread stacks that the kernel does not manage, so only the null
//! and wrap-around checks apply; memory isolation is enforced on target hardware.
//!
//! Part of the trusted computing base.
//!
//! Classification: L1 kernel · syscall user-memory validation · TCB (unsafe allowed) · always
#![allow(unsafe_code)]

use crate::Error;

/// Check a user range; `Ok(())` if the calling task may access `[addr, addr + len)`
/// (`write` = the kernel will write into it).
pub(crate) fn validate(addr: usize, len: usize, write: bool) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }
    if addr == 0 {
        return Err(Error::Invalid);
    }
    let end = addr.checked_add(len).ok_or(Error::Invalid)?;
    #[cfg(target_os = "none")]
    {
        let allowed = crate::kernel::with(|k| {
            let t = k.cur();
            if !t.user {
                return true; // privileged kernel task
            }
            let in_stack = t.stack.as_ref().is_some_and(|s| {
                let base = s.base() as usize;
                addr >= base && end <= base + s.len()
            });
            // Read-only data (string literals, constants) lives in the user-readable code
            // region — flash on the MCU, the kernel's text+rodata pages on x86. The port
            // knows where that is (and that it excludes writable kernel state).
            in_stack || (!write && crate::arch::port::user_readable(addr, end))
        });
        if !allowed {
            return Err(Error::PermissionDenied);
        }
    }
    let _ = (end, write);
    Ok(())
}

/// Run `f` over the validated user bytes `[addr, addr + len)`.
pub(crate) fn with_bytes<R>(addr: usize, len: usize, f: impl FnOnce(&[u8]) -> R) -> Result<R, Error> {
    validate(addr, len, false)?;
    if len == 0 {
        return Ok(f(&[]));
    }
    // SAFETY: `validate` established that the range is non-null, does not wrap, and (on
    // hardware) lies within the calling task's own stack, which nothing else references
    // while the task is inside this syscall. On the host the range comes from a live
    // slice in the calling thread (see `crate::user`).
    let s = unsafe { core::slice::from_raw_parts(addr as *const u8, len) };
    Ok(f(s))
}

/// Run `f` over the validated, writable user bytes `[addr, addr + len)`.
pub(crate) fn with_bytes_mut<R>(addr: usize, len: usize, f: impl FnOnce(&mut [u8]) -> R) -> Result<R, Error> {
    validate(addr, len, true)?;
    if len == 0 {
        return Ok(f(&mut []));
    }
    // SAFETY: as for `with_bytes`; the calling task is blocked in the syscall, so the
    // exclusive borrow cannot be observed concurrently by it.
    let s = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) };
    Ok(f(s))
}
