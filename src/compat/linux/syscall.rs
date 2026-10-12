//! The Linux `aarch64` system-call surface: a loaded Linux task issues `svc #0` with the syscall
//! number in `x8` and arguments in `x0..x5`; this dispatches the common ones against Bismuth
//! services. A minimal preview-1-equivalent set — `write`/`writev` to the console, `read` (EOF),
//! `exit`/`exit_group`, and benign stubs (`brk`, `getpid`, `ioctl`, `set_tid_address`) — enough to
//! carry a static binary from `_start` through a `write`+`exit`. Unknown calls return `-ENOSYS`.
//!
//! The call reads/writes the process's memory through a `&mut [u8]` view of its address space, so
//! the logic is testable without the MMU wiring (the port supplies the real view at integration).
//!
//! Classification: L4 personalities · linux syscalls · safe · linux-abi

use crate::Error;

// aarch64 Linux syscall numbers (asm-generic).
pub const READ: u64 = 63;
pub const WRITE: u64 = 64;
pub const WRITEV: u64 = 66;
pub const IOCTL: u64 = 29;
pub const EXIT: u64 = 93;
pub const EXIT_GROUP: u64 = 94;
pub const SET_TID_ADDRESS: u64 = 96;
pub const BRK: u64 = 214;
pub const GETPID: u64 = 172;

const ENOSYS: i64 = -38;

/// What a syscall does to the task.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Return this value in `x0`.
    Return(i64),
    /// Terminate the task with this exit code.
    Exit(i32),
}

fn rd32(mem: &[u8], at: usize) -> Option<u32> {
    mem.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Dispatch one Linux syscall. `mem` is a view of the task's address space (so pointer arguments
/// index straight into it); `base` is the vaddr that `mem[0]` corresponds to.
pub fn dispatch(nr: u64, a: [u64; 6], base: u64, mem: &mut [u8]) -> Outcome {
    let ptr = |p: u64| -> Option<usize> { (p.checked_sub(base)).map(|x| x as usize) };
    match nr {
        EXIT | EXIT_GROUP => Outcome::Exit(a[0] as i32),
        WRITE => {
            let (fd, len) = (a[0], a[2] as usize);
            if let Some(off) = ptr(a[1]) {
                if let Some(bytes) = mem.get(off..off + len) {
                    if fd == 1 || fd == 2 {
                        crate::console::write_bytes(bytes);
                    }
                    return Outcome::Return(len as i64);
                }
            }
            Outcome::Return(-14) // EFAULT
        }
        WRITEV => {
            // writev(fd, iov, iovcnt): each iovec is { base: u64, len: u64 } (16 bytes here, but
            // aarch64 uses pointer+size = 8+8). Gather and write.
            let (fd, iov, cnt) = (a[0], a[1], a[2] as usize);
            let mut total = 0i64;
            for i in 0..cnt {
                let Some(e) = ptr(iov + (i * 16) as u64) else { return Outcome::Return(-14) };
                let (Some(p), Some(l)) = (rd32(mem, e), rd32(mem, e + 8)) else { return Outcome::Return(-14) };
                if let Some(off) = ptr(p as u64) {
                    if let Some(bytes) = mem.get(off..off + l as usize) {
                        if fd == 1 || fd == 2 {
                            crate::console::write_bytes(bytes);
                        }
                        total += l as i64;
                    }
                }
            }
            Outcome::Return(total)
        }
        READ => Outcome::Return(0),            // EOF (no stdin)
        BRK => Outcome::Return(a[0] as i64),   // accept the requested break
        GETPID => Outcome::Return(1),
        SET_TID_ADDRESS => Outcome::Return(1),
        IOCTL => Outcome::Return(0),
        _ => Outcome::Return(ENOSYS),
    }
}

/// Decode a user pointer from the task's address space (helper for the port's integration).
pub fn user_slice(mem: &[u8], base: u64, ptr: u64, len: usize) -> Result<&[u8], Error> {
    let off = ptr.checked_sub(base).ok_or(Error::Invalid)? as usize;
    mem.get(off..off + len).ok_or(Error::Invalid)
}
