//! The Linux-executable loader: tie the ELF parser, the SysV stack builder, the syscall surface,
//! and the port's EL0 mapping together into a running task. A loaded image lives in one fixed,
//! page-aligned kernel-image buffer that holds the whole process address space — the loaded code
//! and data at the bottom (mapped EL0 read-execute), the SysV stack and scratch space at the top
//! (mapped EL0 read-write). The task enters the ELF entry at EL0 with its initial stack, and its
//! `svc` traps route — via the [`linuxabi`](crate::kernel::linuxabi) hook — back here, where a
//! `&mut [u8]` view of that one buffer backs both the pure [`syscall::dispatch`] calls and the
//! stateful file-descriptor calls ([`openat`](super::syscall::OPENAT)/`read`/`write`/`close`).
//!
//! One image at a time (enough to carry a static binary through its start-up, a `write`, reading a
//! file from the VFS, and `exit`, and to demonstrate the ABI end-to-end). The buffer is page
//! aligned so the port can flip whole 4 KiB pages' EL0 permissions.
//!
//! Classification: L4 personalities · linux loader · safe · linux-abi

use super::{elf::Elf, stack, syscall};
use crate::Error;
use crate::arch::port;
use crate::kernel::cell::IrqCell;
use crate::kernel::task::TaskId;
use crate::kernel::{linuxabi, task};
use crate::security::DomainId;

/// The process address-space buffer: code + data low (EL0 read-execute), stack + scratch high
/// (EL0 read-write). One static buffer → one Linux task at a time.
const IMAGE_BYTES: usize = 128 * 1024;
const PAGE: usize = 4096;

/// A page-aligned byte buffer so the port can flip whole-page EL0 permissions over it.
#[repr(C, align(4096))]
struct Image([u8; IMAGE_BYTES]);

static IMAGE: IrqCell<Image> = IrqCell::new(Image([0; IMAGE_BYTES]));
/// The vaddr that `IMAGE[0]` maps to (the base of the running process's syscall memory view).
static IMAGE_BASE: IrqCell<u64> = IrqCell::new(0);

/// The Linux syscall handler the port's `svc` gate reaches through [`linuxabi`]: the file-backed
/// calls are served here (they need the fd table + VFS), everything else by the pure dispatcher.
/// Both read and write the one process buffer through a `&mut [u8]` view.
fn handle(nr: u64, args: [u64; 6]) -> linuxabi::Outcome {
    if let Some(out) = mm::handle_mm(nr, args) {
        return out;
    }
    #[cfg(feature = "fs")]
    if let Some(out) = fd::handle_fs(nr, args) {
        return out;
    }
    let base = IMAGE_BASE.lock(|b| *b);
    let out = IMAGE.lock(|img| syscall::dispatch(nr, args, base, &mut img.0));
    match out {
        syscall::Outcome::Return(v) => linuxabi::Outcome::Return(v),
        syscall::Outcome::Exit(c) => linuxabi::Outcome::Exit(c),
    }
}

/// `brk` and anonymous `mmap`/`munmap` over the process buffer's read-write arena. `brk` grows a
/// classic heap up from the bottom of the arena; anonymous `mmap` bump-allocates pages down from
/// the top. Both are already backed by real, EL0-read-write pages (the loader opened the whole
/// arena), so there is no faulting-in — just pointer bookkeeping within the fixed buffer. Enough
/// for a `malloc` built on either primitive. One task at a time → one set of statics.
pub mod mm {
    use crate::kernel::cell::IrqCell;
    use crate::kernel::linuxabi::Outcome;

    const BRK: u64 = 214;
    const MUNMAP: u64 = 215;
    const MMAP: u64 = 222;

    const MAP_ANONYMOUS: u64 = 0x20;
    const PAGE: u64 = 4096;
    const MAP_FAILED: i64 = -1;

    /// Bottom of the arena / the program break's floor (the heap's start).
    static HEAP_START: IrqCell<u64> = IrqCell::new(0);
    /// The current program break (top of the `brk` heap).
    static BRK_CUR: IrqCell<u64> = IrqCell::new(0);
    /// The bump pointer for anonymous `mmap`, growing down from the top of the arena.
    static MMAP_CUR: IrqCell<u64> = IrqCell::new(0);

    /// Set the arena `[start, top)` for a freshly loaded task.
    pub fn init(start: u64, top: u64) {
        HEAP_START.lock(|v| *v = start);
        BRK_CUR.lock(|v| *v = start);
        MMAP_CUR.lock(|v| *v = top & !(PAGE - 1));
    }

    /// Serve a memory-management syscall, or `None` for the other handlers.
    pub fn handle_mm(nr: u64, a: [u64; 6]) -> Option<Outcome> {
        match nr {
            BRK => Some(brk(a[0])),
            MMAP => Some(mmap(a)),
            MUNMAP => Some(Outcome::Return(0)), // bump allocator: free is a no-op
            _ => None,
        }
    }

    fn brk(req: u64) -> Outcome {
        let (start, floor) = (HEAP_START.lock(|v| *v), MMAP_CUR.lock(|v| *v));
        // brk(0) (or any address below the heap start) just queries the current break.
        if req < start {
            return Outcome::Return(BRK_CUR.lock(|v| *v) as i64);
        }
        if req > floor {
            // Out of arena: Linux leaves the break unchanged and returns it.
            return Outcome::Return(BRK_CUR.lock(|v| *v) as i64);
        }
        BRK_CUR.lock(|v| *v = req);
        Outcome::Return(req as i64)
    }

    fn mmap(a: [u64; 6]) -> Outcome {
        let (len, flags) = (a[1], a[3]);
        if flags & MAP_ANONYMOUS == 0 || len == 0 {
            return Outcome::Return(MAP_FAILED); // only anonymous maps are backed here
        }
        let need = (len + PAGE - 1) & !(PAGE - 1);
        let floor = BRK_CUR.lock(|v| *v);
        MMAP_CUR.lock(|cur| match cur.checked_sub(need) {
            Some(n) if n >= floor => {
                *cur = n;
                Outcome::Return(n as i64)
            }
            _ => Outcome::Return(MAP_FAILED), // arena exhausted
        })
    }
}

/// Parse and lay out a Linux `aarch64` executable into the process buffer, open its EL0 pages,
/// build its initial stack, and spawn it as an EL0 task (in security domain `domain`) whose `svc`
/// traps run the Linux ABI. `argv[0]` is `name`. Returns the spawned task's id (join it to await
/// its `exit`).
pub fn load_and_run(bin: &[u8], name: &'static str, prio: u8, domain: DomainId) -> Result<TaskId, Error> {
    let elf = Elf::parse(bin)?;
    let (lo, hi) = elf.address_span();
    let span = (hi - lo) as usize;
    // Leave at least a page of read-write scratch/stack above the loaded image.
    if span + PAGE > IMAGE_BYTES {
        return Err(Error::NoResources);
    }

    // A previous run may have left the code pages EL0 read-only (which is also EL1 read-only on
    // this MMU); restore the whole buffer to read-write before we rewrite it.
    let image_addr = IMAGE.lock(|img| img.0.as_ptr() as u64);
    port::open_linux_image((image_addr, 0), (image_addr, IMAGE_BYTES as u64));

    // Copy each PT_LOAD segment into the buffer at (vaddr - lo); zero-extend filesz..memsz.
    let image_addr = IMAGE.lock(|img| -> Result<u64, Error> {
        for b in img.0.iter_mut() {
            *b = 0;
        }
        for s in elf.segments() {
            let dst = (s.vaddr - lo) as usize;
            let src = bin.get(s.offset..s.offset + s.filesz).ok_or(Error::Invalid)?;
            img.0.get_mut(dst..dst + s.filesz).ok_or(Error::NoResources)?.copy_from_slice(src);
            // filesz..memsz is already zero from the wipe above.
        }
        Ok(img.0.as_ptr() as u64)
    })?;

    // A vaddr v sits at IMAGE[v - lo], so the syscall view's base vaddr is image_addr - lo and the
    // entry is image_addr + (entry - lo). PIC (`ET_DYN`) code uses PC-relative addressing, so
    // running at image_addr is fine regardless of lo.
    let view_base = image_addr.wrapping_sub(lo);
    let entry = image_addr + (elf.entry - lo);
    IMAGE_BASE.lock(|b| *b = view_base);
    #[cfg(feature = "fs")]
    fd::reset();

    // Build the SysV initial stack across the whole buffer (strings + vectors land at the top,
    // well above the loaded image at the bottom); the returned sp is a high vaddr.
    let sp = IMAGE.lock(|img| stack::build(&mut img.0, image_addr, &[name], &[]))?;

    // EL0 permissions: the loaded image's pages read-execute; the read-write region above it
    // (page-aligned, up through the stack) read-write.
    let exec_end = ((span + PAGE - 1) & !(PAGE - 1)) as u64;
    let rw_start = image_addr + exec_end;
    let rw_len = IMAGE_BYTES as u64 - exec_end;
    if !port::open_linux_image((image_addr, span as u64), (rw_start, rw_len)) {
        return Err(Error::Unsupported);
    }

    // The heap/anonymous-mmap arena is the read-write region between the loaded image and a guard
    // below the initial stack: `brk` grows up from the bottom, `mmap` bump-allocates down from the
    // top; they fail when they would meet.
    mm::init(rw_start, (sp & !(PAGE as u64 - 1)) - PAGE as u64);

    // Route Linux syscalls here, then spawn the task at EL0.
    linuxabi::register(handle);
    task::Builder::new(name).priority(prio).domain(domain).spawn_linux(entry as usize, sp as usize)
}

/// The file-descriptor table and VFS-backed `openat`/`read`/`write`/`close` for a loaded Linux
/// task. Descriptors 0–2 are the console (handled by the pure dispatcher); 3.. are VFS handles
/// opened through the task's domain capability. Confined to a directory the board granted the
/// domain before sealing — the loaded binary sees exactly that subtree.
#[cfg(feature = "fs")]
mod fd {
    use super::{IMAGE, IMAGE_BASE};
    use crate::fs::{File, OpenMode};
    use crate::kernel::cell::IrqCell;
    use crate::kernel::linuxabi::Outcome;
    use crate::security::DirCap;

    // aarch64 Linux syscall numbers served here.
    const OPENAT: u64 = 56;
    const CLOSE: u64 = 57;
    const READ: u64 = 63;
    const WRITE: u64 = 64;

    const AT_FDCWD: i64 = -100;
    const MAX_FDS: usize = 8;
    const FIRST_FD: i64 = 3;

    // Linux open flags we honour.
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;

    static TABLE: IrqCell<[Option<File>; MAX_FDS]> = IrqCell::new([None; MAX_FDS]);

    /// Clear the table at the start of each load (one task at a time).
    pub fn reset() {
        TABLE.lock(|t| *t = [None; MAX_FDS]);
    }

    /// Serve a file-descriptor syscall, or `None` to let the pure dispatcher handle it (console
    /// fds 0–2, non-file calls). The handler runs on the Linux task's kernel stack, so the VFS
    /// capability calls resolve in *its* domain — the directory the board granted it.
    pub fn handle_fs(nr: u64, a: [u64; 6]) -> Option<Outcome> {
        match nr {
            OPENAT => Some(openat(a)),
            READ if a[0] >= FIRST_FD as u64 => Some(read(a)),
            WRITE if a[0] >= FIRST_FD as u64 => Some(write(a)),
            CLOSE if a[0] >= FIRST_FD as u64 => Some(close(a)),
            _ => None,
        }
    }

    /// Read a NUL-terminated path from the task's memory at vaddr `ptr`, into `buf`; returns its
    /// length, or `None` if unterminated / out of range.
    fn read_cstr(ptr: u64, buf: &mut [u8]) -> Option<usize> {
        let base = IMAGE_BASE.lock(|b| *b);
        let off = ptr.checked_sub(base)? as usize;
        IMAGE.lock(|img| {
            let mem = &img.0;
            let mut n = 0;
            while n < buf.len() {
                let c = *mem.get(off + n)?;
                if c == 0 {
                    return Some(n);
                }
                buf[n] = c;
                n += 1;
            }
            None
        })
    }

    fn openat(a: [u64; 6]) -> Outcome {
        let (dirfd, path_ptr, flags) = (a[0] as i64, a[1], a[2]);
        if dirfd != AT_FDCWD {
            return Outcome::Return(-9); // EBADF: only AT_FDCWD (relative to our jail) supported
        }
        // The board grants the Linux domain a directory named "root"; resolve it in the task's
        // own namespace (we run in its domain), so the binary is confined to that subtree.
        let Ok(cap) = DirCap::open("root") else { return Outcome::Return(-13) }; // EACCES
        let mut pbuf = [0u8; 128];
        let Some(n) = read_cstr(path_ptr, &mut pbuf) else { return Outcome::Return(-36) }; // ENAMETOOLONG
        let Ok(path) = core::str::from_utf8(&pbuf[..n]) else { return Outcome::Return(-22) };

        // Map Linux open flags to Bismuth OpenMode bits.
        let mut mode = if flags & O_WRONLY != 0 {
            OpenMode::WRITE
        } else if flags & O_RDWR != 0 {
            OpenMode::RDWR
        } else {
            OpenMode::READ
        };
        if flags & O_CREAT != 0 {
            mode = mode.with(OpenMode::CREATE);
        }
        if flags & O_TRUNC != 0 {
            mode = mode.with(OpenMode::TRUNC);
        }
        if flags & O_APPEND != 0 {
            mode = mode.with(OpenMode::APPEND);
        }

        let file = match crate::fs::cap_open(&cap, path, mode) {
            Ok(f) => f,
            Err(_) => return Outcome::Return(-2), // ENOENT
        };
        TABLE.lock(|t| {
            for (i, slot) in t.iter_mut().enumerate() {
                if slot.is_none() {
                    *slot = Some(file);
                    return Outcome::Return(FIRST_FD + i as i64);
                }
            }
            crate::fs::close(file);
            Outcome::Return(-24) // EMFILE
        })
    }

    fn file_of(fd: u64) -> Option<File> {
        let i = (fd as i64 - FIRST_FD) as usize;
        TABLE.lock(|t| if i < t.len() { t[i] } else { None })
    }

    fn read(a: [u64; 6]) -> Outcome {
        let (fd, ptr, len) = (a[0], a[1], a[2] as usize);
        let Some(file) = file_of(fd) else { return Outcome::Return(-9) };
        let base = IMAGE_BASE.lock(|b| *b);
        let Some(off) = ptr.checked_sub(base).map(|x| x as usize) else { return Outcome::Return(-14) };
        IMAGE.lock(|img| {
            let Some(dst) = img.0.get_mut(off..off + len) else { return Outcome::Return(-14) };
            match crate::fs::read(file, dst) {
                Ok(got) => Outcome::Return(got as i64),
                Err(_) => Outcome::Return(-5), // EIO
            }
        })
    }

    fn write(a: [u64; 6]) -> Outcome {
        let (fd, ptr, len) = (a[0], a[1], a[2] as usize);
        let Some(file) = file_of(fd) else { return Outcome::Return(-9) };
        let base = IMAGE_BASE.lock(|b| *b);
        let Some(off) = ptr.checked_sub(base).map(|x| x as usize) else { return Outcome::Return(-14) };
        IMAGE.lock(|img| {
            let Some(src) = img.0.get(off..off + len) else { return Outcome::Return(-14) };
            match crate::fs::write(file, src) {
                Ok(put) => Outcome::Return(put as i64),
                Err(_) => Outcome::Return(-5),
            }
        })
    }

    fn close(a: [u64; 6]) -> Outcome {
        let i = (a[0] as i64 - FIRST_FD) as usize;
        let file = TABLE.lock(|t| if i < t.len() { t[i].take() } else { None });
        match file {
            Some(f) => {
                crate::fs::close(f);
                Outcome::Return(0)
            }
            None => Outcome::Return(-9),
        }
    }
}
