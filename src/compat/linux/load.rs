//! The Linux-executable loader and runtime: tie the ELF parser, the SysV stack builder, the
//! syscall surface, and the port's EL0 mapping together into running tasks. Each loaded binary
//! gets its own page-aligned process buffer holding the whole address space — code and data low
//! (EL0 read-execute), stack, heap and anonymous `mmap` high (EL0 read-write). A task enters its
//! ELF entry at EL0, and its `svc` traps route — via the [`linuxabi`](crate::kernel::linuxabi)
//! hook — back here, where the handler finds the running task's process by its security domain and
//! serves the call against that process's buffer.
//!
//! A small fixed pool of process slots (one per security domain) lets several Linux binaries run
//! concurrently — e.g. as separate containers — each confined to its own capabilities and its own
//! buffer. (They share the EL0-visible address space, like any concurrent Bismuth user tasks: the
//! stage-1 MMU has no per-domain page tables, so cross-domain EL0 isolation is a future step; the
//! confinement that holds today is domain-vs-kernel plus per-domain capabilities.)
//!
//! Classification: L4 personalities · linux loader · safe · linux-abi

use super::{elf::Elf, stack, syscall};
use crate::Error;
use crate::arch::port;
use crate::kernel::cell::IrqCell;
use crate::kernel::linuxabi::{self, Outcome};
use crate::kernel::task::{self, TaskId};
use crate::security::{self, DomainId};

#[cfg(feature = "fs")]
use crate::fs::{Dir, File, OpenMode};
#[cfg(feature = "fs")]
use crate::security::DirCap;

/// An open descriptor ≥ 3: a regular file or a directory opened for iteration (`getdents64`).
#[cfg(feature = "fs")]
#[derive(Copy, Clone)]
enum Fd {
    File(File),
    Dir(Dir),
}

/// Per-process address-space buffer size (code + data + stack + heap).
const IMAGE_BYTES: usize = 128 * 1024;
const PAGE: usize = 4096;
/// How many Linux processes (one per domain) can be loaded at once.
const MAX_PROCS: usize = 6;
#[cfg(feature = "fs")]
const MAX_FDS: usize = 8;
#[cfg(feature = "fs")]
const FIRST_FD: i64 = 3;

/// A page-aligned byte buffer so the port can flip whole-page EL0 permissions over it.
#[repr(C, align(4096))]
struct Image([u8; IMAGE_BYTES]);

static IMAGES: [IrqCell<Image>; MAX_PROCS] = [const { IrqCell::new(Image([0; IMAGE_BYTES])) }; MAX_PROCS];

/// One loaded Linux process: which domain owns it, how its vaddrs map into its buffer, and its
/// `brk`/`mmap` arena (and open files, with the filesystem). Slot `i` uses buffer `IMAGES[i]`.
#[derive(Copy, Clone)]
pub struct Proc {
    used: bool,
    domain: u8,
    /// The syscall memory-view base: a vaddr `v` lives at buffer offset `v - base`.
    base: u64,
    /// Bottom of the heap/`mmap` arena and the current `brk`.
    heap_start: u64,
    brk_cur: u64,
    /// `mmap` bump pointer, descending from the top of the arena toward `brk_cur`.
    mmap_cur: u64,
    #[cfg(feature = "fs")]
    fds: [Option<Fd>; MAX_FDS],
}

const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FAILED: i64 = -1;

impl Proc {
    const EMPTY: Proc = Proc {
        used: false,
        domain: 0,
        base: 0,
        heap_start: 0,
        brk_cur: 0,
        mmap_cur: 0,
        #[cfg(feature = "fs")]
        fds: [None; MAX_FDS],
    };

    /// A process with just its `brk`/`mmap` arena set (for unit tests of the allocator).
    pub fn with_arena(start: u64, top: u64) -> Proc {
        Proc {
            used: true,
            heap_start: start,
            brk_cur: start,
            mmap_cur: top & !(PAGE as u64 - 1),
            ..Proc::EMPTY
        }
    }

    /// `brk(req)`: grow/query the program break. `brk(0)` (or below the heap) queries; a request
    /// past the `mmap` cursor leaves the break unchanged (both Linux behaviours); otherwise set.
    pub fn brk(&mut self, req: u64) -> i64 {
        if req < self.heap_start || req > self.mmap_cur {
            return self.brk_cur as i64;
        }
        self.brk_cur = req;
        req as i64
    }

    /// Anonymous `mmap`: bump-allocate `len` (page-rounded) down from the arena top. Only
    /// `MAP_ANONYMOUS` is backed; exhaustion or a file mapping yields `MAP_FAILED`.
    pub fn mmap(&mut self, len: u64, flags: u64) -> i64 {
        if flags & MAP_ANONYMOUS == 0 || len == 0 {
            return MAP_FAILED;
        }
        let need = (len + PAGE as u64 - 1) & !(PAGE as u64 - 1);
        match self.mmap_cur.checked_sub(need) {
            Some(n) if n >= self.brk_cur => {
                self.mmap_cur = n;
                n as i64
            }
            _ => MAP_FAILED,
        }
    }
}

static PROCS: IrqCell<[Proc; MAX_PROCS]> = IrqCell::new([Proc::EMPTY; MAX_PROCS]);

/// The base address of the process buffer loaded for `domain`, if any — the vaddr of its first
/// (code) page. Lets a supervisor point at one container's memory, e.g. to prove that another
/// domain cannot reach it.
pub fn proc_base(domain: u8) -> Option<u64> {
    PROCS.lock(|p| p.iter().find(|x| x.used && x.domain == domain).map(|x| x.base))
}

/// The Linux syscall handler the port's `svc` gate reaches through [`linuxabi`]. It identifies the
/// running process by the current security domain, then serves the call against that process's
/// buffer: memory management and (with the filesystem) descriptors here, everything else by the
/// pure dispatcher.
fn handle(nr: u64, args: [u64; 6]) -> Outcome {
    const BRK: u64 = 214;
    const MUNMAP: u64 = 215;
    const MMAP: u64 = 222;

    let dom = security::current().0;
    let Some(i) = PROCS.lock(|p| p.iter().position(|x| x.used && x.domain == dom)) else {
        return Outcome::Return(-38); // ENOSYS: no process for this domain (shouldn't happen)
    };

    // Memory management operates on the process record alone.
    match nr {
        BRK | MMAP | MUNMAP => {
            return PROCS.lock(|p| {
                let pr = &mut p[i];
                match nr {
                    BRK => Outcome::Return(pr.brk(args[0])),
                    MMAP => Outcome::Return(pr.mmap(args[1], args[3])),
                    _ => Outcome::Return(0), // munmap: bump allocator, free is a no-op
                }
            });
        }
        _ => {}
    }

    if let Some(out) = time_syscall(i, nr, args) {
        return out;
    }

    #[cfg(feature = "fs")]
    if let Some(out) = fs_syscall(i, nr, args) {
        return out;
    }

    let base = PROCS.lock(|p| p[i].base);
    let out = IMAGES[i].lock(|img| syscall::dispatch(nr, args, base, &mut img.0));
    match out {
        syscall::Outcome::Return(v) => Outcome::Return(v),
        syscall::Outcome::Exit(c) => Outcome::Exit(c),
    }
}

/// Read `n` little-endian `u64`s from the process buffer at vaddr `ptr` (bounds-checked).
fn read_u64s(i: usize, ptr: u64, out: &mut [u64]) -> bool {
    let base = PROCS.lock(|p| p[i].base);
    let Some(off) = ptr.checked_sub(base).map(|x| x as usize) else { return false };
    IMAGES[i].lock(|img| {
        for (k, slot) in out.iter_mut().enumerate() {
            let Some(b) = img.0.get(off + k * 8..off + k * 8 + 8) else { return false };
            *slot = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        }
        true
    })
}

/// Write little-endian `u64`s to the process buffer at vaddr `ptr` (bounds-checked).
fn write_u64s(i: usize, ptr: u64, vals: &[u64]) -> bool {
    let base = PROCS.lock(|p| p[i].base);
    let Some(off) = ptr.checked_sub(base).map(|x| x as usize) else { return false };
    IMAGES[i].lock(|img| {
        for (k, v) in vals.iter().enumerate() {
            let Some(b) = img.0.get_mut(off + k * 8..off + k * 8 + 8) else { return false };
            b.copy_from_slice(&v.to_le_bytes());
        }
        true
    })
}

/// Time-related syscalls that read/write the process buffer: `nanosleep`/`clock_nanosleep` block
/// the task for the requested duration; `gettimeofday` reports time since boot. `None` falls
/// through to the other handlers.
fn time_syscall(i: usize, nr: u64, a: [u64; 6]) -> Option<Outcome> {
    const NANOSLEEP: u64 = 101;
    const CLOCK_NANOSLEEP: u64 = 115;
    const GETTIMEOFDAY: u64 = 169;

    match nr {
        NANOSLEEP | CLOCK_NANOSLEEP => {
            // nanosleep(req, rem); clock_nanosleep(clockid, flags, req, rem).
            let req = if nr == NANOSLEEP { a[0] } else { a[2] };
            let mut ts = [0u64; 2]; // { tv_sec, tv_nsec }
            if !read_u64s(i, req, &mut ts) {
                return Some(Outcome::Return(-14)); // EFAULT
            }
            let ms = ts[0].saturating_mul(1000).saturating_add(ts[1] / 1_000_000);
            let ticks = crate::kernel::time::ms_to_ticks(ms);
            task::sleep_ticks(ticks as u64);
            Some(Outcome::Return(0))
        }
        GETTIMEOFDAY => {
            // gettimeofday(tv, tz): struct timeval { i64 tv_sec; i64 tv_usec }.
            let tv = a[0];
            if tv == 0 {
                return Some(Outcome::Return(0));
            }
            let ms = crate::kernel::time::ms_since_boot() as u64;
            if write_u64s(i, tv, &[ms / 1000, (ms % 1000) * 1000]) {
                Some(Outcome::Return(0))
            } else {
                Some(Outcome::Return(-14))
            }
        }
        _ => None,
    }
}

/// Parse and lay out a Linux `aarch64` executable into a free process buffer, open its EL0 pages,
/// build its initial stack, and spawn it as an EL0 task in security domain `domain` whose `svc`
/// traps run the Linux ABI. `argv[0]` is `name`. Returns the spawned task's id (join it to await
/// its `exit`). Fails `NoResources` if every process slot is in use by a live domain.
pub fn load_and_run(bin: &[u8], name: &'static str, prio: u8, domain: DomainId) -> Result<TaskId, Error> {
    let elf = Elf::parse(bin)?;
    let (lo, hi) = elf.address_span();
    let span = (hi - lo) as usize;
    if span + PAGE > IMAGE_BYTES {
        return Err(Error::NoResources);
    }

    // Claim a slot: this domain's existing one, a free one, or one whose domain has been killed.
    // Reserve it (mark used + owned) under the same lock so a concurrent load can't take it.
    let i = PROCS.lock(|p| {
        let slot = p
            .iter()
            .position(|x| x.used && x.domain == domain.0)
            .or_else(|| p.iter().position(|x| !x.used || security::is_killed(DomainId(x.domain))));
        if let Some(i) = slot {
            p[i] = Proc { used: true, domain: domain.0, ..Proc::EMPTY };
        }
        slot
    });
    let Some(i) = i else { return Err(Error::NoResources) };

    // If the domain is a container, charge its memory cgroup for the resident process footprint
    // (the whole address-space buffer); a limit smaller than the process is refused here.
    #[cfg(feature = "containers")]
    match security::container::charge_mem(security::container::ContainerId(domain), IMAGE_BYTES as u32) {
        Ok(()) | Err(Error::NotFound) => {} // charged, or not a container (no cgroup)
        Err(e) => {
            PROCS.lock(|p| p[i].used = false);
            return Err(e);
        }
    }

    // Drop any previous owner of this (possibly reused) buffer and reset it to EL1-only RW so the
    // wipe/copy below can run (a prior run may have left code pages EL0-RO = also EL1-RO).
    let image_addr = IMAGES[i].lock(|img| img.0.as_ptr() as u64);
    port::linux_reset_image(image_addr, IMAGE_BYTES as u64);

    // Copy each PT_LOAD segment to (vaddr - lo); zero-extend filesz..memsz (the wipe zeroes it).
    IMAGES[i].lock(|img| -> Result<(), Error> {
        for b in img.0.iter_mut() {
            *b = 0;
        }
        for s in elf.segments() {
            let dst = (s.vaddr - lo) as usize;
            let src = bin.get(s.offset..s.offset + s.filesz).ok_or(Error::Invalid)?;
            img.0.get_mut(dst..dst + s.filesz).ok_or(Error::NoResources)?.copy_from_slice(src);
        }
        Ok(())
    })?;

    // A vaddr `v` sits at buffer offset `v - lo`; PIC (`ET_DYN`) code runs correctly at image_addr.
    let base = image_addr.wrapping_sub(lo);
    let entry = image_addr + (elf.entry - lo);

    // Build the SysV initial stack across the whole buffer (strings/vectors land at the top).
    let sp = IMAGES[i].lock(|img| stack::build(&mut img.0, image_addr, &[name], &[]))?;

    // EL0 permissions: the image's pages read-execute; the arena above it read-write.
    let exec_end = ((span + PAGE - 1) & !(PAGE - 1)) as u64;
    let rw_start = image_addr + exec_end;
    let rw_len = IMAGE_BYTES as u64 - exec_end;
    if !port::open_linux_image((image_addr, span as u64), (rw_start, rw_len), domain.0) {
        return Err(Error::Unsupported);
    }

    // Record the process (arena = the read-write region up to a guard page below the stack).
    let arena_top = (sp & !(PAGE as u64 - 1)) - PAGE as u64;
    PROCS.lock(|p| {
        p[i] = Proc {
            used: true,
            domain: domain.0,
                base,
            heap_start: rw_start,
            brk_cur: rw_start,
            mmap_cur: arena_top,
            #[cfg(feature = "fs")]
            fds: [None; MAX_FDS],
        };
    });

    linuxabi::register(handle);
    task::Builder::new(name).priority(prio).domain(domain).spawn_linux(entry as usize, sp as usize)
}

/// VFS-backed `openat`/`read`/`write`/`close` for descriptors ≥ 3 of process slot `i`. Descriptors
/// 0–2 (and non-file calls) return `None` to fall through to the console/pure dispatcher. The
/// handler runs in the Linux task's own domain, so `openat` resolves against the directory the
/// board granted *that* domain — the binary sees exactly that subtree.
#[cfg(feature = "fs")]
fn fs_syscall(i: usize, nr: u64, a: [u64; 6]) -> Option<Outcome> {
    const OPENAT: u64 = 56;
    const CLOSE: u64 = 57;
    const GETDENTS64: u64 = 61;
    const LSEEK: u64 = 62;
    const READ: u64 = 63;
    const WRITE: u64 = 64;
    const NEWFSTATAT: u64 = 79;
    const FSTAT: u64 = 80;
    const AT_FDCWD: i64 = -100;

    match nr {
        OPENAT => Some(openat(i, a)),
        READ if a[0] >= FIRST_FD as u64 => Some(rw(i, a, false)),
        WRITE if a[0] >= FIRST_FD as u64 => Some(rw(i, a, true)),
        CLOSE if a[0] >= FIRST_FD as u64 => Some(close(i, a[0])),
        GETDENTS64 if a[0] >= FIRST_FD as u64 => Some(getdents64(i, a)),
        LSEEK if a[0] >= FIRST_FD as u64 => Some(lseek(i, a)),
        FSTAT if a[0] >= FIRST_FD as u64 => Some(fstat(i, a[0], a[1])),
        // newfstatat(dirfd, path, statbuf, flags): with an empty path + AT_EMPTY_PATH it stats the
        // fd (what libc's fstat uses); otherwise open+stat+close the path under the jail.
        NEWFSTATAT => Some(newfstatat(i, a)),
        _ => {
            let _ = AT_FDCWD;
            None
        }
    }
}

/// Fill a Linux `aarch64` `struct stat` (128 bytes) at buffer offset `off` from a VFS `Stat`.
#[cfg(feature = "fs")]
fn write_stat(mem: &mut [u8], off: usize, st: &crate::fs::Stat) -> bool {
    let Some(buf) = mem.get_mut(off..off + 128) else { return false };
    for b in buf.iter_mut() {
        *b = 0;
    }
    // st_mode (offset 16, u32): S_IFDIR=0o040000 or S_IFREG=0o100000, perms 0o755.
    let mode: u32 = if st.kind == crate::fs::NodeKind::Dir { 0o040_755 } else { 0o100_644 };
    buf[16..20].copy_from_slice(&mode.to_le_bytes());
    // st_size (offset 48, i64).
    buf[48..56].copy_from_slice(&(st.size as i64).to_le_bytes());
    // st_blksize (offset 56, i32) and st_blocks (offset 64, i64).
    buf[56..60].copy_from_slice(&512i32.to_le_bytes());
    buf[64..72].copy_from_slice(&(st.blocks as i64).to_le_bytes());
    true
}

/// Fetch the regular `File` behind a descriptor, or `None` if the slot is empty or a directory.
#[cfg(feature = "fs")]
fn file_at(i: usize, fd: u64) -> Option<File> {
    let slot = (fd as i64 - FIRST_FD) as usize;
    PROCS.lock(|p| if slot < MAX_FDS { p[i].fds[slot] } else { None }).and_then(|f| match f {
        Fd::File(file) => Some(file),
        Fd::Dir(_) => None,
    })
}

#[cfg(feature = "fs")]
fn lseek(i: usize, a: [u64; 6]) -> Outcome {
    use crate::fs::SeekFrom;
    let (fd, off, whence) = (a[0], a[1] as i64, a[2]);
    let Some(file) = file_at(i, fd) else {
        return Outcome::Return(-9);
    };
    let from = match whence {
        0 => SeekFrom::Start(off as u64), // SEEK_SET
        1 => SeekFrom::Current(off),      // SEEK_CUR
        2 => SeekFrom::End(off),          // SEEK_END
        _ => return Outcome::Return(-22), // EINVAL
    };
    match crate::fs::seek(file, from) {
        Ok(pos) => Outcome::Return(pos as i64),
        Err(_) => Outcome::Return(-22),
    }
}

#[cfg(feature = "fs")]
fn fstat(i: usize, fd: u64, statbuf: u64) -> Outcome {
    let Some(file) = file_at(i, fd) else {
        return Outcome::Return(-9);
    };
    let Ok(st) = crate::fs::fstat(file) else { return Outcome::Return(-5) };
    let base = PROCS.lock(|p| p[i].base);
    let Some(off) = statbuf.checked_sub(base).map(|x| x as usize) else { return Outcome::Return(-14) };
    IMAGES[i].lock(|img| if write_stat(&mut img.0, off, &st) { Outcome::Return(0) } else { Outcome::Return(-14) })
}

#[cfg(feature = "fs")]
fn newfstatat(i: usize, a: [u64; 6]) -> Outcome {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let (dirfd, path_ptr, statbuf, flags) = (a[0], a[1], a[2], a[3]);
    // fstat()-equivalent: empty path + AT_EMPTY_PATH stats the fd itself.
    if flags & AT_EMPTY_PATH != 0 || read_cstr(i, path_ptr, &mut [0u8; 1]) == Some(0) {
        if dirfd >= FIRST_FD as u64 {
            return fstat(i, dirfd, statbuf);
        }
    }
    // Otherwise open the path under the jail, stat it, close.
    let Ok(cap) = DirCap::open("root") else { return Outcome::Return(-13) };
    let mut pbuf = [0u8; 128];
    let Some(n) = read_cstr(i, path_ptr, &mut pbuf) else { return Outcome::Return(-36) };
    let Ok(path) = core::str::from_utf8(&pbuf[..n]) else { return Outcome::Return(-22) };
    let file = match crate::fs::cap_open(&cap, path, OpenMode::READ) {
        Ok(f) => f,
        Err(_) => return Outcome::Return(-2),
    };
    let st = crate::fs::fstat(file);
    crate::fs::close(file);
    let Ok(st) = st else { return Outcome::Return(-5) };
    let base = PROCS.lock(|p| p[i].base);
    let Some(off) = statbuf.checked_sub(base).map(|x| x as usize) else { return Outcome::Return(-14) };
    IMAGES[i].lock(|img| if write_stat(&mut img.0, off, &st) { Outcome::Return(0) } else { Outcome::Return(-14) })
}

#[cfg(feature = "fs")]
fn read_cstr(i: usize, ptr: u64, buf: &mut [u8]) -> Option<usize> {
    let base = PROCS.lock(|p| p[i].base);
    let off = ptr.checked_sub(base)? as usize;
    IMAGES[i].lock(|img| {
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

#[cfg(feature = "fs")]
fn openat(i: usize, a: [u64; 6]) -> Outcome {
    const AT_FDCWD: i64 = -100;
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;

    const O_DIRECTORY: u64 = 0o40000; // aarch64: 0x4000

    let (dirfd, path_ptr, flags) = (a[0] as i64, a[1], a[2]);
    if dirfd != AT_FDCWD {
        return Outcome::Return(-9); // EBADF: only AT_FDCWD (relative to the jail) supported
    }
    let Ok(cap) = DirCap::open("root") else { return Outcome::Return(-13) }; // EACCES: no granted dir
    let mut pbuf = [0u8; 128];
    let Some(n) = read_cstr(i, path_ptr, &mut pbuf) else { return Outcome::Return(-36) };
    let Ok(path) = core::str::from_utf8(&pbuf[..n]) else { return Outcome::Return(-22) };

    // A directory open (for getdents64) resolves through the confined cap_opendir.
    let fd = if flags & O_DIRECTORY != 0 {
        match crate::fs::cap_opendir(&cap, path) {
            Ok(d) => Fd::Dir(d),
            Err(Error::NotADirectory) => return Outcome::Return(-20), // ENOTDIR
            Err(_) => return Outcome::Return(-2),                     // ENOENT
        }
    } else {
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
        match crate::fs::cap_open(&cap, path, mode) {
            Ok(f) => Fd::File(f),
            Err(_) => return Outcome::Return(-2), // ENOENT
        }
    };
    PROCS.lock(|p| {
        for (slot, cell) in p[i].fds.iter_mut().enumerate() {
            if cell.is_none() {
                *cell = Some(fd);
                return Outcome::Return(FIRST_FD + slot as i64);
            }
        }
        close_fd(fd);
        Outcome::Return(-24) // EMFILE
    })
}

/// Close whichever kind of VFS handle a descriptor holds.
#[cfg(feature = "fs")]
fn close_fd(fd: Fd) {
    match fd {
        Fd::File(f) => crate::fs::close(f),
        Fd::Dir(d) => crate::fs::closedir(d),
    }
}

/// `getdents64(fd, buf, count)`: pack Linux `struct linux_dirent64` records (d_ino:u64, d_off:i64,
/// d_reclen:u16, d_type:u8, d_name[]: NUL-terminated, each record 8-byte aligned) into the user
/// buffer, advancing the directory's cursor. Returns bytes written, or 0 at end of directory.
#[cfg(feature = "fs")]
fn getdents64(i: usize, a: [u64; 6]) -> Outcome {
    use crate::fs::{DirEntry, NodeKind};
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;

    let (fd, ptr, count) = (a[0], a[1], a[2] as usize);
    let slot = (fd as i64 - FIRST_FD) as usize;
    let Some(Fd::Dir(dir)) = PROCS.lock(|p| if slot < MAX_FDS { p[i].fds[slot] } else { None }) else {
        return Outcome::Return(-20); // ENOTDIR (not an open directory)
    };
    let base = PROCS.lock(|p| p[i].base);
    let Some(off) = ptr.checked_sub(base).map(|x| x as usize) else { return Outcome::Return(-14) };

    let mut written = 0usize;
    let mut e = DirEntry::default();
    loop {
        // Snapshot the cursor before reading, so a non-fitting entry can be re-read next call.
        let Ok(cursor) = crate::fs::telldir(dir) else { return Outcome::Return(-5) };
        let more = match crate::fs::readdir(dir, &mut e) {
            Ok(true) => true,
            Ok(false) => false,
            Err(_) => return Outcome::Return(-5),
        };
        if !more {
            break;
        }
        let name = e.name();
        let reclen = (19 + name.len() + 1 + 7) & !7; // 8+8+2+1 header + name + NUL, 8-aligned
        if written + reclen > count {
            // No room: rewind to this entry so the next getdents64 re-reads it.
            crate::fs::seekdir(dir, cursor);
            break;
        }
        let d_type = if e.kind == NodeKind::Dir { DT_DIR } else { DT_REG };
        let ok = IMAGES[i].lock(|img| {
            let Some(rec) = img.0.get_mut(off + written..off + written + reclen) else { return false };
            for b in rec.iter_mut() {
                *b = 0;
            }
            rec[0..8].copy_from_slice(&(e.vnode.0 as u64).to_le_bytes()); // d_ino
            rec[8..16].copy_from_slice(&(written as i64 + reclen as i64).to_le_bytes()); // d_off
            rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes()); // d_reclen
            rec[18] = d_type;
            rec[19..19 + name.len()].copy_from_slice(name.as_bytes());
            true
        });
        if !ok {
            return Outcome::Return(-14);
        }
        written += reclen;
    }
    Outcome::Return(written as i64)
}

#[cfg(feature = "fs")]
fn rw(i: usize, a: [u64; 6], write: bool) -> Outcome {
    let (fd, ptr, len) = (a[0], a[1], a[2] as usize);
    let Some(file) = file_at(i, fd) else {
        return Outcome::Return(-9);
    };
    let base = PROCS.lock(|p| p[i].base);
    let Some(off) = ptr.checked_sub(base).map(|x| x as usize) else { return Outcome::Return(-14) };
    IMAGES[i].lock(|img| {
        if write {
            let Some(src) = img.0.get(off..off + len) else { return Outcome::Return(-14) };
            match crate::fs::write(file, src) {
                Ok(put) => Outcome::Return(put as i64),
                Err(_) => Outcome::Return(-5),
            }
        } else {
            let Some(dst) = img.0.get_mut(off..off + len) else { return Outcome::Return(-14) };
            match crate::fs::read(file, dst) {
                Ok(got) => Outcome::Return(got as i64),
                Err(_) => Outcome::Return(-5),
            }
        }
    })
}

#[cfg(feature = "fs")]
fn close(i: usize, fd: u64) -> Outcome {
    let slot = (fd as i64 - FIRST_FD) as usize;
    let fdv = PROCS.lock(|p| if slot < MAX_FDS { p[i].fds[slot].take() } else { None });
    match fdv {
        Some(f) => {
            close_fd(f);
            Outcome::Return(0)
        }
        None => Outcome::Return(-9),
    }
}
