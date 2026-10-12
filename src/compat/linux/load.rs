//! The Linux-executable loader: tie the ELF parser, the SysV stack builder, the syscall surface,
//! and the port's EL0 mapping together into a running task. A loaded image lives in a fixed,
//! page-aligned kernel-image buffer (code read-execute, a separate stack buffer read-write); the
//! task enters the ELF entry at EL0 with its SysV initial stack, and its `svc` traps route — via
//! the [`linuxabi`](crate::kernel::linuxabi) hook — back here to [`syscall::dispatch`] against a
//! `&mut [u8]` view of that same buffer.
//!
//! Single static image: one Linux task runs at a time (enough to carry a static binary through
//! `write`+`exit` and to demonstrate the ABI end-to-end). The buffers are page-aligned so the
//! port can flip whole 4 KiB pages' EL0 permissions.
//!
//! Classification: L4 personalities · linux loader · safe · linux-abi

use super::{elf::Elf, stack, syscall};
use crate::Error;
use crate::arch::port;
use crate::kernel::cell::IrqCell;
use crate::kernel::task::TaskId;
use crate::kernel::{linuxabi, task};
use crate::security::DomainId;

/// Image buffer: the loaded code + data, mapped EL0 read-execute. Sized for a small static binary.
const IMAGE_BYTES: usize = 64 * 1024;
/// Stack buffer: the SysV initial stack, mapped EL0 read-write.
const STACK_BYTES: usize = 32 * 1024;

/// A page-aligned byte buffer (4 KiB) so the port can flip whole-page EL0 permissions over it.
#[repr(C, align(4096))]
struct Page([u8; IMAGE_BYTES]);

#[repr(C, align(4096))]
struct StackPage([u8; STACK_BYTES]);

static IMAGE: IrqCell<Page> = IrqCell::new(Page([0; IMAGE_BYTES]));
static STACK: IrqCell<StackPage> = IrqCell::new(StackPage([0; STACK_BYTES]));
/// The vaddr that `IMAGE[0]` maps to (the base of the running process's syscall memory view).
static IMAGE_BASE: IrqCell<u64> = IrqCell::new(0);

/// The Linux syscall handler the port's `svc` gate reaches through [`linuxabi`]: build a mutable
/// view of the running image and dispatch the call against it.
fn handle(nr: u64, args: [u64; 6]) -> linuxabi::Outcome {
    let base = IMAGE_BASE.lock(|b| *b);
    let out = IMAGE.lock(|img| syscall::dispatch(nr, args, base, &mut img.0));
    match out {
        syscall::Outcome::Return(v) => linuxabi::Outcome::Return(v),
        syscall::Outcome::Exit(c) => linuxabi::Outcome::Exit(c),
    }
}

/// Parse and lay out a Linux `aarch64` executable into the image buffer, open its EL0 pages, build
/// its initial stack, and spawn it as an EL0 task (in security domain `domain`) whose `svc` traps
/// run the Linux ABI. `argv[0]` is `name`. Returns once the task is scheduled (it runs and exits
/// asynchronously). Returns the spawned task's id (join it to await its `exit`).
pub fn load_and_run(bin: &[u8], name: &'static str, prio: u8, domain: DomainId) -> Result<TaskId, Error> {
    let elf = Elf::parse(bin)?;
    let (lo, hi) = elf.address_span();
    let span = (hi - lo) as usize;
    if span > IMAGE_BYTES {
        return Err(Error::NoResources);
    }

    // Copy each PT_LOAD segment into the image at (vaddr - lo); zero-extend filesz..memsz.
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

    // The process is loaded with its lowest vaddr at IMAGE[0], so a vaddr v sits at IMAGE[v - lo];
    // equivalently the syscall view's base vaddr is image_addr - lo and the entry is image_addr +
    // (entry - lo). PIC (`ET_DYN`) code uses PC-relative addressing, so running at image_addr is
    // fine regardless of lo.
    let view_base = image_addr.wrapping_sub(lo);
    let entry = image_addr + (elf.entry - lo);
    IMAGE_BASE.lock(|b| *b = view_base);

    // Build the SysV initial stack in the stack buffer.
    let (stack_addr, sp) = STACK.lock(|st| -> Result<(u64, u64), Error> {
        let addr = st.0.as_ptr() as u64;
        let sp = stack::build(&mut st.0, addr, &[name], &[])?;
        Ok((addr, sp))
    })?;

    // Open the EL0 pages: image read-execute, stack read-write.
    if !port::open_linux_image((image_addr, span as u64), (stack_addr, STACK_BYTES as u64)) {
        return Err(Error::Unsupported);
    }

    // Route Linux syscalls here, then spawn the task at EL0.
    linuxabi::register(handle);
    task::Builder::new(name).priority(prio).domain(domain).spawn_linux(entry as usize, sp as usize)
}
