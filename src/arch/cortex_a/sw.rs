//! AArch32 context switch (srs/rfe over the SVC stack), the `SVC` syscall gate, the
//! USR-abort-kills-the-domain path, and the task-frame layout.
//!
//! The exception frame is 18 words so it carries the USR-banked `sp`/`lr` of a user task:
//! `[sp_usr, lr_usr, r0..r12, lr, PC, CPSR]`. On an IRQ/SVC/abort the CPU banks the return
//! into the exception mode; `SRSDB #0x13` moves {PC, CPSR} onto the task's **SVC** stack
//! (its kernel stack for a user task), we switch to SVC mode, push `r0-r12, lr`, then save the
//! user-banked `r13/r14` with the `^` form. A Rust routine saves that pointer into the
//! outgoing task, schedules, and returns the incoming one; we restore and `RFE`.
//!
//! Classification: L0 port · cortex-a context switch · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::naked_asm;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::kernel::{self, Kernel};

static FIRST_SWITCH: AtomicBool = AtomicBool::new(true);

pub(super) fn arm_first_switch() {
    FIRST_SWITCH.store(true, Ordering::Relaxed);
}

// Save/restore the 18-word frame. `save_ctx` assumes we are in SVC mode already is false — it
// switches to SVC via `cps` after `srs`. Frame offsets (words): sp_usr=0, lr_usr=1, r0=2 ..
// r12=14, lr=15, PC=16, CPSR=17.
macro_rules! save_ctx {
    () => {
        "srsdb sp!, #0x13
         cps #0x13
         push {{r0-r12, lr}}
         sub sp, sp, #8
         stmia sp, {{r13, r14}}^"
    };
}
macro_rules! restore_ctx {
    () => {
        "ldmia sp, {{r13, r14}}^
         add sp, sp, #8
         pop {{r0-r12, lr}}
         rfeia sp!"
    };
}

/// IRQ vector: preemptive/voluntary context switch.
#[unsafe(naked)]
pub extern "C" fn irq_vector() {
    naked_asm!(
        "sub lr, lr, #4",
        save_ctx!(),
        "mov r0, sp",
        "bl {entry}",
        "mov sp, r0",
        restore_ctx!(),
        entry = sym irq_entry,
    )
}

extern "C" fn irq_entry(sp: u32) -> u32 {
    super::ISR_DEPTH.fetch_add(1, Ordering::SeqCst);
    let id = super::intc::acknowledge();
    let next = if id == super::intc::TIMER_ID {
        let n = kernel::with(|k| {
            if !FIRST_SWITCH.swap(false, Ordering::Relaxed) {
                k.tasks[k.current as usize].sp = sp as usize;
            }
            k.tick();
            super::timer::rearm();
            let n = k.schedule();
            super::enter(k, n)
        });
        super::intc::end(id);
        n
    } else if id == super::intc::RESCHED_ID {
        let n = kernel::with(|k| {
            if !FIRST_SWITCH.swap(false, Ordering::Relaxed) {
                k.tasks[k.current as usize].sp = sp as usize;
            }
            let n = k.schedule();
            super::enter(k, n)
        });
        super::intc::end(id);
        n
    } else {
        sp
    };
    super::SWITCH_PENDING.store(false, Ordering::Relaxed);
    super::ISR_DEPTH.fetch_sub(1, Ordering::SeqCst);
    next
}

/// `SVC` vector: the EL0/USR syscall gate, and (on ARMv6) the SVC-mode reschedule.
#[unsafe(naked)]
pub extern "C" fn svc_vector() {
    naked_asm!(
        save_ctx!(),
        "mov r0, sp",
        "bl {entry}",
        "mov sp, r0",
        restore_ctx!(),
        entry = sym svc_entry,
    )
}

// Frame word offsets.
const F_SP_USR: usize = 0;
const F_R0: usize = 2;
const F_R7: usize = 9;
const F_CPSR: usize = 17;

extern "C" fn svc_entry(sp: u32) -> u32 {
    let f = sp as *mut u32;
    // SAFETY: `f` is the frame this handler just pushed on the SVC stack.
    let spsr = unsafe { f.add(F_CPSR).read() };
    if spsr & 0x1F != 0x10 {
        // Caller was in SVC mode (ARMv6 reschedule): just switch.
        let next = kernel::with(|k| {
            k.tasks[k.current as usize].sp = sp as usize;
            let n = k.schedule();
            super::enter(k, n)
        });
        super::SWITCH_PENDING.store(false, Ordering::Relaxed);
        return next;
    }
    // Caller was in USR mode: a system call. r7 = number, r0-r3 = args, result → r0.
    let (n, args, user_sp) = unsafe {
        (
            f.add(F_R7).read(),
            [
                f.add(F_R0).read() as usize,
                f.add(F_R0 + 1).read() as usize,
                f.add(F_R0 + 2).read() as usize,
                f.add(F_R0 + 3).read() as usize,
            ],
            f.add(F_SP_USR).read() as usize,
        )
    };
    kernel::with(|k| {
        let t = k.cur();
        t.syscall = (n, args);
        t.user_psp = user_sp;
        t.user_exc_return = spsr;
        t.in_syscall = true;
    });
    let (sn, sargs) = kernel::with(|k| k.cur().syscall);
    // SAFETY: enable IRQs so a blocking syscall can be preempted / rescheduled.
    unsafe { core::arch::asm!("cpsie i", options(nomem, nostack, preserves_flags)) };
    let r = crate::security::syscall::dispatch(sn, sargs);
    // SAFETY: re-mask before touching the frame and returning.
    unsafe { core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags)) };
    kernel::with(|k| k.cur().in_syscall = false);
    // SAFETY: write the result into the saved r0 slot.
    unsafe { f.add(F_R0).write(r as u32) };
    sp
}

/// Prefetch/data-abort vector: a fault from USR kills the domain; a kernel fault halts.
#[unsafe(naked)]
pub extern "C" fn abort_vector() {
    naked_asm!(
        save_ctx!(),
        "mov r0, sp",
        "bl {entry}",
        "mov sp, r0",
        restore_ctx!(),
        entry = sym abort_entry,
    )
}

extern "C" fn abort_entry(sp: u32) -> u32 {
    let f = sp as *mut u32;
    // SAFETY: frame pushed by this handler.
    let spsr = unsafe { f.add(F_CPSR).read() };
    if spsr & 0x1F != 0x10 {
        // Kernel-mode abort: unrecoverable.
        let (dfsr, dfar): (u32, u32);
        // SAFETY: reading the fault status/address registers.
        unsafe {
            core::arch::asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) dfsr, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) dfar, options(nomem, nostack, preserves_flags));
        }
        crate::kprintln!("\n*** Cortex-A kernel abort: DFSR={dfsr:#x} DFAR={dfar:#x} — halted ***");
        loop {
            super::wait_for_interrupt();
        }
    }
    // USR-mode abort: sandbox violation — kill the domain, schedule another task.
    let far: u32;
    // SAFETY: reading the fault address register.
    unsafe { core::arch::asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) far, options(nomem, nostack, preserves_flags)) };
    let d = kernel::with(|k| {
        let cur = k.current;
        let d = crate::security::DomainId(k.tasks[cur as usize].domain);
        let in_sc = k.tasks[cur as usize].in_syscall;
        (d, in_sc)
    });
    crate::kprintln!("[sandbox] USR abort: FAR={far:#x} in_syscall={} — domain killed", d.1);
    let d = d.0;
    kernel::with(|k| k.retire(k.current, usize::MAX));
    let _ = crate::security::kill_internal(d);
    crate::security::record_fault(d);
    super::SWITCH_PENDING.store(false, Ordering::Relaxed);
    kernel::with(|k| {
        let n = k.schedule();
        super::enter(k, n)
    })
}

/// Build a fresh task's frame (18 words). Kernel task: SVC mode, `PC = task_trampoline`. User
/// task: USR mode, `PC = entry`, user stack as `SP_usr`, `LR_usr = user_task_return`, arg in
/// `r0`; its frame lives on the private kernel stack and its own stack is opened to USR.
pub(super) fn init_task(k: &mut Kernel, i: u8) {
    let t = &mut k.tasks[i as usize];
    match t.user_entry {
        None => {
            let top = (t.stack.as_ref().expect("task without stack").top() & !7) as u32;
            let sp = top - 72;
            let f = sp as *mut u32;
            // SAFETY: inside the task's exclusively owned, 8-aligned stack.
            unsafe {
                for n in 0..18 {
                    f.add(n).write(0);
                }
                f.add(16).write(super::task_trampoline as *const () as u32); // PC
                f.add(17).write(0x13); // CPSR: SVC, IRQ+FIQ enabled
            }
            t.sp = sp as usize;
        }
        Some(entry) => {
            let ustack = t.stack.as_ref().expect("user task without stack");
            let (ubase, ulen, utop) = (ustack.base() as u32, ustack.len() as u32, (ustack.top() & !7) as u32);
            let kstack_top = (t.kstack.as_ref().expect("user task without kernel stack").top() & !7) as u32;
            let arg = t.arg as u32;
            super::paging::open_user_range(ubase, ulen);
            let sp = kstack_top - 72;
            let f = sp as *mut u32;
            // SAFETY: inside the task's private kernel stack.
            unsafe {
                for n in 0..18 {
                    f.add(n).write(0);
                }
                f.add(0).write(utop); // SP_usr = user stack top
                f.add(1).write(crate::user::user_task_return as *const () as u32); // LR_usr
                f.add(2).write(arg); // r0 = arg
                f.add(16).write(entry as *const () as u32); // PC = user entry
                f.add(17).write(0x10); // CPSR: USR mode, IRQ+FIQ enabled
            }
            t.sp = sp as usize;
        }
    }
}
