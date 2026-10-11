//! AArch64 context switch (the PendSV analog) and the task-stack frame layout.
//!
//! A switch is driven by an interrupt — the generic-timer PPI (preemptive) or the reschedule
//! SGI (voluntary, when a task blocks; raised by `request_switch`, deferred by `DAIF`
//! masking). The IRQ vector saves the full EL1 exception context (`x0`–`x30`, `SP_EL0`,
//! `ELR_EL1`, `SPSR_EL1`) on the outgoing task's stack, hands the stack pointer to a Rust
//! routine that saves it into the outgoing task, schedules, and returns the incoming task's
//! stack pointer; the vector then restores and `ERET`s into it. The direct analog of
//! `x86_64/sw.rs`'s `timer_isr`/`timer_entry`.
//!
//! A new task's stack is pre-loaded with a matching frame so the first `ERET` "returns" into
//! [`super::task_trampoline`] at EL1.
//!
//! Classification: L0 port · aarch64 context switch · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::kernel::{self, Kernel};

/// Skip saving the outgoing context on the very first switch (we came from `start`).
static FIRST_SWITCH: AtomicBool = AtomicBool::new(true);

pub(super) fn arm_first_switch() {
    FIRST_SWITCH.store(true, Ordering::Relaxed);
}

/// Exception frame: 34 × u64 = 272 bytes. x0–x29 at 0..240, x30 at 240, SP_EL0 at 248,
/// ELR_EL1 at 256, SPSR_EL1 at 264.
macro_rules! save_ctx {
    () => {
        "sub sp, sp, #272
         stp x0, x1, [sp, #0]
         stp x2, x3, [sp, #16]
         stp x4, x5, [sp, #32]
         stp x6, x7, [sp, #48]
         stp x8, x9, [sp, #64]
         stp x10, x11, [sp, #80]
         stp x12, x13, [sp, #96]
         stp x14, x15, [sp, #112]
         stp x16, x17, [sp, #128]
         stp x18, x19, [sp, #144]
         stp x20, x21, [sp, #160]
         stp x22, x23, [sp, #176]
         stp x24, x25, [sp, #192]
         stp x26, x27, [sp, #208]
         stp x28, x29, [sp, #224]
         mrs x9, sp_el0
         stp x30, x9, [sp, #240]
         mrs x9, elr_el1
         mrs x10, spsr_el1
         stp x9, x10, [sp, #256]"
    };
}

macro_rules! restore_ctx {
    () => {
        "ldp x9, x10, [sp, #256]
         msr elr_el1, x9
         msr spsr_el1, x10
         ldr x9, [sp, #248]
         msr sp_el0, x9
         ldr x30, [sp, #240]
         ldp x0, x1, [sp, #0]
         ldp x2, x3, [sp, #16]
         ldp x4, x5, [sp, #32]
         ldp x6, x7, [sp, #48]
         ldp x8, x9, [sp, #64]
         ldp x10, x11, [sp, #80]
         ldp x12, x13, [sp, #96]
         ldp x14, x15, [sp, #112]
         ldp x16, x17, [sp, #128]
         ldp x18, x19, [sp, #144]
         ldp x20, x21, [sp, #160]
         ldp x22, x23, [sp, #176]
         ldp x24, x25, [sp, #192]
         ldp x26, x27, [sp, #208]
         ldp x28, x29, [sp, #224]
         add sp, sp, #272"
    };
}

/// IRQ vector body: save context, dispatch (which may switch), restore, `ERET`.
#[unsafe(naked)]
pub extern "C" fn irq_vector() {
    naked_asm!(
        save_ctx!(),
        "mov x0, sp",
        "bl {entry}",
        "mov sp, x0",
        restore_ctx!(),
        "eret",
        entry = sym irq_entry,
    )
}

extern "C" fn irq_entry(sp: u64) -> u64 {
    super::ISR_DEPTH.fetch_add(1, Ordering::SeqCst);
    let id = super::intc::acknowledge();
    let next = if id >= 1020 {
        sp // spurious: no EOI
    } else if id == super::timer::TIMER_PPI {
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
    } else if id < 16 {
        // Reschedule SGI (a task blocked/yielded).
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
        super::intc::end(id); // unexpected device IRQ: acknowledge and ignore (stage 2)
        sp
    };
    super::SWITCH_PENDING.store(false, Ordering::Relaxed);
    super::ISR_DEPTH.fetch_sub(1, Ordering::SeqCst);
    next
}

/// Build a fresh task's initial exception frame. A kernel (EL1) task starts in
/// `task_trampoline` at EL1h; a user (EL0) task starts at its entry at EL0t with its own user
/// stack as `SP_EL0`, `x30 = user_task_return`, and its stack opened to EL0. The frame lives
/// on the task's stack (EL1) or private kernel stack (EL0); the first `ERET` returns into it.
pub(super) fn init_task(k: &mut Kernel, i: u8) {
    let t = &mut k.tasks[i as usize];
    match t.user_entry {
        None => {
            let top = t.stack.as_ref().expect("task without stack").top() & !0xF;
            let sp = top - 272;
            let f = sp as *mut u64;
            // SAFETY: the frame lies inside the task's exclusively owned, 16-aligned stack.
            unsafe {
                for n in 0..34 {
                    f.add(n).write(0);
                }
                f.add(32).write(super::task_trampoline as *const () as u64); // ELR_EL1
                f.add(33).write(0x5); // SPSR_EL1 = EL1h (SP_EL1), DAIF all enabled
            }
            t.sp = sp;
        }
        Some(entry) => {
            let ustack = t.stack.as_ref().expect("user task without stack");
            let (ubase, ulen, utop) = (ustack.base() as u64, ustack.len() as u64, (ustack.top() as u64) & !0xF);
            let kstack_top = t.kstack.as_ref().expect("user task without kernel stack").top() & !0xF;
            let arg = t.arg;
            // Open the task's own stack to EL0 (its code runs from the EL0-mapped kernel text).
            super::paging::open_user_range(ubase, ulen);
            let sp = kstack_top - 272;
            let f = sp as *mut u64;
            // SAFETY: the frame lies inside the task's private kernel stack.
            unsafe {
                for n in 0..34 {
                    f.add(n).write(0);
                }
                f.add(0).write(arg as u64); // x0 = arg
                f.add(30).write(crate::user::user_task_return as *const () as u64); // x30 = LR
                f.add(31).write(utop); // SP_EL0 = user stack top
                f.add(32).write(entry as *const () as u64); // ELR_EL1 = user entry
                f.add(33).write(0x0); // SPSR_EL1 = EL0t (use SP_EL0), DAIF all enabled
            }
            t.sp = sp;
        }
    }
}

/// Lower-EL synchronous exception vector: the `SVC #0` syscall gate and the EL0 abort path.
#[unsafe(naked)]
pub extern "C" fn svc_vector() {
    naked_asm!(
        save_ctx!(),
        "mov x0, sp",
        "bl {entry}",
        "mov sp, x0",
        restore_ctx!(),
        "eret",
        entry = sym svc_entry,
    )
}

extern "C" fn svc_entry(sp: u64) -> u64 {
    let f = sp as *mut u64;
    let esr: u64;
    // SAFETY: reading the syndrome register is side-effect free.
    unsafe { asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack, preserves_flags)) };
    let ec = esr >> 26;
    if ec == 0x15 {
        // SVC: x8 = number, x0–x3 = args. Record the call + saved user context on the task.
        // SAFETY: `f` is the saved GPR image this handler just pushed.
        let (n, args, sp_el0, spsr) = unsafe {
            (
                f.add(8).read() as u32,
                [f.read() as usize, f.add(1).read() as usize, f.add(2).read() as usize, f.add(3).read() as usize],
                f.add(31).read() as usize,
                f.add(33).read() as u32,
            )
        };
        kernel::with(|k| {
            let t = k.cur();
            t.syscall = (n, args);
            t.user_psp = sp_el0;
            t.user_exc_return = spsr;
            t.in_syscall = true;
        });
        let (sn, sargs) = kernel::with(|k| k.cur().syscall);
        // Unmask IRQs so a blocking syscall can be preempted / rescheduled (the reschedule
        // SGI and the timer fire normally; the switch saves this handler's context too).
        // SAFETY: re-enabling interrupts while running the syscall on the task's kernel stack.
        unsafe { asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)) };
        let r = crate::security::syscall::dispatch(sn, sargs);
        // SAFETY: re-masking before we touch the saved frame and `ERET`.
        unsafe { asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)) };
        kernel::with(|k| k.cur().in_syscall = false);
        // SAFETY: write the result into the saved x0 slot for the `ERET`.
        unsafe { f.write(r as u64) };
        sp
    } else {
        // Any other synchronous exception from EL0 (data/instruction abort, illegal state):
        // a sandbox violation — kill the domain and schedule another task.
        let far: u64;
        // SAFETY: reading the fault address register is side-effect free.
        unsafe { asm!("mrs {}, far_el1", out(reg) far, options(nomem, nostack, preserves_flags)) };
        let (d, in_sc, upsp, uspsr) = kernel::with(|k| {
            let cur = k.current;
            let t = &k.tasks[cur as usize];
            (crate::security::DomainId(t.domain), t.in_syscall, t.user_psp, t.user_exc_return)
        });
        crate::kprintln!(
            "[sandbox] EL0 fault: ESR={esr:#x} FAR={far:#x} in_syscall={in_sc} user_sp={upsp:#x} user_spsr={uspsr:#x} — domain killed"
        );
        kernel::with(|k| k.retire(k.current, usize::MAX));
        let _ = crate::security::kill_internal(d); // policy enforcement from a fault path
        crate::security::record_fault(d);
        kernel::with(|k| {
            let n = k.schedule();
            super::enter(k, n)
        })
    }
}
