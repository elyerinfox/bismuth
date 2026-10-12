//! x86-64 context switch (the PendSV analog) and the task-stack frame layout.
//!
//! A switch is driven by an interrupt — the PIT timer IRQ (preemptive, round-robin) or the
//! software yield vector `int 0x81` (cooperative, when a task blocks). The stub saves all
//! 15 general registers below the hardware-pushed iretq frame, hands the stack pointer to a
//! Rust routine that saves it into the outgoing task, schedules, and returns the incoming
//! task's stack pointer; the stub then restores and `iretq`s into it. The target is
//! soft-float, so no 16-byte alignment dance is needed before the `call`.
//!
//! A newly created task's stack is pre-loaded with a matching frame so the first switch
//! "returns" into [`super::task_trampoline`].
//!
//! Classification: L0 port · x86-64 context switch · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::kernel::{self, Kernel};

/// Skip saving the outgoing context on the very first switch (there is no task to save —
/// we came from `start`).
static FIRST_SWITCH: AtomicBool = AtomicBool::new(true);

pub(super) fn arm_first_switch() {
    FIRST_SWITCH.store(true, Ordering::Relaxed);
}

macro_rules! save_gprs {
    () => {
        "push rax\npush rbx\npush rcx\npush rdx\npush rsi\npush rdi\npush rbp\n\
         push r8\npush r9\npush r10\npush r11\npush r12\npush r13\npush r14\npush r15"
    };
}
macro_rules! restore_gprs {
    () => {
        "pop r15\npop r14\npop r13\npop r12\npop r11\npop r10\npop r9\npop r8\n\
         pop rbp\npop rdi\npop rsi\npop rdx\npop rcx\npop rbx\npop rax"
    };
}

/// Timer IRQ: preemptive context switch (plus the kernel tick and PIC EOI).
#[unsafe(naked)]
pub extern "C" fn timer_isr() {
    naked_asm!(
        save_gprs!(),
        "mov rdi, rsp",
        "call {entry}",
        "mov rsp, rax",
        restore_gprs!(),
        "iretq",
        entry = sym timer_entry,
    )
}

/// Software yield (`int 0x81`): cooperative context switch (no tick, no EOI).
#[unsafe(naked)]
pub extern "C" fn yield_isr() {
    naked_asm!(
        save_gprs!(),
        "mov rdi, rsp",
        "call {entry}",
        "mov rsp, rax",
        restore_gprs!(),
        "iretq",
        entry = sym yield_entry,
    )
}

extern "C" fn timer_entry(rsp: u64) -> u64 {
    super::ISR_DEPTH.fetch_add(1, Ordering::SeqCst);
    // If a tickless one-shot was armed, restore the periodic cadence *before* any task resumes
    // (so preemption and timekeeping continue), and advance the clock by the whole nap rather
    // than a single tick.
    let nap = super::NAP_TICKS.swap(0, Ordering::Relaxed);
    if nap > 0 {
        super::pic::restore_periodic();
    }
    let next = kernel::with(|k| {
        if !FIRST_SWITCH.swap(false, Ordering::Relaxed) {
            k.tasks[k.current as usize].sp = rsp as usize;
        }
        if nap > 0 {
            k.advance_to(k.tick + nap as u64);
        } else {
            k.tick();
        }
        let n = k.schedule();
        enter(k, n)
    });
    super::SWITCH_PENDING.store(false, Ordering::Relaxed);
    super::pic::eoi();
    super::ISR_DEPTH.fetch_sub(1, Ordering::SeqCst);
    next
}

extern "C" fn yield_entry(rsp: u64) -> u64 {
    super::ISR_DEPTH.fetch_add(1, Ordering::SeqCst);
    let next = kernel::with(|k| {
        k.tasks[k.current as usize].sp = rsp as usize;
        let n = k.schedule();
        enter(k, n)
    });
    super::SWITCH_PENDING.store(false, Ordering::Relaxed);
    super::ISR_DEPTH.fetch_sub(1, Ordering::SeqCst);
    next
}

/// The incoming task's saved stack pointer. If it is a user task, first publish its private
/// kernel stack into `RSP0` so the CPU switches onto it on the next ring-3 trap.
fn enter(k: &mut Kernel, n: u8) -> u64 {
    let t = &k.tasks[n as usize];
    if t.user {
        if let Some(ks) = t.kstack.as_ref() {
            super::gdt::set_kernel_stack(ks.top() as u64);
        }
    }
    // Flip ring-3 page ownership so only this task's domain can reach its User pages.
    super::paging::switch_ring3(t.domain);
    t.sp as u64
}

// Offsets (in u64 words) into the 15-GPR save image produced by `save_gprs!`, followed by
// the CPU's iretq frame.
const OFF_RDI: usize = 9; // first integer argument (System V)
const OFF_RSI: usize = 10;
const OFF_RDX: usize = 11;
const OFF_RCX: usize = 12;
const OFF_RAX: usize = 14; // syscall number in / result out
const OFF_RIP: usize = 15;
const OFF_CS: usize = 16;
const OFF_RFLAGS: usize = 17;
const OFF_RSP: usize = 18;

/// `int 0x80` system-call gate (trap gate, reachable from ring 3). On entry from ring 3 the
/// CPU has already switched to the task's kernel stack (`RSP0`); we save the user GPRs, run
/// the dispatcher on that kernel stack (so it may block, exactly like the ARM `svc` path),
/// write the result back into the saved `RAX`, and `iretq` to ring 3.
#[unsafe(naked)]
pub extern "C" fn syscall_isr() {
    naked_asm!(
        save_gprs!(),
        "mov rdi, rsp",
        "call {entry}",
        restore_gprs!(),
        "iretq",
        entry = sym syscall_entry,
    )
}

extern "C" fn syscall_entry(rsp: u64) {
    let f = rsp as *mut u64;
    // SAFETY: `f` points at the GPR image + iretq frame this handler just pushed.
    let (n, args, user_rsp, user_rflags) = unsafe {
        (
            f.add(OFF_RAX).read() as u32,
            [
                f.add(OFF_RDI).read() as usize,
                f.add(OFF_RSI).read() as usize,
                f.add(OFF_RDX).read() as usize,
                f.add(OFF_RCX).read() as usize,
            ],
            f.add(OFF_RSP).read() as usize,
            f.add(OFF_RFLAGS).read() as u32,
        )
    };
    // Record the call + saved user context on the task, and mark it in-syscall so a fault
    // taken on the kernel stack is diagnosed as a kernel bug, not a sandbox violation.
    kernel::with(|k| {
        let t = k.cur();
        t.syscall = (n, args);
        t.user_psp = user_rsp;
        t.user_exc_return = user_rflags;
        t.in_syscall = true;
    });
    let (sn, sargs) = kernel::with(|k| k.cur().syscall);
    let r = crate::security::syscall::dispatch(sn, sargs);
    kernel::with(|k| k.cur().in_syscall = false);
    // SAFETY: write the result into the saved RAX slot; `restore_gprs!` loads it for `iretq`.
    unsafe { f.add(OFF_RAX).write(r as u64) };
}

/// Page-fault handler. A fault from ring 3 (or any user-stack overflow) kills just the
/// offending domain and schedules another task; a fault in the kernel is fatal and halts.
#[unsafe(naked)]
pub extern "C" fn page_fault_isr() {
    naked_asm!(
        // The CPU pushed an error code below the iretq frame; our save sits below that.
        save_gprs!(),
        "mov rdi, rsp",
        "call {entry}",
        // On a user fault `entry` returns the next task's stack pointer (a clean switch frame
        // with no error code); on a kernel fault it never returns.
        "mov rsp, rax",
        restore_gprs!(),
        "iretq",
        entry = sym pf_entry,
    )
}

extern "C" fn pf_entry(rsp: u64) -> u64 {
    super::ISR_DEPTH.fetch_add(1, Ordering::SeqCst);
    let f = rsp as *mut u64;
    // With the error code pushed, the iretq frame sits one word higher than usual.
    // SAFETY: `f` points at the pushed GPR image, error code, then the iretq frame.
    let cs = unsafe { f.add(OFF_CS + 1).read() };
    let cr2: u64;
    // SAFETY: reading CR2 (the faulting address) is side-effect free.
    unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags)) };
    let from_ring3 = cs & 3 == 3;

    if !from_ring3 {
        // Fault in kernel (or in a syscall running on behalf of a user task): not recoverable.
        let (psp, rflags, in_sc) = kernel::with(|k| {
            let t = k.cur();
            (t.user_psp, t.user_exc_return, t.in_syscall)
        });
        super::console_sink("\n*** x86 page fault in kernel — halted ***\n");
        crate::kprintln!(
            "  CR2={cr2:#018x} CS={cs:#x} in_syscall={in_sc} user_rsp={psp:#x} user_rflags={rflags:#x}"
        );
        loop {
            // SAFETY: parking the CPU after an unrecoverable fault.
            unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
        }
    }

    // Sandbox violation: retire the faulting task and kill its domain, then switch away so the
    // faulting instruction never runs again.
    let d = kernel::with(|k| {
        let cur = k.current;
        let d = crate::security::DomainId(k.tasks[cur as usize].domain);
        k.retire(cur, usize::MAX);
        d
    });
    let _ = crate::security::kill(d);
    crate::security::record_fault(d);
    let next = kernel::with(|k| {
        let n = k.schedule();
        enter(k, n)
    });
    super::SWITCH_PENDING.store(false, Ordering::Relaxed);
    super::ISR_DEPTH.fetch_sub(1, Ordering::SeqCst);
    next
}

/// Build a fresh task's initial switch frame: 15 zeroed GPRs then an iretq frame that
/// "returns" into the trampoline with interrupts enabled.
pub(super) fn init_task(k: &mut Kernel, i: u8) {
    let t = &mut k.tasks[i as usize];
    match t.user_entry {
        // Kernel (ring-0) task: the switch frame lives on its single stack and "returns" into
        // the privileged trampoline, which runs the entry and exits.
        None => {
            let top = t.stack.as_ref().expect("task without stack").top() & !0xF;
            let sp = top - 20 * 8;
            let frame = sp as *mut u64;
            let (cs, ss) = super::selectors();
            // SAFETY: the frame lies inside the task's exclusively owned, 16-aligned stack.
            unsafe {
                for n in 0..15 {
                    frame.add(n).write(0); // r15..rax
                }
                frame.add(OFF_RIP).write(super::task_trampoline as *const () as u64);
                frame.add(OFF_CS).write(cs as u64);
                frame.add(OFF_RFLAGS).write(0x202); // reserved bit 1 + IF
                frame.add(OFF_RSP).write(top as u64);
                frame.add(19).write(ss as u64); // SS
            }
            t.sp = sp;
        }
        // User (ring-3) task: the switch frame lives on the task's private kernel stack and
        // its iretq frame drops straight to ring 3 — CS/SS are the user selectors, RSP the
        // user stack, RIP the entry, RDI the argument. A returning entry pops the address we
        // seed on the user stack (`user_task_return`), which exits via a syscall.
        Some(entry) => {
            let ustack = t.stack.as_ref().expect("user task without stack");
            let (ubase, ulen) = (ustack.base() as u64, ustack.len() as u64);
            let kstack_top = t.kstack.as_ref().expect("user task without kernel stack").top() & !0xF;
            let ustack_top = ustack.top() & !0xF;
            let arg = t.arg;
            let domain = t.domain;
            // Open this task's own stack to ring 3, owned by its domain (its code already runs
            // from the User-mapped kernel text). Kernel data and other domains' stacks stay
            // supervisor-only — and other ring-3 domains' stacks are demoted while this one runs.
            super::paging::open_user_range(ubase, ulen, domain);
            // Seed the user stack with the return address for a cleanly-returning entry fn.
            let user_rsp = ustack_top - 8;
            // SAFETY: `user_rsp` is inside the task's own (User-mapped) stack.
            unsafe { (user_rsp as *mut u64).write(crate::user::user_task_return as *const () as u64) };
            let sp = kstack_top - 20 * 8;
            let frame = sp as *mut u64;
            // SAFETY: the frame lies inside the task's private kernel stack.
            unsafe {
                for n in 0..15 {
                    frame.add(n).write(0);
                }
                frame.add(OFF_RDI).write(arg as u64); // first argument
                frame.add(OFF_RIP).write(entry as *const () as u64);
                frame.add(OFF_CS).write(super::gdt::USER_CODE as u64);
                frame.add(OFF_RFLAGS).write(0x202); // reserved bit 1 + IF
                frame.add(OFF_RSP).write(user_rsp as u64);
                frame.add(19).write(super::gdt::USER_DATA as u64); // SS
            }
            t.sp = sp;
        }
    }
}
