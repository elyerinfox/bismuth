//! ARMv7-M / ARMv8-M Mainline port (Cortex-M3, M4(F), M7, M33).
//!
//! * Critical sections mask interrupts with PRIMASK.
//! * Context switches run in PendSV at the lowest exception priority, so a switch
//!   requested anywhere (task or ISR) is deferred until no other handler is active.
//! * SysTick drives the kernel tick.
//! * Tasks run in thread mode on PSP; handlers use MSP.
//! * On FPU targets (`eabihf`) the high FP registers are saved lazily, only for tasks
//!   that have actually used the FPU (EXC_RETURN bit 4).
//! * **Hardware isolation:** user (sandboxed) tasks run unprivileged with the MPU
//!   confining them to their own stack plus read-only flash. `svc #1` enters the kernel:
//!   the handler moves the call onto the task's private kernel stack and returns into a
//!   privileged trampoline (which may block); `svc #2` returns the result and drops
//!   privilege again. MPU faults from user code kill the offending domain.
//!
//! Part of the trusted computing base: inline assembly and system registers.
//!
//! Classification: L0 port · Cortex-M port · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::config::TICK_HZ;
use crate::kernel::{self, Kernel};

const ICSR: *mut u32 = 0xE000_ED04 as *mut u32;
const SHPR3: *mut u32 = 0xE000_ED20 as *mut u32;
const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
const SHCSR: *mut u32 = 0xE000_ED24 as *mut u32;
const CFSR: *mut u32 = 0xE000_ED28 as *mut u32;
const MMFAR: *const u32 = 0xE000_ED34 as *const u32;
const MPU_TYPE: *const u32 = 0xE000_ED90 as *const u32;
const MPU_CTRL: *mut u32 = 0xE000_ED94 as *mut u32;
const MPU_RNR: *mut u32 = 0xE000_ED98 as *mut u32;
const MPU_RBAR: *mut u32 = 0xE000_ED9C as *mut u32;
const MPU_RASR: *mut u32 = 0xE000_EDA0 as *mut u32;
const PENDSVSET: u32 = 1 << 28;
const EXC_RETURN_THREAD_PSP: u32 = 0xFFFF_FFFD;

/// SVC immediates.
const SVC_SYSCALL: u8 = 1;
const SVC_SYSRET: u8 = 2;

/// Nestable critical section using PRIMASK.
#[inline(always)]
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    let primask: u32;
    // SAFETY: reading PRIMASK and masking interrupts has no memory-safety implications;
    // the asm acts as a compiler barrier (no `nomem`).
    unsafe { asm!("mrs {}, PRIMASK", "cpsid i", out(reg) primask, options(nostack, preserves_flags)) };
    let r = f();
    if primask & 1 == 0 {
        // SAFETY: interrupts were enabled on entry, so re-enabling restores that state.
        unsafe { asm!("cpsie i", options(nostack, preserves_flags)) };
    }
    r
}

#[inline]
pub fn request_switch() {
    // SAFETY: ICSR is write-one-to-set; writing PENDSVSET only pends PendSV.
    unsafe { ICSR.write_volatile(PENDSVSET) };
}

#[inline]
pub fn in_isr() -> bool {
    let ipsr: u32;
    // SAFETY: reading IPSR is side-effect free.
    unsafe { asm!("mrs {}, IPSR", out(reg) ipsr, options(nomem, nostack, preserves_flags)) };
    ipsr & 0x1FF != 0
}

/// Lay out an initial exception frame so the first PendSV "returns" into the task.
pub(crate) fn init_task(k: &mut Kernel, i: u8) {
    let t = &mut k.tasks[i as usize];
    let top = t.stack.as_ref().expect("task without stack").top();
    // 8 hardware-stacked words + 9 software-saved words (r4-r11, EXC_RETURN).
    let sp = top - 17 * 4;
    let frame = sp as *mut u32;
    // Kernel tasks start in a privileged trampoline; user tasks start directly in their
    // entry function (unprivileged), returning into an exit stub.
    let (r0, lr, pc) = match t.user_entry {
        Some(entry) => (
            t.arg as u32,
            crate::user::user_task_return as *const () as usize as u32,
            entry as *const () as usize as u32,
        ),
        None => (i as u32, task_return_trap as *const () as usize as u32, task_trampoline as *const () as usize as u32),
    };
    let words: [u32; 17] = [
        0, 0, 0, 0, 0, 0, 0, 0,  // r4-r11
        EXC_RETURN_THREAD_PSP,   // lr (EXC_RETURN)
        r0,                      // r0
        0, 0, 0, 0,              // r1-r3, r12
        lr,                      // lr
        pc & !1,                 // pc
        0x0100_0000,             // xPSR (Thumb bit)
    ];
    for (n, w) in words.iter().enumerate() {
        // SAFETY: the frame lies inside the task's (exclusively owned) stack.
        unsafe { frame.add(n).write_volatile(*w) };
    }
    t.sp = sp;
}

extern "C" fn task_trampoline(i: u32) -> ! {
    kernel::task::run_entry(i as u8);
    exit_current(0)
}

extern "C" fn task_return_trap() -> ! {
    // Unreachable: the trampoline never returns.
    loop {
        // SAFETY: `wfi` only waits for an interrupt.
        unsafe { asm!("wfi") };
    }
}

/// Whether an unprivileged task may have the kernel read `[addr, end)` as read-only data:
/// the flash (code + rodata) region, below RAM. Kernel/task RAM is excluded.
pub(crate) fn user_readable(_addr: usize, end: usize) -> bool {
    end <= 0x2000_0000
}

pub(crate) fn exit_current(code: usize) -> ! {
    kernel::with(|k| kernel::task::finish_current(k, code));
    // PendSV fires as soon as the critical section above ends; we never come back.
    loop {
        // SAFETY: `wfi` only waits for an interrupt.
        unsafe { asm!("wfi") };
    }
}

pub(crate) fn idle() {
    // SAFETY: `wfi` only waits for an interrupt.
    unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
}

/// SysTick clocks per kernel tick, recorded by [`start`] (SysTick's input clock / `TICK_HZ`).
static CLOCKS_PER_TICK: AtomicU32 = AtomicU32::new(0);

/// SysTick COUNTFLAG: set once the counter has reached zero since CSR was last read.
const SYST_COUNTFLAG: u32 = 1 << 16;
/// Largest value the 24-bit SysTick reload register can hold.
const SYST_RELOAD_MAX: u32 = 0x00FF_FFFF;

/// Tickless light sleep: suppress the periodic tick, reprogram SysTick to fire at the next
/// timeout (`deadline` in kernel ticks), halt the core, then catch the kernel clock up to
/// however long we actually slept — so every timeout that came due fires, in order, on wake.
///
/// A single nap is capped by SysTick's 24-bit reload; a longer gap simply naps again. If an
/// interrupt wakes us early, we credit only the elapsed time and the governor re-evaluates.
pub(crate) fn sleep_until(deadline: Option<u64>) {
    let per_tick = CLOCKS_PER_TICK.load(Ordering::Relaxed);
    let now = kernel::with(|k| k.tick);
    // How many ticks until the next event; with none pending, nap the maximum span.
    let want = match deadline {
        Some(d) if d > now => d - now,
        Some(_) => return, // deadline already passed: let the loop reschedule
        None => u64::MAX,
    };
    if per_tick == 0 {
        // SysTick clock not recorded (should not happen once started): plain WFI.
        // SAFETY: `wfi` only waits for an interrupt.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
        return;
    }
    let max_ticks = (SYST_RELOAD_MAX / per_tick).max(1) as u64;
    let naps = want.min(max_ticks) as u32;
    let reload = naps * per_tick - 1;

    // SAFETY: SysTick registers; we stop the counter, reprogram its reload, nap, then read
    // the elapsed count and restore the periodic cadence. No other code touches SysTick.
    let elapsed_ticks = unsafe {
        SYST_CSR.write_volatile(0); // stop the periodic tick
        SYST_RVR.write_volatile(reload);
        SYST_CVR.write_volatile(0); // clears the current value and COUNTFLAG
        SYST_CSR.write_volatile(0b111); // enable + TICKINT + processor clock
        asm!("wfi", options(nomem, nostack, preserves_flags));
        SYST_CSR.write_volatile(0); // stop again before reading
        let remaining = SYST_CVR.read_volatile() & SYST_RELOAD_MAX;
        let counted_to_zero = SYST_CSR.read_volatile() & SYST_COUNTFLAG != 0;
        // Restore the normal periodic tick.
        SYST_RVR.write_volatile(per_tick - 1);
        SYST_CVR.write_volatile(0);
        SYST_CSR.write_volatile(0b111);
        let elapsed_clocks = if counted_to_zero { reload + 1 } else { (reload + 1).saturating_sub(remaining) };
        (elapsed_clocks / per_tick) as u64
    };
    // Reconcile: if the SysTick exception fired during the nap it already advanced the tick
    // by one; `advance_to` only moves forward, so this lands on the true tick either way and
    // runs `process_timeouts` for everything now due.
    kernel::with(|k| k.advance_to(now + elapsed_ticks));
}

static FIRST_SWITCH: AtomicBool = AtomicBool::new(true);

/// Called from PendSV with the outgoing task's stack pointer; returns the incoming one.
extern "C" fn bismuth_switch_context(sp: usize) -> usize {
    kernel::with(|k| {
        if !FIRST_SWITCH.swap(false, Ordering::Relaxed) {
            let cur = k.current as usize;
            let t = &mut k.tasks[cur];
            t.sp = sp;
            let in_kstack = t.kstack.as_ref().is_some_and(|s| sp >= s.base() as usize && sp < s.top());
            let checked = if in_kstack { t.kstack.as_ref() } else { t.stack.as_ref() };
            if let Some(s) = checked {
                if sp < s.base() as usize || s.overflowed() {
                    if t.user && !t.in_syscall {
                        // A sandboxed task overflowed its own stack: kill its domain
                        // instead of the whole system.
                        let d = crate::security::DomainId(t.domain);
                        k.retire(cur as u8, usize::MAX);
                        PENDING_KILL.store(d.0 as u32 + 1, Ordering::Relaxed);
                    } else {
                        panic!("stack overflow in task '{}'", t.name);
                    }
                }
            }
        }
        let next = k.schedule();
        let t = &k.tasks[next as usize];
        apply_protection(t.user && !t.in_syscall, t.stack.as_ref());
        t.sp
    })
}

/// Domain to kill (+1) detected inside the switch path, handled after it.
static PENDING_KILL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// MPU region size field for a power-of-two `size` (bytes) ≥ 32.
fn rasr_size(size: usize) -> u32 {
    (size.trailing_zeros() - 1) << 1
}

const RASR_EN: u32 = 1;
const RASR_XN: u32 = 1 << 28;
const AP_FULL: u32 = 0b011 << 24; // privileged RW, unprivileged RW
const AP_RO: u32 = 0b110 << 24; // read-only for everyone
const ATTR_NORMAL: u32 = 1 << 17; // TEX=000 C=1 B=0: normal memory, write-through

/// User (unprivileged) tasks require an MPU to be confined.
pub fn supports_user_tasks() -> bool {
    mpu_present()
}

/// Loading Linux images is not supported on this port (aarch64 EL0 only); fails closed.
#[cfg(feature = "linux-abi")]
pub fn open_linux_image(_code: (u64, u64), _stack: (u64, u64), _domain: u8) -> bool {
    false
}

/// Resetting a loaded image's pages is a no-op off the aarch64 port.
#[cfg(feature = "linux-abi")]
pub fn linux_reset_image(_addr: u64, _len: u64) {}

fn mpu_present() -> bool {
    // SAFETY: MPU_TYPE is a read-only System Control Space register.
    unsafe { (MPU_TYPE.read_volatile() >> 8) & 0xFF >= 2 }
}

/// Reprogram CONTROL.nPRIV and MPU region 1 for the task about to run.
fn apply_protection(unprivileged: bool, stack: Option<&crate::kernel::stack::StackRef>) {
    if !mpu_present() {
        return;
    }
    // SAFETY: System Control Space registers; called from PendSV/SVC (handler mode)
    // with interrupts masked, so the region update is atomic w.r.t. thread code.
    unsafe {
        MPU_RNR.write_volatile(1);
        match (unprivileged, stack) {
            (true, Some(s)) => {
                MPU_RBAR.write_volatile(s.base() as u32);
                MPU_RASR.write_volatile(RASR_XN | AP_FULL | ATTR_NORMAL | rasr_size(s.len()) | RASR_EN);
            }
            _ => MPU_RASR.write_volatile(0),
        }
        let mut control: u32;
        asm!("mrs {}, CONTROL", out(reg) control);
        if unprivileged {
            control |= 1;
        } else {
            control &= !1;
        }
        asm!("msr CONTROL, {}", "isb", in(reg) control);
    }
}

fn mpu_init() {
    if !mpu_present() {
        return;
    }
    // SAFETY: System Control Space registers, configured before the scheduler starts.
    unsafe {
        MPU_CTRL.write_volatile(0);
        // Region 0: the whole code area (flash), read-only and executable for user code.
        MPU_RNR.write_volatile(0);
        MPU_RBAR.write_volatile(0);
        MPU_RASR.write_volatile(AP_RO | ATTR_NORMAL | rasr_size(0x2000_0000) | RASR_EN);
        // Region 1: the running user task's stack (set at each switch).
        MPU_RNR.write_volatile(1);
        MPU_RASR.write_volatile(0);
        // Privileged code keeps the default memory map; user code gets only the regions.
        MPU_CTRL.write_volatile(0b101); // ENABLE | PRIVDEFENA
        // Route MemManage / BusFault / UsageFault to their own handlers.
        SHCSR.write_volatile(SHCSR.read_volatile() | (0b111 << 16));
        asm!("dsb", "isb");
    }
}

fn is_privileged_thread() -> bool {
    let control: u32;
    // SAFETY: reading CONTROL has no side effects.
    unsafe { asm!("mrs {}, CONTROL", out(reg) control, options(nomem, nostack, preserves_flags)) };
    control & 1 == 0
}

/// System call from a user task (`svc #1`). Privileged callers dispatch directly.
pub(crate) fn syscall(n: u32, args: [usize; 4]) -> isize {
    if is_privileged_thread() && !in_isr() {
        return crate::security::syscall::dispatch(n, args);
    }
    let r: isize;
    // SAFETY: `svc #1` traps into `SVCall`, which validates everything; arguments are
    // passed in r0-r3 and the call number in r12; the result comes back in r0.
    unsafe {
        asm!(
            "svc #1",
            inlateout("r0") args[0] => r,
            in("r1") args[1],
            in("r2") args[2],
            in("r3") args[3],
            in("r12") n,
        )
    };
    r
}

/// Runs in privileged thread mode on the task's kernel stack.
extern "C" fn syscall_trampoline() -> ! {
    let (n, args) = kernel::with(|k| k.cur().syscall);
    let r = crate::security::syscall::dispatch(n, args);
    // SAFETY: `svc #2` hands the result back to `SVCall`, which restores the user frame.
    unsafe { asm!("svc #2", in("r0") r, options(noreturn)) }
}

/// SVCall logic. Gets the caller's stack pointer and EXC_RETURN; returns the stack
/// pointer and EXC_RETURN to resume with (packed low/high).
extern "C" fn bismuth_svc(psp: usize, exc_return: u32) -> u64 {
    // `psp` points at the saved [r4-r11] block; the hardware exception frame
    // (r0-r3, r12, lr, pc, xpsr) follows 8 words (32 bytes) above it.
    let hw = (psp + 32) as *mut u32;
    // SAFETY: the hardware stacked an 8-word frame; the stacked PC points just past the
    // 16-bit `svc`, whose low byte is the immediate.
    let (regs, imm) = unsafe {
        let regs: [u32; 8] = core::array::from_fn(|n| hw.add(n).read_volatile());
        (regs, ((regs[6] - 2) as *const u16).read_volatile() as u8)
    };
    let pack = |sp: usize, er: u32| (sp as u64) | ((er as u64) << 32);
    match imm {
        SVC_SYSCALL => {
            let kframe = kernel::with(|k| {
                let t = k.cur();
                if !t.user || t.in_syscall {
                    return None;
                }
                t.syscall = (regs[4], [regs[0] as usize, regs[1] as usize, regs[2] as usize, regs[3] as usize]);
                t.user_psp = psp;
                t.user_exc_return = exc_return;
                t.in_syscall = true;
                // Build a 16-word frame ([r4-r11][hardware frame]) at the top of the
                // task's private kernel stack, matching the save/restore in `SVCall`.
                t.kstack.as_ref().map(|s| s.top() - 64)
            });
            let Some(kf) = kframe else {
                // Not a user task (or re-entrant): refuse via r0 of the caller's frame.
                // SAFETY: r0 slot of the hardware frame above the saved registers.
                unsafe { hw.write_volatile((-(crate::Error::Invalid.errno() as i32)) as u32) };
                return pack(psp, exc_return);
            };
            // Words 0-7: r4-r11 (zeroed). Words 8-15: the hardware frame entering the
            // privileged syscall trampoline.
            let words: [u32; 16] = [
                0, 0, 0, 0, 0, 0, 0, 0, // r4-r11
                0, 0, 0, 0, 0,          // r0-r3, r12
                task_return_trap as *const () as usize as u32,
                (syscall_trampoline as *const () as usize as u32) & !1,
                0x0100_0000,
            ];
            for (n, w) in words.iter().enumerate() {
                // SAFETY: the frame lies at the top of the task's private kernel stack.
                unsafe { (kf as *mut u32).add(n).write_volatile(*w) };
            }
            apply_protection(false, None);
            pack(kf, EXC_RETURN_THREAD_PSP)
        }
        SVC_SYSRET => {
            let user = kernel::with(|k| {
                let t = k.cur();
                // Only the kernel's own trampoline (privileged, inside a syscall) may return.
                if t.in_syscall && is_privileged_thread() {
                    t.in_syscall = false;
                    return Some((t.user_psp, t.user_exc_return));
                }
                None
            });
            match user {
                Some((upsp, uer)) => {
                    // SAFETY: r0 slot of the user's hardware frame (8 words above r4-r11).
                    unsafe { ((upsp + 32) as *mut u32).write_volatile(regs[0]) };
                    let stack = kernel::with(|k| k.cur().stack.as_ref().map(|s| (s.base() as usize, s.len())));
                    apply_user_region(stack);
                    pack(upsp, uer)
                }
                None => pack(psp, exc_return),
            }
        }
        _ => {
            // Unknown SVC from user code: treat as a policy violation.
            let d = kernel::with(|k| crate::security::DomainId(k.cur().domain));
            let _ = crate::security::kill(d);
            pack(psp, exc_return)
        }
    }
}

fn apply_user_region(stack: Option<(usize, usize)>) {
    if !mpu_present() {
        return;
    }
    // SAFETY: System Control Space registers, from handler mode.
    unsafe {
        if let Some((base, len)) = stack {
            MPU_RNR.write_volatile(1);
            MPU_RBAR.write_volatile(base as u32);
            MPU_RASR.write_volatile(RASR_XN | AP_FULL | ATTR_NORMAL | rasr_size(len) | RASR_EN);
        }
        let mut control: u32;
        asm!("mrs {}, CONTROL", out(reg) control);
        asm!("msr CONTROL, {}", "isb", in(reg) control | 1);
    }
}

/// # Safety
/// Exception handler; only the hardware may call it.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn SVCall() {
    // Save the caller's callee-saved registers (r4-r11) below its hardware frame, so a
    // syscall preserves the user's full register state, then let `bismuth_svc` pick the
    // frame to resume (the kernel trampoline, or the user with its r4-r11 restored).
    naked_asm!(
        "mrs r0, psp",
        "stmdb r0!, {{r4-r11}}", // save caller's r4-r11 below its hardware frame
        "mov r1, lr",            // arg2 = EXC_RETURN (and we restore it from the result)
        // MSP is 8-byte aligned on exception entry; we push nothing before the call, so
        // the branch keeps the AAPCS 8-byte alignment. `bl` saves the return address in
        // lr, which we then overwrite with the EXC_RETURN returned by `bismuth_svc`.
        "bl {svc}",              // returns u64: r0 = target psp, r1 = EXC_RETURN
        "mov lr, r1",
        "ldmia r0!, {{r4-r11}}", // restore the resumed context's r4-r11
        "msr psp, r0",
        "isb",
        "bx lr",
        svc = sym bismuth_svc,
    )
}

/// Fault entry shared by MemManage, BusFault and UsageFault.
extern "C" fn bismuth_fault(exc_return: u32) {
    let from_user = exc_return & 0b1100 == 0b1100
        && kernel::with(|k| {
            let t = k.cur();
            t.user && !t.in_syscall
        });
    // SAFETY: reading fault status/address registers and clearing CFSR (write-1-to-clear).
    let (cfsr, addr) = unsafe {
        let c = CFSR.read_volatile();
        CFSR.write_volatile(c);
        (c, MMFAR.read_volatile())
    };
    if !from_user {
        panic!("kernel fault: CFSR={cfsr:#010x} MMFAR={addr:#010x}");
    }
    // Sandbox violation: kill the domain. PendSV (pended by `kill`) runs right after
    // this handler, so the faulting instruction never executes again.
    let d = kernel::with(|k| crate::security::DomainId(k.cur().domain));
    let _ = crate::security::kill(d);
    crate::security::record_fault(d);
}

macro_rules! fault_handler {
    ($name:ident) => {
        /// # Safety
        /// Exception handler; only the hardware may call it.
        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            naked_asm!("mov r0, lr", "push {{r4, lr}}", "bl {f}", "pop {{r4, pc}}", f = sym bismuth_fault)
        }
    };
}

fault_handler!(MemoryManagement);
fault_handler!(BusFault);
fault_handler!(UsageFault);

/// # Safety
/// Exception handler; only the hardware may call it.
#[cfg(not(target_abi = "eabihf"))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn PendSV() {
    naked_asm!(
        "mrs r0, psp",
        "isb",
        "stmdb r0!, {{r4-r11, lr}}",
        "bl {switch}",
        "ldmia r0!, {{r4-r11, lr}}",
        "msr psp, r0",
        "isb",
        "bx lr",
        switch = sym bismuth_switch_context,
    )
}

/// # Safety
/// Exception handler; only the hardware may call it.
#[cfg(target_abi = "eabihf")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn PendSV() {
    naked_asm!(
        "mrs r0, psp",
        "isb",
        "tst lr, #0x10",
        "it eq",
        "vstmdbeq r0!, {{s16-s31}}",
        "stmdb r0!, {{r4-r11, lr}}",
        "bl {switch}",
        "ldmia r0!, {{r4-r11, lr}}",
        "tst lr, #0x10",
        "it eq",
        "vldmiaeq r0!, {{s16-s31}}",
        "msr psp, r0",
        "isb",
        "bx lr",
        switch = sym bismuth_switch_context,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn SysTick() {
    kernel::with(|k| k.tick());
    let d = PENDING_KILL.swap(0, Ordering::Relaxed);
    if d != 0 {
        let _ = crate::security::kill(crate::security::DomainId((d - 1) as u8));
    }
}

/// Scratch area the boot context "saves" into on the very first switch.
static mut BOOT_PSP: [u64; 16] = [0; 16];

/// Start the scheduler. `core_hz` is the SysTick input clock frequency.
pub(crate) fn start(core_hz: u32) -> ! {
    kernel::with(|k| {
        k.ensure_init();
        k.started = true;
    });
    // SAFETY: memory-mapped System Control Block / SysTick registers, configured before
    // interrupts are enabled for the scheduler.
    unsafe {
        // PendSV and SysTick at the lowest priority.
        SHPR3.write_volatile(SHPR3.read_volatile() | 0xFFFF_0000);
        SYST_RVR.write_volatile(core_hz / TICK_HZ - 1);
        SYST_CVR.write_volatile(0);
        SYST_CSR.write_volatile(0b111);
        CLOCKS_PER_TICK.store(core_hz / TICK_HZ, Ordering::Relaxed);
        let psp = (&raw mut BOOT_PSP as usize) + core::mem::size_of::<[u64; 16]>();
        asm!("msr psp, {}", "isb", in(reg) psp);
    }
    mpu_init();
    FIRST_SWITCH.store(true, Ordering::Relaxed);
    request_switch();
    // SAFETY: enabling interrupts lets PendSV switch to the first task.
    unsafe { asm!("cpsie i", "isb") };
    loop {
        // SAFETY: `wfi` only waits for an interrupt.
        unsafe { asm!("wfi") };
    }
}
