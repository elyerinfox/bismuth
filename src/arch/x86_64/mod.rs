//! x86-64 port (long mode), for the PC / thin-client target.
//!
//! This is the second real bare-metal port after Cortex-M. The portable kernel above the
//! six-function port contract is reused unchanged; this module provides that contract plus
//! platform bring-up. It is built in stages:
//!
//! * **Stage 1 (this file's current form):** the port surface compiles for
//!   `x86_64-unknown-none` and early 16550 serial works, so a board can boot to a banner.
//!   Critical sections mask interrupts via `RFLAGS.IF` (`cli`/`sti`); `in_isr` is a nesting
//!   counter; `idle` is `hlt`; `init_task` lays out the initial switch frame.
//! * **Stage 2 (next):** GDT/IDT/TSS, paging, the Local APIC timer tick, and the actual
//!   context switch (a timer/IPI-driven save-restore of callee-saved registers + `rsp`,
//!   the PendSV analog), after which the scheduler preempts for real.
//! * **Stage 3:** ring-3 user tasks via paging + a `SYSCALL`/`int 0x80` gate (the SVC
//!   analog), the `#PF`-kills-the-domain sandbox, then virtio drivers.
//!
//! Part of the trusted computing base: inline assembly, port I/O and (later) system tables.
//!
//! Classification: L0 port · x86-64 port · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::kernel::{self, Kernel};

pub mod gdt;
pub mod idt;
pub mod paging;
pub mod pci;
pub mod pic;
pub mod sw;

/// Nestable critical section via `RFLAGS.IF`. On the outermost exit (interrupts were on),
/// a context switch requested while inside the section is serviced now — the x86 analog of
/// PendSV firing when the critical section ends — by a software yield (`int 0x81`), before
/// interrupts are re-enabled.
#[inline]
pub fn critical<R>(f: impl FnOnce() -> R) -> R {
    let flags: u64;
    // SAFETY: save RFLAGS and mask interrupts; no memory operands, but we touch the stack.
    unsafe { asm!("pushfq", "pop {f}", "cli", f = out(reg) flags, options(nomem)) };
    let r = f();
    if flags & (1 << 9) != 0 {
        if SWITCH_PENDING.load(Ordering::Relaxed) && ISR_DEPTH.load(Ordering::Relaxed) == 0 {
            SWITCH_PENDING.store(false, Ordering::Relaxed);
            // SAFETY: triggers the yield vector; its handler switches tasks and `iretq`s
            // back here (with interrupts still masked), after which we re-enable them.
            unsafe { asm!("int 0x81", options(nomem)) };
        }
        // SAFETY: re-enabling interrupts restores the entry state.
        unsafe { asm!("sti", options(nomem, nostack, preserves_flags)) };
    }
    r
}

pub(super) static SWITCH_PENDING: AtomicBool = AtomicBool::new(false);
pub(super) static ISR_DEPTH: AtomicUsize = AtomicUsize::new(0);
/// Nonzero while a tickless PIT one-shot is armed: the number of kernel ticks it spans (the
/// timer ISR uses it to restore the periodic cadence and reconcile the clock).
pub(super) static NAP_TICKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Request a context switch; serviced by the timer/IPI path (stage 2).
#[inline]
pub fn request_switch() {
    SWITCH_PENDING.store(true, Ordering::Relaxed);
}

/// Whether we are in interrupt context (x86 has no IPSR; we count nesting).
#[inline]
pub fn in_isr() -> bool {
    ISR_DEPTH.load(Ordering::Relaxed) > 0
}

/// Idle: wait for the next interrupt.
pub(crate) fn idle() {
    // SAFETY: `hlt` only waits for an interrupt (interrupts must be enabled by the caller).
    unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
}

/// Tickless light sleep: reprogram the 8254 PIT as a one-shot at the next event and `hlt`,
/// suppressing the intermediate periodic ticks. Only IRQ0 is unmasked, so the one-shot is the
/// only thing that wakes the core; its ISR ([`sw::timer_entry`]) restores the periodic cadence
/// and reconciles the clock by the nap length (`NAP_TICKS`). With no deadline, a plain `hlt`.
pub(crate) fn sleep_until(deadline: Option<u64>) {
    match deadline {
        Some(d) => {
            let now = kernel::time::ticks();
            if d <= now {
                return;
            }
            let naps = pic::arm_oneshot(d - now);
            NAP_TICKS.store(naps, Ordering::Relaxed);
            // SAFETY: `hlt` waits for the one-shot IRQ (interrupts are enabled in the idle task).
            unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
        }
        // SAFETY: `hlt` only waits for an interrupt.
        None => unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) },
    }
}

/// Lay out a fresh task's initial context-switch frame (see [`sw::init_task`]).
pub(crate) fn init_task(k: &mut Kernel, i: u8) {
    sw::init_task(k, i);
}

/// The kernel code/data segment selectors (from our own GDT) for building context-switch
/// iretq frames.
pub(super) fn selectors() -> (u16, u16) {
    (gdt::KERNEL_CODE, gdt::KERNEL_DATA)
}

pub(super) extern "C" fn task_trampoline() -> ! {
    // The switch set `current` before returning into us; run that task's entry.
    let i = kernel::with(|k| k.current);
    kernel::task::run_entry(i);
    exit_current(0)
}

pub(crate) fn exit_current(code: usize) -> ! {
    kernel::with(|k| kernel::task::finish_current(k, code));
    loop {
        idle();
    }
}

/// User (ring-3) tasks are supported once the paging isolation is set up (`init_memory`),
/// which marks kernel data supervisor-only and opens the kernel text + each task's stack.
pub fn supports_user_tasks() -> bool {
    paging::ready()
}

/// Loading Linux images is not supported on this port (aarch64 EL0 only); fails closed.
#[cfg(feature = "linux-abi")]
pub fn open_linux_image(_code: (u64, u64), _stack: (u64, u64), _domain: u8) -> bool {
    false
}

/// Resetting a loaded image's pages is a no-op off the aarch64 port.
#[cfg(feature = "linux-abi")]
pub fn linux_reset_image(_addr: u64, _len: u64) {}

/// Whether an unprivileged task may have the kernel read `[addr, end)` as read-only data: the
/// kernel's User-mapped, non-writable pages (text + rodata). Writable kernel state (supervisor)
/// and task stacks (writable) are excluded — the latter are checked separately as "own stack".
pub(crate) fn user_readable(addr: usize, end: usize) -> bool {
    paging::is_user_ro(addr, end)
}

/// Whether the caller is running in ring 3 (user mode): the current code selector's RPL is 3.
fn in_ring3() -> bool {
    let cs: u16;
    // SAFETY: reading CS is side-effect free.
    unsafe { asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)) };
    cs & 3 == 3
}

/// System call from a task. From ring 3 we trap into the kernel via `int 0x80` (the gate
/// switches to the task's kernel stack and the handler dispatches there); privileged kernel
/// tasks dispatch directly.
pub(crate) fn syscall(n: u32, args: [usize; 4]) -> isize {
    if in_ring3() {
        let r: isize;
        // SAFETY: trap into the kernel. Our handler preserves every register except RAX (the
        // result), so from here only RAX changes; arguments go in the System V argument
        // registers. The handler may touch memory through the pointer arguments.
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") n as usize => r,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("rcx") args[3],
            )
        };
        r
    } else {
        crate::security::syscall::dispatch(n, args)
    }
}

/// Start the scheduler. `core_hz` is the timer input frequency.
///
/// Stage 1: platform bring-up (GDT/IDT/paging/APIC + the first context switch) is not yet
/// wired, so this enables interrupts and idles — a board boots to its serial banner and the
/// idle loop. Stage 2 replaces the body with the real first-switch sequence.
pub(crate) fn start(_core_hz: u32) -> ! {
    kernel::with(|k| {
        k.ensure_init();
        k.started = true;
    });
    // Install the IDT and start the PIT tick, then enable interrupts. (Context switching on
    // the tick is added in the next revision; for now the timer heartbeat validates the
    // interrupt path.)
    gdt::init();
    idt::init();
    pic::init(crate::config::TICK_HZ);
    sw::arm_first_switch();
    // SAFETY: the IDT is installed. Enabling interrupts lets the first PIT tick perform the
    // first context switch into the highest-priority ready task; this `start` context is
    // then abandoned (the loop only runs until that first tick).
    unsafe { asm!("sti", options(nomem, nostack, preserves_flags)) };
    loop {
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}

/// Set up ring-3 isolation from the bootloader's hand-off: record the physical-memory map
/// offset and open the kernel's code + read-only data to unprivileged tasks (writable kernel
/// state stays supervisor-only). The board calls this once, before `bismuth::start`, with
/// `boot_info.physical_memory_offset`, `boot_info.kernel_image_offset` and `kernel_len`.
/// Without it, `supports_user_tasks()` stays effectively unusable (paging edits fail closed).
pub fn init_memory(physical_memory_offset: u64, kernel_image_offset: u64, kernel_len: u64) {
    paging::init(physical_memory_offset);
    paging::open_kernel_text(kernel_image_offset, kernel_len);
}

/// Halt the machine via QEMU's `isa-debug-exit` device (port `0xF4`); on real hardware this
/// just writes a dead port and then parks the CPU. Used by the demo board to end the run.
pub fn debug_exit(code: u32) -> ! {
    // SAFETY: a single out to the debug-exit I/O port.
    unsafe { asm!("out dx, eax", in("dx") 0xF4u16, in("eax") code, options(nomem, nostack, preserves_flags)) };
    loop {
        idle();
    }
}

// ----- early 16550 UART (COM1) for the boot console -----

const COM1: u16 = 0x3F8;

pub(super) fn outb(port: u16, val: u8) {
    // SAFETY: writing a byte to an I/O port has no memory-safety implications.
    unsafe { asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags)) };
}

pub(super) fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: reading an I/O port byte has no memory-safety implications.
    unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
    v
}

/// Initialise COM1 at 115200 8N1 and route the kernel console to it.
pub fn init_console() {
    outb(COM1 + 1, 0x00); // disable interrupts
    outb(COM1 + 3, 0x80); // DLAB
    outb(COM1, 0x01); // divisor 1 => 115200
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03); // 8N1
    outb(COM1 + 2, 0xC7); // enable+clear FIFO, 14-byte threshold
    outb(COM1 + 4, 0x0B); // IRQs off, RTS/DSR set
    crate::console::set_sink(console_sink);
}

/// Console sink: write a string to COM1 (`\n` becomes `\r\n`).
pub fn console_sink(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            serial_byte(b'\r');
        }
        serial_byte(b);
    }
}

fn serial_byte(b: u8) {
    // Wait for the transmit-holding-register-empty bit.
    while inb(COM1 + 5) & 0x20 == 0 {}
    outb(COM1, b);
}
