//! The legacy 8259 PIC (remapped off the CPU exception vectors) and the 8254 PIT as the
//! periodic tick source — the directest analogue of the Cortex-M SysTick. Hand-rolled port
//! I/O on stable; the Local APIC timer is a later optimization.
//!
//! Classification: L0 port · x86-64 PIC/PIT · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering};

use super::{inb, outb};

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const PIT_FREQ: u32 = 1_193_182;
/// PIT counts per kernel tick (the periodic divisor), recorded at [`init`] for the tickless path.
static DIVISOR: AtomicU32 = AtomicU32::new(0);

/// Remap the PICs to vectors 0x20..0x2F, mask everything except IRQ0 (the timer), and
/// program the PIT to fire at `hz`.
pub fn init(hz: u32) {
    // Standard 8259 init control-word sequence to the fixed PIC ports (port I/O is wrapped
    // safely by `outb`/`inb`, whose construction is the sole unsafe assertion).
    let _mask = (inb(PIC1_DATA), inb(PIC2_DATA));
    outb(PIC1_CMD, 0x11); // ICW1: init + expect ICW4
    outb(PIC2_CMD, 0x11);
    outb(PIC1_DATA, 0x20); // ICW2: master vector offset 0x20
    outb(PIC2_DATA, 0x28); // ICW2: slave vector offset 0x28
    outb(PIC1_DATA, 0x04); // ICW3: slave on IRQ2
    outb(PIC2_DATA, 0x02);
    outb(PIC1_DATA, 0x01); // ICW4: 8086 mode
    outb(PIC2_DATA, 0x01);
    // Unmask only IRQ0 on the master; mask the slave entirely.
    outb(PIC1_DATA, 0xFE);
    outb(PIC2_DATA, 0xFF);
    program_pit(hz);
}

fn program_pit(hz: u32) {
    let divisor = (PIT_FREQ / hz.max(1)).clamp(1, 65_535);
    DIVISOR.store(divisor, Ordering::Relaxed);
    outb(0x43, 0x36); // channel 0, lobyte/hibyte, mode 3 (square wave)
    outb(0x40, (divisor & 0xFF) as u8);
    outb(0x40, (divisor >> 8) as u8);
}

/// Tickless: program the PIT as a one-shot (mode 0) that fires once after `naps` kernel ticks,
/// suppressing the intermediate periodic ticks. Returns the number of ticks actually armed
/// (clamped so the 16-bit count does not overflow); the timer ISR restores the periodic cadence
/// and reconciles the clock by this amount. Only IRQ0 is unmasked, so nothing else wakes `hlt`.
pub fn arm_oneshot(naps: u64) -> u32 {
    let divisor = DIVISOR.load(Ordering::Relaxed).max(1);
    let max_naps = (65_535 / divisor).max(1) as u64;
    let naps = naps.clamp(1, max_naps) as u32;
    let count = (naps * divisor).clamp(1, 65_535) as u16;
    outb(0x43, 0x30); // channel 0, lobyte/hibyte, mode 0 (interrupt on terminal count)
    outb(0x40, (count & 0xFF) as u8);
    outb(0x40, (count >> 8) as u8);
    naps
}

/// Restore the periodic (mode 3) tick after a one-shot nap.
pub fn restore_periodic() {
    let divisor = DIVISOR.load(Ordering::Relaxed).max(1) as u16;
    outb(0x43, 0x36);
    outb(0x40, (divisor & 0xFF) as u8);
    outb(0x40, (divisor >> 8) as u8);
}

/// Signal end-of-interrupt to the master PIC (after servicing IRQ0).
pub fn eoi() {
    outb(PIC1_CMD, 0x20);
}
