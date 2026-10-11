//! Interrupt-controller abstraction. Application-class ARM boards split two ways: a GICv2 /
//! GIC-400 (QEMU `virt`, Pi 4, Jetson) or the legacy **BCM2836/7 local controller** (Pi 2/3,
//! which present *no* GIC to the OS). The board selects one via `BoardMap.intc`; the rest of
//! the port talks only to this module, so the context-switch and timer paths are
//! controller-agnostic.
//!
//! Classification: L0 port · aarch64 interrupt controller · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering};

/// GICv2 / GIC-400.
pub const KIND_GIC: u32 = 0;
/// BCM2836/2837 local interrupt controller.
pub const KIND_BCM: u32 = 1;

static KIND: AtomicU32 = AtomicU32::new(KIND_GIC);

pub fn set_kind(k: u32) {
    KIND.store(k, Ordering::Relaxed);
}
fn kind() -> u32 {
    KIND.load(Ordering::Relaxed)
}

/// Enable the controller (distributor/CPU interface, or the local controller's IPI line).
pub fn init() {
    if kind() == KIND_BCM {
        super::bcm::init();
    } else {
        super::gic::init();
    }
}

/// Route the generic-timer interrupt to this core.
pub fn enable_timer() {
    if kind() == KIND_BCM {
        super::bcm::route_timer();
    } else {
        super::gic::enable(super::timer::TIMER_PPI);
    }
}

/// Acknowledge the pending interrupt; returns a normalised ID (timer = [`super::timer::TIMER_PPI`],
/// reschedule = 0, spurious ≥ 1020).
pub fn acknowledge() -> u32 {
    if kind() == KIND_BCM {
        super::bcm::acknowledge()
    } else {
        super::gic::acknowledge()
    }
}

/// Signal end-of-interrupt for `id`.
pub fn end(id: u32) {
    if kind() == KIND_BCM {
        super::bcm::end(id);
    } else {
        super::gic::end(id);
    }
}

/// Raise the self-targeted reschedule interrupt (GIC SGI, or a BCM mailbox IPI).
pub fn resched() {
    if kind() == KIND_BCM {
        super::bcm::resched();
    } else {
        super::gic::resched();
    }
}
