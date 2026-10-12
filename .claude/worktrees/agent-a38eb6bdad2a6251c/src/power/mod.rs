//! System power-state orchestration: the ordered quiesce/restore sequence that moves the
//! whole system between run and low-power states, on top of the existing per-device
//! [`PowerState`]/`set_power` path and the scheduler's idle hooks.
//!
//! This layer owns the *ordering and the cross-subsystem hooks*; the actual low-power CPU
//! or ACPI instruction is the port's job, invoked by the platform after [`suspend_to`]
//! returns. The sequence (research `docs/research/power-management.md` §4.3):
//!
//! 1. zeroize the plaintext hot-file residency cache (before RAM may be lost);
//! 2. suspend drivers **leaf → bus** (reverse registration order), tolerating devices that
//!    do not implement the target state;
//! 3. record the new system state.
//!
//! [`resume`] reverses it: bring drivers up **bus → leaf** (registration order), then run.
//! Future hook points (net quiesce, TPM-sealed retained-RAM) slot in at steps 1–2 as those
//! subsystems land.
//!
//! Only a trusted domain may change the system power state.
//!
//! Classification: L3 services · power management · safe · power

use crate::Error;
use crate::config::MAX_DEVICES;
use crate::driver::{Device, PowerState};
use crate::kernel::cell::IrqCell;

/// System-wide power state (distinct from, and layered above, per-device [`PowerState`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SystemPower {
    /// Fully running.
    Run,
    /// Shallow CPU idle (clock-gated), resumes instantly.
    Idle,
    /// Light sleep; peripherals clock-gated.
    Sleep,
    /// Deep sleep; peripherals suspended, context retained (ACPI S3-like).
    DeepSleep,
    /// Standby.
    Standby,
    /// Suspend-to-disk (ACPI S4-like).
    Hibernate,
    /// Soft off (ACPI S5-like).
    Off,
}

impl SystemPower {
    /// The per-device power state drivers are moved to for this system state.
    fn device_state(self) -> PowerState {
        match self {
            SystemPower::Run => PowerState::On,
            SystemPower::Idle | SystemPower::Sleep => PowerState::Idle,
            SystemPower::DeepSleep | SystemPower::Standby => PowerState::Suspended,
            SystemPower::Hibernate | SystemPower::Off => PowerState::Off,
        }
    }
}

static STATE: IrqCell<SystemPower> = IrqCell::new(SystemPower::Run);

/// The current system power state.
pub fn current() -> SystemPower {
    STATE.lock(|s| *s)
}

/// Quiesce the system toward `target` (drivers suspended leaf→bus, caches flushed). Returns
/// once the system is ready for the platform to enter the low-power CPU/ACPI state; call
/// [`resume`] on wake. Trusted callers only.
pub fn suspend_to(target: SystemPower) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    if target == SystemPower::Run {
        return resume();
    }
    // 1. Drop plaintext hot-file residency before RAM may be lost / the device left idle.
    #[cfg(feature = "fs")]
    crate::fs::resident::suspend_flush();
    // 2. Suspend devices leaf → bus (reverse registration order); best-effort per device.
    let ds = target.device_state();
    for i in (0..MAX_DEVICES).rev() {
        if let Some(dev) = Device::from_index(i) {
            let _ = dev.set_power(ds); // a device that cannot enter `ds` simply stays up
        }
    }
    STATE.lock(|s| *s = target);
    Ok(())
}

/// Resume from a low-power state: bring devices up bus → leaf, then mark the system running.
pub fn resume() -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    for i in 0..MAX_DEVICES {
        if let Some(dev) = Device::from_index(i) {
            let _ = dev.set_power(PowerState::On);
        }
    }
    STATE.lock(|s| *s = SystemPower::Run);
    Ok(())
}

/// Reset to `Run` (host simulator, between runs).
#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    STATE.lock(|s| *s = SystemPower::Run);
}
