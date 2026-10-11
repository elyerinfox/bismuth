//! Tickless idle governor.
//!
//! When the scheduler has no ready work other than the idle task, the governor decides
//! *how deep* to let the CPU sleep until the next scheduled event. The policy is the one
//! Zephyr's "residency" governor and Linux's `menu` governor use, and that FreeRTOS's
//! `portSUPPRESS_TICKS_AND_SLEEP` encodes: **pick the deepest state whose entry is
//! worthwhile for the time available, and that no active latency constraint forbids.**
//!
//! Two inputs drive the choice: the ticks until the next timeout ([`Kernel::next_timeout`]
//! via the idle loop) and a QoS *constraint floor* — a driver mid-transfer, or a task with
//! a deadline, pins the floor at [`SleepDepth::Idle`] so the governor never enters a state
//! that would miss it (the Linux PM-QoS analog). The chosen depth bottoms out in an L0 port
//! function ([`port::idle`] or [`port::sleep_until`]); the governor itself reaches no further.
//!
//! Classification: L1 kernel · tickless idle governor · safe · always

use crate::config;
#[cfg(target_os = "none")]
use crate::arch::port;

use super::cell::IrqCell;

/// How deeply the CPU may idle. Ordered shallow → deep; a constraint names the deepest
/// state it still permits.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SleepDepth {
    /// Not idle — the idle loop should reschedule (work became ready).
    None,
    /// Halt the core with the periodic tick still running (WFI / HLT). Any interrupt wakes it.
    Idle,
    /// Halt the core with the periodic tick suppressed until the next timeout (tickless).
    Sleep,
}

struct Depth {
    state: SleepDepth,
    /// Ticks to be running again after waking from this state.
    exit_latency: u64,
    /// Ticks below which entering this state costs more than it saves.
    min_residency: u64,
}

/// The autonomous idle ladder, shallow → deep. `Idle` is always entrable (zero cost); the
/// governor never enters `DeepSleep`/system states itself — those are L3 `power`'s job.
const DEPTHS: [Depth; 2] = [
    Depth { state: SleepDepth::Idle, exit_latency: 0, min_residency: 0 },
    Depth {
        state: SleepDepth::Sleep,
        exit_latency: config::IDLE_SLEEP_LATENCY as u64,
        min_residency: config::IDLE_SLEEP_RESIDENCY as u64,
    },
];

/// Choose the idle depth for a gap of `time_to_event` ticks (None ⇒ nothing is waiting),
/// not deeper than `floor` permits. Pure: this is the whole policy, and it is what the
/// host tests exercise.
pub fn govern(time_to_event: Option<u64>, floor: SleepDepth) -> SleepDepth {
    let budget = time_to_event.unwrap_or(u64::MAX);
    // Too short to be worth suppressing and re-arming the tick: stay in plain Idle.
    if budget < config::IDLE_SLEEP_THRESHOLD as u64 {
        return SleepDepth::Idle;
    }
    DEPTHS
        .iter()
        .rev()
        .find(|d| d.state <= floor && d.exit_latency + d.min_residency <= budget)
        .map(|d| d.state)
        .unwrap_or(SleepDepth::Idle)
}

// --- QoS latency constraints (the PM-QoS analog) ---

/// Active constraints: each slot, when `Some`, forbids idling deeper than its value.
static CONSTRAINTS: IrqCell<[Option<SleepDepth>; config::IDLE_MAX_CONSTRAINTS]> =
    IrqCell::new([None; config::IDLE_MAX_CONSTRAINTS]);

/// A held latency constraint. While it lives, the governor will not idle deeper than the
/// requested `max`. Dropping it releases the constraint (RAII, like driver power gates).
#[must_use = "the constraint is released as soon as this guard is dropped"]
pub struct IdleConstraint {
    slot: usize,
}

impl Drop for IdleConstraint {
    fn drop(&mut self) {
        CONSTRAINTS.lock(|c| c[self.slot] = None);
    }
}

/// Forbid the governor from idling deeper than `max` until the returned guard is dropped.
/// Returns `None` if all constraint slots are in use (the caller then conservatively
/// assumes the shallowest safe behaviour by other means).
pub fn constrain(max: SleepDepth) -> Option<IdleConstraint> {
    CONSTRAINTS.lock(|c| {
        for (i, slot) in c.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(max);
                return Some(IdleConstraint { slot: i });
            }
        }
        None
    })
}

/// The deepest state all active constraints currently permit (the most restrictive wins).
/// With no constraints the governor may go as deep as its autonomous ladder allows.
pub fn constraint_floor() -> SleepDepth {
    CONSTRAINTS.lock(|c| c.iter().flatten().copied().min().unwrap_or(SleepDepth::Sleep))
}

/// The governed idle step, run by the idle task on real hardware. Decides the depth under
/// the port's critical section (so a wake that races the decision is not lost — a pending
/// interrupt makes `wfi`/`hlt` fall straight through) and enters it.
#[cfg(target_os = "none")]
pub(crate) fn govern_and_sleep() {
    let floor = constraint_floor();
    let (depth, deadline) = super::with(|k| {
        if k.has_ready_work() {
            return (SleepDepth::None, None);
        }
        let next = k.next_timeout();
        let budget = next.map(|t| t.saturating_sub(k.tick));
        (govern(budget, floor), next)
    });
    match depth {
        SleepDepth::None => {}       // someone is ready; return and let the scheduler pick it
        SleepDepth::Idle => port::idle(),
        SleepDepth::Sleep => port::sleep_until(deadline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The constraint tests share the global `CONSTRAINTS` static, so they must not run
    // concurrently with each other.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn picks_deepest_state_that_fits_the_budget() {
        // Nothing waiting ⇒ deepest autonomous state.
        assert_eq!(govern(None, SleepDepth::Sleep), SleepDepth::Sleep);
        // A long gap ⇒ Sleep; a gap below the threshold ⇒ Idle.
        assert_eq!(govern(Some(1_000), SleepDepth::Sleep), SleepDepth::Sleep);
        assert_eq!(govern(Some(1), SleepDepth::Sleep), SleepDepth::Idle);
        // Exactly at latency+residency boundary (1+2 = 3) fits; just under does not.
        assert_eq!(govern(Some(3), SleepDepth::Sleep), SleepDepth::Sleep);
        assert_eq!(govern(Some(2), SleepDepth::Sleep), SleepDepth::Idle);
    }

    #[test]
    fn constraint_floor_vetoes_deeper_states() {
        // A floor of Idle forbids Sleep even for a huge budget.
        assert_eq!(govern(Some(u64::MAX), SleepDepth::Idle), SleepDepth::Idle);
        assert_eq!(govern(None, SleepDepth::Idle), SleepDepth::Idle);
    }

    #[test]
    fn constraints_apply_while_held_and_release_on_drop() {
        let _s = serial();
        assert_eq!(constraint_floor(), SleepDepth::Sleep); // default: no constraints
        {
            let _c = constrain(SleepDepth::Idle).unwrap();
            assert_eq!(constraint_floor(), SleepDepth::Idle);
            {
                let _c2 = constrain(SleepDepth::Sleep).unwrap();
                // Most restrictive wins: Idle (from _c) still governs.
                assert_eq!(constraint_floor(), SleepDepth::Idle);
            }
            assert_eq!(constraint_floor(), SleepDepth::Idle);
        }
        assert_eq!(constraint_floor(), SleepDepth::Sleep); // all released
    }

    #[test]
    fn constraint_slots_are_bounded() {
        let _s = serial();
        let mut held = heapless_vec();
        for _ in 0..config::IDLE_MAX_CONSTRAINTS {
            held.push(constrain(SleepDepth::Idle).expect("slot available"));
        }
        assert!(constrain(SleepDepth::Idle).is_none(), "exhausted slots refuse more");
        drop(held);
        assert!(constrain(SleepDepth::Idle).is_some(), "slots freed after drop");
    }

    // The test binary links `std`; a plain Vec keeps the guards alive together.
    fn heapless_vec() -> std::vec::Vec<IdleConstraint> {
        std::vec::Vec::new()
    }
}
