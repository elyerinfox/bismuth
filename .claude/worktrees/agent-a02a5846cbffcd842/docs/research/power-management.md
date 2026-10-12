# Bismuth Power Management: Sleep States and ACPI Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: adding **sleep / power states / ACPI** to Bismuth — a safe-Rust, `no_std`, no-heap RTOS — across both target families: the **Cortex-M MCU ports** (WFI/WFE, SLEEPDEEP, vendor STOP/STANDBY, RTC wake) and the **x86-64 thin-client port** being designed in `x86-port.md` (ACPI S-states, C-states, HLT/MWAIT). Deliver a generic power-state model, a tickless / low-power idle governor on the existing scheduler, a driver suspend/resume contract reusing the existing `PowerState`/`set_power` path, a **minimal fixed-feature ACPI** subset (no general AML interpreter), the exact ordered suspend/resume sequence (the centerpiece), and a host-simulated, hardware-free test story. QEMU-first on x86; vendor STOP modes stay behind a board hook on MCUs.
>
> Current Bismuth baseline (read from the tree): the portable kernel talks to the CPU through six functions (`src/arch/mod.rs`) — `critical`, `request_switch`, `in_isr`, `init_task`, `exit_current`, `idle` — plus a per-port `start`. `idle()` is **already** the low-power seam: Cortex-M runs `wfi` (`arch/cortex_m.rs`), the host simulator jumps virtual time to the next timeout (`arch/host.rs`). The kernel **already** has the tickless primitives — `next_timeout()`, `advance_to()`, `has_ready_work()`, `can_block()` and a maintained `next_wake` field (`kernel/mod.rs`) — but three of them are gated `#[cfg(not(target_os = "none"))]`, i.e. they exist for the simulator only. Devices **already** carry a `PowerState { On, Idle, Suspended, Off }` and a rights-checked `Device::set_power` that routes `Op::Power` down the middleware chain into `Driver::power`, and the registry records each device's current state (`src/driver/mod.rs`). A `PowerGate` middleware already powers a device on demand and suspends it after an idle timeout (`src/driver/middleware.rs`). The idle task already calls a pluggable `IDLE_HOOK` before sleeping (`kernel/task::set_idle_hook`). The crate is `#![deny(unsafe_code)]` with a 5-module TCB; `Rights::POWER` already gates `Op::Power` per handle. This design **extends** all of that; it does not reinvent it.

---

## 0. TL;DR

- **The seams already exist; this is mostly wiring, not new primitives.** `PowerState`, `set_power`, the `Driver::power` hook, `PowerGate`, `idle()`, `set_idle_hook`, `next_timeout`/`advance_to`/`next_wake` and `Rights::POWER` are all in the tree. The work is (1) a **tickless idle governor** on top of `next_timeout`, (2) a **system power service** that orchestrates the existing `set_power` path plus the net/fs/retained-RAM hooks in a defined order, and (3) the **port-level deep-sleep instructions** (Cortex-M SLEEPDEEP, x86 ACPI S-state register writes). Almost all of it is 100% safe Rust; only the final CPU instructions and ACPI table/register access touch the TCB.
- **Two power models, one ladder.** A single system state enum `SystemPower { Run, Idle, Sleep, DeepSleep, Standby, Hibernate, Off }` maps onto *both* targets: Cortex-M (WFI-idle → tickless light sleep → vendor STOP → vendor STANDBY → freeze-to-flash → shutdown) and x86-64 ACPI (C1 → C1/C2 tickless → **S3** suspend-to-RAM → S3/S4 → **S4** hibernate → **S5** soft-off). Honest feasibility per target is a table, not a promise (§1.3): C-states and S3/S5 are feasible on x86 QEMU-first; MCU STOP/STANDBY are vendor-specific and live behind a board hook.
- **Two layers, cleanly split.** CPU-only idle (Run↔Idle↔Sleep: suppress the tick, halt the core, wake on the next timeout or IRQ) is **L1 `kernel::idle`** — it needs only the scheduler + the port and is where the tickless logic belongs. System transitions (DeepSleep and below: quiesce drivers, net, caches, seal retained RAM) are **L3 `power`** — they orchestrate L2 drivers and L3 services and must sit above them. The L1 governor and the L3 service both bottom out in **L0 port** functions; neither reaches sideways across a layer boundary it may not.
- **The idle governor is residency-based, à la Zephyr/Linux `menu`.** At idle, read the time to the next event from `next_timeout()`; pick the **deepest state whose exit-latency + minimum-residency fits that interval** and whose armed wake sources can still service every pending timeout. Short gaps stay in `Idle` (plain WFI/HLT, tick running); long gaps suppress the tick and enter `Sleep`/`DeepSleep`. This is exactly FreeRTOS's `portSUPPRESS_TICKS_AND_SLEEP(xExpectedIdleTime)` trigger[^frtos] and the Linux `menu` governor's "deepest state that fits before the next timer"[^menu], expressed over Bismuth's existing `next_wake`.
- **ACPI: implement the fixed-feature subset by hand; defer the AML interpreter, explicitly.** A general AML interpreter is huge, `alloc`-hungry and has a soundness history (the rust-osdev [`aml`][aml] crate is self-described as "far from feature-complete"[^acpi-crate]) — it is the single biggest temptation to grow the TCB and we decline it. Instead: parse the **static** tables by hand (RSDP → XSDT → **FADT** → **FACS**) for the PM1a/PM1b control + event blocks, SMI_CMD/ACPI_ENABLE, the GPE blocks, the reset register, and the FACS firmware-waking-vector for S3, and recover the per-state `SLP_TYP` values with a **bounded `_Sx`-package byte-scan of the DSDT** (the well-known iPXE/Unikraft technique[^ipxe][^unikraft]), *not* an interpreter. Evaluate the [`rsdp`][rsdp] + [`acpi`][acpi] crates for the table discovery (both usable `no_std`; `acpi` needs `alloc` disabled[^acpi-crate]) and hand-roll the ~6 fixed-feature register pokes. This keeps new x86 unsafe inside the already-TCB `arch/x86_64/` tree.
- **Reuse `set_power`; do not invent `suspend`/`resume` hooks.** Driver suspend is `dev.set_power(PowerState::Suspended)`, resume is `dev.set_power(previous)`, both through the existing rights-checked middleware chain that already records state and already lets `PowerGate` observe transitions. **Ordering** is the new rule: suspend **leaf→bus** (reverse registration order), resume **bus→leaf** (forward order), since boards register a bus before the devices behind it (natural probe order). An optional explicit `power_order: u8` on `DeviceDesc` is the escape hatch; registration order is the default and needs no new metadata.
- **The ordered sequence is the deliverable's centerpiece (§4.3).** Quiesce tasks → `net::quiesce()` → zeroize the hot-file residency slabs (filesystems §4.2) → suspend drivers leaf→bus → `trust::retained::pre_sleep()` AEAD-seal the retained region (trusted-platform §6b, the **last** software step before RAM is lost) → stop the tick → enter the low-power instruction. Resume is the exact reverse, with **tick catch-up** from an always-on counter (`advance_to`) before drivers come back and before `trust::retained::post_resume()` re-derives the key and decrypts.
- **100% host-testable with no hardware.** A `SimPowerController` (same shape as the trusted-platform doc's `SoftTpm` and the existing `SimSensor`/`SimDisplay`) records the ordered transition callbacks; the host port's `sleep()` just *jumps virtual time* exactly as `host::idle()` already does, and a test injects the `WokenBy` (RTC vs power-button). Assertions: drivers suspended in reverse / resumed in forward order, idempotency, the retained-RAM region is ciphertext after `pre_sleep`, residency slabs are zeroized, and timeouts that elapsed during the simulated sleep fire on resume. Deterministic, instant, no QEMU.
- **Suspending the system is a privileged operation.** A system transition (`DeepSleep`/`Hibernate`/`Off`/reboot) is gated on `security::current_is_trusted()`, consistent with `driver::register`/`security::seal`; per-device `set_power` from an isolated domain already needs `Rights::POWER`. A **power/watchdog supervisor** is a natural `container.rs` role (the `OnFault`/`supervisor` fields are adjacent). `Off`/`Hibernate` must zeroize domain secrets on the way down. No new `Error` variant is needed (`NotReady`, `Busy`, `Unsupported`, `Integrity`, `PermissionDenied` cover it); a new right/manifest flag is optional and deferred.

---

## 1. Problem statement: what exists, what is missing, what is feasible

### 1.1 What exists today (read from the tree)

Bismuth is further along on power than a greenfield design would be. Concretely:

| mechanism | where | what it does today |
|---|---|---|
| `enum PowerState { On, Idle, Suspended, Off }` | `driver/mod.rs:89` | per-device states; `from_raw` for the syscall path |
| `Device::set_power(state)` | `driver/mod.rs:621` | routes `Op::Power(state)` down the middleware chain; on `Ok` **records** the new state in the registry entry |
| `Driver::power(ctx, state)` | `driver/mod.rs:249` | the driver hook; default impl accepts `On`, rejects the rest with `Unsupported` |
| `PowerGate` middleware | `driver/middleware.rs:338` | powers a device on first use, suspends it after `idle_ticks` via a software `Timer`; counts wakeups |
| `Rights::POWER` | `security/mod.rs:71` | per-handle right that `Op::Power` requires (`rights_for`) |
| `port::idle()` | `arch/cortex_m.rs:131`, `arch/host.rs:246` | the CPU low-power seam: `wfi` on ARM; **virtual-time jump** on host |
| `set_idle_hook(fn())` | `kernel/task.rs:551` | a function the idle task runs *before* `port::idle()` — the existing governor insertion point |
| `next_timeout()`, `advance_to()`, `has_ready_work()`, `can_block()`, `next_wake` | `kernel/mod.rs` | the tickless primitives: earliest pending wake, jump-the-clock, is-there-work, may-I-block |
| `Kernel::tick` / `TICK_HZ` / `Timeout` / software `Timer` | `kernel/time.rs`, `kernel/timer.rs` | the tick and timeout machinery any sleep state must reconcile with |

So the device-facing vocabulary (`PowerState`, `set_power`, `Driver::power`), the policy example (`PowerGate`), the authority model (`Rights::POWER`), and the CPU seam (`idle()`) all already exist. What is genuinely missing is the *coordination*.

### 1.2 The gap

1. **No system-wide power state.** `PowerState` is strictly per-device; nothing represents "the whole system is going to sleep," and nothing sequences the drivers, the net task, the caches and the retained-RAM seal.
2. **No real tickless idle.** `idle()` on Cortex-M is a bare `wfi` *with SysTick still running* — the core wakes every tick even when the next task is 500 ms away, burning the tick interrupt's wake energy the whole time. The tickless primitives exist but (a) three of them (`next_timeout`, `advance_to`, `has_ready_work`) are `#[cfg(not(target_os = "none"))]` — **simulator only** — and (b) nothing on the MCU reprograms the tick to the next timeout and catches time up on wake.
3. **No deep sleep.** Nothing sets Cortex-M `SCB.SCR.SLEEPDEEP`, enters a vendor STOP/STANDBY mode, or writes an ACPI S-state. There is no wake-source registry and no resume path.
4. **No ACPI at all.** The x86-port design (`x86-port.md`) deliberately deferred ACPI ("hardcode QEMU's APIC addresses… real-hardware ACPI parsing is a later step," §2 and §11). This document is that later step for the *power* subset: shutdown/reboot and S3/S5.
5. **No security/crypto seam for sleep.** The trusted-platform doc (§6b) and the filesystems doc (§4.2) each define a hook that *must* fire during suspend (AEAD-seal retained RAM; zeroize plaintext residency slabs) — but nothing calls them because there is no suspend sequence to call them from. This document defines *where* in the sequence they fire; the crypto and cache internals stay those docs' concern.

### 1.3 Honest per-target feasibility

Be concrete about what each platform can actually do. The generic model (§2) is the same; the realizable depth differs.

| system state | Cortex-M (MCU) | x86-64 (thin client, QEMU-first) | feasible first cut? |
|---|---|---|---|
| **Run** (G0/S0 C0) | task executing | task executing | yes, trivially |
| **Idle** | `wfi`, SysTick running (C1-equivalent) | `hlt` (C1), APIC timer running | **yes** — exists today as `idle()` |
| **Sleep** (light, tickless) | `wfi` with SysTick **suppressed**, reprogrammed to next timeout; PLL may idle | `hlt`/`mwait` (C1/C2) with APIC timer one-shot at next timeout | **yes** — pure kernel + port, no vendor code |
| **DeepSleep** | vendor **STOP** mode (RAM retained, clocks off, wake on RTC/EXTI) — *vendor-specific, behind a board hook* | **ACPI S3** suspend-to-RAM (FACS waking vector, GPE/SCI wake) | MCU: **per-vendor**; x86: **yes** (QEMU S3) |
| **Standby** | vendor **STANDBY** (deeper; most RAM lost, a small retained/backup region survives) | folds into S3/S4 on PC | MCU: **per-vendor**; x86: subsumed |
| **Hibernate** | freeze a bounded image to flash/littlefs, then shutdown | **ACPI S4** suspend-to-disk | **stretch** (bounded image only; §4.5) |
| **Off** | SoC shutdown / PMIC poweroff GPIO / `SYSRESETREQ`-to-bootloader | **ACPI S5** soft-off (`PM1a_CNT = SLP_TYPa\|SLP_EN`) | **yes** |

The load-bearing honesty: **MCU STOP/STANDBY entry and wake are vendor register sequences** (STM32 `PWR`/`RCC`, nRF `POWER`, …), not architectural. The *architectural* part (SLEEPDEEP in `SCB.SCR`, `wfi`) is generic and lives in `arch/cortex_m.rs`; the vendor part lives behind a board-provided hook (§6). On x86, ACPI gives an architectural S-state mechanism, so DeepSleep/Off are feasible generically from the FADT — which is exactly why ACPI is worth the effort.

---

## 2. The generic power-state model

### 2.1 The system state enum (L3)

A new system-level enum, distinct from (and layered above) the per-device `PowerState`:

```rust
// src/power/mod.rs  —  L3 services · power: system suspend/resume · safe · always
/// System-wide power state. Orthogonal to per-device `driver::PowerState`:
/// a driver may be `Suspended` while the system is `Run` (that is `PowerGate`),
/// but when the *system* enters `DeepSleep` every device is driven to its
/// suspend state in order (§4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SystemPower {
    /// A task is executing (ACPI G0/S0 C0).
    Run,
    /// Core halted, tick running, instant wake (WFI / HLT / C1). Context fully live.
    Idle,
    /// Tickless light sleep: periodic tick suppressed, wake on next timeout or IRQ.
    /// Drivers stay live. Sub-ms–ms wake. (WFI+suppress / C1-C2.)
    Sleep,
    /// RAM-retained deep sleep: clocks/peripherals off, wake only from an armed
    /// wake source. Drivers suspended. (Vendor STOP / ACPI S3.)
    DeepSleep,
    /// Deeper than DeepSleep: only a small retained region survives.
    /// (Vendor STANDBY; subsumed by S3/S4 on x86.)
    Standby,
    /// Suspend-to-storage: a bounded image is persisted, then power is cut;
    /// resume reconstructs from storage at boot. (Freeze-to-flash / ACPI S4.)
    Hibernate,
    /// Soft off. Full re-init on next boot. (SoC shutdown / ACPI S5.)
    Off,
}
```

Two state spaces, deliberately: `driver::PowerState` describes **one device**; `SystemPower` describes **the whole machine**. The system service drives devices *through* their `PowerState` as part of a `SystemPower` transition. Keeping them separate is what lets `PowerGate` suspend an idle UART while the system is wide awake, and lets the system suspend everything without the enums fighting.

### 2.2 Transition rules

- **`Run ↔ Idle ↔ Sleep` are owned by the L1 idle governor** (§3) and need no driver involvement — they are CPU-only, reversible on any interrupt, and never lose state. The governor moves *down* this ladder when the scheduler goes idle and *up* on the first wake. No authority check (the system is simply idle).
- **`DeepSleep`/`Standby`/`Hibernate`/`Off` are owned by the L3 service** (§4) and are *explicit, privileged, system-wide* transitions requested by trusted code or a power supervisor. They run the ordered quiesce sequence. `DeepSleep`/`Standby` resume; `Off` does not; `Hibernate` resumes from storage at next boot.
- **Only adjacent descents, arbitrary ascent.** You descend one rung at a time (so each rung's quiesce precondition holds), but any wake returns straight to `Run`. A spurious wake during descent aborts cleanly back to `Run` (the sequence is written to be abort-safe up to the point of no return — the low-power instruction itself).
- **One transition at a time.** A global `transitioning` guard (an `IrqCell<Option<SystemPower>>`) makes a concurrent request return `Error::Busy`; this also makes the whole thing idempotent (re-requesting the current state is a no-op).

### 2.3 The idle governor policy (residency-based)

When the scheduler has no ready work other than the idle task, the governor must choose *how deep* to sleep. The policy is the one Zephyr's default "residency" policy[^zephyr] and Linux's `menu` governor[^menu] use, and that FreeRTOS's tickless macro encodes[^frtos]: **pick the deepest state whose entry is worthwhile for the time available.**

```rust
// src/kernel/idle.rs  —  L1 kernel · tickless idle governor · safe · always
struct Depth {
    state: SleepDepth,      // Idle | Sleep | DeepSleep (deeper handed to L3)
    exit_latency: u64,      // ticks to be running again
    min_residency: u64,     // ticks below which entry costs more than it saves
}

/// Choose the idle depth given the ticks until the next scheduled event.
fn govern(time_to_event: Option<u64>, constraint_floor: SleepDepth) -> SleepDepth {
    let budget = time_to_event.unwrap_or(u64::MAX); // None ⇒ nothing is waiting
    // Deepest state whose (exit_latency + min_residency) fits the budget,
    // not deeper than any active QoS/latency constraint allows.
    DEPTHS.iter().rev()
        .find(|d| d.exit_latency + d.min_residency <= budget && d.state <= constraint_floor)
        .map(|d| d.state)
        .unwrap_or(SleepDepth::Idle)
}
```

- **`time_to_event`** is `kernel::with(|k| k.next_timeout())` — the earliest `wake_at` among all blocked tasks, *including the timer-service task* (it is a blocked task whose `wake_at` is its next expiry, so software timers are covered for free — verify in §11).
- **`constraint_floor`** is a QoS veto: a driver mid-DMA, or a domain asserting a latency bound (the Linux PM-QoS analog), can pin the floor at `Idle`/`Sleep` so the governor never enters a state that would miss its deadline. Statically bounded (a small array of active constraints).
- **The threshold.** Like `configEXPECTED_IDLE_TIME_BEFORE_SLEEP`[^frtos], a `BISMUTH_IDLE_SLEEP_THRESHOLD_TICKS` floor keeps very short gaps in plain `Idle` (suppressing and re-arming the tick is not worth it for 1–2 ticks).

The governor never enters `DeepSleep` itself — that crosses into driver territory, which is L3. If the budget is large enough to justify DeepSleep *and* a policy allows autonomous deep sleep, the governor signals the L3 service (via a registered callback) rather than reaching up a layer.

---

## 3. Low-power idle & tickless operation on the existing scheduler

### 3.1 Where the tickless logic plugs in

The idle task already runs a hook before sleeping:

```rust
// kernel/task.rs (today)
pub(crate) fn idle_main(_: usize) {
    loop {
        if let Some(f) = IDLE_HOOK.lock(|h| *h) { f(); }
        port::idle();
    }
}
```

The governor **is** that hook (or `idle_main` is rewritten to call `kernel::idle::govern_and_sleep()` directly — cleaner, because the hook can then stay reserved for the watchdog-feed use its docs mention). The governed idle loop:

```rust
// src/kernel/idle.rs  (L1)
pub(crate) fn govern_and_sleep() {
    let depth = kernel::with(|k| {
        if k.has_ready_work() { return SleepDepth::None; } // someone became ready
        govern(k.next_timeout().map(|t| t - k.tick), constraint_floor())
    });
    match depth {
        SleepDepth::None  => { /* fall through, reschedule */ }
        SleepDepth::Idle  => port::idle(),               // WFI/HLT, tick running (today)
        SleepDepth::Sleep => port::sleep_until(next),    // suppress tick, WFI/one-shot
        // deeper ⇒ hand to L3 via a registered deep-sleep callback
    }
}
```

### 3.2 The new port contract function

Add **one** additive port function (the only L0 surface change for tickless):

```rust
// src/arch/mod.rs — additive to the six-function contract
/// Enter a low-power state until `deadline` (kernel ticks) or an interrupt,
/// with the periodic tick suppressed. Returns how we woke.
pub fn sleep_until(deadline: Option<u64>) -> WokenBy;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WokenBy { Timer, Interrupt, WakeSource(WakeId) }
```

Per-port realization:

| port | `idle()` (Idle) | `sleep_until` (Sleep, tickless) |
|---|---|---|
| **Cortex-M** | `wfi` (today) | reprogram SysTick reload to `(deadline - now)` ticks (clamped to its 24-bit range), `wfi`; on wake read how many ticks actually elapsed from the down-counter and re-arm periodic |
| **host sim** | virtual-time jump (today) | **same jump** — `advance_to(min(deadline, limit))`; honor a test-injected `WokenBy` |
| **x86-64** | `hlt` | program the Local APIC timer one-shot (or TSC-deadline) to `deadline`, `hlt`/`mwait`; on wake read the elapsed count |

Crucially, the host port *already does the right thing*: `host::idle()` calls `k.advance_to(t.min(limit))` for the next timeout — tickless idle is how the simulator has always worked. `sleep_until` on host is the same code, which is why the governor is testable with zero hardware (§9).

### 3.3 Reconciling the tick and pending timeouts

This is the correctness core of tickless, and Bismuth's `tick`/`next_wake`/`advance_to` are already built for it.

- **Suppress.** On entering `Sleep`, stop the periodic tick and record `t0 = k.tick`.
- **Wake.** An interrupt (the reprogrammed timer, or a device IRQ) wakes the core. Read the elapsed time from an **always-on** counter (SysTick's own down-counter for the running-clock case; an RTC/LPTIM for clocks-off DeepSleep).
- **Catch up.** Call `k.advance_to(t0 + elapsed)`. `advance_to` already (a) credits `idle_ticks`, (b) sets `tick`, and (c) runs `process_timeouts()` if `tick >= next_wake`, so **every timeout that came due during the sleep fires immediately and in order** on wake. No timer is lost; no busy catch-up loop.
- **Re-arm.** Restart the periodic tick for the `Run` cadence.

The 24-bit SysTick reload caps a single tickless interval; longer sleeps either chain (wake, re-arm, re-sleep) or use an RTC/LPTIM wake — a documented limitation (§11), not a design flaw.

### 3.4 The wake race (the classic tickless hazard)

A wake interrupt that arrives *after* the governor decides to sleep but *before* `wfi` executes must not be lost. Two facts make this safe, and the code must use both:

1. **Decide under `critical()`.** The `has_ready_work()`/`next_timeout()` read and the `wfi` happen inside one masked section — the FreeRTOS `eTaskConfirmSleepModeStatus()` pattern[^frtos]: re-check, under interrupts-masked, that nothing became ready, then sleep.
2. **`wfi`/`hlt` wake on *pending* interrupts even when masked.** A pending interrupt makes `wfi` a no-op (it returns immediately), so an IRQ that fires in the window sets the pending bit and `wfi` falls straight through; interrupts are then unmasked and it is serviced. This is the architectural guarantee that closes the race. (`WFE`/`SEV` is the alternative on ARM where an event-signaled wake is wanted.)

### 3.5 Making the primitives available on the MCU

`next_timeout`, `advance_to` and `has_ready_work` are today `#[cfg(not(target_os = "none"))]` — host only. Real tickless on Cortex-M needs them on the MCU too. The change is a one-line `cfg` relaxation (drop the gate, or widen it to `#[cfg(any(not(target_os = "none"), feature = "tickless"))]`), plus making sure they compile in a no-`std` context (they are pure integer scans over the task table — they do). Flagged as the first concrete code change (§10 stage 1, §11).

---

## 4. The driver power-management contract and the ordered sequence

### 4.1 Reuse `set_power`; do not add `suspend`/`resume`

The existing path is exactly right and already load-bearing:

- `Device::set_power(PowerState::Suspended)` → routes `Op::Power(Suspended)` through the global/user/driver middleware chain → `Driver::power(ctx, Suspended)` → the registry records `Suspended`. `PowerGate` already relies on this (it suspends via `dev.set_power(Suspended)` and observes power ops in its `call`).
- Resume is `Device::set_power(prev)` where `prev` is the state the service recorded before suspending.
- Authority is already enforced: an isolated domain's `DeviceCap` needs `Rights::POWER`; the kernel-domain service path carries `Caller::KERNEL`.

Adding separate `suspend`/`resume` trait methods would duplicate this and split the state machine. **Recommendation: no new `Driver` method.** A driver expresses "I can be suspended" by implementing `power()` for `Suspended`/`Off`; the default impl (reject all but `On`) means "I have no low-power mode," which the service handles explicitly (§4.4).

The one additive refinement worth making to `driver::PowerState`: it has `On, Idle, Suspended, Off`, which is enough. If a driver needs to distinguish "clock-gated, instant resume" (`Idle`) from "context saved, slow resume" (`Suspended`), it already can. No change needed.

### 4.2 Suspend/resume ordering

The rule: **suspend leaf→bus, resume bus→leaf.** A sensor on an I2C bus must be suspended *before* the I2C controller (so the last transaction completes), and the controller resumed *before* the sensor (so the sensor's resume transaction has a bus). This is the Linux device-PM ordering discipline and the reason Linux keeps a `dpm_list` in probe order.

Bismuth already has the ordering for free: **registration order is probe order**, and a board registers a bus before the devices behind it (`probe_all` walks the board's `DeviceDesc` array in order; buses precede their children in the device tree). Therefore:

- **Suspend**: iterate `driver::list()` / registry slots in **reverse** registration order.
- **Resume**: iterate in **forward** registration order.

No new metadata is required for the common case. For the rare board where registration order is wrong, add an **optional** `power_order: u8` to `DeviceDesc` (default 0 = use registration order); the service sorts by it when any device sets it. Statically bounded (it is one byte per device).

### 4.3 The ordered suspend/resume sequence (the centerpiece)

For a `DeepSleep` transition (S3 / STOP). Each step names the module that owns it and whether it is abort-safe (a spurious wake before the point of no return returns cleanly to `Run`).

```
SUSPEND  (src/power/mod.rs, L3, running as trusted code)
 0. ENTER GUARD          power: CAS transitioning = Some(DeepSleep); else Err(Busy).
                         Check authority: security::current_is_trusted() (§8). [abort-safe]
 1. QUIESCE TASKS        power: set system "suspending"; stop admitting new work.
                         App tasks reach a safe point (cooperative) or are simply
                         frozen by the scheduler not running them.                [abort-safe]
 2. STOP THE NET TASK    net::quiesce(): finish the current NAPI poll round, flush
                         TX, mask NIC IRQs, park the net task.                     [abort-safe]
 3. ZEROIZE HOT CACHE    fs::resident::on_suspend(): zeroize() every plaintext
                         residency slab (filesystems §4.2). Write-through ⇒ nothing
                         dirty to flush; drop encrypted-mount DEKs per policy.     [abort-safe]
 4. SUSPEND DRIVERS      power: for each device in REVERSE registration order,
   (leaf → bus)          record its current PowerState, then
                         dev.set_power(Suspended)  (Off for Hibernate/Off).
                         Each driver flushes FIFOs, parks DMA, gates its clock.    [abort-safe*]
 5. DROP TRANSIENT KEYS  security: zeroize transient key material; trust::sealed
                         objects are already sealed.                               [abort-safe]
 6. SEAL RETAINED RAM    trust::retained::pre_sleep() (trusted-platform §6b):
                         bump the monotonic sleep counter, AEAD-seal the .retained
                         region IN PLACE, stash nonce-ctr+tag in backup registers.
                         *** This is the LAST software step that may write RAM that
                             must survive: everything that needs to persist across
                             the sleep was written into .retained BEFORE here. ***  [abort-safe]
 7. ARM WAKE SOURCES     arch::port::arm_wake(&sources): RTC/EXTI/power-button GPE.
                         Save the resume entry (FACS waking vector on x86 S3).     [abort-safe]
 8. STOP THE TICK        kernel/arch: suspend SysTick / APIC timer; record k.tick.  [abort-safe]
 9. ENTER LOW POWER      arch::port::enter(DeepSleep):  <-- POINT OF NO RETURN
      Cortex-M: SCB.SCR |= SLEEPDEEP; (vendor STOP cfg via board hook); wfi
      x86-64:   write PM1a_CNT = (SLP_TYPa<<10) | SLP_EN  (+ PM1b); CPU stops (S3)
```

```
RESUME  (reverse)
 R1. ARCH RE-INIT        Hardware resumes at the saved entry (FACS waking vector /
                         warm-reset handler). Early clock/PLL, paging/GDT/IDT (x86),
                         MMU/MPU re-establish.                                     (arch, TCB)
 R2. RESTART TICK +      Read elapsed from the always-on counter (RTC/LPTIM);
     CATCH UP TIME       k.advance_to(t_saved + elapsed) → due timeouts fire in
                         order (§3.3); re-arm the periodic tick.                   (kernel)
 R3. OPEN RETAINED RAM   trust::retained::post_resume(): re-derive the key through
                         the TPM-rooted keystore (needs a correct measured boot),
                         AEAD-open .retained. Error::Integrity ⇒ tamper/cold-boot:
                         fail closed (zero the region, treat as fresh boot).       (security, L3)
 R4. RESUME DRIVERS      for each device in FORWARD registration order, restore the
     (bus → leaf)        recorded PowerState (set_power(prev)); re-enable IRQs/DMA.  (power, L3)
 R5. RESUME NET          net::resume(): unmask NIC IRQs, restart the poll loop.    (net, L3)
 R6. REPOPULATE CACHES   nothing to restore: residency repopulates lazily on the
                         next hot read; encrypted mounts re-unseal their DEK if R3
                         policy dropped it.                                        (fs, L3)
 R7. EXIT GUARD          power: transitioning = None; scheduler resumes; the task
                         that requested suspend returns Ok.                         (power, L3)
```

`*` Step 4 is abort-safe only up to the device that has gated its clock; a wake during driver suspend resumes the already-suspended devices (R4) before returning. After step 9 there is no abort — only resume.

### 4.4 Non-suspendable drivers

A driver whose `power()` rejects `Suspended` (the default impl) is not a bug — many trivial devices have no low-power mode. Policy:

- For **`Sleep`** (light, drivers stay live) this never arises — drivers are untouched.
- For **`DeepSleep`/`Off`**, the service treats `Err(Unsupported)` from `set_power(Suspended)` as "this device simply stops getting a clock when the SoC/domain powers down" — acceptable, because the SoC is cutting its power anyway. It is **logged**, not fatal. A device that returns `Err(Busy)`/`Err(NotReady)` (genuinely cannot suspend right now, e.g. mid-DMA) **vetoes** the transition: the service aborts (resumes what it suspended) and returns `Error::Busy`. This is the clean, honest distinction between "no low-power mode" and "not now."

---

## 5. ACPI on x86-64: the minimal fixed-feature subset

ACPI is the x86 power path. The design principle, inherited from `x86-port.md` §9 (the vetted-crate / RustCrypto-for-the-CPU strategy) and the trusted-platform doc's "never hand-roll a primitive" rule: **implement the smallest subset that gives shutdown/reboot and S3/S5, keep it inside the already-TCB `arch/x86_64/` tree, and explicitly defer the general AML interpreter.**

### 5.1 Table discovery (RSDP from `BootInfo`)

The bootloader crate hands us `boot_info.rsdp_addr` (`x86-port.md` §2 confirms the field). From there, by hand (or with the `rsdp`/`acpi` crates for the parse, §5.4):

```
rsdp_addr → RSDP (validate "RSD PTR ", checksum) → XSDT (64-bit) / RSDT (32-bit)
          → walk the table pointers, match 4-byte signatures:
              "FACP" → FADT   (fixed ACPI description: the PM register map)
              "FACS" → via FADT.firmware_ctrl / x_firmware_ctrl (S3 waking vector)
              "DSDT" → via FADT.dsdt / x_dsdt           (holds the \_Sx packages)
              "APIC" → MADT   (already wanted by x86-port.md for the LAPIC/IOAPIC)
```

All of these are **static tables** — fixed C-style structs, no interpretation. A bounded table directory (`BISMUTH_ACPI_MAX_TABLES`, a small const) holds the discovered pointers; nothing dynamic.

### 5.2 The fixed-feature register map (from the FADT)

The FADT gives, as plain fields, everything needed for S-states, reset and the power button — **no AML**:

| FADT field | use |
|---|---|
| `pm1a_cnt_blk` / `pm1b_cnt_blk` (+ `x_` 64-bit forms) | the **PM1 control** registers: write `SLP_TYPx<<10 \| SLP_EN(bit13)` to enter an S-state |
| `pm1a_evt_blk` / `pm1b_evt_blk` | PM1 **event/status**: the power-button status/enable bits (fixed-feature button) |
| `gpe0_blk` / `gpe1_blk` | **GPE** blocks: general-purpose events incl. a control-method power button, routed via the SCI |
| `sci_int` | the SCI IRQ (route it through the I/O APIC; §x86 interrupts) |
| `smi_cmd`, `acpi_enable`, `acpi_disable` | write `acpi_enable` to `smi_cmd` to hand the PM registers from firmware/SMM to the OS (skip if `smi_cmd == 0`, which is common under QEMU — ACPI mode is already on) |
| `reset_reg`, `reset_value` | **reboot**: write `reset_value` to `reset_reg` (a Generic Address Structure: I/O port, MMIO, or PCI config) |
| `flags` (e.g. `WBINVD`, `RESET_REG_SUP`) | capability bits gating the above |

### 5.3 The `SLP_TYP` problem, and the bounded `_Sx` scan (not an interpreter)

Writing an S-state needs the `SLP_TYPa`/`SLP_TYPb` values for that state. ACPI 5.0 §7.3.4 says these **must be read from the `\_S0`…`\_S5` objects in the DSDT**[^ipxe], which are AML `Name(_S5, Package(){...})` declarations. A *correct, general* reader of those is an AML interpreter — which we are not building.

The well-established minimal technique (iPXE's `acpi_poweroff`[^ipxe], Unikraft[^unikraft], countless hobby kernels): **scan the DSDT bytes for the `_S5_` signature and parse the tiny fixed `NameOp … PackageOp` that follows** to pull out the first two bytes (`SLP_TYPa`, `SLP_TYPb`). This is a ~30-line bounded byte reader over a `&[u8]`, not an interpreter: it recognizes exactly the `Name(_Sx, Package)` byte pattern and extracts two small integers. Same for `_S3`. It cannot evaluate methods, it has no name resolution, it allocates nothing.

```rust
// arch/x86_64/acpi.rs (TCB — it reads mapped physical memory)
/// Extract (SLP_TYPa, SLP_TYPb) for an S-state from the DSDT by locating the
/// `Name(_Sx, Package{...})` byte pattern. NOT an AML interpreter.
fn slp_typ(dsdt: &[u8], state: SleepState) -> Option<(u8, u8)>;
```

Honesty about the limit: this works on QEMU (where the `_Sx` packages are simple and the values are effectively static[^unikraft][^qemu]) and on most firmware whose `_S5`/`_S3` are plain packages. It does **not** run `_PTS`/`_GTS` (pre-sleep) or `_WAK` (post-wake) control methods, which *some real hardware* needs for a reliable S3[^qemu]. That is the documented limitation (§11): fixed-feature S3/S5 is QEMU-first and best-effort on real hardware; a reliable real-hardware S3 would need AML and is out of scope.

### 5.4 Crate evaluation: `rsdp`, `acpi`, `aml`

| crate | role | `no_std` / heap | maturity | verdict |
|---|---|---|---|---|
| [`rsdp`][rsdp] (rust-osdev) | find + validate the RSDP, hand back the RSDT/XSDT address | **`no_std`, no alloc** | small, stable, companion to `acpi` | **use it** for discovery — it is tiny and allocation-free[^acpi-crate] |
| [`acpi`][acpi] (rust-osdev) | parse the static tables (FADT, MADT, …) via an `AcpiHandler` you implement | `no_std` but **needs `alloc`** for `PlatformInfo`; table structs usable with `alloc`/`allocator_api` disabled[^acpi-crate] | "not feature-complete, but parses the common tables"[^acpi-crate] | **optional** — use only the alloc-free table structs for the FADT/FACS/DSDT pointers; or hand-roll (~100 lines) to avoid the dependency and the `alloc` temptation entirely. Lean toward hand-rolled, as x86-port.md leans toward hand-rolled where the crate's surface is small. |
| [`aml`][aml] (rust-osdev) | interpret AML (DSDT/SSDT) | `no_std` but **needs `alloc`**, large | self-described "far from feature-complete"[^acpi-crate]; soundness history | **defer — do not depend.** This is the single biggest TCB/`unsafe`/complexity temptation and we decline it (§11). The `_Sx` byte-scan (§5.3) replaces it for the only thing power needs. |

Net: **`rsdp` + hand-rolled FADT/FACS/`_Sx` parsing, no `aml`, `acpi` optional and alloc-free only.** The new x86 unsafe is one `AcpiHandler`-style physical-memory mapper (already the kind of thing `arch/x86_64/paging.rs` does) and the PM-register port/MMIO writes (the `PortIo`/`Mmio` wrappers from `x86-port.md`) — all inside the existing `arch/x86_64/` TCB directory, no new TCB module beyond `acpi.rs`.

### 5.5 Shutdown, reboot, and the QEMU specifics

- **Shutdown (S5).** Compute `SLP_TYPa` for S5 (§5.3), write `(SLP_TYPa<<10) | SLP_EN` to `pm1a_cnt_blk` (and `pm1b` if present). On QEMU this is the well-known `outw(0x604, 0x2000)` (PM base 0x600, `PM1a_CNT` at +4; the SLP_TYP|SLP_EN value is static on QEMU[^unikraft][^qemu]).
- **Reboot.** Preferred: ACPI `reset_reg`/`reset_value` from the FADT. Fallbacks (document the ladder): the 8042 keyboard-controller pulse (`out 0x64, 0xFE`), then a triple-fault. On Cortex-M the analog is `SCB.AIRCR = VECTKEY | SYSRESETREQ`.
- **Test exit vs real power-off — keep them distinct.** `x86-port.md` §7 uses `isa-debug-exit` at port `0xF4` for CI PASS/FAIL: QEMU runs `exit((code<<1)|1)`, so it **cannot** signal exit code 0[^qemuexit]. That is the *test harness* exit, not an ACPI operation. Real `power::request_state(Off)` goes through ACPI S5; the demo additionally writes `0xF4` to make QEMU exit the CI run. The ACPI write should run **before** the `isa-debug-exit` fallback (the ACPI path is the clean one; the ISA device is the harness)[^qemu].

---

## 6. Cortex-M low-power

### 6.1 The architectural part (generic, in `arch/cortex_m.rs`, TCB)

- **Idle** is today's `wfi` (`idle()`), with SysTick running.
- **Sleep** (tickless) is `wfi` with SysTick reprogrammed to the next timeout (§3.2). `SCB.SCR.SLEEPONEXIT` is deliberately **not** used (it conflicts with the scheduler's thread-mode model); `SEVONPEND` may be set so `WFE` wakes on newly-pended interrupts.
- **DeepSleep** sets `SCB.SCR.SLEEPDEEP` (bit 2) before `wfi`. This is the *architectural* request for a deep mode; **what "deep" means is vendor-defined.**

```rust
const SCR: *mut u32 = 0xE000_ED10 as *mut u32; // System Control Register
const SCR_SLEEPDEEP: u32 = 1 << 2;
```

### 6.2 The vendor part (behind a board hook)

Entering STM32 STOP vs STANDBY, nRF `SYSTEMOFF`, etc. is a sequence of writes to vendor `PWR`/`RCC`/`POWER` registers that select regulators, retention and the wake configuration — and it is **not** architectural. It must not live in generic `arch/cortex_m.rs`. The clean seam: a board/SoC-provided hook the port calls between `SLEEPDEEP` and `wfi`:

```rust
// A board implements this (its SoC crate pokes PWR/RCC). The generic port
// sets SLEEPDEEP and executes wfi around it.
pub trait DeepSleepHook: Sync {
    fn pre_stop(&self, state: SystemPower);   // configure vendor regulators/retention
    fn configure_wake(&self, srcs: &[WakeSource]); // EXTI/RTC alarm, etc.
    fn post_wake(&self);                      // restore clocks/PLL
}
```

This mirrors how `x86-port.md` keeps board-asserted hardware facts (the `DeviceDesc` MMIO windows) out of the generic kernel. The generic port provides SLEEPDEEP + WFI + the wake-source *concept*; the board provides the register pokes.

### 6.3 RTC / wake

MCU deep sleep stops the core clock, so SysTick cannot time the sleep or wake it — an **always-on** timer (RTC, LPTIM, or a vendor wake timer) is both the timekeeper (for §3.3 catch-up) and a wake source. The board's `DeepSleepHook::configure_wake` programs the RTC alarm to `next_timeout()`; on wake, `post_wake` reads the RTC to compute elapsed ticks for `advance_to`. GPIO/EXTI and a power button are the other wake sources, declared through the §7 registry.

---

## 7. Wake sources & resume

### 7.1 Declaration (static, bounded)

A wake source is "a thing that can bring the system out of DeepSleep." Declared by drivers/boards into a statically-sized registry:

```rust
// src/power/wake.rs  —  L3 services · power: wake-source registry · safe · always
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WakeKind { Timer, Rtc, Gpio, Irq, PowerButton }

#[derive(Copy, Clone)]
pub struct WakeSource {
    pub kind: WakeKind,
    pub device: Option<driver::Device>, // the owning device, if any
    pub id: WakeId,                      // stable id reported back as WokenBy
    enabled: bool,
}

/// Fixed-size registry (no heap).
static WAKE: IrqCell<[Option<WakeSource>; BISMUTH_MAX_WAKE_SOURCES]> = ...;
pub fn register(src: WakeSource) -> Result<WakeId, Error>;  // trusted/board only
pub fn enable(id: WakeId, on: bool) -> Result<(), Error>;
```

The timer wake for `Sleep` (tickless) is *implicit* — it is the reprogrammed tick/APIC-timer at `next_timeout()` and needs no registry entry. The registry is for the *explicit* DeepSleep wakes (RTC alarm, EXTI line, power button, a NIC's wake-on-LAN IRQ).

### 7.2 Resume and attribution

The port's `enter(DeepSleep)` returns (via the resume path) a `WokenBy`, which the L3 service uses to decide the resume shape:

- `WokenBy::Timer`/`Rtc` → a scheduled timeout came due: resume, `advance_to`, let the woken task run.
- `WokenBy::PowerButton` → a user wants the system: full resume to `Run`, possibly notify a supervisor.
- `WokenBy::WakeSource(id)` → attribute to the owning device (e.g. a GPIO interrupt) and resume it first.

The resume sequence itself is §4.3 R1–R7. The arch-specific R1/R2 (re-init + tick catch-up) is the only TCB part; R3–R7 are safe L3 orchestration.

---

## 8. Security & safety

### 8.1 Who may suspend the system

A system transition changes global state and can stop security-relevant tasks, so it is **privileged**:

- `power::request_state(DeepSleep | Standby | Hibernate | Off)` and `power::reboot()` check `security::current_is_trusted()` — exactly the gate `driver::register`, `security::seal` and `driver::add_global_middleware` already use. First cut: kernel-domain (or a trusted supervisor) only.
- A per-device `set_power` from an *isolated* domain already requires `Rights::POWER` on its `DeviceCap`; that is unchanged and orthogonal (a domain suspending *its own* granted device is fine; a domain suspending *the system* is not).
- **Optional, deferred:** a dedicated **power supervisor** container. `container.rs` already has the `supervisor` field and the `OnFault` policy — a watchdog/power supervisor is the same shape. If system suspend should be delegable to a not-fully-trusted supervisor, add a `may_suspend_system: bool` to `DomainSpec` (compile-time validated in `manifest::validate`, like the existing `MANAGE`/`trusted` checks) rather than a new ambient right. Keep it out of the first cut.

### 8.2 Transitions as trusted operations with crypto obligations

- **`Off`/`Hibernate` must zeroize domain secrets** on the way down (step 5), tying into the `kill`-path zeroize the security module already does. A powered-off device that keeps a key in SRAM is a cold-boot target (trusted-platform §6b threat model).
- **The retained-RAM seal (step 6) is the security centerpiece of deep sleep.** It is sequenced as the *last* software step precisely because the threat is a power-pull between "RAM still holds plaintext" and "RAM is off." Sealing last minimizes the plaintext window. The key is re-derived on resume through the TPM-rooted keystore (requires a correct measured boot), so a cold-boot attacker reads only ciphertext — this is the property trusted-platform §6b designs for; here we only guarantee *where the hook fires*.
- **Interaction with container budgets.** A partitioned (ARINC-653) container's CPU budget (`container.rs::CpuBudget`) is meaningless while the system is suspended; the supervisor owns the decision to suspend a partition and must account for the "lost" window on resume. Documented as a policy concern, not enforced in the first cut.

### 8.3 Fail-closed

`trust::retained::post_resume()` returning `Error::Integrity` (tampered/cold-booted retained region) is treated as a **fresh boot**: zero the region, do not trust its contents, continue. A failed resume never silently runs on attacker-controlled retained state.

---

## 9. Host-testability

The whole point of Bismuth's simulator is that security- and timing-relevant behavior is tested deterministically with no hardware (`sim.rs`, `arch/host.rs`). Power transitions fit this model cleanly.

### 9.1 The host port already does tickless

`host::idle()` jumps virtual time to `next_timeout()` via `advance_to` — i.e. the simulator has *always* been tickless. `arch::port::sleep_until(deadline)` on host is the same jump; `enter(DeepSleep)` on host jumps to the armed wake deadline and returns a **test-injected** `WokenBy`. So every sleep path is exercised in virtual time, instantly.

### 9.2 `SimPowerController`

A host-only fake, same shape as the trusted-platform doc's `SoftTpm` and the existing `SimSensor`/`SimDisplay`, that records the ordered sequence of transition callbacks:

```rust
// sim-only
pub struct SimPowerController {
    log: Mutex<Vec<Event>>,   // Suspend(dev)/Resume(dev)/Sealed/CacheZeroized/TickCaughtUp
}
pub fn inject_wake(src: WokenBy);   // a test says how the next DeepSleep ends
```

### 9.3 What the sim tests assert

- **Ordering.** Suspend events appear in **reverse** registration order; resume events in **forward** order (register three fake devices on a fake bus, suspend, assert the log order).
- **Idempotency.** A second `request_state(DeepSleep)` while suspended returns `Error::Busy`; `request_state(Run)` while running is a no-op.
- **Retained-RAM hook fired.** Reuse trusted-platform §6b's test: fill `.retained` with a known pattern, run the suspend sequence, assert the region is now ciphertext (`pre_sleep` ran at step 6); `inject_wake(Timer)`, run resume, assert the pattern is recovered (`post_resume` ran at R3); flip a byte and assert `Error::Integrity` → fail-closed.
- **Cache zeroized.** Fill a residency slab, suspend, assert the slab is zero (filesystems §4.2's `on_suspend` ran at step 3).
- **Tick catch-up.** Block a task on a 500-ms timeout, enter `Sleep`/`DeepSleep`, let the host jump virtual time past 500 ms, resume, assert the task woke (via `advance_to` → `process_timeouts`) and that `idle_ticks` was credited.
- **Veto.** A fake driver returning `Err(Busy)` from `set_power(Suspended)` aborts the transition and the already-suspended devices are resumed (the log shows a clean rollback).
- **Governor choice.** Unit-test `govern(time_to_event, floor)` directly: 1 tick → `Idle`; 10 000 ticks → the deepest fitting state; a `floor` constraint pins it shallower.

All deterministic, all instant, all serialized through the existing `sim::run` lock with full kernel reset between runs.

---

## 10. Proposed module layout, config, and staged order

### 10.1 `src/` module layout (with `//! Classification` lines)

```
src/arch/
  mod.rs            # add to the contract: sleep_until / enter / arm_wake + WokenBy/SleepDepth types
  cortex_m.rs       # //! L0 port · Cortex-M port · TCB (unsafe allowed) · target_os = "none"
                    #   + SCR.SLEEPDEEP, tickless SysTick reprogram, DeepSleepHook call, RTC-wake read
  host.rs           # //! L0 port · host simulator port · safe · host only
                    #   + sleep_until/enter = virtual-time jump; honor sim-injected WokenBy
  x86_64/
    acpi.rs         # //! L0 port · x86-64 ACPI fixed tables · TCB (unsafe allowed) · x86
                    #   RSDP→XSDT→FADT/FACS/DSDT, PM1/GPE/reset regs, bounded _Sx scan
    power.rs        # //! L0 port · x86-64 sleep/Cx/S-state · TCB (unsafe allowed) · x86
                    #   HLT/MWAIT, S3/S5 writes via acpi.rs, APIC-timer one-shot
src/kernel/
  idle.rs           # //! L1 kernel · tickless idle governor · safe · always   (govern + govern_and_sleep)
  mod.rs            # make next_timeout/advance_to/has_ready_work available on target_os="none"
  task.rs           # idle_main calls kernel::idle::govern_and_sleep()
src/power/          # NEW top-level L3 service
  mod.rs            # //! L3 services · power: system suspend/resume orchestration · safe · always
                    #   SystemPower, request_state, reboot, the ordered sequence, the transition guard
  wake.rs           # //! L3 services · power: wake-source registry · safe · always
src/driver/
  mod.rs            # unchanged trait; document suspend = set_power(Suspended); optional power_order on DeviceDesc
  middleware.rs     # PowerGate unchanged (already participates)
src/net/mod.rs      # add net::quiesce()/resume() for the net task
src/fs/resident.rs  # add on_suspend() (zeroize slabs) — specified in filesystems §4.2
src/security/trust/retained.rs  # pre_sleep()/post_resume() — specified in trusted-platform §6b
```

No new TCB *module* on Cortex-M (the additions are inside the existing `arch/cortex_m.rs`). On x86, `acpi.rs` + `power.rs` join the `arch/x86_64/` TCB directory that `x86-port.md` §10.1 already proposed treating as TCB by directory prefix — so the `tests/structure.rs` TCB rule covers them automatically. **Every power *logic* file (`kernel/idle.rs`, `src/power/*`) is `safe`.**

### 10.2 `config.rs` additions (all statically bounded)

```rust
/// Below this many ticks to the next event, stay in plain Idle (tick kept running):
/// the configEXPECTED_IDLE_TIME_BEFORE_SLEEP analog.
pub const BISMUTH_IDLE_SLEEP_THRESHOLD_TICKS: u64 = parse_or(option_env!("BISMUTH_IDLE_SLEEP_THRESHOLD_TICKS"), 2) as u64;
/// Minimum residency (ticks) that makes a DeepSleep entry worthwhile.
pub const BISMUTH_DEEP_SLEEP_MIN_RESIDENCY: u64 = parse_or(option_env!("BISMUTH_DEEP_SLEEP_MIN_RESIDENCY"), 50) as u64;
/// Explicit wake sources the registry tracks.
pub const BISMUTH_MAX_WAKE_SOURCES: usize = parse_or(option_env!("BISMUTH_MAX_WAKE_SOURCES"), 8);
/// ACPI static tables the discovery directory holds (x86).
pub const BISMUTH_ACPI_MAX_TABLES: usize = parse_or(option_env!("BISMUTH_ACPI_MAX_TABLES"), 16);
```

(`TICK_HZ`, `MAX_DEVICES`, and the x86-port frame/kstack consts already exist and are reused. `RETAINED_BYTES` and the FS residency consts come from the trusted-platform / filesystems docs.)

### 10.3 New `Error` / `Right` variants

- **`Error`: none needed.** `Busy` (already transitioning / device won't suspend now), `Unsupported` (port/driver has no such depth), `NotReady` (device powered down), `Integrity` (retained-RAM open failed), `PermissionDenied` (untrusted caller) all already exist and cover every case.
- **`Rights`: none in the first cut.** `Rights::POWER` already gates per-device `set_power`. The system transition uses `current_is_trusted()`. The optional `DomainSpec::may_suspend_system` flag (§8.1) is deferred.

### 10.4 Staged implementation order (with the test per stage)

| stage | deliverable | test |
|---|---|---|
| **1** | **Tickless/low-power idle governor.** `kernel::idle::govern`; add `port::sleep_until`; un-`cfg` `next_timeout`/`advance_to`/`has_ready_work` for `target_os="none"`; `idle_main` calls the governor. | sim: governor picks `Idle` for short gaps, `Sleep` for long ones; blocked-task timeout fires after a virtual-time jump; `idle_ticks` credited; a device IRQ wakes early (no lost wake). |
| **2** | **Driver suspend/resume ordering via `set_power`.** `src/power/` service: `suspend_devices()`/`resume_devices()` leaf↔bus, the transition guard, per-device state record/restore; `net::quiesce`/`resume`. | `SimPowerController`: reverse-suspend / forward-resume order; idempotency (`Busy`); a driver `Err(Busy)` vetoes + clean rollback; per-device state restored. |
| **3** | **Cortex-M stop modes.** `SCR.SLEEPDEEP` + the `DeepSleepHook` seam + RTC-wake read + `arm_wake`/`WokenBy`. | host parity for the hook/registry; QEMU lm3s smoke (limited — it has no STOP, so assert SLEEPDEEP is set and WFI entered). |
| **4** | **x86 ACPI shutdown/reboot.** `arch/x86_64/acpi.rs` (RSDP→XSDT→FADT, `_S5` scan); S5 poweroff + reset register. Keep `isa-debug-exit` for CI. | QEMU exits via ACPI S5 (`outw(0x604,0x2000)` path) and via the reset register; unit-test the FADT/`_Sx` parse over a captured table blob. |
| **5** | **x86 ACPI S3 suspend-to-RAM + wake.** FACS waking vector, `_S3` SLP_TYP, power-button GPE/SCI wake, context save/restore. | QEMU S3 round-trip where supported; unit-test the table parse + the full sim sequence with `inject_wake(PowerButton)`. |
| **6** | **Retained-RAM seal + cache-zeroize hooks wired in** (trusted-platform §6b at step 6/R3; filesystems §4.2 at step 3). | region ciphertext after suspend, recovered after resume, `Integrity` on tamper → fail-closed; residency slabs zeroized. |
| **7** | **Hibernate/S4.** Persist the retained region (+ app-declared state) to the block device; `Off`; restore on boot. (Opt: LAPIC-timer tickless replaces SysTick reprogram on x86.) | FS round-trip of the hibernate image; boot-time resume detection restores the region. |

---

## 11. Open questions, risks, documented-limitation candidates

- **AML is the big temptation — decline it, loudly (lead item).** A general AML interpreter is large, needs `alloc` (breaking the no-heap invariant), has a soundness history, and the rust-osdev [`aml`][aml] crate is itself "far from feature-complete"[^acpi-crate]. **Recommendation: no AML interpreter, in-tree or crate.** Recover `SLP_TYP` with the bounded `_Sx` byte-scan (§5.3). Consequence/limitation: `_PTS`/`_GTS`/`_WAK` control methods are not executed, so **S3 on some real hardware may be unreliable**; fixed-feature S3/S5 is QEMU-first and best-effort on real PCs[^qemu]. If a future need for reliable real-hardware S3 arises, it is a deliberate, separately-reviewed decision to add AML — not a default.
- **MCU STOP/STANDBY are vendor-specific.** Only `SLEEPDEEP` + `wfi` are architectural; the real deep-sleep register sequence (regulators, retention, RTC alarm) is per-SoC and must stay behind the `DeepSleepHook` board seam (§6.2), never in generic `arch/cortex_m.rs`. Risk: getting the wake-source configuration wrong bricks a sleep (no wake armed → never resumes); the host sim cannot catch a vendor-register bug, so these need per-board bring-up.
- **The host-only `cfg` on the tickless primitives is a real, concrete first change.** `next_timeout`/`advance_to`/`has_ready_work` are `#[cfg(not(target_os = "none"))]` today. Un-gating them for the MCU is required for stage 1 and must be verified to compile `no_std` (they are pure integer scans — they should).
- **Software timers and the governor.** The governor's `next_timeout()` must account for the timer-service task. It does *if* the timer-service task is a blocked task with its `wake_at` set to its next expiry (it blocks via `block_on` with a `Timeout::Ticks`). **Verify** this holds (`timer.rs` `service_main` blocks with the computed `next` timeout), or the governor could sleep past a due software timer. This is the one correctness item to confirm before stage 1 ships.
- **The wake race.** Decide-then-sleep must be atomic under `critical()` and rely on `wfi`/`hlt` waking on pending-but-masked interrupts (§3.4). Easy to get subtly wrong; it is the classic tickless bug and must have a dedicated sim test (inject an IRQ in the decide→sleep window).
- **SysTick 24-bit range caps a single tickless interval.** Long sleeps need chaining or an RTC/LPTIM. Documented limitation; the RTC path is needed for DeepSleep anyway (§6.3).
- **DMA across suspend (compounds the x86 no-IOMMU note).** Devices must park/complete DMA before clock-gating (step 4). The `x86-port.md` §11 "DMA without an IOMMU" risk means a mis-suspended DMA engine could scribble RAM during the transition; the suspend order (drivers before the retained-RAM seal) is partly chosen so DMA is quiesced before the region is sealed.
- **Hibernate scope.** A whole-RAM image is unrealistic on an MCU and heavy on a thin client. The feasible first form is "persist the retained region (+ app-declared state) to the block device, then `Off`, restore at boot" (§4.5) — i.e. Hibernate = DeepSleep's seal step targeting stable storage. Full image hibernation is a documented stretch goal, not a commitment.
- **`DeviceDesc` gains optional `power_order`.** Like the `pio` field `x86-port.md` adds, this is a small additive change to a shared L2 struct; confirm it defaults to 0 (= registration order) and does not perturb existing boards.
- **Autonomous deep sleep vs explicit request.** Should the L1 governor ever *initiate* DeepSleep (crossing to L3 via a callback) when a very long idle is detected, or is DeepSleep always an explicit `power::request_state`? Recommend **explicit-only** first (simpler, clearly privileged); add an opt-in "auto-deep-sleep" policy later for always-on battery devices.
- **Documented-limitation candidates:** no general AML / best-effort real-hardware S3; vendor STOP modes need per-board code; SysTick tickless range; whole-RAM hibernate deferred; power-supervisor delegation deferred.

---

### References

- ACPI fixed-feature power management (PM1 control, `SLP_TYP`/`SLP_EN`, the `\_Sx` objects, reset register): ACPI Specification, and the reference `acpi_poweroff` implementation in iPXE, which reads the FADT PM1a/PM1b control blocks and extracts `\_S5` from the DSDT[^ipxe].
- The static-table-scan-not-interpreter technique for `_S5`/`_S3`, and the static QEMU `SLP_TYP|SLP_EN` values: Unikraft's ACPI shutdown and the SeaBIOS/QEMU shutdown path[^unikraft][^qemu].
- Rust ACPI crates (`rsdp` no-alloc discovery; `acpi` static tables, needs `alloc`; `aml` "far from feature-complete"): rust-osdev [`acpi`][acpi] / [`rsdp`][rsdp] / [`aml`][aml][^acpi-crate].
- Tickless idle / dynamic ticking: FreeRTOS low-power tickless (`configUSE_TICKLESS_IDLE`, `portSUPPRESS_TICKS_AND_SLEEP`, `eTaskConfirmSleepModeStatus`)[^frtos]; Linux `NO_HZ`/dynticks and the `menu` idle governor (deepest state fitting before the next timer)[^menu]; Zephyr PM residency policy[^zephyr].
- QEMU test-exit vs power-off: `isa-debug-exit` at `0xF4` runs `exit((code<<1)|1)`[^qemuexit].
- Bismuth internal companions: `docs/research/x86-port.md` (boot order, `BootInfo`/RSDP, TCB/crate strategy, `isa-debug-exit`), `docs/research/trusted-platform.md` §6b (retained-RAM AEAD seal), `docs/research/filesystems.md` §4.2 (hot-file residency zeroize-on-suspend), `docs/research/security.md` (the capability/trust model).

[^frtos]: FreeRTOS "Low Power Support" / tickless idle — the kernel calls `portSUPPRESS_TICKS_AND_SLEEP(xExpectedIdleTime)` only when the idle task is the sole runnable task and at least `configEXPECTED_IDLE_TIME_BEFORE_SLEEP` ticks remain; the argument is the ticks until a task is due ready (the safe deep-sleep window); `eTaskConfirmSleepModeStatus()` re-checks under a critical section. https://www.freertos.org/low-power-tickless-rtos.html and https://freertos.org/Documentation/02-Kernel/02-Kernel-features/07-Lower-power-support
[^menu]: Linux `NO_HZ` (CONFIG_NO_HZ_IDLE avoids scheduling-clock interrupts to idle CPUs) and the `menu` idle governor (picks the deepest idle state whose break-even residency fits the time to the next timer). https://docs.kernel.org/timers/no_hz.html
[^zephyr]: Zephyr Power Management — the system PM "residency" policy selects the deepest `pm_state` whose `min_residency_us`/`exit_latency_us` fit the time to the next scheduled kernel event; device PM suspends/resumes devices around it. https://docs.zephyrproject.org/latest/services/pm/index.html
[^ipxe]: iPXE `acpi_poweroff` — finds the FADT, reads PM1a/PM1b control block addresses, extracts `\_S5` from the DSDT/SSDT (SLP_TYPa = low byte, SLP_TYPb = next), writes SLP_TYP|SLP_EN to each control block. ACPI 5.0 §7.3.4: the SLP_TYP values must be read from the `\_S0`–`\_S5` objects (which strictly needs AML). https://dox.ipxe.org/acpipwr_8c_source.html
[^unikraft]: Unikraft / SeaBIOS QEMU shutdown — writing `0x2000` (SLP_TYPa|SLP_EN, static on QEMU) to PM1a_CNT at port `0x604` (PM base `0x600` + 4) powers the guest off; the ACPI write should precede any ISA-exit fallback. https://lists.xenproject.org/archives/html/minios-devel/2019-03/msg00325.html
[^qemu]: QEMU/SeaBIOS "apm: fix shutdown" (ACPI PM1a_CNT at PM-base+4 = `0x604`); forum/maintainer notes that hardcoded S5 values work on QEMU but real hardware should parse `_S5` from the DSDT and call `_PTS` before setting the S-state. https://qemu.googlesource.com/seabios/+/6375ffd667dce57bee62b2f424bf9bef30eb2432%5E%21 and https://f.osdev.org/viewtopic.php?p=350907
[^qemuexit]: QEMU `isa-debug-exit` (`-device isa-debug-exit,iobase=0xf4,iosize=0x04`) executes `exit((value<<1)|1)`, so it cannot produce exit code 0 — it is the CI PASS/FAIL harness, distinct from an ACPI S5 power-off. https://docs.rs/qemu-exit and https://github.com/rust-embedded/qemu-exit
[^acpi-crate]: rust-osdev `acpi` project — the `acpi` crate "parses the static tables (useful but not feature-complete)" and "requires `alloc`" (for environments without a heap, the companion `rsdp` crate is alloc-free; `acpi` 3.x can disable the `alloc`/`allocator_api` features for table structs); the `aml` crate is "far from feature-complete." https://docs.rs/acpi and https://docs.rs/crate/acpi/latest

[acpi]: https://docs.rs/acpi/
[rsdp]: https://docs.rs/rsdp/
[aml]: https://docs.rs/aml/
