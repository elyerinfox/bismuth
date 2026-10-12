//! Containers: named, versioned, supervisable workload bundles built on domains.
//!
//! A **container is not a new isolation primitive** — a [`DomainId`] already is one
//! (see [`crate::security`]). A container bundles, as one declarable and attestable
//! unit, everything needed to *run and supervise* a workload:
//!
//! ```text
//!   container = a domain (DomainSpec: MPU set, handle table, rights, syscall mask,
//!                         priority ceiling, task quota, net policy, entropy context)
//!             + its device/key grants       (capability routing — no ambient authority)
//!             + a root entry + stack          (what `start` spawns)
//!             + a CPU budget                  (declared/validated; enforcement is Planned)
//!             + a lifecycle & fault policy    (start/stop/restart/health, OnFault)
//!             + a version + image measurement (for update policy and attestation)
//! ```
//!
//! The whole multi-container graph is **validated at compile time** by
//! [`validate_containers`] (a `const fn` used in a `const _: () = …` item), so an
//! over-budget, misgranted, or dangling-supervisor manifest fails the build — a property
//! the research argues Bismuth can have that run-time-routed systems cannot.
//!
//! Lifecycle maps onto operations the kernel already has: [`install`] is
//! [`manifest::apply`](crate::security::manifest) plus budget registration and a
//! [`seal`](crate::security::seal); [`start`] spawns the root task;
//! [`stop`]/[`restart`] use [`kill`](crate::security::kill) (which empties the handle
//! table, bumps the generation, re-derives the per-domain CSPRNG and purges its keys),
//! so a restarted container never replays its random stream and peers' stale handles
//! fail the generation check.
//!
//! Classification: L3 services · security: containers · safe · containers

use super::manifest::DomainDecl;
use super::{DomainId, current_is_trusted};
use crate::Error;
use super::MAX_DOMAINS;
use crate::kernel::cell::IrqCell;
use crate::kernel::stack::StackSource;
use crate::kernel::task::{self, MAX_PRIORITY};

/// A CPU budget for a container (cgroup `cpu.max` / ARINC-653 window analogue).
///
/// Declared and validated now; run-time enforcement in the scheduler is a later phase
/// (the budget is surfaced in [`Health::cpu_ticks`] for a supervisor to act on).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CpuBudget {
    /// Replenishment window, in milliseconds.
    pub period_ms: u32,
    /// CPU time the container may run per window, in microseconds.
    pub micros: u32,
    /// `true` = a reserved, non-overrunnable time partition (ARINC 653);
    /// `false` = a soft budget whose slack is sharable (sporadic-server style).
    pub partitioned: bool,
}

/// What the supervisor does when a container faults or exits abnormally.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OnFault {
    /// Re-run the entry in a freshly reset domain, up to `max` times per `window_ms`.
    Restart { max: u8, window_ms: u32 },
    /// Leave the domain dead; peers' handles fail.
    Stop,
    /// Notify the supervisor container and let policy decide.
    Notify,
    /// Escalate to the system fault policy.
    Halt,
}

/// The root task of a container, spawned by [`start`].
#[derive(Copy, Clone)]
pub struct ContainerEntry {
    /// Unprivileged, MPU-confined entry (the common case for edge workloads).
    pub user_entry: Option<extern "C-unwind" fn(usize)>,
    /// Privileged entry (isolated-but-not-sandboxed; software enforcement only).
    pub entry: Option<fn(usize)>,
    pub arg: usize,
    pub priority: u8,
    /// The root task's statically allocated stack. A sandboxed (user) entry needs an
    /// MPU-aligned `UserStack` here (see `kernel::stack`).
    pub stack: Option<&'static dyn StackSource>,
}

impl ContainerEntry {
    /// A sandboxed (unprivileged) container entry.
    pub const fn user(f: extern "C-unwind" fn(usize), priority: u8, stack: &'static dyn StackSource) -> Self {
        ContainerEntry { user_entry: Some(f), entry: None, arg: 0, priority, stack: Some(stack) }
    }

    /// A privileged (trusted-but-isolated) container entry.
    pub const fn privileged(f: fn(usize), priority: u8, stack: &'static dyn StackSource) -> Self {
        ContainerEntry { user_entry: None, entry: Some(f), arg: 0, priority, stack: Some(stack) }
    }
}

/// A static container declaration.
#[derive(Copy, Clone)]
pub struct ContainerDecl {
    /// The isolation core: an existing [`DomainDecl`] (a `DomainSpec` + device grants).
    pub domain: DomainDecl,
    pub entry: ContainerEntry,
    /// Semantic version of the workload (for attestation / update policy).
    pub version: u32,
    /// CPU budget (None = best-effort under the priority ceiling only).
    pub cpu: Option<CpuBudget>,
    /// Static RAM the container draws from (stacks + pools), for the footprint check.
    pub ram_bytes: u32,
    pub on_fault: OnFault,
    /// Measurement of the workload image (all-zero = not measured), for attestation.
    pub image_hash: [u8; 32],
}

impl ContainerDecl {
    pub fn name(&self) -> &'static str {
        self.domain.spec.name
    }
}

/// The set of containers for a device, plus which one supervises the rest.
#[derive(Copy, Clone)]
pub struct ContainerManifest {
    pub containers: &'static [ContainerDecl],
    /// Supervisor container name (holds restart authority); `None` = the kernel domain.
    pub supervisor: Option<&'static str>,
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Compile-time validation of a container manifest. Use in a `const` item so a policy
/// violation fails the build:
///
/// ```ignore
/// const _: () = container::validate_containers(&MANIFEST);
/// ```
///
/// Checks (on top of the per-domain checks in
/// [`manifest::validate`](crate::security::manifest::validate), which callers run on the
/// embedded [`DomainDecl`]s): soft CPU budgets sum to at most one window; the supervisor
/// names a declared container; declared RAM fits; a sandboxed domain has a user entry and
/// an isolated one a privileged entry.
pub const fn validate_containers(m: &ContainerManifest) {
    let cs = m.containers;
    assert!(cs.len() <= MAX_DOMAINS, "containers: too many");
    // Soft CPU budgets must not exceed 100% of their window.
    // (Scaled to permille to stay in integer arithmetic.)
    let mut soft_permille: u64 = 0;
    let mut hard_permille: u64 = 0;
    let mut i = 0;
    while i < cs.len() {
        let c = &cs[i];
        assert!(c.entry.priority >= 1 && c.entry.priority <= MAX_PRIORITY, "container: bad entry priority");
        assert!(c.entry.priority <= c.domain.spec.priority_ceiling, "container: entry priority exceeds the domain priority ceiling");
        // Sandboxed (hardware_isolated) → user entry; otherwise → privileged entry.
        if c.domain.spec.hardware_isolated {
            assert!(c.entry.user_entry.is_some() && c.entry.entry.is_none(), "sandboxed container needs a user entry");
        } else {
            assert!(c.entry.entry.is_some() && c.entry.user_entry.is_none(), "isolated container needs a privileged entry");
        }
        if let Some(b) = c.cpu {
            assert!(b.period_ms > 0 && b.micros > 0, "container: bad cpu budget");
            assert!(b.micros as u64 <= b.period_ms as u64 * 1000, "container: cpu budget exceeds its window");
            let permille = b.micros as u64 * 1000 / (b.period_ms as u64 * 1000);
            if b.partitioned {
                hard_permille += permille; // reserved windows must fit one major frame
            } else {
                soft_permille += permille;
            }
        }
        // Unique container names.
        let mut j = i + 1;
        while j < cs.len() {
            assert!(!str_eq(c.domain.spec.name, cs[j].domain.spec.name), "container: duplicate name");
            j += 1;
        }
        i += 1;
    }
    // Reserved (partitioned) windows plus soft budgets together must fit the CPU.
    assert!(hard_permille <= 1000, "container: partitioned CPU windows over-commit the major frame");
    assert!(soft_permille + hard_permille <= 1000, "container: total CPU budgets (soft + partitioned) exceed 100%");
    // Supervisor, if named, must be a declared container.
    if let Some(sup) = m.supervisor {
        let mut found = false;
        let mut i = 0;
        while i < cs.len() {
            if str_eq(cs[i].domain.spec.name, sup) {
                found = true;
            }
            i += 1;
        }
        assert!(found, "container: supervisor names an undeclared container");
    }
}

/// A started container, wrapping the domain it owns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ContainerId(pub DomainId);

/// Health snapshot for a watchdog/supervisor or for attestation/telemetry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Health {
    /// Any live task in the domain.
    pub running: bool,
    /// Domain generation (increments on every restart).
    pub generation: u16,
    /// Policy violations recorded against the domain.
    pub violations: u32,
    /// Hardware protection (MPU) faults.
    pub faults: u32,
    /// Total CPU ticks consumed by the container's tasks (for budget accounting).
    pub cpu_ticks: u64,
}

/// The installed containers, indexed by domain id, so lifecycle calls can find a
/// container's declaration (entry, fault policy, budget).
static TABLE: IrqCell<[Option<&'static ContainerDecl>; MAX_DOMAINS]> = IrqCell::new([None; MAX_DOMAINS]);

/// Longest container hostname (the UTS-namespace value).
const HOSTNAME_MAX: usize = 32;

/// Per-container supervisor state (desired-running + restart bookkeeping per fault window) plus
/// the per-container namespace/cgroup values a container runtime keeps in the kernel.
#[derive(Copy, Clone, Default)]
struct RunState {
    /// The supervisor wants this container running (set by `start`, cleared by `stop` and by
    /// a crash-loop / `Stop` policy).
    desired: bool,
    /// Restarts performed in the current fault window.
    restarts: u8,
    /// Tick at which the current fault window started.
    window_start: u64,
    /// UTS namespace: the container's hostname (`hostname_len` 0 = defaults to its name).
    hostname: [u8; HOSTNAME_MAX],
    hostname_len: u8,
    /// Memory cgroup: bytes currently charged (the `memory.current` analog; the limit is the
    /// declaration's `ram_bytes`, i.e. `memory.max`).
    mem_used: u32,
}
static STATE: IrqCell<[RunState; MAX_DOMAINS]> = IrqCell::new(
    [RunState { desired: false, restarts: 0, window_start: 0, hostname: [0; HOSTNAME_MAX], hostname_len: 0, mem_used: 0 }; MAX_DOMAINS],
);

/// Domain id of the supervisor container (it is not itself supervised). `None` = kernel domain.
static SUPERVISOR: IrqCell<Option<u8>> = IrqCell::new(None);
/// Set if any container's `OnFault::Halt` fired (a board/system policy can poll this).
static HALTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    TABLE.lock(|t| *t = [None; MAX_DOMAINS]);
    STATE.lock(|s| *s = [RunState::default(); MAX_DOMAINS]);
    SUPERVISOR.lock(|s| *s = None);
    HALTED.store(false, core::sync::atomic::Ordering::Relaxed);
}

/// Create every declared container's domain and device grants, record the containers,
/// then [`seal`](crate::security::seal) the security configuration. Devices referenced by
/// grants must already be registered. Kernel domain only.
pub fn install(m: &'static ContainerManifest) -> Result<(), Error> {
    if !current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    for c in m.containers {
        let id = super::create_domain(c.domain.spec)?;
        for g in c.domain.grants {
            let dev = crate::driver::Device::find(g.device)?;
            super::grant_device(id, dev, g.rights, g.name)?;
        }
        TABLE.lock(|t| t[id.0 as usize] = Some(c));
        // Push the CPU budget down to the scheduler (L1), converting µs/ms → ticks.
        if let Some(b) = c.cpu {
            let hz = crate::config::TICK_HZ as u64;
            let budget_ticks = (b.micros as u64 * hz / 1_000_000).max(1) as u32;
            let window_ticks = crate::kernel::time::ms_to_ticks(b.period_ms as u64).max(1) as u32;
            crate::kernel::with(|k| k.set_domain_budget(id.0, budget_ticks, window_ticks));
        }
    }
    if let Some(name) = m.supervisor {
        if let Some(d) = super::find_domain(name) {
            SUPERVISOR.lock(|s| *s = Some(d.0));
        }
    }
    super::seal()
}

fn with_decl<R>(c: ContainerId, f: impl FnOnce(&'static ContainerDecl) -> R) -> Result<R, Error> {
    TABLE.lock(|t| t[c.0.0 as usize]).map(f).ok_or(Error::NotFound)
}

/// Find an installed container by name.
pub fn find(name: &str) -> Option<ContainerId> {
    let d = super::find_domain(name)?;
    TABLE.lock(|t| t[d.0 as usize].is_some()).then_some(ContainerId(d))
}

/// Visit every installed container (id + its static declaration), in domain order. Lets a
/// control plane (e.g. the serial shell) enumerate the workload set without a heap.
pub fn for_each<F: FnMut(ContainerId, &'static ContainerDecl)>(mut f: F) {
    let snapshot = TABLE.lock(|t| *t);
    for (i, slot) in snapshot.iter().enumerate() {
        if let Some(decl) = slot {
            f(ContainerId(DomainId(i as u8)), decl);
        }
    }
}

/// Spawn the container's root task into its domain.
pub fn start(c: ContainerId) -> Result<(), Error> {
    if !current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    let decl = with_decl(c, |d| d)?;
    let e = &decl.entry;
    let stack = e.stack.ok_or(Error::Invalid)?.claim().ok_or(Error::Busy)?;
    let builder = task::Builder::new(decl.name()).priority(e.priority).domain(c.0).stack_ref(stack).detached(true);
    let r = match (e.user_entry, e.entry) {
        (Some(f), None) => builder.spawn_user(f, e.arg).map(|_| ()),
        (None, Some(f)) => builder.spawn(f, e.arg).map(|_| ()),
        _ => Err(Error::Invalid),
    };
    if r.is_ok() {
        STATE.lock(|s| s[c.0.0 as usize].desired = true);
    }
    r
}

/// Terminate every task of the container, keeping its declaration so it can be
/// restarted. Idempotent.
pub fn stop(c: ContainerId) -> Result<(), Error> {
    with_decl(c, |_| ())?;
    STATE.lock(|s| s[c.0.0 as usize].desired = false);
    super::kill(c.0)
}

/// `stop` then `start`.
pub fn restart(c: ContainerId) -> Result<(), Error> {
    stop(c)?;
    start(c)
}

/// Current health of a container.
pub fn health(c: ContainerId) -> Result<Health, Error> {
    with_decl(c, |_| ())?;
    let d = c.0.0;
    let (running, cpu_ticks) = crate::kernel::with(|k| {
        let mut running = false;
        let mut ticks = 0u64;
        for t in k.tasks.iter() {
            if t.domain == d && !matches!(t.state, crate::TaskState::Free) {
                ticks += t.run_ticks;
                if !matches!(t.state, crate::TaskState::Dead) {
                    running = true;
                }
            }
        }
        (running, ticks)
    });
    Ok(Health {
        running,
        generation: super::domain_generation(c.0),
        violations: super::violations(c.0),
        faults: super::faults(c.0),
        cpu_ticks,
    })
}

/// The CPU budget declared for a container, if any.
pub fn budget(c: ContainerId) -> Result<Option<CpuBudget>, Error> {
    with_decl(c, |d| d.cpu)
}

/// Suspend a container's tasks (its time-partition window closes): they stop running until
/// [`resume`]. The temporal-isolation primitive for partitioned containers (a frame governor
/// resumes exactly one partition at a time). Trusted callers only.
pub fn suspend(c: ContainerId) -> Result<(), Error> {
    if !current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    with_decl(c, |_| ())?;
    crate::kernel::with(|k| k.suspend_domain(c.0.0));
    Ok(())
}

/// Resume a suspended container's tasks (its partition window opens). Trusted callers only.
pub fn resume(c: ContainerId) -> Result<(), Error> {
    if !current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    with_decl(c, |_| ())?;
    crate::kernel::with(|k| k.resume_domain(c.0.0));
    Ok(())
}

/// Ticks the container has consumed in its current CPU-budget window (0 if it has no budget).
/// The scheduler throttles the container for the rest of the window once this reaches its
/// budget (see [`CpuBudget`]).
pub fn cpu_used(c: ContainerId) -> u32 {
    crate::kernel::with(|k| k.domain_cpu_used(c.0.0))
}

// ----- namespaces & cgroups: the per-container kernel constructs a container runtime relies on
// (the capability model and the CPU budget / task quota already cover caps, `cgroup cpu` and
// `cgroup pids`; these add the UTS namespace, an explicit PID namespace, and the memory cgroup).

/// UTS namespace: set the container's hostname (truncated to `HOSTNAME_MAX`). Trusted only.
pub fn set_hostname(c: ContainerId, name: &str) -> Result<(), Error> {
    if !current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    with_decl(c, |_| ())?;
    let b = name.as_bytes();
    let n = b.len().min(HOSTNAME_MAX);
    STATE.lock(|s| {
        let st = &mut s[c.0.0 as usize];
        st.hostname[..n].copy_from_slice(&b[..n]);
        st.hostname_len = n as u8;
    });
    Ok(())
}

/// UTS namespace: copy the container's hostname into `out`, returning its length. Falls back to
/// the container's declared name if none was set.
pub fn hostname(c: ContainerId, out: &mut [u8]) -> Result<usize, Error> {
    let (buf, len) = STATE.lock(|s| {
        let st = &s[c.0.0 as usize];
        (st.hostname, st.hostname_len as usize)
    });
    if len > 0 {
        let n = len.min(out.len());
        out[..n].copy_from_slice(&buf[..n]);
        Ok(n)
    } else {
        let name = with_decl(c, |d| d.name())?;
        let n = name.len().min(out.len());
        out[..n].copy_from_slice(&name.as_bytes()[..n]);
        Ok(n)
    }
}

/// PID namespace: the number of live (non-`Free`) tasks belonging to the container.
pub fn task_count(c: ContainerId) -> usize {
    let d = c.0.0;
    crate::kernel::with(|k| k.tasks.iter().filter(|t| t.domain == d && !matches!(t.state, crate::TaskState::Free)).count())
}

/// PID namespace: fill `out` with the [`TaskId`]s of the container's live tasks, returning how
/// many were written — a container enumerates only its *own* processes, never a sibling's.
pub fn tasks(c: ContainerId, out: &mut [crate::TaskId]) -> usize {
    let d = c.0.0;
    crate::kernel::with(|k| {
        let mut n = 0;
        for (i, t) in k.tasks.iter().enumerate() {
            if n >= out.len() {
                break;
            }
            if t.domain == d && !matches!(t.state, crate::TaskState::Free) {
                out[n] = crate::kernel::task::TaskId::new(i as u8, t.generation);
                n += 1;
            }
        }
        n
    })
}

/// Memory cgroup: the container's memory limit in bytes (`memory.max`), from its declaration.
pub fn mem_limit(c: ContainerId) -> Result<u32, Error> {
    with_decl(c, |d| d.ram_bytes)
}

/// Memory cgroup: bytes currently charged to the container (`memory.current`).
pub fn mem_used(c: ContainerId) -> u32 {
    STATE.lock(|s| s[c.0.0 as usize].mem_used)
}

/// Memory cgroup: charge `bytes` to the container, refusing (with [`Error::NoResources`]) if it
/// would exceed the limit — the enforcement point a container's allocator/pool calls before
/// handing out memory. A limit of 0 means unlimited.
pub fn charge_mem(c: ContainerId, bytes: u32) -> Result<(), Error> {
    let limit = mem_limit(c)?;
    STATE.lock(|s| {
        let st = &mut s[c.0.0 as usize];
        let next = st.mem_used.saturating_add(bytes);
        if limit != 0 && next > limit {
            return Err(Error::NoResources);
        }
        st.mem_used = next;
        Ok(())
    })
}

/// Memory cgroup: release `bytes` previously charged to the container.
pub fn uncharge_mem(c: ContainerId, bytes: u32) {
    STATE.lock(|s| {
        let st = &mut s[c.0.0 as usize];
        st.mem_used = st.mem_used.saturating_sub(bytes);
    });
}

/// One window of an ARINC-653 major frame: a partition (container) and the length of its slot.
#[derive(Copy, Clone, Debug)]
pub struct Window {
    pub container: ContainerId,
    /// Length of this partition's window, in scheduler ticks.
    pub ticks: u32,
}

/// Run partitions as a repeating ARINC-653 **major frame** for `cycles` iterations (use
/// [`run_major_frame`] for an endless module scheduler). Builds strict temporal partitioning on
/// [`suspend`]/[`resume`]: every partition starts suspended, then each window in turn resumes its
/// partition for `ticks`, sleeps, and suspends it again before the next window — so at any instant
/// at most one partition's tasks are runnable. Call from a task whose priority is **above** every
/// partition's ceiling, so it reliably reclaims the CPU at each window boundary. Trusted only.
pub fn run_frames(frame: &[Window], cycles: usize) -> Result<(), Error> {
    if !current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    for w in frame {
        suspend(w.container)?;
    }
    for _ in 0..cycles {
        for w in frame {
            resume(w.container)?;
            crate::kernel::task::sleep_ticks(w.ticks as u64);
            suspend(w.container)?;
        }
    }
    Ok(())
}

/// The endless ARINC-653 module scheduler: cycle `frame`'s windows forever. Never returns.
/// Trusted only (if the caller is not trusted it idles rather than running unpartitioned).
pub fn run_major_frame(frame: &'static [Window]) -> ! {
    let _ = run_frames(frame, usize::MAX);
    loop {
        crate::kernel::task::sleep_ticks(u32::MAX as u64);
    }
}

/// Supervisor sweep (the kubelet analog): react to every container that should be running but
/// is not, per its [`OnFault`] policy. The supervisor container calls this periodically (or
/// the kernel does). Returns how many containers it acted on. Trusted callers only.
///
/// * `Restart { max, window_ms }` — re-run in a freshly reset domain, up to `max` times per
///   window; a crash loop past `max` gives up (leaves it stopped), bounding the blast radius.
/// * `Stop` — leave it dead. `Notify` — stop and let higher policy decide. `Halt` — set the
///   system halt flag ([`halted`]).
///
/// A sibling container is never touched, so one workload's crash loop cannot starve another.
pub fn supervise() -> usize {
    if !current_is_trusted() {
        return 0;
    }
    let sup = SUPERVISOR.lock(|s| *s);
    let now = crate::kernel::time::ticks();
    let mut acted = 0usize;
    for i in 0..MAX_DOMAINS {
        if Some(i as u8) == sup {
            continue; // the supervisor does not supervise itself
        }
        let Some(decl) = TABLE.lock(|t| t[i]) else {
            continue;
        };
        if !STATE.lock(|s| s[i].desired) {
            continue;
        }
        let c = ContainerId(DomainId(i as u8));
        if health(c).map(|h| h.running).unwrap_or(false) {
            continue; // healthy
        }
        match decl.on_fault {
            OnFault::Restart { max, window_ms } => {
                let window = crate::kernel::time::ms_to_ticks(window_ms as u64);
                let count = STATE.lock(|s| {
                    if now.saturating_sub(s[i].window_start) > window {
                        s[i].window_start = now;
                        s[i].restarts = 0;
                    }
                    s[i].restarts
                });
                if count < max {
                    if restart(c).is_ok() {
                        STATE.lock(|s| s[i].restarts += 1);
                        acted += 1;
                    }
                } else {
                    STATE.lock(|s| s[i].desired = false); // crash loop: give up
                    acted += 1;
                }
            }
            OnFault::Stop => {
                STATE.lock(|s| s[i].desired = false);
                acted += 1;
            }
            OnFault::Notify => {
                STATE.lock(|s| s[i].desired = false);
                acted += 1;
            }
            OnFault::Halt => {
                HALTED.store(true, core::sync::atomic::Ordering::Relaxed);
                STATE.lock(|s| s[i].desired = false);
                acted += 1;
            }
        }
    }
    acted
}

/// Whether an `OnFault::Halt` has fired (a board/system fault policy can poll this).
pub fn halted() -> bool {
    HALTED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Restarts performed for a container in its current fault window (for health/telemetry).
pub fn restart_count(c: ContainerId) -> u32 {
    STATE.lock(|s| s[c.0.0 as usize].restarts as u32)
}

/// Measure a container manifest into a PCR (extend it with [`manifest_hash`]), so a later
/// [`quote`](crate::security::trust::RootOfTrust::quote) attests exactly which container graph
/// is running — the image-provenance box, bound to the root of trust. (feature `tpm`)
#[cfg(feature = "tpm")]
pub fn measure_manifest(m: &ContainerManifest, root: &dyn crate::security::trust::RootOfTrust, pcr: usize) -> Result<(), Error> {
    root.extend(pcr, &manifest_hash(m))
}

/// A SHA-256 measurement of the whole container manifest — the OCI-image-digest analog, as a
/// single provenance value for attestation (its claims are the per-container versions and
/// image hashes plus the capability graph). Deterministic: any change to a `ContainerDecl`
/// (version, image hash, spec, grants) or the supervisor changes the hash. (feature `crypto`)
#[cfg(feature = "crypto")]
pub fn manifest_hash(m: &ContainerManifest) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for c in m.containers {
        h.update(c.name().as_bytes());
        h.update([0u8]); // field separator
        h.update(c.version.to_le_bytes());
        h.update(c.image_hash);
        let spec = &c.domain.spec;
        h.update([spec.hardware_isolated as u8, spec.priority_ceiling, spec.max_tasks]);
        h.update(spec.syscalls.to_le_bytes());
        for g in c.domain.grants {
            h.update(g.device.as_bytes());
            h.update([0u8]);
            h.update(g.name.as_bytes());
            h.update(g.rights.0.to_le_bytes());
        }
    }
    if let Some(s) = m.supervisor {
        h.update(s.as_bytes());
    }
    h.finalize().into()
}
