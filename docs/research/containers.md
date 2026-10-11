# Bismuth Containers: What a "Container" Means on an MMU-less MCU, and How to Build One on Domains

> Status: research and design proposal, not yet implemented.
> Scope: what "container support" can and cannot mean for a `no_std` RTOS on Cortex-M/RISC-V
> MCUs with tens-to-hundreds of KB of RAM, an MPU/PMP but **no MMU**, no filesystem and no
> dynamic loader by default; how Linux containers, ARINC 653 partitions, AUTOSAR
> OS-Applications, Tock processes/TBF, Hubris tasks, Zephyr user mode, TF-M secure partitions
> and WebAssembly sandboxes map onto that world; and an opinionated design for a Bismuth
> **Container** built as a thin packaging/lifecycle layer over the existing **domain**.
>
> This builds directly on [research/security.md](security.md) and the implemented
> [design/security.md](../design/security.md). Read those first. The short version of the
> baseline: Bismuth already has the isolation primitive. `src/security/mod.rs` gives us
> domains (`DomainId`, `DomainSpec`), per-domain handle tables with monotonic `Rights`,
> generation-based revocation, a per-domain syscall allow-mask, per-domain `NetPolicy`,
> `seal`/`restrict`, `kill` (now trusted-only, re-deriving the DRBG and purging keystore
> slots), and `DomainSpec::sandboxed` + `Builder::spawn_user` for hardware-isolated
> (unprivileged, MPU-confined) tasks. `src/security/manifest.rs` declares domains + device
> grants and **validates the whole graph at compile time**. `src/security/entropy` gives each
> domain its own ChaCha20 DRBG, re-derived on (re)start. `src/security/keystore.rs` binds keys
> to their owning domain.

---

## 0. TL;DR

- **A "container" on Bismuth is not a new isolation mechanism. The domain already is the
  isolation mechanism.** A container is a *named, versioned, attestable bundle* = one
  `DomainSpec` + its device/key/socket grants + a CPU/RAM budget + its entropy context +
  a lifecycle/fault policy + an optional measured image hash. The isolation is 100% the
  existing domain machinery; "container" adds packaging, resource accounting, lifecycle
  (start/stop/restart/health) and attestation on top.
- **Most of Linux's container anatomy already exists in Bismuth, and the rest is either
  pointless without an MMU/filesystem or is a known Planned item.** seccomp ≈ the per-domain
  syscall allow-mask (done); capabilities ≈ per-handle `Rights` (done, finer-grained);
  user namespace ≈ the domain itself as the principal (done); net namespace ≈ `NetPolicy`
  (done); mount namespace ≈ the per-domain device namespace built from named grants (done);
  cgroups-pids ≈ `max_tasks` (done); cgroups-cpu ≈ priority ceiling now + a **CPU budget**
  to add (Planned); cgroups-memory ≈ static RAM allotment (done, static); rootfs image ≈ the
  firmware image + manifest now, a **signed app-bundle** later (Planned); the OCI
  digest/signature ≈ the manifest/image hash in a **PSA attestation token** (Planned).
  pid/uts/ipc namespaces are mostly meaningless here: there is no global namespace to
  partition, because the domain *is* the boundary.
- **Best-fit model for Bismuth's edge-compute goal is a blend, phased.** Take Hubris's
  static tasks + supervisor + build-time graph (Bismuth already does this), add ARINC 653's
  resource/time-partitioning and health-monitor/restart discipline as an *option* for
  hard-RT isolation, and reserve Tock's TBF-style **signed, MPU-isolated, independently
  updatable app-bundle** for the later "ship/update a workload" phase. WebAssembly (WAMR/
  wasmi) is a useful *software* sandbox tier for MPU-less cores, but with honest caveats on
  code size and speed; it is a fallback, not the primary model.
- **Phase it: static containers first (a small layer over the existing manifest), loadable
  signed bundles later.** A static container ships *inside* the firmware image, is declared
  in a const manifest, checked at compile time, and started/supervised at boot. This gets
  90% of the value (isolated, budgeted, restartable, attestable workloads) with ~none of the
  TCB risk of a loader. Dynamic loading is the hard, optional, future tier.
- **Inter-container communication is only ever through explicitly granted shared objects:**
  a shared pipe/device handle, a socket under `NetPolicy`, a shared `NetRing` (needs `MAP` +
  one MPU region, Planned), or synchronous **IPC with leases** (Hubris model, research
  Phase 4, Planned). No ambient shared memory. For *sandboxed* containers this must go
  through the syscall boundary; a `&'static` `edge::Topic` is only a real boundary between
  privileged isolated domains, not unprivileged ones.
- **Be honest about the ceiling.** No MMU means no per-container virtual address space, no
  overcommit, no COW, no demand paging, no meaningful ASLR; memory is physically partitioned
  by a scarce MPU region budget (≈8 regions on ARMv7-M) and fixed at build time. No
  filesystem means "image/rootfs/volumes" collapse to the firmware image plus a device
  namespace. The defining Linux feature — run an arbitrary image pulled at run time — needs
  the signed-app-bundle tier and is genuinely expensive. A Bismuth container is closer to an
  **ARINC 653 partition** or a **Tock app** than to a Docker container, and we should say so.

---

## 1. What a container is, and what survives the trip to an MCU

A Linux container is not one thing; it is a convention made of six independent kernel
features plus an image format and a runtime:

1. **Namespaces** (`pid`, `net`, `mount`, `user`, `uts`, `ipc`, `cgroup`, `time`): give a
   process group a private view of a global resource.
2. **cgroups v2** (`cpu`, `memory`, `pids`, `io`, …): bound how much of a resource the group
   may consume.
3. **Capabilities** (`CAP_NET_ADMIN`, …): split root's ambient authority into ~40 bits.
4. **seccomp-bpf**: a per-process syscall filter.
5. **A root filesystem image** (OCI layers): the code and data the container sees as `/`.
6. **A runtime** (runc/containerd/Kubelet): pulls the image, verifies its digest/signature,
   sets up 1–5, starts PID 1, and supervises it.

Each of these answers a question that *also* exists on an MCU — "what can this workload see,
how much can it use, what may it call, where does its code come from, who restarts it when it
dies" — even though the *implementation* assumes an MMU, gigabytes of RAM, a VFS and a
dynamic loader. The useful exercise is to keep the questions and drop the implementations.

### 1.1 Linux container anatomy → Bismuth

| Linux piece | What it isolates/limits | Bismuth equivalent | Status in Bismuth |
|---|---|---|---|
| **user namespace** | uid/gid mapping; "who am I" | The **domain** is the principal (`DomainId`, `Caller.domain`). There are no uids; authority is the handle table, not an identity. | **Done** (domains *are* the user-ns analogue) |
| **mount namespace** | private filesystem view | **Per-domain device namespace**: `DeviceCap::open("/dev/x")` resolves names only in the caller's handle table (`HandleTable::find_name`); a device granted under an alias is invisible by its real name. No VFS, so this *is* the "root fs view". | **Done** |
| **net namespace** | private network stack | Per-domain `NetPolicy { local_ports, peers, listen }` enforced in the socket layer at bind/connect (`check_net`). Could add per-domain interface binding. | **Done** (policy), interface binding Planned |
| **pid namespace** | private PID numbering | Tasks carry `Tcb.domain`; cross-domain task control (`suspend`/`set_priority`/`kill`) requires a trusted caller (`check_task_control`). PID *renumbering* is pointless (no global pid space leaks across a kernel this small). | **Done** (scoping), renumbering **N/A** |
| **uts / ipc namespace** | hostname / SysV IPC | No hostname; no global SysV IPC table to hide. IPC is capability-routed (you can only talk to objects you hold a handle to), which is stronger than hiding a namespace. | **N/A by design** |
| **cgroup cpu** | `cpu.max`, weights | `priority_ceiling` caps urgency today; a real **`CpuBudget`** (µs per window, sporadic-server / ARINC-653-slice) is the missing piece (research Phase 3). | Ceiling **Done**; budget **Planned** |
| **cgroup memory** | `memory.max` | No heap, no overcommit: RAM is *statically* partitioned. A container's footprint is its task stacks + kernel tables, fixed at build and checked by the manifest. | **Done (static)** |
| **cgroup pids** | `pids.max` | `DomainSpec::max_tasks`, enforced in `check_spawn`. | **Done** |
| **cgroup io** | per-device bandwidth | Per-caller rate-limit middleware (research `PerCaller<RateLimit>`); `Stats`/`RateLimit` already exist as layers. | Partial (middleware) |
| **capabilities** | split ambient root | Per-handle `Rights` (READ/WRITE/TRANSFER/CONTROL/CONFIG/POWER/DUPLICATE/MANAGE/INSPECT/K_*). Monotonic (only shrink), generation-checked, no ambient authority for isolated domains. Finer and safer than CAP_* bits. | **Done** |
| **seccomp-bpf** | syscall filter | `DomainSpec.syscalls` allow-mask, one bit per syscall, checked in `syscall::dispatch`; a disallowed call is a violation that kills the domain under `Kill` policy. ~12 syscalls today. | **Done** |
| **rootfs / OCI image** | the code + data | The **firmware image** (static containers live inside it) + the manifest. Later: a **signed app-bundle** (Tock-TBF-style) for code shipped/updated independently. No union mounts, no volumes beyond granted device handles. | Static **Done**; bundle **Planned** |
| **image digest + signature** | provenance / integrity | The **manifest hash** + per-container `image_hash`/`version`, surfaced as claims in a **PSA/EAT attestation token** (research §8, DICE). Signed bundles verified via keystore `K_VERIFY`. | **Planned** |
| **runtime (runc/kubelet)** | setup + supervision | `manifest::apply` + `seal` set up the graph at boot today; a **supervisor domain** + a small container registry add start/stop/restart/health. | apply/seal **Done**; supervisor **Planned** |

The headline: **the isolation and policy columns are overwhelmingly already built.** What
"container support" adds is the *accounting* (CPU budget), the *lifecycle* (supervisor,
restart, health), the *packaging* (a named bundle tying a domain to its grants + budget +
entropy + keys + entry), and the *provenance* (attested manifest/image hash). None of that is
a new isolation boundary; it is management around the existing boundary.

### 1.2 What genuinely cannot (or need not) exist here

- **No per-container address space, overcommit, COW, demand paging, ASLR.** The MMU features
  that make Linux containers cheap and dense are absent. Memory is physically partitioned by
  MPU regions, which are *scarce* (0/8 on ARMv7-M, up to 16 on ARMv8-M, 16–64 PMP entries on
  RISC-V) and *global*. A sandboxed container today costs essentially two MPU regions (its
  code view + its own stack; see design/security.md "What a user task may touch"), leaving
  room for very few per-container device/shared-memory windows. This is the hard ceiling and
  the manifest checker must enforce it.
- **No filesystem.** "Image", "layers", "volumes", "bind mounts" have no VFS to live in. The
  device namespace replaces the mount namespace; the firmware image replaces the rootfs.
- **No dynamic loader by default.** Linux's defining trick — pull an arbitrary image and run
  it — requires a loadable, relocatable or fixed-slot, signed, MPU-isolated app-bundle and a
  loader in the TCB. That is the optional Phase 3 tier (§5.6), not the baseline.
- **pid/uts/ipc namespaces** have nothing to isolate: there is no multi-tenant global
  namespace that leaks between workloads. Capability routing already prevents a container
  from naming anything it was not granted.

So a Bismuth container is honestly a **statically-sized, capability-confined, resource-budgeted,
supervised workload partition** — much closer to an ARINC 653 partition or a Tock app than to
a Docker container. The value proposition for "edge compute" is real nonetheless: ship an
isolated sense→process→publish workload, give it a CPU/RAM budget, restart it when it faults
without taking down the device, and attest exactly what is running.

---

## 2. RTOS / embedded comparators: which model fits "ship and update an isolated workload"

### 2.1 ARINC 653 partitions (avionics IMA)

- **Model:** the OS presents *partitions*, each with a fixed **spatial** allocation (its own
  memory, enforced by the MPU/MMU) and a fixed **temporal** allocation: a cyclic **major
  frame** divided into **minor frames/windows**, one or more per partition. The partition
  scheduler is a strict time-triggered table; *within* a window the partition schedules its
  own processes by priority. A **health monitor** catches faults and applies a configured
  recovery (restart process/partition, or escalate to the module level). Ports (sampling/
  queuing) are the only inter-partition channel.
- **Fit for Bismuth:** this is the gold standard for *hard* real-time isolation and is the
  model to borrow for two things: (a) an *optional* **time partition** (a fixed CPU window a
  container cannot overrun and no other container may steal) layered above the existing
  fixed-priority scheduler, and (b) the **health-monitor + configured restart** discipline
  for the supervisor. Bismuth's default scheduler (O(1) priority, preemptive) is not time-
  triggered; a true ARINC frame is a two-level scheduler change, so offer it feature-gated
  for safety-critical single-purpose devices, with soft CPU budgets as the default.

### 2.2 AUTOSAR OS / OS-Applications (automotive)

- **Model:** an **OS-Application** is a group of tasks/ISRs/alarms with a trust level
  (trusted vs non-trusted), MPU-enforced memory protection, and a service-protection
  allow-list ("which OS services may this application call"). Timing protection bounds
  execution/budget. Very close conceptually to Bismuth's trusted/isolated domain split plus
  the syscall allow-mask plus a CPU budget.
- **Fit:** confirms the design direction (trust tier + memory protection + service allow-list
  + timing budget per application). Nothing new to copy beyond validation of the approach;
  the terminology ("application" = a bundle of tasks with a policy) is almost exactly a
  Bismuth container.

### 2.3 Tock OS: processes and the TBF app-bundle

- **Model:** Tock has a two-tier split — trusted *capsules* in safe Rust inside the kernel
  (Bismuth's drivers/middleware are exactly this) and untrusted **processes**, any language,
  **MPU/PMP-isolated**, **loaded separately from the kernel**. A process is shipped as a
  **Tock Binary Format (TBF)** object: a header (version, entry, required flash/RAM, a
  writeable/readable TLV of metadata and permissions) + the code, written to flash and
  discovered at boot or installed at run time. Grants let a capsule store per-process state
  *inside* the process's own RAM, reclaimed automatically when the process dies.
- **Fit:** TBF is the reference design for Bismuth's **loadable, independently-updatable,
  signed app-bundle** (Phase 3). Its header is the template for a Bismuth bundle header
  (entry, stack size, MPU alignment, the *requested* capability/grant set that the loader
  checks against a declared ceiling). Tock proves this is tractable on Cortex-M with an MPU
  — and also shows the cost: a loader/parser in the TCB, and v7-M power-of-two MPU alignment
  forcing either position independence or fixed slots.

### 2.4 Hubris (Oxide): static tasks + supervisor

- **Model:** the task set is **fixed at build time** (`app.toml`); no run-time task
  creation; tasks are unprivileged, MPU-isolated in non-overlapping regions; the kernel does
  no drivers; IPC is synchronous send/recv/reply with **leases** (borrowed, bounds-checked
  memory, revoked on reply); task **generations** bump on restart and are checked on IPC; a
  priority-0 **supervisor** task handles faults and restarts; IRQs arrive as notification
  bits. Admitted gap: "no capabilities".
- **Fit:** Bismuth already *is* Hubris-plus-capabilities for the static case (compile-time
  manifest, generations, `kill`, notifications). Copy the **supervisor** and **restart**
  model wholesale for container lifecycle, and the **leases** for inter-container IPC
  (research Phase 4). This is the near-term backbone.

### 2.5 Zephyr user mode + "application" isolation

- **Model:** user threads start with **no** permission on any kernel object; permissions are
  granted per object by a supervisor thread; **memory domains/partitions** define accessible
  memory and are inherited by child threads; objects/stacks/drivers must be defined at build
  time. Explicitly out of scope: CPU-starvation DoS, misconfigured domains.
- **Fit:** validates per-object permission grants on MCUs (Bismuth's handles do this) and the
  memory-domain-as-inherited-boundary idea. Bismuth should beat Zephyr precisely on the DoS
  axis it declares out of scope, via the CPU budget + priority ceiling + `max_tasks`.

### 2.6 TF-M secure partitions (PSA FF-M)

- **Model:** on TrustZone-M, **secure partitions** are isolated services (L3: each partition
  isolated from the others) reached by PSA IPC across the secure/non-secure boundary; caller
  identity comes from the static system layout and cannot be spoofed; partitions are *library-
  model* (run-to-completion, no secure scheduler).
- **Fit:** the right home for a *security-sensitive* container (keystore, attestation) is a
  TF-M secure partition or a minimal Rust secure partition (research §9), not an ordinary NS
  domain. For most edge workloads, a Bismuth NS container is the unit; security services sit
  behind the TrustZone boundary. Caller-identity-from-layout is exactly Bismuth's unforgeable
  `Caller`.

### 2.7 WebAssembly on MCUs (WAMR, wasmi): software sandboxing without an MPU

- **Model:** a Wasm runtime (interpreter or AOT) enforces memory safety *in software* — the
  module can only touch its own linear memory, and only imported host functions reach the
  outside. WAMR runs in tens of KB; wasmi is a pure-Rust interpreter. This gives a "container-
  like" sandbox **without** needing an MPU, and gives true portable, dynamically-loadable
  modules.
- **Fit:** a genuinely useful *optional* tier, for (a) cores with **no MPU** (where
  `spawn_user` cannot confine anything — see the STATUS.md gap: `spawn_user` runs unconfined
  on an MPU-less core), and (b) highly dynamic workloads where shipping a Wasm module beats a
  native bundle. Honest caveats: interpreter speed (10–50× native) or an AOT compiler (large
  TCB), code size for the runtime, and the fact that the runtime itself becomes TCB. Treat
  Wasm as a *second* container flavour (`ContainerKind::Wasm`) behind the same lifecycle/
  budget/attestation API, not the default. The MPU-backed native container remains primary
  where an MPU exists.

### 2.8 Verdict

For Bismuth's "edge compute, ship/update an isolated workload" goal:

- **Near term (static):** Hubris static tasks + supervisor + Bismuth's compile-time
  capability manifest, with an ARINC-653-flavoured **CPU budget** and **health/restart**
  policy, and an optional ARINC **time partition** for hard-RT isolation. This is a small,
  low-risk layer over what exists.
- **Later (dynamic, optional):** a Tock-TBF-style **signed, MPU-isolated app-bundle** for
  code updated independently of the kernel image, with provenance via DICE/PSA attestation.
- **Fallback tier (optional):** a **Wasm** container for MPU-less cores or portable modules.

---

## 3. The Bismuth Container concept

A **Container** is a named, versioned bundle that fully describes one isolated workload:

```
Container  =  DomainSpec                      (the isolation core — unchanged)
            + device grants                   (existing GrantDecl)
            + key grants                      (keystore handles, PSA attrs)
            + socket/net policy               (existing NetPolicy, already in DomainSpec)
            + CPU budget / time partition     (new: CpuBudget)
            + RAM allotment                   (static stacks; checked, not enforced by HW alloc)
            + entropy context                 (automatic: the domain's own DRBG)
            + an entry point + root stack      (what `start` spawns)
            + a lifecycle / fault policy      (new: OnFault, health)
            + a measured image hash + version (new: for attestation / update policy)
```

Every line except the last four already exists. The container type is the place that *ties
them together as a unit* so they can be declared, validated, started, supervised, updated and
attested together. Crucially: **the container owns exactly one domain.** One domain : one
container keeps the capability graph, the accounting and the restart semantics all aligned
with the primitive that already enforces isolation.

### 3.1 Static vs loadable: phase it

| | **Static container (Phase 1–2)** | **Loadable app-bundle (Phase 3, optional)** |
|---|---|---|
| Where the code lives | inside the firmware image | separate signed flash object (TBF-style) |
| When declared | compile time (`const` manifest) | run time, discovered or installed |
| Capability graph | fully checked at **build** time | checked at **load** time against a declared ceiling |
| TCB cost | ~none (const tables) | a loader/verifier/parser (fuzz target) |
| Update story | reflash the whole image (MCUboot) | update one bundle, anti-rollback counter |
| Risk | low | high (relocation, MPU alignment, loader bugs) |
| Recommendation | **do this first; it covers most of the value** | only when run-time update of one workload is a hard requirement |

Everything in §3.2–§3.6 is specified for the static case and designed so the loadable case
reuses the same `ContainerSpec`, lifecycle API, budgets and attestation — the only new thing
Phase 3 adds is *how the code and its requested capabilities arrive and are verified*.

### 3.2 Types: extending the real `DomainSpec`/`manifest`

These extend the **actual** types in `src/security/mod.rs` and `src/security/manifest.rs`.
Nothing here changes the isolation core; it wraps it.

```rust
// src/security/container.rs  (sketch; safe Rust, L3 services)

use crate::security::{DomainId, Rights};
use crate::security::manifest::{DomainDecl, GrantDecl};
#[cfg(feature = "crypto")]
use crate::security::keystore::KeyAttrs;

/// A CPU budget for a container (cgroup `cpu.max` / ARINC-653 window analogue), enforced in
/// the scheduler tick against per-domain run-time accounting.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CpuBudget {
    /// Replenishment window, in ms.
    pub period_ms: u32,
    /// CPU time the container may run per window, in µs.
    pub micros: u32,
    /// Hard time partition: `micros` is a *reserved* window no other container may use and
    /// this one may not overrun (ARINC 653). `false` = soft budget: unused slack is sharable
    /// and overrun only throttles (sporadic-server style).
    pub partitioned: bool,
}

/// What the supervisor does when a container's domain faults or exits abnormally.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OnFault {
    /// Re-run the entry in the same (freshly reset) domain; bump generation, re-derive DRBG.
    /// Give up after `max` restarts inside `window_ms` (crash-loop guard).
    Restart { max: u8, window_ms: u32 },
    /// Leave the domain dead. Peers' handles to its objects fail (BadHandle/PeerRestarted).
    Stop,
    /// Raise a notification to the supervisor container and let policy code decide.
    Notify,
    /// Escalate: apply the system fault policy (halt) — for single-function safety devices.
    Halt,
}

/// A key provisioned into the container's keystore namespace, named in its handle table.
#[cfg(feature = "crypto")]
#[derive(Copy, Clone, Debug)]
pub struct KeyGrantDecl {
    pub name: &'static str,  // e.g. "telemetry_aead"
    pub attrs: KeyAttrs,     // PSA type + usage policy (already validated by the keystore)
    pub rights: Rights,      // subset of K_ENCRYPT|K_DECRYPT|K_SIGN|K_VERIFY|K_DERIVE
}

/// Root task of the container: what `start()` spawns into the domain.
#[derive(Copy, Clone)]
pub struct ContainerEntry {
    /// Unprivileged entry (sandboxed container) — the common case for edge workloads.
    pub user_entry: Option<extern "C-unwind" fn(usize)>,
    /// Privileged entry (isolated-but-not-sandboxed container, software enforcement only).
    pub entry: Option<fn(usize)>,
    pub arg: usize,
    pub priority: u8,
    /// Root-task stack bytes (must be a power of two, aligned, for a user entry).
    pub stack_bytes: usize,
}

#[derive(Copy, Clone)]
pub enum ContainerKind {
    /// MPU-isolated native code (requires `hardware_isolated` domain + an MPU).
    Native,
    /// Software-sandboxed WebAssembly module (optional tier; MPU-less cores).
    #[cfg(feature = "wasm")]
    Wasm { module: &'static [u8] },
}

/// A static container: everything needed to run and supervise one workload as a unit.
#[derive(Copy, Clone)]
pub struct ContainerDecl {
    /// The isolation core: reuses the existing `DomainDecl` (a `DomainSpec` + device grants).
    pub domain: DomainDecl,
    pub kind: ContainerKind,
    pub entry: ContainerEntry,
    /// Semantic version of the workload, for attestation and update policy.
    pub version: u32,
    /// CPU budget / time partition (None = best-effort under the priority ceiling only).
    pub cpu: Option<CpuBudget>,
    /// Static RAM this container's tasks draw from (stacks + per-domain pools), for the
    /// build-time footprint check. Not a run-time allocator — Bismuth has no heap.
    pub ram_bytes: u32,
    #[cfg(feature = "crypto")]
    pub keys: &'static [KeyGrantDecl],
    pub on_fault: OnFault,
    /// Measurement of the workload image (0 = not measured yet). Reported in attestation.
    pub image_hash: [u8; 32],
}

/// The set of containers for a device, plus which one supervises the rest.
#[derive(Copy, Clone)]
pub struct ContainerManifest {
    pub containers: &'static [ContainerDecl],
    /// Name of the supervisor container (holds restart authority); None = the kernel domain.
    pub supervisor: Option<&'static str>,
}
```

Note `NetPolicy` is *already* a field of `DomainSpec`, so a container's socket policy needs
no new type — it rides along in `domain.spec.net`.

### 3.3 Compile-time validation: extend `manifest::validate`

The existing `manifest::validate` (a `const fn` used in a `const _: () = …` item so a policy
violation **fails the build**) already checks domain count, unique names, ceilings, quotas,
no `trusted`, no `K_EXPORT`/`MANAGE` in grants, unique grant names, and that the task quota
fits `MAX_TASKS`. Containers add, in the same `const fn` style:

```rust
pub const fn validate_containers(m: &ContainerManifest) {
    // 1. Reuse every existing domain/grant check by validating the embedded Manifest.
    //    (fewer than MAX_DOMAINS, unique names, ceilings, quotas, no trusted/K_EXPORT/MANAGE)

    // 2. CPU budgets: soft budgets sum to <= 100% of the window; partitioned windows are
    //    disjoint and their total <= one major frame.
    //    assert!(sum(micros/period for soft) <= period, "cpu budgets exceed 100%");
    //    assert!(sum(partition windows) <= MAJOR_FRAME_US, "time partitions overcommit the frame");

    // 3. RAM: sum(ram_bytes) + kernel tables <= configured RAM (config::*). Static only.

    // 4. Supervisor: `supervisor` names a declared container; it is the only container that
    //    may hold restart authority over the others.

    // 5. Key grants: each KeyGrantDecl's `rights` are a subset of what `attrs.usage` permits
    //    (reuse the keystore's existing usage/alg invariants). No K_EXPORT in a container.

    // 6. MPU feasibility: for Native containers, (code region + root stack + requested
    //    device/shared windows) fit the target's MPU region budget; stacks are power-of-two
    //    and aligned (the same rule `spawn_user` enforces at run time, moved to build time).

    // 7. Entry sanity: a `hardware_isolated` (sandboxed) domain has a `user_entry`, not a
    //    privileged `entry`, and vice-versa (mirrors `check_spawn`'s user/trusted rules).
}
```

Everything here is a `const` assertion: an over-budget, over-aligned or dangling-supervisor
manifest does not compile. This is the property the research doc argues Bismuth can have that
Linux/Zircon cannot — the whole multi-tenant graph is verified before the device ever boots.

### 3.4 Lifecycle API: start / stop / restart / health

A container's lifecycle maps onto operations Bismuth already has; the new module is mostly
glue + a supervisor.

```rust
/// A started container. Wraps the domain it owns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ContainerId(pub DomainId);

/// Create all declared domains + grants (this is `manifest::apply` extended with key grants
/// and budget registration), then `seal()`. Does not start tasks yet.
pub fn install(m: &ContainerManifest) -> Result<(), Error>;

/// Spawn the container's root task into its domain and begin accounting its budget.
pub fn start(c: ContainerId) -> Result<(), Error>;

/// Retire every task of the container (existing `security::kill`: empties the handle table,
/// bumps the generation, re-derives the DRBG, purges keystore slots), but keep its spec so
/// it can be restarted. Stopping is idempotent.
pub fn stop(c: ContainerId) -> Result<(), Error>;

/// stop + start. Because `kill` bumps the generation and `entropy::domain_created` clears the
/// per-domain DRBG, a restarted container never replays its random stream (already tested in
/// tests/security.rs::entropy_health_seeding_and_per_domain_streams), and stale handles held
/// by peers fail the generation check.
pub fn restart(c: ContainerId) -> Result<(), Error>;

/// Health snapshot for a watchdog/supervisor or for attestation/telemetry.
pub fn health(c: ContainerId) -> Health;

#[derive(Copy, Clone, Debug, Default)]
pub struct Health {
    pub running: bool,          // any live task in the domain
    pub generation: u16,        // security::domain_generation(d): increments per restart
    pub restarts: u16,          // supervisor-maintained
    pub violations: u32,        // security::violations(d)
    pub mpu_faults: u32,        // security::faults(d)
    pub cpu_micros_window: u32, // budget accounting (new)
    pub stack_free_min: usize,  // min over tasks of task::info(..).stack_free (watermark)
}
```

How each maps to existing code:

- **install** = `manifest::apply` (creates domains, `grant_device` for each `GrantDecl`)
  plus, for crypto containers, `keystore::import`/`generate` for each `KeyGrantDecl` into the
  owning domain, plus registering each `CpuBudget` — then `security::seal()`.
- **start** = `task::Builder::new(name).priority(p).domain(c.0).stack(..).spawn_user(entry)`
  (or `.spawn` for a privileged container). `check_spawn` already enforces the ceiling, the
  `max_tasks` quota and the sandboxed/user rules.
- **stop** = `security::kill(c.0)` — now trusted-only (`require_kernel`), already retires
  tasks, wakes joiners (`wake_joiners`), empties the handle table, bumps the generation,
  re-derives the DRBG (`entropy::domain_created`) and purges keystore slots
  (`keystore::purge_domain`). Containers make two documented `kill` gaps **must-fix**:
  releasing mutexes a killed task held, and (for robustness) accounting any pool stacks.
- **restart** relies on an existing subtlety: when a *trusted* domain spawns into a *killed*
  domain, `check_spawn` clears the `killed` flag ("explicit restart by the kernel"). So the
  supervisor re-spawning the entry is exactly the restart path, with a fresh generation.
- **health** composes `security::{violations, faults, domain_generation, is_killed}` +
  `task::list`/`task::info` stack watermarks + the new budget counter.

### 3.5 Resource accounting and enforcement

- **CPU (soft budget, default).** Add a per-domain `run_micros_window` counter, charged in
  the scheduler tick (the tick already runs; `TaskInfo.run_ticks` shows per-task accounting
  exists). When a container exceeds `micros` in the current `period_ms` window, its tasks are
  made ineligible until the window refills — a sporadic-server throttle, *not* a kill. This
  gives DoS resistance (the axis Zephyr declares out of scope) without hurting a well-behaved
  container. Refill on the window boundary.
- **CPU (hard time partition, option).** For `partitioned: true`, layer a top-level cyclic
  frame scheduler above the existing fixed-priority scheduler: the current window selects
  which container's tasks are runnable; inside the window the normal O(1) priority scheduler
  runs. This is the ARINC 653 model and a real (feature-gated) scheduler change — offer it
  for hard-RT single-purpose devices, keep soft budgets as the default. The manifest checker
  guarantees the windows fit the major frame.
- **RAM.** Static only: a container's stacks are declared and the manifest checks the sum
  fits. There is no run-time allocation to bound; the "limit" is enforced by the build, not
  by hardware at run time. (A future per-container pool could add run-time `mem::Pool`
  accounting, but that is not needed for the static model.)
- **Tasks/pids.** `max_tasks`, already enforced.
- **I/O.** Per-container device bandwidth via a `PerCaller<RateLimit>` middleware layer keyed
  on `Caller.domain` (the caller is unforgeable and already threaded through every request).
- **Entropy/keys.** Already per-domain: the DRBG is the container's entropy context, and keys
  are bound to the owning domain by the keystore. No extra accounting needed; draws are
  implicitly charged to the domain.

### 3.6 Inter-container communication

The rule is **capability routing only**: a container can reach another container exactly and
only through an object it was explicitly granted. No ambient shared memory, no global IPC
table. Options, cheapest/most-available first:

1. **Shared device/pipe handle (works today).** Register a `Pipe` (or any driver) in the
   kernel domain; grant container A a handle with `WRITE` and container B a handle with
   `READ` (possibly under different alias names). They communicate as `DeviceCap` I/O; the
   middleware chain and rights apply; a third container that was not granted the pipe cannot
   `open` it (namespace miss). This is the simplest inter-container channel and needs no new
   kernel code — only the grant wiring in the manifest.
2. **Sockets under `NetPolicy` (works today).** Two containers can talk over loopback or a
   `SoftRing`, each constrained by its own `local_ports`/`peers`/`listen` policy
   (demonstrated in tests/security.rs::per_domain_network_policy).
3. **Shared `NetRing` / shared-memory window (Planned).** Zero-copy sharing needs the `MAP`
   right and costs one MPU region in each participant — feasible only within the tight region
   budget, so at most one or two such windows system-wide. Use for high-rate data planes only.
4. **Synchronous IPC with leases (Planned, research Phase 4).** The clean, MMU-free primitive:
   a server container exposes an endpoint; a client holds a handle with `WRITE`; `ipc_call`
   carries a small message plus ≤1 transferred handle and up to a few **leases** (borrowed
   client buffers, R/W, bounds-checked against the client's own MPU regions, revoked when the
   call returns). No standing shared memory, no MPU region spent. This is how a sandboxed
   container should talk to a service container (e.g. a keystore or logging container).
5. **`edge::Topic` pub/sub — privileged only.** `Topic` is a `&'static` object in kernel
   memory. It is a convenient fan-out *between privileged isolated domains* (software
   enforcement), but a *sandboxed* (unprivileged) container cannot touch it directly — it
   would fault under the MPU. For sandboxed containers, front a topic with a device/syscall or
   an IPC endpoint. State this clearly so no one treats `Topic` as a cross-sandbox boundary.

Design guidance: for **sandboxed** containers, inter-container comm must cross the syscall
boundary (options 1, 2, 4). Options 3 and 5 are either Planned or privileged-only. Default to
pipes/IPC; reserve shared memory for measured data-plane needs.

### 3.7 Fault isolation, the supervisor, and restart

- **A supervisor container** (Hubris's priority-0 supervisor analogue; the `supervisor` field
  of `ContainerManifest`) is a small trusted container holding restart authority over the
  others. Because `security::kill` and cross-domain spawn require a trusted caller, the
  supervisor is either the kernel domain or a `trusted` domain (and therefore *not* itself
  isolated — keep it tiny and audited).
- **Fault flow.** A sandboxed container's MPU fault / disallowed syscall / forged handle
  already kills its domain (`violation`/`syscall_violation` → `kill_internal`; faults via
  `record_fault` + the fault handler). Extend this to **raise a task notification to the
  supervisor** (`task::notify`, already exists) with the faulting container id. The supervisor
  wakes (`notify_wait`), reads `health()`, and applies the container's `OnFault`:
  `Restart` (re-spawn the entry; crash-loop-guarded by `max`/`window_ms`), `Stop`, `Notify`
  (hand off to policy), or `Halt`.
- **Blast radius.** A fault is confined to one domain = one container. Peers observe it only
  through failing handles (generation bump → `BadHandle`/`PeerRestarted`), never through
  corrupted shared state — provided inter-container comm follows §3.6 (no ambient shared
  memory). This is the whole point of one-domain-per-container.
- **Must-fix for safe restart (documented gaps).** `kill` releasing mutexes held by retired
  tasks (otherwise a restarted container can deadlock against its own previous instance's
  locks); confirming joiners are woken (they are, via `wake_joiners`) and keystore slots
  purged (they are, via `keystore::purge_domain`). Containers turn these from "nice to have"
  into correctness requirements.

### 3.8 Attestation of the container manifest

Per research §8 (DICE/PSA), the `ContainerManifest` hash and each container's `image_hash` +
`version` become claims in a **PSA-profile EAT token** (RFC 9783), signed inside the keystore
(or forwarded to TF-M's Initial Attestation on TrustZone parts). A verifier then learns,
remotely and unforgeably: *"this device runs container `telemetry` v3 and container `ota` v1,
with exactly these rights, this CPU budget, and this code measurement."* Because the whole
graph is `const`, the manifest hash can be computed at build time and baked in, or recomputed
at boot over the const tables and compared. This is a capability Linux containers only get
with extra attestation infrastructure and that Zircon has no equivalent for.

### 3.9 The container manifest file

A static container manifest is Rust `const` data (as the security manifest already is), or a
`bismuth-xtask`-generated module from a `.toml` (as research §4.4 proposes for domains). A
TOML surface (lowered to the `const` tables above) would read:

```toml
[container.telemetry]
version       = 3
priority_ceiling = 8
max_tasks     = 2
ram_bytes     = 4096
cpu           = { period_ms = 100, micros = 15000, partitioned = false }  # 15% soft budget
on_fault      = "restart"            # restart | stop | notify | halt
restart       = { max = 5, window_ms = 60000 }
bad_handle    = "kill"
syscalls      = ["dev_read", "dev_ioctl", "random", "sleep", "log", "exit"]
hardware_isolated = true             # sandboxed (MPU) container
entry         = { fn = "telemetry_main", stack_bytes = 2048, priority = 4 }
devices       = [ { device = "bme280", name = "temp", rights = ["READ", "CONTROL"] } ]
keys          = [ { name = "telemetry_aead", type = "chacha20poly1305", usage = ["K_ENCRYPT"] } ]
net           = { local_ports = [5683, 5683], peers = ["10.0.0.0/8"], listen = false }

[container.ota]
version       = 1
priority_ceiling = 6
max_tasks     = 1
ram_bytes     = 8192
cpu           = { period_ms = 100, micros = 5000, partitioned = false }
on_fault      = "notify"
hardware_isolated = true
entry         = { fn = "ota_main", stack_bytes = 4096, priority = 3 }
# ota talks to telemetry only through a granted pipe (capability routing):
ipc           = [ { endpoint = "telemetry.ctrl", rights = ["WRITE"] } ]

[supervisor]
container = "ota"    # or omit → the kernel domain supervises
```

Field-by-field, this is: the existing `DomainSpec`/`GrantDecl`/`NetPolicy` fields, plus the
four container additions (version, cpu, ram, on_fault/restart), plus key grants and IPC
endpoints. Nothing in it is un-checkable at build time.

---

## 4. Concrete flow, end to end

```text
build time:   const MANIFEST: ContainerManifest = …;
              const _: () = container::validate_containers(&MANIFEST);   // graph verified or build fails
              (optional) MANIFEST_HASH computed by xtask and baked in

boot (D0):    entropy::add_source(trng); entropy::seed(..);             // DRBGs available
              driver::register(all devices);
              container::install(&MANIFEST)  ─►  manifest::apply (domains + device grants)
                                                 + keystore key grants per container
                                                 + register CpuBudgets
                                                 + security::seal()      // graph frozen; only-tighten after
              container::start(each)          ─►  spawn_user(entry) into each domain

run time:     each container runs confined: MPU (sandboxed) + rights + syscall mask + net
              policy + CPU budget; its own DRBG; its own keys.
              fault  ─► kill domain (blast radius = 1 container) ─► notify supervisor
                     ─► supervisor applies OnFault (restart re-spawns entry; gen bumped;
                        DRBG re-derived; stale peer handles fail)

on request:   attest(nonce) ─► PSA/EAT token incl. MANIFEST_HASH + per-container version/hash
```

---

## 5. Phased, host-sim-testable plan

Each phase lands with deterministic host-simulator tests (`sim::run_to_completion`, the
`note`/`take` pattern of tests/security.rs and tests/sandbox.rs) and keeps
`#![deny(unsafe_code)]`; new `unsafe` only in the existing TCB modules.

| Phase | Deliverable | Host-sim tests | New `unsafe` |
|---|---|---|---|
| **C0. Container type + validation** | `src/security/container.rs`: `ContainerDecl`, `ContainerManifest`, `CpuBudget`, `OnFault`, `KeyGrantDecl`; `validate_containers` as `const fn`. No run-time behaviour change — a container that uses only existing fields behaves exactly like today's domain. | `const _: () = validate_containers(&M)` compiles for a good manifest; negative cases via `trybuild`/doc-`compile_fail` for over-budget CPU, over-aligned stack, dangling supervisor, over-RAM, key-usage mismatch. | none |
| **C1. Lifecycle over existing primitives** | `install`/`start`/`stop`/`restart`/`health`. `install` = extended `manifest::apply` (+ key grants, + budget registration) + `seal`. `start` = `spawn_user`. `stop`/`restart` = `security::kill` + re-spawn. Fix `kill` mutex-release gap. | start→running; stop→not running + generation bumped; restart→generation bumped again + DRBG stream differs (reuse the entropy test's technique: collect randoms before/after restart, assert inequality); health reports violations/faults/stack watermark. | none |
| **C2. CPU budget (soft)** | per-domain `run_micros_window` charged in `tick()`; throttle (not kill) on overrun; refill per window. | a greedy container is throttled while a well-behaved one keeps meeting its period; budget resets each window; sum-of-budgets ≤100% enforced at build. | none |
| **C3. Supervisor + fault policy** | supervisor container; fault → `task::notify(supervisor)`; supervisor applies `OnFault` (`Restart` crash-loop-guarded, `Stop`, `Notify`, `Halt`). | sandboxed container faults (forged handle / bad syscall / MPU write) → domain killed, supervisor notified, `Restart` brings it back with a fresh generation; `max` restarts then `Stop`; blast radius = 1 (a sibling container keeps running). | none |
| **C4. Inter-container IPC** | wire shared-pipe grants through the manifest; then synchronous IPC + leases (research Phase 4) for sandboxed containers. | two containers exchange data over a granted pipe; a third cannot `open` it; lease bounds-checks reject out-of-region buffers (reuse the usermem validation suite). | IPC lease copy lives in `kernel/usermem.rs` (existing TCB) |
| **C5. Attestation of the manifest** | compute `MANIFEST_HASH` (xtask or boot-time over const tables); add manifest-hash + per-container version/hash claims to the PSA/EAT token (depends on research Phase 6). | golden-vector token includes the expected manifest hash; changing any `ContainerDecl` changes the hash. | none |
| **C6. Time partition (option, hard-RT)** | feature-gated two-level cyclic frame scheduler above the priority scheduler for `partitioned` containers. | a partitioned container runs only in its window; no other container runs then; overrun cannot steal a sibling's window; jitter bounded. | arch scheduler hook (existing TCB) |
| **C7. Loadable signed bundle (option, dynamic)** | TBF-style header + loader; signature verify via keystore `K_VERIFY`; requested capabilities checked against a declared *slot ceiling*; anti-rollback counter; map code RX / data RW+XN into an "app-slot" domain. | parser fuzz corpus; a bundle requesting more than its slot ceiling is rejected; bad signature rejected; rollback rejected; a loaded container runs under the same lifecycle/budget/attestation as a static one. | bundle loader/parser (new, small, fuzzed TCB module) |
| **C8. Wasm container (option, MPU-less)** | `ContainerKind::Wasm` behind the same lifecycle/budget API using a vetted `no_std` runtime (wasmi/WAMR); host functions = the syscall surface. | a Wasm module touches only its linear memory; imports gate device/net access by the same rights; budget throttles a hot loop. | confined to the runtime crate, outside the kernel TCB |

Ordering rationale: C0–C3 are a thin, low-risk layer that turns the existing domain into a
supervised, budgeted, restartable container with **no new `unsafe`** and immediate edge-compute
value. C4–C5 round out comms and provenance. C6–C8 are genuinely optional, higher-cost tiers
(hard-RT, dynamic load, software sandbox) added only when a product needs them.

### 5.1 Illustrative test (C1/C3 style, matching tests/security.rs)

```rust
// Shape only — mirrors sandbox.rs / security.rs harness (note/take + run_to_completion).
#[test]
fn container_restarts_on_fault_without_taking_down_a_sibling() {
    sim::run_to_completion(|| {
        entropy::add_source(&TRNG); entropy::seed(200).unwrap();
        driver::register("temp0", &SENSOR).unwrap();
        container::install(&MANIFEST).unwrap();            // telemetry (restart) + sibling (stop)
        container::start(TELEMETRY).unwrap();
        container::start(SIBLING).unwrap();
        // telemetry's entry forges a handle on first run → domain killed → supervisor restarts it.
        // Assert: sibling kept running; telemetry generation incremented; its DRBG stream changed;
        //         health().restarts == 1; after `max` restarts it stays stopped.
    });
}
```

---

## 6. Honest limits: what a Bismuth container can and cannot be

**Can:**
- Confine a workload to exactly the devices, keys, ports, peers and syscalls it was granted,
  with hardware (MPU) enforcement for sandboxed containers and generation-based revocation.
- Bound its CPU (soft budget now, hard time partition optionally) and its task count; fix its
  RAM footprint at build time.
- Give it its own CSPRNG and domain-bound keys.
- Restart it in isolation when it faults, under a supervisor, without downing the device.
- Attest exactly which containers, versions and rights are running — verified against a
  **compile-time-checked** capability graph, a property Linux/Zircon can't match cheaply.

**Cannot (hardware/scope limits, not laziness):**
- Give each container a private virtual address space, overcommit memory, COW-share pages,
  demand-page, or meaningfully randomise layout — no MMU. Memory is physically partitioned by
  a scarce MPU region budget, fixed at build.
- Offer a filesystem, image layers, volumes or bind mounts — no VFS. "Image" = firmware image
  (+ later a signed bundle); "mounts" = the device namespace.
- Run an arbitrary, dynamically-pulled image out of the box — that needs the signed-bundle
  loader tier (C7), which adds real TCB and v7-M alignment pain, or the Wasm tier (C8), which
  trades native speed/size for software sandboxing.
- Densely multi-tenant: expect a handful of containers (`MAX_DOMAINS = 8` including the kernel
  domain today), not hundreds. That is the right number for an edge MCU.
- Protect a privileged (isolated-but-not-sandboxed) container from itself: without
  `hardware_isolated`, the checks are software-only and `unsafe` app code can bypass them
  (see design/security.md threat model). Real confinement requires a sandboxed container on a
  core with an MPU.

A Bismuth container is therefore best described to users as an **"attested, capability-confined,
resource-budgeted, supervised partition"** — an ARINC-653-partition / Tock-app hybrid with a
compile-time-verified capability graph — not as "Docker for microcontrollers". Marketing it as
the latter would overpromise on exactly the axes an MMU-less MCU cannot deliver.

---

## 7. Summary table

| Concern | Linux container | Bismuth container | Mechanism (status) |
|---|---|---|---|
| Identity/principal | user namespace / uid | the domain | `DomainId`/`Caller` (**Done**) |
| Filesystem view | mount ns / rootfs | device namespace | per-domain named handle grants (**Done**) |
| Network view | net namespace | per-domain net policy | `NetPolicy` + `check_net` (**Done**) |
| Syscall surface | seccomp-bpf | syscall allow-mask | `DomainSpec.syscalls` (**Done**) |
| Privilege split | capabilities | per-handle rights | monotonic `Rights` (**Done**) |
| CPU limit | cgroup cpu | ceiling + CPU budget | ceiling **Done**, budget **Planned** (C2) |
| Hard-RT isolation | — (RT patches) | time partition | ARINC-653 two-level sched **Planned** (C6) |
| Memory limit | cgroup memory | static RAM allotment | manifest check (**Done, static**) |
| Task/pid limit | cgroup pids | `max_tasks` | `check_spawn` (**Done**) |
| I/O limit | cgroup io | per-caller rate-limit mw | middleware (**Partial**) |
| Code/image | OCI image | firmware image / signed bundle | static **Done**, bundle **Planned** (C7) |
| Provenance | digest + signature | manifest/image hash | PSA/EAT token **Planned** (C5) |
| Entropy | shared `/dev/urandom` | per-container DRBG | `entropy` per-domain (**Done**) |
| Keys | app's problem | domain-bound keystore | `keystore` (**Done**) |
| Runtime/supervisor | runc/kubelet | supervisor container | `kill`+notify+respawn **Planned** (C3) |
| Lifecycle | start/stop/restart | start/stop/restart/health | over `spawn`/`kill` **Planned** (C1) |
| Inter-container | shared ns / sockets | granted pipe/socket/IPC-lease | pipe/socket **Done**, IPC **Planned** (C4) |
| Isolation enforcement | MMU + namespaces | MPU + capabilities | sandboxed tasks (**Done, ARMv7-M**) |
| Graph verification | run-time (admission) | **compile time** | `validate`/`validate_containers` (**Done/Planned**) |

---

## 8. References

**Containers (Linux) and OCI**
- Linux namespaces overview. https://man7.org/linux/man-pages/man7/namespaces.7.html
- cgroups v2. https://docs.kernel.org/admin-guide/cgroup-v2.html ; https://man7.org/linux/man-pages/man7/cgroups.7.html
- Linux capabilities. https://man7.org/linux/man-pages/man7/capabilities.7.html
- seccomp / seccomp-bpf. https://man7.org/linux/man-pages/man2/seccomp.2.html ; https://docs.kernel.org/userspace-api/seccomp_filter.html
- OCI Image Specification. https://github.com/opencontainers/image-spec ; OCI Runtime Spec. https://github.com/opencontainers/runtime-spec
- OCI image signing (Sigstore/cosign). https://docs.sigstore.dev/

**ARINC 653 / IMA / AUTOSAR**
- ARINC 653 (Avionics Application Standard Software Interface) — overview. https://en.wikipedia.org/wiki/ARINC_653
- Rushby, "Partitioning in Avionics Architectures: Requirements, Mechanisms, and Assurance" (NASA CR-1999-209347). https://ntrs.nasa.gov/citations/19990081529
- AUTOSAR Classic OS specification (OS-Applications, memory + timing + service protection). https://www.autosar.org/standards/classic-platform

**Embedded isolation models**
- Tock OS design (processes vs capsules, grants). https://www.tockos.org/documentation/design/ ; threat model. https://book.tockos.org/doc/threat_model/threat_model
- Tock Binary Format (TBF) and app loading. https://book.tockos.org/doc/tock_binary_format ; https://github.com/tock/tock/blob/master/doc/reference/trd-appid.md
- Hubris reference (static tasks, supervisor, leases, generations). https://hubris.oxide.computer/reference/
- Zephyr user mode overview + memory domains. https://docs.zephyrproject.org/latest/kernel/usermode/overview.html ; https://docs.zephyrproject.org/latest/kernel/usermode/memory_domain.html
- TF-M secure partitions / PSA Firmware Framework-M isolation. https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/ff_isolation.html
- PSA Firmware Framework for M (FF-M). https://developer.arm.com/documentation/den0063/latest

**WebAssembly on MCUs**
- WAMR (WebAssembly Micro Runtime). https://github.com/bytecodealliance/wasm-micro-runtime
- wasmi (pure-Rust `no_std` Wasm interpreter). https://github.com/wasmi-labs/wasmi
- WASI / component model (capability-based host interface). https://github.com/WebAssembly/WASI ; https://component-model.bytecodealliance.org/

**Boot / attestation (shared with the security research)**
- TCG DICE Layering Architecture. https://trustedcomputinggroup.org/resource/dice-layering-architecture/
- RFC 9783, Arm PSA Attestation Token (EAT profile). https://www.rfc-editor.org/rfc/rfc9783
- MCUboot (anti-rollback, signed images). https://docs.mcuboot.com/

**Bismuth internal**
- [research/security.md](security.md) — domains, rights, syscall boundary, entropy, keystore, boot/attestation, TrustZone, phased plan.
- [design/security.md](../design/security.md) — what is implemented today, the threat model, and the limitations/gaps this design depends on fixing.
- Source: `src/security/mod.rs`, `src/security/manifest.rs`, `src/security/syscall.rs`,
  `src/security/entropy/mod.rs`, `src/security/keystore.rs`, `src/kernel/task.rs`,
  `src/kernel/usermem.rs`, `src/user.rs`, `src/edge/mod.rs`; tests in
  `tests/security.rs` and `tests/sandbox.rs`.
</content>
</invoke>
