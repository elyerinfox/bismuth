# Containers

Source: `src/security/container.rs` (feature `containers`, on by default). Tests:
`tests/containers.rs`. Research input: [research/containers.md](../research/containers.md).

## What a container is (and is not)

**A container is not a new isolation primitive.** A [security domain](security.md) is
already the isolation boundary: it has a handle table, rights, a syscall allow-list, a
priority ceiling, a task quota, a network policy, an entropy context and, for sandboxed
domains, an MPU region set. A container *bundles* a domain with everything needed to
run, supervise and attest one workload, as a single declarable unit:

```text
container = a domain (DomainSpec)            isolation, policy, entropy context
          + its device grants                capability routing, no ambient authority
          + a root entry + static stack      what `start` spawns
          + a CPU budget                     declared + compile-time validated; enforcement Planned
          + a fault policy (OnFault)         declared; automatic handling Planned
          + version + image_hash             recorded for attestation; claims Planned
```

Bismuth has no MMU, so a container has no virtual address space, no copy-on-write, no
demand paging, no ASLR and no filesystem image. It is a statically sized,
capability-confined, supervisable **partition**, closer to an ARINC 653 partition or a
Tock app than to "Docker for MCUs".

### Linux concepts mapped onto Bismuth

| Linux | Bismuth equivalent | status |
|-------|--------------------|--------|
| user namespace | the domain is the principal (`DomainId`, `Caller.domain`) | Done |
| mount namespace | per-domain device namespace (`DeviceCap::open` resolves only granted names, aliases hide real names) | Done |
| net namespace | `DomainSpec.net` (`NetPolicy`: ports, peers, listen) | Done (policy); per-domain interface binding Planned |
| pid namespace / cgroup pids | task scoping by domain; `DomainSpec.max_tasks` quota | Done |
| capabilities | per-handle `Rights`, which can only shrink | Done |
| seccomp | `DomainSpec.syscalls` allow-mask, checked in `syscall::dispatch` | Done |
| cgroup memory | static RAM partitioning; `ram_bytes` is declared | Declared; **not checked** (see gaps) |
| cgroup cpu | `CpuBudget` | Declared and compile-time validated; **scheduler enforcement Planned** |
| OCI image / rootfs | the firmware image + the manifest | static Done; signed loadable bundles Planned |
| image digest | `version` + `image_hash` fields | recorded; attestation claims Planned |
| runtime / kubelet | `install` / `start` / `stop` / `restart` / `health` | Done (trusted callers) |

## Types

```rust
pub struct ContainerManifest {
    pub containers: &'static [ContainerDecl],
    pub supervisor: Option<&'static str>,   // a container name; None = the kernel domain
}

pub struct ContainerDecl {
    pub domain: manifest::DomainDecl,       // DomainSpec + device grants (reused from the manifest)
    pub entry: ContainerEntry,
    pub version: u32,
    pub cpu: Option<CpuBudget>,
    pub ram_bytes: u32,
    pub on_fault: OnFault,
    pub image_hash: [u8; 32],               // all zero = not measured
}

pub struct ContainerEntry { pub user_entry, pub entry, pub arg, pub priority, pub stack: Option<&'static dyn StackSource> }
ContainerEntry::user(f: extern "C-unwind" fn(usize), priority, &STACK)   // sandboxed root task
ContainerEntry::privileged(f: fn(usize), priority, &STACK)               // isolated, privileged root task

pub struct CpuBudget { pub period_ms: u32, pub micros: u32, pub partitioned: bool }
pub enum OnFault { Restart { max: u8, window_ms: u32 }, Stop, Notify, Halt }
pub struct ContainerId(pub DomainId);
pub struct Health { pub running: bool, pub generation: u16, pub violations: u32, pub faults: u32, pub cpu_ticks: u64 }
```

The two `ContainerEntry` constructors set `arg` to 0. Set the field directly if the
root task needs an argument.

## Compile-time validation

```rust
const _: () = container::validate_containers(&MANIFEST);
```

`validate_containers` is a `const fn`. Used in a `const` item, any violation **fails the
build**:

| check | build error text |
|-------|------------------|
| at most `MAX_DOMAINS` containers | `containers: too many` |
| entry priority in 1..=31 | `container: bad entry priority` |
| entry priority ≤ the domain's `priority_ceiling` | `container: entry priority exceeds the domain priority ceiling` |
| a sandboxed domain (`hardware_isolated`) has a **user** entry and no privileged one | `sandboxed container needs a user entry` |
| a non-sandboxed domain has a **privileged** entry and no user one | `isolated container needs a privileged entry` |
| `CpuBudget` has `period_ms > 0`, `micros > 0` and `micros ≤ period` | `container: bad cpu budget` / `container: cpu budget exceeds its window` |
| soft budgets (`partitioned: false`) sum to at most 100% (in permille) | `container: soft CPU budgets exceed 100%` |
| partitioned budgets (`partitioned: true`) sum to at most one major frame (100%) | `container: partitioned CPU windows over-commit the major frame` |
| soft + partitioned budgets together sum to at most 100% | `container: total CPU budgets (soft + partitioned) exceed 100%` |
| container names are unique | `container: duplicate name` |
| `supervisor`, if set, names a declared container | `container: supervisor names an undeclared container` |

`validate_containers` does **not** repeat the per-domain checks. Run
`manifest::validate` on the embedded `DomainDecl`s as well. Those checks cover no
`K_EXPORT`/`MANAGE` grants, no trusted domains, unique grant names and task quotas
fitting `MAX_TASKS`. The [guide](../guides/containers.md) shows both.

## Lifecycle

All lifecycle calls that change state require a **trusted** caller: the kernel domain
or a `trusted: true` domain. Everyone else gets `PermissionDenied`.

| call | effect |
|------|--------|
| `install(&'static M)` | For each container: `create_domain`, `grant_device` for each grant (the devices must already be registered), record the declaration. Then **`security::seal()`**. Because it seals, `install` can run **once** per boot; a second call fails with `PermissionDenied`. If a step fails part-way, the domains already created stay. |
| `find(name) -> Option<ContainerId>` | look up an installed container (no trust check) |
| `start(c)` | Claim the declared stack (`Busy` if it is in use) and spawn the root task, **detached**, into the domain. A user entry uses `spawn_user`; a privileged one uses `spawn`. The domain's priority ceiling, task quota and the sandbox rules apply as for any spawn. |
| `stop(c)` | `security::kill(domain)` (see below). Idempotent. The declaration stays, so the container can be started again. |
| `restart(c)` | `stop`, then `start` |
| `health(c) -> Health` | `running` (any live task in the domain), `generation`, `violations`, `faults` (MPU), `cpu_ticks` |
| `budget(c) -> Option<CpuBudget>` | the declared budget |

### What `stop` / `restart` guarantee

`stop` uses `security::kill`, which does all of the following:

1. Retires every task of the domain and wakes their joiners.
2. **Reaps** the domain's dead tasks immediately. This frees their slots and stacks, so
   `start` can claim the same static stack again. A task that is currently running is
   reaped once it is switched out.
3. Empties the handle table and bumps the domain **generation**. Handles that peers
   still hold now fail the generation check.
4. Invalidates the domain's DRBG, so it is re-derived from the root on next use and a
   restarted container **never replays its random stream**.
5. Purges and zeroizes the domain's keystore slots.

Limitation: mutexes held by killed tasks are **not** unlocked, because there is no
per-task held-mutex list. Avoid sharing mutexes between a container and code outside it.

## CPU budgets: declared, not enforced

`CpuBudget { period_ms, micros, partitioned }` models a cgroup `cpu.max` or an
ARINC-653 window:

- `partitioned: false` is a soft budget; soft budgets must sum to ≤ 100%.
- `partitioned: true` is a reserved time partition; these must also sum to ≤ 100% (one
  major frame). Their combined total must also be ≤ 100%. Shares are computed in
  whole permille, rounded down.

**Run-time enforcement is Planned.** The scheduler does not charge, throttle or refill
budgets yet; that is research phase C2 for soft budgets and C6 for time partitions. A
supervisor can watch `health(c).cpu_ticks`: the sum of `run_ticks` over the domain's
current task slots. That counter starts again from zero after a restart, because kill
reaps the old tasks.

## Gaps and Planned work

| item | status |
|------|--------|
| CPU budget enforcement in the scheduler (soft budgets, throttling) | **Planned** (research C2) |
| `OnFault` policies, supervisor notification, crash-loop guard | **Planned** (C3). `on_fault` and `supervisor` are validated and stored, but nothing acts on them: a faulting container's domain is killed (per its `BadHandlePolicy` and the fault handler) and stays down until trusted code calls `restart`. |
| `ram_bytes` footprint check | **not implemented**. The field is stored only; `validate_containers` does not check it, despite its doc comment saying so. |
| inter-container IPC (granted pipes, leases) | **Planned** (C4). Today containers can share a device granted to both. |
| attestation claims (manifest hash, `version`, `image_hash`) | **Planned** (C5, which depends on security Phase 6) |
| time-partition scheduler for `partitioned` budgets | **Planned** (C6) |
| loadable signed app bundles (Tock-TBF style) | **Planned** (C7), not built |
| Wasm containers | **Planned** (C8), not built |
| key grants in the container manifest | **Planned** |
