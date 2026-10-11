# Bismuth Security Architecture: Zircon Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: what Google's Zircon kernel (Fuchsia) does for security, how MCU-class systems (seL4, Tock, Hubris, Zephyr, TF-M/PSA) solve the same problems, and an opinionated design for per-process security contexts, a syscall boundary, entropy, crypto, secure boot/attestation and TrustZone-M in Bismuth. Targets: Cortex-M3/M4/M33/M55 and RV32 MCUs with tens to hundreds of KB of RAM, an MPU or PMP but no MMU, and optionally TrustZone-M, a TRNG and crypto accelerators.
>
> Current Bismuth baseline (read from the tree): a single address space. All tasks run privileged in thread mode on PSP (`arch/cortex_m.rs`) and call the kernel as plain functions. The crate is `#![deny(unsafe_code)]` with a 4-module TCB (`arch/cortex_m.rs`, `arch/mmio.rs`, `kernel/cell.rs`, `kernel/stack.rs`). Devices are `&'static dyn Driver` reached through a 3-stage `Middleware` chain (global → per-device user → driver-provided → driver) carrying a `Request { op, timeout, flags }` and a `DeviceCtx { device, name, class }`. Packets go through a `PacketHook` chain. `Device` is already a generation-checked index handle (`{ index: u8, generation: u8 }`), a useful seed for a handle table.

---

## 0. TL;DR

- **Take Zircon's object-capability model, not its machinery.** Copy these: per-process handle tables, per-handle rights that can only ever be *reduced*, no ambient authority, *resources* that gate MMIO/IRQ ranges, and job policy that children can only tighten. Leave out VMOs/VMARs, the vDSO, ASLR, ELF process loading, the port/async-wait machinery, 64-bit koids, the arbitrary-depth job tree, and the root resource as a bearer token for "everything". Those exist because Zircon has an MMU, gigabytes of RAM and dynamically installed software.
- **A Bismuth "domain" is the security context.** A domain is an MPU-isolated group of tasks with its own handle table, rights, quotas, syscall allow-mask, priority ceiling, fault policy, and **its own CSPRNG instance**. Domains are declared statically in a build-time manifest, as in Hubris, so the whole system's capability graph can be checked at compile time. Tasks *inside* a domain can still be created dynamically (pthreads, FreeRTOS compat) from that domain's quota.
- **Rights are enforced by the kernel *before* the middleware chain, not by a middleware.** Middleware can be detached, reordered and composed, so it is policy, not a security boundary. The syscall dispatcher resolves a handle, checks the rights `Op` needs (ioctl numbers encode their required right, as Linux `_IOR/_IOW` encode direction) and only then calls `Device::request`. An immutable `Caller` (domain id, effective rights, label) travels in the `Request`. Middleware can use it for *finer* policy (per-domain rate limits, ACLs, audit) but can never widen it.
- **Syscall boundary: unprivileged thread mode + `SVC`, with no vDSO.** On Cortex-M, an exception is the only way into privileged mode, so Zircon's PC-in-vDSO check has nothing to add. Add what Zircon lacks: a **per-domain syscall allow-mask**, a single `u64` test per call (Zircon's "vDSO variants" for this are documented as experimental and unused). User pointers become `UserSlice`s validated against the caller's region table. On ARMv8-M the hardware `TT`/`TTT` instruction does the check, and leases cover IPC (Hubris).
- **MPU plan:** use ≤4 dynamic regions per domain plus a background privileged map. On v8-M (M33/M55), base/limit regions at 32-byte granularity plus `PSPLIM` give an exact stack guard. On v7-M (M3/M4), regions must be power-of-two sized and aligned, so a linker-driven layout tool is needed and the stack guard is a 32-byte no-access region (or stack-at-bottom-of-RAM). On RISC-V, use PMP TOR/NAPOT, with Smepmp to lock M-mode out of user memory.
- **Entropy:** a kernel entropy service gathers TRNG samples with **SP 800-90B continuous health tests** (RCT + APT, plus startup tests), conditions them with SHA-256, and seeds a root ChaCha20 DRBG with *fast key erasure*. That root DRBG derives a **separate DRBG per domain**, reseeded on every domain (re)start. That restart is the MCU analogue of `fork()`. Jitter and SRAM power-up noise are mixed in but credited zero unless they are measured per part with NIST's assessment tool. Use vetted crates (`chacha20`/`rand_chacha`, `sha2`, `hmac`, `hkdf`, `rand_core`, `zeroize`, `subtle`). Never write our own primitive or DRBG construction.
- **Crypto service:** keys live only in a *keystore* context: a privileged kernel service at first, then a dedicated domain, then the TrustZone secure side. Callers hold **key handles** with PSA-style usage rights (`ENCRYPT`, `SIGN`, `DERIVE`, …) bound to one algorithm. Backends implement a trait. Hardware accelerators are preferred, with RustCrypto software fallback and known-answer self-tests at boot. Beware Cortex-M3's variable-time `UMULL`.
- **Boot/attestation:** Bismuth is not the bootloader. It consumes a measured-boot handoff (MCUboot or a Rust first stage) and uses **TCG DICE** layering as the default identity scheme for MCUs. It exposes a PSA-style attestation token (RFC 9783 profile) signed inside the keystore.
- **TrustZone-M:** run Bismuth Non-secure with TF-M Secure first (fastest path to PSA Certified). Long-term option: a minimal Rust secure partition holding only keystore, entropy and attestation. Bismuth never puts the scheduler on the secure side.
- **Can Bismuth beat Zircon *for MCUs*?** On several axes, yes: a memory-safe kernel, a **compile-time verified** capability graph, per-syscall ACLs, per-context DRBGs with health-tested entropy, real revocation via object generations, hardware-isolated keys, and every security property tested deterministically in the host simulator. It cannot match Zircon's fine-grained paging, guard pages, ASLR or ability to install third-party software safely at run time. The MPU's region count is the hard ceiling (§7).

---

## 1. Zircon security architecture

### 1.1 Kernel objects, handles and rights

- **Everything is a kernel object** (process, thread, job, VMO, channel, event, port, socket, interrupt, resource, …) with a 64-bit koid that is never reused ([Zircon concepts][zx-concepts]).
- **Handles are the only way to name objects from userspace.** A `zx_handle_t` is a 32-bit value that is meaningful only in the owning process's handle table. Every syscall first resolves the handle in the *caller's* table, then checks the object type and that the handle carries the rights the operation needs ([Zircon concepts][zx-concepts]).
- **Rights are per handle, not per object.** Two handles to one object can carry different rights. Rights include `DUPLICATE`, `TRANSFER`, `READ`, `WRITE`, `EXECUTE`, `MAP`, `GET/SET_PROPERTY`, `ENUMERATE`, `DESTROY`, `GET/SET_POLICY`, `SIGNAL`, `SIGNAL_PEER`, `WAIT`, `INSPECT`, `MANAGE_*`, `APPLY_PROFILE`, `RESIZE` and others. `ZX_RIGHTS_BASIC` = `DUPLICATE | TRANSFER | WAIT | INSPECT`. Default rights "can be reduced via `zx_handle_replace()` or `zx_handle_duplicate()`" ([rights][zx-rights]). Rights are **monotonically non-increasing** along any delegation path. This is the property worth copying.
- **Delegation = moving handles over channels.** A process starts with whatever handles its creator passed it. The last handle closing destroys most objects ([concepts][zx-concepts]).

### 1.2 Jobs, processes, threads and job policy

- Jobs form a tree. Processes live in jobs, threads in processes. A job handle with the right rights can kill or enumerate everything below it.
- **Job policy** (`zx_job_set_policy`) restricts what processes in a job may do ([job_set_policy][zx-jobpol]):
  - **Conditions:** `ZX_POL_BAD_HANDLE`, `ZX_POL_WRONG_OBJECT`, `ZX_POL_VMAR_WX`, `ZX_POL_AMBIENT_MARK_VMO_EXEC`, and per-object-type creation conditions `ZX_POL_NEW_{VMO,CHANNEL,EVENT,…,PROCESS,…}` plus the wildcard `ZX_POL_NEW_ANY`.
  - **Actions:** `ALLOW`, `DENY`, `ALLOW_EXCEPTION`, `DENY_EXCEPTION`, `KILL`.
  - The effective policy combines the parent's with the job's own. `ZX_POL_OVERRIDE_DENY` stops children from changing it, and "as long as a Job has any children its policy cannot be mutated".
  - `ZX_JOB_POL_TIMER_SLACK`: a child can only *increase* minimum slack.
- Policy is mostly about **object creation and misuse**, not about *which syscalls* may be called. No general per-process syscall filter exists (see 1.4).

### 1.3 Memory: VMOs and VMARs

VMOs are page-granular memory objects (paged, physical, contiguous, pager-backed, COW clones). VMARs are hierarchical address-space regions with randomized placement. W^X is policed by `ZX_POL_VMAR_WX` and by the `EXECUTE` right. **Nothing here maps onto an MCU.** There are no pages, no per-process address spaces and no demand paging, and the 8–16 MPU regions are a scarce, global resource.

### 1.4 The vDSO as the only syscall entry

"The Zircon vDSO is the sole means of access to system calls in Zircon." The kernel allows exactly one executable mapping of the vDSO per process. On each syscall it checks the PC of the `syscall` instruction against a per-syscall predicate, and raises a synthetic exception when the check fails ([vDSO][zx-vdso]). The stated aim is to stop the private kernel/vDSO interface from becoming a de-facto ABI. "vDSO variants", which would let a process see only a subset of syscalls (for example, no driver syscalls for ordinary apps), are documented as "an experimental feature that is not yet in real use" ([vDSO][zx-vdso]). In practice, which syscalls a process may call is governed by which *handles* it holds, plus job policy on object creation.

### 1.5 Resources: MMIO, IRQ, SYSTEM

Resources are immutable objects that gate creating physical VMOs (`zx_vmo_create_physical`), interrupts (`zx_interrupt_create`) and x86 I/O ports. Kinds are MMIO, IOPORT, IRQ, SMC and SYSTEM. Each covers a `[base, base+len)` range. Sub-resources are carved out with `zx_resource_create`, and only within the parent's range. *Exclusive* resources reserve a range, and shared and exclusive ranges may not overlap. At boot the kernel hands one resource of each kind to userboot. ACPI and the platform bus then hand finer ones to drivers ([resource][zx-resource]). This maps almost one-to-one onto MCU MMIO windows and NVIC lines.

### 1.6 Kernel CPRNG and `zx_cprng_draw`

From the design doc ([CPRNG][zx-cprng]):

- **Construction:** a 256-bit key and a 128-bit nonce. `Draw()` increments the nonce and encrypts the output buffer with **ChaCha20**. `AddEntropy()` does `k_new = SHA-256(e || k_old)`, so callers cannot set the key.
- **Seeding:** first seeding happens very early in boot, because ASLR needs it. A kernel thread **reseeds every 30 s** for forward secrecy. Sources are the `kernel.entropy-mixin` command-line value (initial seeding only), hardware RNGs (e.g. `RDSEED`) and **jitterentropy**. The `kernel.cprng-(re)seed-require.*` options can make given sources mandatory.
- **Trust:** "only kernel-accessible sources are trusted". Drivers run in userspace and "cannot be trusted". `zx_cprng_add_entropy` lets userspace mix in data but cannot replace the key.
- **API:** `zx_cprng_draw` needs no rights and has no error conditions besides a bad buffer pointer, which kills the process. For bulk use the reference suggests seeding a userspace RNG from it ([cprng_draw][zx-cprng-draw]).
- **Gaps the document itself admits:** there is no strong framework yet for userspace to reach the CPRNG securely, and TPMs and other sources are not supported. The intro says "non-blocking" while the seeding section says `Draw()` blocks until seeded. The public doc also describes no SP 800-90B-style continuous health tests on the sources. There is **one global generator**, and per-process RNG state is left to userspace libraries.

### 1.7 Component framework: sandboxing by capability routing

Components see only the capabilities in their namespace plus a few numbered startup handles: *no ambient authority*. Manifests declare `capabilities`, `use`, `offer` (to children) and `expose` (to the parent). At run time a capability exists only if a valid route from consumer to provider exists, and cyclic routes are rejected ([capabilities][fx-caps]). This is the most useful *system-level* idea for Bismuth. Bismuth can do the same routing **at build time** (§4.4).

### 1.8 Hardening

- **SafeStack:** separate safe and unsafe stacks, so a linear overflow cannot reach return addresses. It is enabled for kernel and userspace when building with Clang ([SafeStack][zx-safestack]).
- **ShadowCallStack:** return addresses go on a separate shadow stack at a randomized address. It is orthogonal to SafeStack ([SCS][zx-scs]).
- **ASLR/KASLR**, seeded from the CPRNG ([CPRNG][zx-cprng]).
- **W^X policy** (`ZX_POL_VMAR_WX`) and gating of executable memory (`ZX_POL_AMBIENT_MARK_VMO_EXEC`) ([job policy][zx-jobpol]).

### 1.9 Weaknesses, criticism, CVEs

- **The kernel is C++.** Memory-safety bugs exist in the kernel itself. Examples:
  - **CVE-2021-22556:** an integer overflow (CWE-190) that let code with execution perform cache invalidation on pages it did not own, "which can give control of kernel memory from userspace". Fixed in kernel 4.1 ([CVE record][cve-22556]).
  - **CVE-2022-0882:** Zircon kernel addresses exposed through the kernel log without the root capability ([NVD][cve-0882]).
- **Quarkslab (2020)** found that userspace isolation works well: RCEs in USB and Bluetooth stayed confined to their processes. They warned that the lowest kernel layers (virtualization, exceptions, scheduling) get no such protection. They also showed a kernel path that trusted a userland-controlled structure ([Quarkslab][qb-fuchsia] via [summary][qb-summary]).
- **Popov (Positive Technologies, 2022)** fuzzed Zircon with syzkaller and built a control-flow-hijack PoC and rootkit. He stressed that Zircon is attractive to attackers precisely because *every* component reaches it through syscalls ([PT Swarm][pt-fuchsia], [slides][pt-slides]).
- **Structural criticisms:**
  - A large syscall surface (well over a hundred calls, each a parser of user input).
  - The root resource historically behaved as ambient "god mode" for whoever held it.
  - No general handle revocation: once transferred, a handle can only be killed by destroying the object or its owner.
  - Policy is mostly per job at creation time.
  - The CPRNG trust model leaves userspace without a strong path.

**Lessons for Bismuth:**
1. A capability model only helps if the kernel that enforces it is memory-safe and small.
2. Keep the syscall surface tiny and table-driven.
3. Do not create a god-handle. Split authority (MMIO ranges, IRQ lines, debug, power, policy) into separate resources from day one.
4. Design revocation in.

---

## 2. MCU-class comparators

### 2.1 seL4

- **Model:** capabilities in CNodes, everything explicit, with untyped memory retyped by the holder of the capability.
- **Proofs:** functional correctness (the C code implements the spec "and nothing more"), plus integrity and confidentiality on selected configurations. The current verified-configurations list includes ARM, AARCH64, RISCV64 and X64; MCS proofs are listed as in progress ([seL4 proofs][sel4-proofs], [verified configurations][sel4-configs]).
- **For Bismuth:** seL4 has no verified Cortex-M/MPU port, and its model assumes an MMU. What to take is the *discipline*: a small kernel, capabilities as the only authority, and invariants written down so tools can check them. Bismuth can use Kani/Prusti-style bounded proofs on the handle table and range checks (§10, phase 8).

### 2.2 Tock OS (Rust, MPU)

**Two-tier isolation** ([Tock design][tock-design], [threat model][tock-threat]):
- **Processes:** untrusted, any language, MPU/PMP-isolated, loaded separately from the kernel.
- **Capsules:** kernel drivers in *safe Rust* (`unsafe` forbidden), isolated by the type system, cooperatively scheduled and therefore trusted for liveness.

Other relevant mechanisms:
- **Grants:** capsules may not allocate from a kernel heap. They allocate *inside the requesting process's memory*, in a region the process cannot touch. Access goes through a closure API that checks the process is still alive, so a dead process's memory is reclaimed by construction ([Tock design][tock-design]).
- **Syscall ABI:** `yield`, `subscribe`, `command`, read-write and read-only `allow`, `memop`, `exit`. `allow` hands a buffer to the kernel after checking that it lies inside the process's memory. The kernel must re-check lengths and must not cache values derived from it (TOCTOU) ([TRD104][tock-trd104]).

**Very relevant to Bismuth:** Bismuth's drivers and middleware are already "safe Rust in the kernel", i.e. capsules. What Bismuth lacks is Tock's *process* tier. Grants are the right answer to "where does per-domain kernel state (handle table, DRBG, socket state) live?" (§4.1).

### 2.3 Hubris (Oxide)

**Design** ([Hubris reference][hubris-ref]):
- The task set is fixed at build time (`app.toml`). There is no task creation or destruction at run time, which the authors note limits denial of service.
- Tasks are unprivileged and MPU-isolated in non-overlapping physical regions.
- The kernel does no drivers.
- **IPC** is synchronous send/receive/reply with **leases** (borrowed memory, R/W/RW, revoked when the sender resumes).
- Task **generations** are bumped on restart and checked on IPC.
- A **supervisor** task (priority 0) handles faults and restarts.
- Interrupts reach tasks as notification bits.
- The "uphill send rule": send only to higher-priority servers.

**Admitted gap:** "no capabilities". Any task can message any other, and only limited MAC is planned.

**For Bismuth:** copy static domains, a build-time layout tool, leases, generations, the supervisor and IRQ-as-notification. Add the capability layer Hubris left out.

### 2.4 Zephyr userspace

- User threads are untrusted and start with no permission on any kernel object or driver except their own thread. Permissions are granted per object by supervisor threads, or by a user thread holding both objects.
- Memory domains and partitions define the accessible memory, and new threads inherit the parent's domain.
- Kernel objects, stacks and user-reachable drivers must be defined at build time.
- **Out of scope by its own documentation:** CPU-starvation DoS, supervisor-thread stack overflow integrity, and misconfigured domains ([Zephyr user mode][zephyr-user]).

**For Bismuth:** Zephyr shows that per-object permission bits are workable on MCUs. Bismuth should do better on DoS by adding per-domain CPU budgets and priority ceilings.

### 2.5 TF-M / PSA Certified

- **TF-M** implements the PSA Firmware Framework-M on TrustZone-M. Isolation levels ([TF-M isolation][tfm-iso], [Zephyr TF-M overview][zephyr-tfm]):
  - **L1:** Secure Processing Environment vs Non-secure Processing Environment.
  - **L2:** additionally PSA RoT vs Application RoT.
  - **L3:** additionally each secure partition isolated from the others.
- **Crypto service:** a secure partition implementing the PSA Crypto API on the TF-PSA-Crypto reference library, with HW backends. It provides **caller isolation**: callers do not share keys, and caller identity comes from the system layout, so it cannot be spoofed. Persistent keys live in Internal Trusted Storage ([TF-M crypto design][tfm-crypto]).
- **For Bismuth:** use PSA Crypto *semantics* (opaque key IDs, usage flags, a permitted algorithm per key) as the keystore API. On TrustZone parts, offer "Bismuth NS + TF-M S" as the certified path.

---

## 3. Can Bismuth do better than Zircon in its domain?

Yes, on the axes that matter for MCUs, and only if the design accepts what the hardware cannot do.

| Axis | Zircon | Bismuth (proposed) | Better? |
|---|---|---|---|
| Kernel memory safety | C++ kernel, kernel CVEs from integer overflow and info leaks | Safe Rust except a small audited TCB. `checked_*` arithmetic on every user-supplied size | **Yes** |
| Authority model | Handles + rights, no ambient authority, but a root resource and run-time routing | Handles + rights. Split resources (MMIO range, IRQ line, DEBUG, POWER, POLICY, KEYSTORE) and no god-handle. The capability graph is **checked at compile time** from a manifest | **Yes** (smaller, auditable) |
| Syscall filtering | Entry via vDSO only. Per-process syscall subsets ("variants") experimental and unused | `SVC` is the only entry by hardware. **Per-domain syscall allow-mask** (one `u64` test). ~25–35 syscalls total | **Yes** |
| Revocation | No general revocation of transferred handles | Object *generation* bump revokes every handle to it. Tables are tiny, so revoking by scan is O(domains × slots) | **Yes** |
| Policy hierarchy | Arbitrary-depth jobs, policy fixed once children exist | Two levels (system → domain), static, can only tighten. Adds CPU budget, priority ceiling, memory and handle quotas | Simpler, adds DoS controls |
| RNG | One global ChaCha20 CPRNG, 30 s reseed, jitter + HW sources, no documented health tests, userspace path weak | Health-tested (SP 800-90B) sources, conditioned seed, root DRBG with fast key erasure, **per-domain DRBGs**, reseed on restart/restore, deterministic sim sources | **Yes** |
| Key isolation | Not a kernel concern (left to userspace and the TEE) | Keystore context with key handles; HW-isolated on TrustZone/secure-element parts | **Yes** for MCUs |
| Memory isolation granularity | Pages, guard pages, ASLR, W^X per mapping | 4–8 MPU regions per domain, coarse, no paging, no meaningful ASLR | **No** (hardware limit) |
| Dynamic software installation | Packages, components, sandboxes created at run time | Static domains. Optional later "app slot" domain for signed loadable code | **No** (by choice) |
| Testing of security properties | Fuzzing, KASAN | Deterministic host simulator: every rights check, quota, health-test failure and revocation is a unit test. Plus fuzzing the dispatcher and Kani proofs of the handle table | **Yes** (cheaper to get high assurance) |

The honest summary: Bismuth can be **more trustworthy per line of code** than Zircon and enforce **stricter, statically known policy**. It cannot be as *flexible*, and its isolation is bounded by MPU geometry, the absence of an IOMMU (DMA!) and physical attacks.

---

## 4. Design: security contexts (domains)

### 4.1 Vocabulary

| Term | Meaning | Zircon analogue |
|---|---|---|
| **Domain** | Unit of isolation and accounting. Owns an MPU region set, a handle table, quotas, a syscall mask, a priority ceiling, a fault policy and a DRBG. Contains ≥1 tasks. | Process (+ its job's policy) |
| **Task** | A thread of execution inside a domain (the existing `Tcb` gains `domain: DomainId`) | Thread |
| **Kernel domain (D0)** | The privileged domain. Existing kernel services (timer service, net task, drivers, middleware) run here. Its tasks keep calling the kernel as functions. | Kernel |
| **Legacy domain** | A privileged domain with an explicit "trusted" flag, for unported code (FreeRTOS compat) during migration. Visible in the manifest and the audit report. | (none) |
| **Object** | A kernel object: device, socket, NetRing, queue, semaphore, event, timer, channel, key, resource, domain, task | Kernel object |
| **Handle** | `u16` or `u32` index + generation into the domain's handle table | `zx_handle_t` |
| **Rights** | A bitset on each handle entry | `zx_rights_t` |
| **Resource** | A capability over a hardware range: MMIO window, IRQ line, DMA channel, flash/OTP range, `DEBUG`, `POWER`, `POLICY`, `ENTROPY_ADMIN`, `KEYSTORE_ADMIN` | Resource |

**Where per-domain kernel state lives** (Tock-grant style): in a statically sized, kernel-only array indexed by `DomainId`, *not* in domain memory. This is simpler than Tock grants and fine for static domains. If dynamic "app slots" arrive later, use real grants carved from the app's RAM allotment.

Rough per-domain cost:

| Item | Size |
|---|---|
| 16-slot handle table × 8 B | 128 B |
| DRBG state | ≈ 112 B |
| Saved MPU set (v8-M, 4 × RBAR/RLAR) | 32 B |
| Quotas and counters | ≈ 32 B |
| **Total** | **≈ 300 B** |

### 4.2 Handle table and rights

```rust
// Sketch only. Safe Rust, kernel-side.
pub struct Handle(u16);                     // [ index:6 | generation:10 ], 0 = invalid

bitflags! { pub struct Rights: u32 {
    const READ      = 1 << 0;  // Op::Read, recv, queue receive
    const WRITE     = 1 << 1;  // Op::Write, send, queue send
    const TRANSFER  = 1 << 2;  // Op::Transfer (bus transaction)
    const CONTROL   = 1 << 3;  // "safe" ioctls (class-defined)
    const CONFIG    = 1 << 4;  // "dangerous" ioctls: baud, address, calibration
    const POWER     = 1 << 5;  // Op::Power
    const WAIT      = 1 << 6;  // block/poll on the object's signals
    const SIGNAL    = 1 << 7;  // raise signals / notify
    const DUPLICATE = 1 << 8;  // duplicate (with ⊆ rights)
    const SEND_CAP  = 1 << 9;  // move this handle to another domain over IPC
    const MANAGE    = 1 << 10; // attach/detach middleware or hooks, change chain
    const MAP       = 1 << 11; // map object memory (NetRing, shared buffer) into the domain
    const INSPECT   = 1 << 12; // stats, info, chain listing
    const DESTROY   = 1 << 13; // kill task/domain, close for everyone, unregister device
    // key objects
    const K_ENCRYPT = 1 << 16; const K_DECRYPT = 1 << 17;
    const K_SIGN    = 1 << 18; const K_VERIFY  = 1 << 19;
    const K_DERIVE  = 1 << 20; const K_EXPORT  = 1 << 21; // EXPORT almost never granted
}}

struct Slot { obj: ObjRef /* kind:4 | index:8 | obj_gen:8 */, rights: Rights, gen: u16 }
```

Rules (each one is a host test):
1. **Monotonic rights.** `duplicate(h, mask)` and `send(h, mask)` produce `rights & mask`. No call can add a bit. Kani can prove this property directly.
2. **Generations everywhere.** A slot generation catches stale handles inside a domain. An object generation (`ObjRef.obj_gen`) is bumped on `revoke(obj)`, `unregister` or close-for-everyone. Every handle naming an older generation then fails with `Error::BadHandle`. This gives real revocation for free. `Device { index, generation }` already does half of this.
3. **Bad-handle policy.** On `BadHandle` or `WrongObject`, the domain's policy chooses `Deny` (return an error, the default) or `Kill` (fault the domain). This is Zircon's `ZX_POL_BAD_HANDLE`. Use `Kill` for hardened builds: a confused or compromised domain should die, not probe.
4. **No ambient authority.** `Device::find("uart0")` by name stays available *only* to D0 and legacy domains. Isolated domains get their handles from the manifest at start-up, in fixed slots (`HANDLE_UART = 3`, …), or by IPC from a domain holding `SEND_CAP`. A POSIX `open("/dev/uart0")` from an isolated domain is resolved against a **per-domain namespace** built from the manifest, as in Fuchsia's component namespace. The fd table becomes a view over the handle table.
5. **Handle values are not secrets.** Never use them for authentication. Authority comes from the table lookup alone.

### 4.3 How the middleware chain enforces rights

Rights are not a middleware. The flow is:

```
SVC → dispatcher
  1. syscall-mask check (domain policy)                 → Deny/Kill
  2. resolve handle in caller's table, check obj kind   → BadHandle/WrongObject
  3. required = rights_for(op)                          → AccessDenied
       Read→READ, Write→WRITE, Transfer→TRANSFER, Power→POWER,
       Ioctl{cmd} → ioctl_right(cmd)  (CONTROL or CONFIG, encoded in cmd bits;
                                       unknown/unencoded ioctls require CONFIG)
  4. validate user buffers → UserSlice (§5.3)           → Fault
  5. quota/budget checks (rate, bytes)                  → NoResources
  6. Device::request(req with Caller)  ── global → per-device → driver mw → driver
```

Concrete changes to the current API:

- **`Request` gains a private `caller: Caller` with a getter.** `Caller { domain: DomainId, rights: Rights, label: u16 }`. Middleware can *read* it but not change it, because the field is private to the `driver` module and `Next::run` forwards the same `Request`. Middleware may still reject (`Err(AccessDenied)`) or rewrite payload. It can never grant.
- **`AccessPolicy` becomes caller-aware**, e.g. "domain `telemetry` may only `Read`; domain `ota` may `Write` + `CONFIG`". `RateLimit` and `Stats` gain per-domain variants (`PerCaller<RateLimit, N>`), which turns the chain into a natural place for *mandatory* fine-grained policy on top of capability checks.
- **Chain management is privileged.** These require `MANAGE` on the device handle (or the `POLICY` resource for global middleware):
  - `Device::attach`, `Device::detach`
  - `add_global_middleware`, `remove_global_middleware`
  - `net` hook attach
  - `unregister`

  Isolated domains can never supply middleware *code*. Middleware is `&'static dyn` in the kernel image and runs privileged, so it is TCB. An isolated domain with `MANAGE` may only pick layers from a manifest-declared catalogue of vetted, parameterisable layers.
- **The global stage runs first and cannot be bypassed.** Put security-relevant layers (audit `Trace`, global `AccessPolicy`) there, and let the manifest mark them `locked` so `remove_global_middleware` refuses them even for D0 after `seal()` (see 4.4).
- **Packet hooks:** attaching or detaching hooks needs `MANAGE` on the interface handle. Sockets are objects with rights:
  - `READ`/`WRITE` for receive and send.
  - `CONFIG` for bind/connect/options.
  - A per-domain **net policy** (allowed interfaces, local ports, peer prefixes) is enforced in the socket layer at bind and connect, *not* in hooks, because hooks see packets before demultiplexing to sockets.
  - Zero-copy `NetRing` mapping needs `MAP` and costs one MPU region.

### 4.4 Job/policy hierarchy for MCUs: a static manifest

Flatten Zircon's job tree to **system → domains**. One optional "supervisor" domain holds `DESTROY`/`INSPECT` on others, as Hubris's supervisor does. Policy is declared in a manifest, compiled into `const` tables, and **validated at build time** by `const fn` assertions in a generated module (no proc-macro needed). A future `bismuth-xtask` can emit the tables and the linker script together.

```toml
[domain.sensor_app]
priority_ceiling = 12          # tasks in this domain can never exceed prio 12
cpu_budget = { per_ms = 100, us = 20000 }   # 20% budget, sporadic-server style
max_tasks = 3                  # quota for dynamic pthread/xTaskCreate
max_handles = 12
ram = 8192                     # data+bss+heap/pool
stacks = [1024, 512]
syscalls = ["dev_read", "dev_ioctl", "sleep", "rng_draw", "ipc_call", "wait"]
on_fault = "restart"           # restart | kill | halt-system | notify-supervisor
bad_handle = "kill"
handles = [
  { slot = 1, object = "dev:bme280", rights = ["READ", "CONTROL", "WAIT"] },
  { slot = 2, object = "ipc:keystore", rights = ["WRITE"] },
  { slot = 3, object = "key:telemetry_aead", rights = ["K_ENCRYPT"] },
  { slot = 4, object = "sock:udp", rights = ["WRITE", "CONFIG"], net = { peers = ["10.0.0.0/8"], ports = [5683] } },
]
```

Build-time checks are where Bismuth beats run-time routing:
- Every referenced object exists.
- Rights are a subset of what the object kind supports.
- **No isolated domain holds `K_EXPORT`, `DESTROY` on D0, `MANAGE` on locked chains, `MMIO` overlapping the kernel or another domain, or a DMA-capable peripheral** (see 5.4).
- MPU layout is feasible for the target's MPU (region count, v7-M power-of-two alignment).
- Priority ceilings respect the IPC uphill rule.
- The sum of CPU budgets is ≤ 100%.
- **Invariant assertions** such as `assert_only_holder!("key:*", "keystore")`, which make capability flow auditable.

At run time, `kernel::seal()` (called once before the scheduler starts) freezes the registry. After that, policy only tightens: a domain may `drop_rights` on its own handles or `restrict_syscalls` on itself (a `pledge`-like operation), never widen.

**Fault policy and restart:** on a MemManage, UsageFault or `Kill` action, the kernel stops the domain's tasks and revokes all objects it *owns*. Peers' handles to them start returning `PeerRestarted`, which is Hubris's generation check. The kernel then zeroes the domain's RAM and reseeds its DRBG (§6.4). Finally it applies `on_fault`.

---

## 5. Syscall boundary and memory protection

### 5.1 Cortex-M entry/exit

- Isolated tasks run with **`CONTROL.nPRIV = 1`** in thread mode on PSP (they already use PSP). D0 tasks keep `nPRIV = 0`. Set `CONTROL` per task in the PendSV switch, next to the `EXC_RETURN` and MPU reload.
- **Entry is `SVC #imm` only.** Cortex-M has no other way from unprivileged thread mode into privileged code except faults and interrupts. This is why Bismuth needs no vDSO and no PC-range check.
- **Pass the syscall number in a register (`r12`, or `r4` as Tock does), not the `SVC` immediate.** Reading the immediate means loading the instruction from user flash, an extra memory access, and the handler must validate that the stacked PC is readable.
- **The SVCall handler** (new asm in `arch/cortex_m.rs`, TCB) does the following:
  1. Captures PSP.
  2. Validates that the stacked exception frame lies inside the current task's stack region. On v8-M with `PSPLIM` this is guaranteed by hardware.
  3. Copies `r0–r3` + `r12` into a `SyscallArgs` value.
  4. Calls the **safe-Rust dispatcher** `kernel::syscall::dispatch(&mut Kernel, TaskId, SyscallArgs) -> SyscallRet`.
  5. Writes the results back into the stacked `r0–r1`.

  Blocking syscalls use the existing `block_current` + PendSV path.
- **Priorities:** SVCall gets a priority above PendSV and below device IRQs. It must not be preempted into a context switch mid-validation. Kernel state is still accessed via `IrqCell`.
- **ABI:** a small `bismuth-abi` crate (no `unsafe`) with syscall numbers, `Rights`, error codes and handle encodings, shared by kernel and the `bismuth-user` library. Aim for **≈25–35 syscalls**:

  | Group | Syscalls |
  |---|---|
  | Handles | close, duplicate, drop_rights, info |
  | Devices | request |
  | Sockets | open, bind/connect, send, recv |
  | Waiting | wait (on signals, ≤N handles), notify |
  | Time | sleep, now |
  | Tasks | spawn (quota), exit, join |
  | IPC | call, recv, reply, lease_read, lease_write |
  | Entropy | rng_draw |
  | Keys | key_op via keystore IPC, not a syscall |
  | Self-restriction | restrict |
  | Debug | log |

  Every POSIX and FreeRTOS compat call becomes a *user-side* library over these.

### 5.2 MPU programming: v7-M vs v8-M vs RISC-V

| | ARMv7-M PMSAv7 (M3/M4/M7) | ARMv8-M PMSAv8 (M33/M55/M23) | RISC-V PMP (+Smepmp) |
|---|---|---|---|
| Regions | 0 or 8 (16 on some M7) | 0–16 per security state | 0–16 (up to 64) entries |
| Geometry | Size 2^n ≥ 32 B, base aligned to size, 8 subregions (≥256 B) | Base/limit, 32-byte granularity, any size | TOR (any range, 2 entries), NAPOT (2^n), NA4; 4-byte granularity |
| Overlap | Allowed, higher region wins | **Overlap is a fault**, so the layout must be disjoint | Lowest-numbered matching entry wins |
| Stack guard | No HW limit register; use a 32 B no-access region or a stack-at-bottom-of-RAM layout | **`PSPLIM`/`MSPLIM`** (Mainline; on Baseline only in Secure state) give an exact, region-free guard | PMP entry or none; some cores add stack-limit CSRs |
| Pointer check | Software range check | **`TT`/`TTT` instruction** reports the MPU region and unprivileged R/W permission for an address | Software range check |
| Kernel view | `PRIVDEFENA = 1` background map for privileged code | Same | M-mode bypasses PMP unless **Smepmp MML** is set; then locked rules deny M-mode access to U memory (SMAP-like) |

Region budget per isolated domain (dynamic, reloaded on switch):

| Region | Contents |
|---|---|
| R_code | Domain text/rodata, RX. On v7-M, alternatively share one "user code" region for all domains |
| R_data | data + bss + stacks + pool, RW, XN |
| R_dev / R_share | One MMIO window or shared buffer/NetRing, RW, XN (optional, at most two) |

Static regions:

| Region | Contents |
|---|---|
| R_kflash | Kernel flash, privileged RX (with `PRIVDEFENA` this can be implicit) |
| R_guard | v7-M only: a 32 B stack guard |

That leaves room for at most 2 domain-specific device windows on an 8-region MPU. The manifest checker enforces this.

**W^X** is unconditional:
- RAM regions are always XN.
- Flash regions are never writable from user mode.
- Flash programming goes through a kernel driver that needs a `FLASH_WRITE` resource.

There is no `VMAR_WX` knob to get wrong.

**v7-M layout tool:** power-of-two alignment wastes RAM badly. Use subregion disabling and sort domains by size. Hubris's build tool solves the same problem and shows it is tractable. The tool emits the linker script; the kernel only checks (`const`) that the tables are valid.

### 5.3 User memory: `UserSlice` and leases

- New TCB module **`kernel/usermem.rs`** (the *only* new place turning user addresses into Rust references). `UserSlice::new(caller_regions, addr, len, Access::Read|Write) -> Result<UserSlice, Error>`:
  - `checked_add` on `addr + len`.
  - The range must lie entirely in one of the caller's RW (or R) regions.
  - On v8-M, cross-check the start and end with `TTT`.
  - `as_bytes()` / `as_bytes_mut()` produce `&[u8]` / `&mut [u8]` with a lifetime bound to the syscall.
- **TOCTOU rule (from Tock TRD104):** the kernel never reads a user length or pointer twice. It copies small arguments (≤64 B, e.g. socket addresses, ioctl structs) into kernel stack buffers before validating them. Large buffers are used in place but treated as untrusted bytes. Another task in the *same* domain may race on them, which only harms that domain.
- **IPC leases (Hubris):** `ipc_call(h, msg, leases[≤4])`. The server reads and writes a lease via `lease_read`/`lease_write` syscalls that copy through the kernel, bounds-checked against the *client's* regions. Leases die when the call returns. No MPU region is spent on IPC.
- **Host simulator:** the simulator has no MPU, so implement a `SimMpu` region table and route every `UserSlice` creation through it. Tests can then assert that out-of-region pointers, wrapped lengths, kernel addresses and other domains' buffers are all rejected. The dispatcher code is identical on host and target. Only the trap and asm differ.

### 5.4 DMA, interrupts and MMIO resources

- **DMA bypasses the MPU.** An isolated domain with raw access to a DMA controller (or to a peripheral with its own bus-master DMA, such as Ethernet MACs and SDMMC) can read and write all of RAM. Rules:
  1. DMA-capable peripherals are never granted as raw MMIO resources to isolated domains. The manifest checker refuses this unless the domain is marked trusted.
  2. DMA is always programmed by a D0 driver that validates buffer addresses with `UserSlice` against the requester's regions.
  3. On v8-M SoCs with TrustZone, also use the SoC's memory/peripheral protection controllers (MPC/PPC, "secure attribution of bus masters") so NS DMA cannot reach secure memory.
- **IRQ as notification (Hubris):** a user-space driver domain gets an `Irq` resource. The kernel ISR masks the line and sets a notification bit on the owning task, and the domain unmasks it via syscall. An IRQ line belongs to exactly one domain.
- **MMIO resources** are Zircon resources, simplified: `Mmio { base, len, exclusive }`. Exclusive by default. Granting one costs an MPU region and maps it RW+XN+Device into the domain.

### 5.5 Hardening that does fit MCUs

- **Stack overflow:** `PSPLIM` on v8-M, guard region or bottom-of-RAM stacks on v7-M. Painted-stack watermarks (already in `kernel/stack.rs`) go to telemetry.
- **Rust:**
  - `overflow-checks = true` in release *for the kernel crate*. The cost is small and it turns CVE-2021-22556-class bugs into panics.
  - `panic = "abort"`, with the panic handler applying the system fault policy.
  - `#![deny(unsafe_code)]` stays.
  - Use `cargo geiger`/`cargo-vet` to track `unsafe` in dependencies.
- **Control flow:** Rust plus no writable code pointers in user-reachable state already removes most stack-smashing value. **PACBTI** (Cortex-M85 and other v8.1-M parts) gives return-address signing and BTI. Enable it via the target features when the part supports it. It is not a requirement.
- **Fault-injection hardening** for boot and keystore decisions: double-checks, constant-time comparisons via `subtle`, and random delays drawn from the DRBG. These are relevant because MCUs are physically reachable.
- **Debug port:** a `DEBUG` resource and the manifest decide whether SWD stays open. Production images lock it through the part's mechanism (RDP/APPROTECT/…), and attestation reports the state.

---

## 6. Entropy architecture

### 6.1 Sources and trust levels

| Source | Credit | Notes |
|---|---|---|
| On-chip TRNG (STM32 RNG, nRF RNG/CRACEN, NXP TRNG, RP2350 TRNG, …) | Per vendor 90B assessment or our own measurement | Primary source. Wrapped with health tests (6.2). Reads via `arch/mmio.rs` |
| Secure element / TF-M `psa_generate_random` | Full, if the device is certified | Preferred where present (TrustZone path) |
| Device-unique seed provisioned at manufacture (OTP/secure storage), plus a monotonic boot counter | 0 (mix-in only) | Guarantees distinct streams even if the TRNG is broken. Counter defeats replay across boots |
| SRAM power-up state (before `.bss` zeroing) | 0 unless assessed | Device-unique noise. Must be read by the boot stub before RAM init |
| Jitter (timer/cycle-counter jitter, ADC LSBs) | 0 unless assessed per part | On cacheless, in-order MCUs at fixed clocks, CPU timing jitter can be close to deterministic. Zircon relies on jitterentropy on application cores, which is a very different setting |
| Radio RSSI/noise | 0 | Attacker-influenced |

"Credit" means entropy counted towards the 256-bit seeding threshold. Anything else is still mixed in, which is harmless because of the hash, but cannot unblock seeding. Per-part credit numbers come from running NIST's [SP 800-90B assessment tool][nist-ea] on raw samples, recorded in the board support package.

### 6.2 SP 800-90B health tests

Implement these in safe Rust (`kernel/entropy/health.rs`, pure functions, fully host-testable) ([SP 800-90B][nist-90b]):

- **Repetition Count Test:** fail if one sample value repeats `C` times in a row, with `C = 1 + ⌈−log₂(α) / H⌉`, where `H` is the assessed min-entropy per sample and α the false-positive rate (pick α = 2⁻³⁰…2⁻⁴⁰).
- **Adaptive Proportion Test:** over a window of `W = 1024` samples (`512` for binary sources), fail if the first sample's value occurs ≥ `C_apt` times. `C_apt` comes from the binomial inverse CDF for `H` and α. Ship a small precomputed table, as RIOT does ([RIOT entropy source][riot-ent]).
- **Start-up tests:** run RCT and APT over at least 1024 consecutive samples before the first use, and discard them.
- **On failure:** mark the source unhealthy, raise a security event (log + supervisor notification), and stop crediting it. If no credited source is healthy at boot, the system stays *unseeded*: `rng_draw` blocks, or returns `Error::NotReady` in non-blocking mode. Key generation is refused, and the manifest chooses whether the system halts. Never silently fall back to an uncredited seed.
- Hardware TRNGs that already implement on-chip health tests (many do) still get the software RCT/APT. They cost microseconds and catch driver bugs such as reading a stale data register.

### 6.3 Conditioning and the root DRBG

- **Conditioner:** SHA-256 over (credited samples ‖ uncredited mix-ins ‖ device seed ‖ boot counter ‖ timestamp), using RustCrypto `sha2`. HMAC-SHA-256 or HKDF-Extract (`hkdf`) are equally acceptable vetted constructions.
- **Root DRBG:** ChaCha20 keystream with **fast key erasure** ([Bernstein][djb-fke]). Each request generates a block, uses the first 32 bytes as the next key, outputs the rest, and wipes the buffer (`zeroize`). This gives forward secrecy *per call*, not just per reseed, which is stronger than Zircon's 30-second reseed alone. It is ~40 lines of glue over the `chacha20` crate's keystream. No new primitive is invented.
- **If formal compliance matters (FIPS 140-3 / SESIP / PSA Certified L2+):** offer an SP 800-90A **HMAC_DRBG or CTR_DRBG** backend behind the same trait ([SP 800-90A][nist-90a]). On TrustZone parts, delegate to the certified secure side instead.
- **Reseed** (`k = SHA-256(seed ‖ k_old)`, the Zircon construction):
  - every *N* outputs or every *T* seconds (default 1 MiB / 60 s, configurable);
  - on every domain restart (6.4);
  - on resume from any power state that restored RAM from a non-volatile copy;
  - on explicit `ENTROPY_ADMIN` request.

### 6.4 Per-context CSPRNG instances

The user's goal is "each process should have its own entropy generator". Each domain gets its own DRBG instance in kernel memory:

- **Derivation:** `seed_d = root.draw(32) ⊕ HKDF-Expand(root_seed_epoch, "bismuth/drbg" ‖ domain_id ‖ generation)`. In practice, `root.draw(32)` alone is enough. The label adds domain separation for the deterministic-simulation mode.
- **Why per-domain:**
  - **State isolation:** a bug that leaks one domain's DRBG state reveals only that domain's future outputs.
  - **Accounting:** draws are charged to the domain's quota or budget, so one domain cannot exhaust a shared generator's reseed budget.
  - **Clean restart semantics.**
  - **Deterministic replay** in the simulator, per domain.
- **Fork-safety analogue:** Bismuth has no `fork()`, but the same hazard appears whenever DRBG state can be *duplicated or replayed*:
  - domain restart from the same image;
  - RAM restored from a backup;
  - a cloned simulator snapshot;
  - a cloned device image provisioned with a RAM-retained state.

  Rules:
  1. A DRBG is always re-derived from the root on domain (re)start, keyed by the bumped generation.
  2. The root reseeds from fresh TRNG output after any state restore.
  3. A persistent boot counter is mixed into every boot seed.

  rand 0.9 deliberately removed implicit fork protection from `ReseedingRng`/`ThreadRng` and recommends that "the code causing the fork" reseeds ([rand 0.9 notes][rand09]). Bismuth's kernel *is* the code causing the "fork" (restart/restore), so it owns this.
- **API:**
  - `rng_draw(buf)` serves from the caller's DRBG. It is non-blocking once the system is seeded and never fails afterwards (Zircon's contract).
  - User-side, `bismuth-user` implements `rand_core::{RngCore, CryptoRng}` over the syscall.
  - It also provides a `getrandom` 0.3 custom backend (`--cfg getrandom_backend="custom"`), so `rand`, `uuid` and RustCrypto key generation work unmodified in user domains. The required `extern` shim needs `unsafe`, so it lives in the user-runtime crate, not in the kernel TCB.
- **Kernel-internal consumers** (TCP ISNs, ephemeral ports, DNS IDs, MAC randomisation, timing jitter for fault-injection resistance) use D0's DRBG. smoltcp needs a random seed for TCP ISNs, so feed it from there instead of a constant.

### 6.5 Vetted crates and why not to roll our own

Crypto fails silently: a wrong-but-plausible keystream, biased modular reduction, or a non-constant-time compare all pass functional tests. Use crates with review history, wide usage and constant-time design:

| Need | Crate(s) | Notes |
|---|---|---|
| RNG traits | `rand_core` | Common trait surface; `CryptoRng` marker |
| DRBG keystream | `chacha20` (RustCrypto) or `rand_chacha` | Pure Rust, `no_std`. Fast-key-erasure wrapper on top |
| Hash/MAC/KDF | `sha2`, `hmac`, `hkdf` | `no_std`; SHA-256 also widely HW-accelerated |
| AEAD | `chacha20poly1305`, `aes-gcm`, `ccm` | `aes-gcm` and `chacha20poly1305` were reviewed by NCC Group in 2020 with no significant findings ([NCC][ncc-aead]). `ccm` for 802.15.4/BLE |
| Block cipher | `aes` | Constant-time bitsliced software implementation; HW backends preferred |
| Signatures / DH | `ed25519-dalek`, `x25519-dalek` (curve25519-dalek), `p256` (ecdsa) | P-256 for PKI/attestation interop. Check the audit status of each version before use |
| Constant time | `subtle` | All tag/MAC/PIN comparisons |
| Secret hygiene | `zeroize` | `Zeroize`/`ZeroizeOnDrop` on keys and DRBG state |
| Post-quantum (later) | `ml-kem`, `ml-dsa` (RustCrypto) | Track maturity. Hybrid only |
| Supply chain | `cargo-vet`, `cargo-deny` | Pin versions and record audits |

**Constant-time hazard on MCUs:** Cortex-M3 `UMULL`/`SMULL`/`UMLAL`/`SMLAL` have *data-dependent* timing (early termination), unlike M4 ([BearSSL notes][bearssl-ctmul]). Software X25519/P-256/Poly1305 on M3 may therefore leak timing. On M3 targets, prefer a HW PKA/secure element for asymmetric operations, or validate the chosen crate's field arithmetic for M3 timing before shipping. Flash accelerators and caches on some MCUs (e.g. instruction/data prefetch caches) can also introduce table-lookup timing, which is one more reason to avoid T-table AES.

---

## 7. Crypto service (keystore)

### 7.1 Model

- **Keys never leave the keystore context.**
  - Phase A: a privileged kernel service in D0 (`kernel::keystore`, safe Rust).
  - Phase B: its own isolated domain, reached by IPC, so a D0 driver bug cannot read keys either.
  - Phase C: TrustZone Secure side or a secure element.

  The API is identical across all three.
- **Key handles:** `key_generate(attrs) -> Handle`, `key_import(attrs, material)`. `attrs` follows PSA semantics: type, bits, `usage` (→ rights `K_ENCRYPT|K_DECRYPT|K_SIGN|K_VERIFY|K_DERIVE|K_EXPORT`), `permitted_alg` (one algorithm), lifetime (volatile/persistent) and an owner-domain id.
  - The keystore checks **both** the caller's handle rights and the key's own usage policy.
  - A key bound to `AES-128-CCM` cannot be used for `AES-ECB`. This blocks cross-algorithm and cross-protocol attacks.
  - `EXPORT` is denied for all keys by default. The manifest checker flags any grant of it.
- **Operations:** `aead_seal/open`, `sign/verify`, `mac`, `derive` (HKDF into a *new key handle*, never into bytes), `hash` (no key, so it can run in the caller's own domain and save an IPC round-trip), `agree` (X25519/ECDH into a derived key handle).
  - Data moves by leases.
  - Multi-part operations are objects with a bounded count per domain (quota).
- **Caller isolation (TF-M style):**
  - Persistent keys are namespaced by owner domain. Domain A cannot name domain B's key IDs at all.
  - Sharing a key means sending its *handle* over IPC (with `SEND_CAP`), which is explicit and visible in the manifest.

### 7.2 Backends

```rust
pub trait AeadBackend { fn seal(&self, key: &KeySlot, nonce: &[u8], aad: &[u8], buf: &mut [u8], tag: &mut [u8]) -> Result<(), Error>; /* open… */ }
pub trait HashBackend { /* init/update/finalize */ }
pub trait SignBackend { /* sign/verify, P-256 / Ed25519 */ }
pub trait KeyWrap     { /* HUK-derived wrapping for persistent keys */ }
```

- **Implementations:**
  - HW: STM32 AES/HASH/PKA, nRF CRACEN/CryptoCell, NXP HASHCRYPT/CASPER/ELS, ESP32-C RSA/SHA/AES.
  - SW: RustCrypto, always compiled in as the fallback and used as the *reference* in simulator cross-check tests.
- **Boot-time known-answer self-tests (KATs)** for every enabled backend (FIPS 140-3 style). A failing HW backend is disabled and the SW fallback takes over (or the system halts, per the manifest). This catches broken silicon errata and driver bugs.
- **Hardware unique key (HUK):** where the part has one (often only usable by the HW AES engine), persistent keys are stored *wrapped* under a HUK-derived KEK in flash. The plaintext key exists only in keystore RAM, and with HW key slots it never touches CPU-visible RAM at all.
- **Accelerator DMA:** HW crypto engines often use DMA. The keystore must own the engine (MMIO + DMA resource), and buffers come through lease copies, never directly from user domains (5.4).

---

## 8. Secure boot, measured boot and attestation hooks

Bismuth should not implement a ROM bootloader, but it must define the hand-off and the hooks:

1. **Verified boot:** an immutable first stage (vendor ROM secure boot, or MCUboot, or a small Rust stage) verifies the Bismuth image signature (ECDSA-P256 or Ed25519) and enforces **anti-rollback** via a monotonic counter (OTP or secure storage).
2. **Measured boot via TCG DICE:** the first stage computes `CDI = KDF(UDS, H(next_image))` and *locks the UDS* (HW latch) before jumping. Bismuth receives the CDI and derives the device alias/attestation key from it inside the keystore ([TCG DICE][tcg-dice]). DICE fits MCUs because it needs only a hash, a KDF and a one-shot latch, and it gives a unique identity per firmware version without a TPM.
3. **Handoff block:** a `#[repr(C)]` struct at a fixed RAM address (parsed in safe Rust from a byte slice) holding:
   - image measurements, firmware version, security counter;
   - boot-state flags (debug open?, lifecycle state);
   - CDI or wrapped keys;
   - any boot entropy (SRAM PUF samples).

   The kernel **consumes and zeroes** the secret parts before starting any domain.
4. **Attestation:**
   - `attest(nonce, claims_mask) -> token` produces a CBOR/COSE_Sign1 token following the **PSA attestation token profile of EAT** ([RFC 9783][rfc9783]). Claims: instance ID, implementation ID, boot seed, software components (measurements), lifecycle state, security counter, and optionally the manifest hash (so the verifier sees the exact capability graph). The token is signed inside the keystore.
   - On the TrustZone path, forward to TF-M's Initial Attestation service.
5. **Runtime measurement:** the manifest hash and the list of trusted/legacy domains are part of the attestation, so "this device runs domain X with only these rights" becomes remotely verifiable. Zircon has no equivalent.
6. **Lifecycle:** support provisioning → deployed → RMA states (keys wiped on RMA) through the `POLICY` resource. Debug unlock requires an authenticated challenge, as PSA does.

---

## 9. TrustZone-M split

| Option | Secure side | Non-secure side | Use when |
|---|---|---|---|
| **A. Bismuth NS + TF-M S** (recommended first) | TF-M: PSA Crypto, ITS/PS, Attestation, FWU, platform entropy | All of Bismuth (scheduler, domains, drivers, net) | Product needs PSA Certified / SESIP soon. Keystore backend = PSA client calls via NSC veneers |
| **B. Bismuth NS + minimal Rust secure partition** (long-term) | Keystore, entropy pool, attestation and secure storage only, as a run-to-completion service with no scheduler | Bismuth | Pure-Rust stack, smaller secure TCB, no certification need |
| **C. Bismuth S-only** | Everything, no NS world | none | TrustZone part but no need for two worlds. Use MPU domains only, and set SAU so everything is Secure |

Notes:
- **Never schedule threads in Secure state.** Keep the secure side a library of non-blocking services (TF-M's Library model). That avoids a secure scheduler and its priority-inversion and DoS problems.
- **NSC veneers must validate NS pointers** with `TT`/`TTA` (CMSE `cmse_check_address_range`) and copy arguments in before use (TOCTOU). Rust's `cmse-nonsecure-entry`/`-call` ABIs are still unstable as of this writing. Until they stabilise, put the veneer layer in a tiny C or asm shim in the secure image (its own TCB), *outside* the Bismuth crate.
- **Bismuth domains still matter on the NS side.** TrustZone protects keys from Bismuth, while MPU domains protect Bismuth's tasks from each other. Both MPUs (S and NS banked) are used.
- **Partition peripherals and memory with SAU/IDAU + MPC/PPC.** The TRNG, crypto engine, key storage and OTP become Secure-only, and NS DMA masters cannot reach Secure SRAM.

---

## 10. What NOT to copy from Zircon

| Zircon feature | Why not for Bismuth | Instead |
|---|---|---|
| VMOs/VMARs, COW clones, pagers | No MMU and no pages; MPU regions are scarce | Static domain memory + leases + a few mapped shared buffers |
| ASLR/KASLR | Address spaces are KBs wide and layouts are fixed by the linker; entropy would be a handful of bits at real cost (PIC, relocation) | W^X, exact stack limits, Rust memory safety, PACBTI where present |
| vDSO + PC check | `SVC` is already the only entry; no shared libraries | `SVC` + per-domain syscall mask |
| ELF process loading, dynamic component install | Static images; loaders add a large parser to the TCB | Build-time domains; later, signed "app slots" à la Tock if needed |
| Arbitrary-depth job tree | Few domains; deep trees add policy complexity with no benefit | system → domains (+ supervisor) |
| 64-bit koids, 32-bit handle values | Memory cost | 16-bit handles with generations |
| Ports, async waits, futexes | Heavy objects; existing event flags and notifications suffice | `wait(handles[≤N], signals)` + task notifications + IRQ-as-notification |
| Channels carrying arbitrary handle arrays + FIDL wire format | Complexity and copy cost | Synchronous IPC with ≤1 handle per message and leases; a small Rust-typed message schema |
| Root resource as a bearer token for "everything" | God-capability; a criticised pattern | Split resources (MMIO/IRQ/DMA ranges, DEBUG, POWER, POLICY, ENTROPY_ADMIN, KEYSTORE_ADMIN); D0 holds them all but isolated domains get exact slices |
| Run-time capability routing (component manager) | Run-time routing logic is TCB and fails late | Compile-time routing check from the manifest |
| Huge syscall surface (`object_get_info` topics, etc.) | Every syscall parses untrusted input | ~30 syscalls, table-driven, fuzzed |

**What *to* copy:**
- handles + monotonic rights;
- no ambient authority;
- resources for hardware ranges (shared vs exclusive);
- policy that only tightens, with `BAD_HANDLE → KILL`;
- the ChaCha20 + SHA-256 mix CPRNG design and "only kernel-reachable sources are trusted";
- object signals for `wait`;
- the component-framework idea of a *namespace built from declared capabilities*.

---

## 11. Phased implementation plan

Each phase lands with host-simulator tests (`cargo test`, deterministic) and keeps `#![deny(unsafe_code)]`. New `unsafe` is listed explicitly and confined to new TCB modules with `// SAFETY:` comments and their own tests.

| Phase | Deliverable | Host-sim tests | New `unsafe` |
|---|---|---|---|
| **0. Vocabulary** | `security` module: `DomainId`, `Rights`, `Handle`, `HandleTable<N>`, `ObjRef` + object generations, `Caller`, `Policy` types. `Tcb.domain`. D0 default so nothing changes behaviourally | Rights monotonicity (property tests); stale/forged handles; revocation via generation bump; table exhaustion → `NoResources` | none |
| **1. Rights at the API edge** | `Caller` threaded into `Request` (private field). Rights gate before the middleware chain. Ioctl right encoding in `driver::class::ioctl`. `MANAGE` for attach/detach/global middleware and hooks. Caller-aware `AccessPolicy`, `PerCaller<RateLimit>`. POSIX fd table as a handle-table view. Socket rights + per-domain net policy | Per-op denial matrix; middleware cannot widen; locked global layers; socket bind/peer policy; existing tests pass unchanged under D0 | none |
| **2. Entropy** | `entropy::{Source, health, conditioner, Drbg}`; root DRBG (ChaCha20 FKE); per-domain DRBGs; `rng_draw`; sim sources (deterministic, stuck-at, biased, intermittent); TRNG driver via `arch/mmio.rs`; smoltcp ISN seeding | RCT/APT trip on stuck/biased streams and not on good ones (α-calibrated); startup tests; unseeded → `NotReady`; reseed-on-restart produces distinct streams; FKE: old outputs not reproducible from new state; KATs vs ChaCha20 RFC 8439 vectors | none (`chacha20`, `sha2`, `zeroize` deps) |
| **3. Manifest and policy** | Manifest → `const` tables (initially hand-written `const` arrays, later generated by `xtask`). Build-time assertions (rights subset, no `K_EXPORT`, no DMA to isolated, budgets ≤100%, priority ceilings). Quotas; CPU budget enforcement in `tick()`; `seal()`; `restrict()`; fault policy + supervisor notification | Quota exhaustion; priority ceiling enforced on `spawn`/`set_priority`; budget overrun throttles; `Kill`/`Restart` paths revoke owned objects and peers see `PeerRestarted`; `seal()` freezes the registry | none |
| **4. Syscall boundary** | `bismuth-abi` crate; `kernel::syscall::dispatch` (safe); `kernel/usermem.rs` (`UserSlice`); `SimMpu` region model; syscall mask; IPC call/recv/reply + leases; user library `bismuth-user` (POSIX/FreeRTOS shims move here for isolated domains). On target: SVCall asm, `CONTROL.nPRIV` per task, `arch/mpu_v7.rs` / `arch/mpu_v8.rs` / `arch/pmp.rs`, PSPLIM, MemManage → fault policy | Sim: every syscall via a register-array trampoline; pointer-validation suite (wrap, kernel addr, other domain, partially-in-range); TOCTOU (args copied once); syscall-mask denial; lease bounds. Target: QEMU `mps2-an385` (M3), `mps2-an505`/`an521` (M33) in CI for fault-on-violation tests | `arch/cortex_m.rs` (SVC/MPU switch asm), `arch/mpu_*.rs` (register writes, could live in `arch/mmio.rs`), `kernel/usermem.rs` (address → slice) |
| **5. Keystore + crypto** | Keystore service (D0 first) with key handles, PSA-style attrs, SW backends (RustCrypto), KATs, HW backend trait + one board implementation; persistent keys wrapped under HUK or a sim KEK; later moved into its own domain over IPC | KATs for every algorithm; HW-vs-SW differential tests (sim HW backend = SW + fault injection); usage/alg policy denial; cross-domain key isolation; `EXPORT` denial; zeroize on destroy (inspect state in sim) | none (HW backends via `arch/mmio.rs`) |
| **6. Boot hand-off + attestation** | Handoff parser (safe, bounds-checked); DICE CDI → alias key; `attest()` producing a COSE_Sign1 PSA-profile token; manifest hash claim; lifecycle states; MCUboot integration notes | Parser fuzz corpus; token golden vectors; secrets zeroed after consumption; rollback counter monotonicity | none |
| **7. TrustZone-M** | Option A: keystore/entropy backend = TF-M PSA client (NS). Board ports with SAU/MPC/PPC configuration owned by TF-M. Option B prototype later | Sim: PSA backend mocked behind the same trait. QEMU `mps2-an521` runs TF-M + Bismuth NS | NSC call shim (outside the crate, or a tiny `arch/cmse.rs`) |
| **8. Assurance** | `cargo-fuzz` on `dispatch`, ioctl decoding, handoff parser and manifest checker; **Kani** proofs (rights monotonicity, `UserSlice` range arithmetic, handle-table generation logic, health-test counters); Miri over `kernel/cell.rs` + `stack.rs` host tests; `cargo-vet` audits for crypto deps; TCB line-count report in CI | Fuzz/proof harnesses run in CI (bounded) | none |

Ordering rationale:
- Phases 0–3 change no hardware behaviour but make every security decision explicit and tested. They are useful even while everything still runs privileged, because rights checks catch bugs in trusted code too.
- Phase 4 then only adds the *mechanism* (trap + MPU). The policy it enforces has already been tested for months on the host.
- Entropy (phase 2) comes early because sockets, TCP ISNs and every later crypto feature depend on it.

---

## 12. Summary table

| Topic | Recommendation |
|---|---|
| Security context | Static **domain** = MPU region set + handle table + rights + quotas + syscall mask + priority ceiling + CPU budget + fault policy + own DRBG |
| Capability model | Zircon-style handles, rights only reduce, generation-based revocation, no ambient authority, split resources (no root god-handle) |
| Devices/sockets | Kernel rights gate *before* middleware; `Caller` in `Request` is read-only to middleware; chain management needs `MANAGE`; per-domain socket policy in the socket layer |
| Policy hierarchy | system → domains (+ supervisor); manifest compiled to `const` tables; capability graph verified at build time; only-tighten at run time (`restrict`, `seal`) |
| Syscalls | Unprivileged thread mode + `SVC`, syscall number in a register, ~30 table-driven calls, per-domain allow-mask, no vDSO |
| Memory protection | v8-M base/limit + `PSPLIM` + `TT`; v7-M power-of-two layout tool + guard region; RISC-V PMP + Smepmp; W^X unconditional; DMA only through kernel drivers |
| User memory / IPC | `UserSlice` (single TCB module), copy-in small args, Hubris-style leases, synchronous IPC |
| Entropy | TRNG + SP 800-90B RCT/APT + startup tests; SHA-256 conditioning; ChaCha20 fast-key-erasure root DRBG; per-domain DRBGs; reseed on restart/restore/time/volume; jitter/SRAM credited 0 unless assessed |
| Crypto | Keystore context, PSA-style key handles + usage/alg policy, keys never exported, HW backends + RustCrypto fallback + KATs, `subtle`/`zeroize`, M3 multiply timing caveat |
| Boot/attestation | Verified + measured boot via DICE, handoff block, PSA-profile EAT token (RFC 9783) including the manifest hash, anti-rollback, lifecycle |
| TrustZone-M | First Bismuth NS + TF-M S; later a minimal Rust secure partition; no secure-side scheduler |
| Don't copy | VMOs/VMARs, ASLR, vDSO, ELF loading, deep job trees, ports/futexes, FIDL-scale IPC, root resource, run-time routing, large syscall surface |
| Assurance | Deterministic sim tests per phase, fuzzing, Kani proofs on the TCB-adjacent logic, `cargo-vet` |

---

## References

**Zircon / Fuchsia**
- [zx-concepts]: Zircon Kernel Concepts. https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/docs/concepts/kernel/concepts.md
- [zx-rights]: Zircon Rights. https://fuchsia.dev/fuchsia-src/concepts/kernel/rights
- [zx-jobpol]: `zx_job_set_policy`. https://fuchsia.dev/reference/syscalls/job_set_policy
- [zx-vdso]: Zircon vDSO. https://fuchsia.dev/fuchsia-src/concepts/kernel/vdso
- [zx-resource]: Resource kernel object. https://fuchsia.dev/fuchsia-src/reference/kernel_objects/resource
- [zx-cprng]: Cryptographically Secure Pseudo Random Number Generator (Zircon). https://fuchsia.dev/fuchsia-src/concepts/kernel/cprng
- [zx-cprng-draw]: `zx_cprng_draw`. https://fuchsia.dev/reference/syscalls/cprng_draw ; `zx_cprng_add_entropy`: https://fuchsia.dev/reference/syscalls/cprng_add_entropy
- Jitterentropy collector (Fuchsia). https://docs.fuchsia.dev/cpp/crypto/entropy/_ZTVN6crypto7entropy22JitterentropyCollectorE.html
- [fx-caps]: Component capabilities. https://fuchsia.dev/fuchsia-src/concepts/components/v2/capabilities
- [zx-safestack]: SafeStack in Zircon & Fuchsia. https://fuchsia.googlesource.com/fuchsia/+/b0ba8b34057f8cc0dd6819ccf0510c4690d82bfc/zircon/docs/safestack.md
- [zx-scs]: ShadowCallStack in Zircon & Fuchsia. https://fuchsia.googlesource.com/fuchsia/+/main/docs/concepts/kernel/shadow_call_stack.md
- [cve-22556]: CVE-2021-22556 record. https://www.cve.org/CVERecord?id=CVE-2021-22556 (mirror: https://vulnerability.circl.lu/vuln/cve-2021-22556)
- [cve-0882]: CVE-2022-0882. https://nvd.nist.gov/vuln/detail/cve-2022-0882
- [qb-fuchsia]: Quarkslab, "Playing Around With The Fuchsia Operating System" (June 2020). https://blog.quarkslab.com/tag/google.html ; [qb-summary]: https://tech.slashdot.org/story/20/06/10/008245/playing-around-with-the-fuchsia-os
- [pt-fuchsia]: A. Popov, "A Kernel Hacker Meets Fuchsia OS" (Positive Technologies, 2022). https://swarm.ptsecurity.com/a-kernel-hacker-meets-fuchsia-os/ ; [pt-slides]: https://archive.nullcon.net/goa-2022/documents/kernel-hacker-meets-fuchsia-OS-Goa22.pdf

**Comparators**
- [sel4-proofs]: seL4 Proofs. https://sel4.systems/Verification/proofs.html ; [sel4-configs]: Verified configurations. https://docs.sel4.systems/projects/sel4/verified-configurations.html
- [tock-design]: Tock design. https://www.tockos.org/documentation/design/ ; [tock-threat]: Tock threat model. https://book.tockos.org/doc/threat_model/threat_model ; [tock-trd104]: TRD104 syscalls. https://book.tockos.org/trd/trd104-syscalls
- [hubris-ref]: Hubris reference. https://hubris.oxide.computer/reference/
- [zephyr-user]: Zephyr user mode overview. https://docs.zephyrproject.org/latest/kernel/usermode/overview.html
- [tfm-crypto]: TF-M Crypto Service design. https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/services/tfm_crypto_design.html
- [tfm-iso]: TF-M FF-M isolation. https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/ff_isolation.html ; [zephyr-tfm]: https://docs.zephyrproject.org/latest/services/tfm/overview.html

**Entropy and crypto**
- [nist-90b]: NIST SP 800-90B, Recommendation for the Entropy Sources Used for Random Bit Generation. https://csrc.nist.gov/pubs/sp/800/90/b/final
- [nist-90a]: NIST SP 800-90A Rev. 1 (DRBGs). https://csrc.nist.gov/pubs/sp/800/90/a/r1/final
- [nist-ea]: NIST SP 800-90B Entropy Assessment tool. https://github.com/usnistgov/SP800-90B_EntropyAssessment
- [riot-ent]: RIOT OS entropy source health tests (RCT/APT implementation). https://api.riot-os.org/group__sys__entropy__source__common.html
- Linux RFC: SP 800-90B RCT in the kernel RNG. https://lkml.iu.edu/hypermail/linux/kernel/2009.2/06123.html
- [djb-fke]: D. J. Bernstein, "Fast-key-erasure random-number generators" (2017). https://blog.cr.yp.to/20170723-random.html
- [rand09]: rand 0.9 update guide (fork protection removed, reseed responsibility). https://rust-random.github.io/book/update-0.9.html
- [ncc-aead]: NCC Group, Public Report: RustCrypto AES-GCM and ChaCha20+Poly1305 Implementation Review (2020). https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/
- [bearssl-ctmul]: T. Pornin, "Constant-Time Mul" (Cortex-M3 multiply timing). https://www.bearssl.org/ctmul.html
- RFC 8439, ChaCha20 and Poly1305. https://www.rfc-editor.org/rfc/rfc8439
- RustCrypto: https://github.com/RustCrypto ; rand_core/rand_chacha: https://github.com/rust-random/rand ; subtle: https://github.com/dalek-cryptography/subtle ; zeroize: https://github.com/RustCrypto/utils/tree/master/zeroize ; getrandom custom backends: https://docs.rs/getrandom

**Boot and attestation**
- [tcg-dice]: TCG DICE Layering Architecture. https://trustedcomputinggroup.org/resource/dice-layering-architecture/
- [rfc9783]: RFC 9783, Arm's Platform Security Architecture (PSA) Attestation Token. https://www.rfc-editor.org/rfc/rfc9783
- MCUboot. https://docs.mcuboot.com/

**Architecture**
- Armv7-M Architecture Reference Manual (PMSAv7). https://developer.arm.com/documentation/ddi0403/latest
- Armv8-M Architecture Reference Manual (PMSAv8, stack limits, TT, Security Extension). https://developer.arm.com/documentation/ddi0553/latest
- RISC-V Privileged Specification (PMP) and Smepmp. https://github.com/riscv/riscv-isa-manual ; https://github.com/riscv/riscv-tee/blob/main/Smepmp/Smepmp.pdf
- QEMU Arm MPS2/MPS3 boards (AN385/AN505/AN521) for M3/M33 CI. https://www.qemu.org/docs/master/system/arm/mps2.html

[zx-concepts]: https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/docs/concepts/kernel/concepts.md
[zx-rights]: https://fuchsia.dev/fuchsia-src/concepts/kernel/rights
[zx-jobpol]: https://fuchsia.dev/reference/syscalls/job_set_policy
[zx-vdso]: https://fuchsia.dev/fuchsia-src/concepts/kernel/vdso
[zx-resource]: https://fuchsia.dev/fuchsia-src/reference/kernel_objects/resource
[zx-cprng]: https://fuchsia.dev/fuchsia-src/concepts/kernel/cprng
[zx-cprng-draw]: https://fuchsia.dev/reference/syscalls/cprng_draw
[fx-caps]: https://fuchsia.dev/fuchsia-src/concepts/components/v2/capabilities
[zx-safestack]: https://fuchsia.googlesource.com/fuchsia/+/b0ba8b34057f8cc0dd6819ccf0510c4690d82bfc/zircon/docs/safestack.md
[zx-scs]: https://fuchsia.googlesource.com/fuchsia/+/main/docs/concepts/kernel/shadow_call_stack.md
[cve-22556]: https://www.cve.org/CVERecord?id=CVE-2021-22556
[cve-0882]: https://nvd.nist.gov/vuln/detail/cve-2022-0882
[qb-fuchsia]: https://blog.quarkslab.com/tag/google.html
[qb-summary]: https://tech.slashdot.org/story/20/06/10/008245/playing-around-with-the-fuchsia-os
[pt-fuchsia]: https://swarm.ptsecurity.com/a-kernel-hacker-meets-fuchsia-os/
[pt-slides]: https://archive.nullcon.net/goa-2022/documents/kernel-hacker-meets-fuchsia-OS-Goa22.pdf
[sel4-proofs]: https://sel4.systems/Verification/proofs.html
[sel4-configs]: https://docs.sel4.systems/projects/sel4/verified-configurations.html
[tock-design]: https://www.tockos.org/documentation/design/
[tock-threat]: https://book.tockos.org/doc/threat_model/threat_model
[tock-trd104]: https://book.tockos.org/trd/trd104-syscalls
[hubris-ref]: https://hubris.oxide.computer/reference/
[zephyr-user]: https://docs.zephyrproject.org/latest/kernel/usermode/overview.html
[tfm-crypto]: https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/services/tfm_crypto_design.html
[tfm-iso]: https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/ff_isolation.html
[zephyr-tfm]: https://docs.zephyrproject.org/latest/services/tfm/overview.html
[nist-90b]: https://csrc.nist.gov/pubs/sp/800/90/b/final
[nist-90a]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final
[nist-ea]: https://github.com/usnistgov/SP800-90B_EntropyAssessment
[riot-ent]: https://api.riot-os.org/group__sys__entropy__source__common.html
[djb-fke]: https://blog.cr.yp.to/20170723-random.html
[rand09]: https://rust-random.github.io/book/update-0.9.html
[ncc-aead]: https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/
[bearssl-ctmul]: https://www.bearssl.org/ctmul.html
[tcg-dice]: https://trustedcomputinggroup.org/resource/dice-layering-architecture/
[rfc9783]: https://www.rfc-editor.org/rfc/rfc9783
