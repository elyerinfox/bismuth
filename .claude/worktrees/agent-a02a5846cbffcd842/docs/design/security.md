# Security

Source: `src/security/mod.rs` (domains, handles, rights, `DeviceCap`, policies),
`src/security/manifest.rs`, `src/security/entropy/*`, `src/security/keystore.rs`.
Research input: [research/security.md](../research/security.md).

## What exists today, and what does not

Bismuth implements the *policy* half of the research design in software. It does not
yet implement the *mechanism* half, meaning hardware privilege separation.

| research phase | status |
|----------------|--------|
| 0. Vocabulary: `DomainId`, `Rights`, `Handle`, handle tables, generations, `Tcb.domain` | **Implemented** |
| 1. Rights at the API edge: `Caller` in `Request`, rights gate before middleware, ioctl rights, `MANAGE`, POSIX fds through the domain namespace, socket policy | **Implemented** (gaps listed under [limitations](#limitations-and-known-gaps)) |
| 2. Entropy: health tests, conditioner, root DRBG, per-domain DRBGs, sim sources, TRNG driver, smoltcp seeding | **Implemented** |
| 3. Manifest and policy: compile-time validation, quotas, priority ceilings, `seal`, `restrict`, bad-handle policy | **Implemented**. CPU budgets, the syscall mask and supervisor notification are **Planned**. |
| 4. Syscall boundary: SVC, unprivileged thread mode, MPU/PMP, `UserSlice`, IPC with leases, `PSPLIM` | **Done (ARMv7-M).** `SVC` syscall gate, unprivileged thread mode, ARMv7-M MPU (flash read-only + the task's own stack), per-domain syscall allow-list, validated user buffers, faults kill the domain. Passes on QEMU Cortex-M3 in debug and release. See [hardware isolation](#hardware-isolation-sandboxed-tasks). Still **Planned**: ARMv8-M MPU and `PSPLIM`, RISC-V PMP, IPC with leases, peripheral regions. |
| 5. Keystore: key handles, PSA-style attributes, RustCrypto backends, KATs | **Implemented** in the kernel domain. Hardware backends, persistent and wrapped keys, and a keystore domain over IPC are **Planned**. |
| 6. Boot hand-off, DICE, attestation tokens | **Planned** |
| 7. TrustZone-M split | **Planned** |
| 8. Assurance: fuzzing, Kani, Miri, `cargo-vet` | **Planned** |

> **Important.** Ordinary tasks, including tasks in isolated domains, run privileged
> and share one address space. For them, the checks below are enforced at the kernel
> API: they stop *mistakes* and confused deputies in safe Rust code, but not
> *malicious* code. Application crates are not bound by the kernel's
> `#![deny(unsafe_code)]`, so code that uses `unsafe`, or that calls one of the
> unchecked APIs in [limitations](#limitations-and-known-gaps), can bypass them. Only
> **sandboxed** tasks (`DomainSpec::sandboxed` + `Builder::spawn_user`) are confined
> by hardware; see [hardware isolation](#hardware-isolation-sandboxed-tasks).

## Domains

A **domain** is the unit of isolation: a group of tasks with its own handle table, policy
and CSPRNG.

- `DomainId(u8)`. `DomainId::KERNEL` (0) is the privileged kernel domain.
- `MAX_DOMAINS = 8`, including the kernel domain, and `HANDLES = 16` per domain. Both
  are constants in `src/security/mod.rs`, not build variables.
- A task's domain is set at spawn (`task::Builder::domain(d)`). By default a task joins
  its creator's domain. Interrupt handlers and boot code run as the kernel domain.
- `security::current()` returns the calling task's domain.

```rust
pub struct DomainSpec {
    pub name: &'static str,
    pub priority_ceiling: u8,          // tasks never run above this
    pub max_tasks: u8,                 // live-task quota
    pub bad_handle: BadHandlePolicy,   // Deny | Kill
    pub net: Option<NetPolicy>,        // None = no sockets
    pub trusted: bool,                 // keeps ambient authority (migration aid only)
    pub console: bool,                 // may log through kprintln!
    pub syscalls: u32,                 // syscall allow-list, bit n = syscall n (sandboxed tasks)
    pub hardware_isolated: bool,       // tasks must be unprivileged user tasks (spawn_user)
}
DomainSpec::isolated(name, ceiling, max_tasks)   // no network, untrusted, Kill on bad handle,
                                                 // console allowed, all syscalls, not hardware-isolated
DomainSpec::sandboxed(name, ceiling, max_tasks)  // isolated + hardware_isolated: true
```

| function | who may call | effect |
|----------|--------------|--------|
| `create_domain(spec)` | trusted, before `seal` | `Invalid` if the ceiling is above 31 or the quota is 0; `NoResources` when the table is full |
| `find_domain(name)` | anyone | look a domain up by name |
| `seal()` | trusted | freezes the configuration: no new domains, no grants, no removal of global middleware |
| `restrict(no_network, Some(ceiling))` | the domain itself | `pledge`-style self-restriction: drop network access and/or lower the ceiling; never widens |
| `kill(d)` | trusted | Retire every task of `d` (exit code `usize::MAX`) and wake their joiners. Reap the domain's dead tasks, freeing slots and stacks. Empty its handle table, bump its generation, invalidate its DRBG, and purge its keystore slots. [Containers](containers.md) build `stop`/`restart` on this. |
| `violations(d)`, `is_killed(d)`, `domain_generation(d)`, `is_trusted(d)` | anyone | introspection |

**Trusted vs. isolated.** The kernel domain and any domain with `trusted: true` have
**ambient authority**: they can use the raw `Device` API, attach middleware, register
entropy sources and create tasks in other domains. Isolated domains act **only through
handles**.

### Task policy

- **Spawning.** Only trusted domains may spawn into another domain. A spawn fails with
  `PermissionDenied` above the target's priority ceiling, and with `NoResources` once
  the target's live-task quota is reached. When a trusted domain spawns into a killed
  domain, the domain is restarted (its killed flag is cleared).
- **Sandboxed domains** (`hardware_isolated: true`) accept only user tasks
  (`spawn_user`); a plain `spawn` fails with `PermissionDenied`. Trusted domains,
  including the kernel domain, can never run user tasks (`Invalid`).
- **Task control.** `suspend`, `resume`, `set_priority`, `join` and `detach` on a task in
  another domain need a trusted caller. `set_priority` cannot exceed the target domain's
  ceiling.

## Handles and rights

A `Handle` is a 16-bit value: `[index:6 | generation:10]`. It names an `Object`
(`Device(Device)` or `Key { slot, generation }`) in **one domain's** table, together
with `Rights` and a namespace name. Generation 0 is never issued, so handle value 0 is
never valid. A forged or stale handle fails the generation check with `BadHandle`.

| right | bit | allows |
|-------|-----|--------|
| `READ` | 0 | `Op::Read` |
| `WRITE` | 1 | `Op::Write` |
| `TRANSFER` | 2 | `Op::Transfer` |
| `CONTROL` | 3 | operational and query ioctls ([ioctl reference](../reference/ioctl.md)) |
| `CONFIG` | 4 | configuration ioctls, and any unknown ioctl |
| `POWER` | 5 | `Op::Power` |
| `DUPLICATE` | 8 | `security::duplicate` |
| `MANAGE` | 10 | `DeviceCap::attach` / `detach` (middleware) |
| `INSPECT` | 12 | defined, but **not enforced anywhere yet** |
| `K_ENCRYPT` / `K_DECRYPT` | 16 / 17 | AEAD seal / open |
| `K_SIGN` / `K_VERIFY` | 18 / 19 | HMAC compute / verify |
| `K_DERIVE` | 20 | HKDF derive |
| `K_EXPORT` | 21 | read raw key material (almost never granted) |

Composites are `DEVICE_RW = READ | WRITE | CONTROL | INSPECT`, `ALL` and `NONE`.
`rights_for(&op)` gives the right an operation needs.

Rights only shrink:

| function | caller | effect |
|----------|--------|--------|
| `grant_device(d, dev, rights, name)` | trusted, before `seal` | puts the device in `d`'s namespace as `/dev/<name>`; the name can be an alias |
| `duplicate(h, rights)` | any domain, on its own handles | needs `DUPLICATE`; the new handle gets `old ∩ rights` |
| `drop_rights(h, mask)` | any domain, on its own handles | removes rights permanently |
| `close(h)` | any domain, on its own handles | removes the handle |
| `rights_of(h)` | any domain, on its own handles | returns the handle's rights |

## DeviceCap flow

```text
isolated task                                   kernel
─────────────                                   ──────
DeviceCap::open("temp0")  ─► look the name up in the caller's own handle table
                             (trusted domains fall back to Device::find with ALL rights)
cap.read(buf)             ─► rights_for(Op::Read) = READ
                             resolve: handle valid? generation ok? object is a Device?
                                      rights ⊇ READ?          ── no ─► violation(d, err)
                             req.caller = Caller { domain: d, rights: handle rights }
                             Device::request(req) ─► global → user → driver middleware ─► Driver
                             BadHandle from a revoked device ─► violation(d, BadHandle)
```

- The raw `Device::request` refuses requests without a caller from untrusted domains
  (`PermissionDenied`). There is **no ambient authority**.
- Middleware reads the unforgeable `req.caller()`. The field is private and only the
  kernel sets it. This makes caller-aware policies possible in middleware.
- POSIX `open("/dev/x")` from an isolated domain resolves through `DeviceCap::open`, so
  file descriptors respect the domain namespace. Opening a device by its real name fails
  if it was granted under an alias.

### Violations and the bad-handle policy

Every failed handle resolution, missing right, or network-policy denial increments the
domain's `violations` counter. If the domain is untrusted, has
`BadHandlePolicy::Kill`, and the error is `BadHandle` (a forged, stale or revoked
handle), the whole domain is **killed**. The idea is that a confused domain should die,
not probe. `PermissionDenied` is counted but never kills.

### Revocation

`security::revoke_device(dev)` (trusted only) gives the device a new generation. Every
outstanding `Device` value and every domain handle that refers to it then fails with
`BadHandle`, while the device stays registered under the fresh `Device` that the call
returns. A holder's next use counts as a violation, which **kills** a domain with the
`Kill` policy. After `seal()` there is no way to grant the fresh device again.

## Network policy

```rust
pub struct NetPolicy {
    pub local_ports: (u16, u16),   // inclusive bind range (0 = ephemeral, always allowed)
    pub peers: ([u8; 4], u8),      // allowed remote network/prefix
    pub listen: bool,              // may accept TCP connections
}
NetPolicy::ANY
```

`UdpSocket::bind`, `send_to`, `TcpStream::connect` and `TcpListener::bind` call
`check_net` for the calling domain. The kernel domain is always allowed. `net: None`
denies all socket use.

## Static manifest

`security::manifest` declares domains and their grants in code, and **validates them at
compile time**:

```rust
static MANIFEST: Manifest = Manifest {
    domains: &[DomainDecl {
        spec: DomainSpec::isolated("telemetry", 8, 2),
        grants: &[GrantDecl { device: "temp0", name: "temp", rights: Rights::READ }],
    }],
};
const _: () = manifest::validate(&MANIFEST);   // a policy violation fails the build

// at boot, after devices are registered:
let ids = manifest::apply(&MANIFEST)?;          // create domains, grant devices
security::seal()?;
```

`validate` asserts all of the following at compile time:

- fewer than `MAX_DOMAINS` domains, with unique names;
- every ceiling is in 1..=31 and every quota is ≥ 1;
- no declared domain is `trusted`;
- no grant contains `K_EXPORT` or `MANAGE`, and no grant is empty;
- grant names are unique within each domain;
- the total task quota + 4 fits in `MAX_TASKS`.

## Entropy and CSPRNG (`crypto` feature)

```text
 TRNG / sources ──► SP 800-90B health tests ──► SHA-256 conditioner ──► root DRBG
 (credited by assessed min-entropy;             (also absorbs entropy::mix   │ derive per domain
  first 1024 samples tested, then discarded)     material, never credited)   ▼
                                                     domain 0 DRBG … domain N DRBG
```

- **Sources.** `EntropySource { name, min_entropy_bits (0..=8 per byte), read }`.
  Register with `entropy::add_source` (trusted only; at most 4). Bundled sources:
  - `Stm32Rng` for real hardware, through `Mmio`. The hardware seed and clock error
    flags count as a failure.
  - `SimTrng`, a deterministic xorshift for tests only.
  - `FaultySource` (`StuckAt(v)` or `Biased`) for negative tests.
- **Health tests** (`entropy::health`, SP 800-90B §4.4, α = 2⁻³⁰):
  - The Repetition Count Test has cutoff `1 + ⌈30/H⌉`.
  - The Adaptive Proportion Test uses a 1024-sample window. Its cutoff comes from the
    exact binomial tail and is computed at compile time.
  - A start-up phase tests the first 1024 samples and discards them.
  - A source that fails a test, or whose `read` errors, is marked unhealthy and is never
    credited again.
- **Seeding.** `entropy::collect()` pulls from every healthy source. Each passing byte
  after start-up credits `H` bits. When 256 credited bits (`SEED_BITS`) have
  accumulated, the conditioner digest seeds the root DRBG, or reseeds it if it already
  exists. `entropy::seed(rounds)` collects until seeded. `entropy::mix(data)` adds
  uncredited material such as device IDs or boot counters.
- **No weak fallback.** Until the root is seeded, `entropy::fill` returns `NotReady`.
  It never falls back to a weak seed.
- **DRBG** (`entropy::drbg`). ChaCha20 with fast key erasure: each `generate` call
  produces a keystream whose first 32 bytes become the next key, so the old key is
  erased (forward secrecy per call). Reseeding computes `key = SHA-256(seed ‖ key)`.
- **Per-domain generators.** `entropy::fill(buf)` draws from the *calling domain's*
  DRBG. Each one is derived as
  `SHA-256("bismuth/drbg/v1" ‖ domain ‖ generation ‖ root output)`. Domain generators
  fold in fresh root output every 1 MiB, and are re-derived whenever the domain is
  created or killed, so a restarted domain never replays a stream. Output is generated
  in 256-byte chunks to keep critical sections short.
- `entropy::DomainRng` implements `rand_core::RngCore + CryptoRng`. `fill_bytes` panics
  if the system is unseeded; `try_fill_bytes` returns an error instead.
- `entropy::status()` returns `seeded`, `healthy_sources`, `health_failures` and
  `root_reseeds`.

## Keystore (`crypto` feature)

PSA-style key handles over vetted RustCrypto crates (`chacha20poly1305`, `hmac`,
`hkdf`, `sha2`, `zeroize`). No primitive is hand-rolled.

- Key material lives only in the keystore table: 16 slots of 32-byte keys. A domain
  holds a **handle** with `K_*` rights, named `"key"` in its table.
- `KeyAttrs { ty: KeyType, usage: Rights }`. The types are `ChaCha20Poly1305`,
  `HmacSha256` and `HkdfSha256`, with the presets `KeyAttrs::aead()`, `mac()` and
  `kdf()`. Usage must suit the algorithm: AEAD allows encrypt/decrypt, MAC allows
  sign/verify, KDF allows derive, and any of them may add `K_EXPORT` or `DUPLICATE`.
- Every operation checks **three** things: the handle's rights, the key's own usage
  policy, and its algorithm binding. A MAC key can never encrypt.
- Keys are bound to the creating domain. A handle that ends up in another domain is
  rejected.

| function | purpose |
|----------|---------|
| `generate(attrs)` | new key from the caller's DRBG (needs a seeded system) |
| `import(attrs, &[u8; 32])` | bring in existing key material |
| `aead_seal(h, nonce, aad, buf) -> tag` | encrypt in place |
| `aead_open(h, nonce, aad, buf, tag)` | decrypt; `buf` is wiped and `Integrity` returned on auth failure |
| `mac(h, data)` / `mac_verify(h, data, tag)` | HMAC-SHA-256; verify is constant-time |
| `derive(h, info, attrs)` | HKDF-SHA-256 expand into a *new key handle*; the bytes never leave the keystore |
| `export(h, &mut out)` | needs `K_EXPORT` on both the handle and the key policy |
| `key_type(h)` | the key's algorithm |
| `destroy(h)` | zeroize, bump the generation so stale handles fail |
| `sha256(data)` | keyless hash |

Nonce uniqueness for AEAD is the caller's job.

- **Self-tests.** `keystore::self_test()` runs known-answer tests: SHA-256 against
  FIPS 180-4 "abc", HMAC against RFC 4231 test case 2, and ChaCha20-Poly1305 against
  RFC 8439 §2.8.2. It runs automatically before first use. If a test fails, every
  keystore operation returns `NotReady`.
- **Planned:** hardware crypto backends behind the same API, persistent keys wrapped
  under a hardware unique key, moving the keystore into its own domain behind IPC, and
  using the `subtle` dependency (declared, not yet used directly).

## Threat model

**In scope today (software enforcement):**

- Buggy or confused application code in an isolated domain using a device, operation,
  ioctl, socket port or peer it was not granted. Such code is refused before any driver
  code runs, and the attempt is counted.
- Handle forgery and use-after-revoke: generation checks, with the domain killed under
  the `Kill` policy.
- Middleware spoofing its caller. The `Caller` cannot be forged.
- Priority abuse and task flooding by a domain: ceilings and quotas.
- Key misuse: algorithm and usage binding, no export by default, zeroization on
  destroy.
- Weak randomness: health-tested sources, no output before seeding, per-domain
  generators, and no replay after a restart.

**In scope for sandboxed tasks (hardware enforcement):**

- Arbitrary memory reads and writes by sandboxed code. The MPU confines it to its own
  stack and read-only flash, and a fault kills its domain.
- Using any kernel service except through the syscall allow-list.

**Out of scope (Planned or not addressed):**

- Code in *privileged* tasks, including isolated-but-not-sandboxed domains, that uses
  `unsafe` or reads and writes arbitrary memory. One address space, no MPU confinement.
- DMA-capable peripherals reached by a malicious driver.
- Timing and power side channels. A Cortex-M3 has variable-time multiply, so the
  ChaCha/Poly1305 timing on M3 is unverified.
- Physical attacks, fault injection, secure boot and attestation (Phases 6 and 7).

## Limitations and known gaps

These are verified against the current source (third update, 2026-10-10):

- **`kill` does not unlock mutexes held by the killed tasks.** No per-task list of held
  mutexes exists, so any task that later waits on such a mutex blocks forever unless
  its wait has a timeout. Since this update, `kill` does wake joiners and purge the
  domain's keystore slots.
- `net::transmit`, and therefore `NetRing::transmit`, can be called from any domain on
  purpose: it is the data path used by sockets and rings. Every management call is
  trusted-only (see [networking](networking.md#security-interplay)).
- `Rights::INSPECT` is defined but not checked anywhere.
- The POSIX fd table is global, not per domain. A device fd opened by a trusted domain
  is still re-checked on use (raw `Device` requests from untrusted domains are denied),
  but a `DeviceCap` fd is resolved in the *using* task's domain.

Resolved in this update and verified in the source:

- `SVCall` pushes nothing before calling `bismuth_svc`, so MSP keeps the 8-byte
  alignment that exception entry guarantees (`CCR.STKALIGN`). This meets the AAPCS
  requirement.
- The syscall entry points are no longer public: `security::syscall::dispatch` and both
  ports' `syscall` are `pub(crate)`, and `user::raw_syscall` is `#[cfg(test)]
  pub(crate)`. No public safe function can turn an integer into a slice.
- `kill` is trusted-only (`require_kernel`). Internal paths (violations, faults) use
  `kill_internal`.
- `spawn_user` returns `Unsupported` on a core without an MPU
  (`port::supports_user_tasks()`).
- `driver::register`/`unregister`, `net::register`, `set_up`, `set_offloads`,
  `attach_hook`, `add_global_hook` and `register_protocol` require a trusted caller.
- `PowerGate` wakes the device with `req.derive`, so the original `Caller` is kept.
- Entropy credits at most 8 bits per sample.

## Hardware isolation (sandboxed tasks)

**Status: done for ARMv7-M.** Checked in three places:

- `tests/sandbox.rs` in the simulator;
- the QEMU `lm3s6965evb` demo, debug and release. A sandboxed task reads a sensor
  through syscalls and has its unauthorized write denied (`sandbox: exit=Ok(0)`);
- MPU fault handling, according to the lead's report: on hardware, an unprivileged
  access to kernel memory raised a data-access violation (CFSR), the domain was
  killed, and the system kept running. The demo does not trigger that path itself; it
  prints `mpu faults=0`.

Source: `src/arch/cortex_m.rs` (SVC, MPU, faults), `src/security/syscall.rs` (the
gate), `src/kernel/usermem.rs` (user buffers, TCB), `src/user.rs` (client API) and
`src/kernel/stack.rs` (`UserStack*`).

```rust
static APP_STACK: UserStack2K = UserStack2K::new();       // power-of-two size, aligned to it

extern "C-unwind" fn app(_: usize) {                       // runs unprivileged
    let h = user::open("temp").unwrap();                   // namespace lookup via syscall
    let mut raw = [0u8; 4];
    user::read(h, &mut raw, Timeout::Forever).unwrap();    // rights-checked DeviceCap read
    user::log(b"sampled\n");
}

let d = security::create_domain(DomainSpec::sandboxed("app", 6, 2))?;
security::grant_device(d, sensor, Rights::READ | Rights::CONTROL, "temp")?;
task::Builder::new("app").priority(4).domain(d).stack(&APP_STACK).spawn_user(app, 0)?;
```

### Spawning user tasks

- Use `Builder::spawn_user(entry: extern "C-unwind" fn(usize), arg)`.
- The task stack must be a power of two (at least 256 bytes) and aligned to its own
  size, as an ARMv7-M MPU region requires. `UserStack1K`, `UserStack2K` and
  `UserStack4K` (re-exported at the crate root) satisfy this. Any other stack is
  rejected with `Invalid`.
- On bare metal, each user task also takes a **private kernel stack** from the stack
  pool for executing its system calls. If the pool is empty, the spawn fails with
  `NoMemory`.

### What a user task may touch (ARMv7-M MPU)

| region | access |
|--------|--------|
| 0 | the whole code area `0x0000_0000..0x2000_0000`: read-only, executable |
| 1 | the running user task's own stack: read/write, execute-never (reprogrammed at every context switch) |

The MPU is enabled with `PRIVDEFENA`, so privileged code keeps the default memory map.
User code can reach nothing else: no kernel statics, no other stacks, no peripherals.
`CONTROL.nPRIV` is set while a user task runs outside a syscall. If the core has no MPU
(`MPU_TYPE.DREGION < 2`), protection is silently skipped.

### System calls

User code may use **only** `bismuth::user` plus pure `core` code. Every other kernel API
touches kernel memory and faults under the MPU.

- `svc #1` traps into `SVCall`. The handler saves the user frame and switches the task
  onto its kernel stack in privileged thread mode, where `security::syscall::dispatch`
  runs; it may block. `svc #2` returns the result and drops privilege again.
- The call number goes in `r12`, arguments in `r0`–`r3`, and the result comes back in
  `r0`: non-negative for success, `-errno` for failure.
- Each call is checked against the domain's `syscalls` allow-list
  (`syscall::bit(nr::X)`; `syscall::ALL` allows everything). A call that is not on the
  list counts as a violation, and kills the domain under `BadHandlePolicy::Kill`.
- Buffers pass through `kernel::usermem`. That module rejects null and wrapping
  ranges. On hardware it also requires the range to lie inside the caller's own stack
  (or, for reads, in flash), so the kernel cannot be tricked into touching memory the
  task could not touch itself.

| `user::` function | `nr` | notes |
|-------------------|------|-------|
| `yield_now` | `YIELD` (0) | |
| `sleep_ticks(n)` | `SLEEP` (1) | |
| `exit(code)` | `EXIT` (2) | also reached by returning from the entry function |
| `ticks()` | `TICKS` (3) | |
| `open(name) -> Handle` | `DEV_OPEN` (4) | resolves in the domain namespace |
| `read(h, buf, timeout)` | `DEV_READ` (5) | `DeviceCap` rights check, then the middleware chain |
| `write(h, buf)` | `DEV_WRITE` (6) | |
| `ioctl(h, cmd, arg)` | `DEV_IOCTL` (7) | |
| `random(buf)` | `RANDOM` (8) | the domain's DRBG (`crypto`; otherwise `Unsupported`) |
| `notify_wait(timeout)` | `NOTIFY_WAIT` (9) | |
| `drop_rights(h, mask)` | `DROP_RIGHTS` (10) | |
| `log(bytes)` | `LOG` (11) | kernel console |

### Faults

- A MemManage, BusFault or UsageFault raised by user code (outside a syscall) kills the
  task's domain and increments `security::faults(d)`. The same fault raised by kernel
  code panics with the `CFSR` and `MMFAR` values.
- A user-task stack overflow, detected at context switch, retires the task and kills
  its domain at the next tick; it does not panic the system.
- An unknown `svc` immediate from user code kills the domain.
- The kernel defines `SVCall`, `MemoryManagement`, `BusFault` and `UsageFault` in
  addition to `PendSV` and `SysTick`. Boards must not define them.

### On the host simulator

There are no privilege levels or MPU on the host. `user::*` calls run the same
dispatcher directly, so the allow-list, handle, rights and namespace checks are
identical (`tests/sandbox.rs`). Memory checks are limited to null and wrap-around.

### Implementation note: preserving r4–r11 across a syscall

On exception entry the hardware stacks only `r0`–`r3`, `r12`, `lr`, `pc` and `xPSR`.
The syscall switches the task onto its kernel stack and back, so `SVCall` must also save
and restore the user's callee-saved registers `r4`–`r11` itself. It does this with
`stmdb`/`ldmia` around `bismuth_svc`, using a 16-word frame (`[r4–r11][hardware frame]`)
that mirrors PendSV. The kernel-stack frame that enters `syscall_trampoline` has the
same layout. Without the extra save, a user task resumed with clobbered registers. The
bug only showed up in debug builds.

### Still Planned for this phase

- An ARMv8-M MPU (base/limit regions) with `PSPLIM`, and RISC-V PMP.
- Peripheral (MMIO) regions for user-mode drivers.
- Synchronous IPC with leases.
- More than one MPU stack region; there is no shared-memory window yet (for example
  for `NetRing` buffers).
- Moving the POSIX and FreeRTOS layers onto the syscall client for sandboxed code.
