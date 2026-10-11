# Bismuth Dynamic Extensions: Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: whether and how Bismuth can load and unload extensions — drivers, filesystems,
> network hooks, edge stages, policy — at run time ("kernel modules" in spirit), and an
> opinionated, layered design that delivers that dynamism **without** importing unvetted
> native code or `unsafe`. Surveys how safe/embedded systems do runtime extension without
> native `.ko`: Tock's process model + Tock Binary Format, Zephyr's `llext`, eBPF as a
> safe in-kernel VM, WebAssembly interpreters for embedded, and microkernel userspace
> drivers (seL4, Redox, Fuchsia DFv2), the last because the project benchmarks itself
> against Zircon.
>
> Current Bismuth baseline (read from the tree): extensions are **compile-time
> registered**, not dynamic. A driver is a `&'static dyn Driver` added by
> `driver::register` / `driver::unregister` (slot reuse + a per-slot `generation` that
> revokes every outstanding `Device`/`DeviceCap`, `driver/mod.rs`) or bound from a board
> description by `probe_all` against a static `FACTORIES` table. A block device is a
> `&'static dyn BlockDevice` in a small `driver::block` registry (`register`/`find` + a
> fast path; **no generation or `unregister` yet**). Network data-plane hooks
> (`PacketHook`) attach and detach through `net::attach_hook` / `net::detach_hook` /
> `net::add_global_hook` (all trusted-only). Edge stages (`edge::dsp::Stage`) compose with
> `.then` and run inside a task; there is no stage registry. The filesystem subsystem
> (`src/fs/`, a `FileSystem` trait + a mount table with per-mount generation and
> `mount`/`unmount`) is **designed but not yet built** (see `docs/research/filesystems.md`);
> `DeviceClass::Block` has a trait and registry, no driver. Containers already give the
> lifecycle precedent: `install` = `manifest::apply` + `seal`; `start` spawns the root task;
> `stop`/`restart` = `kill` (empties the handle table, bumps the domain generation,
> re-derives the CSPRNG, purges keys). Security is frozen by `seal()`: after it, no new
> domains or grants, policy can only tighten (`security/mod.rs`). The crate is
> `#![deny(unsafe_code)]` with `unsafe` confined to a five-module TCB
> (`arch/cortex_m.rs`, `arch/mmio.rs`, `kernel/cell.rs`, `kernel/stack.rs`,
> `kernel/usermem.rs`), plus the planned x86-64 port TCB (`docs/research/x86-port.md`).
> Memory is statically sized from `config.rs`; there is no heap.

---

## 0. TL;DR

- **The honest non-goal, up front: no Linux-style binary kernel modules (`.ko`).** Loading
  unvetted native code and runtime-linking it into the kernel with full privilege breaks
  every Bismuth non-negotiable at once: it defeats the safe-Rust TCB discipline (the loaded
  code is `unsafe` by definition and unbounded), it defeats the capability model (in-kernel
  native code has ambient authority over all of RAM and MMIO), it needs a runtime ELF
  linker and W^X executable memory the MCU does not have, and it fits neither no-heap nor
  (on the MCU) no-MMU. We do **not** build it, and we say so in the limitations (§7). The
  one narrow future exception: on the x86-64 port, which has an MMU, *userspace* native
  modules in their own address spaces become plausible later (§4) — but **privileged
  in-kernel native modules stay permanently out**.
- **Three feasible, layered designs, in priority order.** Each is 100% safe Rust and
  heap-free; each gets more dynamic and more isolated than the last, at rising cost.
- **PRIMARY — an Extension framework (§2).** Generalise the lifecycle the kernel already
  half-implements (`driver::register`/`unregister` with its revoking `generation`, the
  block registry, the designed FS `mount`/`unmount`, the net hook attach/detach, edge
  stages) into **one uniform `Extension` trait** with `load`/`unload`, a static catalogue of
  compiled-in, vetted extensions that are **inert until loaded**, **reference counting** so
  an in-use driver/FS cannot be unloaded, **generation-based revocation** of everything a
  loaded extension produced, **static-slot reclamation** on unload, and **capability /
  manifest gating** of who may load. The "module" is a `&'static dyn Extension` compiled
  into the image but activatable/deactivatable at run time — the same move containers make
  over domains. This is the core deliverable.
- **A sandboxed bytecode VM (§3) for *truly external* (not-compiled-in) code.** For genuine
  load-a-blob dynamism, run the extension memory-safe inside an interpreter with only the
  host functions its domain is granted. **Verdict after evaluating the crates: on the MCU,
  write a small in-house eBPF-style engine with a static verifier in safe Rust** — it is
  tiny, needs no heap and no `unsafe`, and the verifier is checkable. **WebAssembly
  (`wasmi`) is ruled out on the MCU because it requires `alloc` (a heap); rbpf likewise uses
  `alloc` and `unsafe`.** `wasmi` becomes plausible only inside a *userspace* domain on the
  x86-64 port, where a per-domain allocator exists. Good for edge-compute stages, packet /
  stream filters and policy hooks; **not** for high-rate ISR drivers.
- **Userspace drivers over IPC (§4), microkernel style.** Reuse the existing hardware
  sandbox (`DomainSpec::sandboxed` → unprivileged MPU tasks + the SVC gate + granted
  `DeviceCap`/MMIO) so a "loadable driver" is an unprivileged task in its own domain serving
  a device interface over IPC; "load" = spawn + grant (container `start`), "unload" = kill
  the domain (which already reaps). **There is no IPC/lease mechanism yet (it is Planned)**,
  so this depends on that work; §4 specifies the minimal channel it needs. The x86-64 MMU
  enriches it (separate address spaces, `#PF` isolation).
- **Security (§5).** Who may load is a capability (`Rights::LOAD`) declared in the manifest,
  trusted-only by default. The hard problem is reconciling run-time loading with `seal()`'s
  "policy can only tighten": the design's answer is that **loading never widens the frozen
  capability graph — it only populates pre-declared, currently-empty capability targets** —
  so the manifest stays the security boundary whether an extension is loaded or not. Blast
  radius rises from compiled-in (safe-Rust-bounded) to VM (interpreter + host surface) to
  userspace-driver (MPU domain, killable).
- **Layout, config, staging (§6).** A new `src/ext/` at **L3 services** (the trait,
  registry and per-kind adapters; the VM under `ext/vm/`), new `BISMUTH_MAX_EXTENSIONS` /
  VM-sizing knobs, one new `Rights::LOAD` bit and a manifest `ExtGrant`, and one
  `tests/structure.rs` line banning `crate::ext` from the lower layers. Staged: (1) trait +
  registry + driver/block adapters with refcount + revocation; (2) capability/manifest gating
  + `seal` reconciliation; (3) loadable-FS mount/unmount once `fs` lands; (4) userspace driver
  over IPC once IPC lands; (5) optional eBPF/Wasm sandbox.

---

## 1. Problem statement: what Bismuth does today, and what "dynamic" would add

The user asked: *"any way we can implement a dynamic extension system like kernel modules
that would allow us to load/unload extensions, like say a driver or a filesystem?"*

Bismuth already has the *shape* of a module system — it just resolves it at compile time.
Four subsystems independently implement "register a capability provider, then tear it down":

1. **Drivers** (`driver/mod.rs`). `register(name, &dyn Driver)` finds a free registry slot,
   bumps that slot's `generation`, runs the driver's `init`, and returns a
   `Device { index, generation }`. `unregister(dev)` clears the slot; `regenerate()` bumps
   the generation so **every outstanding `Device` value and every `DeviceCap` fails its next
   check with `BadHandle`** — real revocation, already built. `probe_all(descs, FACTORIES)`
   binds board descriptions to drivers by compatible string, device-tree style. All of these
   are trusted-only.
2. **Block devices** (`driver/block/mod.rs`). A smaller `register(name, &dyn BlockDevice)` +
   `find` + a `read_at`/`prog_at`/`erase_blk`/`sync` fast path. It has **no `unregister` and
   no generation** yet — a gap the Extension framework should close by giving it the same
   revocation the driver registry has.
3. **Network hooks** (`net/hook.rs`, `net/mod.rs`). `attach_hook(idx, dir, &dyn PacketHook)`
   / `detach_hook(idx, dir, name)` / `add_global_hook(dir, hook)` install data-plane layers
   (firewall, rate-limit, steer, counter) that return a `Verdict`. `register_protocol` binds
   an L3 node by ethertype. All trusted-only.
4. **Filesystems** (designed, `docs/research/filesystems.md`). A `FileSystem` trait with a
   mount table that already specifies a **per-mount `generation` bumped on unmount to revoke
   stale file handles** — the same pattern. A loadable filesystem *is literally*
   `mount`/`unmount`.

And **containers** (`security/container.rs`) already prove the lifecycle pattern one level
up: a container is *not a new isolation primitive* — it wraps an existing `DomainId` and adds
`install`/`start`/`stop`/`restart`/`health`, where `stop`/`restart` go through `kill` (which
empties the handle table, bumps the domain generation, re-derives the CSPRNG and purges
keys). The Extension framework is the same idea applied one level down: **an extension is not
a new primitive — it wraps an existing registration and adds a uniform load/unload life.**

What "dynamic" adds on top of today's compile-time registration:

- **Selection and ordering decided at run time**, not baked into `main`. A board can carry a
  catalogue of drivers/filesystems and activate the subset the attached hardware or the
  operator asks for.
- **Teardown and replacement in the field** — unload a filesystem to swap the medium, retire
  a driver whose device was removed, disable a policy hook — with the guarantee that
  outstanding handles are revoked, not left dangling.
- **Genuinely external code** (§3/§4) that was *not* compiled into the image, for the cases
  where compile-time vetting is too rigid.

### 1.1 Why not binary kernel modules (`.ko`)

Linux `.ko` modules are relocatable native object files linked into the running kernel at
full privilege. Reproducing that on Bismuth would require, and break, the following:

- **A runtime ELF loader + relocation engine, and W^X executable memory.** The MCU has no
  MMU to make a fresh page executable-but-not-writable; on the x86-64 port it would mean the
  kernel deliberately creating new ring-0 executable mappings — exactly the
  `ZX_POL_VMAR_WX` / `MARK_VMO_EXEC` hazard the security research works to keep out
  ([`security.md`][sec-doc] §1.8). Zephyr's `llext`, the nearest embedded equivalent, is an
  ELF loader that **modifies the binary code in place to relink it, and its own docs warn
  that "in case of errors the results are difficult to predict"**, that it needs
  per-architecture support, and that Harvard cores are unsupported ([Zephyr llext][llext]).
  That is the maintenance surface and failure mode we are avoiding.
- **Abandoning the safe-Rust TCB.** Loaded native code is `unsafe` by construction and
  unbounded. Bismuth's entire assurance argument is `#![deny(unsafe_code)]` with `unsafe`
  confined to five audited files; a `.ko` loader makes every loaded byte part of the TCB
  with none of the audit. There is no partial version of this.
- **Abandoning the capability model.** In-kernel native code has ambient authority over all
  RAM and MMIO; there are no handles to check. The whole point of the domain/handle/rights
  model is that *nothing* has ambient authority except the kernel domain.
- **No ABI to stabilise safely.** Even Fuchsia's modern driver framework, which runs drivers
  in *userspace*, "has not reached ABI stability yet" ([Fuchsia DFv2][dfv2]); an in-kernel
  native ABI across Rust compiler versions and `#[repr(Rust)]` layouts is a non-starter.

So native in-kernel modules are a permanent non-goal. Everything below delivers the *useful*
part of "kernel modules" — runtime load/unload of drivers, filesystems and policy — by other
means. The **one** future exception worth naming: on the x86-64 port's MMU, a *userspace*
native module in its own ring-3 address space, reaching hardware only through granted
capabilities and IPC (§4), is a legitimate design — because there it is just another
sandboxed domain, not privileged kernel code.

---

## 2. The Extension framework (primary deliverable)

### 2.1 The `Extension` trait

An extension is a `&'static dyn Extension`: compiled into the image, inert until loaded. It
is **not** a new isolation or registration primitive — it is a thin, uniform *adapter* over
a registration that already exists, exactly as a container is an adapter over a domain.
(Bismuth's drivers and middleware are already Tock-style *capsules* — kernel extensions
written in safe Rust with `unsafe` forbidden, isolated by the type system rather than the
MPU, `security.md` §2.2; the Extension framework simply gives those capsules a load/unload
life.) This
keeps layering clean (the adapter lives above what it wraps) and means the framework reuses
`driver::register`, `vfs::mount`, `net::attach_hook`, etc. rather than duplicating them.

```rust
//! Classification: L3 services · extension framework: trait, registry, lifecycle · safe · ext

/// What kind of capability provider an extension activates. Determines the blast radius
/// (§5) and whether an isolated domain may ever be allowed to load it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExtKind {
    Driver,      // privileged in-kernel: driver::register / unregister
    Block,       // privileged in-kernel: driver::block registry (gains generation, §2.5)
    FileSystem,  // privileged in-kernel: vfs::mount / unmount (depends on `fs`)
    NetHook,     // privileged in-kernel: net::attach_hook / detach_hook
    EdgeStage,   // privileged in-kernel: an edge pipeline stage
    Middleware,  // privileged in-kernel: a device middleware layer
    Vm,          // sandboxed bytecode program (§3): memory-safe, no ambient authority
    UserDriver,  // userspace driver domain over IPC (§4): MPU-isolated, killable
}

/// Static identity of an extension — the analogue of `DriverInfo`.
#[derive(Copy, Clone, Debug)]
pub struct ExtInfo {
    pub name: &'static str,                 // unique catalogue name, e.g. "fat", "lfs", "fw-ssh"
    pub kind: ExtKind,
    pub version: (u8, u8, u8),
    /// The single namespace name this extension will expose when loaded (a `/dev/<name>`,
    /// a mount point, a hook name). Empty for extensions that expose nothing nameable.
    /// This is the name the manifest forward-declares for post-seal loading (§5.2).
    pub provides: &'static str,
    /// Names of other extensions that must already be loaded (a FileSystem depends on its
    /// backing Block extension). Bounded by `EXT_MAX_DEPENDS`.
    pub depends: &'static [&'static str],
}

/// A loadable, unloadable capability provider. 100% safe Rust; no heap.
pub trait Extension: Sync {
    fn info(&self) -> ExtInfo;

    /// Activate: perform the underlying registration (register the driver, mount the FS,
    /// attach the hook, install the stage). Called by the registry's `load` after
    /// dependencies are pinned and gating has passed. Idempotency and cleanup-on-failure
    /// are the implementation's responsibility, as in `driver::register`.
    fn load(&'static self) -> Result<(), Error>;

    /// Deactivate: undo it (unregister / unmount / detach), reclaiming the static slot and
    /// revoking outstanding handles via the underlying generation bump. The registry
    /// guarantees this is only ever called with a zero reference count (§2.3).
    fn unload(&'static self) -> Result<(), Error>;
}
```

The per-kind **adapters** are small concrete types in `src/ext/`, each `&'static`, each
delegating to the subsystem it wraps:

```rust
/// A loadable driver == register / unregister. `load` registers, `unload` unregisters
/// (which bumps the device generation → every DeviceCap to it fails BadHandle).
pub struct DriverExt { info: ExtInfo, driver: &'static dyn crate::driver::Driver,
                       dev: IrqCell<Option<crate::driver::Device>> }

/// A loadable filesystem == mount / unmount. `load` pins the backing Block extension
/// (acquire, §2.3) and mounts; `unload` unmounts (bumps the mount generation → file
/// handles fail) and releases the Block extension.
#[cfg(feature = "fs")]
pub struct FileSystemExt { info: ExtInfo, fs: &'static dyn crate::fs::FileSystem,
                           at: &'static str, backing: &'static str,
                           guard: IrqCell<Option<ExtGuard>> }

/// A loadable net hook == attach_hook / detach_hook on one interface + direction.
pub struct NetHookExt  { info: ExtInfo, hook: &'static dyn crate::net::PacketHook,
                         ifindex: crate::net::IfIndex, dir: crate::net::Dir }
```

Thus **a loadable driver and a loadable filesystem are the *same* operation** — `load` is
"register/mount", `unload` is "unregister/unmount" — expressed once in the registry and
specialised only in the adapter. `DriverExt` over a `&dyn Driver` and `FileSystemExt` over a
`&dyn FileSystem` both become `&'static dyn Extension` in one catalogue.

### 2.2 The catalogue and the registry

Two structures, mirroring how drivers split `FACTORIES` (static, compiled-in) from the
`REGISTRY` (runtime slots):

```rust
/// The compiled-in, vetted catalogue of available extensions — inert until loaded.
/// The board/app provides it, exactly as it provides `DeviceDesc`s and `FACTORIES`.
pub static CATALOGUE: &[&'static dyn Extension] = &[ /* &FAT0_EXT, &LFS_EXT, &FW_SSH_EXT */ ];

pub const MAX_EXTENSIONS: usize = parse_or(option_env!("BISMUTH_MAX_EXTENSIONS"), 8);

struct ExtSlot {
    ext: &'static dyn Extension,
    generation: u16,   // bumped on unload → revokes ExtId handles to this slot
    refs: u16,         // dependents pinning it; unload refused while > 0 (§2.3)
}

static REGISTRY: IrqCell<[Option<ExtSlot>; MAX_EXTENSIONS]> =
    IrqCell::new([const { None }; MAX_EXTENSIONS]);

/// A handle to a loaded extension (index + generation), the ExtKind-level analogue of
/// `Device { index, generation }`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtId { index: u8, generation: u16 }
```

Lifecycle, all re-using existing idioms (the registry lock is released before calling into a
subsystem, exactly as `driver::block::dev` and the net core do, so no lock is ever held
across a blocking `load`/`unload`):

```rust
/// Activate a catalogue extension by name. Gated by §5: trusted, or a domain holding
/// `Rights::LOAD` for this extension; and, after seal(), only under the sealed-mode rules.
pub fn load(name: &str) -> Result<ExtId, Error> {
    gate_load(name)?;                             // §5.1 capability + §5.2 seal reconciliation
    let ext = CATALOGUE.iter().find(|e| e.info().name == name).ok_or(Error::NotFound)?;
    if find(name).is_some() { return Err(Error::Exists); }     // already loaded
    let mut pinned: [Option<ExtGuard>; EXT_MAX_DEPENDS] = Default::default();
    for (i, dep) in ext.info().depends.iter().enumerate() {    // pin dependencies first
        pinned[i] = Some(acquire_by_name(dep)?);               // Err if a dep isn't loaded
    }
    ext.load()?;                                               // register / mount / attach
    let id = insert_slot(*ext)?;                               // claim a free slot, gen += 1
    stash_guards(id, pinned);                                  // held until this ext unloads
    Ok(id)
}

/// Deactivate. Refused with `Busy` while anything still holds a reference (§2.3); the
/// generation bump then revokes any ExtId that slipped through.
pub fn unload(id: ExtId) -> Result<(), Error> {
    gate_unload(id)?;
    with_slot(id, |s| if s.refs != 0 { Err(Error::Busy) } else { Ok(()) })??;
    let ext = with_slot(id, |s| s.ext)?;
    ext.unload()?;                                             // unregister / unmount / detach
    drop_stashed_guards(id);                                   // release this ext's deps
    clear_slot(id);                                            // reclaim the slot, gen += 1
    Ok(())
}
```

### 2.3 Reference counting and generation-based revocation — two mechanisms, two jobs

The brief asks for both. They are complementary, not redundant:

- **Reference counting** answers *"may this be unloaded now?"* for **durable dependencies**
  whose lifetime the registry can see. A mounted filesystem pins its backing block device; a
  running edge pipeline pins its stage extension; a container that owns a userspace driver
  pins it. These take an **`ExtGuard`** — an RAII handle, modelled exactly on `mem::PoolBox`,
  that increments `refs` on `acquire` and decrements on `Drop`:

  ```rust
  pub struct ExtGuard { id: ExtId }                 // increments refs on acquire
  impl Drop for ExtGuard { fn drop(&mut self) { with_slot(self.id, |s| s.refs -= 1); } }

  /// Pin a loaded extension so it cannot be unloaded while the guard lives.
  pub fn acquire(id: ExtId) -> Result<ExtGuard, Error>;
  pub fn acquire_by_name(name: &str) -> Result<ExtGuard, Error>;
  ```

  `unload` refuses with `Error::Busy` while `refs > 0`. This is the "an in-use driver/FS
  cannot be unloaded" guarantee, and it is the common, graceful path.

- **Generation-based revocation** answers *"what about handles we did **not** refcount?"* —
  the transient per-operation handles (`DeviceCap`, open file handles) that re-resolve on
  every call and are too hot to refcount. Here we **reuse the revocation Bismuth already
  has**: `DriverExt::unload` calls `driver::unregister`, which bumps the device
  `generation`, so every `DeviceCap` to it fails its next `resolve` with `BadHandle` (and,
  under a domain's `BadHandlePolicy::Kill`, kills a probing domain). `FileSystemExt::unload`
  bumps the mount generation ([`filesystems.md`][fs-doc] §2.3) to the same effect. The `ExtSlot`'s own
  `generation` does the same for `ExtId` handles. Nothing new is invented; the extension
  framework simply *routes* unload through the existing generation bumps.

The division of labour: **refcount prevents the unsafe unload (graceful, returns `Busy`);
generations make the unload safe even if it happens anyway (hard backstop, returns
`BadHandle`).** A privileged operator who *forces* an unload past the refcount (a future
`unload_forced`, kernel-only) still cannot create a dangling pointer — every product of the
extension is generation-checked.

### 2.4 Static-slot reclamation (no heap)

"Reclaim on unload" means exactly what reaping a task means for its stack: a fixed slot
returns to a free pool, never a `free()`.

- The **registry slot** (`ExtSlot`) is set to `None` and its generation bumped; a later
  `load` reuses it.
- The extension's **underlying registration slot** is reclaimed by the subsystem it wraps:
  `driver::unregister` frees the device-registry entry (slot reuse already implemented),
  `vfs::unmount` frees the mount-table entry, `detach_hook` compacts the hook array.
- The extension's **`&'static` backing storage** (the driver's register state, the FS's
  cache pools) is compiled in and simply goes inert; it is reused only if the *same*
  extension is loaded again. This is the honest limit of the compiled-in model: **loading is
  activation, not instantiation** — you cannot have more live instances than the catalogue
  compiled (§7). For the "load N copies of an arbitrary blob" case, that is what the VM's
  fixed *program slots* (§3) and the userspace model's *domain pool* (§4) are for.

### 2.5 Integration touch-ups to existing subsystems

- **Give `driver::block` the driver registry's revocation.** Add `unregister(BlockId)` and a
  per-slot `generation` to `BlockId`, so a `BlockExt::unload` revokes any `FsVnode`/handle
  routed through it. This is a prerequisite for a safe loadable filesystem and closes a gap
  the block registry has today regardless of extensions.
- **Net hooks already support detach**, so `NetHookExt` is a direct wrapper; the only
  addition is that `add_global_hook`'s locked layers (the audit/policy ones) must refuse
  unload after `seal()`, exactly as `remove_global_middleware` already does.
- **Edge stages** gain the thinnest registry: an `EdgeStageExt` holds a `&'static dyn Stage`
  and `load`/`unload` publish/retract it from a slot a `run_pipeline` task consults — or,
  more simply, an edge pipeline *acquires* its stage extension (an `ExtGuard`) for its
  lifetime, so unloading a stage in use returns `Busy`.

### 2.6 Classification

| file | classification |
|---|---|
| `src/ext/mod.rs` | `L3 services · extension framework: trait, registry, lifecycle · safe · ext` |
| `src/ext/driver.rs` | `L3 services · extension: driver / block adapters · safe · ext` |
| `src/ext/fs.rs` | `L3 services · extension: filesystem adapter · safe · ext` |
| `src/ext/net.rs` | `L3 services · extension: net-hook adapter · safe · ext` |
| `src/ext/edge.rs` | `L3 services · extension: edge-stage adapter · safe · ext` |

Why L3: the unifying trait must see `driver`/`block` (L2, downward), `net`/`fs`/`edge`
(L3, same layer) and `security` (L3). L2 cannot import `net`/`edge`/`compat`
(`tests/structure.rs`), so the trait *cannot* live next to the driver model at L2 without
losing the net/edge/fs kinds — hence the adapter pattern at L3, with each adapter importing
its subsystem downward or sideways. An L2 driver stays a plain `Driver`; it never implements
`Extension` itself (that would be an upward import). The only `structure.rs` change the
framework needs is adding `"crate::ext"` to the forbidden list for `L0 port`, `L1 kernel`
and `L2 devices`, so nothing below L3 reaches up into it — the same one-line rule the
filesystem design adds for `crate::fs`.

---

## 3. The sandboxed bytecode VM (for truly external code)

The Extension framework (§2) is genuinely dynamic in *lifecycle* but its code is still
compiled in and vetted. For code that was **not** compiled into the image — an operator's
packet filter, a field-deployed edge reducer, a policy rule downloaded over the network — the
only memory-safe, `unsafe`-free, heap-free way to gain dynamism is to **run the extension
inside an interpreter** that can only touch the host functions and memory its domain is
granted. The interpreter is the new trust boundary and must be assessed as rigorously as the
x86 port assesses its crates.

### 3.1 WASM vs eBPF: the crate evaluation and the verdict

| option | no_std | heap (`alloc`) | `unsafe` | size | fit for Bismuth MCU |
|---|---|---|---|---|---|
| **`wasmi`** (register VM, wasmtime-inspired) | yes | **required** | internal `unsafe` | large | **No** on MCU (needs a heap); plausible only in an x86-64 userspace domain ([wasmi][wasmi]) |
| **`wasm3`/WAMR** (C interpreters via FFI) | — | yes | **C via FFI** | med/large | **No** — FFI to C is `unsafe` and leaves the safe-Rust TCB |
| **`rbpf`** (Rust eBPF interpreter + x86 JIT) | yes (`std` off) | **uses `alloc`** | internal `unsafe`; JIT only with `std` | small-med | **No** as-is (heap + `unsafe`); a reference for the *semantics* ([rbpf][rbpf], [docs][rbpf-docs]) |
| **in-house eBPF-style engine** | yes | **none** | **none** | tiny | **Yes** — the recommendation |

The decisive facts:

- **`wasmi` requires `alloc`.** Its own `no_std` story is "disable `std`, but you still need
  the `core` + `alloc` libraries" ([wasmi][wasmi]). A heap is a Bismuth non-negotiable
  violation on the MCU. Its register-based engine is fast and its sandboxing is sound, but
  WebAssembly's linear-memory model also wants a sizeable, growable memory — the opposite of
  a fixed static budget. `wasmi` is therefore **out on the MCU** and **in** only as a
  *userspace* plugin host on the x86-64 port (§4), where a dedicated per-domain allocator can
  back it and a bug stays ring-3.
- **`rbpf` uses `alloc` and `unsafe`**, and its JIT compiles only with `std`
  ([rbpf][rbpf-docs]); the interpreter is a good semantic reference but we would not link it.
- **eBPF the *instruction set* is tiny and verifier-friendly.** Eleven 64-bit registers, a
  512-byte bounded stack, a fixed ~100-opcode encoding, and (historically) no unbounded
  loops — modern kernels allow only *bounded* loops the verifier can prove terminate
  ([eBPF verifier][ebpf-verifier]). That is small enough to **implement from scratch in safe
  Rust with entirely static storage and no `unsafe` at all**, which no off-the-shelf crate
  gives us.

**Verdict: build a minimal eBPF-style engine in safe Rust for the MCU.** A `[u64; 11]`
register file, a `[u8; EXT_VM_STACK]` stack, a `[u8; EXT_VM_MEM]` scratch map, a decoded
program in a fixed `[Insn; EXT_VM_INSNS]` buffer, and a big `match` over opcodes — all on the
Rust stack / in static cells, all bounds-checked by the language. This is the same discipline
`net::csum` uses for hand-rolled, `unsafe`-free frame parsing.

### 3.2 The verifier is the trust boundary

An interpreter bounds *memory* safety by construction (every array access is checked Rust),
but **liveness and resource** safety need a load-time **verifier**, because a privileged
in-kernel VM must never hang or spin. Linux's eBPF verifier is exactly this — a static
analyser that must prove safety before a single instruction runs ([eBPF verifier][ebpf-verifier])
— and its weaknesses are instructive: it is simultaneously *over-conservative* (rejects valid
programs) and has been *unsound* in corner cases (range-tracking CVEs), which is why research
favours abstract interpretation ([PLDI'19 Zone-domain analyser][ebpf-pldi19]) and
correct-by-construction languages ([BeePL][beepl]) over an ever-growing ad-hoc checker. The
lessons for Bismuth's small verifier:

- Keep the accepted language **deliberately tiny and prove-by-structure**: forward-only
  jumps plus a single bounded counted-loop form with a compile-time trip limit; no computed
  jumps; every memory access against the fixed stack/map bounds; a static instruction budget
  (`EXT_VM_INSNS`) so load rejects an oversize program. A small checkable verifier beats a
  large permissive one.
- Enforce a **runtime step budget** as a backstop to the static one: the interpreter counts
  executed instructions and aborts with `Error::Overflow` past `EXT_VM_STEPS`, so even a
  verifier bug cannot wedge the kernel. (This is the heap-free analogue of a watchdog.)
- Reject-by-default: anything the verifier cannot prove is refused at `load`, returning
  `Error::Invalid`.

### 3.3 The host-function surface = the capability

A VM program has **no ambient authority**: it can do arithmetic and touch its own
stack/map, and otherwise can only call **host functions** that its domain's capabilities
authorise. The host table is where the VM plugs into Bismuth, and each entry is itself
rights-checked:

- **Packet filter / stream hook.** The program runs as a `PacketHook` (§1), reading the
  frame from its read-only map and returning a `Verdict` (`Pass`/`Drop`/`Consumed`). This
  reuses `net::filter`'s existing `MatchExpr`/`RuleSet` world; a VM hook is the
  *programmable* version of the fixed `Firewall` hook. Host calls: read packet bytes, read a
  connection-track mark, bump a counter.
- **Edge stage.** The program is an `edge::dsp::Stage` — `i32 → Option<i32>` — a downloadable
  anomaly detector or reducer. Host calls: read a sample, read the clock, publish to a
  `Topic`.
- **Policy hook.** The program evaluates a yes/no decision (admit this request, allow this
  power transition) over a small fixed input struct, as a programmable `AccessPolicy`.

Each host function checks the caller domain's rights before acting, so a VM extension is
strictly weaker than the domain that loaded it. A program granted only "read packet, return
verdict" can never read a sensor or send a packet.

### 3.4 What it is, and is not, for — honestly

- **Good for:** low-to-moderate-rate, bounded, pure-ish transforms and decisions — packet
  and stream filters, edge-compute reductions, policy rules — that benefit from being
  updatable in the field without a firmware flash.
- **Not for:** high-rate ISR-path drivers. Interpreted dispatch is 10–100× a native call;
  a VM in the per-packet fast path or a bit-banged bus ISR will miss deadlines. Those stay
  compiled-in extensions (§2) or userspace drivers (§4). The VM also cannot touch MMIO or
  DMA — it has no host function for raw hardware, by design.
- **Code-size honesty:** the in-house eBPF engine + verifier is a few KB of `.text` and a
  handful of static buffers; it is the only VM that fits the MCU footprint table in
  `STATUS.md`. `wasmi` on x86-64 is hundreds of KB and a heap — acceptable there, never on
  the MCU.

### 3.5 Classification

| file | classification |
|---|---|
| `src/ext/vm/mod.rs` | `L3 services · extension: bytecode vm core and host table · safe · ext-vm` |
| `src/ext/vm/verify.rs` | `L3 services · extension: vm load-time verifier · safe · ext-vm` |
| `src/ext/vm/ebpf.rs` | `L3 services · extension: ebpf-style interpreter · safe · ext-vm` |

A VM program loaded as an extension is an `ExtKind::Vm`; its `load` verifies the blob into a
free program slot, `unload` frees the slot. Program slots are a fixed `Pool`-style array, so
"load an external blob" *is* heap-free and genuinely dynamic — the one place the design
loads code that was not compiled in, and it stays memory-safe because it never becomes native
instructions.

---

## 4. Userspace drivers over IPC (microkernel style)

The strongest isolation for a loadable driver is the one Bismuth already built for
sandboxing: run it as an **unprivileged, MPU-confined task in its own domain**, reaching
hardware only through granted capabilities, and serving a device interface over IPC. This is
the seL4 / Redox / Fuchsia model — "drivers are userspace components, each in its own
address space; a faulty driver cannot damage other interfaces; the cost is extra context
switches" ([seL4 DDF][sel4ddf], [Redox drivers][redox], [Fuchsia DFv2][dfv2]) — mapped onto
Bismuth's existing `DomainSpec::sandboxed`, SVC gate, `DeviceCap` and MMIO grants. Tock is
the closest MCU precedent: it loads untrusted *processes* at run time from the
position-independent Tock Binary Format, a privileged loader app stages the binary to flash
and asks the kernel to start it "without a restart and without disturbing running
applications" ([Tock dynamic app loading][tock-load], [app_loader capsule][tock-apploader],
[Tock book][tock-book]) — the same spawn-into-an-isolated-context move, minus the native
relocation (Bismuth's loadable userspace code is a container `start`, not a relinked blob).

### 4.1 Load = spawn + grant; unload = kill

This is **containers, verbatim** (`security/container.rs`): a userspace-driver extension is a
`ContainerDecl` whose domain is `sandboxed`, granted the MMIO window / IRQ / backing device
it drives (never a DMA-capable peripheral as raw MMIO to an isolated domain —
`security.md` §5.4). `load` = `container::start` (spawn the root task into its domain);
`unload` = `container::stop` → `kill` (terminate tasks, empty the handle table, bump the
domain generation so peers' handles fail `PeerRestarted`, reap stacks). `OnFault::Restart`
already gives crash-restart — the microkernel property the survey could not find in seL4/Redox
docs, Bismuth has in `container.rs`. So **most of this already exists**; what is missing is
the channel the driver serves on.

### 4.2 The minimal IPC/lease primitive this needs (currently Planned)

There is no IPC yet — it is listed Planned in `STATUS.md` and sketched in `security.md` §5.3.
A userspace driver needs the minimum of it:

- **Synchronous call/reply with leases** (Hubris model, `security.md` §5.1/§5.3):
  `ipc_call(server_handle, msg, leases[≤N])` from the client; `ipc_recv` / `ipc_reply` on the
  server; the server reads/writes a client buffer through `lease_read` / `lease_write`
  syscalls that the kernel bounds-checks against the *client's* regions and that **die when
  the call returns** (no MPU region spent on IPC). A channel endpoint is a kernel object with
  `READ`/`WRITE` rights, granted in the manifest like a `DeviceCap`.
- **A kernel-side `Device` shim** so existing consumers are unchanged: the userspace driver
  domain registers (via a trusted broker) a `&'static dyn Driver` whose `handle` turns each
  `Op` into an `ipc_call` to the server domain and blocks the caller until `ipc_reply`. Thus
  a userspace-served device looks exactly like any other `/dev/<name>`; `DeviceCap`,
  middleware and the fd layer all work. `unload` revokes the shim's generation and kills the
  server.

This is the one design that is **scoped as dependent on other Planned work**: it is a thin
layer *once IPC and leases exist*, and close to impossible to fake without them. Recommended
staging: land it right after the IPC primitive (§6).

### 4.3 x86-64 MMU enrichment

On the x86-64 port ([`x86-port.md`][x86-doc]) the MMU replaces the MPU and enriches this
model: each userspace driver domain gets a full private page table (not 4–8 MPU regions), a
`#PF` outside its mapped memory kills the domain exactly as a MemManage fault does on ARM, and
ring-3 isolation is paging-enforced. This is where a *native* userspace module (compiled
separately, loaded into its own ring-3 address space) becomes legitimate — it is just another
sandboxed domain, reaching hardware via granted MMIO and IPC, never privileged kernel code.
The x86 port already commits its five drivers to the existing traits and keeps them safe over
the `virtio-drivers` boundary; a loadable userspace driver is the same, one isolation level
out. DMA stays the hazard: without an IOMMU a bus-mastering device defeats isolation, so a
DMA-capable peripheral is driven by a trusted D0 shim that validates buffers, never handed raw
to the sandboxed driver.

---

## 5. Security

### 5.1 Who may load / unload

Loading is a capability, not ambient. Add one right and one manifest declaration:

```rust
// security/mod.rs — one free bit (6); 7, 9, 11, 13–15 remain free.
impl Rights { pub const LOAD: Rights = Rights(1 << 6); } // load/unload a declared extension

// security/manifest.rs — alongside GrantDecl.
pub struct ExtGrant { pub ext: &'static str, pub rights: Rights } // rights ⊆ {LOAD}
```

- **Default: trusted-only**, matching `driver::register`, `net::attach_hook` and
  `vfs::mount` today — `ext::load` begins with `current_is_trusted()`. This alone makes the
  whole framework usable from the kernel domain and from a trusted supervisor container.
- **Delegated: an isolated domain holding `Rights::LOAD` on a named extension** may load that
  extension and no other — a real, enforced "this domain may load the WireGuard filter."
  `gate_load` resolves the extension name against the caller domain's `ExtGrant`s.
- **The manifest validator forbids the dangerous grant.** `validate` (a `const fn`, build-time
  failure) must reject `Rights::LOAD` granted to an isolated domain for a **privileged
  in-kernel kind** (`Driver`, `Block`, `FileSystem`, `NetHook`, `Middleware`, `EdgeStage`):
  letting an untrusted domain activate privileged in-kernel code is the `.ko` hazard through
  the back door. An isolated domain may hold `LOAD` **only** for `ExtKind::Vm` or
  `ExtKind::UserDriver` — the memory-safe / MPU-isolated kinds. This is the single most
  important manifest rule the framework adds, and it is checkable at compile time, which is
  precisely the advantage `containers.md`/`security.md` argue Bismuth has over run-time
  routing.

### 5.2 Reconciling load/unload with `seal()`

`seal()` freezes the security configuration: after it, `create_domain` and `grant_device` are
refused (`require_unsealed`), and policy can only *tighten*. A naive dynamic loader that makes
a new device/mount appear at run time appears to *widen* authority after seal — the core
tension. Two modes resolve it; recommend shipping the first and offering the second:

- **`ExtPolicy::BootOnly` (default, MVP).** `load`/`unload` are permitted **only while
  unsealed**. "Dynamic" then means *compose at bring-up* — select and order extensions at
  boot from the catalogue, before `seal()` — after which the loaded set is frozen along with
  everything else. Honest, trivially safe, and already enough for "pick the drivers the
  attached board needs." It is the exact analogue of `container::install` (apply + seal).
- **`ExtPolicy::Sealed` (advanced, opt-in).** Post-seal load/unload is allowed to `LOAD`
  holders **under one invariant: loading may only populate a name the manifest already
  forward-declared, and may never widen any domain's frozen reachable set.** Concretely:
  - An extension's `provides` name (its `/dev/<name>` or mount point) must match a
    manifest-declared slot; loading *fills* a pre-declared, currently-empty capability
    target, it does not create a new route. A domain that had no grant naming that target can
    never reach it, loaded or not — **the manifest stays the security boundary.** This is
    Zircon/Fuchsia capability routing ("a capability exists only if a route was declared",
    `security.md` §1.7) applied so that *instantiation* is dynamic but *routing* is frozen.
  - Unload is still revocation: the generation bump (§2.3) invalidates every handle to the
    retired extension, and a reload gets a fresh generation, so a domain must re-open — it
    never silently inherits a successor's capability.
  - The audit obligation: because this is the one post-seal authority change, it must emit a
    security event (the `Trace`/supervisor path) on every post-seal load/unload, and the
    manifest must mark exactly which forward-declared slots are hot-loadable. Anything not so
    marked stays `BootOnly`.

This reconciliation is the design's key security claim: **dynamism in lifecycle, not in the
capability graph.** It is also why native in-kernel `.ko` is impossible here — native code has
no `provides` name to confine and no generation to revoke.

### 5.3 Revocation and blast radius per approach

| approach | loaded code is | isolation | revocation on unload | blast radius of a bug |
|---|---|---|---|---|
| **Compiled-in extension (§2)** | vetted safe Rust in the image | none (runs privileged in D0) | device/mount/ext generation bump | **bounded by safe Rust** (panic/logic error, never memory corruption); if it runs as D0 middleware/driver, a logic bug is a kernel-domain bug |
| **Bytecode VM (§3)** | external bytecode, interpreted | memory-safe by the interpreter; no ambient authority | free the program slot; generation on the hook/stage | the host-function surface its domain granted **+ the interpreter's own soundness** (the new trust boundary) |
| **Userspace driver / IPC (§4)** | any code, ring-3/MPU-confined | full MPU/MMU domain isolation | `kill` → generation bump → `PeerRestarted` | that domain's MPU regions + granted peripherals; a crash is killed and restarted (`OnFault`); DMA without an IOMMU is the residual hazard |

The progression is the whole point: as you move from compiled-in to VM to userspace, you gain
the ability to run less-trusted and genuinely-external code, and you pay in dispatch cost,
context switches and (for userspace) IPC latency and MPU regions. Pick the weakest-privilege
tier that meets the deadline.

---

## 6. Proposed `src/` layout, config, errors, and staged order

### 6.1 Module tree

```
src/ext/
  mod.rs        //! Classification: L3 services · extension framework: trait, registry, lifecycle · safe · ext
  driver.rs     //! Classification: L3 services · extension: driver / block adapters · safe · ext
  fs.rs         //! Classification: L3 services · extension: filesystem adapter · safe · ext        (feature `fs`)
  net.rs        //! Classification: L3 services · extension: net-hook adapter · safe · ext          (feature `net`)
  edge.rs       //! Classification: L3 services · extension: edge-stage adapter · safe · ext         (feature `edge`)
  user.rs       //! Classification: L3 services · extension: userspace-driver adapter · safe · ext   (feature `ipc`)
  vm/
    mod.rs      //! Classification: L3 services · extension: bytecode vm core and host table · safe · ext-vm
    verify.rs   //! Classification: L3 services · extension: vm load-time verifier · safe · ext-vm
    ebpf.rs     //! Classification: L3 services · extension: ebpf-style interpreter · safe · ext-vm
```

`tests/structure.rs`: add `"crate::ext"` to the forbidden list for `L0 port`, `L1 kernel` and
`L2 devices` (one line), so the lower layers cannot reach up into the framework — mirroring
the `crate::fs` rule the filesystem design adds. No other structure change is needed: L3 may
freely use `driver`, `block`, `net`, `fs`, `edge`, `security` (only `compat::posix/freertos`
are banned from L3).

### 6.2 Config knobs (`config.rs`, same `parse_or` + `mcu_or_host` idiom)

```rust
// ----- extensions (feature `ext`) -----
pub const MAX_EXTENSIONS: usize  = parse_or(option_env!("BISMUTH_MAX_EXTENSIONS"), 8);
pub const EXT_MAX_DEPENDS: usize = parse_or(option_env!("BISMUTH_EXT_MAX_DEPENDS"), 4);  // cf. LLEXT_MAX_DEPENDENCIES = 8
// ----- bytecode VM (feature `ext-vm`) -----
pub const EXT_VM_SLOTS: usize = parse_or(option_env!("BISMUTH_EXT_VM_SLOTS"), mcu_or_host(0, 4)); // 0 ⇒ compiled out
pub const EXT_VM_INSNS: usize = parse_or(option_env!("BISMUTH_EXT_VM_INSNS"), 512);   // static program budget
pub const EXT_VM_STACK: usize = parse_or(option_env!("BISMUTH_EXT_VM_STACK"), 512);   // eBPF 512-byte stack
pub const EXT_VM_MEM:   usize = parse_or(option_env!("BISMUTH_EXT_VM_MEM"), 256);     // scratch map bytes
pub const EXT_VM_STEPS: u32   = parse_or(option_env!("BISMUTH_EXT_VM_STEPS"), 100_000) as u32; // runtime budget
```

Setting `EXT_VM_SLOTS = 0` (the MCU default) compiles the VM out entirely, so a board that
wants only the compiled-in framework pays nothing for the interpreter.

### 6.3 New `Rights` / `Error` variants

- **`Rights::LOAD = Rights(1 << 6)`** (§5.1). Bit 6 is free in the current `Rights`.
- **No new `Error` variant is required**; the framework maps onto existing ones:
  `NotFound` (no such extension), `Exists` (already loaded), `Busy` (refs > 0 / in use),
  `PermissionDenied` (gating failed, or load attempted after seal under `BootOnly`),
  `Unsupported` (kind not loadable on this build), `Invalid` (VM verifier rejected the blob),
  `Overflow` (VM runtime step budget exhausted). *Optional:* a dedicated `Error::Verify` for
  verifier rejections if a distinct `errno` is wanted (maps to `EINVAL`), following the
  precedent that `filesystems.md` proposes a handful of FS-specific variants.

### 6.4 Staged implementation order (each with its host/sim test)

1. **Extension trait + registry + driver/block adapters.** `Extension`, `CATALOGUE`,
   `REGISTRY`, `ExtId`, `load`/`unload`, `acquire`/`ExtGuard` refcount, generation
   reclamation; `DriverExt`; add `unregister` + generation to `driver::block` and `BlockExt`.
   *Test (host):* load a `SimSensor` driver → it appears in the device registry and a
   `DeviceCap` reads it; `unload` → the `DeviceCap` now fails `BadHandle` (revocation);
   `acquire` the extension, then `unload` returns `Busy`; drop the guard, `unload` succeeds;
   loading past `MAX_EXTENSIONS` returns `NoResources`.
2. **Capability + manifest gating + `seal` reconciliation.** `Rights::LOAD`, `ExtGrant`, the
   `const fn validate` rule rejecting `LOAD`-to-isolated-for-privileged-kind, `ExtPolicy`
   (`BootOnly` default; `Sealed` with forward-declared `provides`).
   *Test (host):* a trusted domain loads any extension; an isolated domain with an `ExtGrant`
   loads its one permitted extension and is denied an unlisted one; post-seal `load` under
   `BootOnly` returns `PermissionDenied`; under `Sealed`, a `load` into a forward-declared
   slot succeeds and a domain *without* a grant to that name still cannot open it; a manifest
   granting `LOAD` for an `ExtKind::Driver` to an isolated domain **fails the build**
   (`const _: () = validate(&M);`).
3. **Loadable filesystem == mount/unmount** (depends on `src/fs/`). `FileSystemExt` over the
   VFS; a mount takes an `ExtGuard` on its backing `BlockExt`.
   *Test (host):* load a `RamFs` extension → mount appears, a path resolves and reads back;
   `unload` the block extension while mounted → `Busy`; `unload` the filesystem → the mount
   generation bumps and open file handles fail; then the block extension unloads cleanly.
4. **Userspace driver over IPC** (depends on the Planned IPC/lease primitive). `UserDriverExt`
   = a sandboxed `ContainerDecl` + the kernel-side `Device` shim that forwards `Op`s over
   `ipc_call`. *Test (host + QEMU Cortex-M3):* a sandboxed device-server domain serves reads
   over IPC through a shim `/dev/<name>`; a `DeviceCap` read returns its data; `kill` the
   server → the shim's generation bumps and the `DeviceCap` fails; `OnFault::Restart` brings
   it back under a fresh generation.
5. **Optional sandboxed VM** (feature `ext-vm`; `EXT_VM_SLOTS > 0`). The eBPF-style engine +
   verifier + host table; `VmExt` loads a verified blob into a program slot and plugs it in as
   a `PacketHook` / `Stage` / policy hook. *Test (host):* a verified filter program drops
   matching packets and passes the rest (compared against the fixed `Firewall` hook); a
   program with a backward jump / oversize length is **rejected** at load (`Invalid`); a
   program that loops is terminated at `EXT_VM_STEPS` (`Overflow`); a program with no
   packet-read grant cannot read the frame. On x86-64 only, a `wasmi` host in a userspace
   domain runs a WASM plugin (feature-gated, never on the MCU).

---

## 7. Open questions, risks, and documented-limitation candidates

- **Native `.ko` is a permanent non-goal (lead).** Runtime-linked privileged native code
  breaks the safe-Rust TCB, the capability model, no-heap and no-MMU all at once (§1.1); it
  has no `provides` name to confine and no generation to revoke (§5.2). Document it as a
  limitation, with the x86-64 *userspace* native module (§4.3) as the only future variant,
  and privileged in-kernel native modules as never.
- **ABI stability.** Compiled-in extensions share the crate's exact Rust types at build time,
  so they have *no* cross-version ABI problem — the strength of the primary design. The VM
  (§3) and IPC (§4) paths *do* cross a boundary and need a **stable wire ABI**: define the VM
  bytecode encoding and the IPC message/lease layout in a small `bismuth-abi` crate (as
  `security.md` already proposes for syscalls), version them, and treat them like the syscall
  table. Even Fuchsia's userspace DFv2 "has not reached ABI stability yet"
  ([Fuchsia DFv2][dfv2]) and Zephyr `llext` leaves symbol/ABI compatibility to the integrator
  ([llext][llext]) — set expectations accordingly.
- **No-heap vs large VM memories.** WebAssembly's growable linear memory and `wasmi`/`rbpf`'s
  `alloc` are fundamentally at odds with a fixed static budget (§3.1). The mitigation is the
  in-house eBPF engine with statically-bounded stack/map/program buffers on the MCU, and
  confining `wasmi` to a userspace domain with its own allocator on x86-64. A board that sets
  the VM budgets too low simply cannot load a given blob — a clean, bounded failure, not an
  OOM.
- **Refcount leaks.** A leaked `ExtGuard` would pin an extension unloadable forever. Mitigate
  by tying every guard to a reaped lifetime — a mount, a pipeline task, a container — so
  `kill`/unmount drops it; audit that no guard outlives its owner. (The analogous hazard for
  `mem::PoolBox` is handled the same way: drop returns the slot.)
- **The forward-declared-name exception (§5.2) is the one place authority changes after
  seal.** It must be audited: can a malicious catalogue entry claim a `provides` name it
  should not? Answer: the name must match a manifest slot the operator wrote, and the manifest
  is compile-time — so the risk is a mis-written manifest, caught by the same `validate` that
  checks every other grant. Still, mark it clearly and emit a security event per post-seal
  load.
- **"Activation, not instantiation."** The compiled-in model cannot create more live
  instances than the catalogue holds (§2.4); you cannot "load three more copies of the FAT
  driver" unless three were compiled. For true multiplicity of *external* code, the VM's
  program-slot pool (§3) and the userspace domain pool (§4) are the answer. Document this as
  an intended limitation, not a gap.
- **Temptations to `unsafe` to watch for** (each must be refused or confined): a runtime ELF
  relocation engine (**refuse** — this is `.ko`); `transmute`/`bytemuck`-with-unsafe over VM
  bytecode or IPC buffers (**refuse** — decode with explicit `from_le_bytes`, as `net::csum`
  and the littlefs design do); FFI to a C interpreter like wasm3/WAMR (**refuse** — leaves the
  safe-Rust TCB); the x86-64 `virtio_drivers::Hal` and PCI accessor (**confine** — already TCB
  in the x86 port, not part of this framework). If any proposed extension work needs `unsafe`
  outside the five-module TCB (plus the x86-64 port TCB), that is the signal it has drifted
  toward native `.ko` and should be rescoped to the VM or userspace tier.

---

<!-- internal companions -->
[sec-doc]: ./security.md
[fs-doc]: ./filesystems.md
[x86-doc]: ./x86-port.md

<!-- external sources -->
[tock-load]: https://tockos.org/blog/2025/talking-tock-59/
[tock-book]: https://book.tockos.org/course/setup/dynamic-app-loading
[tock-apploader]: https://docs.tockos.org/capsules_extra/app_loader/
[llext]: https://docs.zephyrproject.org/4.2.0/services/llext/index.html
[ebpf-verifier]: https://howtech.substack.com/p/inside-the-ebpf-verifier-ensuring
[ebpf-pldi19]: https://pldi19.sigplan.org/event/pldi-2019-papers-simple-and-precise-static-analysis-of-untrusted-linux-kernel-extensions
[beepl]: https://arxiv.org/html/2507.09883v1
[rbpf]: https://github.com/qmonnet/rbpf
[rbpf-docs]: https://docs.rs/rbpf/
[wasmi]: https://docs.rs/wasmi/
[dfv2]: https://fuchsia.dev/docs/concepts/drivers/driver_framework
[sel4ddf]: https://trustworthy.systems/projects/drivers
[redox]: https://doc.redox-os.org/book/drivers.html
```
