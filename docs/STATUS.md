# Status

Last verified against the source on **2026-10-11** with rustc 1.99. This update re-ran
`cargo test` (122 passed, 0 warnings), `cargo build --target thumbv7m-none-eabi`,
`cargo build --target thumbv7em-none-eabihf` and the board demo build (all clean). The
QEMU demo run and `cargo doc --no-deps` were last re-checked on 2026-10-10 and are
unaffected by the filesystem subsystem, which the MCU board does not build.

## Implemented vs. planned

Legend:

- **Done**: built and covered by tests.
- **Partial**: built, with listed gaps.
- **In progress**: code exists but is being finished.
- **Planned**: not built.

### Kernel (L0/L1)

| feature | status | notes |
|---------|--------|-------|
| Cortex-M3/M4/M7 port (PendSV, SysTick, PRIMASK) | Done | runs on QEMU `lm3s6965evb` (M3) |
| Lazy FPU context switching (`eabihf`) | Done | builds for `thumbv7em-none-eabihf`; no FPU board demo yet |
| ARMv8-M Mainline (M33) | Partial | the port claims it; no board or test exercises it |
| ARMv6-M, RISC-V ports | Planned | `compile_error!` for non-ARM bare metal |
| Host simulator (baton, virtual time, deadlock/panic detection) | Done | |
| O(1) bitmap scheduler, 32 priorities, round-robin slicing | Done | |
| Priority-inheritance mutex | Partial | not transitive (chained) |
| Semaphore, CondVar, Queue, EventFlags, notifications | Done | |
| Software timers (service task) | Done | |
| Fixed-block pools (`mem::Pool`) | Done | |
| Stack painting, high-water marks, overflow detection at switch | Done | detection only; `PSPLIM`/MPU guard Planned |
| Tickless idle on MCU | Planned | `advance_to` exists; only the simulator uses it |

### Devices (L2)

| feature | status | notes |
|---------|--------|-------|
| Driver model, registry, mandatory driver middleware | Done | |
| Middleware chain (global → user → driver), attach/detach | Done | |
| Middleware library (11 layers) | Done | see the [catalogue](design/drivers-and-middleware.md#built-in-middleware-catalogue-bismuthdrivermiddleware) |
| `probe_all` / `DeviceDesc` / `Mmio` | Done | |
| Class APIs: Serial, Gpio, I2cBus, Sensor | Done | |
| Block device class (`BlockDevice`, `BlockGeometry`, `MediaKind`, registry + fast path) | Done | `driver::block`, always built; `SimFlash`/`SimDisk`/`SimRam` + power-cut injection; see [filesystem](design/filesystem.md) |
| Block wrappers: `BlockCache` (write-back/through), `Partition`, `ReadOnly`, `WearCounter` | Done | `driver::block::cache`; composed at build time |
| Block `/dev/<name>` control node + `0x09xx` ioctls + raw fd access | Planned | `register` populates the registry only |
| Class API: Spi | Planned | the class discriminant exists; no wrapper or driver |
| Drivers: pipe, PL011, sim-sensor, sim-gpio, sim-i2c | Done | all have probe factories |
| Real-hardware drivers beyond PL011 and STM32 RNG | Planned | |
| Console (`kprintln!`) to sink or device | Done | |
| TTY line discipline (`Tty` middleware), `Termios`, ISIG → notifications, typed `TtyControl` (trusted-only lookup) | Done | no `VMIN`/`VTIME`/`IXON`; see [tty](design/tty.md) |
| PTY (`Pty`/`PtyMaster`/`PtySlave`) | Done | no probe factory |
| Display class (`Display`, `PixelFormat`, window + write protocol, 0x07xx) + `SimDisplay` | Done | see [human interface](design/human-interface.md) |
| Input class (`InputEvent`, `Input`, 0x08xx) + `SimInput` | Done | packets can split across reads |
| Real panel/input drivers, `embedded-graphics` `DrawTarget`, keymap → TTY, DMA blits | Planned | |
| Interrupt-driven UART, termios → hardware projection, real `tcdrain` | Planned | |
| `accel` offload (CRC-32, Q15 MAC, copy) with vetting and fallback | Done | no hardware engine driver yet |

### Services (L3)

| feature | status | notes |
|---------|--------|-------|
| Packet buffers, RX/TX/APP pools, headroom, static payload | Done | no refcounting or chains (by design for now) |
| `NetDevice` / `FrameDevice` + `SoftRing` | Done | `timer()` is called each poll round; `set_rx_filter()` is not called yet |
| Net task: budgeted RX, 2-band TX, doorbell, reclaim, stats | Done | |
| Checksum offload with software fallback (IPv4/ICMP/UDP/TCP) | Done | no IPv6 |
| Packet hooks (counter, firewall, rate limit, steer) | Done | |
| `NetRing` zero-copy rings, protocol nodes | Done | |
| smoltcp IPv4/ARP/ICMP/UDP/TCP + socket API | Done | |
| Packet filter `net::filter` (`RuleSet`, `MatchExpr`, iptables/pf builders, drop tap) | Done | IPv4 only; see [firewall](design/firewall.md) |
| `ConnTrack` stateful tracking | Done | direction-aware (`ESTABLISHED` only on a reply); no TCP flag handling |
| NAT, REJECT, user chains, nftables sets/VM, eBPF, IPv6 filtering | Planned / out of scope | |
| DHCP, DNS, IPv6, `embedded-nal`, TLS | Planned | |
| Hardware MAC/PHY drivers | Planned | |
| Domains, handles, rights, `DeviceCap`, `Caller` | Done | see the [gaps](design/security.md#limitations-and-known-gaps) |
| Priority ceilings, quotas, net policy, `seal`, `restrict` | Done | |
| Compile-time manifest validation | Done | |
| Entropy: SP 800-90B health tests, conditioner, ChaCha20 FKE DRBG, per-domain DRBGs | Done | |
| Keystore (AEAD, HMAC, HKDF, KATs, zeroize) | Done | in the kernel domain; no HW backends or persistence |
| Sandboxed tasks: SVC gate, MPU (ARMv7-M), syscall allow-list, user memory checks (research Phase 4) | Done | passes in the simulator and on QEMU Cortex-M3 (debug and release); ARMv8-M MPU/`PSPLIM`, RISC-V PMP, IPC/leases still Planned |
| Containers: `ContainerDecl`/`ContainerManifest`, compile-time `validate_containers`, install/start/stop/restart/health/budget | Done | trusted callers only; see [containers](design/containers.md) |
| Container CPU-budget enforcement, `OnFault`/supervisor handling, IPC, attestation claims, signed loadable bundles, Wasm | Planned | budgets and fault policies are declared and validated only |
| CPU budgets, supervisor notification, IPC and leases | Planned | |
| Secure/measured boot, attestation, TrustZone-M | Planned | |
| Edge DSP stages, `Topic`, `run_pipeline` | Done | |
| VFS core: `FileSystem` trait, mount table (longest-prefix), iterative resolver, global open-file table, generation revocation | Done | feature `fs`; trusted-only mount/unmount; see [filesystem](design/filesystem.md) |
| RamFs (`RamFs<INODES,BLOCKS,BS>`): inode table + shared block arena, sibling-linked dirs, block-chain files | Done | the VFS bring-up vehicle and `/tmp` |
| littlefs (power-safe flash FS), FAT (managed-media interop) | Planned | designed in [research/filesystems.md](research/filesystems.md) |
| Hot-file residency cache (Layer 2); per-domain mount namespaces + directory-subtree capabilities | Planned | file ops are currently unchecked within one global namespace |

### Personalities (L4)

| feature | status | notes |
|---------|--------|-------|
| POSIX: pthreads, mutex/cond/keys/once, semaphores, clocks, mqueues, fds, `poll`, sockets | Done | see [deviations](guides/posix.md#known-deviations-from-posix) |
| POSIX files (features `posix` + `fs`): VFS-backed `open`, `O_CREAT`/`O_TRUNC`/`O_APPEND`, `lseek`, `stat`/`fstat`, `mkdir`/`rmdir`/`unlink`/`rename`, `ftruncate`, `fsync` | Done | non-`/dev/` paths resolve through the VFS; `mkdir` mode ignored (capabilities, not bits) |
| POSIX `<termios.h>` | Done | trusted (kernel-domain) callers only; `TCSADRAIN`/`TCSAFLUSH` act like `TCSANOW`; `tcflush` only clears the TTY's buffers |
| POSIX C ABI (`posix-abi` feature) | Planned | the feature is declared but unused |
| FreeRTOS: tasks, queues, semaphores/mutexes, event groups, notifications, timers | Partial | see the [semantic differences](guides/freertos-porting.md) |
| `embedded-hal` 1.0 / `embedded-io` adapters, both directions | Done | |
| `user` syscall client for sandboxed tasks | Done | 12 syscalls |

## Test suites

`cargo test` on 2026-10-11 (fifteenth update): **122 passed, 0 failed**, plus 7 doc examples marked
`ignore`.

| suite | tests | covers |
|-------|------:|--------|
| unit (`src/`) | 18 | syscall argument validation (forged pointers); accel CRC/dot product; DSP FIR, EMA, chain, stats, z-score, RMS, biquad; checksums (RFC 1071, fill/verify, non-IP); DRBG (FKE, RFC 8439 block); health tests (SP 800-90B cutoffs, stuck, biased, good) |
| `tests/block.rs` | 11 | flash erase/program-once + out-of-range; power-cut torn write; disk overwrite-in-place + no-op erase; RAM round-trip; `Partition` remap; `ReadOnly` refusal; `WearCounter` counts; `BlockCache` write-back/through, LRU eviction flush, erase-before-flush over flash; registry register/find + fast path |
| `tests/fs.rs` | 7 | create/write/read/seek/truncate + read-only refusal; multi-block files; dirs create/list/remove + dotted paths + `rmdir` non-empty; rename + error paths; mount lifecycle + `O_TRUNC`; POSIX file API through the VFS; `O_APPEND` writes at end |
| `tests/kernel.rs` | 20 | preemption, virtual time, `sleep_until` drift, semaphores, PI mutex, recursion, queues, event flags, condvar, join, deadlock/panic/tick-limit outcomes, timers, notifications, suspend, stacks |
| `tests/drivers.rs` | 11 | chain order, pipe blocking + stats, sensor calibration + filters, power gate, access policy, retry, rate limit, GPIO debounce, I2C, probing, console device |
| `tests/net.rs` | 10 | packet buffers, loopback + protocol node + counter, RX budget, steer → `NetRing`, UDP echo, TCP transfer and close, refused connect, checksum fallback + offload toggle, firewall, control plane |
| `tests/posix.rs` | 9 | pthreads + mutex, mutex types, condvar + timedwait, semaphores, clocks, mqueues, TSD + once, fds + poll, BSD sockets |
| `tests/freertos.rs` | 4 | tasks, queues and delays; binary semaphore from ISR and mutexes; event groups and notifications; timers |
| `tests/security.rs` | 10 | no ambient authority + rights gate, forged handle kill, revocation, ceilings/quotas, seal + rights shrink, net policy, POSIX namespace, entropy, keystore, manifest |
| `tests/containers.rs` | 2 | install/start/health/restart of a sandboxed container with compile-time validation; untrusted domains refused `stop`/`install` |
| `tests/tty.rs` | 5 | canonical editing + echo over a PTY, raw mode via `tcsetattr`, Ctrl-C interrupts a read + notifies, termios round-trip + `tcflush`, one line per canonical read with no input loss |
| `tests/hid.rs` | 4 | display blit window + caps + `Stats` bytes, keyboard blocking read, mouse poll + overflow, display blank/power |
| `tests/firewall.rs` | 4 | allow UDP/5683 + drop the rest over a wire (ARP still flows), ConnTrack ESTABLISHED replies, unsolicited inbound stays NEW, pf `pass`/`block` |
| `tests/sandbox.rs` | 2 | sandboxed task via syscalls with policy checks; syscall allow-list and spawn rules |
| `tests/edge.rs` | 2 | accel vetting and fallback; isolated anomaly pipeline |
| `tests/structure.rs` | 3 | classification lines, TCB allow-list, downward-only layering |

### QEMU demo (`boards/qemu-lm3s6965`)

The demo **passes** in both debug and release builds (re-checked at the third update on
2026-10-10). It covers:

- the sensor pipeline;
- priority inheritance;
- a software timer;
- a sandboxed unprivileged task: it reads via syscalls, its write is denied, and it
  ends with `sandbox: exit=Ok(0) killed=false mpu faults=0`;
- the task list.

The full output is in [getting started](guides/getting-started.md#3-run-the-qemu-demo).

### Footprint

The QEMU demo, release build (`opt-level = "s"`, LTO), kernel features
`--no-default-features --features edge`, measured with `rust-size`:

| measured | text | data | bss | notes |
|----------|-----:|-----:|----:|-------|
| reported by the lead, before the sandbox section | 37,328 B | 5,960 B | 23,224 B | |
| measured for this update, current demo including the sandbox task | 47,608 B | 6,688 B | 27,488 B | |

Most of `bss` is the demo's own static task stacks plus kernel tables at their default
sizes (see [configuration](reference/configuration.md)).

## Known issues

Verified against the source on 2026-10-11 (fifteenth update).

| severity | issue | where |
|----------|-------|-------|
| medium | `security::kill` does not unlock mutexes held by the killed tasks; there is no per-task held-mutex list | [security](design/security.md#limitations-and-known-gaps) |
| medium | FreeRTOS: `xTaskNotifyGive` ORs bit 0 instead of counting; `vTaskDelete` of another task only suspends it; `vQueueDelete` does not wake waiters | [FreeRTOS](guides/freertos-porting.md) |
| low | `Rights::INSPECT` is never enforced | [security](design/security.md) |
| low | `subtle` is only used transitively; the kernel has no direct use of it | `Cargo.toml` |
| low | `NetDevice::set_rx_filter()` is never called by the core | [networking](design/networking.md#as-built-vs-the-research-proposal) |
| low | `SoftRing::tx_encap` drops a frame that cannot be linearized but reports success (counted as sent) | `src/net/device.rs` |
| low | `ContainerDecl::ram_bytes` is documented as a footprint check but never validated | `src/security/container.rs` |
| low | `TTY_SET_SIGTARGET` is defined (CONFIG) but handled by nothing; `TTY_FLUSH` ignores its queue argument and never flushes the device buffer; `TCSADRAIN`/`TCSAFLUSH` are ignored | [tty](design/tty.md) |
| low | The TTY registry is keyed by device index without the generation | `src/driver/char/tty.rs` |
| low | `ContainerDecl::on_fault`, `supervisor`, `version` and `image_hash` are stored only (Planned) | [containers](design/containers.md#gaps-and-planned-work) |
| low | `Tty` module docs claim `VMIN`/`VTIME` support, but raw mode ignores them; `IXON` is defined but unimplemented | `src/driver/char/tty.rs` |
| low | Drivers with empty driver middleware, against the "every driver provides middleware" rule: `HalOutputPinDriver`, `SimDisplay`, `SimInput` | `src/compat/hal.rs`, `src/driver/{display,input}/sim.rs` |
| low | Input: the docs claim `Syn` packets are read atomically, but a read can split a packet | [human interface](design/human-interface.md#limitations-and-known-gaps) |
| low | `Display::blit` is three requests and not atomic across tasks (use one owner task or a mutex) | `src/driver/display/mod.rs` |
| low | Firewall `ConnTrack` is minimal: ICMP and other port-less flows collapse per host pair; TCP flags are parsed but unused (no FIN/RST teardown) | [firewall](design/firewall.md#limitations-and-known-gaps) |
| low | `DeviceClass::Other` changed from 7 to 9 in `GET_CLASS` results (new variants inserted before it) | `src/driver/mod.rs` |
| low | The `FileSystem` trait and `fs` module docs say the VFS passes `.` and `..` to the filesystem, but the resolver short-circuits `.` itself; only `..` (and real names) reach `lookup`. Harmless because RamFs also handles `.` | `src/fs/vnode.rs`, `src/fs/mod.rs` |
| low | The `fs` feature's `Cargo.toml` comment claims it enables "the VFS, RAM FS, littlefs (flash) and FAT"; only the VFS and RamFs exist | `Cargo.toml` |
| low | File operations (`open`/`read`/`write`/`stat`/…) carry no capability check yet — the VFS is one trusted global namespace; only `mount`/`unmount`/`block::register` are trusted-gated | `src/fs/mod.rs` |

### Resolved

All of these were fixed on 2026-10-10 and verified in the source:

- The syscall entry points are no longer public: `dispatch` and the port `syscall` are
  `pub(crate)`, and `raw_syscall` is `#[cfg(test)]`.
- `kill` is trusted-only. It now wakes joiners and purges the domain's keystore slots.
- The management APIs (`driver::register`/`unregister`, `net::register`, `set_up`,
  `set_offloads`, `attach_hook`, `add_global_hook`, `register_protocol`) are
  trusted-only.
- `spawn_user` returns `Unsupported` on a core without an MPU.
- FreeRTOS binary and counting semaphores respect their maximum.
- Timed POSIX calls with a deadline that has already passed return `ETIMEDOUT`.
- `PowerGate` keeps the original `Caller`.
- Entropy credits at most 8 bits per sample.
- `Deadband` compares in `i64`.
- `RawMutex` refuses interrupt context.
- rustdoc and host test builds are warning-free.
- The QEMU demo passes in debug and release (r4–r11 are now saved in the syscall path).
- TTY: a canonical read returns exactly one line, and typed-ahead input after `VEOF` or
  a signal character is preserved in a persistent `pending` buffer (checked with a
  probe: reads `"ab\n"`, `"cd\n"`, `"xy"`, `"zz\n"`).
- TTY: `tty::control` is trusted-only, so isolated domains can no longer reconfigure
  TTYs or redirect Ctrl-C. Trade-off: POSIX `tc*` calls are trusted-only.
- `compat::posix` no longer has a lowercase `termios` alias clashing with the module.
- Containers: the entry priority must be ≤ the domain ceiling, and partitioned budgets
  must fit one frame (both build errors).
- `Display::blit` does its coordinate math in `u32` and returns `Invalid` on overflow.
- POSIX `poll` reports input fds readable only when events are queued.
- **Firewall `ConnTrack` bypass (was high):** a flow becomes `ESTABLISHED` only on a
  packet in the opposite direction from its opener. My original probe (two unsolicited
  inbound UDP frames) now gives `drop`, `drop`; covered by the regression test
  `conntrack_does_not_promote_unsolicited_inbound`.
- `RuleSet::named` gives sets distinct hook names; the `with_tap` doc is corrected.
- Container budgets: soft + partitioned together must be ≤ 100% (build error).
- `net::detach_hook` is trusted-only.
- `mq_timed*` remaps `EAGAIN` to `ETIMEDOUT` only for blocking descriptors.
- FreeRTOS counting give uses the atomic `Semaphore::give_bounded`.
- `NetDevice::timer()` is called once per interface per poll round.
- `SimI2c` has a probe factory in `FACTORIES`.
- The demo's state column is padded.
- `SVCall` no longer pushes `lr` before calling `bismuth_svc`, so the call keeps AAPCS 8-byte stack alignment. This relies on the hardware's 8-byte stack alignment on exception entry (`CCR.STKALIGN`), which is the reset default on ARMv7-M cores. Re-verified on QEMU in debug and release.

## Changelog

### 2026-10-11 (fifteenth update): filesystem subsystem

The first part of the filesystem effort landed and is now documented.

- **DONE and documented:**
  - **Block device class** (`driver::block`, L2, always built): the `BlockDevice` trait,
    `BlockGeometry`, `MediaKind` (`Flash`/`Disk`/`Ram`), the trusted-gated registry and the
    `geometry`/`read_at`/`prog_at`/`erase_blk`/`sync` fast path; `SimFlash` (erase-before-write
    + `power_cut_after` injection), `SimDisk`, `SimRam`; and the composition wrappers
    `BlockCache` (write-back/through), `Partition`, `ReadOnly`, `WearCounter`.
  - **VFS + RamFs** (`fs`, L3, feature `fs`): the `FileSystem` trait and value types, the
    mount table with longest-prefix matching and generation-based handle revocation, the
    iterative bounded path resolver, the global open-file table, and `RamFs`.
  - **POSIX wiring** (`compat::posix`, features `posix` + `fs`): non-`/dev/` paths resolve
    through the VFS via a new `Kind::File` fd; `O_TRUNC`/`O_APPEND`, `SEEK_*`, the `stat`
    struct and `lseek`/`ftruncate`/`fsync`/`fstat`/`stat`/`mkdir`/`rmdir`/`unlink`/`rename`.
  - New `Error` variants (`NotADirectory`, `IsADirectory`, `NotEmpty`, `ReadOnly`,
    `NameTooLong`, `NoSpace`) with errno mappings, and the `crate::fs` import barrier in
    `tests/structure.rs`.
- **PLANNED** (designed in [research/filesystems.md](research/filesystems.md)): littlefs
  (flash), FAT (managed media), hot-file residency (Layer 2 cache), per-domain mount
  namespaces and directory-subtree capabilities, and the `/dev/<name>` block control node
  with the `0x09xx` ioctl page.
- New pages: [design/filesystem.md](design/filesystem.md) and
  [guides/filesystem.md](guides/filesystem.md); the guide's examples were compiled and run
  against the kernel (block raw ops + wrappers, block registry, the `fs::` API, the POSIX
  file API). Updated the module map (3 fs files + the 3 block files, 83 total; the new
  import barrier; a `block/` note), the configuration reference (the `BISMUTH_*` FS knobs),
  the errors reference (6 new variants), the ioctl reference (reserved `0x09xx` page),
  README and the docs index.
- Tests: **122 passed, 0 warnings** (`tests/block.rs` 11, `tests/fs.rs` 7). Both MCU
  cross-builds and the board demo build are clean; the MCU board does not build the `fs`
  feature (the block class is always compiled but dead-code-eliminated when unused).
- **Note for the lead:** the briefing listed the block cache/wrappers as "designed but not
  yet implemented," but `src/driver/block/cache.rs` (and 6 of the 11 `block.rs` tests)
  landed in the tree during this pass — documented as built. See the three new low-severity
  findings in Known issues (a `.`/`..` resolver doc overstatement, the `fs` feature comment
  overclaiming littlefs/FAT, and the as-yet-uncapability-checked file ops).

### 2026-10-10 (fourteenth update): driver reorganisation

- `driver/` is now organised by device class: `char/`, `gpio/`, `i2c/`, `sensor/`,
  `display/` and `input/`, plus `ioctl.rs`, `middleware.rs` and the core `mod.rs` with
  `FACTORIES`. The docs now use the new public paths:
  - `driver::class::ioctl` is now `driver::ioctl`;
  - the `class::{Serial, Gpio, I2cBus, Sensor}` wrappers are now
    `driver::{char, gpio, i2c, sensor}::…`;
  - `driver::drivers::*` moved into the class modules;
  - `driver::drivers::FACTORIES` is now `driver::FACTORIES`;
  - `driver::tty` is now `driver::char::tty`, with re-exports in `driver::char`.
- Updated the README layout, the drivers design page (new layout section, a path column
  in the bundled-driver table, and why `net::drivers` stays separate), `tty.md`,
  `human-interface.md`, all guides with code (TTY, display and input, writing a driver,
  porting a board, POSIX, testing), the ioctl and configuration references, and the
  regenerated module map (with a "where drivers live" section).
- Re-compiled and re-ran every documented example against the new tree. Tests: 104
  passed, 0 warnings.

### 2026-10-10 (thirteenth update)

- Verified the combined container CPU check (`soft + partitioned ≤ 100%`). Added it to
  the build-check table in `containers.md` and moved the finding to Resolved.
- `ConnTrack` was already recorded as resolved in the twelfth update, verified against
  the 104-test tree.

### 2026-10-10 (twelfth update)

- Verified the `ConnTrack` fix in the source (`opener_in`, opposite-direction
  promotion) and with my original probe (`drop`, `drop`). Also verified
  `RuleSet::named` and the `with_tap` doc fix. Moved them to Resolved.
- Updated `firewall.md`: the state model, and the requirement that the tracker sees
  both directions; the bypass gap is removed. Updated the firewall guide: the warning
  is replaced by the verified behaviour, plus distinct set names.
- There are no open high-severity issues. Tests: 104 passed, 0 warnings; the QEMU demo
  passes.

### 2026-10-10 (eleventh update)

- Verified the lead's fixes in the source; the TTY bugs were re-checked with the
  original probe input:
  - TTY one-line reads and no input loss;
  - trusted-only `tty::control`;
  - the `termios` alias removed;
  - container ceiling and partition checks;
  - `blit` overflow handled;
  - `poll` on input fds.
- Updated `tty.md` (canonical algorithm, access-control trade-off, limitations), the
  TTY guide, the POSIX guide, `containers.md` and its guide (new build checks),
  `human-interface.md` and its guide, and STATUS. Tests: 103 passed, 0 warnings.
- Still open, re-verified: the **high** `ConnTrack` direction bug, which is unchanged
  in the source. The probe still gives `drop`, then `pass`.
- New low finding: the soft and partitioned container budget sums are checked
  separately, so their combination can exceed 100%.

### 2026-10-10 (tenth update): firewall

All four requested features are now documented.

- New pages: [design/firewall.md](design/firewall.md) and
  [guides/firewall.md](guides/firewall.md). The guide's snippets were compiled against
  the kernel.
- Updated `networking.md` (`ct_mark`, pointer to `net::filter`), README (the
  `net-filter` feature, highlights, layout, links), the docs index, the module map and
  the matrix. Tests: 102 passed, 0 warnings.
- New **high** finding: `ConnTrack` is direction-blind, a firewall bypass reproduced
  with a probe test.
- New low findings: duplicate hook names, ICMP flow collapse, an inaccurate `with_tap`
  doc.

### 2026-10-10 (ninth update): display and input

- New pages: [design/human-interface.md](design/human-interface.md) and
  [guides/display-and-input.md](guides/display-and-input.md). The guide's example was
  compiled and run against the kernel.
- The docs record the actual ioctl blocks: display `0x07xx`, input `0x08xx`. They differ
  from the research because `0x06xx` is the TTY block.
- Updated the ioctl reference (new blocks, `DeviceClass` discriminants), the drivers
  page (classes, bundled drivers), README, the docs index, the module map and the
  matrix. Tests: 99 passed.
- New findings:
  - the packet-atomicity claim is wrong;
  - `poll` reports input fds as always readable;
  - the sim display and input drivers have no driver middleware;
  - `blit` can overflow, and is not atomic across tasks;
  - the `Other` discriminant shifted.

### 2026-10-10 (eighth update): TTY

- New pages: [design/tty.md](design/tty.md) and [guides/tty.md](guides/tty.md). The
  guide's snippets were compiled and run against the kernel.
- Updated the POSIX guide (`<termios.h>` section), the ioctl reference (0x06xx block),
  README, the docs index, the module map and the feature matrix. Tests: 95 passed.
- New findings:
  - a canonical multi-line read bug and input loss after `VEOF`/signal characters
    (both reproduced with a probe test);
  - unchecked `TtyControl` access;
  - `ENOTTY` from isolated-domain fds;
  - the unhandled `TTY_SET_SIGTARGET`;
  - a `TTY_FLUSH`/`tcsetattr` semantics gap;
  - the `termios` name clash;
  - an inaccurate `VMIN`/`VTIME` claim in the module docs.

### 2026-10-10 (seventh update): containers

- New pages: [design/containers.md](design/containers.md) and
  [guides/containers.md](guides/containers.md). The guide's example was compiled and
  run against the kernel.
- Added to the feature matrix, the test table (91 passed), the README (feature flag,
  highlights, layout), the docs index and the regenerated module map.
- Documented that `kill` now reaps a domain's dead tasks, which lets `restart` reclaim
  the static stack.
- New low-severity findings:
  - `ram_bytes` is never validated, although its doc says it is.
  - Entry priority is not checked against the domain ceiling at compile time.
  - `partitioned` budgets are not summed.

### 2026-10-10 (sixth update)

- Verified the round-3 fixes in the source:
  - `detach_hook` is trusted-only;
  - the `mq_timed*` `EAGAIN` handling respects `O_NONBLOCK`;
  - `Semaphore::give_bounded` is used by FreeRTOS;
  - `NetDevice::timer()` is called (also for interfaces that are down);
  - `i2c::FACTORY` is in `FACTORIES`, with 2 instances;
  - the demo's task table is padded.
- Moved the fixed items from Known issues to Resolved, and updated `networking.md`,
  `drivers-and-middleware.md`, `configuration.md`, `posix.md`, `freertos-porting.md`,
  `scheduler.md` and the `getting-started.md` QEMU output to match.
- Re-verified: 89 tests pass, 0 warnings, the QEMU demo passes.

### 2026-10-10 (fifth update)

- Verified the SVCall alignment fix (no push before the `bl`). The QEMU demo still
  passes in debug and release. The item moved from Known issues to Resolved. Items #1
  (syscall entry points no longer public) and #2 (`kill` authorization) were already
  recorded as resolved in the fourth update.

### 2026-10-10 (fourth update)

- Rebuilt "Known issues" after the lead's fixes; every item was re-verified in the
  source. Resolved items moved to a "Resolved" list.
- Two new findings: `net::detach_hook` has no trusted check, and `mq_timed*` returns
  `ETIMEDOUT` for `O_NONBLOCK` queues. A minor non-atomic max check in the FreeRTOS
  `xSemaphoreGive` was also noted.
- Updated to match: `security.md` (limitations, `kill` caller, no public
  `raw_syscall`), `networking.md` (trusted management APIs), `drivers-and-middleware.md`
  (`register`/`unregister` are trusted-only), `freertos-porting.md` (semaphore caps),
  `posix.md` (deviations), `scheduler.md` (mutexes refuse ISR context),
  `porting-a-board.md` (`spawn_user` without an MPU).
- Tests: 89 passed. rustdoc: 0 warnings. Host test build: 0 warnings.

### 2026-10-10 (third update)

- **Phase 4 (hardware isolation) is marked Done for ARMv7-M.** I verified this against
  the source and on QEMU:
  - `security::syscall` gate with the 12-call `nr` set and allow-list;
  - the `user` client;
  - `kernel::usermem` (TCB);
  - `UserStack1K/2K/4K` and `StackSource`;
  - `Builder::spawn_user` and `DomainSpec::sandboxed`;
  - MPU regions, `CONTROL.nPRIV` and the SVCall and fault handlers.

  The QEMU demo now passes in debug and release with the sandboxed task. The parts of
  the research's Phase 4 that are not built (ARMv8-M MPU, `PSPLIM`, RISC-V PMP, IPC and
  leases, peripheral regions) stay Planned.
- `security.md` gained an implementation note: `SVCall` must save and restore r4–r11,
  using a 16-word frame that mirrors PendSV.
- `getting-started.md` now has the current QEMU output, including the sandbox lines.
- Still open, re-verified in this update:
  - the safe-API soundness issue (`dispatch`, `raw_syscall` and the port `syscall` are
    still `pub`, and privileged or host callers bypass the range check);
  - `kill` still has no authorization check;
  - new: the 4-byte MSP alignment in `SVCall` (low).
- Tests: 88 passed.

### 2026-10-10 (second update)

- New [module map](reference/module-map.md) reference. It documents the classification
  scheme (`layer · category · safety · feature`), the TCB allow-list and the layering
  rules enforced by `tests/structure.rs`, and it has a per-file table generated from
  the classification lines. The architecture page and the index link to it.
- `edge-and-accel.md` now explains why there are no SIMD intrinsics (safe-Rust rule).
- Added the footprint measurement (above).
- Re-verified test counts: still 88. That count includes `tests/sandbox.rs` (2 tests),
  which is in the tree.
- **Not applied: the request to mark Phase 4 as Planned.** The source contains a
  substantial, tested implementation: `src/security/syscall.rs`, `src/user.rs`,
  `src/kernel/usermem.rs` (on the TCB allow-list in `tests/structure.rs`),
  `Builder::spawn_user`, MPU, SVCall and fault handlers in `src/arch/cortex_m.rs`,
  `tests/sandbox.rs`, and a sandbox section in the QEMU demo. The docs therefore keep
  calling it **in progress**: host tests pass, but the hardware demo fails. If this
  code is meant to be removed or disabled, say so and the docs will be switched to
  Planned once it is gone.
- "All feature combinations warning-free" could not be confirmed. The host test build
  shows the 4 warnings listed under Known issues.

### 2026-10-10

Documentation:

- Initial documentation set: the root `README.md`; `docs/README.md` (index); design
  notes (architecture, scheduler, drivers and middleware, networking, security, edge
  and accel); guides (getting started, porting a board, writing a driver, POSIX,
  FreeRTOS porting, testing with the simulator); reference pages (configuration,
  errors, ioctl); and this status page.
- The examples in "writing a driver", "getting started" and "testing with the
  simulator" were compiled and run against the kernel as a scratch crate.

Code state documented (as found in the tree on this date):

- Module classification headers and the `tests/structure.rs` rules (classification,
  TCB allow-list, layering).
- Timers and pools moved into `kernel::timer` and `kernel::mem`; they are re-exported
  as `bismuth::timer` and `bismuth::mem`.
- New `accel` module (CRC-32, Q15 MAC, copy offload) and `edge` (DSP stages, `Topic`,
  `run_pipeline`).
- New FreeRTOS compatibility suite (`tests/freertos.rs`).
- Hardware isolation work in progress:
  - `security::syscall` (SVC gate, allow-list);
  - `kernel::usermem`, a fifth TCB file;
  - the `user` client API;
  - `UserStack1K/2K/4K` and `Builder::spawn_user`;
  - `DomainSpec::{syscalls, hardware_isolated, sandboxed()}`;
  - MPU, SVCall and fault handlers in the Cortex-M port;
  - `tests/sandbox.rs`;
  - a sandbox section in the QEMU demo.
- Test count went from 72 (start of day) to 88.
