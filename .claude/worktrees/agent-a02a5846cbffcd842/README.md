# Bismuth

Bismuth is a small, modular real-time kernel for edge-computing IoT devices, written in
`no_std` Rust. It has no heap: every kernel table is sized at compile time. It runs on
Cortex-M (ARMv7-M and ARMv8-M Mainline) and in a deterministic host simulator that the
test suite uses.

```text
compat (POSIX · FreeRTOS · embedded-hal) · user (syscall client)      L4 personalities
security (+ syscall gate) · net (+ smoltcp) · fs (VFS + RamFs) · edge  L3 services
driver framework + middleware · block device class · accel · console  L2 devices
scheduler · tasks · time · timers · pools · sync                      L1 kernel
arch: Cortex-M port · host simulator · MMIO                           L0 port
```

## Highlights

- **RTOS core.** Fixed-priority preemptive scheduler with O(1) task selection (a 32-level
  ready bitmap) and round-robin time slicing. Includes priority-inheritance mutexes,
  semaphores, condition variables, message queues, event flags, task notifications,
  software timers and fixed-block memory pools.
- **Driver framework with mandatory middleware.** Every request passes through a chain:
  global layers, then per-device user layers, then the driver's own layers. Every driver
  must supply its own layers (line discipline, calibration, debouncing, and so on). The
  framework ships a library of reusable layers: stats, trace, rate limit, retry, power
  gating, access policy, filters and deadband. Boards bind drivers by *compatible* string,
  as with a device tree.
- **Networking.** The design borrows from FreeBSD iflib/netmap and Linux NAPI, scaled
  down for MCUs:
  - packet buffers drawn from separate RX, TX and application pools;
  - one network task that owns all interfaces and polls them with a budget;
  - two-band transmit queues;
  - checksum offload with a software fallback;
  - packet hooks (firewall, rate limit, steering);
  - zero-copy `NetRing`s and custom protocol nodes;
  - IPv4, TCP, UDP and ICMP through [smoltcp], with a socket API on top;
  - a packet filter (`net::filter`): first-match rule chains with iptables- and
    pf-style builders and simple connection tracking.
- **Security.** Security domains own handle tables. Rights can only ever be reduced, and
  bumping an object's generation revokes every handle to it. Isolated domains have no
  ambient authority: the kernel checks rights *before* the middleware chain runs. Domains
  can also carry priority ceilings, task quotas, a network policy, `seal()` and a
  manifest that is checked at compile time. **Sandboxed tasks** run
  unprivileged under the Cortex-M MPU and reach the kernel only through an
  allow-listed `SVC` system-call gate. The crypto side has entropy health tests
  from NIST SP 800-90B, a root CSPRNG built on ChaCha20 with fast key erasure, one
  CSPRNG per domain, and a PSA-style keystore over RustCrypto.
- **Containers.** A container is a named, versioned workload bundle: a domain, its
  grants, a root task, a CPU budget, a fault policy and an image hash. The whole set is
  validated at compile time, and trusted code can install, start, stop, restart and
  health-check containers. It is an attested partition, not "Docker for MCUs".
  CPU-budget enforcement and automatic fault policies are Planned.
- **Terminals.** A `Tty` line-discipline middleware fits over any character device.
  It provides canonical line editing with echo, output translation, and Ctrl-C handling
  through task notifications. The kernel also has `Pty` pseudo-terminals and POSIX
  `<termios.h>`, all in safe Rust: termios travels through a typed interface, never
  through raw ioctl pointers.
- **Display and input.** There are `Display` and `Input` device classes on the
  ordinary driver model. Displays take a damage window plus pixel writes; input devices
  produce evdev-style 16-byte events. Simulator drivers cover both.
- **Storage and filesystems.** A block device class (`BlockDevice` + `BlockGeometry` +
  `MediaKind`) covers erase-before-write flash, managed SD/eMMC sectors and RAM disks
  behind one trait, with simulated media (including flash power-cut injection) and
  build-time composition wrappers (block cache, partition, read-only, wear counter). On
  top sits a no-heap VFS: a `FileSystem` trait keyed by integer vnodes, a mount table with
  generation-based handle revocation, a bounded iterative path resolver, and a RAM
  filesystem. POSIX `open`/`read`/`write`/`lseek`/`stat`/`mkdir`/… resolve real paths
  through it. littlefs, FAT, caching residency and per-domain namespaces are planned.
- **Edge compute.** Fixed-point DSP stages (FIR, biquad, EMA, decimation, running
  statistics, z-score anomaly detection, RMS) chain into pipelines that publish to
  pub/sub topics. Hardware offload (`accel`) covers CRC, Q15 multiply-accumulate and
  copy. An engine is checked against the software reference before use, and the
  software path takes over if it fails.
- **Compatibility.**
  - A POSIX subset: pthreads, semaphores, clocks, message queues, file descriptors on
    `/dev/*`, `poll`, BSD sockets.
  - A FreeRTOS-style API: tasks, queues, semaphores, event groups, notifications and
    timers.
  - `embedded-hal` 1.0 and `embedded-io` adapters in both directions.
- **Host simulator.** Tests run whole systems in virtual time. They finish instantly and
  deterministically, and the simulator reports deadlocks and task panics as outcomes.

## Safety rule: safe Rust only

The crate is `#![deny(unsafe_code)]`. Only these five files, the **trusted computing base
(TCB)**, may contain `unsafe`:

| file | why it needs `unsafe` |
|------|-----------------------|
| `src/arch/cortex_m.rs` | inline assembly, PendSV/SysTick/SVCall/fault handlers, MPU and system registers |
| `src/arch/mmio.rs` | volatile register access behind the safe `Mmio` window |
| `src/kernel/cell.rs` | `IrqCell` / `TaskCell`, the shared-state cells everything else builds on |
| `src/kernel/stack.rs` | raw task-stack memory handed to the CPU |
| `src/kernel/usermem.rs` | turning validated `(address, length)` system-call arguments into slices |

`tests/structure.rs` enforces this list, along with per-file classification lines and
downward-only layer imports (see the [module map](docs/reference/module-map.md)). A board crate makes one `unsafe` assertion: it
calls `Mmio::new(base, len)` to declare where each peripheral lives. Everything above
that point, including drivers, is safe code. See
[docs/design/architecture.md](docs/design/architecture.md#safe-rust-and-the-tcb).

## Quick start

The project needs a recent stable Rust toolchain. Edition 2024 is required, and so is
stable `#[unsafe(naked)]` support, which arrived in Rust 1.88. Development uses rustc
1.99.

```sh
# Host: unit tests plus the integration suites, all in the deterministic simulator
cargo test

# Cross-build the kernel for MCUs
rustup target add thumbv7m-none-eabi thumbv7em-none-eabihf
cargo build --target thumbv7m-none-eabi      # Cortex-M3
cargo build --target thumbv7em-none-eabihf   # Cortex-M4F/M7 (FPU, lazy FP stacking)

# QEMU demo (Cortex-M3, lm3s6965evb); needs qemu-system-arm on PATH
cd boards/qemu-lm3s6965
cargo run
```

The demo prints sensor readings that pass through a middleware pipeline, demonstrates
a real priority-inversion scenario, and runs a sandboxed task under the MPU. It ends with
`BISMUTH QEMU DEMO: PASS`. Sample output is in
[docs/guides/getting-started.md](docs/guides/getting-started.md).

## Crate features

Defined in `Cargo.toml`. All are on by default except `posix-abi`.

| feature | default | enables | extra dependencies |
|---------|:-------:|---------|--------------------|
| `posix` | yes | `compat::posix`: pthreads, semaphores, mqueues, clocks, fds, `poll`, sockets (with `net-ip`) | none |
| `posix-abi` | no | **Planned:** export POSIX under the C symbol names. The feature is declared but nothing uses it yet. | none |
| `hal-compat` | yes | `compat::hal`: `embedded-hal` / `embedded-io` adapters | `embedded-hal`, `embedded-io` |
| `freertos-compat` | yes | `compat::freertos`: FreeRTOS-style API | none |
| `net` | yes | `net`: packet buffers, `NetDevice`, net task, hooks, `NetRing` | none |
| `net-filter` | yes | `net::filter`: stateful IPv4 packet filter (`RuleSet`, `ConnTrack`) with iptables/pf-style builders (implies `net`) | none |
| `net-ip` | yes | `net::ip`, `net::socket`: IPv4/TCP/UDP/ICMP via smoltcp (implies `net`) | `smoltcp` |
| `crypto` | yes | `security::entropy`, `security::keystore` (domains are always built) | `chacha20`, `sha2`, `hkdf`, `hmac`, `chacha20poly1305`, `zeroize`, `subtle`, `rand_core` |
| `containers` | yes | `security::container`: declarative, compile-time-validated workload bundles over domains (install/start/stop/restart/health) | none |
| `edge` | yes | `edge`: DSP stages (`edge::dsp`), `Topic` pub/sub, `run_pipeline` | none |
| `fs` | yes | `fs`: the VFS (mount table, resolver, open-file table), `RamFs`, and POSIX file paths (with `posix`). The block device class in `driver::block` is always built. | none |

Kernel limits (task count, tick rate, pool sizes, socket counts and so on) are build-time
environment variables such as `BISMUTH_MAX_TASKS=8`. See
[docs/reference/configuration.md](docs/reference/configuration.md).

## Repository layout

```text
src/
  arch/        L0  ports: cortex_m.rs (TCB), host.rs (simulator), mmio.rs (TCB)
  kernel/      L1  scheduler core (mod.rs), task, time, timer, mem (pools), cell (TCB), stack (TCB), usermem (TCB)
  sync/        L1  Mutex/RawMutex, Semaphore, CondVar, Queue, EventFlags
  driver/      L2  core (mod.rs: Driver, Device, registry, FACTORIES), ioctl.rs, middleware.rs,
                   one folder per class: char/ (pipe, pl011, pty, tty), gpio/, i2c/, sensor/,
                   display/, input/ (typed wrapper in mod.rs, simulated drivers in sim.rs),
                   block/ (BlockDevice trait + registry, cache.rs wrappers, sim flash/disk/ram)
  accel/       L2  hardware offload with software fallback (CRC-32, Q15 MAC, copy)
  console.rs   L2  kprint!/kprintln!
  fs/          L3  VFS core + mount table (mod.rs), FileSystem contract (vnode.rs), RamFs (ramfs.rs)
  net/         L3  buf, device, hook, ring, csum, filter (firewall), ip (smoltcp), socket, drivers/ (loopback, wire)
  security/    L3  domains/handles/rights, manifest, container, syscall (SVC gate), entropy/, keystore
  edge/        L3  dsp.rs (fixed-point stages), Topic pub/sub, run_pipeline
  compat/      L4  posix/, freertos.rs, hal.rs, errno.rs
  user.rs      L4  system-call client API for sandboxed (unprivileged) tasks
  config.rs, error.rs, sim.rs, lib.rs
tests/         integration suites: kernel, drivers, block, fs, net, posix, freertos, security, sandbox, containers, tty, hid, firewall, edge, structure
boards/qemu-lm3s6965/   example board crate + QEMU demo
docs/          design notes, guides, reference, status (start at docs/README.md)
```

## Documentation

| | |
|---|---|
| [docs/README.md](docs/README.md) | documentation index |
| [Architecture](docs/design/architecture.md) | layers, design principles, how the simulator works |
| [Scheduler](docs/design/scheduler.md) | tasks, ready bitmap, blocking, priority inheritance, context switch |
| [Drivers and middleware](docs/design/drivers-and-middleware.md) | the driver model and the middleware catalogue |
| [Networking](docs/design/networking.md) | the network core as built |
| [Filesystem](docs/design/filesystem.md) · [guide](docs/guides/filesystem.md) | block device class + sim media, VFS (mount table, resolver, open-file table), RamFs, POSIX file paths |
| [Security](docs/design/security.md) | domains, rights, sandboxed tasks, entropy, keystore, threat model |
| [Containers](docs/design/containers.md) · [guide](docs/guides/containers.md) | workload bundles over domains, lifecycle, compile-time validation |
| [TTY, PTY and termios](docs/design/tty.md) · [guide](docs/guides/tty.md) | line discipline middleware, pseudo-terminals, POSIX termios |
| [Display and input](docs/design/human-interface.md) · [guide](docs/guides/display-and-input.md) | display and input device classes |
| [Firewall](docs/design/firewall.md) · [guide](docs/guides/firewall.md) | `RuleSet`, `ConnTrack`, iptables/pf builders |
| [Edge compute and offload](docs/design/edge-and-accel.md) | DSP stages, pipelines, topics, `accel` engines |
| [Getting started](docs/guides/getting-started.md) | first application, first test |
| [Module map](docs/reference/module-map.md) | per-file layer/safety classification and the rules `tests/structure.rs` enforces |
| [Status](docs/STATUS.md) | implemented vs. planned, test counts, footprint, changelog |

## License

MIT OR Apache-2.0, as declared in `Cargo.toml`.

[smoltcp]: https://github.com/smoltcp-rs/smoltcp
