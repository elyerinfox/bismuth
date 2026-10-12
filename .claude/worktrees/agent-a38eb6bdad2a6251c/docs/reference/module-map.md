# Module map and classification

Every source file under `src/` begins its module docs with one classification line:

```rust
//! Classification: <layer> · <category> · <safety> · <feature gate>
```

| field | allowed values | meaning |
|-------|----------------|---------|
| layer | `L0 port`, `L1 kernel`, `L2 devices`, `L3 services`, `L4 personalities`, `support` | position in the layer stack |
| category | free text | what the file is about, e.g. `net: packet buffers` |
| safety | `safe` or `TCB (unsafe allowed)` | whether the file may opt into `unsafe` |
| feature gate | free text | the Cargo feature or `cfg` that builds it (`always`, `net`, `host only`, `target_os = "none"`, …) |

## What `tests/structure.rs` enforces

These rules are checked on every `cargo test`:

1. **Classification.** Every `.rs` file under `src/` has a well-formed line with four
   `·`-separated fields, a known layer, and a known safety value.
2. **TCB allow-list.** A file contains `#![allow(unsafe_code)]` (or
   `#[allow(unsafe_code)]`) **if and only if** it is on the allow-list, and exactly
   those files are classified `TCB (unsafe allowed)`. The crate root must keep
   `#![deny(unsafe_code)]`. The allow-list today:
   - `src/arch/cortex_m.rs`
   - `src/arch/mmio.rs`
   - `src/kernel/cell.rs`
   - `src/kernel/stack.rs`
   - `src/kernel/usermem.rs`
3. **Downward-only imports.** A file may not name these module paths, outside comments:

   | layer | may not import |
   |-------|----------------|
   | L0 port | `crate::driver`, `crate::net`, `crate::compat`, `crate::edge`, `crate::security`, `crate::fs` |
   | L1 kernel | `crate::driver`, `crate::net`, `crate::compat`, `crate::edge`, `crate::console`, `crate::fs` |
   | L2 devices | `crate::net::`, `crate::compat`, `crate::edge`, `crate::fs` |
   | L3 services | `crate::compat::posix`, `crate::compat::freertos` |

   The documented exceptions, which necessarily call upwards:
   - **Kernel → security domain hooks:** `crate::security::current`,
     `crate::security::check_*`, `crate::security::DomainId`,
     `crate::security::Caller`.
   - **Port trap and fault entry → syscall gate and fault accounting:**
     `crate::security::syscall::dispatch`, `crate::security::kill`,
     `crate::security::record_fault`.

   The check is textual: it looks for these strings on non-comment lines. A glob
   import or an alias could bypass it, so reviewers should still watch the layering.

## Adding a file

1. Add the classification line to its `//!` docs, choosing the lowest layer that fits.
2. Import only from the same or lower layers.
3. Do not use `unsafe`. If you really need it, the change must extend the TCB
   allow-list in `tests/structure.rs`, and it deserves a review of its own.

## Where drivers live

`src/driver/` is organised **by device class**:

- `char/`, `gpio/`, `i2c/`, `sensor/`, `display/` and `input/` each hold the class's
  typed wrapper in `mod.rs` and its bundled drivers, with simulated ones in `sim.rs`;
- `block/` holds the `BlockDevice` trait and the block registry (`mod.rs`) with simulated
  flash/disk/ram in `sim.rs`. Unlike the other classes it is **not** an `Op`/middleware
  device: filesystems call it on a fast path, so it has a trait and registry rather than a
  `Device` wrapper (see [design/filesystem.md](../design/filesystem.md));
- `driver/mod.rs` is the core: `Driver`, `Device`, registry, `probe_all`,
  `DeviceClass` and `FACTORIES`;
- `driver/ioctl.rs` is the central ioctl registry;
- `driver/middleware.rs` holds the generic layers.

These class folders are only for devices that implement the generic `Driver` trait.
Network drivers (`src/net/drivers/`: loopback, simulated wire) implement
`NetDevice`/`FrameDevice` instead, so they live with the network subsystem that defines
that contract. Security entropy sources (`security/entropy/sources.rs`) and `accel`
engines likewise live with the subsystem whose trait they implement.

## Module map

This table is generated from the classification lines (83 files).

| layer | file | category | safety | feature |
|-------|------|----------|--------|---------|
| L0 port | `src/arch/cortex_m.rs` | Cortex-M port | **TCB** | target_os = "none" |
| L0 port | `src/arch/host.rs` | host simulator port | safe | host only |
| L0 port | `src/arch/mmio.rs` | memory-mapped I/O | **TCB** | always |
| L0 port | `src/arch/mod.rs` | port interface | safe | always |
| L1 kernel | `src/kernel/cell.rs` | shared-state cells | **TCB** | always |
| L1 kernel | `src/kernel/mem.rs` | memory pools | safe | always |
| L1 kernel | `src/kernel/mod.rs` | scheduler core | safe | always |
| L1 kernel | `src/kernel/stack.rs` | task stacks | **TCB** | always |
| L1 kernel | `src/kernel/task.rs` | task management | safe | always |
| L1 kernel | `src/kernel/time.rs` | time | safe | always |
| L1 kernel | `src/kernel/timer.rs` | software timers | safe | always |
| L1 kernel | `src/kernel/usermem.rs` | syscall user-memory validation | **TCB** | always |
| L1 kernel | `src/sync/condvar.rs` | synchronization | safe | always |
| L1 kernel | `src/sync/event.rs` | synchronization | safe | always |
| L1 kernel | `src/sync/mod.rs` | synchronization | safe | always |
| L1 kernel | `src/sync/mutex.rs` | synchronization | safe | always |
| L1 kernel | `src/sync/queue.rs` | inter-task communication | safe | always |
| L1 kernel | `src/sync/semaphore.rs` | synchronization | safe | always |
| L2 devices | `src/accel/mod.rs` | hardware offload | safe | always |
| L2 devices | `src/console.rs` | kernel console | safe | always |
| L2 devices | `src/driver/block/cache.rs` | block: write-back cache / wrappers | safe | always |
| L2 devices | `src/driver/block/mod.rs` | block device class | safe | always |
| L2 devices | `src/driver/block/sim.rs` | block driver: simulated flash/disk | safe | always |
| L2 devices | `src/driver/char/mod.rs` | char class | safe | always |
| L2 devices | `src/driver/char/pipe.rs` | driver: char (pipe) | safe | always |
| L2 devices | `src/driver/char/pl011.rs` | driver: char (PL011 UART) | safe | always |
| L2 devices | `src/driver/char/pty.rs` | driver: pty | safe | always |
| L2 devices | `src/driver/char/tty.rs` | tty line discipline | safe | always |
| L2 devices | `src/driver/display/mod.rs` | display class | safe | always |
| L2 devices | `src/driver/display/sim.rs` | driver: sim-display | safe | always |
| L2 devices | `src/driver/gpio/mod.rs` | gpio class | safe | always |
| L2 devices | `src/driver/gpio/sim.rs` | driver: gpio (simulated) | safe | always |
| L2 devices | `src/driver/i2c/mod.rs` | i2c class | safe | always |
| L2 devices | `src/driver/i2c/sim.rs` | driver: i2c (simulated) | safe | always |
| L2 devices | `src/driver/input/mod.rs` | input class | safe | always |
| L2 devices | `src/driver/input/sim.rs` | driver: sim-input | safe | always |
| L2 devices | `src/driver/ioctl.rs` | ioctl registry | safe | always |
| L2 devices | `src/driver/middleware.rs` | middleware library | safe | always |
| L2 devices | `src/driver/mod.rs` | driver model and registry | safe | always |
| L2 devices | `src/driver/sensor/mod.rs` | sensor class | safe | always |
| L2 devices | `src/driver/sensor/sim.rs` | driver: sensor (simulated) | safe | always |
| L3 services | `src/edge/dsp.rs` | edge: DSP stages | safe | edge |
| L3 services | `src/edge/mod.rs` | edge compute | safe | edge |
| L3 services | `src/fs/mod.rs` | fs: vfs core and mount table | safe | fs |
| L3 services | `src/fs/ramfs.rs` | fs: ram filesystem | safe | fs |
| L3 services | `src/fs/vnode.rs` | fs: vfs contract | safe | fs |
| L3 services | `src/net/buf.rs` | net: packet buffers | safe | net |
| L3 services | `src/net/csum.rs` | net: checksums | safe | net |
| L3 services | `src/net/device.rs` | net: driver contract | safe | net |
| L3 services | `src/net/drivers/loopback.rs` | net driver: loopback | safe | net |
| L3 services | `src/net/drivers/mod.rs` | net: bundled drivers | safe | net |
| L3 services | `src/net/drivers/wire.rs` | net driver: simulated cable | safe | net |
| L3 services | `src/net/filter.rs` | net: packet filter | safe | net-filter |
| L3 services | `src/net/hook.rs` | net: packet hooks | safe | net |
| L3 services | `src/net/ip.rs` | net: IP stack (smoltcp) | safe | net-ip |
| L3 services | `src/net/mod.rs` | net: core and net task | safe | net |
| L3 services | `src/net/ring.rs` | net: zero-copy rings | safe | net |
| L3 services | `src/net/socket.rs` | net: sockets | safe | net-ip |
| L3 services | `src/security/container.rs` | security: containers | safe | containers |
| L3 services | `src/security/entropy/drbg.rs` | security: DRBG | safe | crypto |
| L3 services | `src/security/entropy/health.rs` | security: entropy health tests | safe | crypto |
| L3 services | `src/security/entropy/mod.rs` | security: entropy and CSPRNG | safe | crypto |
| L3 services | `src/security/entropy/sources.rs` | security: entropy sources | safe | crypto |
| L3 services | `src/security/keystore.rs` | security: keystore | safe | crypto |
| L3 services | `src/security/manifest.rs` | security: static manifest | safe | always |
| L3 services | `src/security/mod.rs` | security: domains, handles, rights | safe | always |
| L3 services | `src/security/syscall.rs` | security: system-call gate | safe | always |
| L4 personalities | `src/compat/errno.rs` | POSIX errno values | safe | always |
| L4 personalities | `src/compat/freertos.rs` | FreeRTOS API | safe | freertos-compat |
| L4 personalities | `src/compat/hal.rs` | embedded-hal / embedded-io | safe | hal-compat |
| L4 personalities | `src/compat/mod.rs` | compatibility layers | safe | always |
| L4 personalities | `src/compat/posix/mod.rs` | POSIX | safe | posix |
| L4 personalities | `src/compat/posix/mqueue.rs` | POSIX message queues | safe | posix |
| L4 personalities | `src/compat/posix/pthread.rs` | POSIX threads | safe | posix |
| L4 personalities | `src/compat/posix/semaphore.rs` | POSIX semaphores | safe | posix |
| L4 personalities | `src/compat/posix/termios.rs` | POSIX termios | safe | posix |
| L4 personalities | `src/compat/posix/time.rs` | POSIX clocks | safe | posix |
| L4 personalities | `src/compat/posix/unistd.rs` | POSIX file descriptors and sockets | safe | posix |
| L4 personalities | `src/user.rs` | user runtime (syscall client) | safe | always |
| support | `src/config.rs` | configuration | safe | always |
| support | `src/error.rs` | errors | safe | always |
| support | `src/lib.rs` | crate root | safe | always |
| support | `src/sim.rs` | host simulator | safe | host only |

Re-exports at the crate root:

- `bismuth::timer` is `kernel::timer`, and `bismuth::mem` is `kernel::mem`.
- `bismuth::{task, time, Stack, StackRef, UserStack1K, UserStack2K, UserStack4K,
  TaskId, TaskState, Instant, Timeout, Error}`.
- `bismuth::prelude`.
