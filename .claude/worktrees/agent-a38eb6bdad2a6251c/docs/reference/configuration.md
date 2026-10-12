# Build-time configuration

All kernel limits are `const`s in `src/config.rs`. They are read with `option_env!` when
the kernel crate compiles, so kernel tables can be sized statically. Override any of
them with an environment variable:

```sh
BISMUTH_MAX_TASKS=8 BISMUTH_TICK_HZ=100 cargo build --target thumbv7m-none-eabi
```

Or, per board, in `.cargo/config.toml`. Cargo passes `[env]` to dependency crates too:

```toml
[env]
BISMUTH_MAX_TASKS = "8"
BISMUTH_NET_RX_BUFS = "4"
```

Values must be plain decimal integers. Anything else fails the build with
`bismuth config values must be decimal integers`. An empty value means the default.

**MCU vs. host defaults.** Some defaults differ between bare-metal builds
(`target_os = "none"`) and host builds (the simulator, `cargo test`). These are chosen by
`mcu_or_host(mcu, host)` in `src/config.rs`.

## Kernel

| variable | constant | default | meaning |
|----------|----------|--------:|---------|
| `BISMUTH_MAX_TASKS` | `MAX_TASKS` | 16 | Task control blocks, including idle. Must be in 2..=255 (checked at compile time). |
| (fixed) | `PRIORITIES` | 32 | Priority levels. Not configurable: the ready bitmap is a `u32`. |
| `BISMUTH_TICK_HZ` | `TICK_HZ` | 1000 | Kernel tick rate (must be > 0). SysTick reload = `core_hz / TICK_HZ − 1`. |
| `BISMUTH_TIME_SLICE` | `TIME_SLICE_TICKS` | 10 | Round-robin slice between equal-priority tasks, in ticks. 0 disables slicing. |
| `BISMUTH_MAX_TIMERS` | `MAX_TIMERS` | 8 | Software timers that can be active at once. |
| `BISMUTH_POOL_STACKS` | `POOL_STACKS` | 4 | Stacks in the shared pool, used by tasks spawned without a static stack (pthreads, `xTaskCreate`, `Builder` without `.stack`). |
| `BISMUTH_POOL_STACK_SIZE` | `POOL_STACK_SIZE` | 2048 | Bytes per pooled stack. |
| `BISMUTH_IDLE_STACK_SIZE` | `IDLE_STACK_SIZE` | 512 | Idle task stack (bytes). |
| `BISMUTH_TIMER_STACK_SIZE` | `TIMER_STACK_SIZE` | 1024 | Timer-service task stack (bytes). Timer callbacks run on it. |

## Devices and POSIX

| variable | constant | default | meaning |
|----------|----------|--------:|---------|
| `BISMUTH_MAX_DEVICES` | `MAX_DEVICES` | 16 | Registered devices (including `/dev/<ifname>` control devices). |
| `BISMUTH_MAX_LAYERS` | `MAX_LAYERS` | 6 | User middleware layers per device. Also caps global layers, and packet hooks per interface per direction and globally per direction. |
| `BISMUTH_MAX_FDS` | `MAX_FDS` | 16 | POSIX descriptors, including 0–2 (console). |
| `BISMUTH_MAX_MQUEUES` | `MAX_MQUEUES` | 4 | POSIX message queues. |
| `BISMUTH_MQUEUE_BYTES` | `MQUEUE_BYTES` | 512 | Storage per message queue (`mq_maxmsg × mq_msgsize` must fit). |

## Networking (`net`, `net-ip`)

| variable | constant | MCU default | host default | meaning |
|----------|----------|------------:|-------------:|---------|
| `BISMUTH_MAX_NETIFS` | `MAX_NETIFS` | 4 | 4 | Network interfaces. |
| `BISMUTH_NET_RX_BUFS` | `NET_RX_BUFS` | 6 | 32 | `RX_POOL` blocks (1600 B each). |
| `BISMUTH_NET_TX_BUFS` | `NET_TX_BUFS` | 6 | 32 | `TX_POOL` blocks. |
| `BISMUTH_NET_APP_BUFS` | `NET_APP_BUFS` | 6 | 32 | `APP_POOL` blocks (socket data). |
| `BISMUTH_NET_BUDGET` | `NET_BUDGET` | 16 | 16 | Packets processed per interface per direction per poll round. |
| `BISMUTH_NET_TXQ_LEN` | `NET_TXQ_LEN` | 8 | 8 | Depth of each of the two TX bands per interface. |
| `BISMUTH_NET_IP_RXQ` | `NET_IP_RXQ` | 8 | 8 | Per-interface queue feeding the IP stack. |
| `BISMUTH_NET_IP_IFACES` | `NET_IP_IFACES` | 1 | 2 | Interfaces that can run an IP stack. |
| `BISMUTH_NET_UDP_SOCKETS` | `NET_UDP_SOCKETS` | 2 | 4 | UDP sockets per IP interface. |
| `BISMUTH_NET_TCP_SOCKETS` | `NET_TCP_SOCKETS` | 2 | 4 | TCP sockets per IP interface (a listener uses one while armed). |
| `BISMUTH_NET_SOCKET_BUF` | `NET_SOCKET_BUF` | 1024 | 4096 | Bytes of RX and of TX buffer per socket. |
| `BISMUTH_NET_STACK_SIZE` | `NET_STACK_SIZE` | 16384 | 4096 | Net task stack. It holds the smoltcp socket storage on MCUs. On the host the task runs on a 1 MiB thread stack, so the value is nominal there. |
| `BISMUTH_NET_PRIORITY` | `NET_PRIORITY` | 20 | 20 | Net task priority. |

## Filesystems (`fs`)

The block device class is always compiled; the VFS, RamFs and the POSIX file wiring are
behind the `fs` feature (on by default, off for the MCU board). See
[design/filesystem.md](../design/filesystem.md).

| variable | constant | MCU default | host default | meaning |
|----------|----------|------------:|-------------:|---------|
| `BISMUTH_MAX_BLOCKDEVS` | `MAX_BLOCKDEVS` | 4 | 4 | Registered block devices. |
| `BISMUTH_MAX_MOUNTS` | `MAX_MOUNTS` | 4 | 4 | Simultaneously mounted filesystems. |
| `BISMUTH_MAX_OPEN_FILES` | `MAX_OPEN_FILES` | 8 | 32 | VFS open-file table slots. Counts open files **and** open directories (one slot each). |
| `BISMUTH_FS_PATH_MAX` | `FS_PATH_MAX` | 128 | 128 | Longest absolute path the resolver accepts (else `NameTooLong`). |
| `BISMUTH_FS_NAME_MAX` | `FS_NAME_MAX` | 64 | 64 | Longest single path component / filename. Also sizes the `DirEntry` name buffer. |
| `BISMUTH_RAMFS_INODES` | `RAMFS_INODES` | 16 | 64 | Default RamFs inodes (files + directories). |
| `BISMUTH_RAMFS_BLOCKS` | `RAMFS_BLOCKS` | 16 | 128 | Default RamFs data blocks in the shared arena. |
| `BISMUTH_RAMFS_BLOCK` | `RAMFS_BLOCK` | 256 | 256 | Bytes per RamFs data block. |

The `RAMFS_*` defaults only bind the sizes the kernel uses for its own instances; a
`RamFs<INODES, BLOCKS, BS>` takes its sizes as const generics, so an application can
instantiate whatever it needs (roughly `INODES·sizeof(Inode) + BLOCKS·BS` bytes).

## Fixed limits (not configurable)

These are constants in the source. They are listed here so you can size an application.

| limit | value | where |
|-------|------:|-------|
| Security domains (including kernel) | 8 | `security::MAX_DOMAINS` |
| Handles per domain | 16 | `security::HANDLES` |
| Keystore slots | 16 | `security/keystore.rs` |
| Entropy sources | 4 | `security/entropy/mod.rs` |
| Protocol nodes (`register_protocol`) | 8 | `net/mod.rs` |
| Socket packet queue, each direction | 4 | `net/socket.rs` |
| Socket command queue | 16 | `net/socket.rs` |
| Packet block: headroom / max frame / block | 64 / 1536 / 1600 B | `net/buf.rs` |
| pthread keys / TLS slots per task | 4 / 4 | `compat/posix/pthread.rs`, `kernel/mod.rs` |
| mqueue messages per queue / name length / priorities | 32 / 32 B / 32 | `compat/posix/mqueue.rs` |
| FreeRTOS pools: queues (512 B each), semaphores+mutexes, event groups, timers | 8, 16, 8, 8 | `compat/freertos.rs` |
| Bundled driver instances via factories: PL011, sim-sensor, pipe (256 B), sim-gpio, sim-i2c | 4, 4, 4, 1, 2 | `driver/drivers/*.rs` |
| `MovingAverage`/`Deadband` channels | 4 | `driver/middleware.rs` |
| `Sensor::read` channels | 8 | `driver/sensor/mod.rs` |
| Minimum task stack | 256 B | `kernel/task.rs` |

## Rebuilds

Cargo records which environment variables `option_env!` reads, so changing a
`BISMUTH_*` value rebuilds the kernel automatically.
