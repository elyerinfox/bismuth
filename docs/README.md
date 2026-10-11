# Bismuth documentation

These pages describe the code as it is built today. Anything not yet implemented is
labelled **Planned**. When a page and the code disagree, the code is right; please
report the discrepancy.

## Start here

- [Project README](../README.md): what Bismuth is, quick start, feature flags.
- [Getting started](guides/getting-started.md): build, run the QEMU demo, write a first
  task and a first simulator test.
- [Status](STATUS.md): what is implemented and what is planned, test counts, changelog.

## Design

How the kernel works and why.

| page | covers |
|------|--------|
| [Architecture](design/architecture.md) | layer diagram, design principles (static allocation, safe Rust + TCB, single-owner net task, two network planes, middleware), the host simulator (baton, virtual time) |
| [Scheduler](design/scheduler.md) | tasks and priorities, ready bitmap, time slicing, wait keys, priority inheritance, ISR rules, Cortex-M context switch, lazy FPU stacking, stack painting |
| [Drivers and middleware](design/drivers-and-middleware.md) | `Driver`, `Request`/`Op`, chain order, built-in middleware catalogue, `probe_all`/`DeviceDesc`/`Mmio`, device classes |
| [Networking](design/networking.md) | as built vs. the research proposal; `NetDevice`, `PacketBuf`, hooks, `NetRing`, protocol nodes, smoltcp, sockets, configuration knobs |
| [Filesystem](design/filesystem.md) | block device class (`BlockDevice`, `MediaKind`, sim media, cache/partition/read-only/wear wrappers), the VFS (mount table, resolver, open-file table, generation revocation), RamFs, POSIX wiring, as built vs. research |
| [Security](design/security.md) | domains, handles and rights, `DeviceCap`, policies, manifest, sandboxed tasks (SVC + MPU), entropy pipeline, keystore, threat model, known gaps |
| [Containers](design/containers.md) | container = domain + grants + entry + budget + fault policy + image hash; compile-time validation, lifecycle, Linux mapping, gaps |
| [TTY, PTY and termios](design/tty.md) | `Tty` line-discipline middleware, `Termios`, terminal signals without UNIX signals, typed `TtyControl` (no pointer ioctls), PTYs, `<termios.h>`, known bugs |
| [Human interface](design/human-interface.md) | `Display` (window + pixel stream, 0x07xx) and `Input` (evdev-style events, 0x08xx) classes, simulator drivers, gaps |
| [Firewall](design/firewall.md) | `RuleSet` first-match chains, `MatchExpr`, IPv4-only default semantics, `ConnTrack`, iptables/pf builders, out-of-scope list, known gaps |
| [Edge compute and offload](design/edge-and-accel.md) | fixed-point DSP stages, `Topic` pub/sub, `run_pipeline`, `accel` engines with vetting and software fallback |

## Guides

Task-oriented how-tos.

| page | covers |
|------|--------|
| [Getting started](guides/getting-started.md) | toolchain, `cargo test`, the QEMU demo, a first application |
| [Porting a board](guides/porting-a-board.md) | creating a board crate from `boards/qemu-lm3s6965`; the one `unsafe` boundary (`Mmio::new`) |
| [Writing a driver](guides/writing-a-driver.md) | a complete GPIO driver with its own middleware and a probe factory, step by step |
| [POSIX](guides/posix.md) | the supported POSIX surface and how it differs from a real POSIX system |
| [Using the filesystem](guides/filesystem.md) | register a block device, compose wrappers, mount a RamFs, use the `fs::` and POSIX file APIs |
| [Porting FreeRTOS code](guides/freertos-porting.md) | the supported FreeRTOS API and how its semantics differ |
| [Containers](guides/containers.md) | declare, validate, install, start, supervise and test a sandboxed container |
| [Terminals](guides/tty.md) | a TTY on a UART or a PTY, raw mode, Ctrl-C handling, simulator tests |
| [Display and input](guides/display-and-input.md) | draw on a panel, react to keys, test with `SimDisplay`/`SimInput` |
| [Firewall](guides/firewall.md) | allow one service, pf-style rules, outbound-only stateful policy, drop logging |
| [Testing with the simulator](guides/testing-with-the-simulator.md) | `sim::run`, outcomes, virtual time vs. realtime, simulated hardware |

## Reference

| page | covers |
|------|--------|
| [Configuration](reference/configuration.md) | every `BISMUTH_*` build variable, with MCU and host defaults |
| [Errors](reference/errors.md) | `Error` variants and their `errno` mapping |
| [ioctl numbers](reference/ioctl.md) | every ioctl command and the right it requires |
| [Module map](reference/module-map.md) | per-file classification (layer · category · safety · feature), TCB allow-list, layering rules enforced by `tests/structure.rs` |

## Research (input documents)

Background studies that the design was based on. These are proposals, not descriptions
of the code. Each design page explains where the implementation differs from them.

- [research/networking.md](research/networking.md): FreeBSD/Linux/MCU stacks and the
  recommended network design.
- [research/security.md](research/security.md): Zircon/seL4/Tock/Hubris and the
  recommended security design.
- [research/filesystems.md](research/filesystems.md): the vnode/VFS, littlefs, FAT and
  MCU-class filesystems, and the recommended `fs` design.

## Conventions

- Paths such as `src/net/buf.rs` are relative to the repository root.
- Type paths are given from the crate root, which is named `bismuth` (for example
  `bismuth::driver::Device`).
- "Tick" means one kernel tick: `BISMUTH_TICK_HZ`, 1000 Hz by default.
