# Architecture

Bismuth is one `no_std` crate (`bismuth`) organised in five layers. A board crate links
it, describes its hardware, spawns tasks and calls `bismuth::start(core_hz)`.

## Layers

```text
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ L4 personalities  compat::posix     compat::freertos   compat::hal    user   │
 │                   pthreads, fds,    xTask*, xQueue*,   e-hal, e-io    SVC    │
 │                   mqueue, sockets   timers, events     adapters       client │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ L3 services       security             net                    edge           │
 │                   domains, rights,     PacketBuf pools,       dsp stages,    │
 │                   DeviceCap, manifest, net task, hooks,       Topic pub/sub, │
 │                   syscall gate,        NetRing, smoltcp,      run_pipeline   │
 │                   entropy, keystore    sockets                               │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ L2 devices        driver: Driver, Middleware, registry, probe_all, class     │
 │                   (ioctls, typed views), middleware library, bundled drivers │
 │                   accel: CRC / Q15 MAC / copy offload    console: kprintln!  │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ L1 kernel         kernel: scheduler core, task, time, timer, mem (pools),    │
 │                   cell, stack, usermem (TCB)                                 │
 │                   sync: Mutex, Semaphore, CondVar, Queue, EventFlags         │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ L0 port           arch::cortex_m (TCB)   arch::host (simulator)              │
 │                   arch::mmio (TCB)                                           │
 └──────────────────────────────────────────────────────────────────────────────┘
   support: config (build-time limits), error (Error ↔ errno), sim (host only)
```

The full per-file table is in the [module map](../reference/module-map.md). Every source
file starts with a classification line, for example:

```rust
//! Classification: L3 services · net: packet buffers · safe · net
```

The four fields are layer · category · safety · feature gate. `tests/structure.rs`
checks three things on every `cargo test`:

1. Every file under `src/` has a well-formed classification line.
2. `#![allow(unsafe_code)]` appears in exactly the TCB files, and those files are
   classified `TCB (unsafe allowed)`.
3. Layers only depend downwards. The test bans these imports:

   | layer | must not import |
   |-------|-----------------|
   | L0 port | `crate::driver`, `crate::net`, `crate::compat`, `crate::edge`, `crate::security` |
   | L1 kernel | `crate::driver`, `crate::net`, `crate::compat`, `crate::edge`, `crate::console` |
   | L2 devices | `crate::net::`, `crate::compat`, `crate::edge` |
   | L3 services | `crate::compat::posix`, `crate::compat::freertos` |

   Two exceptions are documented, because these calls necessarily go upwards:
   - The kernel calls into security for domain checks: `crate::security::current`,
     `crate::security::check_*`, `crate::security::DomainId` and
     `crate::security::Caller`.
   - The port's trap and fault entry calls the system-call gate and fault accounting:
     `crate::security::syscall::dispatch`, `crate::security::kill` and
     `crate::security::record_fault`.

## Design principles

### Static allocation, no heap

- Every limit is a `const` in `src/config.rs` that a `BISMUTH_*` environment variable can
  override at build time. See [configuration](../reference/configuration.md). Kernel
  tables (`[Tcb; MAX_TASKS]`, the device registry, fd table, timer table, interface
  table and so on) are fixed arrays inside `static`s.
- Task stacks are `static STACK: Stack<N> = Stack::new();`. Tasks created without a
  static stack (pthreads, FreeRTOS `xTaskCreate`) get one from a pool of
  `POOL_STACKS × POOL_STACK_SIZE` stacks.
- The FreeRTOS and POSIX "create" calls (`xQueueCreate`, `mq_open`, ...) allocate from
  fixed object pools.
- `mem::Pool<T, N>` and `net::PacketPool<N>` hand out fixed blocks. Allocation can block
  with a timeout, which gives producers and consumers a natural back-pressure.
- Every kernel object is `const`-constructible, so it can live in a `static`.

### Safe Rust and the TCB

`#![deny(unsafe_code)]` applies crate-wide. Only the trusted computing base can opt out:

| TCB file | provides |
|----------|----------|
| `src/arch/cortex_m.rs` | PRIMASK critical sections, PendSV (naked asm), SysTick, SVCall and fault handlers, MPU and `CONTROL` programming, initial exception frames |
| `src/arch/mmio.rs` | `Mmio`: `unsafe fn new(base, len)`, then safe, bounds-checked, alignment-checked `read32`/`write32`/`modify32` |
| `src/kernel/cell.rs` | `IrqCell<T>` and `TaskCell<T>` (below) |
| `src/kernel/stack.rs` | `Stack<N>`, `UserStack1K/2K/4K` (MPU-aligned), `StackRef`, stack painting and the stack pool |
| `src/kernel/usermem.rs` | turning validated system-call `(address, length)` arguments into slices |

All other shared state is built on two cells from `kernel::cell` (re-exported from
`bismuth::sync`):

- **`IrqCell<T>`**: a `RefCell` that is only borrowed inside `lock(|v| ...)`, which runs
  in a critical section. On Cortex-M that means interrupts are masked. On the host it
  means the global port lock is held. A re-entrant `lock` panics instead of causing
  undefined behaviour. Keep closures short.
- **`TaskCell<T>`**: an exclusive claim that can last a long time, used for mutex-protected
  data, pool slots and packet blocks. `borrow_mut()` sets a flag inside a critical
  section and returns a `TaskRef`, which releases the claim on drop. A conflicting claim
  panics. A `TaskRef` is `Send`, which is how a `PacketBuf` can travel through a queue to
  another task.

The kernel state itself (`kernel::Kernel`) is one `IrqCell` reached through the
crate-internal `kernel::with(|k| ...)`.

A board crate only needs `unsafe` for `Mmio::new`. That call is where the board asserts
that an address range really is a given peripheral. See
[porting a board](../guides/porting-a-board.md).

### Wait keys instead of wait lists

Kernel objects do not keep intrusive wait queues. A blocked task records a **key**, the
object's address (or the address + 1 for a second condition, such as a queue's
"not full"). Waking scans the task table for the highest-priority waiter on that key,
breaking ties FIFO by a wait sequence number. With task counts in the tens, this keeps
every object `const`-constructible and freely movable while idle. The price is an O(n)
scan on wake-up. Details are in the [scheduler](scheduler.md).

### The middleware model (control plane)

All device I/O is a `Request { op, timeout, flags, caller }` that passes through a chain
of `Middleware` layers before reaching `Driver::handle`:

```text
global (system-wide) → per-device user layers → driver's own layers → Driver::handle/power
```

Every driver *must* provide its own middleware (`Driver::middleware`). Logic that adapts
raw hardware into a clean device belongs there, not hidden inside `handle`: line
discipline, calibration, debouncing, address checks. That keeps it inspectable
(`Device::chain`) and reusable. See [drivers and middleware](drivers-and-middleware.md).

### Networking: single owner, two planes

- **Single owner.** One `net` task owns every interface's rings, its transmit queues
  and the smoltcp IP stack, including the socket buffers on its stack. The fast path
  takes no locks. Interrupt handlers only call `net::schedule()`, which notifies the
  task.
- **Two planes.** The *control plane* (`/dev/<ifname>`: ioctls for MTU, link and
  offloads, plus raw frame writes) uses the normal driver middleware chain. The *data
  plane* (packets) uses a cheaper hook chain of `PacketHook`s that return a `Verdict`
  per packet. Hooks run global → per-interface → driver, which mirrors the middleware
  order.

See [networking](networking.md).

### Security checks at the API edge

Security domains carry handle tables. Isolated domains cannot use the raw `Device` API.
`DeviceCap` checks the handle's rights *before* any middleware runs and stamps the
request with an unforgeable `Caller`. *Sandboxed* tasks go further: they run unprivileged under the MPU and reach the kernel only
through the `SVC` system-call gate (`bismuth::user` → `security::syscall`). See
[security](security.md).

### One error type

`bismuth::Error` (`src/error.rs`) is the single error type. Each variant maps to a POSIX
`errno` (see [errors](../reference/errors.md)). This is what lets the compatibility
layers stay thin.

## The port interface

`src/arch/mod.rs` selects `arch::port`. It is `cortex_m` on `target_arch = "arm"` with
`target_os = "none"`, and `host` on any hosted target. Other bare-metal targets fail
with `compile_error!`. A port provides:

| function | purpose |
|----------|---------|
| `critical(f)` | run `f` with interrupts masked (nestable) |
| `request_switch()` | pend a context switch that fires when the critical section ends |
| `in_isr()` | whether the caller is in interrupt context |
| `init_task(k, i)` | build the initial execution context for task slot `i` |
| `exit_current(code)` | terminate the running task |
| `idle()` | idle-task body (sleep the CPU) |
| `syscall(n, args)` | system-call entry for `bismuth::user`: `svc #1` from unprivileged code on Cortex-M, a direct dispatch on the host |
| `start(...)` | start scheduling (`bismuth::start(core_hz)` on MCUs; `sim::run` on the host) |

## Boot sequence (MCU)

1. The board's `#[entry] fn main()` (from `cortex-m-rt`) runs in thread mode on MSP.
2. The board registers devices. It can call `driver::probe_all(&BOARD, FACTORIES)` and
   `driver::register(...)`, set the console (`console::set_device`), attach middleware,
   spawn tasks, start timers, and optionally create security domains (directly or
   through `security::manifest::apply`) and call `security::seal()`.
3. `bismuth::start(core_hz)` creates the idle task, sets PendSV and SysTick to the lowest
   priority, programs SysTick for `TICK_HZ`, points PSP at a scratch area, pends PendSV
   and enables interrupts. The first PendSV switches to the highest-priority ready task.
   `start` never returns.

Kernel calls made before `start` (the boot code) run as the kernel domain:
`security::current()` returns `DomainId::KERNEL` from interrupt context, and boot code
is treated the same way.

## How the host simulator works

`src/arch/host.rs` (the port) and `src/sim.rs` (the API) run a complete Bismuth system
inside a normal `cargo test` process. The kernel code is identical to the MCU build;
only the port changes.

### Threads and the baton

```text
 test thread                       task threads (one per Bismuth task)
 ───────────                       ───────────────────────────────────
 sim::run(cfg, setup)              each task thread parks in wait_for_baton(me)
   reset_all()                       until BATON.running == me
   setup()   ── spawns tasks ──►   init_task: spawn an OS thread "bismuth:<name>"
   host::start()                     (1 MiB host stack, independent of the Stack<N>)
     schedule() → BATON.running
     wait until shutdown ◄────────  finish(Outcome) on completion/deadlock/panic/...
   join all threads, reset_all()
```

- **Baton.** Every task runs on its own OS thread, but the `BATON` mutex/condvar lets
  exactly one task thread run at a time: the one whose index is in `BATON.running`. The
  kernel therefore behaves exactly as it would on a single-core MCU.
- **Interrupt masking.** `critical()` takes a global `LOCKED` flag (nestable through a
  thread-local depth counter). This plays the role of PRIMASK.
- **Context switches.** `request_switch()` sets `SWITCH_PENDING`. When the outermost
  critical section ends, `maybe_switch()` calls `Kernel::schedule()`. If another task
  was chosen, it hands over the baton and parks the current thread. This mirrors PendSV
  firing when interrupts are re-enabled.
- **Interrupt context.** Any thread that is not a task thread (the test thread, or a
  thread that simulates hardware) counts as an interrupt handler: `in_isr()` returns
  true, and it cannot block. Such a thread may request a switch; the running task
  performs it at its next kernel call. `sim::interrupt(|| ...)` makes a task thread act
  as an ISR for the duration of a closure.

### Virtual time

By default no wall clock is involved. The idle task runs only when nothing else can,
and then:

1. If any non-daemon task is ready, it asks for a switch.
2. If no live (non-daemon) tasks remain, the outcome is `Outcome::Completed`.
3. If `tick ≥ tick_limit`, the outcome is `Outcome::TickLimit`.
4. Otherwise it jumps the tick counter straight to the earliest pending timeout
   (`Kernel::advance_to(next_timeout)`). A 10-second sleep therefore costs nothing.
5. If no timeout is pending, every remaining task is blocked forever. The simulator
   prints each blocked task and its wait key to stderr and ends with `Outcome::Deadlock`.

`Config { realtime: true, .. }` instead sleeps one real tick per idle pass and calls
`Kernel::tick()`. Use it when non-task threads (simulated hardware) inject events
asynchronously.

### Outcomes, panics and exits

| `sim::Outcome` | when |
|----------------|------|
| `Completed` | every non-daemon task finished (daemons such as `idle`, `timers` and `net` do not count) |
| `Deadlock` | tasks remain, all blocked, no timeout pending |
| `TickLimit` | `Config::tick_limit` (default 1,000,000 ticks) reached |
| `Shutdown(code)` | a task called `sim::shutdown(code)` |
| `Panic(msg)` | a task panicked; `msg` contains the task index and panic message |

Task exits and shutdown use unwinding internally (`TaskExit`, `ShutdownSignal`
payloads), caught in each thread's `catch_unwind`. `sim::run` serialises runs through
a global lock. It also resets all kernel, security, timer, net, driver, console, POSIX,
FreeRTOS and `accel` state before and after each run, so every test behaves as if it had
a freshly booted device.

The [simulator testing guide](../guides/testing-with-the-simulator.md) shows how to
use all of this.
