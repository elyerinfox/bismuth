# Getting started

## Prerequisites

- A stable Rust toolchain that supports edition 2024 and stable naked functions
  (Rust 1.88 or newer). The project is developed with rustc 1.99.
- For MCUs: `rustup target add thumbv7m-none-eabi thumbv7em-none-eabihf`.
- For the QEMU demo: `qemu-system-arm` on `PATH`.

## 1. Run the test suites (host simulator)

```sh
cargo test
```

Every integration test boots a complete Bismuth system inside the
[deterministic simulator](testing-with-the-simulator.md) and runs it in virtual time,
so the whole suite finishes in well under a second once it is compiled. Current counts
are in [STATUS.md](../STATUS.md#test-suites).

Build-time configuration works for tests too:

```sh
BISMUTH_MAX_TASKS=24 BISMUTH_TICK_HZ=100 cargo test
```

## 2. Cross-compile the kernel

```sh
cargo build --target thumbv7m-none-eabi       # Cortex-M3
cargo build --target thumbv7em-none-eabihf    # Cortex-M4F / M7, with lazy FPU context switching
```

Both builds use the default features, networking and crypto included. For small parts,
choose features explicitly, for example:

```toml
bismuth-kernel = { path = "...", default-features = false, features = ["edge"] }
```

## 3. Run the QEMU demo

```sh
cd boards/qemu-lm3s6965
cargo run          # builds for thumbv7m-none-eabi and runs qemu-system-arm (see .cargo/config.toml)
```

Output captured on 2026-10-10 from the current tree:

```text
Bismuth 0.1.0 on lm3s6965evb (Cortex-M3)
  t=  62 temp0 = 20.35 C
[sandbox] running unprivileged
[sandbox] sensor read ok; unauthorized write denied by the kernel
  t= 123 temp0 = 20.54 C
  t= 193 temp0 = 20.75 C
  t= 263 temp0 = 20.96 C
  t= 313 temp0 = 21.13 C
  t= 363 temp0 = 21.32 C
  t= 413 temp0 = 21.51 C
pipeline: 7 reported readings
sandbox: exit=Ok(0) killed=false mpu faults=0
priority inversion: high got lock at t=21, medium finished at t=62, low ran at prio 6
sensor stats: 40 reads, 28 bytes, 33 suppressed by deadband
heartbeat timer fired 8 times
task       prio      state  stack   free
idle          0      Ready    512    420
sampler       4       Dead   2048    784
reporter      3       Dead   2048    964
low           2       Dead   1536   1368
medium        5       Dead   1536   1388
high          6       Dead   1536   1316
super         1      Ready   3072   1380
timers       31    Blocked   1024    604
BISMUTH QEMU DEMO: PASS
```

Here is what the demo (`boards/qemu-lm3s6965/src/main.rs`) exercises on the real ARMv7-M
port:

- **Driver binding.** `probe_all(&BOARD, FACTORIES)` binds the PL011 UART at
  `0x4000_C000` and makes it the console. Every `kprintln!` therefore flows through the
  UART's `LineDiscipline` middleware.
- **A sensor pipeline.** `temp0` is a `SimSensor` whose driver middleware converts ADC
  counts to centi-°C. The user layers `Stats`, then `Deadband(15)`, then
  `MovingAverage<4>` are attached on top. A `sampler` task reads it every 10 ticks
  using `sleep_until`, so the period does not drift, and sends readings over a `Queue`
  to a `reporter`. The deadband suppressed 33 of 40 readings. `Stats` is the outermost
  layer, so it counted only the 7 × 4 bytes that were reported.
- **Priority inheritance.** `low` (priority 2) holds a mutex. `high` (6) then blocks on
  it while a CPU-bound `medium` (5) runs. Thanks to inheritance, `high` got the lock at
  t=21, long before `medium` finished at t=62, and `low` ran at priority 6.
- **A sandboxed task.** A task in a `DomainSpec::sandboxed` domain, on a
  `UserStack2K`, runs unprivileged under the MPU. It opens and reads its granted sensor
  through `bismuth::user` syscalls, and the kernel denies its write, because the handle
  carries only `READ`. It exits with code 0, and its domain is not killed.
- **A software timer.** The `HEARTBEAT` timer is periodic and runs in the `timers`
  service task (priority 31).
- **A `task::list` dump.** The `free` column is the painted stack that was never
  touched.

The demo exits QEMU through semihosting, with a success or failure exit code.

## 4. A first application

A board crate provides the entry point and calls `bismuth::start`:

```rust
#![no_std]
#![no_main]

use bismuth::prelude::*;
use bismuth::sync::Queue;
use bismuth::{Timeout, time};
use cortex_m_rt::entry;

static PRODUCER_STACK: Stack<1024> = Stack::new();
static CONSUMER_STACK: Stack<1024> = Stack::new();
static READINGS: Queue<u32, 8> = Queue::new();

fn producer(_: usize) {
    let mut last = time::ticks();
    for n in 0.. {
        task::sleep_until(&mut last, 100);              // every 100 ticks, no drift
        let _ = READINGS.send(n, Timeout::Forever);
    }
}

fn consumer(_: usize) {
    loop {
        if let Ok(n) = READINGS.recv(Timeout::ms(500)) {
            kprintln!("reading {}", n);
        }
    }
}

#[entry]
fn main() -> ! {
    task::spawn("producer", 3, &PRODUCER_STACK, producer, 0).unwrap();
    task::spawn("consumer", 2, &CONSUMER_STACK, consumer, 0).unwrap();
    bismuth::start(12_000_000)   // SysTick input clock in Hz; never returns
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop {} }
```

The board also needs a `memory.x`, a `build.rs` that puts it on the linker search path,
`-C link-arg=-Tlink.x`, and a console device if you want `kprintln!` output. On bare
metal the default console sink discards output. See
[porting a board](porting-a-board.md).

## 5. A first simulator test

The same code runs on the host. In `tests/my_app.rs`:

```rust
use bismuth::sim;
use bismuth::sync::Queue;
use bismuth::{Timeout, task, time};

static Q: Queue<u32, 4> = Queue::new();

#[test]
fn producer_consumer() {
    sim::run_to_completion(|| {
        task::Builder::new("producer").priority(3).spawn(|_| {
            for n in 0..10 {
                task::sleep_ticks(100);
                Q.send(n, Timeout::Forever).unwrap();
            }
        }, 0).unwrap();
        task::Builder::new("consumer").priority(2).spawn(|_| {
            for n in 0..10 {
                assert_eq!(Q.recv(Timeout::Forever), Ok(n));
            }
            assert_eq!(time::ticks(), 1000);   // virtual time: exact and instant
        }, 0).unwrap();
    });
}
```

Next steps:

- [Writing a driver](writing-a-driver.md)
- [Testing with the simulator](testing-with-the-simulator.md)
- [POSIX](posix.md) and [FreeRTOS](freertos-porting.md) for porting existing code
- [Architecture](../design/architecture.md) for how it all fits together
