# Testing with the simulator

`bismuth::sim` (host builds only, `src/sim.rs` + `src/arch/host.rs`) runs a complete
Bismuth system inside an ordinary `#[test]`. The kernel, drivers, network stack and
security code are exactly the code that runs on the MCU; only the port differs. How
the simulator works internally (baton, virtual time) is described in
[architecture](../design/architecture.md#how-the-host-simulator-works).

## The API

```rust
pub fn run(config: sim::Config, setup: impl FnOnce()) -> sim::Outcome;
pub fn run_to_completion(setup: impl FnOnce());     // panics unless Outcome::Completed

pub struct Config {
    pub tick_limit: Option<u64>,   // default Some(1_000_000)
    pub realtime: bool,            // default false (virtual time)
}

pub enum Outcome { Completed, Deadlock, TickLimit, Shutdown(i32), Panic(String) }

pub fn shutdown(code: i32) -> !;                    // end the run from inside a task
pub fn interrupt<R>(f: impl FnOnce() -> R) -> R;    // run f as if in an ISR
```

`run` performs these steps:

1. Takes a global lock, so runs never overlap.
2. Resets all kernel state.
3. Calls `setup`.
4. Starts the scheduler and blocks until the system ends.
5. Resets everything again.

## A typical test

```rust
use std::sync::Mutex as StdMutex;
use bismuth::sim::{self, Config, Outcome};
use bismuth::sync::Semaphore;
use bismuth::{Timeout, task, time};

static READY: Semaphore = Semaphore::binary();
static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

#[test]
fn consumer_waits_for_producer() {
    sim::run_to_completion(|| {
        task::Builder::new("consumer").priority(4).spawn(|_| {
            READY.take(Timeout::Forever).unwrap();
            LOG.lock().unwrap().push(format!("got it at t={}", time::ticks()));
        }, 0).unwrap();
        task::Builder::new("producer").priority(2).spawn(|_| {
            task::sleep_ms(250);
            READY.give().unwrap();
        }, 0).unwrap();
    });
    assert_eq!(*LOG.lock().unwrap(), ["got it at t=250"]);
}
```

### Rules of thumb

- **`setup` runs on the test thread, before the scheduler starts.** It counts as
  interrupt context in the kernel domain. Use it to register devices, attach
  middleware, create domains, configure the network and spawn tasks. Do not block in
  it; a blocking call returns `WouldBlock`.
- **Task entries are `fn(usize)`.** Non-capturing closures coerce to that type. Pass
  data through the `usize` argument (an index, an `IfIndex`, a `DomainId`) or through
  `static`s.
- **Record, then assert after the run.** Pushing observations into a
  `static StdMutex<Vec<_>>` and asserting after `run` returns gives clear failure
  messages. An `assert!` *inside* a task also works: the panic becomes
  `Outcome::Panic("task N panicked: ...")`, and `run_to_completion` turns that into a
  test failure.
- **Use separate statics per test.** `sim::run` resets kernel tables (tasks, the device
  registry, timers, net, security, the fd table, POSIX and FreeRTOS pools, `accel` engines). It cannot
  reset *your* statics: a `Pipe`'s buffered bytes, a `Stats` counter, a `SimSensor`'s
  forced value. The bundled suites declare `SENSOR2`, `SENSOR3` and so on for exactly
  this reason.
- **Serialise tests that share globals.** `sim::run` itself is serialised, but the
  assertions that run after it are not. The suites in `tests/` hold a per-file
  `SERIAL` mutex for the whole test.
- **Daemon tasks do not keep a run alive.** These are `idle`, the `timers` service and
  `net`, plus anything spawned with `.daemon(true)`. A run completes when every
  non-daemon task has finished, even if a periodic timer or the network stack is still
  active.

## Outcomes

| outcome | typical cause | how to test for it |
|---------|---------------|--------------------|
| `Completed` | every non-daemon task returned or exited | `run_to_completion` |
| `Deadlock` | all remaining tasks blocked forever; the simulator lists each task and its wait key on stderr | `assert_eq!(sim::run(Config::default(), ..), Outcome::Deadlock)` |
| `TickLimit` | a task loops forever (for example a periodic sampler) | `Config { tick_limit: Some(500), realtime: false }` |
| `Shutdown(code)` | a task called `sim::shutdown(code)` | end-to-end scenarios with long-running tasks |
| `Panic(msg)` | a task panicked; `msg` includes the task index and message | `match outcome { Outcome::Panic(m) => assert!(m.contains("boom")), .. }` |

## Virtual time vs. realtime

**Virtual time** is the default. Whenever every task is blocked, the clock jumps straight
to the next timeout. `sleep_ms(10_000)` returns instantly, and `time::ticks()` advances
by exactly 10,000 at 1 kHz. Results are exact and repeatable: the `kernel.rs` suite
asserts precise tick values, for example that `sleep_until` does not drift.

Use **realtime** (`Config { realtime: true, .. }`) only when an ordinary `std::thread`
injects events asynchronously, for example a thread that simulates a hardware interrupt
by calling `SEM.give()` or `net::schedule()`. In virtual time, the simulator could
declare a deadlock, or jump time ahead, before that thread acts. In realtime mode the
idle task sleeps one real tick per pass instead.

Any non-task thread counts as interrupt context. Kernel calls from it behave like ISR
calls: they cannot block, and they run as the kernel domain. Inside a task,
`sim::interrupt(|| ...)` runs a closure as if it were an ISR, which is useful for testing
ISR-only code paths.

## Simulated hardware

| component | use it for |
|-----------|-----------|
| `driver::char::Pipe<N>` | a blocking byte stream; a stand-in UART |
| `driver::sensor::SimSensor` | sensor pipelines; `force_counts(Some(c))` pins the raw ADC value |
| `driver::gpio::SimGpio` | GPIO and debouncing; `drive_inputs(levels)` sets inputs, `outputs()` reads outputs |
| `driver::i2c::SimI2c` + `driver::i2c::Tmp102` | I2C transactions with an emulated target (`set_temperature`); implement `I2cTarget` for your own |
| `net::drivers::Loopback<N>` | network core and hook tests on one interface |
| `net::drivers::Wire` + `WireEnd` (wrapped in `SoftRing`) | two full IP stacks on one cable; fault injection with `set_link(false)`, `drop_every(n)`, `corrupt_next(n)`; offload tests with `WireEnd::with_caps` |
| `security::entropy::SimTrng` | a deterministic, healthy TRNG for tests that need seeding |
| `security::entropy::FaultySource` | `StuckAt(v)` / `Biased` sources for health-test failures |
| an `Mmio` window over a `static [AtomicU32; N]` | register-level driver tests (see [writing a driver](writing-a-driver.md#step-6-test-it-in-the-simulator)) |

Two-host network setup, from `tests/net.rs`:

```rust
static WIRE: Wire = Wire::new();
static A: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 0, [2, 0, 0, 0, 0, 1]));
static B: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 1, [2, 0, 0, 0, 0, 2]));

sim::run_to_completion(|| {
    let ia = net::register("eth-a", &A).unwrap();
    let ib = net::register("eth-b", &B).unwrap();
    ip::configure(ia, IpConfig { addr: [10, 0, 0, 1], prefix_len: 24, gateway: None }).unwrap();
    ip::configure(ib, IpConfig { addr: [10, 0, 0, 2], prefix_len: 24, gateway: None }).unwrap();
    net::start().unwrap();
    // spawn server/client tasks using UdpSocket::bind_on(ib, ..), TcpStream::connect_on(ia, ..)
});
```

## Debugging

- `kprintln!` on the host writes directly to the process's stdout. The test harness
  does **not** capture it, so it shows up interleaved with test output. Redirect it
  with `console::set_sink(fn(&str))`, or route it to a device with
  `console::set_device`.
- Attach `driver::middleware::Trace` to a device to log every request and its result.
- `task::list` shows each task's state, priority (including inheritance boosts) and run
  ticks. A deadlock report names every blocked task and the key it waits on. That key
  is an object address (the address + 1 means a queue's "not full" side).
- To check that a scenario does not depend on the default configuration, run the suite
  with other limits: `BISMUTH_TIME_SLICE=1 cargo test`.

## Running the bundled suites

```sh
cargo test                      # everything
cargo test --test kernel        # one suite: kernel, drivers, net, posix, security, structure
cargo test --test net udp       # one test by name filter
```

Suite contents and counts are listed in [STATUS.md](../STATUS.md#test-suites).
