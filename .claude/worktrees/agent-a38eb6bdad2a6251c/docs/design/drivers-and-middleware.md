# Drivers and middleware

Source: `src/driver/mod.rs` (model and registry), `src/driver/middleware.rs` (trait and
library), `src/driver/ioctl.rs` (ioctl numbers and required rights), and one folder per
device class (`src/driver/{char,gpio,i2c,sensor,display,input}/`), each with the typed
wrapper in `mod.rs` and its bundled drivers beside it.

```text
  application ── POSIX fd ── embedded-hal ── FreeRTOS API      (compatibility layers)
          \            |            |            /
           ▼           ▼            ▼           ▼
        Device handle (/dev/<name>)   or   DeviceCap (isolated domains: rights gate)
                            │  Request { op, timeout, flags, caller }
            ┌───────────────▼───────────────┐
            │ global middleware (system)    │  e.g. trace, audit, policy
            │ device middleware (user)      │  e.g. stats, rate limit, filters
            │ driver middleware (built-in)  │  e.g. line discipline, calibration
            └───────────────┬───────────────┘
                            ▼
                   Driver::handle / Driver::power                (hardware)
```

## The model

### Requests

```rust
pub enum Op<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
    Transfer { addr: u16, tx: &'a [u8], rx: &'a mut [u8] }, // I2C address / SPI chip select
    Ioctl { cmd: u32, arg: usize },                          // result returned as Ok(value)
    Power(PowerState),                                       // routed to Driver::power
}

pub struct Request<'a> { pub op: Op<'a>, pub timeout: Timeout, pub flags: u32, caller: Option<Caller> }
pub type IoResult = Result<usize, Error>;   // bytes transferred, or the ioctl's value
```

- `Request::new(op)` starts with `Timeout::Forever` and no flags. Builder methods:
  `with_timeout`, `with_flags`.
- `FLAG_NONBLOCK` is POSIX `O_NONBLOCK`. `req.effective_timeout()` returns `NoWait`
  when it is set.
- `req.caller()` returns the issuing `security::Caller` (domain plus handle rights).
  Only the kernel can set it. Middleware can read it but cannot change or forge it, and
  a request with no caller reads as `Caller::KERNEL`.
- `req.derive(op)` makes a sub-request that keeps the timeout, flags **and caller**.
  Layers that split or rewrite requests should use it rather than `Request::new`, which
  would drop the caller.
- `Op::kind()` returns the `OpKind` (`Read`, `Write`, `Transfer`, `Ioctl` or `Power`),
  and `OpKind::bit()` returns its bitmask.

### The `Driver` trait

```rust
pub trait Driver: Sync {
    fn info(&self) -> DriverInfo;                                        // name, class, version, compatible[]
    fn middleware(&self) -> &'static [&'static dyn Middleware];           // REQUIRED
    fn init(&self, ctx: &DeviceCtx) -> Result<(), Error> { Ok(()) }       // once, at registration
    fn handle(&self, ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult; // after the chain
    fn power(&self, ctx: &DeviceCtx, s: PowerState) -> Result<(), Error>; // default: only On
}
```

Drivers are `Sync` singletons, typically `static`s. Mutable hardware state lives behind
`IrqCell`, `Mutex` or atomics. `DeviceCtx { device, name, class }` is passed to every
call.

**Every driver must provide middleware.** Logic that turns raw hardware behaviour into a
clean device abstraction belongs in middleware, not buried in `handle`. Examples are
CR/LF translation, ADC-count calibration, debouncing and address validation. That way
it can be listed (`Device::chain`), reused by other drivers, and reasoned about as a
pipeline. Use a `static` slice; a driver whose hardware needs no adaptation can return
`&[]`, but should say why.

### The `Middleware` trait

```rust
pub trait Middleware: Sync {
    fn name(&self) -> &'static str;                                  // unique per chain; used by detach
    fn call(&self, ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult;
    fn on_attach(&'static self, _ctx: &DeviceCtx) {}                 // when attached to a device
}
```

A layer may inspect or rewrite `req`, short-circuit with an error, call `next.run(req)`
zero or more times (to retry, split or probe), and post-process the result. `Next` is
`Copy`.

## Chain order

`Device::request` builds `Next { stages: [global, device user layers, driver layers] }`
and runs:

```text
request ─► G1 ─► G2 ─► U1 ─► U2 ─► D1 ─► Driver::handle   (or Driver::power for Op::Power)
result  ◄─ G1 ◄─ G2 ◄─ U1 ◄─ U2 ◄─ D1 ◄─┘
```

- **Global layers** (`driver::add_global_middleware`) apply to every device and run
  first. Only trusted domains may add them. `remove_global_middleware(name)` is refused
  for untrusted domains and after `security::seal()`.
- **User layers** (`Device::attach`) run in attachment order. `Device::detach(name)`
  removes one. Both require a trusted domain; isolated domains use
  `DeviceCap::attach`/`detach`, which needs the `MANAGE` right. Up to
  `config::MAX_LAYERS` (default 6) user layers per device, and as many global layers.
- **Driver layers** (`Driver::middleware()`) run last, innermost first in the slice.
- After the chain, `Op::Power(state)` goes to `Driver::power`. If it succeeds, the
  registry records the new `PowerState`.
- `Device::chain(&mut names)` lists the full chain, outermost first.

Post-processing runs in reverse. A layer attached *earlier* therefore sees the result
*after* every later layer has transformed it. For example, with `attach(&DEADBAND)` and
then `attach(&AVG)`, the deadband judges the *averaged* value
(`tests/drivers.rs::sensor_driver_middleware_calibrates_and_user_layers_filter`).

With security domains, the rights check happens in `DeviceCap::request` **before** the
chain runs (see [security](security.md#devicecap-flow)).

## Built-in middleware catalogue (`bismuth::driver::middleware`)

| layer | constructor | name | behaviour |
|-------|-------------|------|-----------|
| `Stats` | `Stats::new()` / `Stats::named(n)` | `stats` / `n` | Counts reads, writes, transfers, ioctls (power ops count as ioctls), errors, bytes in/out (`u32`), and max latency in ticks. `snapshot()` returns a `StatsSnapshot`. |
| `Trace` | `Trace::new()` | `trace` | After each request, logs `[trace t=<tick>] <dev>: <op> -> <result>` through `kprintln!`. A re-entrant call (tracing the console device itself) is passed through untraced. |
| `Exclusive` | `Exclusive::new()` | `exclusive` | Serialises all requests through a recursive priority-inheritance `RawMutex`. Waits up to the request's effective timeout. |
| `RateLimit` | `RateLimit::new(max_ops, window_ticks, LimitMode::Reject \| Delay)` | `rate-limit` | Fixed window aligned to multiples of `window_ticks`. `Reject` returns `WouldBlock`. `Delay` sleeps until the next window, or returns `WouldBlock` for non-blocking requests. |
| `Retry` | `Retry::new(attempts, backoff_ticks)` | `retry` | Retries `Io`, `Timeout`, `NotReady` and `Busy`, up to `attempts` tries in total, with exponential back-off `backoff << (n-1)`. `retries()` returns the total retries. |
| `PowerGate` | `PowerGate::new(idle_ticks)` | `power-gate` | On attach, records the device and arms a software timer. A request to an unpowered device first sends `Power(On)` down the chain (counted in `wakeups()`). After `idle_ticks` without use, the timer task calls `set_power(Suspended)`. `is_powered()`. |
| `AccessPolicy` | `AccessPolicy::allow(&[OpKind..])` / `read_only()` | `access-policy` | Returns `PermissionDenied` for operation kinds outside the mask. `read_only()` allows `Read`, `Ioctl` and `Power`. It does not look at the caller. |
| `NonBlocking` | `NonBlocking` | `nonblocking` | Rewrites `req.timeout` to the effective timeout, so drivers only need to look at `timeout`. |
| `MovingAverage<W>` | `MovingAverage::<W>::new()` | `moving-average` | On reads, replaces each sample (little-endian `i32` per channel, channels 0–3) with the average of its last `W` values. |
| `Calibrate` | `Calibrate::new(num, den, offset)` / `named(..)` | `calibrate` / name | On reads: `out = in * num / den + offset`, computed in `i64`. `den` must be non-zero, which is checked at compile time in `const` use. |
| `Deadband` | `Deadband::new(delta)` | `deadband` | Report by exception: a read returns `Ok(0)` unless some channel (0–3) moved by more than `delta` since the last *reported* reading. The first reading is always reported. `suppressed()`. |

Driver-provided layers bundled with the crate:

| layer | file | name | behaviour |
|-------|------|------|-----------|
| `char::LineDiscipline` | `char/pl011.rs` | `line-discipline` | Writes: `\n` → `\r\n`, by splitting the write with `req.derive`. Reads: `\r` → `\n`. |
| `gpio::Debounce` | `gpio/sim.rs` | `debounce` | `GPIO_GET` reports an input pin's level only after it has been stable for N ticks (5 in `SimGpio`). It tracks pin directions from the `GPIO_CONFIG_*` ioctls. |
| `i2c::AddressCheck` | `i2c/sim.rs` | `i2c-address-check` | Rejects reserved 7-bit addresses (0x00–0x07 and 0x78–0x7F) and empty transfers with `Invalid`. |
| sim-sensor calibration | `sensor/sim.rs` | `adc-to-centi-celsius` | `Calibrate(16500, 4095, -4000)`: 12-bit ADC counts → centi-°C (−40.00 to +125.00 °C). |
| `net::LinkGuard` | `net/mod.rs` | `link-guard` | Refuses raw frame writes to `/dev/<ifname>` while the interface is down or has no link (`NotReady`). |

## Registry and device handles

| function | notes |
|----------|-------|
| `driver::register(name, &'static dyn Driver) -> Device` | Trusted callers only (otherwise `PermissionDenied`). `Exists` if the name is taken, `NoResources` past `MAX_DEVICES` (default 16). Calls `on_attach` on the driver's layers, then `init`. If `init` fails the device is removed. |
| `driver::unregister(dev)` | trusted only; invalidates the handle |
| `Device::find("uart0" \| "/dev/uart0")` | looks a device up by name |
| `Device::{read, read_timeout, write, write_all, transfer, ioctl, set_power, power}` | convenience wrappers over `request` |
| `Device::request(&mut Request)` | the raw API. **Trusted domains only.** Isolated domains get `PermissionDenied` and must use `security::DeviceCap`. |
| `Device::info()` / `driver::list(&mut [Option<DeviceInfo>])` | name, `DriverInfo`, power state, layer counts |
| `security::revoke_device(dev)` | gives the slot a new generation. Every outstanding `Device` and handle then fails with `BadHandle`. |

A `Device` is an index plus an 8-bit generation, so a stale handle is detected rather
than reaching the wrong device.

## Board description and probing

Boards describe hardware statically, similar to a device tree, and bind drivers by
compatible string:

```rust
pub struct DeviceDesc {
    pub name: &'static str,                       // exposed as /dev/<name>
    pub compatible: &'static str,                 // matched against DriverInfo::compatible
    pub mmio: Option<Mmio>,                       // register window, if memory-mapped
    pub irq: u16,                                 // u16::MAX if none
    pub params: &'static [(&'static str, u32)],   // ("baud", 115200), ("channels", 2), ...
}
pub struct DriverFactory {
    pub compatible: &'static [&'static str],
    pub create: fn(&'static DeviceDesc) -> Result<&'static dyn Driver, Error>,
}
```

`driver::probe_all(&BOARD, factories)` binds each description to the first factory whose
`compatible` list contains it, calls `create`, and registers the result. It returns the
number of devices registered. Descriptions without a matching factory, and probes that
fail, are skipped silently. `desc.param("baud")` reads a parameter.

`Mmio` (`src/arch/mmio.rs`) is the only way drivers touch registers. Creating one is the
board's single `unsafe` act: `unsafe { Mmio::new(base, len) }` asserts that the range is
that peripheral, valid for volatile 32-bit access, and not aliased. `new` panics if
`base` is not 4-byte aligned. After that, `read32`, `write32` and `modify32` are safe,
and each panics on an out-of-range or misaligned offset.

`driver::FACTORIES` contains factories for `arm,pl011`, `bismuth,sim-sensor`,
`bismuth,pipe`, `bismuth,sim-gpio` and `bismuth,sim-i2c`. The I2C one is also public as
`driver::i2c::sim::FACTORY`. Factories hand out instances from small static arrays and
return `NoResources` when the array is exhausted:

| factory | instances |
|---------|-----------|
| PL011 | 4 |
| sim-sensor | 4 |
| pipe | 4, of 256 bytes each |
| sim-gpio | 1 |
| sim-i2c | 2 |

Targets for a factory-created `SimI2c` cannot be attached through the trait object, so
tests that need emulated targets still register a `static SimI2c` directly.

## Device classes (typed wrappers per class folder)

`DeviceClass`: `Char`, `Gpio`, `I2c`, `Spi`, `Sensor`, `Block`, `Net`, `Display`,
`Input`, `Other`. `Display` and `Input` have their own typed wrappers in
`driver::display` and `driver::input`; see
[human interface](human-interface.md). The raw
`Device` API is uniform; class wrappers add a typed API on top of the same pipeline.
`open` fails with `Unsupported` if the device's class does not match.

| wrapper | methods |
|---------|---------|
| `driver::char::Serial(Device)` | `open`, `read(buf, timeout)`, `write` (writes all), `set_baud`, `available` |
| `driver::gpio::Gpio(Device)` | `open`, `configure_output/input(mask)`, `set/clear/toggle(mask)`, `get`, `is_high(pin)` |
| `driver::i2c::I2cBus(Device)` | `open`, `write(addr, bytes)`, `read(addr, buf)`, `write_read(addr, tx, rx)` |
| `driver::sensor::Sensor(Device)` | `open`, `channels`, `read(&mut [i32])` (up to 8 channels; returns channels filled, `0` = suppressed), `set_rate_hz` |

`Spi` and `Block` exist as classes, but there is no class wrapper or bundled driver for
them yet (**Planned**). The ioctl numbers and the right each requires are listed in
[ioctl reference](../reference/ioctl.md).

## Bundled drivers (in their class folders)

`driver/` is organised **by device class**. Each folder holds the class's typed wrapper
in `mod.rs`, plus the bundled drivers for that class; simulated ones are in `sim.rs`.
Every driver is also re-exported from its class module (for example
`driver::char::Pipe`, `driver::gpio::SimGpio`).

```text
driver/
  mod.rs        Driver, Op/Request, Device, registry, probe_all, DeviceClass, DriverFactory, FACTORIES
  ioctl.rs      ioctl numbers + required_right
  middleware.rs generic middleware library
  char/         Serial · pipe.rs (Pipe) · pl011.rs (Pl011, LineDiscipline) · pty.rs · tty.rs (Tty, Termios, …)
  gpio/         Gpio · sim.rs (SimGpio, Debounce)
  i2c/          I2cBus · sim.rs (SimI2c, AddressCheck, Tmp102, I2cTarget)
  sensor/       Sensor · sim.rs (SimSensor)
  display/      Display, PixelFormat, Rect, … · sim.rs (SimDisplay)
  input/        Input, InputEvent, EventKind, code · sim.rs (SimInput)
```

Network drivers (`net::drivers`: `Loopback`, `Wire`) are **not** here. They implement
the `NetDevice`/`FrameDevice` contract rather than `Driver`, so they live with the
network subsystem that defines that contract.

| driver | path | class | compatible | built-in middleware | notes |
|--------|------|-------|------------|---------------------|-------|
| `Pipe<N>` | `char::Pipe` | Char | `bismuth,pipe` | `NonBlocking` | in-memory byte pipe; reads block for data, writes block for space (partial writes allowed); `SERIAL_RX_AVAILABLE`, `SERIAL_FLUSH` |
| `Pl011` | `char::Pl011` | Char | `arm,pl011` | `LineDiscipline` | polled PL011 UART over `Mmio`; TX spins on FIFO-full; RX polls and sleeps 1 tick between polls; `SERIAL_SET_BAUD` only records the value (no divisor programming) |
| `SimSensor` | `sensor::SimSensor` | Sensor | `bismuth,sim-sensor` | ADC → centi-°C `Calibrate` | deterministic triangle wave plus noise; `force_counts` for tests; power-off makes reads fail with `NotReady` |
| `SimGpio` | `gpio::SimGpio` | Gpio | `bismuth,sim-gpio` | `Debounce(5)` | 32-pin port; `drive_inputs`, `outputs` for tests |
| `PtyMaster`/`PtySlave` | `char::{Pty, PtyMaster, PtySlave}` | Char | `bismuth,pty` | `NonBlocking` | pseudo-terminal pair over two pipes; see [tty](tty.md) |
| `SimDisplay<W,H,P>` | `display::SimDisplay` | Display | `bismuth,sim-display` | *(none)* | RGB565 RAM framebuffer; `pixel()` readback |
| `SimInput<N>` | `input::SimInput` | Input | `bismuth,sim-input` | *(none)* | event queue; `inject`, `tap`, `overruns` |
| `SimI2c` | `i2c::SimI2c` | I2c | `bismuth,sim-i2c` | `AddressCheck` | up to 8 emulated `I2cTarget`s; `Tmp102` sample target; NACK = `Io` |

The `embedded-hal`/`embedded-io` bridges in `compat::hal` (`HalSerialDriver`,
`HalI2cDriver`, `HalOutputPinDriver`) are also `Driver`s. They turn vendor HAL
peripherals into Bismuth devices.

## Writing a driver

The [writing a driver](../guides/writing-a-driver.md) guide builds a complete,
test-verified memory-mapped GPIO driver. It has its own active-low middleware, a probe
factory and a board entry. In outline:

1. Define the driver struct; hold `Mmio` behind an `IrqCell` if a factory binds it late.
2. Write at least one driver middleware and expose it as a `static` slice.
3. Implement `Driver` (`info`, `middleware`, `handle`, and optionally `init` and `power`).
   Answer `GET_CLASS`, and return `Unsupported` for anything you do not handle.
4. Honour `req.timeout` (or add `NonBlocking` and only read `timeout`). Block through
   kernel primitives, never by spinning.
5. Provide a `DriverFactory` so boards can bind it with `probe_all`.
6. Test it in the simulator.
