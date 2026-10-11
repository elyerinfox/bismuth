# Writing a driver

This guide builds `LedPort`, a memory-mapped GPIO driver for an LED bank wired
active-low. It covers the built-in middleware every driver must have, a probe factory,
board binding and a simulator test. The code below is the exact code of a test that was
compiled and run against the current kernel. For the concepts behind it, read
[drivers and middleware](../design/drivers-and-middleware.md).

The hardware is two 32-bit registers: `ODR` (output data) at `0x00` and `DIR`
(1 = output) at `0x04`. The LEDs light when their pin is driven **low**.

## Step 1: imports and registers

```rust
use bismuth::Error;
use bismuth::arch::mmio::Mmio;
use bismuth::driver::gpio::Gpio;
use bismuth::driver::ioctl;
use bismuth::driver::middleware::Middleware;
use bismuth::driver::{
    self, DeviceClass, DeviceCtx, DeviceDesc, Driver, DriverFactory, DriverInfo, IoResult, Next, Op, Request,
};
use bismuth::sync::IrqCell;

const ODR: usize = 0x00; // output data register
const DIR: usize = 0x04; // direction register, 1 = output
```

## Step 2: the driver's own middleware

Every driver must contribute middleware: the logic that adapts raw hardware into a
clean device. Here that logic is the active-low inversion. Keeping it out of `handle`
means `Device::chain` shows it, and other active-low drivers can reuse it.

```rust
/// Built-in middleware: the LEDs on this board are wired active-low, so a logical
/// "set" must drive the pin low. Users of the device never see the inversion.
pub struct ActiveLow;

impl Middleware for ActiveLow {
    fn name(&self) -> &'static str {
        "active-low"
    }

    fn call(&self, _ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        let mut get = false;
        if let Op::Ioctl { cmd, .. } = &mut req.op {
            *cmd = match *cmd {
                ioctl::GPIO_SET => ioctl::GPIO_CLEAR,
                ioctl::GPIO_CLEAR => ioctl::GPIO_SET,
                c => c,
            };
            get = *cmd == ioctl::GPIO_GET;
        }
        let r = next.run(req)?;
        Ok(if get { !(r as u32) as usize } else { r })
    }
}

static ACTIVE_LOW: ActiveLow = ActiveLow;
static MIDDLEWARE: [&dyn Middleware; 1] = [&ACTIVE_LOW];
```

Points to note:

- Middleware rewrites `req.op` in place and post-processes the result on the way back.
- Rights are checked *before* the chain runs, against the original command. For
  isolated domains, `GPIO_SET` and `GPIO_CLEAR` both need `CONTROL`, so the rewrite does
  not change what a caller is allowed to do.
- To split a request into several, call `next.run(&mut req.derive(op))` (see
  `pl011::LineDiscipline`). `derive` keeps the caller, timeout and flags.

## Step 3: the driver

```rust
/// A memory-mapped LED port.
pub struct LedPort {
    regs: IrqCell<Option<Mmio>>,
}

impl LedPort {
    pub const fn new(regs: Mmio) -> Self {
        LedPort { regs: IrqCell::new(Some(regs)) }
    }

    const fn unbound() -> Self {
        LedPort { regs: IrqCell::new(None) }
    }

    fn regs(&self) -> Result<Mmio, Error> {
        self.regs.lock(|r| *r).ok_or(Error::NotReady)
    }
}

impl Driver for LedPort {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "led-port", class: DeviceClass::Gpio, version: (0, 1, 0), compatible: &["acme,led-port"] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &MIDDLEWARE
    }

    fn init(&self, _ctx: &DeviceCtx) -> Result<(), Error> {
        self.regs()?.write32(ODR, u32::MAX); // active-low: all LEDs off
        Ok(())
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let Op::Ioctl { cmd, arg } = req.op else { return Err(Error::Unsupported) };
        let m = self.regs()?;
        let mask = arg as u32;
        match cmd {
            ioctl::GPIO_SET => m.modify32(ODR, |v| v | mask),
            ioctl::GPIO_CLEAR => m.modify32(ODR, |v| v & !mask),
            ioctl::GPIO_TOGGLE => m.modify32(ODR, |v| v ^ mask),
            ioctl::GPIO_CONFIG_OUTPUT => m.modify32(DIR, |v| v | mask),
            ioctl::GPIO_CONFIG_INPUT => m.modify32(DIR, |v| v & !mask),
            ioctl::GPIO_GET => return Ok(m.read32(ODR) as usize),
            ioctl::GET_CLASS => return Ok(DeviceClass::Gpio as usize),
            _ => return Err(Error::Unsupported),
        }
        Ok(0)
    }
}
```

Guidelines:

- **`Sync` singletons.** Drivers are `static`s, so keep mutable state behind `IrqCell`
  (short critical sections), `sync::Mutex` (longer sections, priority inheritance) or
  atomics.
- **Answer `GET_CLASS`**, and return `Unsupported` for anything else you do not handle.
  POSIX `ioctl` turns `Unsupported` into `ENOTTY`.
- **Honour timeouts.** Read `req.timeout`, and either honour `FLAG_NONBLOCK` with
  `req.effective_timeout()` or add the `NonBlocking` middleware. Wait with the public
  `sync` primitives (for example a `Semaphore` that the ISR gives, taken with
  `req.timeout`), or poll with `task::sleep_ticks`; never busy-spin. The
  crate-internal `kernel::block_on` that `Pipe` uses is not public, so out-of-tree
  drivers build on `sync` types.
- **Power.** Override `power()` if the device supports `Idle`, `Suspended` or `Off`.
  The default accepts only `On`. Users can then add `PowerGate` for automatic
  idle-suspend.
- **Interrupts.** Do the minimum in the ISR (acknowledge, mask, then `give` or
  `notify`). Do the rest in the request path or in a driver task.

## Step 4: a probe factory

Boards bind drivers by compatible string. A factory hands out instances from a small
static array and binds the `Mmio` from the `DeviceDesc`:

```rust
static PORTS: [LedPort; 2] = [const { LedPort::unbound() }; 2];

fn create(desc: &'static DeviceDesc) -> Result<&'static dyn Driver, Error> {
    let mmio = desc.mmio.ok_or(Error::Invalid)?;
    PORTS
        .iter()
        .find(|p| p.regs.lock(|r| r.is_none() && r.replace(mmio).is_none()))
        .map(|p| p as &dyn Driver)
        .ok_or(Error::NoResources)
}

pub const LED_FACTORY: DriverFactory = DriverFactory { compatible: &["acme,led-port"], create };
```

Read board parameters with `desc.param("key")`. For example, `char::pl011::create` reads
`"baud"` and `sensor::sim::create` reads `"channels"`.

## Step 5: bind it on a board

```rust
#[allow(unsafe_code)]
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "led0",
    compatible: "acme,led-port",
    // SAFETY: the LED port's two registers live at 0x4002_0000 and are used only via this window.
    mmio: Some(unsafe { Mmio::new(0x4002_0000, 8) }),
    irq: u16::MAX,
    params: &[],
}];

// in main():
driver::probe_all(&BOARD, &[LED_FACTORY]);
let led = Gpio::open("/dev/led0").unwrap();
led.configure_output(0b1).unwrap();
led.set(0b1).unwrap();     // LED 0 on: the pin is driven low by the middleware's inversion
```

Without a board description, you can also register an instance directly:
`driver::register("led0", &MY_STATIC_LED_PORT)`.

## Step 6: test it in the simulator

On the host, point the `Mmio` window at a static array that stands in for the
registers. This is a test-only `unsafe`; the kernel crate itself never needs one.

```rust
use core::sync::atomic::{AtomicU32, Ordering};
use bismuth::driver::middleware::Stats;
use bismuth::sim;

static REGS: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static STATS: Stats = Stats::new();

#[test]
#[allow(unsafe_code)]
fn led_port_example_works() {
    let base = REGS.as_ptr() as usize;
    // SAFETY: REGS is a static block of two 32-bit words used only through this window.
    let mmio = unsafe { Mmio::new(base, 8) };
    let board: &'static [DeviceDesc] =
        Box::leak(Box::new([DeviceDesc { name: "led0", compatible: "acme,led-port", mmio: Some(mmio), irq: u16::MAX, params: &[] }]));
    sim::run_to_completion(|| {
        assert_eq!(driver::probe_all(board, &[LED_FACTORY]), 1);
        let led = Gpio::open("/dev/led0").unwrap();
        led.0.attach(&STATS).unwrap();
        assert_eq!(REGS[0].load(Ordering::Relaxed), u32::MAX);
        led.configure_output(0b1).unwrap();
        led.set(0b1).unwrap();
        assert_eq!(REGS[0].load(Ordering::Relaxed) & 1, 0, "active-low: set drives the pin low");
        assert!(led.is_high(0).unwrap());
        led.clear(0b1).unwrap();
        assert!(!led.is_high(0).unwrap());
        let mut names = [""; 4];
        let n = led.0.chain(&mut names).unwrap();
        assert_eq!(&names[..n], ["stats", "active-low"]);
        assert_eq!(STATS.snapshot().ioctls, 5);
    });
}
```

The setup closure of `sim::run_to_completion` runs as the kernel domain before the
scheduler starts. That is why it can call the device API directly. Blocking calls
belong inside tasks. See [testing with the simulator](testing-with-the-simulator.md).

## Checklist

- [ ] `info()`: unique `name`, the right `DeviceClass`, and `compatible` strings in
      `vendor,device` form.
- [ ] `middleware()` returns a `static` slice containing at least one layer that
      expresses the hardware-specific adaptation.
- [ ] `handle` answers `GET_CLASS`, returns `Unsupported` for the rest, honours
      timeouts and never spins indefinitely.
- [ ] All register access goes through `Mmio`, and the driver contains no `unsafe`.
- [ ] There is a `DriverFactory` so boards can bind it with `probe_all`.
- [ ] There is a simulator test, plus a test under `AccessPolicy` or a `DeviceCap` if
      the driver will be shared with isolated domains.
- [ ] The ioctls you use are listed in the [ioctl reference](../reference/ioctl.md).
      New ioctl numbers belong in `driver::ioctl`, with their required right in
      `required_right`.
