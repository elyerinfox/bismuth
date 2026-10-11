//! The driver framework.
//!
//! ```text
//!   application ── POSIX fd ── embedded-hal ── FreeRTOS API      (compatibility layers)
//!          \            |            |            /
//!           ▼           ▼            ▼           ▼
//!                    Device handle (/dev/<name>)
//!                            │  Request { op, timeout, flags }
//!            ┌───────────────▼───────────────┐
//!            │ global middleware (system)    │  e.g. tracing, access policy
//!            │ device middleware (user)      │  e.g. stats, rate limit, filter
//!            │ driver middleware (built-in)  │  e.g. line discipline, calibration
//!            └───────────────┬───────────────┘
//!                            ▼
//!                   Driver::handle / Driver::power                (hardware)
//! ```
//!
//! Every driver *must* provide its own middleware ([`Driver::middleware`]): the logic
//! that sits between raw hardware access and a clean device abstraction (line
//! discipline for UARTs, calibration for sensors, debouncing for GPIO, ...). Keeping it
//! as middleware instead of burying it in `handle` means it can be inspected, reused by
//! other drivers, and reasoned about as a pipeline.
//!
//! Devices can be registered directly ([`register`]) or bound from a static board
//! description by *compatible* string ([`probe_all`]), Linux device-tree style.
//!
//! Classification: L2 devices · driver model and registry · safe · always

pub mod block;
pub mod char;
pub mod display;
pub mod gpio;
pub mod i2c;
pub mod input;
pub mod ioctl;
pub mod middleware;
pub mod sensor;
pub mod spi;

use core::fmt;

use crate::Error;
use crate::config::{MAX_DEVICES, MAX_LAYERS};
use crate::kernel::cell::IrqCell;
use crate::kernel::time::Timeout;

pub use middleware::Middleware;

/// Confirm a device belongs to `class`, for the typed class wrappers.
pub(crate) fn expect(dev: Device, class: DeviceClass) -> Result<Device, Error> {
    if dev.class()? == class { Ok(dev) } else { Err(Error::Unsupported) }
}

/// Factories for the bundled drivers, for [`probe_all`].
pub const FACTORIES: &[DriverFactory] = &[
    DriverFactory { compatible: &["arm,pl011"], create: char::pl011::create },
    DriverFactory { compatible: &["ns16550", "ns16550a", "snps,dw-apb-uart"], create: char::ns16550::create },
    DriverFactory { compatible: &["bismuth,pipe"], create: char::pipe::create },
    DriverFactory { compatible: &["bismuth,sim-sensor"], create: sensor::sim::create },
    DriverFactory { compatible: &["bismuth,sim-gpio"], create: gpio::sim::create },
    i2c::sim::FACTORY,
];

/// Result of an I/O request: bytes transferred (or an ioctl's return value).
pub type IoResult = Result<usize, Error>;

/// Broad device category; determines which class API and compatibility adapters apply.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DeviceClass {
    /// Byte stream (UART, USB CDC, pipe).
    Char,
    /// Digital I/O port of up to 32 pins.
    Gpio,
    /// I2C bus controller.
    I2c,
    /// SPI bus controller.
    Spi,
    /// Sampled sensor producing `i32` readings per channel.
    Sensor,
    /// Block storage.
    Block,
    /// Network interface.
    Net,
    /// Display / framebuffer panel.
    Display,
    /// Input device (keyboard, mouse, touch, buttons).
    Input,
    Other,
}

/// Device power states.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PowerState {
    On,
    /// Clock-gated, resumes instantly.
    Idle,
    /// Low-power state; context retained.
    Suspended,
    Off,
}

impl PowerState {
    pub fn from_raw(v: usize) -> Option<Self> {
        Some(match v {
            0 => PowerState::On,
            1 => PowerState::Idle,
            2 => PowerState::Suspended,
            3 => PowerState::Off,
            _ => return None,
        })
    }
}

/// Static description of a driver.
#[derive(Copy, Clone, Debug)]
pub struct DriverInfo {
    pub name: &'static str,
    pub class: DeviceClass,
    pub version: (u8, u8, u8),
    /// Compatible strings this driver binds to (e.g. `"arm,pl011"`).
    pub compatible: &'static [&'static str],
}

/// The operation carried by a [`Request`].
pub enum Op<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
    /// Bus transaction: write `tx` then read into `rx` at `addr` (I2C address or SPI chip select).
    Transfer { addr: u16, tx: &'a [u8], rx: &'a mut [u8] },
    /// Device-specific control (see [`ioctl`]); the result is returned as `Ok(value)`.
    Ioctl { cmd: u32, arg: usize },
    /// Power-state change; routed to [`Driver::power`] after the middleware chain.
    Power(PowerState),
}

/// Discriminant of an [`Op`], convenient for middleware policies.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpKind {
    Read,
    Write,
    Transfer,
    Ioctl,
    Power,
}

impl OpKind {
    pub const fn bit(self) -> u8 {
        1 << self as u8
    }
}

impl Op<'_> {
    pub fn kind(&self) -> OpKind {
        match self {
            Op::Read(_) => OpKind::Read,
            Op::Write(_) => OpKind::Write,
            Op::Transfer { .. } => OpKind::Transfer,
            Op::Ioctl { .. } => OpKind::Ioctl,
            Op::Power(_) => OpKind::Power,
        }
    }
}

impl fmt::Debug for Op<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Read(b) => write!(f, "Read({})", b.len()),
            Op::Write(b) => write!(f, "Write({})", b.len()),
            Op::Transfer { addr, tx, rx } => write!(f, "Transfer(@{addr:#x}, tx={}, rx={})", tx.len(), rx.len()),
            Op::Ioctl { cmd, arg } => write!(f, "Ioctl({cmd:#x}, {arg:#x})"),
            Op::Power(p) => write!(f, "Power({p:?})"),
        }
    }
}

/// Request flag: never block inside the driver (POSIX `O_NONBLOCK`).
pub const FLAG_NONBLOCK: u32 = 1 << 0;

/// An I/O request travelling down the middleware chain to a driver.
#[derive(Debug)]
pub struct Request<'a> {
    pub op: Op<'a>,
    pub timeout: Timeout,
    pub flags: u32,
    /// Set by the kernel only; middleware can read but not forge it.
    caller: Option<crate::security::Caller>,
}

impl<'a> Request<'a> {
    pub fn new(op: Op<'a>) -> Self {
        Request { op, timeout: Timeout::Forever, flags: 0, caller: None }
    }

    /// Who issued the request (domain and handle rights).
    pub fn caller(&self) -> crate::security::Caller {
        self.caller.unwrap_or(crate::security::Caller::KERNEL)
    }

    pub(crate) fn set_caller(&mut self, c: crate::security::Caller) {
        self.caller = Some(c);
    }

    /// A derived request (e.g. a middleware splitting a write) that keeps the caller.
    pub fn derive<'b>(&self, op: Op<'b>) -> Request<'b> {
        Request { op, timeout: self.timeout, flags: self.flags, caller: self.caller }
    }

    pub fn with_timeout(mut self, t: Timeout) -> Self {
        self.timeout = t;
        self
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// The effective timeout, taking `FLAG_NONBLOCK` into account.
    pub fn effective_timeout(&self) -> Timeout {
        if self.flags & FLAG_NONBLOCK != 0 { Timeout::NoWait } else { self.timeout }
    }
}

/// Context passed to middleware and drivers for each request.
#[derive(Copy, Clone, Debug)]
pub struct DeviceCtx {
    pub device: Device,
    pub name: &'static str,
    pub class: DeviceClass,
}

/// A device driver.
///
/// Drivers are `Sync` singletons (typically `static`s); mutable hardware state lives
/// behind interior mutability ([`crate::sync::IrqCell`], [`crate::sync::Mutex`]).
pub trait Driver: Sync {
    fn info(&self) -> DriverInfo;

    /// The middleware this driver contributes, innermost (closest to hardware) last.
    /// Required: every driver defines how its raw hardware behaviour is adapted.
    fn middleware(&self) -> &'static [&'static dyn Middleware];

    /// Bring the device up. Called once at registration.
    fn init(&self, _ctx: &DeviceCtx) -> Result<(), Error> {
        Ok(())
    }

    /// Perform a request that has passed through the middleware chain.
    fn handle(&self, ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult;

    /// Change power state.
    fn power(&self, _ctx: &DeviceCtx, state: PowerState) -> Result<(), Error> {
        match state {
            PowerState::On => Ok(()),
            _ => Err(Error::Unsupported),
        }
    }
}

/// The continuation of the middleware chain. Middleware calls [`Next::run`] (zero or
/// more times) to pass a request further down towards the driver.
#[derive(Copy, Clone)]
pub struct Next<'a> {
    stages: [&'a [&'static dyn Middleware]; 3],
    driver: &'static dyn Driver,
    ctx: &'a DeviceCtx,
}

impl Next<'_> {
    pub fn run(self, req: &mut Request<'_>) -> IoResult {
        let mut rest = self;
        for i in 0..3 {
            if let Some((first, tail)) = self.stages[i].split_first() {
                rest.stages[i] = tail;
                return first.call(self.ctx, req, rest);
            }
        }
        match req.op {
            Op::Power(state) => self.driver.power(self.ctx, state).map(|_| 0),
            _ => self.driver.handle(self.ctx, req),
        }
    }
}

// ----- registry -----

/// Placeholder layer used to fill fixed-size middleware arrays.
struct Nop;
impl Middleware for Nop {
    fn name(&self) -> &'static str {
        "nop"
    }
    fn call(&self, _: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        next.run(req)
    }
}
static NOP: Nop = Nop;

#[derive(Copy, Clone)]
struct Layers {
    items: [&'static dyn Middleware; MAX_LAYERS],
    len: usize,
}

impl Layers {
    const EMPTY: Layers = Layers { items: [&NOP; MAX_LAYERS], len: 0 };

    fn push(&mut self, m: &'static dyn Middleware) -> Result<(), Error> {
        if self.len == MAX_LAYERS {
            return Err(Error::NoResources);
        }
        self.items[self.len] = m;
        self.len += 1;
        Ok(())
    }

    fn remove(&mut self, name: &str) -> bool {
        let Some(pos) = self.items[..self.len].iter().position(|m| m.name() == name) else {
            return false;
        };
        self.items.copy_within(pos + 1..self.len, pos);
        self.len -= 1;
        self.items[self.len] = &NOP;
        true
    }

    fn as_slice(&self) -> &[&'static dyn Middleware] {
        &self.items[..self.len]
    }
}

#[derive(Copy, Clone)]
struct Entry {
    name: &'static str,
    driver: &'static dyn Driver,
    class: DeviceClass,
    layers: Layers,
    power: PowerState,
    generation: u8,
}

struct Registry {
    devices: [Option<Entry>; MAX_DEVICES],
    generations: [u8; MAX_DEVICES],
    global: Layers,
}

static REGISTRY: IrqCell<Registry> =
    IrqCell::new(Registry { devices: [None; MAX_DEVICES], generations: [0; MAX_DEVICES], global: Layers::EMPTY });

fn reg<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    REGISTRY.lock(f)
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    reg(|r| {
        r.devices = [None; MAX_DEVICES];
        r.global = Layers::EMPTY;
    });
}

/// Handle to a registered device.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Device {
    index: u8,
    generation: u8,
}

/// Register a device under `name` and initialise its driver.
pub fn register(name: &'static str, driver: &'static dyn Driver) -> Result<Device, Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    let info = driver.info();
    let dev = reg(|r| {
        if r.devices.iter().flatten().any(|e| e.name == name) {
            return Err(Error::Exists);
        }
        let i = r.devices.iter().position(|e| e.is_none()).ok_or(Error::NoResources)?;
        r.generations[i] = r.generations[i].wrapping_add(1);
        let generation = r.generations[i];
        r.devices[i] =
            Some(Entry { name, driver, class: info.class, layers: Layers::EMPTY, power: PowerState::On, generation });
        Ok(Device { index: i as u8, generation })
    })?;
    let ctx = DeviceCtx { device: dev, name, class: info.class };
    for m in driver.middleware() {
        m.on_attach(&ctx);
    }
    if let Err(e) = driver.init(&ctx) {
        reg(|r| r.devices[dev.index as usize] = None);
        return Err(e);
    }
    Ok(dev)
}

/// Remove a device. Outstanding handles become invalid.
pub fn unregister(dev: Device) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    reg(|r| {
        dev.check(r)?;
        r.devices[dev.index as usize] = None;
        Ok(())
    })
}

/// Add a middleware layer applied to every device (outermost). Kernel domain only.
pub fn add_global_middleware(m: &'static dyn Middleware) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    reg(|r| r.global.push(m))
}

/// Remove a global layer. Kernel domain only, and refused once the security
/// configuration is sealed (global layers are where audit/policy layers live).
pub fn remove_global_middleware(name: &str) -> bool {
    if !crate::security::current_is_trusted() || crate::security::is_sealed() {
        return false;
    }
    reg(|r| r.global.remove(name))
}

/// Summary of a registered device, for listings.
#[derive(Copy, Clone, Debug)]
pub struct DeviceInfo {
    pub device: Device,
    pub name: &'static str,
    pub driver: DriverInfo,
    pub power: PowerState,
    pub user_layers: usize,
    pub driver_layers: usize,
}

/// Fill `out` with registered devices; returns the count written.
pub fn list(out: &mut [Option<DeviceInfo>]) -> usize {
    let mut n = 0;
    for i in 0..MAX_DEVICES {
        if n == out.len() {
            break;
        }
        if let Some(d) = Device::from_index(i) {
            if let Ok(info) = d.info() {
                out[n] = Some(info);
                n += 1;
            }
        }
    }
    n
}

impl Device {
    fn check<'r>(&self, r: &'r Registry) -> Result<&'r Entry, Error> {
        match r.devices.get(self.index as usize) {
            Some(Some(e)) if e.generation == self.generation => Ok(e),
            _ => Err(Error::BadHandle),
        }
    }

    /// Look a device up by name (`"uart0"` or `"/dev/uart0"`).
    pub fn find(name: &str) -> Result<Device, Error> {
        let name = name.strip_prefix("/dev/").unwrap_or(name);
        reg(|r| {
            r.devices
                .iter()
                .enumerate()
                .find_map(|(i, e)| e.filter(|e| e.name == name).map(|e| Device { index: i as u8, generation: e.generation }))
                .ok_or(Error::NotFound)
        })
    }

    pub fn index(self) -> usize {
        self.index as usize
    }

    /// The device currently registered at index `i` (with its live generation), if any.
    pub fn from_index(i: usize) -> Option<Device> {
        reg(|r| r.devices.get(i).copied().flatten().map(|e| Device { index: i as u8, generation: e.generation }))
    }

    pub fn info(self) -> Result<DeviceInfo, Error> {
        reg(|r| {
            let e = self.check(r)?;
            Ok(DeviceInfo {
                device: self,
                name: e.name,
                driver: e.driver.info(),
                power: e.power,
                user_layers: e.layers.len,
                driver_layers: e.driver.middleware().len(),
            })
        })
    }

    pub fn name(self) -> Result<&'static str, Error> {
        reg(|r| self.check(r).map(|e| e.name))
    }

    pub fn class(self) -> Result<DeviceClass, Error> {
        reg(|r| self.check(r).map(|e| e.class))
    }

    /// Attach a middleware layer to this device (applied after global layers, before
    /// the driver's own middleware). Kernel domain only; isolated domains need a
    /// [`DeviceCap`](crate::security::DeviceCap) with `MANAGE`.
    pub fn attach(self, m: &'static dyn Middleware) -> Result<(), Error> {
        if !crate::security::current_is_trusted() {
            return Err(Error::PermissionDenied);
        }
        self.attach_privileged(m)
    }

    pub(crate) fn attach_privileged(self, m: &'static dyn Middleware) -> Result<(), Error> {
        let ctx = reg(|r| {
            let e = self.check(r)?;
            let ctx = DeviceCtx { device: self, name: e.name, class: e.class };
            r.devices[self.index as usize].as_mut().unwrap().layers.push(m)?;
            Ok::<_, Error>(ctx)
        })?;
        m.on_attach(&ctx);
        Ok(())
    }

    /// Detach a user middleware layer by name. Kernel domain only.
    pub fn detach(self, name: &str) -> Result<(), Error> {
        if !crate::security::current_is_trusted() {
            return Err(Error::PermissionDenied);
        }
        self.detach_privileged(name)
    }

    pub(crate) fn detach_privileged(self, name: &str) -> Result<(), Error> {
        reg(|r| {
            self.check(r)?;
            if r.devices[self.index as usize].as_mut().unwrap().layers.remove(name) {
                Ok(())
            } else {
                Err(Error::NotFound)
            }
        })
    }

    /// Names of the full chain, outermost first: global, user, driver.
    pub fn chain(self, out: &mut [&'static str]) -> Result<usize, Error> {
        let (g, l, d) = reg(|r| {
            let e = self.check(r)?;
            Ok::<_, Error>((r.global, e.layers, e.driver))
        })?;
        let mut n = 0;
        for m in g.as_slice().iter().chain(l.as_slice()).chain(d.middleware()) {
            if n < out.len() {
                out[n] = m.name();
                n += 1;
            }
        }
        Ok(n)
    }

    /// Send a request through the middleware chain to the driver.
    ///
    /// This raw API carries ambient authority and is only available to trusted domains;
    /// isolated domains go through [`DeviceCap`](crate::security::DeviceCap), which checks
    /// rights first and stamps the request with its [`Caller`](crate::security::Caller).
    pub fn request(self, req: &mut Request<'_>) -> IoResult {
        if req.caller.is_none() {
            if !crate::security::current_is_trusted() {
                return Err(Error::PermissionDenied);
            }
            req.caller = Some(crate::security::Caller::KERNEL);
        }
        let (global, e) = reg(|r| {
            let e = *self.check(r)?;
            Ok::<_, Error>((r.global, e))
        })?;
        let ctx = DeviceCtx { device: self, name: e.name, class: e.class };
        let next = Next { stages: [global.as_slice(), e.layers.as_slice(), e.driver.middleware()], driver: e.driver, ctx: &ctx };
        let r = next.run(req);
        if let (Op::Power(state), Ok(_)) = (&req.op, &r) {
            let state = *state;
            reg(|r| {
                if let Some(Some(e)) = r.devices.get_mut(self.index as usize) {
                    e.power = state;
                }
            });
        }
        r
    }

    pub fn read(self, buf: &mut [u8]) -> IoResult {
        self.request(&mut Request::new(Op::Read(buf)))
    }

    pub fn read_timeout(self, buf: &mut [u8], timeout: Timeout) -> IoResult {
        self.request(&mut Request::new(Op::Read(buf)).with_timeout(timeout))
    }

    pub fn write(self, buf: &[u8]) -> IoResult {
        self.request(&mut Request::new(Op::Write(buf)))
    }

    /// Write the whole buffer, looping over short writes.
    pub fn write_all(self, mut buf: &[u8]) -> Result<(), Error> {
        while !buf.is_empty() {
            let n = self.write(buf)?;
            if n == 0 {
                return Err(Error::Io);
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    pub fn transfer(self, addr: u16, tx: &[u8], rx: &mut [u8]) -> IoResult {
        self.request(&mut Request::new(Op::Transfer { addr, tx, rx }))
    }

    pub fn ioctl(self, cmd: u32, arg: usize) -> IoResult {
        self.request(&mut Request::new(Op::Ioctl { cmd, arg }))
    }

    pub fn set_power(self, state: PowerState) -> Result<(), Error> {
        self.request(&mut Request::new(Op::Power(state))).map(|_| ())
    }

    pub fn power(self) -> Result<PowerState, Error> {
        reg(|r| self.check(r).map(|e| e.power))
    }

    /// Write on behalf of the kernel console (bypasses the ambient-authority check for
    /// domains whose policy allows logging).
    pub(crate) fn console_write(self, mut buf: &[u8]) -> Result<(), Error> {
        while !buf.is_empty() {
            let mut req = Request::new(Op::Write(buf));
            req.caller = Some(crate::security::Caller::KERNEL);
            let n = self.request(&mut req)?;
            if n == 0 {
                return Err(Error::Io);
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    /// Give the device a new generation, invalidating every outstanding handle.
    pub(crate) fn regenerate(self) -> Result<Device, Error> {
        reg(|r| {
            self.check(r)?;
            let i = self.index as usize;
            r.generations[i] = r.generations[i].wrapping_add(1);
            let g = r.generations[i];
            r.devices[i].as_mut().unwrap().generation = g;
            Ok(Device { index: self.index, generation: g })
        })
    }
}

// ----- board description & driver binding -----

/// A device instance described by the board (the equivalent of a device-tree node).
#[derive(Debug)]
pub struct DeviceDesc {
    /// Device name, exposed as `/dev/<name>`.
    pub name: &'static str,
    /// Matched against [`DriverInfo::compatible`].
    pub compatible: &'static str,
    /// Register window, if the device is memory-mapped.
    pub mmio: Option<crate::arch::mmio::Mmio>,
    /// Interrupt number (`u16::MAX` if none).
    pub irq: u16,
    /// Free-form integer parameters (`("baud", 115200)`, `("channels", 2)`, ...).
    pub params: &'static [(&'static str, u32)],
}

impl DeviceDesc {
    pub fn param(&self, key: &str) -> Option<u32> {
        self.params.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

/// A driver that can be instantiated for matching device descriptions.
pub struct DriverFactory {
    pub compatible: &'static [&'static str],
    /// Create (or hand out a static instance of) the driver for `desc`.
    pub create: fn(&'static DeviceDesc) -> Result<&'static dyn Driver, Error>,
}

/// Bind every description to the first factory with a matching compatible string and
/// register the resulting devices. Returns how many devices were registered;
/// descriptions with no driver or whose probe fails are skipped.
pub fn probe_all(descs: &'static [DeviceDesc], factories: &[DriverFactory]) -> usize {
    let mut n = 0;
    for d in descs {
        let Some(f) = factories.iter().find(|f| f.compatible.contains(&d.compatible)) else {
            continue;
        };
        if let Ok(drv) = (f.create)(d) {
            if register(d.name, drv).is_ok() {
                n += 1;
            }
        }
    }
    n
}
