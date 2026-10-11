//! Networking: a FreeBSD/Linux-inspired network core sized for microcontrollers.
//!
//! Implements the design in `docs/research/networking.md`:
//!
//! ```text
//!  apps ── sockets (net::socket) ── POSIX / embedded-io compat      NetRing apps
//!            │  messages + per-socket queues                          ▲ zero-copy
//!  ┌─────────▼───────────────┐  ┌──────────────────────┐               │
//!  │ IP stack (smoltcp node) │  │ protocol nodes       │      Steer hook
//!  └─────────▲───────────────┘  │ (by EtherType)       │               │
//!            └────────┬─────────┴──────────▲───────────┘               │
//!               dispatch by EtherType ─────┘                           │
//!  ┌──────────────────┴────────────────────────────────────────────────┴──┐
//!  │ packet hook chain: global → per-interface → driver   (Verdict)       │
//!  ├──────────────────────────────────────────────────────────────────────┤
//!  │ net core (single `net` task): RX poll with budget + refill, checksum │
//!  │ software fallback, 2-band TX queues, doorbell batching, reclaim      │
//!  ├──────────────────────────────────────────────────────────────────────┤
//!  │ NetDevice (iflib-lite ring ops)  ◄── SoftRing ◄── FrameDevice         │
//!  │ PacketPool blocks: RX / TX / APP pools                               │
//!  └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! * **Single owner.** All interface state, rings and the IP stack are driven by one
//!   `net` task, so the fast path needs no locks (lwIP tcpip_thread / netisr direct
//!   dispatch). Interrupt handlers only call [`schedule`].
//! * **Two planes.** Control requests (`/dev/<ifname>` ioctls) flow through the normal
//!   driver middleware chain; packets flow through [`hook`]s.
//! * **Offload with fallback.** Drivers advertise [`NetCaps`]; whatever they lack
//!   (checksums, scatter-gather) the core does in software.
//!
//! Classification: L3 services · net: core and net task · safe · net

pub mod buf;
pub mod csum;
pub mod device;
pub mod drivers;
#[cfg(feature = "net-filter")]
pub mod filter;
pub mod hook;
#[cfg(feature = "net-ip")]
pub mod ip;
pub mod ring;
#[cfg(feature = "net-ip")]
pub mod socket;

use core::sync::atomic::{AtomicU8, Ordering};

pub use buf::{PacketBuf, PacketPool};
pub use device::{FrameDevice, HwAddr, LinkState, NetCaps, NetDevInfo, NetDevice, RxFilter, SoftRing};
pub use hook::{Dir, PacketHook, Verdict};
pub use ring::NetRing;

use crate::Error;
use crate::config::{MAX_LAYERS, MAX_NETIFS, NET_APP_BUFS, NET_BUDGET, NET_RX_BUFS, NET_STACK_SIZE, NET_TX_BUFS, NET_TXQ_LEN};
use crate::driver::ioctl;
use crate::driver::middleware::Middleware;
use crate::driver::{self, Device, DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Next, Op, PowerState, Request};
use crate::kernel::cell::IrqCell;
use crate::kernel::stack::Stack;
use crate::kernel::task::{self, TaskId};
use crate::kernel::time::{self, Timeout};
use crate::sync::Queue;

/// Index of a registered network interface.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct IfIndex(pub u8);

/// Receive buffers (pre-posted to drivers).
pub static RX_POOL: PacketPool<NET_RX_BUFS> = PacketPool::new("net-rx");
/// Transmit buffers (built by the IP stack and raw senders).
pub static TX_POOL: PacketPool<NET_TX_BUFS> = PacketPool::new("net-tx");
/// Buffers carrying data between the net task and applications.
pub static APP_POOL: PacketPool<NET_APP_BUFS> = PacketPool::new("net-app");

/// Per-interface counters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IfStats {
    pub rx_packets: u32,
    pub rx_bytes: u32,
    pub rx_dropped: u32,
    pub rx_csum_errors: u32,
    pub rx_no_proto: u32,
    /// Poll rounds that used the whole budget (receive overload indicator).
    pub rx_budget_exhausted: u32,
    pub tx_packets: u32,
    pub tx_bytes: u32,
    pub tx_dropped: u32,
    pub hook_drops: u32,
}

impl IfStats {
    fn add(&mut self, d: &IfStats) {
        self.rx_packets += d.rx_packets;
        self.rx_bytes += d.rx_bytes;
        self.rx_dropped += d.rx_dropped;
        self.rx_csum_errors += d.rx_csum_errors;
        self.rx_no_proto += d.rx_no_proto;
        self.rx_budget_exhausted += d.rx_budget_exhausted;
        self.tx_packets += d.tx_packets;
        self.tx_bytes += d.tx_bytes;
        self.tx_dropped += d.tx_dropped;
        self.hook_drops += d.hook_drops;
    }
}

struct NopHook;
impl PacketHook for NopHook {
    fn name(&self) -> &'static str {
        "nop"
    }
    fn on_packet(&self, _: Dir, _: IfIndex, pkt: PacketBuf) -> Verdict {
        Verdict::Pass(pkt)
    }
}
static NOP_HOOK: NopHook = NopHook;

#[derive(Copy, Clone)]
struct HookList {
    items: [&'static dyn PacketHook; MAX_LAYERS],
    len: usize,
}

impl HookList {
    const EMPTY: HookList = HookList { items: [&NOP_HOOK; MAX_LAYERS], len: 0 };

    fn push(&mut self, h: &'static dyn PacketHook) -> Result<(), Error> {
        if self.len == MAX_LAYERS {
            return Err(Error::NoResources);
        }
        self.items[self.len] = h;
        self.len += 1;
        Ok(())
    }

    fn remove(&mut self, name: &str) -> bool {
        let Some(pos) = self.items[..self.len].iter().position(|h| h.name() == name) else {
            return false;
        };
        self.items.copy_within(pos + 1..self.len, pos);
        self.len -= 1;
        true
    }

    fn as_slice(&self) -> &[&'static dyn PacketHook] {
        &self.items[..self.len]
    }
}

#[derive(Copy, Clone)]
pub(crate) struct IfEntry {
    name: &'static str,
    dev: &'static dyn NetDevice,
    enabled: NetCaps,
    up: bool,
    posted: u16,
    stats: IfStats,
    hooks_in: HookList,
    hooks_out: HookList,
    #[cfg(feature = "net-ip")]
    ip: Option<ip::IpConfig>,
}

struct Global {
    ifaces: [Option<IfEntry>; MAX_NETIFS],
    hooks_in: HookList,
    hooks_out: HookList,
    nodes: [Option<(u16, &'static dyn NetNode)>; 8],
    net_task: Option<TaskId>,
}

static NET: IrqCell<Global> = IrqCell::new(Global {
    ifaces: [None; MAX_NETIFS],
    hooks_in: HookList::EMPTY,
    hooks_out: HookList::EMPTY,
    nodes: [None; 8],
    net_task: None,
});

/// Two transmit bands per interface: 0 = high priority, 1 = bulk.
static TXQ: [[Queue<PacketBuf, NET_TXQ_LEN>; 2]; MAX_NETIFS] =
    [const { [const { Queue::new() }, const { Queue::new() }] }; MAX_NETIFS];

/// A protocol handler for a given EtherType (netgraph-lite node).
/// Nodes run in the net task and may transmit with [`transmit`].
pub trait NetNode: Sync {
    fn name(&self) -> &'static str;
    fn receive(&self, ifindex: IfIndex, pkt: PacketBuf);
}

// ----- registration & configuration -----

/// Register a network device as interface `name`. It also appears as the control-plane
/// device `/dev/<name>`, with the usual middleware chain.
pub fn register(name: &'static str, dev: &'static dyn NetDevice) -> Result<IfIndex, Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    let caps = dev.info().caps;
    let idx = NET.lock(|g| {
        if g.ifaces.iter().flatten().any(|e| e.name == name) {
            return Err(Error::Exists);
        }
        let i = g.ifaces.iter().position(|e| e.is_none()).ok_or(Error::NoResources)?;
        g.ifaces[i] = Some(IfEntry {
            name,
            dev,
            enabled: caps,
            up: true,
            posted: 0,
            stats: IfStats::default(),
            hooks_in: HookList::EMPTY,
            hooks_out: HookList::EMPTY,
            #[cfg(feature = "net-ip")]
            ip: None,
        });
        Ok(IfIndex(i as u8))
    })?;
    dev.open()?;
    let ctl = &CONTROL[idx.0 as usize];
    ctl.index.store(idx.0, Ordering::Relaxed);
    if let Err(e) = driver::register(name, ctl) {
        NET.lock(|g| g.ifaces[idx.0 as usize] = None);
        return Err(e);
    }
    Ok(idx)
}

/// Look an interface up by name.
pub fn find(name: &str) -> Result<IfIndex, Error> {
    NET.lock(|g| {
        g.ifaces
            .iter()
            .position(|e| e.is_some_and(|e| e.name == name))
            .map(|i| IfIndex(i as u8))
            .ok_or(Error::NotFound)
    })
}

pub(crate) fn with_if<R>(idx: IfIndex, f: impl FnOnce(&mut IfEntry) -> R) -> Result<R, Error> {
    NET.lock(|g| g.ifaces.get_mut(idx.0 as usize).and_then(|e| e.as_mut()).map(f).ok_or(Error::BadHandle))
}

/// Administratively enable or disable an interface.
pub fn set_up(idx: IfIndex, up: bool) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    with_if(idx, |e| e.up = up)?;
    schedule();
    Ok(())
}

/// Enable a subset of the device's hardware offloads (ethtool `-K`); the rest is done in
/// software. Returns the capabilities actually enabled.
pub fn set_offloads(idx: IfIndex, want: NetCaps) -> Result<NetCaps, Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    with_if(idx, |e| {
        e.enabled = want & e.dev.info().caps;
        e.enabled
    })
}

pub fn stats(idx: IfIndex) -> Result<IfStats, Error> {
    with_if(idx, |e| e.stats)
}

/// Summary of an interface.
#[derive(Copy, Clone, Debug)]
pub struct IfInfo {
    pub index: IfIndex,
    pub name: &'static str,
    pub hw_addr: HwAddr,
    pub mtu: u16,
    pub link: LinkState,
    pub up: bool,
    pub offloads: NetCaps,
}

pub fn info(idx: IfIndex) -> Result<IfInfo, Error> {
    let (name, dev, up, offloads) = with_if(idx, |e| (e.name, e.dev, e.up, e.enabled))?;
    Ok(IfInfo { index: idx, name, hw_addr: dev.hw_addr(), mtu: dev.info().mtu, link: dev.link(), up, offloads })
}

/// Attach a packet hook to one interface.
pub fn attach_hook(idx: IfIndex, dir: Dir, hook: &'static dyn PacketHook) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    with_if(idx, |e| match dir {
        Dir::In => e.hooks_in.push(hook),
        Dir::Out => e.hooks_out.push(hook),
    })?
}

pub fn detach_hook(idx: IfIndex, dir: Dir, name: &str) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    let found = with_if(idx, |e| match dir {
        Dir::In => e.hooks_in.remove(name),
        Dir::Out => e.hooks_out.remove(name),
    })?;
    if found { Ok(()) } else { Err(Error::NotFound) }
}

/// Attach a packet hook to every interface (runs before per-interface hooks).
pub fn add_global_hook(dir: Dir, hook: &'static dyn PacketHook) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    NET.lock(|g| match dir {
        Dir::In => g.hooks_in.push(hook),
        Dir::Out => g.hooks_out.push(hook),
    })
}

/// Handle all received frames of `ethertype` with `node` instead of the IP stack.
pub fn register_protocol(ethertype: u16, node: &'static dyn NetNode) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    NET.lock(|g| {
        if g.nodes.iter().flatten().any(|(t, _)| *t == ethertype) {
            return Err(Error::Exists);
        }
        let slot = g.nodes.iter_mut().find(|n| n.is_none()).ok_or(Error::NoResources)?;
        *slot = Some((ethertype, node));
        Ok(())
    })
}

// ----- data path entry points -----

/// Queue a complete Ethernet frame for transmission on `idx`. Frames with
/// `meta.prio >= 4` use the high-priority band. On failure the packet is returned.
pub fn transmit(idx: IfIndex, mut pkt: PacketBuf) -> Result<(), (Error, PacketBuf)> {
    let Some(q) = TXQ.get(idx.0 as usize) else { return Err((Error::BadHandle, pkt)) };
    pkt.meta.ifindex = idx.0;
    let band = if pkt.meta.prio >= 4 { 0 } else { 1 };
    match q[band].try_send(pkt) {
        Ok(()) => {
            schedule();
            Ok(())
        }
        Err(e) => {
            let _ = with_if(idx, |e| e.stats.tx_dropped += 1);
            Err((e.error, e.item))
        }
    }
}

/// Wake the net task (call from driver interrupt handlers after masking the IRQ).
pub fn schedule() {
    if let Some(t) = NET.lock(|g| g.net_task) {
        let _ = task::notify(t, 1);
    }
}

static NET_STACK: Stack<NET_STACK_SIZE> = Stack::new();

/// Start the net task. Register interfaces (and configure IP) first.
pub fn start() -> Result<TaskId, Error> {
    if let Some(t) = NET.lock(|g| g.net_task) {
        return Ok(t);
    }
    let t = task::Builder::new("net")
        .priority(crate::config::NET_PRIORITY)
        .stack(&NET_STACK)
        .daemon(true)
        .kernel_service()
        .spawn(net_main, 0)?;
    NET.lock(|g| g.net_task = Some(t));
    Ok(t)
}

fn net_main(_: usize) {
    #[cfg(feature = "net-ip")]
    ip::run();
    #[cfg(not(feature = "net-ip"))]
    {
        let mut core = Core::new();
        loop {
            let more = core.round();
            core.wait(more, None);
        }
    }
}

/// State owned by the net task.
pub(crate) struct Core {
    /// A transmit packet the driver refused (ring full), retried first next round.
    pending: [Option<PacketBuf>; MAX_NETIFS],
}

impl Core {
    pub(crate) fn new() -> Self {
        Core { pending: [const { None }; MAX_NETIFS] }
    }

    /// One poll round over every interface. Returns `true` if work remains.
    pub(crate) fn round(&mut self) -> bool {
        let (ifaces, gin, gout, nodes) = NET.lock(|g| (g.ifaces, g.hooks_in, g.hooks_out, g.nodes));
        let mut more = false;
        for (i, e) in ifaces.iter().enumerate() {
            let Some(e) = e else { continue };
            let idx = IfIndex(i as u8);
            let mut d = IfStats::default();
            let mut posted = e.posted;
            if e.up {
                more |= self.rx(idx, e, &gin, &nodes, &mut posted, &mut d);
                more |= self.tx(idx, e, &gout, &mut d);
            }
            e.dev.timer();
            e.dev.tx_reclaim();
            NET.lock(|g| {
                if let Some(Some(ent)) = g.ifaces.get_mut(i) {
                    ent.posted = posted;
                    ent.stats.add(&d);
                }
            });
        }
        more
    }

    fn rx(
        &mut self,
        idx: IfIndex,
        e: &IfEntry,
        gin: &HookList,
        nodes: &[Option<(u16, &'static dyn NetNode)>],
        posted: &mut u16,
        d: &mut IfStats,
    ) -> bool {
        let dev = e.dev;
        // Keep the RX ring stocked from the RX pool; if the pool is dry the ring runs
        // short and the hardware drops (graceful overload).
        while *posted < dev.info().rx_ring {
            let Ok(b) = RX_POOL.try_alloc() else { break };
            if dev.rx_refill(b).is_err() {
                break;
            }
            *posted += 1;
        }
        let mut n = 0;
        while n < NET_BUDGET {
            let Some(mut p) = dev.rx_poll() else { break };
            *posted = posted.saturating_sub(1);
            n += 1;
            p.meta.ifindex = idx.0;
            p.meta.timestamp = time::ticks();
            if e.enabled.contains(NetCaps::RX_CSUM) {
                p.meta.csum = buf::CsumState::Verified;
            } else {
                match csum::verify_frame(p.data()) {
                    csum::Check::Bad => {
                        d.rx_csum_errors += 1;
                        continue;
                    }
                    csum::Check::Good => p.meta.csum = buf::CsumState::Verified,
                    csum::Check::NotIp => {}
                }
            }
            d.rx_packets += 1;
            d.rx_bytes += p.len() as u32;
            let p = match hook::run_chain(&[gin.as_slice(), e.hooks_in.as_slice(), dev.hooks()], Dir::In, idx, p) {
                Ok(p) => p,
                Err(dropped) => {
                    if dropped {
                        d.hook_drops += 1;
                    }
                    continue;
                }
            };
            self.dispatch(idx, e, nodes, p, d);
        }
        if n == NET_BUDGET {
            d.rx_budget_exhausted += 1;
            true
        } else {
            dev.irq_enable(true);
            false
        }
    }

    fn dispatch(
        &mut self,
        idx: IfIndex,
        e: &IfEntry,
        nodes: &[Option<(u16, &'static dyn NetNode)>],
        p: PacketBuf,
        d: &mut IfStats,
    ) {
        let et = csum::ethertype(p.data());
        if let Some((_, node)) = nodes.iter().flatten().find(|(t, _)| Some(*t) == et) {
            node.receive(idx, p);
            return;
        }
        #[cfg(feature = "net-ip")]
        if e.ip.is_some() && matches!(et, Some(csum::ETHERTYPE_IPV4 | csum::ETHERTYPE_ARP)) {
            if ip::RXQ[idx.0 as usize].try_send(p).is_err() {
                d.rx_dropped += 1;
            }
            return;
        }
        let _ = e;
        d.rx_no_proto += 1;
    }

    fn tx(&mut self, idx: IfIndex, e: &IfEntry, gout: &HookList, d: &mut IfStats) -> bool {
        let i = idx.0 as usize;
        let dev = e.dev;
        let caps = e.enabled;
        let mut sent = 0;
        let mut more = false;
        while sent < NET_BUDGET {
            let p = match self.pending[i].take() {
                Some(p) => p,
                None => {
                    let Ok(p) = TXQ[i][0].try_recv().or_else(|_| TXQ[i][1].try_recv()) else { break };
                    let Ok(mut p) =
                        hook::run_chain(&[gout.as_slice(), e.hooks_out.as_slice(), dev.hooks()], Dir::Out, idx, p)
                    else {
                        d.hook_drops += 1;
                        continue;
                    };
                    let need_ip = !caps.contains(NetCaps::TX_CSUM_IPV4);
                    let need_l4 = !caps.contains(NetCaps::TX_CSUM_L4);
                    if p.ext().is_some() && (!caps.contains(NetCaps::SG) || need_l4) && p.linearize().is_err() {
                        d.tx_dropped += 1;
                        continue;
                    }
                    if need_ip || need_l4 {
                        csum::fill_frame(p.data_mut(), csum::Fill { ipv4: need_ip, l4: need_l4 });
                    }
                    p
                }
            };
            let len = p.total_len() as u32;
            match dev.tx_encap(p) {
                Ok(()) => {
                    sent += 1;
                    d.tx_packets += 1;
                    d.tx_bytes += len;
                }
                Err(p) => {
                    self.pending[i] = Some(p);
                    more = true;
                    break;
                }
            }
        }
        if sent > 0 {
            dev.tx_flush();
        }
        more || sent == NET_BUDGET
    }

    /// Sleep until notified (or `timeout_ticks`), unless work is pending.
    pub(crate) fn wait(&mut self, more: bool, timeout_ticks: Option<u64>) {
        if more {
            task::yield_now();
            return;
        }
        let t = match timeout_ticks {
            Some(0) => {
                task::yield_now();
                return;
            }
            Some(t) => Timeout::Ticks(t),
            None => Timeout::Forever,
        };
        let _ = task::notify_wait(t);
    }
}

// ----- control plane: /dev/<ifname> -----

/// Built-in middleware of every network interface device: refuses raw frame writes
/// while the interface is down or has no link.
pub struct LinkGuard;

impl Middleware for LinkGuard {
    fn name(&self) -> &'static str {
        "link-guard"
    }

    fn call(&self, ctx: &DeviceCtx, req: &mut Request<'_>, next: Next<'_>) -> IoResult {
        if let Op::Write(_) = req.op {
            let idx = find(ctx.name)?;
            let i = info(idx)?;
            if !i.up || !i.link.up {
                return Err(Error::NotReady);
            }
        }
        next.run(req)
    }
}

static LINK_GUARD: LinkGuard = LinkGuard;
static CONTROL_MW: [&dyn Middleware; 1] = [&LINK_GUARD];

struct ControlDriver {
    index: AtomicU8,
}

static CONTROL: [ControlDriver; MAX_NETIFS] = [const { ControlDriver { index: AtomicU8::new(0) } }; MAX_NETIFS];

impl Driver for ControlDriver {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "netif", class: DeviceClass::Net, version: (1, 0, 0), compatible: &[] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &CONTROL_MW
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let idx = IfIndex(self.index.load(Ordering::Relaxed));
        let timeout = req.timeout;
        match &mut req.op {
            Op::Write(frame) => {
                let p = TX_POOL.alloc_from(frame, timeout)?;
                transmit(idx, p).map_err(|(e, _)| e)?;
                Ok(frame.len())
            }
            Op::Ioctl { cmd, arg } => {
                let i = info(idx)?;
                let s = stats(idx)?;
                Ok(match *cmd {
                    ioctl::NET_GET_MTU => i.mtu as usize,
                    ioctl::NET_GET_HWADDR => i.hw_addr.to_u64() as usize,
                    ioctl::NET_GET_LINK => i.link.up as usize | ((i.link.speed_mbps as usize) << 16),
                    ioctl::NET_SET_UP => {
                        set_up(idx, *arg != 0)?;
                        0
                    }
                    ioctl::NET_GET_OFFLOADS => i.offloads.0 as usize,
                    ioctl::NET_SET_OFFLOADS => set_offloads(idx, NetCaps(*arg as u32))?.0 as usize,
                    ioctl::NET_GET_RX_PACKETS => s.rx_packets as usize,
                    ioctl::NET_GET_TX_PACKETS => s.tx_packets as usize,
                    ioctl::NET_GET_RX_DROPPED => (s.rx_dropped + s.rx_csum_errors + s.hook_drops) as usize,
                    ioctl::GET_CLASS => DeviceClass::Net as usize,
                    _ => return Err(Error::Unsupported),
                })
            }
            _ => Err(Error::Unsupported),
        }
    }

    fn power(&self, _ctx: &DeviceCtx, state: PowerState) -> Result<(), Error> {
        set_up(IfIndex(self.index.load(Ordering::Relaxed)), state == PowerState::On)
    }
}

/// Look up the control-plane device of an interface.
pub fn control_device(idx: IfIndex) -> Result<Device, Error> {
    let name = with_if(idx, |e| e.name)?;
    Device::find(name)
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    // Drain queued packets first so their blocks return to the pools.
    for q in TXQ.iter() {
        for band in q {
            while band.try_recv().is_ok() {}
        }
    }
    #[cfg(feature = "net-ip")]
    ip::reset();
    let devs = NET.lock(|g| g.ifaces.map(|e| e.map(|e| e.dev)));
    for d in devs.iter().flatten() {
        d.stop();
    }
    NET.lock(|g| {
        g.ifaces = [None; MAX_NETIFS];
        g.hooks_in = HookList::EMPTY;
        g.hooks_out = HookList::EMPTY;
        g.nodes = [None; 8];
        g.net_task = None;
    });
    drivers::reset();
}
