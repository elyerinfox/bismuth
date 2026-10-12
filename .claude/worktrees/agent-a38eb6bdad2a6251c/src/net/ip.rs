//! The IP stack node: smoltcp driven by the net task.
//!
//! smoltcp (itself `#![deny(unsafe_code)]`) provides ARP, IPv4, ICMP echo, UDP and TCP.
//! It sits on top of the network core like any other protocol consumer: received
//! IPv4/ARP frames are queued to it by the core, and frames it emits go back through
//! [`super::transmit`] (and therefore through the outbound hook chain and checksum
//! fallback). All of its state, including socket buffers, lives on the net task's stack:
//! a single owner, no locks and no `unsafe` statics.
//!
//! Classification: L3 services · net: IP stack (smoltcp) · safe · net-ip

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use super::buf::{MAX_FRAME, PacketBuf};
use super::socket;
use super::{Core, IfIndex, TX_POOL, with_if};
use crate::Error;
use crate::config::{MAX_NETIFS, NET_ICMP_SOCKETS, NET_IP_IFACES, NET_IP_RXQ, NET_SOCKET_BUF, NET_TCP_SOCKETS, NET_UDP_SOCKETS};
use crate::kernel::cell::IrqCell;
use crate::kernel::time::{self, ms_to_ticks};
use crate::sync::Queue;

/// Static IPv4 configuration of an interface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IpConfig {
    pub addr: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
}

/// Enable IP on an interface. Must be called before [`super::start`].
pub fn configure(idx: IfIndex, cfg: IpConfig) -> Result<(), Error> {
    if cfg.prefix_len > 32 {
        return Err(Error::Invalid);
    }
    with_if(idx, |e| e.ip = Some(cfg))
}

/// Frames waiting to be consumed by the IP stack, per interface.
pub(crate) static RXQ: [Queue<PacketBuf, NET_IP_RXQ>; MAX_NETIFS] = [const { Queue::new() }; MAX_NETIFS];

/// Which interface each IP instance serves (filled when the net task starts).
static INSTANCES: IrqCell<[Option<IfIndex>; NET_IP_IFACES]> = IrqCell::new([None; NET_IP_IFACES]);

/// IP instance number serving `idx`.
pub(crate) fn instance_of(idx: IfIndex) -> Result<usize, Error> {
    INSTANCES.lock(|m| m.iter().position(|x| *x == Some(idx))).ok_or(Error::NotReady)
}

/// Interface of the first IP instance.
pub(crate) fn default_iface() -> Result<IfIndex, Error> {
    INSTANCES.lock(|m| m[0]).ok_or(Error::NotReady)
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    for q in RXQ.iter() {
        while q.try_recv().is_ok() {}
    }
    INSTANCES.lock(|m| *m = [None; NET_IP_IFACES]);
    socket::reset();
}

// ----- smoltcp device adapter -----

struct SmolDev {
    idx: IfIndex,
    mtu: usize,
}

struct RxTok(PacketBuf);
struct TxTok(IfIndex);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0.data())
    }
}

impl phy::TxToken for TxTok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        match TX_POOL.try_alloc() {
            Ok(mut p) => match p.extend(len) {
                Ok(buf) => {
                    let r = f(buf);
                    let _ = super::transmit(self.0, p);
                    r
                }
                Err(_) => f(&mut [0u8; MAX_FRAME][..len.min(MAX_FRAME)]),
            },
            // Pool exhausted: let smoltcp build the frame into scratch space and drop it,
            // exactly as a full hardware ring would.
            Err(_) => f(&mut [0u8; MAX_FRAME][..len.min(MAX_FRAME)]),
        }
    }
}

impl phy::Device for SmolDev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok;

    fn receive(&mut self, _ts: SInstant) -> Option<(RxTok, TxTok)> {
        let p = RXQ[self.idx.0 as usize].try_recv().ok()?;
        Some((RxTok(p), TxTok(self.idx)))
    }

    fn transmit(&mut self, _ts: SInstant) -> Option<TxTok> {
        Some(TxTok(self.idx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.mtu + 14;
        // The network core verifies received checksums and fills transmitted ones
        // (in hardware or in software), so smoltcp does not need to.
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }
}

// ----- per-instance storage, owned by the net task -----

const UDP_META: usize = 8;

struct UdpStore {
    rx_meta: [udp::PacketMetadata; UDP_META],
    rx: [u8; NET_SOCKET_BUF],
    tx_meta: [udp::PacketMetadata; UDP_META],
    tx: [u8; NET_SOCKET_BUF],
}

impl UdpStore {
    const EMPTY: UdpStore = UdpStore {
        rx_meta: [udp::PacketMetadata::EMPTY; UDP_META],
        rx: [0; NET_SOCKET_BUF],
        tx_meta: [udp::PacketMetadata::EMPTY; UDP_META],
        tx: [0; NET_SOCKET_BUF],
    };
}

struct TcpStore {
    rx: [u8; NET_SOCKET_BUF],
    tx: [u8; NET_SOCKET_BUF],
}

impl TcpStore {
    const EMPTY: TcpStore = TcpStore { rx: [0; NET_SOCKET_BUF], tx: [0; NET_SOCKET_BUF] };
}

const ICMP_META: usize = 4;

struct IcmpStore {
    rx_meta: [icmp::PacketMetadata; ICMP_META],
    rx: [u8; NET_SOCKET_BUF],
    tx_meta: [icmp::PacketMetadata; ICMP_META],
    tx: [u8; NET_SOCKET_BUF],
}

impl IcmpStore {
    const EMPTY: IcmpStore = IcmpStore {
        rx_meta: [icmp::PacketMetadata::EMPTY; ICMP_META],
        rx: [0; NET_SOCKET_BUF],
        tx_meta: [icmp::PacketMetadata::EMPTY; ICMP_META],
        tx: [0; NET_SOCKET_BUF],
    };
}

const SOCKETS: usize = NET_UDP_SOCKETS + NET_TCP_SOCKETS + NET_ICMP_SOCKETS;

/// One IP stack instance bound to one interface.
pub(crate) struct Stack<'a> {
    dev: SmolDev,
    pub(crate) iface: Interface,
    pub(crate) sockets: SocketSet<'a>,
    pub(crate) udp: [SocketHandle; NET_UDP_SOCKETS],
    pub(crate) tcp: [SocketHandle; NET_TCP_SOCKETS],
    pub(crate) icmp: [SocketHandle; NET_ICMP_SOCKETS],
}

fn ipv4(a: [u8; 4]) -> Ipv4Address {
    Ipv4Address::new(a[0], a[1], a[2], a[3])
}

pub(crate) fn endpoint(addr: [u8; 4], port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(ipv4(addr)), port)
}

pub(crate) fn now() -> SInstant {
    SInstant::from_millis(time::ticks_to_ms(time::ticks()) as i64)
}

impl<'a> Stack<'a> {
    fn new(
        idx: IfIndex,
        cfg: IpConfig,
        udp_store: &'a mut [UdpStore; NET_UDP_SOCKETS],
        tcp_store: &'a mut [TcpStore; NET_TCP_SOCKETS],
        icmp_store: &'a mut [IcmpStore; NET_ICMP_SOCKETS],
        sock_store: &'a mut [SocketStorage<'a>; SOCKETS],
    ) -> Result<Self, Error> {
        let info = super::info(idx)?;
        let mut dev = SmolDev { idx, mtu: info.mtu as usize };
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(info.hw_addr.0)));
        config.random_seed = info.hw_addr.to_u64() ^ time::ticks();
        // TCP initial sequence numbers etc. must be unpredictable: seed from the kernel
        // domain's CSPRNG when entropy is available.
        #[cfg(feature = "crypto")]
        {
            let mut b = [0u8; 8];
            if crate::security::entropy::fill_for(crate::security::DomainId::KERNEL, &mut b).is_ok() {
                config.random_seed = u64::from_le_bytes(b);
            }
        }
        let mut iface = Interface::new(config, &mut dev, now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(ipv4(cfg.addr)), cfg.prefix_len));
        });
        if let Some(gw) = cfg.gateway {
            iface.routes_mut().add_default_ipv4_route(ipv4(gw)).map_err(|_| Error::NoResources)?;
        }
        let mut sockets = SocketSet::new(&mut sock_store[..]);
        let mut udp = [SocketHandle::default(); NET_UDP_SOCKETS];
        for (h, s) in udp.iter_mut().zip(udp_store.iter_mut()) {
            let rx = udp::PacketBuffer::new(&mut s.rx_meta[..], &mut s.rx[..]);
            let tx = udp::PacketBuffer::new(&mut s.tx_meta[..], &mut s.tx[..]);
            *h = sockets.add(udp::Socket::new(rx, tx));
        }
        let mut tcp = [SocketHandle::default(); NET_TCP_SOCKETS];
        for (h, s) in tcp.iter_mut().zip(tcp_store.iter_mut()) {
            let rx = tcp::SocketBuffer::new(&mut s.rx[..]);
            let tx = tcp::SocketBuffer::new(&mut s.tx[..]);
            *h = sockets.add(tcp::Socket::new(rx, tx));
        }
        let mut icmp = [SocketHandle::default(); NET_ICMP_SOCKETS];
        for (h, s) in icmp.iter_mut().zip(icmp_store.iter_mut()) {
            let rx = icmp::PacketBuffer::new(&mut s.rx_meta[..], &mut s.rx[..]);
            let tx = icmp::PacketBuffer::new(&mut s.tx_meta[..], &mut s.tx[..]);
            *h = sockets.add(icmp::Socket::new(rx, tx));
        }
        Ok(Stack { dev, iface, sockets, udp, tcp, icmp })
    }

    fn poll(&mut self) {
        let _ = self.iface.poll(now(), &mut self.dev, &mut self.sockets);
    }

    /// Ticks until smoltcp next needs attention (retransmits, ARP, ...).
    fn delay_ticks(&mut self) -> Option<u64> {
        self.iface.poll_delay(now(), &self.sockets).map(|d| ms_to_ticks(d.total_millis()))
    }
}

/// The net task body when IP is enabled.
pub(crate) fn run() {
    let mut core = Core::new();
    let mut udp_store = [const { [const { UdpStore::EMPTY }; NET_UDP_SOCKETS] }; NET_IP_IFACES];
    let mut tcp_store = [const { [const { TcpStore::EMPTY }; NET_TCP_SOCKETS] }; NET_IP_IFACES];
    let mut icmp_store = [const { [const { IcmpStore::EMPTY }; NET_ICMP_SOCKETS] }; NET_IP_IFACES];
    let mut sock_store = [const { [SocketStorage::EMPTY; SOCKETS] }; NET_IP_IFACES];

    // Create one IP instance per IP-configured interface, in interface order.
    let mut configured = (0..MAX_NETIFS as u8)
        .map(IfIndex)
        .filter_map(|i| with_if(i, |e| e.ip).ok().flatten().map(|c| (i, c)));
    let mut stacks: [Option<Stack<'_>>; NET_IP_IFACES] = [const { None }; NET_IP_IFACES];
    for (k, (((us, ts), is), ss)) in
        udp_store.iter_mut().zip(tcp_store.iter_mut()).zip(icmp_store.iter_mut()).zip(sock_store.iter_mut()).enumerate()
    {
        let Some((idx, cfg)) = configured.next() else { break };
        if let Ok(st) = Stack::new(idx, cfg, us, ts, is, ss) {
            INSTANCES.lock(|m| m[k] = Some(idx));
            stacks[k] = Some(st);
        }
    }

    let mut sockets = socket::NetSide::new();
    loop {
        let mut more = core.round();
        sockets.service(&mut stacks);
        for st in stacks.iter_mut().flatten() {
            st.poll();
        }
        sockets.service(&mut stacks);
        more |= core.round();
        let mut delay = stacks.iter_mut().flatten().filter_map(|s| s.delay_ticks()).min();
        if sockets.busy() {
            // Data is waiting on pool space or socket buffers: retry next tick rather
            // than spinning (which would starve lower-priority tasks).
            delay = Some(delay.map_or(1, |d| d.min(1)));
        }
        core.wait(more, delay);
    }
}
