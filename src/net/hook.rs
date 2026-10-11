//! Packet hooks: "middleware for packets" (FreeBSD pfil / Linux XDP style).
//!
//! The control plane of a network interface uses the regular driver
//! [`Middleware`](crate::driver::Middleware) chain. The data plane is too hot for a
//! request/response chain per packet, so packets instead traverse a *hook chain* that
//! returns a verdict and may take ownership of the packet. Hooks attach exactly like
//! middleware: global hooks first, then per-interface hooks, then hooks contributed by
//! the driver ([`NetDevice::hooks`](super::NetDevice::hooks)).
//!
//! Classification: L3 services · net: packet hooks · safe · net

use core::sync::atomic::{AtomicU32, Ordering};

use super::buf::PacketBuf;
use super::csum;
use super::ring::RingSink;
use super::IfIndex;
use crate::kernel::cell::IrqCell;
use crate::kernel::time;

/// Direction of a packet relative to the interface.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Received from the wire (pfil `LinkIn`).
    In,
    /// About to be transmitted (pfil `LinkOut`).
    Out,
}

/// What happens to a packet after a hook ran.
#[derive(Debug)]
pub enum Verdict {
    /// Continue down the chain with this (possibly modified) packet.
    Pass(PacketBuf),
    /// Discard (counted as a hook drop).
    Drop,
    /// The hook took ownership (e.g. redirected it to a [`NetRing`](super::NetRing)).
    Consumed,
}

/// A data-plane hook.
pub trait PacketHook: Sync {
    fn name(&self) -> &'static str;
    fn on_packet(&self, dir: Dir, ifindex: IfIndex, pkt: PacketBuf) -> Verdict;
}

/// Run `pkt` through a sequence of hook lists; returns the packet if it survived.
pub(crate) fn run_chain(
    lists: &[&[&'static dyn PacketHook]],
    dir: Dir,
    ifindex: IfIndex,
    mut pkt: PacketBuf,
) -> Result<PacketBuf, bool> {
    for list in lists {
        for h in *list {
            match h.on_packet(dir, ifindex, pkt) {
                Verdict::Pass(p) => pkt = p,
                Verdict::Drop => return Err(true),
                Verdict::Consumed => return Err(false),
            }
        }
    }
    Ok(pkt)
}

// ----- built-in hooks -----

/// Counts packets and bytes per direction (telemetry).
pub struct Counter {
    name: &'static str,
    pub packets_in: AtomicU32,
    pub packets_out: AtomicU32,
    pub bytes_in: AtomicU32,
    pub bytes_out: AtomicU32,
}

impl Counter {
    pub const fn new(name: &'static str) -> Self {
        Counter {
            name,
            packets_in: AtomicU32::new(0),
            packets_out: AtomicU32::new(0),
            bytes_in: AtomicU32::new(0),
            bytes_out: AtomicU32::new(0),
        }
    }

    pub fn packets(&self, dir: Dir) -> u32 {
        match dir {
            Dir::In => self.packets_in.load(Ordering::Relaxed),
            Dir::Out => self.packets_out.load(Ordering::Relaxed),
        }
    }
}

impl PacketHook for Counter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn on_packet(&self, dir: Dir, _ifindex: IfIndex, pkt: PacketBuf) -> Verdict {
        let (p, b) = match dir {
            Dir::In => (&self.packets_in, &self.bytes_in),
            Dir::Out => (&self.packets_out, &self.bytes_out),
        };
        p.fetch_add(1, Ordering::Relaxed);
        b.fetch_add(pkt.total_len() as u32, Ordering::Relaxed);
        Verdict::Pass(pkt)
    }
}

/// A match rule for filters and steering.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Match {
    EtherType(u16),
    UdpDstPort(u16),
    TcpDstPort(u16),
}

impl Match {
    pub fn matches(&self, frame: &[u8]) -> bool {
        match *self {
            Match::EtherType(t) => csum::ethertype(frame) == Some(t),
            Match::UdpDstPort(p) => csum::l4_dst_port(frame) == Some((csum::PROTO_UDP, p)),
            Match::TcpDstPort(p) => csum::l4_dst_port(frame) == Some((csum::PROTO_TCP, p)),
        }
    }
}

/// Firewall / ACL: drops packets matching any rule (deny-list) in the given direction.
pub struct Firewall<const N: usize> {
    dir: Dir,
    rules: [Match; N],
    pub dropped: AtomicU32,
}

impl<const N: usize> Firewall<N> {
    pub const fn deny(dir: Dir, rules: [Match; N]) -> Self {
        Firewall { dir, rules, dropped: AtomicU32::new(0) }
    }
}

impl<const N: usize> PacketHook for Firewall<N> {
    fn name(&self) -> &'static str {
        "firewall"
    }

    fn on_packet(&self, dir: Dir, _ifindex: IfIndex, pkt: PacketBuf) -> Verdict {
        if dir == self.dir && self.rules.iter().any(|r| r.matches(pkt.data())) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Verdict::Drop;
        }
        Verdict::Pass(pkt)
    }
}

/// Packet-rate limiter (token bucket refilled every tick window), e.g. DoS protection
/// on the receive path.
pub struct RateLimit {
    dir: Dir,
    max_packets: u32,
    window_ticks: u64,
    state: IrqCell<(u64, u32)>,
    pub dropped: AtomicU32,
}

impl RateLimit {
    pub const fn new(dir: Dir, max_packets: u32, window_ticks: u64) -> Self {
        RateLimit { dir, max_packets, window_ticks, state: IrqCell::new((0, 0)), dropped: AtomicU32::new(0) }
    }
}

impl PacketHook for RateLimit {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    fn on_packet(&self, dir: Dir, _ifindex: IfIndex, pkt: PacketBuf) -> Verdict {
        if dir != self.dir {
            return Verdict::Pass(pkt);
        }
        let now = time::ticks();
        let ok = self.state.lock(|(start, n)| {
            if now >= *start + self.window_ticks {
                *start = now;
                *n = 0;
            }
            *n += 1;
            *n <= self.max_packets
        });
        if ok {
            Verdict::Pass(pkt)
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            Verdict::Drop
        }
    }
}

/// Steers matching received packets to a [`NetRing`](super::NetRing) for zero-copy
/// processing by an application task (AF_XDP / netmap style).
pub struct Steer {
    rule: Match,
    ring: &'static dyn RingSink,
}

impl Steer {
    pub const fn new(rule: Match, ring: &'static dyn RingSink) -> Self {
        Steer { rule, ring }
    }
}

impl PacketHook for Steer {
    fn name(&self) -> &'static str {
        "steer"
    }

    fn on_packet(&self, dir: Dir, _ifindex: IfIndex, pkt: PacketBuf) -> Verdict {
        if dir != Dir::In || !self.rule.matches(pkt.data()) {
            return Verdict::Pass(pkt);
        }
        match self.ring.deliver(pkt) {
            Ok(()) => Verdict::Consumed,
            Err(_) => Verdict::Drop, // ring full: drop rather than stall the net task
        }
    }
}
