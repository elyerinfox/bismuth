//! Packet filtering: a compact, static firewall engine on top of the [`PacketHook`]
//! chain, with iptables/pf-style builders that all lower to the same objects.
//!
//! The data plane already has pfil/XDP-style hooks ([`crate::net::hook`]); this adds a
//! **[`RuleSet`]**: a first-match-wins array of [`Rule`]s plus a default policy, exactly
//! like an iptables chain or a pf ruleset of `quick` rules. Each [`Rule`] is a
//! conjunctive [`MatchExpr`] (IPv4 src/dst prefix, protocol, port ranges, interface,
//! direction, connection state) and an [`Action`]. There is no bytecode VM and no heap —
//! one 5-tuple parse per packet ([`csum::inet_tuple`](crate::net::csum)) then
//! up to `N` cheap comparisons, in the single `net` task, so no locking.
//!
//! Optional stateful filtering is a separate [`ConnTrack`] hook that stamps a
//! connection-state mark into [`PacketMeta`](crate::net::buf::PacketMeta) for a later
//! `RuleSet` to match with [`ConnMask`].
//!
//! The front-end builders ([`Rule::new`] + const chaining, the pf-style [`pass`]/[`block`]
//! helpers) are different spellings of one enforcement engine — the same "one core, many
//! compat front-ends" shape as the driver layer's POSIX/FreeRTOS/embedded-hal views.
//!
//! Classification: L3 services · net: packet filter · safe · net-filter

use core::sync::atomic::{AtomicU32, Ordering};

use super::csum::{self, InetTuple};
use super::hook::{Dir, PacketHook, Verdict};
use super::ring::RingSink;
use super::{IfIndex, PacketBuf};
use crate::kernel::cell::IrqCell;
use crate::kernel::time;

/// An IPv4 address + prefix length. `len == 0` matches anything.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ip4Prefix {
    pub addr: [u8; 4],
    pub len: u8,
}

impl Ip4Prefix {
    pub const ANY: Ip4Prefix = Ip4Prefix { addr: [0; 4], len: 0 };

    pub const fn host(a: [u8; 4]) -> Self {
        Ip4Prefix { addr: a, len: 32 }
    }

    pub const fn new(a: [u8; 4], len: u8) -> Self {
        Ip4Prefix { addr: a, len }
    }

    fn contains(&self, ip: [u8; 4]) -> bool {
        let mask = if self.len == 0 { 0 } else { u32::MAX << (32 - self.len.min(32) as u32) };
        u32::from_be_bytes(ip) & mask == u32::from_be_bytes(self.addr) & mask
    }
}

/// An inclusive port range. `(0, 65535)` matches anything.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub const ANY: PortRange = PortRange { lo: 0, hi: u16::MAX };

    pub const fn only(p: u16) -> Self {
        PortRange { lo: p, hi: p }
    }

    pub const fn range(lo: u16, hi: u16) -> Self {
        PortRange { lo, hi }
    }

    fn contains(&self, p: u16) -> bool {
        self.lo <= p && p <= self.hi
    }
}

/// Connection-state mask (set bits = acceptable states); empty = don't care.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnMask(pub u8);

impl ConnMask {
    pub const ANY: ConnMask = ConnMask(0);
    pub const NEW: ConnMask = ConnMask(1 << 0);
    pub const ESTABLISHED: ConnMask = ConnMask(1 << 1);
    pub const INVALID: ConnMask = ConnMask(1 << 2);
}

/// A conjunctive match: every non-wildcard field must hold.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MatchExpr {
    pub ifindex: Option<u8>,
    pub ethertype: Option<u16>,
    pub proto: Option<u8>,
    pub src: Ip4Prefix,
    pub dst: Ip4Prefix,
    pub sport: PortRange,
    pub dport: PortRange,
    pub state: ConnMask,
}

impl MatchExpr {
    /// Everything-wildcard; builders start here.
    pub const ANY: MatchExpr = MatchExpr {
        ifindex: None,
        ethertype: None,
        proto: None,
        src: Ip4Prefix::ANY,
        dst: Ip4Prefix::ANY,
        sport: PortRange::ANY,
        dport: PortRange::ANY,
        state: ConnMask::ANY,
    };

    fn matches(&self, k: &InetTuple, ifindex: IfIndex, ct: ConnMask) -> bool {
        // An IP-filter rule (no explicit ethertype) only matches IPv4 frames, so a
        // catch-all `MatchExpr::ANY` never touches ARP or other L2 traffic — exactly as
        // the Linux IPv4 `filter` table never sees ARP. Filter L2 by setting `ethertype`.
        if self.ethertype.is_none() && k.ethertype != Some(csum::ETHERTYPE_IPV4) {
            return false;
        }
        self.ifindex.is_none_or(|i| i == ifindex.0)
            && self.ethertype.is_none_or(|t| Some(t) == k.ethertype)
            && self.proto.is_none_or(|p| Some(p) == k.proto)
            && self.src.contains(k.src)
            && self.dst.contains(k.dst)
            && self.sport.contains(k.sport)
            && self.dport.contains(k.dport)
            && (self.state.0 == 0 || self.state.0 & ct.0 != 0)
    }
}

/// What a matching rule does. Terminal actions stop evaluation (first-match-wins).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// ACCEPT / pass → `Verdict::Pass`.
    Accept,
    /// DROP / block → `Verdict::Drop`.
    Drop,
    /// LOG-only / non-terminal: fall through to the next rule.
    Continue,
}

/// One rule: a match plus an action, optionally counted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub m: MatchExpr,
    pub action: Action,
    pub log: bool,
}

impl Rule {
    /// A wildcard, non-terminal rule; chain the `const` builders to constrain it, then
    /// finish with [`accept`](Self::accept)/[`drop`](Self::drop).
    pub const fn new() -> Self {
        Rule { m: MatchExpr::ANY, action: Action::Continue, log: false }
    }

    pub const fn proto(mut self, p: u8) -> Self {
        self.m.proto = Some(p);
        self
    }
    pub const fn tcp(self) -> Self {
        self.proto(csum::PROTO_TCP)
    }
    pub const fn udp(self) -> Self {
        self.proto(csum::PROTO_UDP)
    }
    pub const fn dport(mut self, p: u16) -> Self {
        self.m.dport = PortRange::only(p);
        self
    }
    pub const fn dport_range(mut self, lo: u16, hi: u16) -> Self {
        self.m.dport = PortRange::range(lo, hi);
        self
    }
    pub const fn sport(mut self, p: u16) -> Self {
        self.m.sport = PortRange::only(p);
        self
    }
    pub const fn src(mut self, p: Ip4Prefix) -> Self {
        self.m.src = p;
        self
    }
    pub const fn dst(mut self, p: Ip4Prefix) -> Self {
        self.m.dst = p;
        self
    }
    pub const fn iface(mut self, idx: u8) -> Self {
        self.m.ifindex = Some(idx);
        self
    }
    pub const fn state(mut self, s: ConnMask) -> Self {
        self.m.state = s;
        self
    }
    pub const fn log(mut self) -> Self {
        self.log = true;
        self
    }
    pub const fn accept(mut self) -> Self {
        self.action = Action::Accept;
        self
    }
    pub const fn drop(mut self) -> Self {
        self.action = Action::Drop;
        self
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self::new()
    }
}

/// pf-style `pass` rule (accept, matching `m`).
pub const fn pass(m: MatchExpr) -> Rule {
    Rule { m, action: Action::Accept, log: false }
}

/// pf-style `block` rule (drop, matching `m`).
pub const fn block(m: MatchExpr) -> Rule {
    Rule { m, action: Action::Drop, log: true }
}

/// A first-match-wins rule chain, attached per direction like
/// [`Firewall`](crate::net::hook::Firewall).
pub struct RuleSet<const N: usize> {
    name: &'static str,
    dir: Dir,
    rules: [Rule; N],
    default: Action,
    hits: [AtomicU32; N],
    dropped: AtomicU32,
    passed: AtomicU32,
    tap: Option<&'static dyn RingSink>,
}

impl<const N: usize> RuleSet<N> {
    /// A rule chain for `dir` with the given rules and default (chain policy).
    pub const fn new(dir: Dir, rules: [Rule; N], default: Action) -> Self {
        Self::named("ruleset", dir, rules, default)
    }

    /// Like [`new`](Self::new) but with a distinct hook name, so two rule sets on one
    /// interface can be told apart by `detach_hook`.
    pub const fn named(name: &'static str, dir: Dir, rules: [Rule; N], default: Action) -> Self {
        RuleSet {
            name,
            dir,
            rules,
            default,
            hits: [const { AtomicU32::new(0) }; N],
            dropped: AtomicU32::new(0),
            passed: AtomicU32::new(0),
            tap: None,
        }
    }

    /// Dropped packets can be mirrored to a ring for a pcap/logger task; set before
    /// registering. (Only drops are mirrored, not every `.log()` hit.)
    pub const fn with_tap(mut self, tap: &'static dyn RingSink) -> Self {
        self.tap = Some(tap);
        self
    }

    /// Hit count for rule `i` (only rules with `log` set are counted).
    pub fn hits(&self, i: usize) -> u32 {
        self.hits.get(i).map_or(0, |h| h.load(Ordering::Relaxed))
    }

    pub fn dropped(&self) -> u32 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn passed(&self) -> u32 {
        self.passed.load(Ordering::Relaxed)
    }
}

impl<const N: usize> PacketHook for RuleSet<N> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn on_packet(&self, dir: Dir, ifindex: IfIndex, pkt: PacketBuf) -> Verdict {
        if dir != self.dir {
            return Verdict::Pass(pkt);
        }
        let key = csum::inet_tuple(pkt.data()).unwrap_or_default();
        let ct = ConnMask(pkt.meta.ct_mark);
        let mut matched: Option<Action> = None;
        for (i, r) in self.rules.iter().enumerate() {
            if r.m.matches(&key, ifindex, ct) {
                if r.log {
                    self.hits[i].fetch_add(1, Ordering::Relaxed);
                }
                match r.action {
                    Action::Continue => continue,
                    terminal => {
                        matched = Some(terminal);
                        break;
                    }
                }
            }
        }
        // This is an IPv4 filter: the default policy applies only to IPv4 frames. A
        // non-IPv4 frame (e.g. ARP) that no explicit rule matched passes through, so
        // address resolution is never blocked by an IP firewall (as with iptables).
        let is_ipv4 = key.ethertype == Some(csum::ETHERTYPE_IPV4);
        let act = matched.unwrap_or(if is_ipv4 { self.default } else { Action::Accept });
        match act {
            Action::Accept | Action::Continue => {
                self.passed.fetch_add(1, Ordering::Relaxed);
                Verdict::Pass(pkt)
            }
            Action::Drop => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                // Mirror the dropped frame to a tap ring if configured (best-effort).
                if let Some(tap) = self.tap {
                    return match tap.deliver(pkt) {
                        Ok(()) => Verdict::Consumed,
                        Err(_) => Verdict::Drop,
                    };
                }
                Verdict::Drop
            }
        }
    }
}

// ----- optional stateful tracking -----

#[derive(Copy, Clone, Default, PartialEq, Eq)]
struct CanonTuple {
    a: [u8; 4],
    b: [u8; 4],
    pa: u16,
    pb: u16,
    proto: u8,
}

impl CanonTuple {
    /// Normalise so both directions of a flow map to the same key.
    fn from(t: &InetTuple) -> Option<Self> {
        let proto = t.proto?;
        let (a, pa, b, pb) = if (t.src, t.sport) <= (t.dst, t.dport) {
            (t.src, t.sport, t.dst, t.dport)
        } else {
            (t.dst, t.dport, t.src, t.sport)
        };
        Some(CanonTuple { a, b, pa, pb, proto })
    }
}

#[derive(Copy, Clone, Default)]
struct Conn {
    key: CanonTuple,
    used: bool,
    /// Whether the packet that opened this flow arrived inbound (`Dir::In`).
    opener_in: bool,
    established: bool,
    last: u64,
}

/// A fixed-size connection tracker. Run it (in-direction) *before* a [`RuleSet`] so the
/// set can match `ConnMask::ESTABLISHED` for return traffic. Never drops.
pub struct ConnTrack<const C: usize> {
    table: IrqCell<[Conn; C]>,
    timeout_ticks: u64,
    created: AtomicU32,
    evicted: AtomicU32,
}

impl<const C: usize> ConnTrack<C> {
    pub const fn new(timeout_ticks: u64) -> Self {
        ConnTrack {
            table: IrqCell::new(
                [Conn { key: CanonTuple { a: [0; 4], b: [0; 4], pa: 0, pb: 0, proto: 0 }, used: false, opener_in: false, established: false, last: 0 }; C],
            ),
            timeout_ticks,
            created: AtomicU32::new(0),
            evicted: AtomicU32::new(0),
        }
    }

    pub fn created(&self) -> u32 {
        self.created.load(Ordering::Relaxed)
    }

    pub fn evicted(&self) -> u32 {
        self.evicted.load(Ordering::Relaxed)
    }

    fn update(&self, k: &CanonTuple, dir: Dir, now: u64) -> ConnMask {
        let inbound = dir == Dir::In;
        self.table.lock(|t| {
            // Existing flow? A flow becomes ESTABLISHED only when a packet arrives in
            // the *opposite* direction from the one that opened it — so an unsolicited
            // remote peer sending several packets never promotes itself past a
            // "drop NEW, accept ESTABLISHED" policy.
            for c in t.iter_mut() {
                if c.used && c.last + self.timeout_ticks >= now && c.key == *k {
                    c.last = now;
                    if inbound != c.opener_in {
                        c.established = true;
                    }
                    return if c.established { ConnMask::ESTABLISHED } else { ConnMask::NEW };
                }
            }
            // New flow: take a free or expired slot, else evict the oldest.
            let mut victim = 0usize;
            let mut oldest = u64::MAX;
            for (i, c) in t.iter_mut().enumerate() {
                if !c.used || c.last + self.timeout_ticks < now {
                    victim = i;
                    break;
                }
                if c.last < oldest {
                    oldest = c.last;
                    victim = i;
                }
            }
            if t[victim].used {
                self.evicted.fetch_add(1, Ordering::Relaxed);
            }
            t[victim] = Conn { key: *k, used: true, opener_in: inbound, established: false, last: now };
            self.created.fetch_add(1, Ordering::Relaxed);
            ConnMask::NEW
        })
    }
}

impl<const C: usize> PacketHook for ConnTrack<C> {
    fn name(&self) -> &'static str {
        "conntrack"
    }

    fn on_packet(&self, dir: Dir, _ifindex: IfIndex, mut pkt: PacketBuf) -> Verdict {
        if let Some(k) = csum::inet_tuple(pkt.data()).as_ref().and_then(CanonTuple::from) {
            let mark = self.update(&k, dir, time::ticks());
            pkt.meta.ct_mark = mark.0;
        }
        Verdict::Pass(pkt)
    }
}
