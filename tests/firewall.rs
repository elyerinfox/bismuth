//! Packet filter: RuleSet + ConnTrack over two IP stacks on a simulated wire.

#![cfg(feature = "net-filter")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex as StdMutex;

use bismuth::net::csum;
use bismuth::net::drivers::{Wire, WireEnd};
use bismuth::net::filter::{Action, ConnMask, ConnTrack, Ip4Prefix, MatchExpr, Rule, RuleSet, block, pass};
use bismuth::net::hook::Dir;
use bismuth::net::ip::{self, IpConfig};
use bismuth::net::socket::UdpSocket;
use bismuth::net::{self, IfIndex, SoftRing};
use bismuth::{Error, Timeout, sim, task};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 0xA];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 0xB];

// Host B's inbound policy: allow CoAP (UDP/5683), drop everything else.
static FW_IN: RuleSet<2> = RuleSet::new(
    Dir::In,
    [Rule::new().udp().dport(5683).accept().log(), Rule::new().accept().drop().log()],
    Action::Drop,
);

static WIRE: Wire = Wire::new();
static ETH_A: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 0, MAC_A));
static ETH_B: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 1, MAC_B));

fn two_hosts() -> (IfIndex, IfIndex) {
    let a = net::register("fa", &ETH_A).unwrap();
    let b = net::register("fb", &ETH_B).unwrap();
    ip::configure(a, IpConfig { addr: [10, 0, 0, 1], prefix_len: 24, gateway: None }).unwrap();
    ip::configure(b, IpConfig { addr: [10, 0, 0, 2], prefix_len: 24, gateway: None }).unwrap();
    (a, b)
}

#[test]
fn ruleset_allows_one_port_and_drops_the_rest() {
    let _g = serial();
    sim::run_to_completion(|| {
        let (ia, ib) = two_hosts();
        net::attach_hook(ib, Dir::In, &FW_IN).unwrap();
        net::start().unwrap();
        task::Builder::new("server").priority(5).spawn(move |ib| {
            let ib = IfIndex(ib as u8);
            let coap = UdpSocket::bind_on(ib, 5683).unwrap();
            let other = UdpSocket::bind_on(ib, 9999).unwrap();
            let mut buf = [0u8; 32];
            // CoAP datagram is allowed through.
            assert_eq!(coap.recv_from(&mut buf, Timeout::ms(1000)).map(|(n, _)| n), Ok(4));
            // The port-9999 datagram is dropped by the firewall → times out.
            assert_eq!(other.recv_from(&mut buf, Timeout::ms(300)), Err(Error::Timeout));
        }, ib.0 as usize).unwrap();
        task::Builder::new("client").priority(4).spawn(move |ia| {
            let ia = IfIndex(ia as u8);
            let s = UdpSocket::bind_on(ia, 4000).unwrap();
            let to = |p| SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), p);
            s.send_to(b"ping", to(5683)).unwrap();
            task::sleep_ticks(20);
            s.send_to(b"nope", to(9999)).unwrap();
            task::sleep_ticks(50);
        }, ia.0 as usize).unwrap();
    });
    use std::sync::atomic::Ordering;
    let _ = Ordering::Relaxed;
    assert!(FW_IN.passed() >= 1, "CoAP passed");
    assert!(FW_IN.dropped() >= 1, "port 9999 dropped");
    assert!(FW_IN.hits(0) >= 1 && FW_IN.hits(1) >= 1, "both rules logged hits");
}

// Stateful: drop inbound NEW connections, but allow ESTABLISHED replies to flows B started.
static CT: ConnTrack<16> = ConnTrack::new(10_000);
static FW_STATE: RuleSet<2> = RuleSet::new(
    Dir::In,
    [Rule::new().state(ConnMask::ESTABLISHED).accept(), Rule::new().accept().drop().log()],
    Action::Drop,
);
static WIRE2: Wire = Wire::new();
static ETH_C: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE2, 0, MAC_A));
static ETH_D: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE2, 1, MAC_B));

#[test]
fn conntrack_allows_established_replies() {
    let _g = serial();
    sim::run_to_completion(|| {
        let c = net::register("fc", &ETH_C).unwrap();
        let d = net::register("fd", &ETH_D).unwrap();
        ip::configure(c, IpConfig { addr: [10, 0, 0, 1], prefix_len: 24, gateway: None }).unwrap();
        ip::configure(d, IpConfig { addr: [10, 0, 0, 2], prefix_len: 24, gateway: None }).unwrap();
        // On host C (10.0.0.1): track flows, then only accept established inbound.
        net::attach_hook(c, Dir::In, &CT).unwrap(); // conntrack runs first
        net::attach_hook(c, Dir::In, &FW_STATE).unwrap();
        net::attach_hook(c, Dir::Out, &CT).unwrap(); // see our own outbound to establish state
        net::start().unwrap();
        task::Builder::new("peer").priority(5).spawn(move |d| {
            let d = IfIndex(d as u8);
            let s = UdpSocket::bind_on(d, 7000).unwrap();
            let mut buf = [0u8; 32];
            // Wait for C's request, then reply — the reply is ESTABLISHED, allowed in.
            let (n, from) = s.recv_from(&mut buf, Timeout::ms(1000)).unwrap();
            assert_eq!(n, 3);
            s.send_to(b"PONG", from).unwrap();
        }, d.0 as usize).unwrap();
        task::Builder::new("initiator").priority(4).spawn(move |c| {
            let c = IfIndex(c as u8);
            let s = UdpSocket::bind_on(c, 6000).unwrap();
            let to = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 7000);
            s.send_to(b"REQ", to).unwrap(); // outbound → conntrack creates the flow
            let mut buf = [0u8; 32];
            // The reply comes back inbound and is ESTABLISHED, so the firewall lets it in.
            let (n, _) = s.recv_from(&mut buf, Timeout::ms(1000)).unwrap();
            assert_eq!(&buf[..n], b"PONG");
        }, c.0 as usize).unwrap();
    });
    assert!(CT.created() >= 1, "a flow was tracked");
}

#[test]
fn pf_style_builders_compile_and_match() {
    let _g = serial();
    // pf-style rules: block in everything, pass CoAP from the local subnet quick.
    static PF: RuleSet<2> = RuleSet::new(
        Dir::In,
        [
            pass(MatchExpr { proto: Some(csum::PROTO_UDP), src: Ip4Prefix::new([10, 0, 0, 0], 24), ..MatchExpr::ANY }),
            block(MatchExpr::ANY),
        ],
        Action::Drop,
    );
    sim::run_to_completion(|| {
        let (_a, ib) = two_hosts();
        net::attach_hook(ib, Dir::In, &PF).unwrap();
        net::start().unwrap();
        task::Builder::new("srv").priority(5).spawn(move |ib| {
            let ib = IfIndex(ib as u8);
            let s = UdpSocket::bind_on(ib, 5683).unwrap();
            let mut buf = [0u8; 16];
            assert_eq!(s.recv_from(&mut buf, Timeout::ms(1000)).map(|(n, _)| n), Ok(2));
        }, ib.0 as usize).unwrap();
        task::Builder::new("cli").priority(4).spawn(move |_| {
            let s = UdpSocket::bind_on(IfIndex(0), 4000).unwrap();
            s.send_to(b"hi", SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5683)).unwrap();
            task::sleep_ticks(30);
        }, 0).unwrap();
    });
    assert!(PF.passed() >= 1);
}

// Regression: an unsolicited remote peer sending two packets must NOT get the second
// marked ESTABLISHED (direction-blind ConnTrack would let it bypass a drop-NEW policy).
static CT_B: ConnTrack<8> = ConnTrack::new(10_000);
static FW_B: RuleSet<2> = RuleSet::named(
    "stateful-in",
    Dir::In,
    [Rule::new().state(ConnMask::ESTABLISHED).accept(), Rule::new().accept().drop().log()],
    Action::Drop,
);
static WIRE3: Wire = Wire::new();
static ETH_E: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE3, 0, MAC_A));
static ETH_F: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE3, 1, MAC_B));

#[test]
fn conntrack_does_not_promote_unsolicited_inbound() {
    let _g = serial();
    sim::run_to_completion(|| {
        let e = net::register("fe", &ETH_E).unwrap();
        let f = net::register("ff", &ETH_F).unwrap();
        ip::configure(e, IpConfig { addr: [10, 0, 0, 1], prefix_len: 24, gateway: None }).unwrap();
        ip::configure(f, IpConfig { addr: [10, 0, 0, 2], prefix_len: 24, gateway: None }).unwrap();
        // Host E tracks and only accepts ESTABLISHED inbound — but never initiates.
        net::attach_hook(e, Dir::In, &CT_B).unwrap();
        net::attach_hook(e, Dir::In, &FW_B).unwrap();
        net::attach_hook(e, Dir::Out, &CT_B).unwrap();
        net::start().unwrap();
        task::Builder::new("listener").priority(5).spawn(move |e| {
            let e = IfIndex(e as u8);
            let s = UdpSocket::bind_on(e, 22).unwrap();
            let mut buf = [0u8; 32];
            // Two unsolicited inbound datagrams: BOTH must be dropped by the firewall.
            assert_eq!(s.recv_from(&mut buf, Timeout::ms(400)), Err(Error::Timeout));
        }, e.0 as usize).unwrap();
        task::Builder::new("attacker").priority(4).spawn(move |f| {
            let f = IfIndex(f as u8);
            let s = UdpSocket::bind_on(f, 6666).unwrap();
            let to = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 22);
            s.send_to(b"a", to).unwrap();
            task::sleep_ticks(20);
            s.send_to(b"b", to).unwrap(); // the bypass would let THIS one through
            task::sleep_ticks(50);
        }, f.0 as usize).unwrap();
    });
    // Both unsolicited inbound UDP packets were dropped (the socket timed out above,
    // proving neither was promoted to ESTABLISHED). ARP frames pass through as non-IPv4,
    // so `passed()` may be >0 — the security property is that no UDP reached the socket.
    assert!(FW_B.dropped() >= 2, "both unsolicited packets dropped: {}", FW_B.dropped());
}
