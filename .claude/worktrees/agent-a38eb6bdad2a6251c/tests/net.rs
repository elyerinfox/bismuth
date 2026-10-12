//! Network subsystem: buffers, core, hooks, rings, and two IP stacks over a simulated wire.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex as StdMutex;

use bismuth::driver::ioctl;
use bismuth::net::drivers::{Loopback, Wire, WireEnd};
use bismuth::net::hook::{Counter, Firewall, Match, Steer};
use bismuth::net::ip::{self, IpConfig};
use bismuth::net::socket::{TcpListener, TcpStream, UdpSocket};
use bismuth::net::{self, APP_POOL, Dir, IfIndex, NetCaps, NetNode, NetRing, PacketBuf, SoftRing, TX_POOL};
use bismuth::sim;
use bismuth::task;
use bismuth::{Error, Timeout};

/// Tests in this file share global logs; run them one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0A];
const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0B];

fn frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

#[test]
fn packet_buffer_headroom_and_zero_copy_payload() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let before = TX_POOL.available();
        let mut p = TX_POOL.alloc_from(b"payload", Timeout::NoWait).unwrap();
        assert_eq!(TX_POOL.available(), before - 1);
        p.push_header(4).unwrap().copy_from_slice(b"HDR:");
        assert_eq!(p.data(), b"HDR:payload");
        p.pull_header(4).unwrap();
        assert_eq!(p.data(), b"payload");
        static ASSET: &[u8] = b"<html>flash-resident</html>";
        p.attach_static(ASSET).unwrap();
        assert_eq!(p.total_len(), 7 + ASSET.len());
        assert_eq!(p.append(b"x"), Err(Error::Overflow)); // linear part is sealed
        p.linearize().unwrap();
        assert_eq!(p.ext(), None);
        assert!(p.data().ends_with(b"</html>"));
        drop(p);
        assert_eq!(TX_POOL.available(), before);
        assert!(TX_POOL.stats().high_water >= 1);
    });
}

static LO: Loopback<16> = Loopback::new();
static LO_COUNT: Counter = Counter::new("lo-count");
static GOT: StdMutex<Vec<(u8, Vec<u8>)>> = StdMutex::new(Vec::new());

struct EchoNode;
impl NetNode for EchoNode {
    fn name(&self) -> &'static str {
        "custom-88b5"
    }
    fn receive(&self, ifindex: IfIndex, pkt: PacketBuf) {
        GOT.lock().unwrap().push((ifindex.0, pkt.data()[14..].to_vec()));
    }
}
static ECHO_NODE: EchoNode = EchoNode;

#[test]
fn loopback_custom_protocol_node_and_counter_hook() {
    let _serial = serial();
    GOT.lock().unwrap().clear();
    sim::run_to_completion(|| {
        let lo = net::register("lo", &LO).unwrap();
        net::attach_hook(lo, Dir::In, &LO_COUNT).unwrap();
        net::register_protocol(0x88B5, &ECHO_NODE).unwrap();
        net::start().unwrap();
        task::Builder::new("app").priority(3).spawn(|_| {
            let lo = net::find("lo").unwrap();
            for i in 0..3u8 {
                let p = TX_POOL.alloc_from(&frame([0; 6], [0; 6], 0x88B5, &[i; 4]), Timeout::Forever).unwrap();
                net::transmit(lo, p).unwrap();
            }
            task::sleep_ticks(5);
            let s = net::stats(lo).unwrap();
            assert_eq!((s.tx_packets, s.rx_packets), (3, 3));
        }, 0).unwrap();
    });
    let got = GOT.lock().unwrap().clone();
    assert_eq!(got, vec![(0, vec![0; 4]), (0, vec![1; 4]), (0, vec![2; 4])]);
    assert_eq!(LO_COUNT.packets(Dir::In), 3);
}

static LO2: Loopback<64> = Loopback::new();

#[test]
fn rx_budget_bounds_work_per_round() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let lo = net::register("lo2", &LO2).unwrap();
        net::start().unwrap();
        task::Builder::new("flood").priority(25).spawn(|lo| {
            let lo = IfIndex(lo as u8);
            // Higher priority than the net task: queue a burst bigger than the budget.
            for _ in 0..(bismuth::config::NET_BUDGET + 8).min(bismuth::config::NET_TXQ_LEN * 2) {
                let mut p = TX_POOL.alloc_from(&frame([0; 6], [0; 6], 0x9000, b"x"), Timeout::Forever).unwrap();
                p.meta.prio = 7; // high band for half of them
                let _ = net::transmit(lo, p);
                let p = TX_POOL.alloc_from(&frame([0; 6], [0; 6], 0x9000, b"y"), Timeout::Forever).unwrap();
                let _ = net::transmit(lo, p);
            }
            task::sleep_ticks(10);
            let s = net::stats(lo).unwrap();
            assert!(s.tx_packets > 0 && s.rx_packets == s.tx_packets, "{s:?}");
            assert_eq!(s.rx_no_proto, s.rx_packets); // nobody handles EtherType 0x9000
        }, lo.0 as usize).unwrap();
    });
}

static RING: NetRing<8> = NetRing::new();
static STEER: Steer = Steer::new(Match::EtherType(0x88B6), &RING);
static LO3: Loopback<16> = Loopback::new();

#[test]
fn steer_hook_delivers_zero_copy_to_netring_and_app_forwards() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let lo = net::register("lo3", &LO3).unwrap();
        net::attach_hook(lo, Dir::In, &STEER).unwrap();
        net::start().unwrap();
        task::Builder::new("edge-app").priority(5).spawn(|lo| {
            let lo = IfIndex(lo as u8);
            let p = TX_POOL.alloc_from(&frame([0; 6], [0; 6], 0x88B6, b"sensor:42"), Timeout::Forever).unwrap();
            net::transmit(lo, p).unwrap();
            // The very same pool block arrives here, untouched by any copy.
            let mut pkt = RING.recv(Timeout::Ticks(10)).unwrap();
            assert_eq!(pkt.pool_name(), "net-tx");
            assert_eq!(&pkt.data()[14..], b"sensor:42");
            // Process in place and forward with a different EtherType (not steered).
            pkt.data_mut()[12..14].copy_from_slice(&0x88B7u16.to_be_bytes());
            RING.transmit(lo, pkt).unwrap();
            task::sleep_ticks(5);
            assert_eq!(RING.delivered(), 1);
            assert_eq!(net::stats(lo).unwrap().rx_packets, 2);
        }, lo.0 as usize).unwrap();
    });
}

/// Two hosts, A (10.0.0.1) and B (10.0.0.2), on one simulated cable.
macro_rules! two_hosts {
    ($wire:ident, $a:ident, $b:ident, $caps_a:expr) => {
        static $wire: Wire = Wire::new();
        static $a: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&$wire, 0, MAC_A).with_caps($caps_a));
        static $b: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&$wire, 1, MAC_B));
    };
}

fn setup_two_hosts(a: &'static dyn net::NetDevice, b: &'static dyn net::NetDevice) -> (IfIndex, IfIndex) {
    let ia = net::register("eth-a", a).unwrap();
    let ib = net::register("eth-b", b).unwrap();
    ip::configure(ia, IpConfig { addr: [10, 0, 0, 1], prefix_len: 24, gateway: None }).unwrap();
    ip::configure(ib, IpConfig { addr: [10, 0, 0, 2], prefix_len: 24, gateway: None }).unwrap();
    net::start().unwrap();
    (ia, ib)
}

two_hosts!(WIRE_U, UA, UB, NetCaps::NONE);

#[test]
fn udp_echo_between_two_stacks() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let (ia, ib) = setup_two_hosts(&UA, &UB);
        task::Builder::new("echo-server").priority(5).spawn(move |ib| {
            let s = UdpSocket::bind_on(IfIndex(ib as u8), 7).unwrap();
            let mut buf = [0u8; 64];
            let (n, from) = s.recv_from(&mut buf, Timeout::Forever).unwrap();
            assert_eq!(from, SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 40000));
            s.send_to(&buf[..n], from).unwrap();
            task::sleep_ticks(5);
        }, ib.0 as usize).unwrap();
        task::Builder::new("client").priority(4).spawn(move |ia| {
            let s = UdpSocket::bind_on(IfIndex(ia as u8), 40000).unwrap();
            s.send_to(b"hello edge", SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 7)).unwrap();
            let mut buf = [0u8; 64];
            let (n, from) = s.recv_from(&mut buf, Timeout::ms(1000)).unwrap();
            assert_eq!(&buf[..n], b"hello edge");
            assert_eq!(from.port(), 7);
        }, ia.0 as usize).unwrap();
    });
    assert!(WIRE_U.frames.load(std::sync::atomic::Ordering::Relaxed) >= 4); // ARP + datagrams
}

two_hosts!(WIRE_T, TA, TB, NetCaps::NONE);

#[test]
fn tcp_connect_transfer_and_close() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let (ia, ib) = setup_two_hosts(&TA, &TB);
        task::Builder::new("server").priority(5).spawn(move |ib| {
            let mut l = TcpListener::bind_on(IfIndex(ib as u8), 8080).unwrap();
            let conn = l.accept(Timeout::Forever).unwrap();
            let mut total = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = conn.read(&mut buf, Timeout::ms(5000)).unwrap();
                if n == 0 {
                    break; // client closed
                }
                total.extend_from_slice(&buf[..n]);
                conn.write_all(&buf[..n].to_ascii_uppercase()).unwrap();
            }
            assert_eq!(total.len(), 3000);
        }, ib.0 as usize).unwrap();
        task::Builder::new("client").priority(4).spawn(move |ia| {
            let to = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 8080);
            let c = TcpStream::connect_on(IfIndex(ia as u8), to, Timeout::ms(2000)).unwrap();
            // Larger than one packet block and than the socket buffer on small configs.
            let data: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
            c.write_all(&data).unwrap();
            let mut echoed = Vec::new();
            let mut buf = [0u8; 512];
            while echoed.len() < data.len() {
                let n = c.read(&mut buf, Timeout::ms(5000)).unwrap();
                assert!(n > 0, "unexpected EOF");
                echoed.extend_from_slice(&buf[..n]);
            }
            assert_eq!(echoed, data.to_ascii_uppercase());
            c.close();
            task::sleep_ms(100);
        }, ia.0 as usize).unwrap();
    });
}

#[test]
fn tcp_connect_to_closed_port_fails() {
    let _serial = serial();
    two_hosts!(WIRE_R, RA, RB, NetCaps::NONE);
    sim::run_to_completion(|| {
        let (ia, _) = setup_two_hosts(&RA, &RB);
        task::Builder::new("client").priority(4).spawn(move |ia| {
            let to = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9999);
            let r = TcpStream::connect_on(IfIndex(ia as u8), to, Timeout::ms(2000));
            assert!(r.is_err(), "connect to a closed port must fail");
        }, ia.0 as usize).unwrap();
    });
}

two_hosts!(WIRE_C, CA, CB, NetCaps::RX_CSUM);

#[test]
fn software_checksum_fallback_and_runtime_offload_toggle() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let (ia, ib) = setup_two_hosts(&CA, &CB);
        task::Builder::new("t").priority(4).spawn(move |arg| {
            let (ia, ib) = (IfIndex((arg >> 8) as u8), IfIndex(arg as u8));
            // A claims RX checksum offload; turn it off so the core verifies in software.
            assert_eq!(net::info(ia).unwrap().offloads, NetCaps::RX_CSUM);
            assert_eq!(net::set_offloads(ia, NetCaps::NONE).unwrap(), NetCaps::NONE);
            let rx = UdpSocket::bind_on(ia, 5000).unwrap();
            let tx = UdpSocket::bind_on(ib, 5001).unwrap();
            let to = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);
            // Warm up ARP, then corrupt exactly one datagram on the wire.
            tx.send_to(b"first", to).unwrap();
            let mut buf = [0u8; 32];
            assert_eq!(rx.recv_from(&mut buf, Timeout::ms(500)).unwrap().0, 5);
            WIRE_C.corrupt_next(1);
            tx.send_to(b"corrupted", to).unwrap();
            tx.send_to(b"intact", to).unwrap();
            let (n, _) = rx.recv_from(&mut buf, Timeout::ms(500)).unwrap();
            assert_eq!(&buf[..n], b"intact");
            assert_eq!(net::stats(ia).unwrap().rx_csum_errors, 1);
        }, ((ia.0 as usize) << 8) | ib.0 as usize).unwrap();
    });
}

two_hosts!(WIRE_F, FA, FB, NetCaps::NONE);
static DENY_9: Firewall<1> = Firewall::deny(Dir::In, [Match::UdpDstPort(9)]);

#[test]
fn firewall_hook_drops_matching_inbound_traffic() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let (ia, ib) = setup_two_hosts(&FA, &FB);
        net::attach_hook(ib, Dir::In, &DENY_9).unwrap();
        task::Builder::new("t").priority(4).spawn(move |arg| {
            let (ia, ib) = (IfIndex((arg >> 8) as u8), IfIndex(arg as u8));
            let discard = UdpSocket::bind_on(ib, 9).unwrap();
            let allowed = UdpSocket::bind_on(ib, 10).unwrap();
            let tx = UdpSocket::bind_on(ia, 0).unwrap();
            let b = |p| SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), p);
            tx.send_to(b"blocked", b(9)).unwrap();
            tx.send_to(b"allowed", b(10)).unwrap();
            let mut buf = [0u8; 16];
            assert_eq!(allowed.recv_from(&mut buf, Timeout::ms(500)).unwrap().0, 7);
            assert_eq!(discard.recv_from(&mut buf, Timeout::ms(100)), Err(Error::Timeout));
            assert_eq!(DENY_9.dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
            assert_eq!(net::stats(ib).unwrap().hook_drops, 1);
        }, ((ia.0 as usize) << 8) | ib.0 as usize).unwrap();
    });
}

two_hosts!(WIRE_K, KA, KB, NetCaps::NONE);

#[test]
fn control_plane_via_dev_node_and_middleware() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let (ia, _ib) = setup_two_hosts(&KA, &KB);
        task::Builder::new("t").priority(4).spawn(move |ia| {
            let dev = net::control_device(IfIndex(ia as u8)).unwrap();
            assert_eq!(dev.ioctl(ioctl::NET_GET_MTU, 0), Ok(1500));
            assert_eq!(dev.ioctl(ioctl::NET_GET_HWADDR, 0), Ok(0x02_0000_0000_0A));
            assert_eq!(dev.ioctl(ioctl::NET_GET_LINK, 0).unwrap() & 1, 1);
            let mut names = [""; 4];
            let n = dev.chain(&mut names).unwrap();
            assert_eq!(&names[..n], ["link-guard"]);
            // Raw frame write through /dev/eth-a (AF_PACKET style).
            let f = frame(MAC_B, MAC_A, 0x88B5, b"raw");
            assert_eq!(dev.write(&f), Ok(f.len()));
            // Link down: the driver's LinkGuard middleware refuses raw writes.
            WIRE_K.set_link(false);
            assert_eq!(dev.write(&f), Err(Error::NotReady));
            WIRE_K.set_link(true);
            // Administratively down via power management.
            dev.set_power(bismuth::driver::PowerState::Suspended).unwrap();
            assert!(!net::info(IfIndex(ia as u8)).unwrap().up);
            assert_eq!(dev.write(&f), Err(Error::NotReady));
            task::sleep_ticks(5);
            assert_eq!(APP_POOL.available(), APP_POOL.capacity());
        }, ia.0 as usize).unwrap();
    });
}
