//! Internet checksums and the software fallback for checksum offload.
//!
//! The network core asks drivers what they can offload ([`super::NetCaps`]). Whatever
//! the hardware cannot do is done here, so upper layers (and the IP stack) can always
//! assume checksums are filled on transmit and verified on receive.
//!
//! Classification: L3 services · net: checksums · safe · net

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// One's-complement sum of `data` (folded to 16 bits, not inverted), starting at `init`.
pub fn sum(data: &[u8], init: u32) -> u32 {
    let mut acc = init;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u32) << 8;
    }
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    acc
}

/// The Internet checksum (RFC 1071) of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    !(sum(data, 0) as u16)
}

fn pseudo_header(ip: &[u8], proto: u8, l4_len: usize) -> u32 {
    let mut acc = sum(&ip[12..20], 0); // source + destination addresses
    acc += proto as u32;
    acc += l4_len as u32;
    acc
}

/// Locate the IPv4 packet inside an Ethernet frame (skipping one VLAN tag).
fn ipv4_span(frame: &[u8]) -> Option<(usize, usize)> {
    if frame.len() < 14 {
        return None;
    }
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < 18 {
            return None;
        }
        off += 4;
        ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
    }
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = off + 2;
    let b = frame.get(ip..)?;
    if b.len() < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = (b[0] & 0x0F) as usize * 4;
    let total = u16::from_be_bytes([b[2], b[3]]) as usize;
    if ihl < 20 || total < ihl || total > b.len() {
        return None;
    }
    Some((ip, total))
}

/// Result of checking a received frame's checksums.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Check {
    /// Not an IPv4 frame (nothing to verify).
    NotIp,
    Good,
    Bad,
}

/// Verify the IPv4 header and ICMP/UDP/TCP checksums of an Ethernet frame.
pub fn verify_frame(frame: &[u8]) -> Check {
    let Some((ip, total)) = ipv4_span(frame) else { return Check::NotIp };
    let pkt = &frame[ip..ip + total];
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if sum(&pkt[..ihl], 0) != 0xFFFF {
        return Check::Bad;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3FFF;
    if frag != 0 {
        return Check::Good; // fragments: L4 checksum covers the reassembled datagram
    }
    let l4 = &pkt[ihl..];
    let ok = match pkt[9] {
        PROTO_ICMP => sum(l4, 0) == 0xFFFF,
        PROTO_TCP if l4.len() >= 20 => sum(l4, pseudo_header(pkt, PROTO_TCP, l4.len())) == 0xFFFF,
        PROTO_UDP if l4.len() >= 8 => {
            let stored = u16::from_be_bytes([l4[6], l4[7]]);
            stored == 0 || sum(l4, pseudo_header(pkt, PROTO_UDP, l4.len())) == 0xFFFF
        }
        _ => true,
    };
    if ok { Check::Good } else { Check::Bad }
}

/// What to compute when filling checksums in software.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fill {
    pub ipv4: bool,
    pub l4: bool,
}

/// Compute and store the IPv4 header and ICMP/UDP/TCP checksums of an Ethernet frame.
/// Returns `true` if the frame was IPv4.
pub fn fill_frame(frame: &mut [u8], what: Fill) -> bool {
    let Some((ip, total)) = ipv4_span(frame) else { return false };
    let pkt = &mut frame[ip..ip + total];
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if what.ipv4 {
        pkt[10] = 0;
        pkt[11] = 0;
        let c = checksum(&pkt[..ihl]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3FFF;
    if !what.l4 || frag != 0 {
        return true;
    }
    let proto = pkt[9];
    let l4_len = total - ihl;
    let ph = pseudo_header(pkt, proto, l4_len);
    let (_, l4) = pkt.split_at_mut(ihl);
    let field = match proto {
        PROTO_ICMP if l4.len() >= 4 => Some((2, 0)),
        PROTO_TCP if l4.len() >= 20 => Some((16, ph)),
        PROTO_UDP if l4.len() >= 8 => Some((6, ph)),
        _ => None,
    };
    if let Some((at, init)) = field {
        l4[at] = 0;
        l4[at + 1] = 0;
        let mut c = !(sum(l4, init) as u16);
        if proto == PROTO_UDP && c == 0 {
            c = 0xFFFF; // RFC 768: transmitted as all ones
        }
        l4[at..at + 2].copy_from_slice(&c.to_be_bytes());
    }
    true
}

/// The parsed 5-tuple of a frame, for packet filtering / connection tracking.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InetTuple {
    pub ethertype: Option<u16>,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: Option<u8>,
    pub sport: u16,
    pub dport: u16,
    /// TCP flags (SYN/ACK/FIN/RST) for connection tracking; 0 for non-TCP.
    pub tcp_flags: u8,
}

/// Parse an Ethernet frame's IPv4 5-tuple. Non-IPv4 frames yield just the ethertype.
pub fn inet_tuple(frame: &[u8]) -> Option<InetTuple> {
    let et = ethertype(frame);
    let mut t = InetTuple { ethertype: et, ..InetTuple::default() };
    let Some((ip, total)) = ipv4_span(frame) else { return Some(t) };
    let pkt = &frame[ip..ip + total];
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    t.src.copy_from_slice(&pkt[12..16]);
    t.dst.copy_from_slice(&pkt[16..20]);
    let proto = pkt[9];
    t.proto = Some(proto);
    let l4 = &pkt[ihl..];
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1FFF;
    if frag == 0 {
        match proto {
            PROTO_UDP | PROTO_TCP if l4.len() >= 4 => {
                t.sport = u16::from_be_bytes([l4[0], l4[1]]);
                t.dport = u16::from_be_bytes([l4[2], l4[3]]);
                if proto == PROTO_TCP && l4.len() >= 14 {
                    t.tcp_flags = l4[13];
                }
            }
            _ => {}
        }
    }
    Some(t)
}

/// EtherType of a frame (after one optional VLAN tag).
pub fn ethertype(frame: &[u8]) -> Option<u16> {
    if frame.len() < 14 {
        return None;
    }
    let t = u16::from_be_bytes([frame[12], frame[13]]);
    if t == ETHERTYPE_VLAN && frame.len() >= 18 {
        return Some(u16::from_be_bytes([frame[16], frame[17]]));
    }
    Some(t)
}

/// `(protocol, destination port)` of an IPv4 UDP/TCP frame, for steering hooks.
pub fn l4_dst_port(frame: &[u8]) -> Option<(u8, u16)> {
    let (ip, total) = ipv4_span(frame)?;
    let pkt = &frame[ip..ip + total];
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let proto = pkt[9];
    let l4 = &pkt[ihl..];
    match proto {
        PROTO_UDP | PROTO_TCP if l4.len() >= 4 => Some((proto, u16::from_be_bytes([l4[2], l4[3]]))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        // Example from RFC 1071 section 3.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(sum(&data, 0), 0xddf2);
        assert_eq!(checksum(&data), !0xddf2);
    }

    fn udp_frame() -> std::vec::Vec<u8> {
        let mut f = std::vec![0u8; 14 + 20 + 8 + 4];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = &mut f[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(20u16 + 8 + 4).to_be_bytes());
        ip[8] = 64;
        ip[9] = PROTO_UDP;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let udp = &mut ip[20..];
        udp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        udp[2..4].copy_from_slice(&5678u16.to_be_bytes());
        udp[4..6].copy_from_slice(&12u16.to_be_bytes());
        udp[8..12].copy_from_slice(b"ping");
        f
    }

    #[test]
    fn fill_then_verify_roundtrip_and_corruption() {
        let mut f = udp_frame();
        assert_eq!(verify_frame(&f), Check::Bad);
        assert!(fill_frame(&mut f, Fill { ipv4: true, l4: true }));
        assert_eq!(verify_frame(&f), Check::Good);
        assert_eq!(l4_dst_port(&f), Some((PROTO_UDP, 5678)));
        f[14 + 28] ^= 0x01; // flip a payload bit
        assert_eq!(verify_frame(&f), Check::Bad);
    }

    #[test]
    fn non_ip_frames_are_ignored() {
        let mut f = std::vec![0u8; 60];
        f[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        assert_eq!(verify_frame(&f), Check::NotIp);
        assert!(!fill_frame(&mut f, Fill { ipv4: true, l4: true }));
        assert_eq!(ethertype(&f), Some(ETHERTYPE_ARP));
    }
}
