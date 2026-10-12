//! The network driver contract.
//!
//! Two driver tiers (see `docs/research/networking.md` §4.2):
//!
//! * **Ring drivers** implement [`NetDevice`]: a small set of control operations plus
//!   iflib-style ring operations. The network core owns batching, buffer refill and
//!   reclaim, checksum fallback, hooks and statistics; the driver only moves buffers
//!   between its descriptor rings and the core. Buffers are passed as owned
//!   [`PacketBuf`] handles (the safe equivalent of posting DMA addresses).
//! * **Frame drivers** (SPI/UART Ethernet chips, radios, simulators) implement the much
//!   simpler [`FrameDevice`] and are wrapped in a [`SoftRing`], which turns them into a
//!   `NetDevice`.
//!
//! Classification: L3 services · net: driver contract · safe · net

use core::ops::{BitAnd, BitOr};

use super::buf::PacketBuf;
use super::hook::PacketHook;
use crate::Error;
use crate::sync::Queue;

/// Offload / feature capabilities (Linux `NETIF_F_*`, FreeBSD `IFCAP_*`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NetCaps(pub u32);

impl NetCaps {
    pub const NONE: NetCaps = NetCaps(0);
    /// Hardware fills the IPv4 header checksum on transmit.
    pub const TX_CSUM_IPV4: NetCaps = NetCaps(1 << 0);
    /// Hardware fills ICMP/UDP/TCP checksums on transmit.
    pub const TX_CSUM_L4: NetCaps = NetCaps(1 << 1);
    /// Hardware verifies IPv4 and L4 checksums on receive.
    pub const RX_CSUM: NetCaps = NetCaps(1 << 2);
    /// Scatter-gather transmit (zero-copy payload segments).
    pub const SG: NetCaps = NetCaps(1 << 3);
    pub const VLAN_INSERT: NetCaps = NetCaps(1 << 4);
    pub const VLAN_STRIP: NetCaps = NetCaps(1 << 5);
    pub const MCAST_FILTER: NetCaps = NetCaps(1 << 6);
    pub const PROMISC: NetCaps = NetCaps(1 << 7);
    pub const HW_TIMESTAMP: NetCaps = NetCaps(1 << 8);
    pub const ALL_CSUM: NetCaps = NetCaps(0b111);

    pub const fn contains(self, other: NetCaps) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for NetCaps {
    type Output = NetCaps;
    fn bitor(self, rhs: NetCaps) -> NetCaps {
        NetCaps(self.0 | rhs.0)
    }
}

impl BitAnd for NetCaps {
    type Output = NetCaps;
    fn bitand(self, rhs: NetCaps) -> NetCaps {
        NetCaps(self.0 & rhs.0)
    }
}

/// A 48-bit MAC address.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HwAddr(pub [u8; 6]);

impl HwAddr {
    pub const BROADCAST: HwAddr = HwAddr([0xFF; 6]);

    pub fn to_u64(self) -> u64 {
        let mut b = [0u8; 8];
        b[2..].copy_from_slice(&self.0);
        u64::from_be_bytes(b)
    }
}

/// Physical link status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkState {
    pub up: bool,
    pub speed_mbps: u16,
    pub full_duplex: bool,
}

impl LinkState {
    pub const DOWN: LinkState = LinkState { up: false, speed_mbps: 0, full_duplex: false };
    pub const UP_100_FULL: LinkState = LinkState { up: true, speed_mbps: 100, full_duplex: true };
}

/// Receive filter settings.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxFilter {
    pub promiscuous: bool,
    pub all_multicast: bool,
}

/// Static description of a network device.
#[derive(Copy, Clone, Debug)]
pub struct NetDevInfo {
    pub name: &'static str,
    /// IP MTU (payload of an Ethernet frame).
    pub mtu: u16,
    pub caps: NetCaps,
    /// RX descriptors the core should keep posted.
    pub rx_ring: u16,
}

/// A ring-based network driver (iflib-lite).
pub trait NetDevice: Sync {
    fn info(&self) -> NetDevInfo;
    fn hw_addr(&self) -> HwAddr;

    // ---- control plane ----
    fn open(&self) -> Result<(), Error> {
        Ok(())
    }
    /// Stop the device and release every buffer held in its rings.
    fn stop(&self) {}
    fn link(&self) -> LinkState;
    fn set_rx_filter(&self, _f: RxFilter) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Periodic housekeeping (link polling, watchdog); called by the net task.
    fn timer(&self) {}
    /// Enable/disable the receive interrupt (NAPI-style masking while polling).
    fn irq_enable(&self, _on: bool) {}

    // ---- RX ring ----
    /// Post an empty buffer for reception. Returns it back if the ring is full.
    fn rx_refill(&self, buf: PacketBuf) -> Result<(), PacketBuf>;
    /// Take the next completed received packet, if any.
    fn rx_poll(&self) -> Option<PacketBuf>;

    // ---- TX ring ----
    /// Queue one packet for transmission. Returns it back if the ring is full.
    fn tx_encap(&self, pkt: PacketBuf) -> Result<(), PacketBuf>;
    /// Doorbell: start transmission of everything queued (called once per batch).
    fn tx_flush(&self) {}
    /// Release completed transmit buffers; returns how many were reclaimed.
    fn tx_reclaim(&self) -> usize {
        0
    }

    /// Packet hooks contributed by the driver (innermost), mirroring
    /// [`crate::driver::Driver::middleware`] on the data plane.
    fn hooks(&self) -> &'static [&'static dyn PacketHook] {
        &[]
    }
}

/// A simple frame-at-a-time driver (SPI Ethernet chips, radios, simulators).
pub trait FrameDevice: Sync {
    fn info(&self) -> NetDevInfo;
    fn hw_addr(&self) -> HwAddr;
    fn link(&self) -> LinkState {
        LinkState::UP_100_FULL
    }
    /// Copy one received frame into `buf`, returning its length.
    fn recv(&self, buf: &mut [u8]) -> Option<usize>;
    /// Transmit one frame.
    fn send(&self, frame: &[u8]) -> Result<(), Error>;
    /// Stop the device and discard anything buffered.
    fn stop(&self) {}
    fn hooks(&self) -> &'static [&'static dyn PacketHook] {
        &[]
    }
}

/// Adapts a [`FrameDevice`] into a [`NetDevice`] by keeping posted RX buffers in a
/// software ring (`N` deep).
pub struct SoftRing<F, const N: usize> {
    dev: F,
    posted: Queue<PacketBuf, N>,
}

impl<F, const N: usize> SoftRing<F, N> {
    pub const fn new(dev: F) -> Self {
        SoftRing { dev, posted: Queue::new() }
    }

    pub fn inner(&self) -> &F {
        &self.dev
    }
}

impl<F: FrameDevice, const N: usize> NetDevice for SoftRing<F, N> {
    fn info(&self) -> NetDevInfo {
        let mut i = self.dev.info();
        i.rx_ring = i.rx_ring.min(N as u16);
        i
    }

    fn hw_addr(&self) -> HwAddr {
        self.dev.hw_addr()
    }

    fn link(&self) -> LinkState {
        self.dev.link()
    }

    fn stop(&self) {
        while self.posted.try_recv().is_ok() {}
        self.dev.stop();
    }

    fn rx_refill(&self, buf: PacketBuf) -> Result<(), PacketBuf> {
        self.posted.try_send(buf).map_err(|e| e.item)
    }

    fn rx_poll(&self) -> Option<PacketBuf> {
        let mut buf = self.posted.try_recv().ok()?;
        match self.dev.recv(buf.rx_space()) {
            Some(n) if buf.set_len(n).is_ok() => Some(buf),
            _ => {
                // Nothing received: keep the buffer posted.
                let _ = self.posted.send_front(buf, crate::Timeout::NoWait);
                None
            }
        }
    }

    fn tx_encap(&self, mut pkt: PacketBuf) -> Result<(), PacketBuf> {
        // Frame devices cannot scatter-gather: the core linearizes for us when the
        // device lacks `SG`, but be defensive.
        if pkt.linearize().is_err() {
            return Ok(()); // cannot fit: drop
        }
        let _ = self.dev.send(pkt.data());
        Ok(())
    }

    fn hooks(&self) -> &'static [&'static dyn PacketHook] {
        self.dev.hooks()
    }
}
