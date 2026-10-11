//! Loopback network device (ring tier).
//!
//! Transmitted buffers are handed straight back as received packets: a zero-copy
//! buffer swap, like netmap forwarding. Like Linux `lo`, it claims every checksum
//! offload since frames never touch a wire.
//!
//! Classification: L3 services · net driver: loopback · safe · net

use crate::net::buf::PacketBuf;
use crate::net::device::{HwAddr, LinkState, NetCaps, NetDevInfo, NetDevice};
use crate::sync::Queue;

pub struct Loopback<const N: usize> {
    looped: Queue<PacketBuf, N>,
}

impl<const N: usize> Default for Loopback<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Loopback<N> {
    pub const fn new() -> Self {
        Loopback { looped: Queue::new() }
    }

    /// Discard anything in flight (used between simulator runs).
    pub fn flush(&self) {
        while self.looped.try_recv().is_ok() {}
    }
}

impl<const N: usize> NetDevice for Loopback<N> {
    fn info(&self) -> NetDevInfo {
        NetDevInfo { name: "loopback", mtu: 1500, caps: NetCaps::ALL_CSUM | NetCaps::SG, rx_ring: 0 }
    }

    fn hw_addr(&self) -> HwAddr {
        HwAddr([0; 6])
    }

    fn link(&self) -> LinkState {
        LinkState::UP_100_FULL
    }

    fn stop(&self) {
        self.flush();
    }

    fn rx_refill(&self, buf: PacketBuf) -> Result<(), PacketBuf> {
        Err(buf) // no RX ring: received packets are the transmitted buffers themselves
    }

    fn rx_poll(&self) -> Option<PacketBuf> {
        self.looped.try_recv().ok()
    }

    fn tx_encap(&self, pkt: PacketBuf) -> Result<(), PacketBuf> {
        match self.looped.try_send(pkt) {
            Ok(()) => {
                crate::net::schedule();
                Ok(())
            }
            Err(e) => Err(e.item),
        }
    }
}
