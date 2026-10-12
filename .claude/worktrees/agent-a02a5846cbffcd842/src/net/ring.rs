//! NetRing: netmap-style zero-copy packet rings for edge-compute applications.
//!
//! A ring hands *ownership* of pool-backed packets between the net task and an
//! application task: no copies, and Rust ownership guarantees the application cannot
//! touch a buffer after giving it back. Packets are steered into a ring by a
//! [`Steer`](super::hook::Steer) hook; the application can forward the very same
//! buffer back out with [`NetRing::transmit`] (netmap buffer-swap forwarding).
//!
//! Classification: L3 services · net: zero-copy rings · safe · net

use core::sync::atomic::{AtomicU32, Ordering};

use super::IfIndex;
use super::buf::PacketBuf;
use crate::Error;
use crate::kernel::time::Timeout;
use crate::sync::Queue;

/// Something that can accept received packets (implemented by [`NetRing`]).
pub trait RingSink: Sync {
    fn deliver(&self, pkt: PacketBuf) -> Result<(), PacketBuf>;
}

/// A receive ring of `N` packets.
pub struct NetRing<const N: usize> {
    rx: Queue<PacketBuf, N>,
    delivered: AtomicU32,
    overruns: AtomicU32,
}

impl<const N: usize> Default for NetRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> NetRing<N> {
    pub const fn new() -> Self {
        NetRing { rx: Queue::new(), delivered: AtomicU32::new(0), overruns: AtomicU32::new(0) }
    }

    /// Wait for the next packet.
    pub fn recv(&self, timeout: Timeout) -> Result<PacketBuf, Error> {
        self.rx.recv(timeout)
    }

    /// Take up to `out.len()` already-queued packets without waiting (batch receive).
    pub fn recv_batch(&self, out: &mut [Option<PacketBuf>]) -> usize {
        let mut n = 0;
        while n < out.len() {
            match self.rx.try_recv() {
                Ok(p) => {
                    out[n] = Some(p);
                    n += 1;
                }
                Err(_) => break,
            }
        }
        n
    }

    /// Transmit a (possibly modified) packet on `ifindex`, e.g. to forward it.
    pub fn transmit(&self, ifindex: IfIndex, pkt: PacketBuf) -> Result<(), Error> {
        super::transmit(ifindex, pkt).map_err(|(e, _)| e)
    }

    pub fn delivered(&self) -> u32 {
        self.delivered.load(Ordering::Relaxed)
    }

    pub fn overruns(&self) -> u32 {
        self.overruns.load(Ordering::Relaxed)
    }
}

impl<const N: usize> RingSink for NetRing<N> {
    fn deliver(&self, pkt: PacketBuf) -> Result<(), PacketBuf> {
        match self.rx.try_send(pkt) {
            Ok(()) => {
                self.delivered.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.overruns.fetch_add(1, Ordering::Relaxed);
                Err(e.item)
            }
        }
    }
}
