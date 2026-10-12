//! A simulated Ethernet cable connecting two [`WireEnd`]s (frame-tier devices).
//!
//! Lets two complete network stacks talk to each other inside one simulated system,
//! with fault injection (link down, loss, corruption) for testing.
//!
//! Classification: L3 services · net driver: simulated cable · safe · net

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::Error;
use crate::kernel::cell::IrqCell;
use crate::net::buf::{MAX_FRAME, PacketBuf, PacketPool};
use crate::net::device::{FrameDevice, HwAddr, LinkState, NetCaps, NetDevInfo};
use crate::sync::Queue;

const DEPTH: usize = 8;

/// Frames in flight on the wire live in their own pool.
static WIRE_POOL: PacketPool<{ 2 * DEPTH * 2 }> = PacketPool::new("wire");

/// The cable: two unidirectional frame queues plus fault-injection knobs.
pub struct Wire {
    lanes: [Queue<PacketBuf, DEPTH>; 2],
    link_up: AtomicBool,
    /// Drop every n-th frame (0 = never).
    drop_every: AtomicU32,
    /// Corrupt the next n frames (flip a payload bit).
    corrupt_next: AtomicU32,
    counter: IrqCell<u32>,
    pub frames: AtomicU32,
    pub lost: AtomicU32,
}

impl Default for Wire {
    fn default() -> Self {
        Self::new()
    }
}

impl Wire {
    pub const fn new() -> Self {
        Wire {
            lanes: [Queue::new(), Queue::new()],
            link_up: AtomicBool::new(true),
            drop_every: AtomicU32::new(0),
            corrupt_next: AtomicU32::new(0),
            counter: IrqCell::new(0),
            frames: AtomicU32::new(0),
            lost: AtomicU32::new(0),
        }
    }

    pub fn set_link(&self, up: bool) {
        self.link_up.store(up, Ordering::Relaxed);
    }

    pub fn drop_every(&self, n: u32) {
        self.drop_every.store(n, Ordering::Relaxed);
    }

    pub fn corrupt_next(&self, n: u32) {
        self.corrupt_next.store(n, Ordering::Relaxed);
    }

    pub fn flush(&self) {
        for l in &self.lanes {
            while l.try_recv().is_ok() {}
        }
    }

    fn carry(&self, lane: usize, frame: &[u8]) -> Result<(), Error> {
        if !self.link_up.load(Ordering::Relaxed) {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return Err(Error::NotReady);
        }
        self.frames.fetch_add(1, Ordering::Relaxed);
        let every = self.drop_every.load(Ordering::Relaxed);
        let n = self.counter.lock(|c| {
            *c += 1;
            *c
        });
        if every != 0 && n % every == 0 {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return Ok(()); // silently lost on the wire
        }
        let mut p = WIRE_POOL.try_alloc()?;
        p.append(frame)?;
        if self.corrupt_next.load(Ordering::Relaxed) > 0 {
            self.corrupt_next.fetch_sub(1, Ordering::Relaxed);
            if let Some(b) = p.data_mut().last_mut() {
                *b ^= 0x01;
            }
        }
        self.lanes[lane].try_send(p).map_err(|e| e.error)?;
        crate::net::schedule();
        Ok(())
    }
}

/// One end of a [`Wire`].
pub struct WireEnd {
    wire: &'static Wire,
    side: usize,
    mac: HwAddr,
    caps: NetCaps,
}

impl WireEnd {
    /// `side` 0 transmits on lane 0 and receives lane 1; side 1 the opposite.
    pub const fn new(wire: &'static Wire, side: usize, mac: [u8; 6]) -> Self {
        WireEnd { wire, side, mac: HwAddr(mac), caps: NetCaps::NONE }
    }

    /// Pretend the "hardware" offloads these features (for offload tests).
    pub const fn with_caps(mut self, caps: NetCaps) -> Self {
        self.caps = caps;
        self
    }
}

impl FrameDevice for WireEnd {
    fn info(&self) -> NetDevInfo {
        NetDevInfo { name: "sim-wire", mtu: 1500, caps: self.caps, rx_ring: 4 }
    }

    fn hw_addr(&self) -> HwAddr {
        self.mac
    }

    fn link(&self) -> LinkState {
        if self.wire.link_up.load(Ordering::Relaxed) { LinkState::UP_100_FULL } else { LinkState::DOWN }
    }

    fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        let p = self.wire.lanes[1 - self.side].try_recv().ok()?;
        let n = buf.len().min(MAX_FRAME);
        Some(p.copy_to(&mut buf[..n]))
    }

    fn send(&self, frame: &[u8]) -> Result<(), Error> {
        self.wire.carry(self.side, frame)
    }

    fn stop(&self) {
        while self.wire.lanes[1 - self.side].try_recv().is_ok() {}
    }
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {}
