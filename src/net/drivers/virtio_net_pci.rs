//! virtio-net over the **legacy** virtio-pci transport (the I/O-BAR interface of a transitional
//! virtio device, which QEMU's `virtio-net-pci` exposes). This is the x86-64 analogue of
//! [`virtio_net`](super::virtio_net): the same split virtqueues and polled frame flow, but the
//! device registers live behind a PCI I/O BAR reached with port I/O, and — because x86 does not
//! identity-map — the two rings and the frame buffers are handed to the device by their *physical*
//! addresses (walked out of the page tables). A receive virtqueue kept posted and a transmit
//! virtqueue with one in-flight frame. It is a [`FrameDevice`], so wrapping it in a
//! [`SoftRing`](crate::net::SoftRing) turns it into a full `NetDevice` for the net core.
//!
//! Part of the trusted computing base: it does DMA. The virtqueue rings and the frame buffers are
//! shared with the device, accessed with volatile reads/writes ordered by `fence`. Single instance
//! (one NIC).
//!
//! Classification: L3 services · net driver: virtio-net (PCI) · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU16, Ordering, fence};

use crate::Error;
use crate::arch::x86_64::paging;
use crate::arch::x86_64::pci::{self, PciDevice};
use crate::kernel::cell::IrqCell;
use crate::net::buf::MAX_FRAME;
use crate::net::device::{FrameDevice, HwAddr, LinkState, NetCaps, NetDevInfo};

// Legacy virtio-pci I/O register offsets (no MSI-X), relative to the I/O BAR base.
const R_DEVICE_FEATURES: u16 = 0x00; // u32, RO
const R_DRIVER_FEATURES: u16 = 0x04; // u32
const R_QUEUE_PFN: u16 = 0x08; // u32 (physical page number of the ring)
const R_QUEUE_SIZE: u16 = 0x0C; // u16, RO
const R_QUEUE_SEL: u16 = 0x0E; // u16
const R_QUEUE_NOTIFY: u16 = 0x10; // u16
const R_STATUS: u16 = 0x12; // u8
const R_CONFIG: u16 = 0x14; // device-specific config (MAC), no MSI-X

// Device status bits (legacy has no FEATURES_OK step).
const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;

// Descriptor flag: the device writes this buffer (used for the receive ring).
const VRING_WRITE: u16 = 2;

// VIRTIO_NET_F_MAC = bit 5. We negotiate only this (legacy, no VERSION_1, no MRG_RXBUF).
const F_NET_MAC: u32 = 1 << 5;

// virtio vendor + transitional (legacy) / modern network device ids.
const VIRTIO_VENDOR: u16 = 0x1AF4;
const NET_DEVICE_IDS: [u16; 2] = [0x1000, 0x1041]; // transitional (legacy) and modern net

// The legacy virtio-net header (no VERSION_1 / no MRG_RXBUF) is 10 bytes.
const NET_HDR: usize = 10;
const FRAME_CAP: usize = MAX_FRAME; // 1536
const BUF_CAP: usize = 2048;
const RXCOUNT: usize = 8; // receive buffers kept posted

const QALIGN: usize = 4096;
const MAX_QSIZE: usize = 256;
const RING_BYTES: usize = 16384;

#[repr(C, align(4096))]
struct Ring([u8; RING_BYTES]);

// One DMA arena (one NIC): two rings + receive buffers + one transmit buffer.
static mut RXRING: Ring = Ring([0; RING_BYTES]);
static mut TXRING: Ring = Ring([0; RING_BYTES]);
static mut RXBUF: [[u8; BUF_CAP]; RXCOUNT] = [[0; BUF_CAP]; RXCOUNT];
static mut TXBUF: [u8; BUF_CAP] = [0; BUF_CAP];

/// Legacy split-ring field offsets for a negotiated queue size `n`.
#[derive(Copy, Clone)]
struct Layout {
    n: usize,
    avail_off: usize,
    used_off: usize,
}

impl Layout {
    fn new(n: usize) -> Layout {
        let avail_off = 16 * n;
        let avail_end = avail_off + 6 + 2 * n;
        let used_off = avail_end.div_ceil(QALIGN) * QALIGN;
        Layout { n, avail_off, used_off }
    }
    fn bytes(&self) -> usize {
        self.used_off + 6 + 8 * self.n
    }
}

// Volatile field writers/readers into a byte ring, by absolute offset from a ring base pointer.
unsafe fn w16(base: *mut u8, off: usize, v: u16) {
    unsafe { (base.add(off) as *mut u16).write_volatile(v) };
}
unsafe fn w32(base: *mut u8, off: usize, v: u32) {
    unsafe { (base.add(off) as *mut u32).write_volatile(v) };
}
unsafe fn w64(base: *mut u8, off: usize, v: u64) {
    unsafe { (base.add(off) as *mut u64).write_volatile(v) };
}
unsafe fn r16(base: *mut u8, off: usize) -> u16 {
    unsafe { (base.add(off) as *const u16).read_volatile() }
}
unsafe fn r32(base: *mut u8, off: usize) -> u32 {
    unsafe { (base.add(off) as *const u32).read_volatile() }
}

fn rxring() -> *mut u8 {
    // SAFETY: address of our DMA ring static (no dereference).
    unsafe { (&raw mut RXRING.0) as *mut u8 }
}
fn txring() -> *mut u8 {
    // SAFETY: address of our DMA ring static (no dereference).
    unsafe { (&raw mut TXRING.0) as *mut u8 }
}
fn rxbuf_addr(i: usize) -> *const u8 {
    // SAFETY: address arithmetic into our RX buffer static (no dereference); `i < RXCOUNT`.
    unsafe { (&raw const RXBUF as *const u8).add(i * BUF_CAP) }
}

/// Physical address of a kernel buffer, or an error if it is not mapped.
fn phys(vaddr: u64) -> Result<u64, Error> {
    paging::translate(vaddr).ok_or(Error::NotReady)
}

/// Confirm a ring is physically contiguous across the pages the device reads linearly, zero it,
/// and return its physical page number for `QUEUE_PFN`.
fn setup_ring(base: *mut u8, layout: &Layout) -> Result<u32, Error> {
    if layout.bytes() > RING_BYTES {
        return Err(Error::Unsupported);
    }
    // SAFETY: exclusive init of our static ring.
    unsafe { core::ptr::write_bytes(base, 0, RING_BYTES) };
    let va = base as u64;
    let pa = phys(va)?;
    let mut off = QALIGN as u64;
    while (off as usize) < layout.bytes() {
        if phys(va + off)? != pa + off {
            return Err(Error::Unsupported); // ring not physically contiguous
        }
        off += QALIGN as u64;
    }
    Ok((pa / QALIGN as u64) as u32)
}

struct Inner {
    mac: [u8; 6],
    ready: bool,
    rx_last_used: u16,
    rx_avail_idx: u16,
    tx_last_used: u16,
    tx_avail_idx: u16,
    n: usize, // negotiated queue size (same for both queues on QEMU)
}

/// A virtio-net NIC on the legacy virtio-pci transport. Const-constructible (so it can live in a
/// `static` wrapped in a [`SoftRing`](crate::net::SoftRing)); [`probe`](Self::probe) scans PCI and
/// brings the device up at boot.
pub struct VirtioNetPci {
    io: AtomicU16,
    inner: IrqCell<Inner>,
}

impl Default for VirtioNetPci {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioNetPci {
    pub const fn new() -> Self {
        VirtioNetPci {
            io: AtomicU16::new(0),
            inner: IrqCell::new(Inner {
                mac: [0; 6],
                ready: false,
                rx_last_used: 0,
                rx_avail_idx: 0,
                tx_last_used: 0,
                tx_avail_idx: 0,
                n: 0,
            }),
        }
    }

    fn io(&self) -> u16 {
        self.io.load(Ordering::Relaxed)
    }

    /// Scan PCI for a virtio-net device and bring it up over its legacy I/O BAR. Returns
    /// `NotReady` if none is present, `Unsupported` if the rings cannot be used.
    pub fn probe(&self) -> Result<(), Error> {
        let dev: PciDevice = pci::find(VIRTIO_VENDOR, &NET_DEVICE_IDS).ok_or(Error::NotReady)?;
        let io = dev.io_bar(0).ok_or(Error::Unsupported)?;
        dev.enable_io_and_bus_master();
        self.io.store(io, Ordering::Relaxed);

        // Reset, then ACK + DRIVER.
        pci::outb_at(io + R_STATUS, 0);
        pci::outb_at(io + R_STATUS, S_ACK);
        pci::outb_at(io + R_STATUS, S_ACK | S_DRIVER);
        // Negotiate only VIRTIO_NET_F_MAC.
        let dev_feat = pci::inl(io + R_DEVICE_FEATURES);
        pci::outl(io + R_DRIVER_FEATURES, dev_feat & F_NET_MAC);

        // Both queues share the device's fixed legacy size.
        pci::outw(io + R_QUEUE_SEL, 0);
        let n = pci::inw(io + R_QUEUE_SIZE) as usize;
        if n == 0 || n > MAX_QSIZE || !n.is_power_of_two() || n < RXCOUNT {
            return Err(Error::Unsupported);
        }
        let layout = Layout::new(n);

        // Receive queue (0) and transmit queue (1).
        let rx_pfn = setup_ring(rxring(), &layout)?;
        pci::outw(io + R_QUEUE_SEL, 0);
        pci::outl(io + R_QUEUE_PFN, rx_pfn);
        let tx_pfn = setup_ring(txring(), &layout)?;
        pci::outw(io + R_QUEUE_SEL, 1);
        pci::outl(io + R_QUEUE_PFN, tx_pfn);

        // MAC from device config (6 bytes at R_CONFIG).
        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            *b = pci::inb_at(io + R_CONFIG + i as u16);
        }

        pci::outb_at(io + R_STATUS, S_ACK | S_DRIVER | S_DRIVER_OK);

        // Post every receive buffer: descriptor i owns RXBUF[i], device-writable.
        let rx = rxring();
        for i in 0..RXCOUNT {
            let buf_pa = phys(rxbuf_addr(i) as u64)?;
            // SAFETY: writing our own ring before publishing avail.idx; buffers are device-writable.
            unsafe {
                w64(rx, 16 * i, buf_pa);
                w32(rx, 16 * i + 8, BUF_CAP as u32);
                w16(rx, 16 * i + 12, VRING_WRITE);
                w16(rx, 16 * i + 14, 0);
                w16(rx, layout.avail_off + 4 + 2 * i, i as u16);
            }
        }
        fence(Ordering::Release);
        // SAFETY: publish avail.idx after the descriptors + avail ring are in place.
        unsafe { w16(rx, layout.avail_off + 2, RXCOUNT as u16) };
        fence(Ordering::Release);
        pci::outw(io + R_QUEUE_NOTIFY, 0);

        self.inner.lock(|st| {
            st.mac = mac;
            st.ready = true;
            st.rx_last_used = 0;
            st.rx_avail_idx = RXCOUNT as u16;
            st.tx_last_used = 0;
            st.tx_avail_idx = 0;
            st.n = n;
        });
        Ok(())
    }

    pub fn mac(&self) -> HwAddr {
        HwAddr(self.inner.lock(|st| st.mac))
    }
}

impl FrameDevice for VirtioNetPci {
    fn info(&self) -> NetDevInfo {
        NetDevInfo { name: "virtio-net-pci", mtu: 1500, caps: NetCaps::NONE, rx_ring: RXCOUNT as u16 }
    }

    fn hw_addr(&self) -> HwAddr {
        self.mac()
    }

    fn link(&self) -> LinkState {
        if self.inner.lock(|st| st.ready) { LinkState::UP_100_FULL } else { LinkState::DOWN }
    }

    fn recv(&self, out: &mut [u8]) -> Option<usize> {
        let io = self.io();
        self.inner.lock(|st| {
            if !st.ready {
                return None;
            }
            let rx = rxring();
            let layout = Layout::new(st.n);
            // SAFETY: the device publishes completed RX buffers by advancing used.idx; an Acquire
            // fence after reading it orders their contents before our copy.
            let n = unsafe {
                let used_idx = r16(rx, layout.used_off + 2);
                fence(Ordering::Acquire);
                if used_idx == st.rx_last_used {
                    return None;
                }
                let slot = (st.rx_last_used as usize) % st.n;
                let id = r32(rx, layout.used_off + 4 + 8 * slot) as usize;
                let total = r32(rx, layout.used_off + 4 + 8 * slot + 4) as usize;
                let frame = total.saturating_sub(NET_HDR).min(FRAME_CAP);
                let copied = frame.min(out.len());
                if id < RXCOUNT {
                    let base = rxbuf_addr(id);
                    let src = core::slice::from_raw_parts(base.add(NET_HDR), copied);
                    out[..copied].copy_from_slice(src);
                    // Re-post this buffer.
                    let avail_slot = (st.rx_avail_idx as usize) % st.n;
                    w16(rx, layout.avail_off + 4 + 2 * avail_slot, id as u16);
                    fence(Ordering::Release);
                    st.rx_avail_idx = st.rx_avail_idx.wrapping_add(1);
                    w16(rx, layout.avail_off + 2, st.rx_avail_idx);
                    fence(Ordering::Release);
                }
                st.rx_last_used = st.rx_last_used.wrapping_add(1);
                copied
            };
            pci::outw(io + R_QUEUE_NOTIFY, 0);
            Some(n)
        })
    }

    fn send(&self, frame: &[u8]) -> Result<(), Error> {
        if frame.len() > FRAME_CAP {
            return Err(Error::Invalid);
        }
        let io = self.io();
        let tx_pa = phys((&raw const TXBUF) as u64)?;
        self.inner.lock(|st| {
            if !st.ready {
                return Err(Error::NotReady);
            }
            let tx = txring();
            let layout = Layout::new(st.n);
            // SAFETY: we exclusively own the TX arena in this critical section; the device only
            // reads it between our notify and the used-index advance we poll for.
            unsafe {
                let buf = (&raw mut TXBUF) as *mut u8;
                for i in 0..NET_HDR {
                    buf.add(i).write_volatile(0);
                }
                let dst = core::slice::from_raw_parts_mut(buf.add(NET_HDR), frame.len());
                dst.copy_from_slice(frame);
                w64(tx, 0, tx_pa);
                w32(tx, 8, (NET_HDR + frame.len()) as u32);
                w16(tx, 12, 0);
                w16(tx, 14, 0);
                let slot = (st.tx_avail_idx as usize) % st.n;
                w16(tx, layout.avail_off + 4 + 2 * slot, 0);
                fence(Ordering::Release);
                st.tx_avail_idx = st.tx_avail_idx.wrapping_add(1);
                w16(tx, layout.avail_off + 2, st.tx_avail_idx);
                fence(Ordering::Release);
            }
            pci::outw(io + R_QUEUE_NOTIFY, 1);
            // Poll the transmit used ring for completion.
            let mut spins = 0u32;
            loop {
                let used_idx = unsafe { r16(tx, layout.used_off + 2) };
                fence(Ordering::Acquire);
                if used_idx != st.tx_last_used {
                    st.tx_last_used = used_idx;
                    return Ok(());
                }
                spins += 1;
                if spins > 100_000_000 {
                    return Err(Error::Timeout);
                }
                core::hint::spin_loop();
            }
        })
    }
}
