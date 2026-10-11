//! virtio-net over the virtio-MMIO transport (QEMU `virt`, and many SoCs). A minimal,
//! synchronous, polled driver: a receive virtqueue kept posted and a transmit virtqueue with
//! one in-flight frame. It is a [`FrameDevice`], so wrapping it in a
//! [`SoftRing`](crate::net::SoftRing) turns it into a full `NetDevice` for the net core.
//!
//! Part of the trusted computing base: it does DMA. Device registers go through the safe
//! [`Mmio`] window; the two virtqueue rings and the frame buffers are shared with the device,
//! so they are accessed with volatile reads/writes and ordered with `fence` (an `Acquire` load
//! of a used-ring index publishes the device's writes). Identity-mapped RAM means a static's
//! virtual address is its physical (DMA) address. Single instance (one NIC).
//!
//! Classification: L3 services · net driver: virtio-net (MMIO) · TCB (unsafe allowed) · net
#![allow(unsafe_code)]

use core::sync::atomic::{Ordering, fence};

use crate::Error;
use crate::arch::mmio::Mmio;
use crate::kernel::cell::IrqCell;
use crate::net::buf::MAX_FRAME;
use crate::net::device::{FrameDevice, HwAddr, LinkState, NetCaps, NetDevInfo};

// virtio-mmio registers (shared layout with the block transport).
const MAGIC: usize = 0x000;
const VERSION: usize = 0x004;
const DEVICE_ID: usize = 0x008;
const DEVICE_FEATURES: usize = 0x010;
const DEVICE_FEATURES_SEL: usize = 0x014;
const DRIVER_FEATURES: usize = 0x020;
const DRIVER_FEATURES_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const STATUS: usize = 0x070;
const QUEUE_DESC_LOW: usize = 0x080;
const QUEUE_DESC_HIGH: usize = 0x084;
const QUEUE_DRIVER_LOW: usize = 0x090;
const QUEUE_DRIVER_HIGH: usize = 0x094;
const QUEUE_DEVICE_LOW: usize = 0x0A0;
const QUEUE_DEVICE_HIGH: usize = 0x0A4;
const CONFIG: usize = 0x100;

// Status bits.
const S_ACK: u32 = 1;
const S_DRIVER: u32 = 2;
const S_DRIVER_OK: u32 = 4;
const S_FEATURES_OK: u32 = 8;

// Feature bits. VIRTIO_NET_F_MAC = 5 (low word); VIRTIO_F_VERSION_1 = 32 (bit 0 of high word).
const F_NET_MAC: u32 = 1 << 5;
const F_VERSION_1_HI: u32 = 1;

const QSIZE: usize = 8;
const DEVICE_ID_NET: u32 = 1;
// virtio-net header is 12 bytes once VIRTIO_F_VERSION_1 is negotiated (includes num_buffers).
const NET_HDR: usize = 12;
const FRAME_CAP: usize = MAX_FRAME; // 1536
const BUF_CAP: usize = 2048; // NET_HDR + FRAME_CAP rounded up, keeps buffers page-friendly

// Descriptor flag: the device writes this buffer (used for the receive ring).
const VRING_WRITE: u16 = 2;

#[repr(C, align(16))]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, align(2))]
struct Avail {
    flags: u16,
    idx: u16,
    ring: [u16; QSIZE],
    used_event: u16,
}

#[repr(C)]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
struct Used {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QSIZE],
    avail_event: u16,
}

#[repr(C, align(4096))]
struct Vq {
    desc: [Desc; QSIZE],
    avail: Avail,
    used: Used,
}

const EMPTY_VQ: Vq = Vq {
    desc: [const { Desc { addr: 0, len: 0, flags: 0, next: 0 } }; QSIZE],
    avail: Avail { flags: 0, idx: 0, ring: [0; QSIZE], used_event: 0 },
    used: Used { flags: 0, idx: 0, ring: [const { UsedElem { id: 0, len: 0 } }; QSIZE], avail_event: 0 },
};

// The single DMA arena (one NIC). In identity-mapped RAM, so each address is its DMA address.
static mut RXVQ: Vq = EMPTY_VQ;
static mut TXVQ: Vq = EMPTY_VQ;
static mut RXBUF: [[u8; BUF_CAP]; QSIZE] = [[0; BUF_CAP]; QSIZE];
static mut TXBUF: [u8; BUF_CAP] = [0; BUF_CAP];

struct Inner {
    rx_last_used: u16,
    rx_avail_idx: u16,
    tx_last_used: u16,
    tx_avail_idx: u16,
}

pub struct VirtioNet {
    regs: Mmio,
    mac: HwAddr,
    inner: IrqCell<Inner>,
}

impl VirtioNet {
    /// Bind to a virtio-MMIO window and bring the NIC up. Fails if the slot is empty or not a
    /// network device.
    pub fn probe(regs: Mmio) -> Result<Self, Error> {
        if regs.read32(MAGIC) != 0x7472_6976 || regs.read32(VERSION) != 2 || regs.read32(DEVICE_ID) != DEVICE_ID_NET {
            return Err(Error::NotReady);
        }
        // Reset, then ACKNOWLEDGE + DRIVER.
        regs.write32(STATUS, 0);
        regs.write32(STATUS, S_ACK);
        regs.write32(STATUS, S_ACK | S_DRIVER);
        // Negotiate: VIRTIO_NET_F_MAC (low word) + VIRTIO_F_VERSION_1 (high word).
        regs.write32(DEVICE_FEATURES_SEL, 0);
        let dev_lo = regs.read32(DEVICE_FEATURES);
        regs.write32(DRIVER_FEATURES_SEL, 0);
        regs.write32(DRIVER_FEATURES, dev_lo & F_NET_MAC);
        regs.write32(DEVICE_FEATURES_SEL, 1);
        let _ = regs.read32(DEVICE_FEATURES);
        regs.write32(DRIVER_FEATURES_SEL, 1);
        regs.write32(DRIVER_FEATURES, F_VERSION_1_HI);
        regs.write32(STATUS, S_ACK | S_DRIVER | S_FEATURES_OK);
        if regs.read32(STATUS) & S_FEATURES_OK == 0 {
            return Err(Error::Unsupported);
        }
        // MAC address from the config space (6 bytes at offset 0).
        let m0 = regs.read32(CONFIG);
        let m1 = regs.read32(CONFIG + 4);
        let mac = HwAddr([m0 as u8, (m0 >> 8) as u8, (m0 >> 16) as u8, (m0 >> 24) as u8, m1 as u8, (m1 >> 8) as u8]);

        // Queue 0 = receive, queue 1 = transmit.
        let rxvq = &raw const RXVQ;
        let txvq = &raw const TXVQ;
        // SAFETY: addresses of our static DMA arena; identity-mapped so VA == PA.
        unsafe {
            setup_queue(&regs, 0, &*rxvq)?;
            setup_queue(&regs, 1, &*txvq)?;
        }
        regs.write32(STATUS, S_ACK | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);

        // Post every receive buffer: descriptor i owns RXBUF[i], device-writable.
        // SAFETY: we own the arena until DRIVER_OK publishes it; identity-mapped VA == PA.
        unsafe {
            let rx = &raw mut RXVQ;
            for i in 0..QSIZE {
                let addr = (&raw const RXBUF[i]) as u64;
                (*rx).desc[i] = Desc { addr, len: BUF_CAP as u32, flags: VRING_WRITE, next: 0 };
                (*rx).avail.ring[i] = i as u16;
            }
            fence(Ordering::Release);
            core::ptr::write_volatile(&raw mut (*rx).avail.idx, QSIZE as u16);
            fence(Ordering::Release);
        }
        regs.write32(QUEUE_NOTIFY, 0);

        Ok(VirtioNet {
            regs,
            mac,
            inner: IrqCell::new(Inner { rx_last_used: 0, rx_avail_idx: QSIZE as u16, tx_last_used: 0, tx_avail_idx: 0 }),
        })
    }

    /// The device's MAC address.
    pub fn mac(&self) -> HwAddr {
        self.mac
    }
}

/// Program one virtqueue's descriptor/driver/device ring base addresses and mark it ready.
///
/// SAFETY: `vq` points at our static DMA arena, which lives for the program's lifetime and is
/// identity-mapped (virtual address == physical/DMA address).
unsafe fn setup_queue(regs: &Mmio, idx: u32, vq: &Vq) -> Result<(), Error> {
    regs.write32(QUEUE_SEL, idx);
    if regs.read32(QUEUE_NUM_MAX) < QSIZE as u32 {
        return Err(Error::Unsupported);
    }
    regs.write32(QUEUE_NUM, QSIZE as u32);
    let desc_pa = (&vq.desc) as *const _ as u64;
    let avail_pa = (&vq.avail) as *const _ as u64;
    let used_pa = (&vq.used) as *const _ as u64;
    regs.write32(QUEUE_DESC_LOW, desc_pa as u32);
    regs.write32(QUEUE_DESC_HIGH, (desc_pa >> 32) as u32);
    regs.write32(QUEUE_DRIVER_LOW, avail_pa as u32);
    regs.write32(QUEUE_DRIVER_HIGH, (avail_pa >> 32) as u32);
    regs.write32(QUEUE_DEVICE_LOW, used_pa as u32);
    regs.write32(QUEUE_DEVICE_HIGH, (used_pa >> 32) as u32);
    regs.write32(QUEUE_READY, 1);
    Ok(())
}

impl FrameDevice for VirtioNet {
    fn info(&self) -> NetDevInfo {
        NetDevInfo { name: "virtio-net", mtu: 1500, caps: NetCaps::NONE, rx_ring: QSIZE as u16 }
    }

    fn hw_addr(&self) -> HwAddr {
        self.mac
    }

    fn link(&self) -> LinkState {
        LinkState::UP_100_FULL
    }

    fn recv(&self, out: &mut [u8]) -> Option<usize> {
        self.inner.lock(|st| {
            // SAFETY: the device publishes completed RX buffers by advancing used.idx; an
            // Acquire fence after reading it orders their contents before our copy.
            let n = unsafe {
                let rx = &raw mut RXVQ;
                let used_idx = core::ptr::read_volatile(&raw const (*rx).used.idx);
                fence(Ordering::Acquire);
                if used_idx == st.rx_last_used {
                    return None;
                }
                let slot = (st.rx_last_used as usize) % QSIZE;
                let id = core::ptr::read_volatile(&raw const (*rx).used.ring[slot].id) as usize;
                let total = core::ptr::read_volatile(&raw const (*rx).used.ring[slot].len) as usize;
                // `total` spans the 12-byte virtio-net header plus the Ethernet frame.
                let frame = total.saturating_sub(NET_HDR).min(FRAME_CAP);
                let n = frame.min(out.len());
                if id < QSIZE {
                    let base = (&raw const RXBUF[id]) as *const u8;
                    let src = core::slice::from_raw_parts(base.add(NET_HDR), n);
                    out[..n].copy_from_slice(src);
                    // Re-post this buffer for the next packet.
                    let avail_slot = (st.rx_avail_idx as usize) % QSIZE;
                    (*rx).avail.ring[avail_slot] = id as u16;
                    fence(Ordering::Release);
                    st.rx_avail_idx = st.rx_avail_idx.wrapping_add(1);
                    core::ptr::write_volatile(&raw mut (*rx).avail.idx, st.rx_avail_idx);
                    fence(Ordering::Release);
                }
                st.rx_last_used = st.rx_last_used.wrapping_add(1);
                n
            };
            self.regs.write32(QUEUE_NOTIFY, 0);
            Some(n)
        })
    }

    fn send(&self, frame: &[u8]) -> Result<(), Error> {
        if frame.len() > FRAME_CAP {
            return Err(Error::Invalid);
        }
        self.inner.lock(|st| {
            // SAFETY: we exclusively own the TX arena inside this critical section; the device
            // only reads it between our notify and the used-index advance we poll for.
            unsafe {
                let tx = &raw mut TXVQ;
                let buf = (&raw mut TXBUF) as *mut u8;
                // Zero the 12-byte header, then lay the frame after it.
                for i in 0..NET_HDR {
                    core::ptr::write_volatile(buf.add(i), 0);
                }
                let dst = core::slice::from_raw_parts_mut(buf.add(NET_HDR), frame.len());
                dst.copy_from_slice(frame);
                (*tx).desc[0] = Desc { addr: buf as u64, len: (NET_HDR + frame.len()) as u32, flags: 0, next: 0 };
                let slot = (st.tx_avail_idx as usize) % QSIZE;
                (*tx).avail.ring[slot] = 0;
                fence(Ordering::Release);
                st.tx_avail_idx = st.tx_avail_idx.wrapping_add(1);
                core::ptr::write_volatile(&raw mut (*tx).avail.idx, st.tx_avail_idx);
                fence(Ordering::Release);
            }
            self.regs.write32(QUEUE_NOTIFY, 1);
            // Poll the transmit used ring for completion.
            let mut spins = 0u32;
            loop {
                let used_idx = unsafe { core::ptr::read_volatile(&raw const (*(&raw const TXVQ)).used.idx) };
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
