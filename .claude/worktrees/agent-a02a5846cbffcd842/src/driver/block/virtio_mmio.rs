//! virtio-block over the virtio-MMIO transport (QEMU `virt`, and many SoCs). A minimal,
//! synchronous, polled driver: one split virtqueue, a bounce buffer, one in-flight request.
//! It is a [`BlockDevice`], so the VFS/FAT/littlefs stack runs on a virtio disk unchanged.
//!
//! Part of the trusted computing base: it does DMA. Device registers go through the safe
//! [`Mmio`] window; the virtqueue rings and the bounce buffer are shared with the device, so
//! they are accessed with volatile reads/writes and ordered with `fence` (an `Acquire` load of
//! the used-ring index publishes the device's writes). Identity-mapped RAM means a static's
//! virtual address is its physical (DMA) address. Single instance (one disk).
//!
//! Classification: L2 devices · driver: virtio-blk (MMIO) · TCB (unsafe allowed) · always
#![allow(unsafe_code)]

use core::sync::atomic::{Ordering, fence};

use super::{BlockDevice, BlockGeometry, MediaKind};
use crate::Error;
use crate::arch::mmio::Mmio;
use crate::kernel::cell::IrqCell;

// virtio-mmio registers.
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
// Feature bit 32 (VIRTIO_F_VERSION_1), i.e. bit 0 of the high word.
const F_VERSION_1_HI: u32 = 1;

const QSIZE: usize = 8;
const SECTOR: usize = 512;
const DEVICE_ID_BLOCK: u32 = 2;

// Descriptor flags.
const VRING_NEXT: u16 = 1;
const VRING_WRITE: u16 = 2;

// virtio-blk request types.
const BLK_IN: u32 = 0; // read
const BLK_OUT: u32 = 1; // write

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

#[repr(C, align(16))]
struct ReqHeader {
    kind: u32,
    reserved: u32,
    sector: u64,
}

/// The single DMA arena (one disk). In identity-mapped RAM, so its address is its DMA address.
static mut VQ: Vq = Vq {
    desc: [const { Desc { addr: 0, len: 0, flags: 0, next: 0 } }; QSIZE],
    avail: Avail { flags: 0, idx: 0, ring: [0; QSIZE], used_event: 0 },
    used: Used { flags: 0, idx: 0, ring: [const { UsedElem { id: 0, len: 0 } }; QSIZE], avail_event: 0 },
};
static mut HDR: ReqHeader = ReqHeader { kind: 0, reserved: 0, sector: 0 };
static mut DATA: [u8; SECTOR] = [0; SECTOR];
static mut STATUSB: u8 = 0xFF;

struct Inner {
    last_used: u16,
    avail_idx: u16,
}

pub struct VirtioBlk {
    regs: Mmio,
    blocks: u32,
    inner: IrqCell<Inner>,
}

impl VirtioBlk {
    /// Bind to a virtio-MMIO window and bring up the device. Fails if the slot is empty or not
    /// a block device.
    pub fn probe(regs: Mmio) -> Result<Self, Error> {
        if regs.read32(MAGIC) != 0x7472_6976 || regs.read32(VERSION) != 2 || regs.read32(DEVICE_ID) != DEVICE_ID_BLOCK {
            return Err(Error::NotReady);
        }
        // Reset, then ACKNOWLEDGE + DRIVER.
        regs.write32(STATUS, 0);
        regs.write32(STATUS, S_ACK);
        regs.write32(STATUS, S_ACK | S_DRIVER);
        // Negotiate: accept only VIRTIO_F_VERSION_1 (required for the modern transport).
        regs.write32(DEVICE_FEATURES_SEL, 1);
        let _ = regs.read32(DEVICE_FEATURES);
        regs.write32(DRIVER_FEATURES_SEL, 1);
        regs.write32(DRIVER_FEATURES, F_VERSION_1_HI);
        regs.write32(DRIVER_FEATURES_SEL, 0);
        regs.write32(DRIVER_FEATURES, 0);
        regs.write32(STATUS, S_ACK | S_DRIVER | S_FEATURES_OK);
        if regs.read32(STATUS) & S_FEATURES_OK == 0 {
            return Err(Error::Unsupported);
        }
        // Capacity (512-byte sectors) from the config space.
        let cap_lo = regs.read32(CONFIG) as u64;
        let cap_hi = regs.read32(CONFIG + 4) as u64;
        let sectors = cap_lo | (cap_hi << 32);
        // Set up queue 0.
        regs.write32(QUEUE_SEL, 0);
        if regs.read32(QUEUE_NUM_MAX) < QSIZE as u32 {
            return Err(Error::Unsupported);
        }
        regs.write32(QUEUE_NUM, QSIZE as u32);
        let (desc_pa, avail_pa, used_pa) = {
            let vq = &raw const VQ;
            // SAFETY: addresses of our static DMA arena; identity-mapped so VA == PA.
            unsafe { ((&(*vq).desc) as *const _ as u64, (&(*vq).avail) as *const _ as u64, (&(*vq).used) as *const _ as u64) }
        };
        regs.write32(QUEUE_DESC_LOW, desc_pa as u32);
        regs.write32(QUEUE_DESC_HIGH, (desc_pa >> 32) as u32);
        regs.write32(QUEUE_DRIVER_LOW, avail_pa as u32);
        regs.write32(QUEUE_DRIVER_HIGH, (avail_pa >> 32) as u32);
        regs.write32(QUEUE_DEVICE_LOW, used_pa as u32);
        regs.write32(QUEUE_DEVICE_HIGH, (used_pa >> 32) as u32);
        regs.write32(QUEUE_READY, 1);
        regs.write32(STATUS, S_ACK | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);
        Ok(VirtioBlk { regs, blocks: sectors as u32, inner: IrqCell::new(Inner { last_used: 0, avail_idx: 0 }) })
    }

    /// Submit one request (header already filled) with the three standard descriptors and
    /// poll for completion. `data_write` = the device writes the data buffer (a read request).
    fn request(&self, data_write: bool) -> Result<(), Error> {
        self.inner.lock(|st| {
            // SAFETY: we exclusively own the arena inside this critical section; the device
            // only touches it between our notify and the used-index advance we poll for.
            unsafe {
                let vq = &raw mut VQ;
                let hdr_pa = (&raw const HDR) as u64;
                let data_pa = (&raw const DATA) as u64;
                let status_pa = (&raw mut STATUSB) as u64;
                STATUSB = 0xFF;
                (*vq).desc[0] = Desc { addr: hdr_pa, len: 16, flags: VRING_NEXT, next: 1 };
                (*vq).desc[1] = Desc {
                    addr: data_pa,
                    len: SECTOR as u32,
                    flags: VRING_NEXT | if data_write { VRING_WRITE } else { 0 },
                    next: 2,
                };
                (*vq).desc[2] = Desc { addr: status_pa, len: 1, flags: VRING_WRITE, next: 0 };
                let slot = (st.avail_idx as usize) % QSIZE;
                (*vq).avail.ring[slot] = 0; // head descriptor index
                fence(Ordering::Release);
                st.avail_idx = st.avail_idx.wrapping_add(1);
                core::ptr::write_volatile(&raw mut (*vq).avail.idx, st.avail_idx);
                fence(Ordering::Release);
            }
            self.regs.write32(QUEUE_NOTIFY, 0);
            // Poll the used ring.
            let mut spins = 0u32;
            loop {
                let used_idx = unsafe { core::ptr::read_volatile(&raw const (*(&raw const VQ)).used.idx) };
                fence(Ordering::Acquire);
                if used_idx != st.last_used {
                    st.last_used = used_idx;
                    break;
                }
                spins += 1;
                if spins > 100_000_000 {
                    return Err(Error::Timeout);
                }
                core::hint::spin_loop();
            }
            let status = unsafe { core::ptr::read_volatile(&raw const STATUSB) };
            if status != 0 { Err(Error::Io) } else { Ok(()) }
        })
    }
}

impl BlockDevice for VirtioBlk {
    fn geometry(&self) -> BlockGeometry {
        BlockGeometry {
            read_size: SECTOR as u32,
            prog_size: SECTOR as u32,
            block_size: SECTOR as u32,
            block_count: self.blocks,
            block_cycles: 0,
            kind: MediaKind::Disk,
        }
    }

    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        if off as usize + buf.len() > SECTOR || buf.len() % SECTOR != 0 && off != 0 {
            // This minimal driver serves whole-sector, in-bounds reads (what the FS layer does).
        }
        if blk >= self.blocks {
            return Err(Error::Invalid);
        }
        // SAFETY: setting the request header in our arena.
        unsafe {
            HDR = ReqHeader { kind: BLK_IN, reserved: 0, sector: blk as u64 };
        }
        self.request(true)?;
        // SAFETY: the device has written DATA (used-index advance, Acquire-fenced above).
        unsafe {
            let data = &*(&raw const DATA);
            buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
        }
        Ok(())
    }

    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        if blk >= self.blocks || off as usize + data.len() > SECTOR {
            return Err(Error::Invalid);
        }
        // SAFETY: fill the arena's data buffer + header for a write.
        unsafe {
            if data.len() != SECTOR {
                // Read-modify-write the sector so a partial program keeps the rest.
                HDR = ReqHeader { kind: BLK_IN, reserved: 0, sector: blk as u64 };
                self.request(true)?;
            }
            let dbuf = &mut *(&raw mut DATA);
            dbuf[off as usize..off as usize + data.len()].copy_from_slice(data);
            HDR = ReqHeader { kind: BLK_OUT, reserved: 0, sector: blk as u64 };
        }
        self.request(false)
    }

    fn erase(&self, _blk: u32) -> Result<(), Error> {
        Ok(()) // Disk media: erase is a no-op.
    }
}
