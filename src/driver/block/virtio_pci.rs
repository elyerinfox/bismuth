//! virtio-block over the **legacy** virtio-pci transport (the I/O-BAR interface of a transitional
//! virtio device, which QEMU's `virtio-blk-pci` exposes by default). This is the x86-64 analogue
//! of [`virtio_mmio`](super::virtio_mmio): the same split virtqueue and polled request flow, but
//! the device registers live behind a PCI I/O BAR reached with port I/O, and — because x86 does
//! not identity-map — the ring and buffers are handed to the device by their *physical* addresses
//! (walked out of the page tables). A minimal, synchronous, polled driver: one queue, a bounce
//! buffer, one in-flight request. It is a [`BlockDevice`], so the VFS/FAT stack runs unchanged.
//!
//! Part of the trusted computing base: it does DMA. The virtqueue rings and the bounce buffer are
//! shared with the device, accessed with volatile reads/writes ordered by `fence`.
//!
//! Classification: L2 devices · driver: virtio-blk (PCI) · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::sync::atomic::{Ordering, fence};

use super::{BlockDevice, BlockGeometry, MediaKind};
use crate::Error;
use crate::arch::x86_64::paging;
use crate::arch::x86_64::pci::{self, PciDevice};
use crate::kernel::cell::IrqCell;

// Legacy virtio-pci I/O register offsets (no MSI-X), relative to the I/O BAR base.
const R_DEVICE_FEATURES: u16 = 0x00; // u32, RO
const R_DRIVER_FEATURES: u16 = 0x04; // u32
const R_QUEUE_PFN: u16 = 0x08; // u32 (physical page number of the ring)
const R_QUEUE_SIZE: u16 = 0x0C; // u16, RO
const R_QUEUE_SEL: u16 = 0x0E; // u16
const R_QUEUE_NOTIFY: u16 = 0x10; // u16
const R_STATUS: u16 = 0x12; // u8
const R_CONFIG: u16 = 0x14; // device-specific config (blk capacity), no MSI-X

// Device status bits (legacy has no FEATURES_OK step).
const S_ACK: u8 = 1;
const S_DRIVER: u8 = 2;
const S_DRIVER_OK: u8 = 4;

// Descriptor flags.
const VRING_NEXT: u16 = 1;
const VRING_WRITE: u16 = 2;

// virtio-blk request types.
const BLK_IN: u32 = 0; // read
const BLK_OUT: u32 = 1; // write

const SECTOR: usize = 512;
const QALIGN: usize = 4096; // legacy ring: `used` starts on the next 4 KiB boundary after `avail`

// virtio vendor + transitional/modern block device ids.
const VIRTIO_VENDOR: u16 = 0x1AF4;
const BLK_DEVICE_IDS: [u16; 2] = [0x1001, 0x1042]; // transitional (legacy) and modern block

// Ring arena sized for the largest queue we accept (256): desc 4096 + avail, then `used` on the
// next page, up to ~10 KiB — three pages; four for headroom. Must be physically contiguous.
const MAX_QSIZE: usize = 256;
const RING_BYTES: usize = 16384;

#[repr(C, align(4096))]
struct Ring([u8; RING_BYTES]);

#[repr(C, align(16))]
struct ReqHeader {
    kind: u32,
    reserved: u32,
    sector: u64,
}

static mut RING: Ring = Ring([0; RING_BYTES]);
#[repr(align(16))]
struct HdrCell(ReqHeader);
static mut HDR: HdrCell = HdrCell(ReqHeader { kind: 0, reserved: 0, sector: 0 });
#[repr(align(512))]
struct DataCell([u8; SECTOR]);
static mut DATA: DataCell = DataCell([0; SECTOR]);
static mut STATUSB: u8 = 0xFF;

/// Ring field offsets for a negotiated queue size `n` (legacy split-ring layout).
#[derive(Copy, Clone)]
struct Layout {
    n: usize,
    avail_off: usize,
    used_off: usize,
}

impl Layout {
    fn new(n: usize) -> Layout {
        let avail_off = 16 * n;
        let avail_end = avail_off + 6 + 2 * n; // flags,idx,ring[n],used_event
        let used_off = avail_end.div_ceil(QALIGN) * QALIGN;
        Layout { n, avail_off, used_off }
    }
    fn bytes(&self) -> usize {
        self.used_off + 6 + 8 * self.n
    }
}

fn ring_ptr() -> *mut u8 {
    // SAFETY: taking the address of our DMA ring static (no dereference here).
    unsafe { (&raw mut RING.0) as *mut u8 }
}

// Volatile field writers/readers into the byte ring, by absolute offset.
unsafe fn w16(off: usize, v: u16) {
    unsafe { (ring_ptr().add(off) as *mut u16).write_volatile(v) };
}
unsafe fn w32(off: usize, v: u32) {
    unsafe { (ring_ptr().add(off) as *mut u32).write_volatile(v) };
}
unsafe fn w64(off: usize, v: u64) {
    unsafe { (ring_ptr().add(off) as *mut u64).write_volatile(v) };
}
unsafe fn r16(off: usize) -> u16 {
    unsafe { (ring_ptr().add(off) as *const u16).read_volatile() }
}

struct Inner {
    last_used: u16,
    avail_idx: u16,
}

pub struct VirtioBlkPci {
    io: u16,
    layout: Layout,
    blocks: u32,
    inner: IrqCell<Inner>,
}

/// Physical address of a kernel buffer, or an error if it is not mapped.
fn phys(vaddr: u64) -> Result<u64, Error> {
    paging::translate(vaddr).ok_or(Error::NotReady)
}

impl VirtioBlkPci {
    /// Scan PCI for a virtio-block device and bring it up over its legacy I/O BAR. Returns
    /// `NotReady` if none is present, `Unsupported` if its ring cannot be used (e.g. the queue is
    /// larger than we size for, or the ring arena is not physically contiguous).
    pub fn probe() -> Result<Self, Error> {
        let dev: PciDevice = pci::find(VIRTIO_VENDOR, &BLK_DEVICE_IDS).ok_or(Error::NotReady)?;
        let io = dev.io_bar(0).ok_or(Error::Unsupported)?; // legacy registers live in I/O BAR0
        dev.enable_io_and_bus_master();

        // Reset, then ACK + DRIVER.
        pci::outb_at(io + R_STATUS, 0);
        pci::outb_at(io + R_STATUS, S_ACK);
        pci::outb_at(io + R_STATUS, S_ACK | S_DRIVER);
        // Accept no optional features (the base block interface is enough).
        let _ = pci::inl(io + R_DEVICE_FEATURES);
        pci::outl(io + R_DRIVER_FEATURES, 0);

        // Queue 0: the legacy queue size is fixed by the device.
        pci::outw(io + R_QUEUE_SEL, 0);
        let n = pci::inw(io + R_QUEUE_SIZE) as usize;
        if n == 0 || n > MAX_QSIZE || !n.is_power_of_two() {
            return Err(Error::Unsupported);
        }
        let layout = Layout::new(n);
        if layout.bytes() > RING_BYTES {
            return Err(Error::Unsupported);
        }

        // Zero the ring and confirm it is physically contiguous across the pages the device will
        // read linearly (x86 .bss may not be — then we cannot DMA from it).
        // SAFETY: exclusive init of our static ring.
        unsafe { core::ptr::write_bytes(ring_ptr(), 0, RING_BYTES) };
        let base = ring_ptr() as u64;
        let ring_pa = phys(base)?;
        let mut off = QALIGN as u64;
        while (off as usize) < layout.bytes() {
            if phys(base + off)? != ring_pa + off {
                return Err(Error::Unsupported); // ring not physically contiguous
            }
            off += QALIGN as u64;
        }

        // Publish the ring to the device (legacy: physical page number).
        pci::outl(io + R_QUEUE_PFN, (ring_pa / QALIGN as u64) as u32);
        pci::outb_at(io + R_STATUS, S_ACK | S_DRIVER | S_DRIVER_OK);

        // Capacity (512-byte sectors) from device config.
        let cap_lo = pci::inl(io + R_CONFIG) as u64;
        let cap_hi = pci::inl(io + R_CONFIG + 4) as u64;
        let sectors = cap_lo | (cap_hi << 32);

        Ok(VirtioBlkPci {
            io,
            layout,
            blocks: sectors as u32,
            inner: IrqCell::new(Inner { last_used: 0, avail_idx: 0 }),
        })
    }

    fn request(&self, data_write: bool) -> Result<(), Error> {
        let hdr_pa = phys((&raw const HDR) as u64)?;
        let data_pa = phys((&raw const DATA) as u64)?;
        let status_pa = phys((&raw const STATUSB) as u64)?;
        self.inner.lock(|st| {
            // SAFETY: we exclusively own the ring + buffers inside this critical section; the
            // device only touches them between our notify and the used-index advance we poll for.
            unsafe {
                STATUSB = 0xFF;
                // Three descriptors: header (R), data (R or W), status (W).
                w64(0, hdr_pa);
                w32(8, 16);
                w16(12, VRING_NEXT);
                w16(14, 1);
                w64(16, data_pa);
                w32(24, SECTOR as u32);
                w16(28, VRING_NEXT | if data_write { VRING_WRITE } else { 0 });
                w16(30, 2);
                w64(32, status_pa);
                w32(40, 1);
                w16(44, VRING_WRITE);
                w16(46, 0);
                // avail.ring[idx % n] = head (0); publish avail.idx.
                let slot = (st.avail_idx as usize) % self.layout.n;
                w16(self.layout.avail_off + 4 + 2 * slot, 0);
                fence(Ordering::Release);
                st.avail_idx = st.avail_idx.wrapping_add(1);
                w16(self.layout.avail_off + 2, st.avail_idx);
                fence(Ordering::Release);
            }
            pci::outw(self.io + R_QUEUE_NOTIFY, 0);
            // Poll the used ring.
            let mut spins = 0u32;
            loop {
                let used_idx = unsafe { r16(self.layout.used_off + 2) };
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

impl BlockDevice for VirtioBlkPci {
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
        if blk >= self.blocks || off as usize + buf.len() > SECTOR {
            return Err(Error::Invalid);
        }
        // SAFETY: setting the request header in our arena.
        unsafe { HDR.0 = ReqHeader { kind: BLK_IN, reserved: 0, sector: blk as u64 } };
        self.request(true)?;
        // SAFETY: the device has written DATA (used-index advance, Acquire-fenced above).
        unsafe {
            let data = &(*(&raw const DATA)).0;
            buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
        }
        Ok(())
    }

    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        if blk >= self.blocks || off as usize + data.len() > SECTOR {
            return Err(Error::Invalid);
        }
        // SAFETY: fill the arena's data buffer + header for a write (read-modify-write a partial
        // sector first so the untouched bytes are preserved).
        unsafe {
            if data.len() != SECTOR {
                HDR.0 = ReqHeader { kind: BLK_IN, reserved: 0, sector: blk as u64 };
                self.request(true)?;
            }
            let dbuf = &mut (*(&raw mut DATA)).0;
            dbuf[off as usize..off as usize + data.len()].copy_from_slice(data);
            HDR.0 = ReqHeader { kind: BLK_OUT, reserved: 0, sector: blk as u64 };
        }
        self.request(false)
    }

    fn erase(&self, _blk: u32) -> Result<(), Error> {
        Ok(()) // Disk media: erase is a no-op.
    }
}
