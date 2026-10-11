//! Block storage device class: offset-addressed persistent media (NOR/NAND flash,
//! SD/eMMC, RAM disks) — the foundation the filesystem subsystem (`crate::fs`) is built
//! on.
//!
//! Unlike character or sensor devices, block I/O is *offset-addressed* and bulk, so it
//! does not flow through the [`Op`](super::Op) enum or the per-device middleware chain.
//! A filesystem instead calls the [`BlockDevice`] trait directly on a fast path (exactly
//! as the net core calls `NetDevice`), and the data-plane layers (cache, partition,
//! read-only, wear counter) are *composition wrappers* that implement `BlockDevice`
//! around an inner one, not `Op` middleware.
//!
//! The trait's `read / prog / erase / sync` plus [`BlockGeometry`] shape is deliberately
//! the intersection of littlefs's `lfs_config` block ops and Rust's `embedded-storage`
//! NOR-flash traits, so one trait drives raw erase-before-write flash and managed
//! (SD/eMMC) sectors alike. All block *logic* is safe Rust; a real controller's registers
//! and DMA live in `arch::mmio` (the TCB), exactly as network MAC drivers do.
//!
//! Classification: L2 devices · block device class · safe · always

pub mod cache;
pub mod control;
pub mod virtio_mmio;
#[cfg(feature = "crypto")]
pub mod crypt;
pub mod sim;

pub use cache::{BlockCache, Partition, ReadOnly, WearCounter};
pub use control::BlockControl;
#[cfg(feature = "crypto")]
pub use crypt::CryptBlock;
pub use sim::{SimDisk, SimFlash, SimRam};

use crate::Error;
use crate::config::MAX_BLOCKDEVS;
use crate::kernel::cell::IrqCell;

/// How a block medium behaves on write.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaKind {
    /// NOR/NAND flash: a region must be erased (to `erase_value`, usually `0xFF`) before
    /// it can be programmed; a programmed region cannot be rewritten without an erase.
    Flash { erase_value: u8 },
    /// Managed disk (SD/eMMC/USB-MSC): sectors overwrite in place, `erase` is a no-op and
    /// the card's own FTL does wear leveling.
    Disk,
    /// Volatile RAM disk: overwrite in place, `sync` is a no-op.
    Ram,
}

/// Static geometry of a block device.
///
/// Mirrors `lfs_config { read, prog, block }_size / block_count / block_cycles` and
/// `embedded-storage`'s `READ_SIZE` / `WRITE_SIZE` / `ERASE_SIZE`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockGeometry {
    /// Minimum/alignment of a read, in bytes.
    pub read_size: u32,
    /// Minimum/alignment of a program, in bytes.
    pub prog_size: u32,
    /// Erase-block / sector size, in bytes.
    pub block_size: u32,
    /// Number of erase blocks.
    pub block_count: u32,
    /// Rated erase cycles (`0` = unknown); feeds the wear policy.
    pub block_cycles: u32,
    /// Medium behaviour.
    pub kind: MediaKind,
}

impl BlockGeometry {
    /// Total capacity in bytes.
    pub const fn capacity(&self) -> u64 {
        self.block_size as u64 * self.block_count as u64
    }

    /// The byte value a block holds after an erase (`0` for non-flash media).
    pub const fn erase_value(&self) -> u8 {
        match self.kind {
            MediaKind::Flash { erase_value } => erase_value,
            _ => 0,
        }
    }
}

/// A block/flash storage device. Implementations are 100% safe Rust, except the virtio-blk
/// driver ([`virtio_mmio`]), which does DMA and is therefore part of the TCB.
///
/// The caller guarantees alignment and in-block bounds; an implementation may still
/// validate and return [`Error::Invalid`] (the simulated devices do, to catch
/// filesystem bugs).
pub trait BlockDevice: Sync {
    /// Static geometry.
    fn geometry(&self) -> BlockGeometry;

    /// Read into `buf` from block `blk` starting at byte `off`. `off` and `buf.len()` are
    /// multiples of `read_size` and stay within one block.
    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error>;

    /// Program `data` into block `blk` at byte `off` (multiples of `prog_size`). For
    /// [`MediaKind::Flash`] the target region must already be erased.
    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error>;

    /// Erase one block (to `erase_value`). [`MediaKind::Disk`]/[`MediaKind::Ram`]: a no-op
    /// returning `Ok`.
    fn erase(&self, blk: u32) -> Result<(), Error>;

    /// Flush any volatile write buffer to stable storage.
    fn sync(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// A registered block device, addressed by index into the registry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockId(pub u8);

struct Entry {
    name: &'static str,
    dev: &'static dyn BlockDevice,
}

static REGISTRY: IrqCell<[Option<Entry>; MAX_BLOCKDEVS]> = IrqCell::new([const { None }; MAX_BLOCKDEVS]);

/// Register a block device under `name`. Trusted callers only (like `net::register`).
pub fn register(name: &'static str, dev: &'static dyn BlockDevice) -> Result<BlockId, Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    REGISTRY.lock(|r| {
        if r.iter().flatten().any(|e| e.name == name) {
            return Err(Error::Exists);
        }
        for (i, slot) in r.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Entry { name, dev });
                return Ok(BlockId(i as u8));
            }
        }
        Err(Error::NoResources)
    })
}

/// Look up a registered block device by name.
pub fn find(name: &str) -> Option<BlockId> {
    REGISTRY.lock(|r| {
        r.iter()
            .enumerate()
            .find_map(|(i, e)| e.as_ref().filter(|e| e.name == name).map(|_| BlockId(i as u8)))
    })
}

/// Resolve an id to its device reference, releasing the registry lock before returning so
/// no caller ever holds it across a (possibly blocking) device operation.
fn dev(id: BlockId) -> Result<&'static dyn BlockDevice, Error> {
    REGISTRY
        .lock(|r| r.get(id.0 as usize).and_then(|e| e.as_ref()).map(|e| e.dev))
        .ok_or(Error::NotFound)
}

// Fast path used by filesystems (no `Op`, no middleware chain — like `net::transmit`).

/// Geometry of a registered device.
pub fn geometry(id: BlockId) -> Result<BlockGeometry, Error> {
    Ok(dev(id)?.geometry())
}

/// Read from a registered device.
pub fn read_at(id: BlockId, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
    dev(id)?.read(blk, off, buf)
}

/// Program a registered device.
pub fn prog_at(id: BlockId, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
    dev(id)?.prog(blk, off, data)
}

/// Erase a block of a registered device.
pub fn erase_blk(id: BlockId, blk: u32) -> Result<(), Error> {
    dev(id)?.erase(blk)
}

/// Flush a registered device to stable storage.
pub fn sync(id: BlockId) -> Result<(), Error> {
    dev(id)?.sync()
}

/// Clear the registry (host simulator, between runs).
#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    REGISTRY.lock(|r| {
        for slot in r.iter_mut() {
            *slot = None;
        }
    });
}
