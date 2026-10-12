//! Block-device composition wrappers — the data-plane analogue of `Op` middleware.
//!
//! Because block I/O is offset-addressed and bypasses the `Op` enum, cache / partition /
//! read-only / wear-counter layers are `BlockDevice` *wrappers* around an inner
//! `BlockDevice`, composed at build time (the direct analogue of `SoftRing` wrapping a
//! `FrameDevice`). Each is const-constructible, statically sized and safe.
//!
//! [`BlockCache`] note: it holds its own line lock across the inner device call, so it is
//! intended for non-blocking / polled media; and it must be **write-through under a
//! power-safe filesystem** (littlefs owns its own caching), because a write-back layer
//! between a power-safe FS and the medium would turn a committed CRC into a promise still
//! only in volatile RAM. Write-back is for `MediaKind::Disk` / read-mostly mounts.
//!
//! Classification: L2 devices · block: write-back cache / wrappers · safe · always

use core::sync::atomic::{AtomicU32, Ordering};

use super::{BlockDevice, BlockGeometry, MediaKind};
use crate::Error;
use crate::kernel::cell::IrqCell;

// ----- Partition: cap a device to a sub-range of blocks -----

/// Exposes blocks `base..base+count` of `inner` as a device of `count` blocks (offsets
/// relative to `base`). A partition / MTD region.
pub struct Partition<D> {
    inner: D,
    base: u32,
    count: u32,
}

impl<D: BlockDevice> Partition<D> {
    pub const fn new(inner: D, base: u32, count: u32) -> Self {
        Partition { inner, base, count }
    }

    /// The wrapped device.
    pub fn inner(&self) -> &D {
        &self.inner
    }

    fn map(&self, blk: u32) -> Result<u32, Error> {
        if blk < self.count { Ok(self.base + blk) } else { Err(Error::Invalid) }
    }
}

impl<D: BlockDevice> BlockDevice for Partition<D> {
    fn geometry(&self) -> BlockGeometry {
        BlockGeometry { block_count: self.count, ..self.inner.geometry() }
    }
    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        self.inner.read(self.map(blk)?, off, buf)
    }
    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        self.inner.prog(self.map(blk)?, off, data)
    }
    fn erase(&self, blk: u32) -> Result<(), Error> {
        self.inner.erase(self.map(blk)?)
    }
    fn sync(&self) -> Result<(), Error> {
        self.inner.sync()
    }
}

// ----- ReadOnly: refuse all mutation -----

/// Exposes `inner` read-only; every `prog`/`erase` returns [`Error::ReadOnly`] (e.g. a
/// signed firmware image).
pub struct ReadOnly<D> {
    inner: D,
}

impl<D: BlockDevice> ReadOnly<D> {
    pub const fn new(inner: D) -> Self {
        ReadOnly { inner }
    }

    /// The wrapped device.
    pub fn inner(&self) -> &D {
        &self.inner
    }
}

impl<D: BlockDevice> BlockDevice for ReadOnly<D> {
    fn geometry(&self) -> BlockGeometry {
        self.inner.geometry()
    }
    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        self.inner.read(blk, off, buf)
    }
    fn prog(&self, _blk: u32, _off: u32, _data: &[u8]) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }
    fn erase(&self, _blk: u32) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }
    fn sync(&self) -> Result<(), Error> {
        Ok(())
    }
}

// ----- WearCounter: count erases per block -----

/// Counts erases per block, for telemetry and to validate wear-leveling in tests.
pub struct WearCounter<D, const BLOCKS: usize> {
    inner: D,
    erases: [AtomicU32; BLOCKS],
}

impl<D: BlockDevice, const BLOCKS: usize> WearCounter<D, BLOCKS> {
    pub const fn new(inner: D) -> Self {
        WearCounter { inner, erases: [const { AtomicU32::new(0) }; BLOCKS] }
    }

    /// Erase count of one block.
    pub fn erases(&self, blk: u32) -> u32 {
        self.erases.get(blk as usize).map_or(0, |a| a.load(Ordering::Relaxed))
    }

    /// Total erases across all blocks.
    pub fn total(&self) -> u32 {
        self.erases.iter().map(|a| a.load(Ordering::Relaxed)).sum()
    }

    /// Highest erase count on any single block (wear spread = max vs mean).
    pub fn peak(&self) -> u32 {
        self.erases.iter().map(|a| a.load(Ordering::Relaxed)).max().unwrap_or(0)
    }

    /// The wrapped device.
    pub fn inner(&self) -> &D {
        &self.inner
    }
}

impl<D: BlockDevice, const BLOCKS: usize> BlockDevice for WearCounter<D, BLOCKS> {
    fn geometry(&self) -> BlockGeometry {
        self.inner.geometry()
    }
    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        self.inner.read(blk, off, buf)
    }
    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        self.inner.prog(blk, off, data)
    }
    fn erase(&self, blk: u32) -> Result<(), Error> {
        self.inner.erase(blk)?;
        if let Some(a) = self.erases.get(blk as usize) {
            a.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    fn sync(&self) -> Result<(), Error> {
        self.inner.sync()
    }
}

// ----- BlockCache: N cached whole blocks of BS bytes -----

struct Line<const BS: usize> {
    blk: u32,
    valid: bool,
    dirty: bool,
    last: u64,
    data: [u8; BS],
}

impl<const BS: usize> Line<BS> {
    const EMPTY: Line<BS> = Line { blk: 0, valid: false, dirty: false, last: 0, data: [0; BS] };
}

struct CacheState<const N: usize, const BS: usize> {
    lines: [Line<BS>; N],
    clock: u64,
}

/// A whole-block cache of `N` lines of `BS` bytes (one erase-block each; `BS` must equal
/// the inner device's `block_size`). LRU eviction. `write_through` flushes each write
/// immediately; otherwise dirty lines are written back on eviction and [`BlockDevice::sync`].
pub struct BlockCache<D, const N: usize, const BS: usize> {
    inner: D,
    st: IrqCell<CacheState<N, BS>>,
    write_through: bool,
}

impl<D: BlockDevice, const N: usize, const BS: usize> BlockCache<D, N, BS> {
    /// A cache over `inner`. `write_through` is required when a power-safe filesystem sits
    /// on top (see the module note).
    pub const fn new(inner: D, write_through: bool) -> Self {
        BlockCache { inner, st: IrqCell::new(CacheState { lines: [const { Line::EMPTY }; N], clock: 0 }), write_through }
    }

    /// The wrapped device (bypasses the cache — tests / inspection).
    pub fn inner(&self) -> &D {
        &self.inner
    }

    fn victim(s: &CacheState<N, BS>) -> usize {
        if let Some(i) = s.lines.iter().position(|l| !l.valid) {
            return i;
        }
        let mut best = 0;
        for i in 1..N {
            if s.lines[i].last < s.lines[best].last {
                best = i;
            }
        }
        best
    }

    fn flush_line(&self, s: &mut CacheState<N, BS>, i: usize) -> Result<(), Error> {
        if !(s.lines[i].valid && s.lines[i].dirty) {
            return Ok(());
        }
        let blk = s.lines[i].blk;
        match self.inner.geometry().kind {
            MediaKind::Flash { .. } => {
                self.inner.erase(blk)?;
                self.inner.prog(blk, 0, &s.lines[i].data)?;
            }
            _ => self.inner.prog(blk, 0, &s.lines[i].data)?,
        }
        s.lines[i].dirty = false;
        Ok(())
    }

    /// Ensure block `blk` is resident; returns its line index.
    fn ensure(&self, s: &mut CacheState<N, BS>, blk: u32) -> Result<usize, Error> {
        if let Some(i) = s.lines.iter().position(|l| l.valid && l.blk == blk) {
            s.clock += 1;
            s.lines[i].last = s.clock;
            return Ok(i);
        }
        let v = Self::victim(s);
        self.flush_line(s, v)?;
        self.inner.read(blk, 0, &mut s.lines[v].data)?;
        s.clock += 1;
        s.lines[v].blk = blk;
        s.lines[v].valid = true;
        s.lines[v].dirty = false;
        s.lines[v].last = s.clock;
        Ok(v)
    }

    fn bounds(off: u32, len: usize) -> Result<usize, Error> {
        let o = off as usize;
        if o + len > BS { Err(Error::Invalid) } else { Ok(o) }
    }
}

impl<D: BlockDevice, const N: usize, const BS: usize> BlockDevice for BlockCache<D, N, BS> {
    fn geometry(&self) -> BlockGeometry {
        self.inner.geometry()
    }

    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        let o = Self::bounds(off, buf.len())?;
        self.st.lock(|s| {
            let i = self.ensure(s, blk)?;
            buf.copy_from_slice(&s.lines[i].data[o..o + buf.len()]);
            Ok(())
        })
    }

    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        let o = Self::bounds(off, data.len())?;
        self.st.lock(|s| {
            let i = self.ensure(s, blk)?;
            s.lines[i].data[o..o + data.len()].copy_from_slice(data);
            s.lines[i].dirty = true;
            if self.write_through {
                self.flush_line(s, i)?;
            }
            Ok(())
        })
    }

    fn erase(&self, blk: u32) -> Result<(), Error> {
        self.st.lock(|s| {
            for l in s.lines.iter_mut() {
                if l.valid && l.blk == blk {
                    l.valid = false;
                    l.dirty = false;
                }
            }
        });
        self.inner.erase(blk)
    }

    fn sync(&self) -> Result<(), Error> {
        self.st.lock(|s| {
            for i in 0..N {
                self.flush_line(s, i)?;
            }
            Ok::<(), Error>(())
        })?;
        self.inner.sync()
    }
}
