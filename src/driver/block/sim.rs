//! Simulated block devices for host testing and bring-up: an erase-before-write NOR-style
//! flash, a managed (overwrite-in-place) disk, and a volatile RAM disk. Each enforces its
//! medium's contract strictly so filesystem bugs surface in the simulator rather than in
//! the field, and the flash offers power-cut injection for power-loss-recovery tests.
//!
//! Classification: L2 devices · block driver: simulated flash/disk · safe · always

use super::{BlockDevice, BlockGeometry, MediaKind};
use crate::Error;
use crate::kernel::cell::IrqCell;

/// Outcome a programmed [`SimFlash`] can be forced into, to model a power cut mid-write.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Fault {
    /// No injected fault.
    None,
    /// Fail after this many more mutating ops (prog/erase); the triggering op applies only
    /// its first half, then returns [`Error::Io`] (a torn write).
    After(u32),
}

/// A simulated NOR-style flash: `block_count` blocks of `BS` bytes, byte-programmable,
/// erased to `0xFF`. Programming a byte that is not currently `0xFF` is rejected
/// ([`Error::Io`]) — modelling littlefs's "a word is never written twice" assumption.
pub struct SimFlash<const BLOCKS: usize, const BS: usize> {
    data: IrqCell<[[u8; BS]; BLOCKS]>,
    fault: IrqCell<Fault>,
    block_cycles: u32,
}

impl<const BLOCKS: usize, const BS: usize> Default for SimFlash<BLOCKS, BS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCKS: usize, const BS: usize> SimFlash<BLOCKS, BS> {
    /// A fully-erased flash (every byte `0xFF`).
    pub const fn new() -> Self {
        Self { data: IrqCell::new([[0xFF; BS]; BLOCKS]), fault: IrqCell::new(Fault::None), block_cycles: 500 }
    }

    /// Inject a power cut: the `n`-th following mutating op (1 = the next one) applies only
    /// its first half and then fails with [`Error::Io`]. `0` disables injection.
    pub fn power_cut_after(&self, n: u32) {
        self.fault.lock(|f| *f = if n == 0 { Fault::None } else { Fault::After(n - 1) });
    }

    /// Inspect one byte (tests).
    pub fn peek(&self, blk: u32, off: u32) -> u8 {
        self.data.lock(|d| d[blk as usize][off as usize])
    }

    /// Whether a whole block is still erased (all `0xFF`).
    pub fn is_erased(&self, blk: u32) -> bool {
        self.data.lock(|d| d[blk as usize].iter().all(|&b| b == 0xFF))
    }

    /// Count down a pending fault; returns how many bytes of this op may be applied before
    /// it (if any) trips (`None` = apply all, `Some(n)` = apply `n` then fail).
    fn fault_budget(&self, full: usize) -> Option<usize> {
        self.fault.lock(|f| match *f {
            Fault::None => None,
            Fault::After(0) => {
                *f = Fault::None;
                Some(full / 2)
            }
            Fault::After(n) => {
                *f = Fault::After(n - 1);
                None
            }
        })
    }
}

impl<const BLOCKS: usize, const BS: usize> BlockDevice for SimFlash<BLOCKS, BS> {
    fn geometry(&self) -> BlockGeometry {
        BlockGeometry {
            read_size: 1,
            prog_size: 1,
            block_size: BS as u32,
            block_count: BLOCKS as u32,
            block_cycles: self.block_cycles,
            kind: MediaKind::Flash { erase_value: 0xFF },
        }
    }

    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        let (blk, off) = (blk as usize, off as usize);
        if blk >= BLOCKS || off + buf.len() > BS {
            return Err(Error::Invalid);
        }
        self.data.lock(|d| buf.copy_from_slice(&d[blk][off..off + buf.len()]));
        Ok(())
    }

    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        let (bi, oi) = (blk as usize, off as usize);
        if bi >= BLOCKS || oi + data.len() > BS {
            return Err(Error::Invalid);
        }
        // Reject programming any byte that is not currently erased (`0xFF`).
        let already_written = self.data.lock(|d| data.iter().enumerate().any(|(i, _)| d[bi][oi + i] != 0xFF));
        if already_written {
            return Err(Error::Io);
        }
        let budget = self.fault_budget(data.len());
        let n = budget.unwrap_or(data.len());
        self.data.lock(|d| d[bi][oi..oi + n].copy_from_slice(&data[..n]));
        if budget.is_some() { Err(Error::Io) } else { Ok(()) }
    }

    fn erase(&self, blk: u32) -> Result<(), Error> {
        let bi = blk as usize;
        if bi >= BLOCKS {
            return Err(Error::Invalid);
        }
        let budget = self.fault_budget(BS);
        let n = budget.unwrap_or(BS);
        self.data.lock(|d| d[bi][..n].fill(0xFF));
        if budget.is_some() { Err(Error::Io) } else { Ok(()) }
    }
}

/// A simulated managed disk: `block_count` sectors of `BS` bytes, overwrite-in-place,
/// sector-granular I/O. `erase` is a no-op. Models SD/eMMC.
pub struct SimDisk<const BLOCKS: usize, const BS: usize> {
    data: IrqCell<[[u8; BS]; BLOCKS]>,
}

impl<const BLOCKS: usize, const BS: usize> Default for SimDisk<BLOCKS, BS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCKS: usize, const BS: usize> SimDisk<BLOCKS, BS> {
    /// A zeroed disk.
    pub const fn new() -> Self {
        Self { data: IrqCell::new([[0; BS]; BLOCKS]) }
    }

    /// Inspect one byte (tests).
    pub fn peek(&self, blk: u32, off: u32) -> u8 {
        self.data.lock(|d| d[blk as usize][off as usize])
    }
}

impl<const BLOCKS: usize, const BS: usize> BlockDevice for SimDisk<BLOCKS, BS> {
    fn geometry(&self) -> BlockGeometry {
        BlockGeometry {
            read_size: BS as u32,
            prog_size: BS as u32,
            block_size: BS as u32,
            block_count: BLOCKS as u32,
            block_cycles: 0,
            kind: MediaKind::Disk,
        }
    }

    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        let (blk, off) = (blk as usize, off as usize);
        if blk >= BLOCKS || off + buf.len() > BS {
            return Err(Error::Invalid);
        }
        self.data.lock(|d| buf.copy_from_slice(&d[blk][off..off + buf.len()]));
        Ok(())
    }

    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        let (blk, off) = (blk as usize, off as usize);
        if blk >= BLOCKS || off + data.len() > BS {
            return Err(Error::Invalid);
        }
        self.data.lock(|d| d[blk][off..off + data.len()].copy_from_slice(data));
        Ok(())
    }

    fn erase(&self, blk: u32) -> Result<(), Error> {
        if blk as usize >= BLOCKS {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// A simulated volatile RAM disk: byte-granular, overwrite-in-place, `sync` is a no-op.
pub struct SimRam<const BLOCKS: usize, const BS: usize> {
    data: IrqCell<[[u8; BS]; BLOCKS]>,
}

impl<const BLOCKS: usize, const BS: usize> Default for SimRam<BLOCKS, BS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCKS: usize, const BS: usize> SimRam<BLOCKS, BS> {
    /// A zeroed RAM disk.
    pub const fn new() -> Self {
        Self { data: IrqCell::new([[0; BS]; BLOCKS]) }
    }
}

impl<const BLOCKS: usize, const BS: usize> BlockDevice for SimRam<BLOCKS, BS> {
    fn geometry(&self) -> BlockGeometry {
        BlockGeometry {
            read_size: 1,
            prog_size: 1,
            block_size: BS as u32,
            block_count: BLOCKS as u32,
            block_cycles: 0,
            kind: MediaKind::Ram,
        }
    }

    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        let (blk, off) = (blk as usize, off as usize);
        if blk >= BLOCKS || off + buf.len() > BS {
            return Err(Error::Invalid);
        }
        self.data.lock(|d| buf.copy_from_slice(&d[blk][off..off + buf.len()]));
        Ok(())
    }

    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error> {
        let (blk, off) = (blk as usize, off as usize);
        if blk >= BLOCKS || off + data.len() > BS {
            return Err(Error::Invalid);
        }
        self.data.lock(|d| d[blk][off..off + data.len()].copy_from_slice(data));
        Ok(())
    }

    fn erase(&self, blk: u32) -> Result<(), Error> {
        if blk as usize >= BLOCKS {
            return Err(Error::Invalid);
        }
        self.data.lock(|d| d[blk as usize].fill(0));
        Ok(())
    }
}
