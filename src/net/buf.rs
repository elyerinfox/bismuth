//! Packet buffers: pool-backed, zero-copy, with fixed headroom (mbuf/pbuf hybrid).
//!
//! A [`PacketBuf`] is an *owning handle* to one block of a static [`PacketPool`].
//! Moving a packet between layers moves the handle; dropping it returns the block.
//! Every block reserves [`HEADROOM`] bytes in front of the data so headers can be
//! prepended without copying, and a packet may carry an extra zero-copy payload
//! segment that lives in flash or other `'static` memory (sendfile-style TX).
//!
//! Pools are separated by role (RX / TX / app) so that a receive flood cannot starve
//! transmission or sockets.
//!
//! Classification: L3 services · net: packet buffers · safe · net

use core::fmt;

use crate::Error;
use crate::kernel::cell::{IrqCell, TaskCell, TaskRef};
use crate::kernel::time::Timeout;
use crate::kernel::{WakeReason, block_on, with};

/// Bytes reserved in front of every packet for header prepends
/// (Ethernet 14 + VLAN 4 + IPv4 20 + TCP 20, rounded up).
pub const HEADROOM: usize = 64;
/// Largest frame a block can hold after the headroom (Ethernet MTU + header + FCS slack).
pub const MAX_FRAME: usize = 1536;
/// Total size of one pool block.
pub const BLOCK_SIZE: usize = HEADROOM + MAX_FRAME;

pub type Block = [u8; BLOCK_SIZE];

/// Type-erased operations a [`PacketBuf`] needs from its pool.
pub trait BlockPool: Sync {
    fn block(&'static self, idx: u16) -> TaskRef<'static, Block>;
    fn release(&'static self, idx: u16);
    fn name(&self) -> &'static str;
}

/// A static pool of `N` packet blocks.
pub struct PacketPool<const N: usize> {
    name: &'static str,
    blocks: [TaskCell<Block>; N],
    used: IrqCell<[bool; N]>,
    stats: IrqCell<PoolStats>,
}

/// Allocation statistics of a packet pool.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    pub allocs: u32,
    pub failures: u32,
    pub in_use: u16,
    pub high_water: u16,
}

impl<const N: usize> PacketPool<N> {
    pub const fn new(name: &'static str) -> Self {
        assert!(N > 0 && N <= u16::MAX as usize);
        PacketPool {
            name,
            blocks: [const { TaskCell::new([0; BLOCK_SIZE]) }; N],
            used: IrqCell::new([false; N]),
            stats: IrqCell::new(PoolStats { allocs: 0, failures: 0, in_use: 0, high_water: 0 }),
        }
    }

    fn key(&self) -> usize {
        self as *const _ as usize
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn available(&self) -> usize {
        self.used.lock(|u| u.iter().filter(|b| !**b).count())
    }

    pub fn stats(&self) -> PoolStats {
        self.stats.lock(|s| *s)
    }

    /// Allocate an empty packet, waiting up to `timeout` for a free block.
    pub fn alloc(&'static self, timeout: Timeout) -> Result<PacketBuf, Error> {
        let r = block_on(
            self.key(),
            timeout,
            |_| {
                self.used.lock(|u| {
                    let i = u.iter().position(|b| !*b)?;
                    u[i] = true;
                    Some(i as u16)
                })
            },
            |_| unreachable!("pools never hand off"),
            |_| {},
        );
        match r {
            Ok(idx) => {
                self.stats.lock(|s| {
                    s.allocs += 1;
                    s.in_use += 1;
                    s.high_water = s.high_water.max(s.in_use);
                });
                Ok(PacketBuf::from_block(self, idx))
            }
            Err(e) => {
                self.stats.lock(|s| s.failures += 1);
                Err(e)
            }
        }
    }

    /// Allocate without waiting (safe from interrupt handlers).
    pub fn try_alloc(&'static self) -> Result<PacketBuf, Error> {
        self.alloc(Timeout::NoWait).map_err(|_| Error::NoMemory)
    }

    /// Allocate a packet holding a copy of `data`.
    pub fn alloc_from(&'static self, data: &[u8], timeout: Timeout) -> Result<PacketBuf, Error> {
        let mut p = self.alloc(timeout)?;
        p.append(data)?;
        Ok(p)
    }
}

impl<const N: usize> BlockPool for PacketPool<N> {
    fn block(&'static self, idx: u16) -> TaskRef<'static, Block> {
        self.blocks[idx as usize].borrow_mut()
    }

    fn release(&'static self, idx: u16) {
        with(|k| {
            self.used.lock(|u| u[idx as usize] = false);
            self.stats.lock(|s| s.in_use -= 1);
            k.wake_one(self.key(), WakeReason::Signaled);
        });
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Packet metadata carried alongside the bytes (kept small on purpose).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketMeta {
    /// Interface the packet arrived on / leaves through.
    pub ifindex: u8,
    /// Traffic class 0..=7; >= 4 uses the high-priority TX band.
    pub prio: u8,
    /// Checksum status (RX: what has been verified; TX: what still must be filled).
    pub csum: CsumState,
    pub vlan: Option<u16>,
    /// RX timestamp in kernel ticks.
    pub timestamp: u64,
    /// Remote endpoint (IPv4 address, port) for datagrams exchanged with sockets.
    pub peer: Option<([u8; 4], u16)>,
    /// Connection-tracking mark (0 = untracked; else `ConnMask` bits). Set by a
    /// `ConnTrack` hook for a later `RuleSet` to match on. See `net::filter`.
    pub ct_mark: u8,
}

/// Checksum bookkeeping for offload / software fallback.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum CsumState {
    /// Nothing known / nothing requested.
    #[default]
    None,
    /// RX: all checksums verified good (by hardware or software).
    Verified,
    /// RX: a checksum was found to be bad.
    Bad,
}

/// An owned network packet.
pub struct PacketBuf {
    pool: &'static dyn BlockPool,
    idx: u16,
    block: Option<TaskRef<'static, Block>>,
    head: u16,
    len: u16,
    /// Zero-copy payload appended after the block data (e.g. a flash-resident asset).
    ext: Option<&'static [u8]>,
    pub meta: PacketMeta,
}

impl PacketBuf {
    fn from_block(pool: &'static dyn BlockPool, idx: u16) -> Self {
        PacketBuf {
            pool,
            idx,
            block: Some(pool.block(idx)),
            head: HEADROOM as u16,
            len: 0,
            ext: None,
            meta: PacketMeta::default(),
        }
    }

    fn blk(&self) -> &Block {
        self.block.as_ref().expect("live packet holds its block")
    }

    fn blk_mut(&mut self) -> &mut Block {
        self.block.as_mut().expect("live packet holds its block")
    }

    /// Name of the pool this packet came from.
    pub fn pool_name(&self) -> &'static str {
        self.pool.name()
    }

    /// Length of the linear (in-block) part.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.ext.is_none_or(|e| e.is_empty())
    }

    /// Total length including any zero-copy payload.
    pub fn total_len(&self) -> usize {
        self.len as usize + self.ext.map_or(0, |e| e.len())
    }

    pub fn headroom(&self) -> usize {
        self.head as usize
    }

    pub fn tailroom(&self) -> usize {
        BLOCK_SIZE - self.head as usize - self.len as usize
    }

    /// The linear packet bytes.
    pub fn data(&self) -> &[u8] {
        &self.blk()[self.head as usize..(self.head + self.len) as usize]
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        let (h, l) = (self.head as usize, self.len as usize);
        &mut self.blk_mut()[h..h + l]
    }

    /// The zero-copy payload segment, if any.
    pub fn ext(&self) -> Option<&'static [u8]> {
        self.ext
    }

    /// Prepend `n` bytes of header space (like `skb_push` / `M_PREPEND`).
    pub fn push_header(&mut self, n: usize) -> Result<&mut [u8], Error> {
        if n > self.head as usize {
            return Err(Error::Overflow);
        }
        self.head -= n as u16;
        self.len += n as u16;
        let h = self.head as usize;
        Ok(&mut self.blk_mut()[h..h + n])
    }

    /// Strip `n` bytes from the front (like `skb_pull` / `m_adj`).
    pub fn pull_header(&mut self, n: usize) -> Result<(), Error> {
        if n > self.len as usize {
            return Err(Error::Invalid);
        }
        self.head += n as u16;
        self.len -= n as u16;
        Ok(())
    }

    /// Append bytes at the tail of the linear part.
    pub fn append(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > self.tailroom() || self.ext.is_some() {
            return Err(Error::Overflow);
        }
        let end = (self.head + self.len) as usize;
        self.blk_mut()[end..end + data.len()].copy_from_slice(data);
        self.len += data.len() as u16;
        Ok(())
    }

    /// Reserve `n` bytes at the tail and return them for filling in.
    pub fn extend(&mut self, n: usize) -> Result<&mut [u8], Error> {
        if n > self.tailroom() || self.ext.is_some() {
            return Err(Error::Overflow);
        }
        let end = (self.head + self.len) as usize;
        self.len += n as u16;
        Ok(&mut self.blk_mut()[end..end + n])
    }

    /// Shorten the linear part to `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len as u16);
    }

    /// Reset to an empty packet with full headroom (for buffer recycling).
    pub fn reset(&mut self) {
        self.head = HEADROOM as u16;
        self.len = 0;
        self.ext = None;
        self.meta = PacketMeta::default();
    }

    /// Give the whole block (minus headroom) as writable space, e.g. for a receive.
    pub fn rx_space(&mut self) -> &mut [u8] {
        self.reset();
        let h = self.head as usize;
        &mut self.blk_mut()[h..]
    }

    /// Mark `n` bytes of [`rx_space`](Self::rx_space) as filled.
    pub fn set_len(&mut self, n: usize) -> Result<(), Error> {
        if self.head as usize + n > BLOCK_SIZE {
            return Err(Error::Overflow);
        }
        self.len = n as u16;
        Ok(())
    }

    /// Attach a zero-copy payload after the linear data (sendfile-style).
    pub fn attach_static(&mut self, payload: &'static [u8]) -> Result<(), Error> {
        if self.ext.is_some() {
            return Err(Error::Busy);
        }
        self.ext = Some(payload);
        Ok(())
    }

    /// Copy any zero-copy payload into the block so the packet is one linear span
    /// (software fallback for devices without scatter-gather).
    pub fn linearize(&mut self) -> Result<(), Error> {
        if let Some(ext) = self.ext.take() {
            if let Err(e) = self.append(ext) {
                self.ext = Some(ext);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Copy the whole packet (linear + payload) into `out`; returns bytes written.
    pub fn copy_to(&self, out: &mut [u8]) -> usize {
        let a = self.data();
        let n = a.len().min(out.len());
        out[..n].copy_from_slice(&a[..n]);
        let mut total = n;
        if let Some(e) = self.ext {
            let m = e.len().min(out.len() - total);
            out[total..total + m].copy_from_slice(&e[..m]);
            total += m;
        }
        total
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        // Give up the block borrow before the slot becomes allocatable again.
        self.block = None;
        self.pool.release(self.idx);
    }
}

impl fmt::Debug for PacketBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBuf")
            .field("pool", &self.pool.name())
            .field("idx", &self.idx)
            .field("len", &self.len)
            .field("headroom", &self.head)
            .field("ext", &self.ext.map(|e| e.len()))
            .field("meta", &self.meta)
            .finish()
    }
}
