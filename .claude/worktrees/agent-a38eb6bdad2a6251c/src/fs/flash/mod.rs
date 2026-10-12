//! A power-fail-safe, wear-spreading, log-structured flash filesystem built on the
//! [`meta::MetaPair`] copy-on-write journal.
//!
//! It follows littlefs's architecture — directories as copy-on-write metadata pairs,
//! commit-or-ignore power-loss recovery, an allocator with no on-disk free list — with a
//! Bismuth-native on-disk format (not byte-compatible with upstream littlefs v2; exact v2
//! compatibility, which would let the chip be read by `littlefs-fuse` on a PC, is a
//! documented future refinement). It targets raw NOR/NAND flash, where FAT's lack of
//! power-loss safety makes it unsuitable.
//!
//! ## Design (and the CoW-bug mitigations it bakes in, see `docs/research/cow-bugs.md`)
//!
//! * **Metadata pairs do not relocate in v1.** A directory owns two consecutive blocks
//!   `(b0, b0+1)` for its lifetime, so a stable [`FsVnode`] can be derived from the
//!   physical location without a use-after-relocate hazard; parent entries reference a
//!   child directory by its fixed `b0` and never need patching. (Metadata wear-leveling
//!   via relocation is the documented deferral; file *data* blocks still wear-spread.)
//! * **Data before metadata.** A file write copies the whole data chain into freshly
//!   allocated, erased blocks and only then commits the new head into the directory pair
//!   (the atomic point). A power loss before the commit leaves the old file intact and the
//!   new blocks as orphans.
//! * **No on-disk free list.** The in-RAM used-block bitmap is rebuilt by a full tree scan
//!   at mount; orphans (written but never committed) are simply absent from it and thus
//!   reclaimed. `SimFlash`'s program-once rule catches any double-allocation for free.
//! * **Bounded, iterative walks.** The mount scan uses a fixed worklist and a hard
//!   iteration cap; a cycle or over-deep tree returns [`Error::Integrity`], never a stack
//!   overflow.
//! * **Deletes never allocate.** A metadata commit reuses the pair's own two blocks
//!   (ping-pong), so `unlink`/`truncate`/`rmdir` need no free block — the classic
//!   CoW-delete ENOSPC deadlock cannot occur.
//!
//! `FsVnode` encoding: a directory is its pair's primary block `b0` (bit 31 clear); a file
//! is `(1<<31) | (slot<<24) | parent_b0`. Root is `FsVnode(0)` (the pair at blocks 0/1).
//!
//! Classification: L3 services · fs: power-safe flash filesystem · safe · fs

pub mod meta;

pub use meta::{MetaPair, crc32};

use super::vnode::{DirEntry, FileSystem, FsInfo, FsVnode, NodeKind, OpenId, OpenMode, Stat};
use crate::Error;
use crate::config::{LFS_MAX_OPEN, LFS_RESERVE_BLOCKS, LFS_WALK_STACK};
use crate::driver::block::BlockDevice;
use crate::kernel::cell::IrqCell;

const NIL: u32 = u32::MAX;
const FILE_BIT: u32 = 1 << 31;
const ADDR_MASK: u32 = 0x00FF_FFFF; // 24 bits of block address
const SLOT_SHIFT: u32 = 24;

// Directory-entry slot (fixed size for stable per-entry ids): kind, name_len, a, b, name.
const KIND_FREE: u8 = 0;
const KIND_FILE: u8 = 1;
const KIND_DIR: u8 = 2;
const NAME: usize = 40;
const SLOT: usize = 10 + NAME; // kind(1)+name_len(1)+a(4)+b(4)+name(NAME)
const DIR_HDR: usize = 8; // parent_b0(4) + reserved(4)
const META_OVERHEAD: usize = 12; // MetaPair header(8) + crc(4)

fn vnode_dir(b0: u32) -> FsVnode {
    FsVnode(b0 & ADDR_MASK)
}
fn vnode_file(parent_b0: u32, slot: usize) -> FsVnode {
    FsVnode(FILE_BIT | ((slot as u32) << SLOT_SHIFT) | (parent_b0 & ADDR_MASK))
}
fn is_file(v: FsVnode) -> bool {
    v.0 & FILE_BIT != 0
}
fn addr(v: FsVnode) -> u32 {
    v.0 & ADDR_MASK
}
fn file_slot(v: FsVnode) -> usize {
    ((v.0 >> SLOT_SHIFT) & 0x7F) as usize
}

fn rd_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
fn wr_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

struct State<const BLOCKS: usize> {
    used: [bool; BLOCKS],
    cursor: u32,
    inited: bool,
    open: [Option<u32>; LFS_MAX_OPEN],
}

/// A flash filesystem over `BLOCKS` erase blocks of `BS` bytes.
pub struct FlashFs<const BLOCKS: usize, const BS: usize> {
    dev: &'static dyn BlockDevice,
    st: IrqCell<State<BLOCKS>>,
}

impl<const BLOCKS: usize, const BS: usize> FlashFs<BLOCKS, BS> {
    /// Entry slots per directory pair.
    const SLOTS: usize = (BS - META_OVERHEAD - DIR_HDR) / SLOT;
    /// Directory payload length (header + all slots).
    const DPL: usize = DIR_HDR + Self::SLOTS * SLOT;
    /// Data bytes per data block (the last 4 bytes are the next-block pointer).
    const DCAP: usize = BS - 4;

    /// Bind the filesystem to a block device. Call [`format`](Self::format) or
    /// [`mount`](Self::mount) before mounting it into the VFS.
    pub const fn new(dev: &'static dyn BlockDevice) -> Self {
        FlashFs { dev, st: IrqCell::new(State { used: [false; BLOCKS], cursor: 2, inited: false, open: [None; LFS_MAX_OPEN] }) }
    }

    fn entry_off(slot: usize) -> usize {
        DIR_HDR + slot * SLOT
    }

    fn read_next(&self, blk: u32) -> Result<u32, Error> {
        let mut p = [0u8; 4];
        self.dev.read(blk, (BS - 4) as u32, &mut p)?;
        Ok(u32::from_le_bytes(p))
    }

    // ----- allocator -----

    fn alloc_block(&self) -> Result<u32, Error> {
        self.st.lock(|s| {
            let free = s.used.iter().filter(|&&u| !u).count() as u32;
            if free <= LFS_RESERVE_BLOCKS {
                return Err(Error::NoSpace);
            }
            for k in 0..BLOCKS {
                let i = (s.cursor as usize + k) % BLOCKS;
                if !s.used[i] {
                    s.used[i] = true;
                    s.cursor = ((i + 1) % BLOCKS) as u32;
                    return Ok(i as u32);
                }
            }
            Err(Error::NoSpace)
        })
    }

    /// Allocate two consecutive free blocks for a new directory pair.
    fn alloc_pair(&self) -> Result<u32, Error> {
        self.st.lock(|s| {
            let free = s.used.iter().filter(|&&u| !u).count() as u32;
            if free <= LFS_RESERVE_BLOCKS + 2 {
                return Err(Error::NoSpace);
            }
            for i in 0..BLOCKS - 1 {
                if !s.used[i] && !s.used[i + 1] {
                    s.used[i] = true;
                    s.used[i + 1] = true;
                    return Ok(i as u32);
                }
            }
            Err(Error::NoSpace)
        })
    }

    fn free_one(&self, blk: u32) {
        if (blk as usize) < BLOCKS {
            self.st.lock(|s| s.used[blk as usize] = false);
        }
    }

    fn free_chain(&self, head: u32) {
        let mut b = head;
        let mut n = 0;
        while b != NIL && (b as usize) < BLOCKS {
            let next = self.read_next(b).unwrap_or(NIL);
            self.free_one(b);
            b = next;
            n += 1;
            if n > BLOCKS {
                break;
            }
        }
    }

    // ----- directory metadata -----

    fn load_dir(&self, b0: u32) -> Result<(MetaPair<BS>, [u8; BS]), Error> {
        let mp = MetaPair::<BS>::mount(self.dev, b0, b0 + 1)?;
        let mut buf = [0u8; BS];
        mp.read(self.dev, &mut buf)?;
        Ok((mp, buf))
    }

    fn find_slot(buf: &[u8], name: &str) -> Option<usize> {
        for slot in 0..Self::SLOTS {
            let off = Self::entry_off(slot);
            if buf[off] == KIND_FREE {
                continue;
            }
            let len = buf[off + 1] as usize;
            if &buf[off + 10..off + 10 + len] == name.as_bytes() {
                return Some(slot);
            }
        }
        None
    }

    fn free_slot(buf: &[u8]) -> Option<usize> {
        (0..Self::SLOTS).find(|&slot| buf[Self::entry_off(slot)] == KIND_FREE)
    }

    // ----- copy-on-write file rewrite (data before metadata) -----

    /// Rewrite the file at `(parent_b0, slot)` to `new_size` bytes, overlaying `ov` at byte
    /// `ov_off`. Builds a fresh data chain, commits the new head atomically, then frees the
    /// old chain. A power loss before the commit preserves the old file.
    fn rewrite(&self, parent_b0: u32, slot: usize, new_size: u32, ov_off: u32, ov: &[u8]) -> Result<(), Error> {
        let (mut mp, mut buf) = self.load_dir(parent_b0)?;
        let eoff = Self::entry_off(slot);
        if buf[eoff] != KIND_FILE {
            return Err(Error::Invalid);
        }
        let old_head = rd_u32(&buf, eoff + 2);
        let old_size = rd_u32(&buf, eoff + 6);
        let dcap = Self::DCAP as u32;
        let num = new_size.div_ceil(dcap) as usize;

        // Build the new chain backwards so each block's next pointer is known when written.
        let mut next = NIL;
        let mut new_head = NIL;
        let mut i = num;
        while i > 0 {
            i -= 1;
            let nb = match self.alloc_block() {
                Ok(b) => b,
                Err(e) => {
                    self.free_chain(new_head);
                    return Err(e);
                }
            };
            let bstart = i as u32 * dcap;
            let valid = (new_size - bstart).min(dcap) as usize;
            let mut blk = [0u8; BS];
            // Base content: the corresponding old block (same alignment), if any.
            if bstart < old_size {
                if let Some(ob) = self.chain_block_at(old_head, bstart)? {
                    let mut obuf = [0u8; BS];
                    self.dev.read(ob, 0, &mut obuf)?;
                    let ov_old = (old_size - bstart).min(dcap) as usize;
                    blk[..ov_old].copy_from_slice(&obuf[..ov_old]);
                }
            }
            // Overlay the written region.
            for j in 0..valid {
                let fpos = bstart + j as u32;
                if fpos >= ov_off && (fpos - ov_off) < ov.len() as u32 {
                    blk[j] = ov[(fpos - ov_off) as usize];
                }
            }
            wr_u32(&mut blk, BS - 4, next);
            if let Err(e) = self.dev.erase(nb).and_then(|_| self.dev.prog(nb, 0, &blk)) {
                self.free_one(nb);
                self.free_chain(new_head);
                return Err(e);
            }
            new_head = nb;
            next = nb;
        }

        wr_u32(&mut buf, eoff + 2, new_head);
        wr_u32(&mut buf, eoff + 6, new_size);
        mp.commit(self.dev, &buf[..Self::DPL])?;
        self.free_chain(old_head);
        Ok(())
    }

    /// The existing block holding byte `off` of a chain, or `None` if the chain is shorter.
    fn chain_block_at(&self, head: u32, off: u32) -> Result<Option<u32>, Error> {
        let target = off / Self::DCAP as u32;
        let mut b = head;
        for _ in 0..target {
            if b == NIL {
                return Ok(None);
            }
            b = self.read_next(b)?;
        }
        Ok((b != NIL).then_some(b))
    }

    // ----- format & mount -----

    /// Format a fresh, empty filesystem (an empty root directory at blocks 0/1).
    pub fn format(&self) -> Result<(), Error> {
        if self.dev.geometry().block_size as usize != BS || self.dev.geometry().block_count as usize != BLOCKS {
            return Err(Error::Invalid);
        }
        let mut mp = MetaPair::<BS>::format(self.dev, 0, 1)?;
        let mut buf = [0u8; BS];
        wr_u32(&mut buf, 0, 0); // root's parent is itself
        mp.commit(self.dev, &buf[..Self::DPL])?;
        self.st.lock(|s| {
            for u in s.used.iter_mut() {
                *u = false;
            }
            s.used[0] = true;
            s.used[1] = true;
            s.cursor = 2;
            s.open = [None; LFS_MAX_OPEN];
            s.inited = true;
        });
        Ok(())
    }

    /// Mount an already-formatted filesystem: rebuild the used-block bitmap by scanning the
    /// directory tree (the sole allocator truth; orphans are reclaimed by their absence).
    pub fn mount(&self) -> Result<(), Error> {
        if self.dev.geometry().block_size as usize != BS {
            return Err(Error::Invalid);
        }
        self.st.lock(|s| {
            for u in s.used.iter_mut() {
                *u = false;
            }
            s.open = [None; LFS_MAX_OPEN];
            let mut wl = [0u32; LFS_WALK_STACK];
            s.used[0] = true;
            s.used[1] = true;
            wl[0] = 0;
            let mut wn = 1usize;
            let mut iters = 0usize;
            while wn > 0 {
                iters += 1;
                if iters > BLOCKS * 2 {
                    return Err(Error::Integrity);
                }
                wn -= 1;
                let d = wl[wn];
                let mp = MetaPair::<BS>::mount(self.dev, d, d + 1)?;
                let mut buf = [0u8; BS];
                mp.read(self.dev, &mut buf)?;
                for slot in 0..Self::SLOTS {
                    let off = Self::entry_off(slot);
                    match buf[off] {
                        KIND_FILE => {
                            let head = rd_u32(&buf, off + 2);
                            self.mark_chain(s, head)?;
                        }
                        KIND_DIR => {
                            let cb = rd_u32(&buf, off + 2);
                            if (cb as usize) + 1 >= BLOCKS {
                                return Err(Error::Integrity);
                            }
                            s.used[cb as usize] = true;
                            s.used[cb as usize + 1] = true;
                            if wn >= LFS_WALK_STACK {
                                return Err(Error::NoResources);
                            }
                            wl[wn] = cb;
                            wn += 1;
                        }
                        _ => {}
                    }
                }
            }
            s.cursor = 2;
            s.inited = true;
            Ok(())
        })
    }

    fn mark_chain(&self, s: &mut State<BLOCKS>, head: u32) -> Result<(), Error> {
        let mut b = head;
        let mut n = 0;
        while b != NIL {
            if (b as usize) >= BLOCKS {
                return Err(Error::Integrity);
            }
            s.used[b as usize] = true;
            b = self.read_next(b)?;
            n += 1;
            if n > BLOCKS {
                return Err(Error::Integrity);
            }
        }
        Ok(())
    }

    fn require_inited(&self) -> Result<(), Error> {
        if self.st.lock(|s| s.inited) { Ok(()) } else { Err(Error::NotReady) }
    }
}

impl<const BLOCKS: usize, const BS: usize> FileSystem for FlashFs<BLOCKS, BS> {
    fn root(&self) -> FsVnode {
        vnode_dir(0)
    }

    fn lookup(&self, dir: FsVnode, name: &str) -> Result<FsVnode, Error> {
        self.require_inited()?;
        if is_file(dir) {
            return Err(Error::NotADirectory);
        }
        let b0 = addr(dir);
        let (_, buf) = self.load_dir(b0)?;
        match name {
            "." => Ok(dir),
            ".." => Ok(vnode_dir(rd_u32(&buf, 0))),
            _ => {
                let slot = Self::find_slot(&buf, name).ok_or(Error::NotFound)?;
                let off = Self::entry_off(slot);
                if buf[off] == KIND_DIR {
                    Ok(vnode_dir(rd_u32(&buf, off + 2)))
                } else {
                    Ok(vnode_file(b0, slot))
                }
            }
        }
    }

    fn stat(&self, v: FsVnode) -> Result<Stat, Error> {
        self.require_inited()?;
        if is_file(v) {
            let (_, buf) = self.load_dir(addr(v))?;
            let off = Self::entry_off(file_slot(v));
            if buf[off] != KIND_FILE {
                return Err(Error::NotFound);
            }
            let size = rd_u32(&buf, off + 6);
            Ok(Stat { kind: NodeKind::File, size: size as u64, blocks: size.div_ceil(Self::DCAP as u32), mtime: 0, vnode: v })
        } else {
            Ok(Stat { kind: NodeKind::Dir, size: 0, blocks: 2, mtime: 0, vnode: v })
        }
    }

    fn open(&self, v: FsVnode, _mode: OpenMode) -> Result<OpenId, Error> {
        self.require_inited()?;
        if !is_file(v) {
            return Err(Error::IsADirectory);
        }
        self.st.lock(|s| {
            for (i, slot) in s.open.iter_mut().enumerate() {
                if slot.is_none() {
                    *slot = Some(v.0);
                    return Ok(OpenId(i as u16));
                }
            }
            Err(Error::NoResources)
        })
    }

    fn read(&self, f: OpenId, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let v = self.st.lock(|s| s.open.get(f.0 as usize).copied().flatten()).ok_or(Error::BadHandle)?;
        let v = FsVnode(v);
        let (_, dir) = self.load_dir(addr(v))?;
        let eoff = Self::entry_off(file_slot(v));
        if dir[eoff] != KIND_FILE {
            return Err(Error::NotFound);
        }
        let head = rd_u32(&dir, eoff + 2);
        let size = rd_u32(&dir, eoff + 6) as u64;
        if off >= size {
            return Ok(0);
        }
        let avail = (size - off).min(buf.len() as u64) as usize;
        let dcap = Self::DCAP;
        let mut done = 0;
        while done < avail {
            let pos = off + done as u64;
            let within = (pos % dcap as u64) as usize;
            let blk = match self.chain_block_at(head, pos as u32)? {
                Some(b) => b,
                None => break,
            };
            let n = (dcap - within).min(avail - done);
            let mut bbuf = [0u8; BS];
            self.dev.read(blk, 0, &mut bbuf)?;
            buf[done..done + n].copy_from_slice(&bbuf[within..within + n]);
            done += n;
        }
        Ok(done)
    }

    fn write(&self, f: OpenId, off: u64, buf: &[u8]) -> Result<usize, Error> {
        let v = self.st.lock(|s| s.open.get(f.0 as usize).copied().flatten()).ok_or(Error::BadHandle)?;
        let v = FsVnode(v);
        if off + buf.len() as u64 > ADDR_MASK as u64 * Self::DCAP as u64 {
            return Err(Error::NoSpace);
        }
        let (_, dir) = self.load_dir(addr(v))?;
        let eoff = Self::entry_off(file_slot(v));
        let old_size = rd_u32(&dir, eoff + 6) as u64;
        let new_size = old_size.max(off + buf.len() as u64) as u32;
        self.rewrite(addr(v), file_slot(v), new_size, off as u32, buf)?;
        Ok(buf.len())
    }

    fn truncate(&self, f: OpenId, len: u64) -> Result<(), Error> {
        let v = self.st.lock(|s| s.open.get(f.0 as usize).copied().flatten()).ok_or(Error::BadHandle)?;
        let v = FsVnode(v);
        if len > ADDR_MASK as u64 * Self::DCAP as u64 {
            return Err(Error::NoSpace);
        }
        self.rewrite(addr(v), file_slot(v), len as u32, 0, &[])
    }

    fn close(&self, f: OpenId) {
        self.st.lock(|s| {
            if let Some(slot) = s.open.get_mut(f.0 as usize) {
                *slot = None;
            }
        });
    }

    fn create(&self, dir: FsVnode, name: &str, kind: NodeKind) -> Result<FsVnode, Error> {
        self.require_inited()?;
        if is_file(dir) {
            return Err(Error::NotADirectory);
        }
        if name.len() > NAME {
            return Err(Error::NameTooLong);
        }
        let b0 = addr(dir);
        let (mut mp, mut buf) = self.load_dir(b0)?;
        if Self::find_slot(&buf, name).is_some() {
            return Err(Error::Exists);
        }
        let slot = Self::free_slot(&buf).ok_or(Error::NoSpace)?;
        let off = Self::entry_off(slot);
        let result;
        match kind {
            NodeKind::File => {
                buf[off] = KIND_FILE;
                wr_u32(&mut buf, off + 2, NIL); // empty chain
                wr_u32(&mut buf, off + 6, 0); // size 0
                result = vnode_file(b0, slot);
            }
            NodeKind::Dir => {
                let cb = self.alloc_pair()?;
                // Initialise the child's (empty) metadata pair with us as its parent.
                let mut child = MetaPair::<BS>::format(self.dev, cb, cb + 1).inspect_err(|_| {
                    self.free_one(cb);
                    self.free_one(cb + 1);
                })?;
                let mut cbuf = [0u8; BS];
                wr_u32(&mut cbuf, 0, b0);
                child.commit(self.dev, &cbuf[..Self::DPL])?;
                buf[off] = KIND_DIR;
                wr_u32(&mut buf, off + 2, cb);
                wr_u32(&mut buf, off + 6, cb + 1);
                result = vnode_dir(cb);
            }
        }
        buf[off + 1] = name.len() as u8;
        buf[off + 10..off + 10 + name.len()].copy_from_slice(name.as_bytes());
        mp.commit(self.dev, &buf[..Self::DPL])?;
        Ok(result)
    }

    fn unlink(&self, dir: FsVnode, name: &str) -> Result<(), Error> {
        self.require_inited()?;
        let b0 = addr(dir);
        let (mut mp, mut buf) = self.load_dir(b0)?;
        let slot = Self::find_slot(&buf, name).ok_or(Error::NotFound)?;
        let off = Self::entry_off(slot);
        let (kind, a) = (buf[off], rd_u32(&buf, off + 2));
        // Tombstone the slot and commit first (atomic removal), then reclaim blocks.
        buf[off] = KIND_FREE;
        mp.commit(self.dev, &buf[..Self::DPL])?;
        match kind {
            KIND_FILE => self.free_chain(a),
            KIND_DIR => {
                self.free_one(a);
                self.free_one(a + 1);
            }
            _ => {}
        }
        Ok(())
    }

    fn rename(&self, odir: FsVnode, old: &str, ndir: FsVnode, new: &str) -> Result<(), Error> {
        self.require_inited()?;
        // v1: same-directory rename only (a single atomic pair commit). Cross-directory
        // rename needs bounded global move state and is a documented limitation.
        if addr(odir) != addr(ndir) {
            return Err(Error::Unsupported);
        }
        if new.len() > NAME {
            return Err(Error::NameTooLong);
        }
        let b0 = addr(odir);
        let (mut mp, mut buf) = self.load_dir(b0)?;
        let slot = Self::find_slot(&buf, old).ok_or(Error::NotFound)?;
        if Self::find_slot(&buf, new).is_some() {
            return Err(Error::Exists);
        }
        let off = Self::entry_off(slot);
        buf[off + 10..off + 10 + NAME].fill(0);
        buf[off + 1] = new.len() as u8;
        buf[off + 10..off + 10 + new.len()].copy_from_slice(new.as_bytes());
        mp.commit(self.dev, &buf[..Self::DPL])
    }

    fn readdir(&self, dir: FsVnode, cookie: u32, out: &mut DirEntry) -> Result<Option<u32>, Error> {
        self.require_inited()?;
        if is_file(dir) {
            return Err(Error::NotADirectory);
        }
        let b0 = addr(dir);
        let (_, buf) = self.load_dir(b0)?;
        for slot in cookie as usize..Self::SLOTS {
            let off = Self::entry_off(slot);
            if buf[off] == KIND_FREE {
                continue;
            }
            let len = buf[off + 1] as usize;
            out.set_name(core::str::from_utf8(&buf[off + 10..off + 10 + len]).unwrap_or(""));
            if buf[off] == KIND_DIR {
                out.kind = NodeKind::Dir;
                out.vnode = vnode_dir(rd_u32(&buf, off + 2));
            } else {
                out.kind = NodeKind::File;
                out.vnode = vnode_file(b0, slot);
            }
            return Ok(Some(slot as u32 + 1));
        }
        Ok(None)
    }

    fn sync(&self) -> Result<(), Error> {
        self.dev.sync()
    }

    fn info(&self) -> FsInfo {
        FsInfo { name: "flashfs", read_only: false, power_safe: true, block_size: BS as u32, case_sensitive: true }
    }
}
