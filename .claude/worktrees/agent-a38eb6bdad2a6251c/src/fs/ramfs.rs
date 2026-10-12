//! A RAM filesystem: a fixed inode table plus a shared fixed-block arena, no heap and no
//! backing device. It is the bring-up vehicle for the whole VFS — it proves the
//! [`FileSystem`](super::vnode::FileSystem) trait, the mount table, path resolution and
//! the POSIX wiring before any block driver exists — and the natural implementation of
//! `/tmp`.
//!
//! Directories are sibling-linked lists of inode indices; file data is a chain of
//! fixed-size arena blocks allocated from a shared bitmap, exactly as `net::PacketPool`
//! allocates packet blocks. Total memory is bounded by
//! `INODES·sizeof(Inode) + BLOCKS·BS`.
//!
//! Classification: L3 services · fs: ram filesystem · safe · fs

use super::vnode::{DirEntry, FileSystem, FsInfo, FsVnode, NodeKind, OpenId, OpenMode, Stat};
use crate::Error;
use crate::config::FS_NAME_MAX;
use crate::kernel::cell::IrqCell;

const NIL: u16 = u16::MAX;

#[derive(Copy, Clone)]
struct Inode {
    used: bool,
    kind: NodeKind,
    name: [u8; FS_NAME_MAX],
    name_len: u8,
    parent: u16,
    first_child: u16,  // directories: head of the child list
    next_sibling: u16, // the next entry in the parent's child list
    first_block: u16,  // files: head of the data-block chain
    size: u32,
}

impl Inode {
    const EMPTY: Inode = Inode {
        used: false,
        kind: NodeKind::File,
        name: [0; FS_NAME_MAX],
        name_len: 0,
        parent: NIL,
        first_child: NIL,
        next_sibling: NIL,
        first_block: NIL,
        size: 0,
    };

    fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }
}

struct State<const INODES: usize, const BLOCKS: usize, const BS: usize> {
    inodes: [Inode; INODES],
    arena: [[u8; BS]; BLOCKS],
    block_next: [u16; BLOCKS],
    block_used: [bool; BLOCKS],
    inited: bool,
}

impl<const INODES: usize, const BLOCKS: usize, const BS: usize> State<INODES, BLOCKS, BS> {
    const fn new() -> Self {
        State {
            inodes: [Inode::EMPTY; INODES],
            arena: [[0; BS]; BLOCKS],
            block_next: [NIL; BLOCKS],
            block_used: [false; BLOCKS],
            inited: false,
        }
    }

    fn init_root(&mut self) {
        for b in self.block_used.iter_mut() {
            *b = false;
        }
        for i in self.inodes.iter_mut() {
            *i = Inode::EMPTY;
        }
        self.inodes[0] = Inode { used: true, kind: NodeKind::Dir, parent: 0, ..Inode::EMPTY };
        self.inodes[0].name[0] = b'/';
        self.inodes[0].name_len = 1;
        self.inited = true;
    }

    fn alloc_inode(&mut self) -> Option<u16> {
        self.inodes.iter().position(|n| !n.used).map(|i| i as u16)
    }

    fn alloc_block(&mut self) -> Option<u16> {
        let i = self.block_used.iter().position(|&u| !u)?;
        self.block_used[i] = true;
        self.block_next[i] = NIL;
        self.arena[i] = [0; BS];
        Some(i as u16)
    }

    fn free_chain(&mut self, mut b: u16) {
        while b != NIL {
            let next = self.block_next[b as usize];
            self.block_used[b as usize] = false;
            self.block_next[b as usize] = NIL;
            b = next;
        }
    }

    /// The block index holding byte offset `off` of file `ino`, allocating and zeroing the
    /// chain as needed to reach it. Returns `None` on out-of-space.
    fn block_for(&mut self, ino: u16, off: u32) -> Option<u16> {
        let target = (off / BS as u32) as usize;
        let mut cur = self.inodes[ino as usize].first_block;
        if cur == NIL {
            cur = self.alloc_block()?;
            self.inodes[ino as usize].first_block = cur;
        }
        for _ in 0..target {
            if self.block_next[cur as usize] == NIL {
                let nb = self.alloc_block()?;
                self.block_next[cur as usize] = nb;
            }
            cur = self.block_next[cur as usize];
        }
        Some(cur)
    }

    /// The existing block index holding byte `off`, or `None` if the chain is shorter.
    fn block_at(&self, ino: u16, off: u32) -> Option<u16> {
        let target = (off / BS as u32) as usize;
        let mut cur = self.inodes[ino as usize].first_block;
        for _ in 0..target {
            if cur == NIL {
                return None;
            }
            cur = self.block_next[cur as usize];
        }
        (cur != NIL).then_some(cur)
    }

    fn child_named(&self, dir: u16, name: &str) -> Option<u16> {
        let mut c = self.inodes[dir as usize].first_child;
        while c != NIL {
            if self.inodes[c as usize].name() == name {
                return Some(c);
            }
            c = self.inodes[c as usize].next_sibling;
        }
        None
    }

    fn detach_child(&mut self, dir: u16, child: u16) {
        let mut c = self.inodes[dir as usize].first_child;
        if c == child {
            self.inodes[dir as usize].first_child = self.inodes[child as usize].next_sibling;
            return;
        }
        while c != NIL {
            let next = self.inodes[c as usize].next_sibling;
            if next == child {
                self.inodes[c as usize].next_sibling = self.inodes[child as usize].next_sibling;
                return;
            }
            c = next;
        }
    }
}

/// A RAM filesystem of `INODES` inodes and `BLOCKS` data blocks of `BS` bytes each.
pub struct RamFs<const INODES: usize, const BLOCKS: usize, const BS: usize> {
    st: IrqCell<State<INODES, BLOCKS, BS>>,
}

impl<const INODES: usize, const BLOCKS: usize, const BS: usize> Default for RamFs<INODES, BLOCKS, BS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const INODES: usize, const BLOCKS: usize, const BS: usize> RamFs<INODES, BLOCKS, BS> {
    /// An empty RAM filesystem (lazily initialised with a root directory on first use).
    pub const fn new() -> Self {
        RamFs { st: IrqCell::new(State::new()) }
    }

    /// Reset to an empty filesystem (one empty root). Useful between tests.
    pub fn format(&self) {
        self.st.lock(|s| s.init_root());
    }

    fn with<R>(&self, f: impl FnOnce(&mut State<INODES, BLOCKS, BS>) -> R) -> R {
        self.st.lock(|s| {
            if !s.inited {
                s.init_root();
            }
            f(s)
        })
    }
}

impl<const INODES: usize, const BLOCKS: usize, const BS: usize> FileSystem for RamFs<INODES, BLOCKS, BS> {
    fn root(&self) -> FsVnode {
        self.with(|_| ());
        FsVnode(0)
    }

    fn lookup(&self, dir: FsVnode, name: &str) -> Result<FsVnode, Error> {
        self.with(|s| {
            let d = dir.0 as usize;
            if d >= INODES || !s.inodes[d].used || s.inodes[d].kind != NodeKind::Dir {
                return Err(Error::NotADirectory);
            }
            match name {
                "." => Ok(dir),
                ".." => Ok(FsVnode(s.inodes[d].parent as u32)),
                _ => s.child_named(dir.0 as u16, name).map(|c| FsVnode(c as u32)).ok_or(Error::NotFound),
            }
        })
    }

    fn stat(&self, v: FsVnode) -> Result<Stat, Error> {
        self.with(|s| {
            let i = v.0 as usize;
            if i >= INODES || !s.inodes[i].used {
                return Err(Error::NotFound);
            }
            let n = &s.inodes[i];
            let blocks = n.size.div_ceil(BS as u32);
            Ok(Stat { kind: n.kind, size: n.size as u64, blocks, mtime: 0, vnode: v })
        })
    }

    fn open(&self, v: FsVnode, _mode: OpenMode) -> Result<OpenId, Error> {
        self.with(|s| {
            let i = v.0 as usize;
            if i >= INODES || !s.inodes[i].used {
                return Err(Error::NotFound);
            }
            Ok(OpenId(v.0 as u16))
        })
    }

    fn read(&self, f: OpenId, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        self.with(|s| {
            let ino = f.0;
            let size = s.inodes[ino as usize].size;
            if off >= size as u64 {
                return Ok(0);
            }
            let avail = (size as u64 - off).min(buf.len() as u64) as usize;
            let mut done = 0;
            while done < avail {
                let pos = off as u32 + done as u32;
                let within = (pos % BS as u32) as usize;
                let blk = match s.block_at(ino, pos) {
                    Some(b) => b as usize,
                    None => break,
                };
                let n = (BS - within).min(avail - done);
                buf[done..done + n].copy_from_slice(&s.arena[blk][within..within + n]);
                done += n;
            }
            Ok(done)
        })
    }

    fn write(&self, f: OpenId, off: u64, buf: &[u8]) -> Result<usize, Error> {
        if off + buf.len() as u64 > u32::MAX as u64 {
            return Err(Error::Overflow);
        }
        self.with(|s| {
            let ino = f.0;
            let mut done = 0;
            while done < buf.len() {
                let pos = off as u32 + done as u32;
                let within = (pos % BS as u32) as usize;
                let blk = match s.block_for(ino, pos) {
                    Some(b) => b as usize,
                    None => {
                        if done == 0 {
                            return Err(Error::NoSpace);
                        }
                        break;
                    }
                };
                let n = (BS - within).min(buf.len() - done);
                s.arena[blk][within..within + n].copy_from_slice(&buf[done..done + n]);
                done += n;
            }
            let end = off as u32 + done as u32;
            if end > s.inodes[ino as usize].size {
                s.inodes[ino as usize].size = end;
            }
            Ok(done)
        })
    }

    fn truncate(&self, f: OpenId, len: u64) -> Result<(), Error> {
        if len > u32::MAX as u64 {
            return Err(Error::Overflow);
        }
        self.with(|s| {
            let ino = f.0;
            let len = len as u32;
            let size = s.inodes[ino as usize].size;
            if len < size {
                // Free whole blocks past the new end; keep the block that holds `len`.
                if len == 0 {
                    let head = s.inodes[ino as usize].first_block;
                    s.free_chain(head);
                    s.inodes[ino as usize].first_block = NIL;
                } else if let Some(last) = s.block_at(ino, len - 1) {
                    let tail = s.block_next[last as usize];
                    s.free_chain(tail);
                    s.block_next[last as usize] = NIL;
                }
                s.inodes[ino as usize].size = len;
            } else if len > size {
                // Grow: ensure a block exists for the last byte (new bytes read as zero).
                if len > 0 && s.block_for(ino, len - 1).is_none() {
                    return Err(Error::NoSpace);
                }
                s.inodes[ino as usize].size = len;
            }
            Ok(())
        })
    }

    fn close(&self, _f: OpenId) {}

    fn create(&self, dir: FsVnode, name: &str, kind: NodeKind) -> Result<FsVnode, Error> {
        if name.len() > FS_NAME_MAX {
            return Err(Error::NameTooLong);
        }
        self.with(|s| {
            let d = dir.0 as u16;
            if d as usize >= INODES || !s.inodes[d as usize].used || s.inodes[d as usize].kind != NodeKind::Dir {
                return Err(Error::NotADirectory);
            }
            if s.child_named(d, name).is_some() {
                return Err(Error::Exists);
            }
            let ni = s.alloc_inode().ok_or(Error::NoResources)?;
            let mut node = Inode { used: true, kind, parent: d, next_sibling: s.inodes[d as usize].first_child, ..Inode::EMPTY };
            let nb = name.as_bytes();
            node.name[..nb.len()].copy_from_slice(nb);
            node.name_len = nb.len() as u8;
            s.inodes[ni as usize] = node;
            s.inodes[d as usize].first_child = ni;
            Ok(FsVnode(ni as u32))
        })
    }

    fn unlink(&self, dir: FsVnode, name: &str) -> Result<(), Error> {
        self.with(|s| {
            let d = dir.0 as u16;
            let child = s.child_named(d, name).ok_or(Error::NotFound)?;
            s.detach_child(d, child);
            let head = s.inodes[child as usize].first_block;
            s.free_chain(head);
            s.inodes[child as usize] = Inode::EMPTY;
            Ok(())
        })
    }

    fn rename(&self, odir: FsVnode, old: &str, ndir: FsVnode, new: &str) -> Result<(), Error> {
        if new.len() > FS_NAME_MAX {
            return Err(Error::NameTooLong);
        }
        self.with(|s| {
            let (od, nd) = (odir.0 as u16, ndir.0 as u16);
            if nd as usize >= INODES || !s.inodes[nd as usize].used || s.inodes[nd as usize].kind != NodeKind::Dir {
                return Err(Error::NotADirectory);
            }
            let child = s.child_named(od, old).ok_or(Error::NotFound)?;
            if s.child_named(nd, new).is_some() {
                return Err(Error::Exists);
            }
            s.detach_child(od, child);
            let nb = new.as_bytes();
            s.inodes[child as usize].name = [0; FS_NAME_MAX];
            s.inodes[child as usize].name[..nb.len()].copy_from_slice(nb);
            s.inodes[child as usize].name_len = nb.len() as u8;
            s.inodes[child as usize].parent = nd;
            s.inodes[child as usize].next_sibling = s.inodes[nd as usize].first_child;
            s.inodes[nd as usize].first_child = child;
            Ok(())
        })
    }

    fn readdir(&self, dir: FsVnode, cookie: u32, out: &mut DirEntry) -> Result<Option<u32>, Error> {
        self.with(|s| {
            let d = dir.0 as usize;
            if d >= INODES || !s.inodes[d].used || s.inodes[d].kind != NodeKind::Dir {
                return Err(Error::NotADirectory);
            }
            let child = if cookie == 0 {
                s.inodes[d].first_child
            } else {
                s.inodes[(cookie - 1) as usize].next_sibling
            };
            if child == NIL {
                return Ok(None);
            }
            let n = &s.inodes[child as usize];
            out.set_name(n.name());
            out.kind = n.kind;
            out.vnode = FsVnode(child as u32);
            Ok(Some(child as u32 + 1))
        })
    }

    fn sync(&self) -> Result<(), Error> {
        Ok(())
    }

    fn info(&self) -> FsInfo {
        FsInfo { name: "ramfs", read_only: false, power_safe: false, block_size: BS as u32, case_sensitive: true }
    }
}
