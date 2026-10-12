//! An overlay (union) filesystem — the layered root filesystem a container runtime stacks an
//! image on: a read-only **lower** (the image) under a writable **upper** (the container's
//! changes). Reads see the merge (upper shadows lower); the first write to a lower file
//! **copies it up** into the upper layer; deletes record a **whiteout** that hides the lower
//! entry. The lower is never modified, so one image backs many containers.
//!
//! It composes two [`FileSystem`]s (e.g. a read-only image FS under a [`RamFs`](super::RamFs))
//! and is itself a `FileSystem`, so the VFS mounts it like any other. 100% safe Rust; bounded
//! fixed tables (no heap). Same-directory operations; cross-directory `rename` is unsupported.
//!
//! Classification: L3 services · overlay filesystem · safe · fs

use super::vnode::{DirEntry, FileSystem, FsInfo, FsVnode, NodeKind, OpenId, OpenMode, Stat};
use crate::Error;
use crate::config::FS_NAME_MAX;
use crate::kernel::cell::IrqCell;

const OV_NODES: usize = 64;
const OV_OPENS: usize = 16;
const OV_WHITEOUTS: usize = 32;
const COPY_CHUNK: usize = 256;

#[derive(Copy, Clone)]
struct Node {
    used: bool,
    parent: u32,
    name: [u8; FS_NAME_MAX],
    name_len: u8,
    kind: NodeKind,
    upper: Option<FsVnode>,
    lower: Option<FsVnode>,
}

const EMPTY_NODE: Node =
    Node { used: false, parent: 0, name: [0; FS_NAME_MAX], name_len: 0, kind: NodeKind::File, upper: None, lower: None };

#[derive(Copy, Clone)]
struct OvOpen {
    used: bool,
    in_upper: bool,
    sub: OpenId,
}

#[derive(Copy, Clone)]
struct Whiteout {
    used: bool,
    parent: u32,
    name: [u8; FS_NAME_MAX],
    name_len: u8,
}

struct State {
    nodes: [Node; OV_NODES],
    opens: [OvOpen; OV_OPENS],
    wh: [Whiteout; OV_WHITEOUTS],
}

/// A writable `upper` layered over a read-only `lower`.
pub struct OverlayFs<'a> {
    lower: &'a dyn FileSystem,
    upper: &'a dyn FileSystem,
    st: IrqCell<State>,
}

fn name_eq(a: &[u8], a_len: u8, b: &str) -> bool {
    &a[..a_len as usize] == b.as_bytes()
}

impl<'a> OverlayFs<'a> {
    /// Compose a read-only `lower` under a writable `upper`. Call once before mounting.
    pub fn new(lower: &'a dyn FileSystem, upper: &'a dyn FileSystem) -> Self {
        let mut nodes = [EMPTY_NODE; OV_NODES];
        // Node 0 is the merged root.
        nodes[0] = Node {
            used: true,
            parent: 0,
            name: [0; FS_NAME_MAX],
            name_len: 0,
            kind: NodeKind::Dir,
            upper: Some(upper.root()),
            lower: Some(lower.root()),
        };
        OverlayFs {
            lower,
            upper,
            st: IrqCell::new(State {
                nodes,
                opens: [OvOpen { used: false, in_upper: false, sub: OpenId(0) }; OV_OPENS],
                wh: [Whiteout { used: false, parent: 0, name: [0; FS_NAME_MAX], name_len: 0 }; OV_WHITEOUTS],
            }),
        }
    }

    fn is_whiteout(&self, parent: u32, name: &str) -> bool {
        self.st.lock(|s| s.wh.iter().any(|w| w.used && w.parent == parent && name_eq(&w.name, w.name_len, name)))
    }

    fn add_whiteout(&self, parent: u32, name: &str) -> Result<(), Error> {
        self.st.lock(|s| {
            for w in s.wh.iter_mut() {
                if !w.used {
                    let n = name.len().min(FS_NAME_MAX);
                    w.used = true;
                    w.parent = parent;
                    w.name[..n].copy_from_slice(&name.as_bytes()[..n]);
                    w.name_len = n as u8;
                    return Ok(());
                }
            }
            Err(Error::NoResources)
        })
    }

    fn clear_whiteout(&self, parent: u32, name: &str) {
        self.st.lock(|s| {
            for w in s.wh.iter_mut() {
                if w.used && w.parent == parent && name_eq(&w.name, w.name_len, name) {
                    w.used = false;
                }
            }
        });
    }

    /// Find an existing overlay node by (parent, name), or allocate one.
    fn intern(&self, parent: u32, name: &str, kind: NodeKind, upper: Option<FsVnode>, lower: Option<FsVnode>) -> Result<u32, Error> {
        self.st.lock(|s| {
            for (i, n) in s.nodes.iter().enumerate() {
                if n.used && n.parent == parent && name_eq(&n.name, n.name_len, name) {
                    // Refresh the layer presence (a copy-up may have added the upper side).
                    let i = i as u32;
                    let nn = &mut s.nodes[i as usize];
                    if upper.is_some() {
                        nn.upper = upper;
                    }
                    if lower.is_some() {
                        nn.lower = lower;
                    }
                    return Ok(i);
                }
            }
            for (i, n) in s.nodes.iter_mut().enumerate() {
                if !n.used {
                    let ln = name.len().min(FS_NAME_MAX);
                    n.used = true;
                    n.parent = parent;
                    n.name = [0; FS_NAME_MAX];
                    n.name[..ln].copy_from_slice(&name.as_bytes()[..ln]);
                    n.name_len = ln as u8;
                    n.kind = kind;
                    n.upper = upper;
                    n.lower = lower;
                    return Ok(i as u32);
                }
            }
            Err(Error::NoResources)
        })
    }

    fn node(&self, v: u32) -> Result<Node, Error> {
        self.st.lock(|s| s.nodes.get(v as usize).copied().filter(|n| n.used)).ok_or(Error::NotFound)
    }

    /// Ensure `v` (and its parent chain) exists in the upper layer, copying file contents up
    /// from the lower layer the first time. Returns the upper vnode of `v`.
    fn ensure_upper(&self, v: u32) -> Result<FsVnode, Error> {
        let n = self.node(v)?;
        if let Some(uv) = n.upper {
            return Ok(uv);
        }
        if v == 0 {
            return Ok(self.upper.root());
        }
        // The parent must exist in the upper layer first.
        let pupper = self.ensure_upper(n.parent)?;
        let name = {
            let mut buf = [0u8; FS_NAME_MAX];
            let len = n.name_len as usize;
            buf[..len].copy_from_slice(&n.name[..len]);
            (buf, len)
        };
        let name_str = core::str::from_utf8(&name.0[..name.1]).map_err(|_| Error::Invalid)?;
        let uv = match n.kind {
            NodeKind::Dir => self.upper.create(pupper, name_str, NodeKind::Dir)?,
            NodeKind::File => {
                let uv = self.upper.create(pupper, name_str, NodeKind::File)?;
                // Copy the lower file's bytes up.
                if let Some(lv) = n.lower {
                    let lo = self.lower.open(lv, OpenMode::READ)?;
                    let up = self.upper.open(uv, OpenMode::WRITE)?;
                    let mut off = 0u64;
                    let mut buf = [0u8; COPY_CHUNK];
                    loop {
                        let got = self.lower.read(lo, off, &mut buf)?;
                        if got == 0 {
                            break;
                        }
                        let mut w = 0;
                        while w < got {
                            w += self.upper.write(up, off + w as u64, &buf[w..got])?;
                        }
                        off += got as u64;
                    }
                    self.lower.close(lo);
                    self.upper.close(up);
                }
                uv
            }
        };
        self.st.lock(|s| s.nodes[v as usize].upper = Some(uv));
        Ok(uv)
    }
}

impl FileSystem for OverlayFs<'_> {
    fn root(&self) -> FsVnode {
        FsVnode(0)
    }

    fn lookup(&self, dir: FsVnode, name: &str) -> Result<FsVnode, Error> {
        let dv = dir.0;
        let n = self.node(dv)?;
        if name == ".." {
            return Ok(FsVnode(n.parent));
        }
        if self.is_whiteout(dv, name) {
            return Err(Error::NotFound);
        }
        let upper = n.upper.and_then(|uv| self.upper.lookup(uv, name).ok());
        let lower = n.lower.and_then(|lv| self.lower.lookup(lv, name).ok());
        if upper.is_none() && lower.is_none() {
            return Err(Error::NotFound);
        }
        // Kind comes from the authoritative (upper-preferred) layer.
        let kind = if let Some(uv) = upper {
            self.upper.stat(uv).map(|s| s.kind).unwrap_or(NodeKind::File)
        } else {
            self.lower.stat(lower.unwrap()).map(|s| s.kind).unwrap_or(NodeKind::File)
        };
        Ok(FsVnode(self.intern(dv, name, kind, upper, lower)?))
    }

    fn stat(&self, v: FsVnode) -> Result<Stat, Error> {
        let n = self.node(v.0)?;
        let mut st = if let Some(uv) = n.upper {
            self.upper.stat(uv)?
        } else if let Some(lv) = n.lower {
            self.lower.stat(lv)?
        } else {
            return Err(Error::NotFound);
        };
        st.vnode = v;
        st.kind = n.kind;
        Ok(st)
    }

    fn open(&self, v: FsVnode, mode: OpenMode) -> Result<OpenId, Error> {
        let writing = mode.contains(OpenMode::WRITE) || mode.contains(OpenMode::TRUNC);
        let (in_upper, sub) = if writing {
            let uv = self.ensure_upper(v.0)?;
            (true, self.upper.open(uv, mode)?)
        } else {
            let n = self.node(v.0)?;
            if let Some(uv) = n.upper {
                (true, self.upper.open(uv, mode)?)
            } else if let Some(lv) = n.lower {
                (false, self.lower.open(lv, mode)?)
            } else {
                return Err(Error::NotFound);
            }
        };
        self.st.lock(|s| {
            for (i, o) in s.opens.iter_mut().enumerate() {
                if !o.used {
                    *o = OvOpen { used: true, in_upper, sub };
                    return Ok(OpenId(i as u16));
                }
            }
            Err(Error::NoResources)
        })
    }

    fn read(&self, f: OpenId, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let o = self.st.lock(|s| s.opens[f.0 as usize]);
        if o.in_upper { self.upper.read(o.sub, off, buf) } else { self.lower.read(o.sub, off, buf) }
    }

    fn write(&self, f: OpenId, off: u64, buf: &[u8]) -> Result<usize, Error> {
        let o = self.st.lock(|s| s.opens[f.0 as usize]);
        if o.in_upper {
            self.upper.write(o.sub, off, buf)
        } else {
            Err(Error::PermissionDenied) // read-only lower; a write-mode open would have copied up
        }
    }

    fn truncate(&self, f: OpenId, len: u64) -> Result<(), Error> {
        let o = self.st.lock(|s| s.opens[f.0 as usize]);
        if o.in_upper { self.upper.truncate(o.sub, len) } else { Err(Error::PermissionDenied) }
    }

    fn close(&self, f: OpenId) {
        let o = self.st.lock(|s| {
            let o = s.opens[f.0 as usize];
            s.opens[f.0 as usize].used = false;
            o
        });
        if o.in_upper {
            self.upper.close(o.sub);
        } else {
            self.lower.close(o.sub);
        }
    }

    fn create(&self, dir: FsVnode, name: &str, kind: NodeKind) -> Result<FsVnode, Error> {
        let pupper = self.ensure_upper(dir.0)?;
        let uv = self.upper.create(pupper, name, kind)?;
        self.clear_whiteout(dir.0, name);
        Ok(FsVnode(self.intern(dir.0, name, kind, Some(uv), None)?))
    }

    fn unlink(&self, dir: FsVnode, name: &str) -> Result<(), Error> {
        let dn = self.node(dir.0)?;
        // Remove it from the upper layer if it is there.
        if let Some(uv) = dn.upper {
            if let Ok(target) = self.upper.lookup(uv, name) {
                let _ = target;
                self.upper.unlink(uv, name)?;
            }
        }
        // If the lower layer still provides it, record a whiteout so the merge hides it.
        if dn.lower.and_then(|lv| self.lower.lookup(lv, name).ok()).is_some() {
            self.add_whiteout(dir.0, name)?;
        }
        // Drop any interned overlay node for (dir, name).
        self.st.lock(|s| {
            for n in s.nodes.iter_mut() {
                if n.used && n.parent == dir.0 && name_eq(&n.name, n.name_len, name) {
                    n.used = false;
                }
            }
        });
        Ok(())
    }

    fn rename(&self, _odir: FsVnode, _old: &str, _ndir: FsVnode, _new: &str) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn readdir(&self, dir: FsVnode, cookie: u32, out: &mut DirEntry) -> Result<Option<u32>, Error> {
        let n = self.node(dir.0)?;
        // Phase 0 = upper entries; phase 1 = lower entries not shadowed by upper or whited out.
        // Cookie: top bit selects the phase, low 31 bits are the sub-filesystem's cookie.
        let phase = cookie >> 31;
        let mut sub = cookie & 0x7FFF_FFFF;
        if phase == 0 {
            if let Some(uv) = n.upper {
                if let Some(next) = self.upper.readdir(uv, sub, out)? {
                    return Ok(Some(next & 0x7FFF_FFFF));
                }
            }
            sub = 0; // fall through to the lower phase
        }
        // Lower phase.
        if let Some(lv) = n.lower {
            loop {
                match self.lower.readdir(lv, sub, out)? {
                    Some(next) => {
                        let name = core::str::from_utf8(&out.name[..out.name_len as usize]).unwrap_or("");
                        let shadowed = self.is_whiteout(dir.0, name)
                            || n.upper.and_then(|uv| self.upper.lookup(uv, name).ok()).is_some();
                        if !shadowed {
                            return Ok(Some((next & 0x7FFF_FFFF) | 0x8000_0000));
                        }
                        sub = next & 0x7FFF_FFFF; // skip the shadowed entry, keep scanning
                    }
                    None => return Ok(None),
                }
            }
        }
        Ok(None)
    }

    fn sync(&self) -> Result<(), Error> {
        self.upper.sync()
    }

    fn info(&self) -> FsInfo {
        FsInfo { name: "overlay", read_only: false, power_safe: false, block_size: 512, case_sensitive: true }
    }
}
