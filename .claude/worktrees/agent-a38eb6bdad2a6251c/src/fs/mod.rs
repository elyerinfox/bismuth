//! The VFS core: the mount table, the global open-file table, and path resolution.
//!
//! One single-owner `IrqCell<Vfs>` holds the tables — a direct analogue of
//! `net::Global` — while the filesystem op-tables ([`FileSystem`]) are called *outside*
//! that lock, so a (possibly blocking) flash operation never runs under it. Per-file state
//! lives entirely in each filesystem's own pool; the VFS stores only the mount table and a
//! fixed open-file table mapping a handle to `(mount, open-id, position)`.
//!
//! Path resolution is iterative, recursion-free and bounded by `FS_PATH_MAX` /
//! `FS_NAME_MAX`; the resolver collapses `.` itself and passes `..` to the filesystem (so
//! `..` cannot escape the mount root). Mounts are longest-prefix matched.
//!
//! Classification: L3 services · fs: vfs core and mount table · safe · fs

pub mod fat;
pub mod flash;
pub mod overlay;
pub mod ramfs;
pub mod resident;
pub mod vnode;

pub use fat::FatFs;
pub use flash::FlashFs;
pub use overlay::OverlayFs;
pub use ramfs::RamFs;
pub use vnode::{DirEntry, FileSystem, FsInfo, FsVnode, NodeKind, OpenId, OpenMode, Stat};

use crate::Error;
use crate::config::{FS_NAME_MAX, FS_PATH_MAX, MAX_MOUNTS, MAX_OPEN_FILES};
use crate::kernel::cell::IrqCell;

/// Identifies a mount slot.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct MountId(pub u8);

/// An open file handle (index into the VFS open-file table).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct File(u16);

/// An open directory handle.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Dir(u16);

/// Seek origin for [`seek`].
#[derive(Copy, Clone, Debug)]
pub enum SeekFrom {
    Start(u64),
    Current(i64),
    End(i64),
}

struct Mount {
    path: &'static str,
    fs: &'static dyn FileSystem,
}

#[derive(Copy, Clone)]
struct OpenFile {
    mount: MountId,
    node: FsVnode,
    id: OpenId,
    pos: u64,
    mode: OpenMode,
    generation: u16,
}

struct Vfs {
    mounts: [Option<Mount>; MAX_MOUNTS],
    gens: [u16; MAX_MOUNTS],
    open: [Option<OpenFile>; MAX_OPEN_FILES],
}

static VFS: IrqCell<Vfs> = IrqCell::new(Vfs {
    mounts: [const { None }; MAX_MOUNTS],
    gens: [0; MAX_MOUNTS],
    open: [const { None }; MAX_OPEN_FILES],
});

// ----- mounting -----

/// Mount `fs` at absolute path `path` (trusted callers only).
pub fn mount(path: &'static str, fs: &'static dyn FileSystem) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    if !path.starts_with('/') {
        return Err(Error::Invalid);
    }
    VFS.lock(|v| {
        if v.mounts.iter().flatten().any(|m| m.path == path) {
            return Err(Error::Exists);
        }
        for i in 0..MAX_MOUNTS {
            if v.mounts[i].is_none() {
                v.gens[i] = v.gens[i].wrapping_add(1);
                v.mounts[i] = Some(Mount { path, fs });
                return Ok(());
            }
        }
        Err(Error::NoResources)
    })
}

/// Unmount the filesystem at `path`, syncing it and revoking outstanding handles (trusted
/// callers only). Fails with [`Error::Busy`] if any file on it is still open.
pub fn unmount(path: &str) -> Result<(), Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    let fs = VFS.lock(|v| {
        let i = v.mounts.iter().position(|m| m.as_ref().is_some_and(|m| m.path == path)).ok_or(Error::NotFound)?;
        if v.open.iter().flatten().any(|o| o.mount.0 as usize == i) {
            return Err(Error::Busy);
        }
        let fs = v.mounts[i].take().unwrap().fs;
        Ok(fs)
    })?;
    fs.sync()
}

// ----- path resolution -----

fn prefix_match(path: &str, mp: &str) -> bool {
    if mp == "/" {
        return path.starts_with('/');
    }
    path == mp || (path.starts_with(mp) && path.as_bytes().get(mp.len()) == Some(&b'/'))
}

/// `(mount, fs, generation, mount-point length)` of the innermost mount containing `path`.
fn mount_of(path: &str) -> Result<(MountId, &'static dyn FileSystem, u16, usize), Error> {
    VFS.lock(|v| {
        let mut best: Option<(usize, MountId, &'static dyn FileSystem, u16)> = None;
        for (i, m) in v.mounts.iter().enumerate() {
            let Some(m) = m else { continue };
            if prefix_match(path, m.path) && best.is_none_or(|(bl, ..)| m.path.len() > bl) {
                best = Some((m.path.len(), MountId(i as u8), m.fs, v.gens[i]));
            }
        }
        best.map(|(l, id, fs, g)| (id, fs, g, l))
    })
    .ok_or(Error::NotFound)
}

/// Resolve an absolute path to `(mount, fs, generation, vnode)`.
fn resolve(path: &str) -> Result<(MountId, &'static dyn FileSystem, u16, FsVnode), Error> {
    if path.len() > FS_PATH_MAX {
        return Err(Error::NameTooLong);
    }
    let (id, fs, g, prefix) = mount_of(path)?;
    let mut cur = fs.root();
    for comp in path[prefix..].split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp.len() > FS_NAME_MAX {
            return Err(Error::NameTooLong);
        }
        cur = fs.lookup(cur, comp)?;
    }
    Ok((id, fs, g, cur))
}

/// Resolve the *parent* directory of `path`, returning it plus the final component.
fn resolve_parent(path: &str) -> Result<(MountId, &'static dyn FileSystem, u16, FsVnode, &str), Error> {
    if path.len() > FS_PATH_MAX {
        return Err(Error::NameTooLong);
    }
    let trimmed = path.trim_end_matches('/');
    let idx = trimmed.rfind('/').ok_or(Error::Invalid)?;
    let name = &trimmed[idx + 1..];
    if name.is_empty() || name == "." || name == ".." {
        return Err(Error::Invalid);
    }
    if name.len() > FS_NAME_MAX {
        return Err(Error::NameTooLong);
    }
    let dir_path = if idx == 0 { "/" } else { &trimmed[..idx] };
    let (id, fs, g, dir) = resolve(dir_path)?;
    Ok((id, fs, g, dir, name))
}

// ----- open-file table helpers -----

fn alloc_slot(of: OpenFile) -> Option<u16> {
    VFS.lock(|v| {
        for i in 0..MAX_OPEN_FILES {
            if v.open[i].is_none() {
                v.open[i] = Some(of);
                return Some(i as u16);
            }
        }
        None
    })
}

/// Snapshot of an open slot plus its filesystem, validating the slot and mount generation.
fn snapshot(slot: u16) -> Result<(OpenFile, &'static dyn FileSystem), Error> {
    VFS.lock(|v| {
        let of = *v.open.get(slot as usize).and_then(|o| o.as_ref()).ok_or(Error::BadHandle)?;
        let m = v.mounts[of.mount.0 as usize].as_ref().ok_or(Error::BadHandle)?;
        if v.gens[of.mount.0 as usize] != of.generation {
            return Err(Error::BadHandle);
        }
        Ok((of, m.fs))
    })
}

fn set_pos(slot: u16, pos: u64) {
    VFS.lock(|v| {
        if let Some(Some(o)) = v.open.get_mut(slot as usize) {
            o.pos = pos;
        }
    });
}

fn free_slot(slot: u16) -> Option<OpenFile> {
    VFS.lock(|v| v.open.get_mut(slot as usize).and_then(|s| s.take()))
}

// ----- files -----

/// Open (optionally creating) a file at `path`.
pub fn open(path: &str, mode: OpenMode) -> Result<File, Error> {
    let (id, fs, g, node) = match resolve(path) {
        Ok(found) => {
            if mode.contains(OpenMode::CREATE) && mode.contains(OpenMode::EXCL) {
                return Err(Error::Exists);
            }
            found
        }
        Err(Error::NotFound) if mode.contains(OpenMode::CREATE) => {
            let (id, fs, g, dir, name) = resolve_parent(path)?;
            let v = fs.create(dir, name, NodeKind::File)?;
            (id, fs, g, v)
        }
        Err(e) => return Err(e),
    };
    finish_open(id, fs, g, node, mode)
}

/// Shared open tail: validate it's a file, apply `TRUNC`/`APPEND`, and allocate a handle.
fn finish_open(id: MountId, fs: &'static dyn FileSystem, g: u16, node: FsVnode, mode: OpenMode) -> Result<File, Error> {
    if fs.stat(node)?.kind == NodeKind::Dir {
        return Err(Error::IsADirectory);
    }
    let oid = fs.open(node, mode)?;
    if mode.contains(OpenMode::TRUNC) && mode.contains(OpenMode::WRITE) {
        if let Err(e) = fs.truncate(oid, 0) {
            fs.close(oid);
            return Err(e);
        }
    }
    let pos = if mode.contains(OpenMode::APPEND) { fs.stat(node)?.size } else { 0 };
    let of = OpenFile { mount: id, node, id: oid, pos, mode, generation: g };
    match alloc_slot(of) {
        Some(slot) => Ok(File(slot)),
        None => {
            fs.close(oid);
            Err(Error::NoResources)
        }
    }
}

/// Read from the current position, advancing it.
pub fn read(f: File, buf: &mut [u8]) -> Result<usize, Error> {
    let (of, fs) = snapshot(f.0)?;
    if !of.mode.contains(OpenMode::READ) {
        return Err(Error::PermissionDenied);
    }
    // Serve from the hot-file residency cache if the whole file is resident.
    if let Some(n) = resident::try_serve(of.mount.0, of.node.0, of.generation, of.pos, buf) {
        set_pos(f.0, of.pos + n as u64);
        return Ok(n);
    }
    let n = fs.read(of.id, of.pos, buf)?;
    set_pos(f.0, of.pos + n as u64);
    // Consider promoting the whole (small) file into residency.
    if resident::enabled() {
        if let Ok(st) = fs.stat(of.node) {
            if st.size as usize <= resident::max_file() {
                resident::observe(of.mount.0, of.node.0, of.generation, st.size as u32, |dst| {
                    let mut done = 0usize;
                    while done < dst.len() {
                        let k = fs.read(of.id, done as u64, &mut dst[done..])?;
                        if k == 0 {
                            break;
                        }
                        done += k;
                    }
                    Ok(done)
                });
            }
        }
    }
    Ok(n)
}

/// Write at the current position (or the end, for `APPEND`), advancing it.
pub fn write(f: File, buf: &[u8]) -> Result<usize, Error> {
    let (of, fs) = snapshot(f.0)?;
    if !of.mode.contains(OpenMode::WRITE) {
        return Err(Error::PermissionDenied);
    }
    let off = if of.mode.contains(OpenMode::APPEND) { fs.stat(of.node)?.size } else { of.pos };
    let n = fs.write(of.id, off, buf)?;
    set_pos(f.0, off + n as u64);
    resident::invalidate(of.mount.0, of.node.0); // write-through coherency
    Ok(n)
}

/// Move the file position; returns the new absolute position.
pub fn seek(f: File, from: SeekFrom) -> Result<u64, Error> {
    let (of, fs) = snapshot(f.0)?;
    let base = match from {
        SeekFrom::Start(o) => return {
            set_pos(f.0, o);
            Ok(o)
        },
        SeekFrom::Current(d) => (of.pos as i64, d),
        SeekFrom::End(d) => (fs.stat(of.node)?.size as i64, d),
    };
    let newpos = base.0.checked_add(base.1).ok_or(Error::Overflow)?;
    if newpos < 0 {
        return Err(Error::Invalid);
    }
    set_pos(f.0, newpos as u64);
    Ok(newpos as u64)
}

/// Truncate an open file to `len`.
pub fn ftruncate(f: File, len: u64) -> Result<(), Error> {
    let (of, fs) = snapshot(f.0)?;
    if !of.mode.contains(OpenMode::WRITE) {
        return Err(Error::PermissionDenied);
    }
    fs.truncate(of.id, len)?;
    resident::invalidate(of.mount.0, of.node.0);
    Ok(())
}

/// Flush an open file's filesystem to stable storage.
pub fn fsync(f: File) -> Result<(), Error> {
    let (_, fs) = snapshot(f.0)?;
    fs.sync()
}

/// Metadata of an open file.
pub fn fstat(f: File) -> Result<Stat, Error> {
    let (of, fs) = snapshot(f.0)?;
    fs.stat(of.node)
}

/// Close an open file.
pub fn close(f: File) {
    if let Some(of) = free_slot(f.0) {
        let fs = VFS.lock(|v| {
            v.mounts[of.mount.0 as usize]
                .as_ref()
                .filter(|_| v.gens[of.mount.0 as usize] == of.generation)
                .map(|m| m.fs)
        });
        if let Some(fs) = fs {
            fs.close(of.id);
        }
    }
}

// ----- metadata & namespace ops -----

/// Metadata of the node at `path`.
pub fn stat(path: &str) -> Result<Stat, Error> {
    let (_, fs, _, node) = resolve(path)?;
    fs.stat(node)
}

/// Create a directory at `path`.
pub fn mkdir(path: &str) -> Result<(), Error> {
    let (_, fs, _, dir, name) = resolve_parent(path)?;
    if fs.lookup(dir, name).is_ok() {
        return Err(Error::Exists);
    }
    fs.create(dir, name, NodeKind::Dir).map(|_| ())
}

/// Remove a file at `path`.
pub fn unlink(path: &str) -> Result<(), Error> {
    let (id, fs, _, dir, name) = resolve_parent(path)?;
    let v = fs.lookup(dir, name)?;
    if fs.stat(v)?.kind == NodeKind::Dir {
        return Err(Error::IsADirectory);
    }
    fs.unlink(dir, name)?;
    resident::invalidate(id.0, v.0);
    Ok(())
}

/// Remove an empty directory at `path`.
pub fn rmdir(path: &str) -> Result<(), Error> {
    let (_, fs, _, dir, name) = resolve_parent(path)?;
    let v = fs.lookup(dir, name)?;
    if fs.stat(v)?.kind != NodeKind::Dir {
        return Err(Error::NotADirectory);
    }
    let mut e = DirEntry::default();
    if fs.readdir(v, 0, &mut e)?.is_some() {
        return Err(Error::NotEmpty);
    }
    fs.unlink(dir, name)
}

/// Rename `old` to `new` (same mount only in v1).
pub fn rename(old: &str, new: &str) -> Result<(), Error> {
    let (oid, ofs, ogen, odir, oname) = resolve_parent(old)?;
    let (nid, _, ngen, ndir, nname) = resolve_parent(new)?;
    if oid != nid || ogen != ngen {
        return Err(Error::Unsupported);
    }
    ofs.rename(odir, oname, ndir, nname)
}

// ----- directories -----

/// Open a directory for iteration.
pub fn opendir(path: &str) -> Result<Dir, Error> {
    let (id, fs, g, node) = resolve(path)?;
    if fs.stat(node)?.kind != NodeKind::Dir {
        return Err(Error::NotADirectory);
    }
    let of = OpenFile { mount: id, node, id: OpenId(0), pos: 0, mode: OpenMode::READ, generation: g };
    alloc_slot(of).map(Dir).ok_or(Error::NoResources)
}

/// Read the next directory entry into `out`. Returns `false` at end of directory.
pub fn readdir(d: Dir, out: &mut DirEntry) -> Result<bool, Error> {
    let (of, fs) = snapshot(d.0)?;
    match fs.readdir(of.node, of.pos as u32, out)? {
        Some(next) => {
            set_pos(d.0, next as u64);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// The directory's current iteration cursor (an opaque position for [`seekdir`]).
pub fn telldir(d: Dir) -> Result<u64, Error> {
    snapshot(d.0).map(|(of, _)| of.pos)
}

/// Restore a directory's iteration cursor to a value from [`telldir`] (e.g. to re-read an entry
/// that did not fit a caller's buffer).
pub fn seekdir(d: Dir, pos: u64) {
    set_pos(d.0, pos);
}

/// Close a directory handle.
pub fn closedir(d: Dir) {
    free_slot(d.0);
}

// ----- per-domain mount namespaces (capability-confined subtrees) -----

pub use crate::security::DirCap;
use crate::security::{DomainId, Handle, Object, Rights};

/// Grant domain `d` a capability over the subtree at `path`, visible in its namespace as
/// `name` (resolved by [`DirCap::open`]). Trusted callers, before `seal`. The domain can
/// thereafter name only files at or below `path`, with `rights` — a static per-domain
/// chroot that beats a run-time-routed or ambient-global namespace.
pub fn grant_dir(d: DomainId, path: &str, rights: Rights, name: &'static str) -> Result<Handle, Error> {
    if !crate::security::current_is_trusted() || crate::security::is_sealed() {
        return Err(Error::PermissionDenied);
    }
    let (id, fs, g, node) = resolve(path)?;
    if fs.stat(node)?.kind != NodeKind::Dir {
        return Err(Error::NotADirectory);
    }
    crate::security::grant_object(d, Object::Dir { mount: id.0, vnode: node.0, generation: g }, rights, name)
}

/// The mount's filesystem, if `generation` still matches (else the mount was replaced).
fn mount_checked(mount: u8, generation: u16) -> Result<&'static dyn FileSystem, Error> {
    VFS.lock(|v| {
        let m = v.mounts.get(mount as usize).and_then(|m| m.as_ref()).ok_or(Error::BadHandle)?;
        if v.gens[mount as usize] != generation {
            return Err(Error::BadHandle);
        }
        Ok(m.fs)
    })
}

/// Resolve `rel` starting at subtree root `base`, never escaping above it (`..` at the root
/// is a no-op). This is what confines a domain to its granted subtree.
fn resolve_from(fs: &'static dyn FileSystem, base: FsVnode, rel: &str) -> Result<FsVnode, Error> {
    if rel.len() > FS_PATH_MAX {
        return Err(Error::NameTooLong);
    }
    let mut cur = base;
    let mut depth = 0u32;
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if depth > 0 {
                cur = fs.lookup(cur, "..")?;
                depth -= 1;
            }
            continue;
        }
        if comp.len() > FS_NAME_MAX {
            return Err(Error::NameTooLong);
        }
        cur = fs.lookup(cur, comp)?;
        depth += 1;
    }
    Ok(cur)
}

/// Like [`resolve_from`] but returns the parent directory and the final component.
fn resolve_parent_from<'a>(fs: &'static dyn FileSystem, base: FsVnode, rel: &'a str) -> Result<(FsVnode, &'a str), Error> {
    let trimmed = rel.trim_end_matches('/');
    let (dir_rel, name) = match trimmed.rfind('/') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(Error::Invalid);
    }
    if name.len() > FS_NAME_MAX {
        return Err(Error::NameTooLong);
    }
    let dir = resolve_from(fs, base, dir_rel)?;
    Ok((dir, name))
}

/// Open a file by a path relative to `cap`'s subtree, honouring the capability's rights.
pub fn cap_open(cap: &DirCap, rel: &str, mode: OpenMode) -> Result<File, Error> {
    let need = if mode.contains(OpenMode::WRITE) || mode.contains(OpenMode::CREATE) { Rights::WRITE } else { Rights::READ };
    let (mount, base, g, _caller) = cap.resolve(need)?;
    let fs = mount_checked(mount, g)?;
    let base = FsVnode(base);
    match resolve_from(fs, base, rel) {
        Ok(node) => {
            if mode.contains(OpenMode::CREATE) && mode.contains(OpenMode::EXCL) {
                return Err(Error::Exists);
            }
            finish_open(MountId(mount), fs, g, node, mode)
        }
        Err(Error::NotFound) if mode.contains(OpenMode::CREATE) => {
            let (dir, name) = resolve_parent_from(fs, base, rel)?;
            let v = fs.create(dir, name, NodeKind::File)?;
            finish_open(MountId(mount), fs, g, v, mode)
        }
        Err(e) => Err(e),
    }
}

/// Open a directory for iteration by a path relative to `cap`'s subtree (requires `READ`). The
/// confined analogue of [`opendir`]: a sandboxed/loaded task lists only directories at or below
/// the subtree the capability names.
pub fn cap_opendir(cap: &DirCap, rel: &str) -> Result<Dir, Error> {
    let (mount, base, g, _caller) = cap.resolve(Rights::READ)?;
    let fs = mount_checked(mount, g)?;
    let node = resolve_from(fs, FsVnode(base), rel)?;
    if fs.stat(node)?.kind != NodeKind::Dir {
        return Err(Error::NotADirectory);
    }
    let of = OpenFile { mount: MountId(mount), node, id: OpenId(0), pos: 0, mode: OpenMode::READ, generation: g };
    alloc_slot(of).map(Dir).ok_or(Error::NoResources)
}

/// Metadata of a node relative to `cap`'s subtree (requires `READ`).
pub fn cap_stat(cap: &DirCap, rel: &str) -> Result<Stat, Error> {
    let (mount, base, g, _caller) = cap.resolve(Rights::READ)?;
    let fs = mount_checked(mount, g)?;
    let node = resolve_from(fs, FsVnode(base), rel)?;
    fs.stat(node)
}

/// Create a directory relative to `cap`'s subtree (requires `WRITE`).
pub fn cap_mkdir(cap: &DirCap, rel: &str) -> Result<(), Error> {
    let (mount, base, g, _caller) = cap.resolve(Rights::WRITE)?;
    let fs = mount_checked(mount, g)?;
    let (dir, name) = resolve_parent_from(fs, FsVnode(base), rel)?;
    if fs.lookup(dir, name).is_ok() {
        return Err(Error::Exists);
    }
    fs.create(dir, name, NodeKind::Dir).map(|_| ())
}

/// Remove a file relative to `cap`'s subtree (requires `WRITE`).
pub fn cap_unlink(cap: &DirCap, rel: &str) -> Result<(), Error> {
    let (mount, base, g, _caller) = cap.resolve(Rights::WRITE)?;
    let fs = mount_checked(mount, g)?;
    let (dir, name) = resolve_parent_from(fs, FsVnode(base), rel)?;
    let v = fs.lookup(dir, name)?;
    if fs.stat(v)?.kind == NodeKind::Dir {
        return Err(Error::IsADirectory);
    }
    fs.unlink(dir, name)?;
    resident::invalidate(mount, v.0);
    Ok(())
}

/// Open a file through `cap` and grant the calling (sandboxed) domain a rights-checked
/// [`FileCap`](crate::security::FileCap) handle to it, for use over the syscall ABI.
pub fn cap_open_handle(cap: &DirCap, rel: &str, mode: OpenMode) -> Result<crate::security::Handle, Error> {
    let file = cap_open(cap, rel, mode)?;
    let rights = if mode.contains(OpenMode::WRITE) { Rights::READ | Rights::WRITE } else { Rights::READ };
    crate::security::FileCap::grant(file.0, rights)
}

/// Read a file by its VFS open-file index (the caller must have validated the capability).
pub fn read_at_handle(open: u16, buf: &mut [u8]) -> Result<usize, Error> {
    read(File(open), buf)
}

/// Write a file by its VFS open-file index (capability validated by the caller).
pub fn write_at_handle(open: u16, buf: &[u8]) -> Result<usize, Error> {
    write(File(open), buf)
}

/// Close a file by its VFS open-file index (capability validated by the caller).
pub fn close_handle(open: u16) {
    close(File(open));
}

/// Clear all mounts and open files (host simulator, between runs).
#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    VFS.lock(|v| {
        for m in v.mounts.iter_mut() {
            *m = None;
        }
        for o in v.open.iter_mut() {
            *o = None;
        }
    });
}
