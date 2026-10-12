//! The VFS contract: the value types and the [`FileSystem`] trait that every mounted
//! filesystem implements.
//!
//! Following Kleiman's vnode split and Linux's superblock/inode/file model, but adapted to
//! a no-heap MCU: the "vnode" is a value ([`FsVnode`], a `u32` the filesystem interprets —
//! an inode index, a cluster, a metadata-pair id), never an allocated object with an
//! embedded vtable. The op-table lives on the *mount* (`&'static dyn FileSystem`), and all
//! heavy per-file state lives in each filesystem's own statically-sized pool, never in the
//! VFS. This is the single most important decision for staying heap-free.
//!
//! Classification: L3 services · fs: vfs contract · safe · fs

use crate::Error;
use crate::config::FS_NAME_MAX;

/// A filesystem-defined node identity, stable for the life of the mount.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct FsVnode(pub u32);

/// A filesystem-defined open-file identity (into the filesystem's own open-file pool).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OpenId(pub u16);

/// Whether a node is a regular file or a directory.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum NodeKind {
    #[default]
    File,
    Dir,
}

/// How a file is opened (the subset of POSIX `O_*` flags the VFS needs).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OpenMode(pub u8);

impl OpenMode {
    pub const READ: OpenMode = OpenMode(1 << 0);
    pub const WRITE: OpenMode = OpenMode(1 << 1);
    pub const CREATE: OpenMode = OpenMode(1 << 2);
    pub const TRUNC: OpenMode = OpenMode(1 << 3);
    pub const APPEND: OpenMode = OpenMode(1 << 4);
    pub const EXCL: OpenMode = OpenMode(1 << 5);

    /// Read + write.
    pub const RDWR: OpenMode = OpenMode(Self::READ.0 | Self::WRITE.0);

    /// Whether every bit in `flag` is set.
    pub const fn contains(self, flag: OpenMode) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// Union of two flag sets.
    pub const fn with(self, flag: OpenMode) -> OpenMode {
        OpenMode(self.0 | flag.0)
    }
}

/// Metadata about a node (`stat`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub kind: NodeKind,
    pub size: u64,
    pub blocks: u32,
    /// Modification time (kernel ticks or RTC seconds; `0` if unknown).
    pub mtime: u64,
    pub vnode: FsVnode,
}

/// One directory entry, filled in place by [`FileSystem::readdir`] (no allocation).
#[derive(Copy, Clone, Debug)]
pub struct DirEntry {
    pub name: [u8; FS_NAME_MAX],
    pub name_len: u8,
    pub kind: NodeKind,
    pub vnode: FsVnode,
}

impl Default for DirEntry {
    fn default() -> Self {
        DirEntry { name: [0; FS_NAME_MAX], name_len: 0, kind: NodeKind::File, vnode: FsVnode(0) }
    }
}

impl DirEntry {
    /// The entry name as a string slice (invalid UTF-8 becomes empty).
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }

    /// Set the entry name from `s`, truncating to `FS_NAME_MAX`.
    pub fn set_name(&mut self, s: &str) {
        let n = s.len().min(FS_NAME_MAX);
        self.name[..n].copy_from_slice(&s.as_bytes()[..n]);
        self.name_len = n as u8;
    }
}

/// Static facts about a mounted filesystem (for `statvfs` and policy).
#[derive(Copy, Clone, Debug)]
pub struct FsInfo {
    pub name: &'static str,
    pub read_only: bool,
    pub power_safe: bool,
    pub block_size: u32,
    pub case_sensitive: bool,
}

/// A mounted filesystem instance. One `&'static dyn FileSystem` per mount.
///
/// Keyed entirely by integers the filesystem chooses, so the VFS stores no per-file memory.
/// `read`/`write` take an explicit `off` so the VFS owns the position (in the open-file
/// table), keeping the filesystem re-entrant and letting two handles share one open file.
pub trait FileSystem: Sync {
    /// The root directory's vnode.
    fn root(&self) -> FsVnode;

    /// Resolve one path component inside directory `dir`. The VFS collapses `.` itself;
    /// `..` and ordinary names reach here, so the filesystem resolves `..` (which must not
    /// escape the mount root).
    fn lookup(&self, dir: FsVnode, name: &str) -> Result<FsVnode, Error>;

    /// Metadata for a node.
    fn stat(&self, v: FsVnode) -> Result<Stat, Error>;

    /// Begin an open of `v`. Returns an [`OpenId`] into the filesystem's own pool.
    fn open(&self, v: FsVnode, mode: OpenMode) -> Result<OpenId, Error>;
    /// Read from an open file at absolute offset `off`.
    fn read(&self, f: OpenId, off: u64, buf: &mut [u8]) -> Result<usize, Error>;
    /// Write to an open file at absolute offset `off`.
    fn write(&self, f: OpenId, off: u64, buf: &[u8]) -> Result<usize, Error>;
    /// Resize an open file.
    fn truncate(&self, f: OpenId, len: u64) -> Result<(), Error>;
    /// Release an open file.
    fn close(&self, f: OpenId);

    /// Create a file or directory named `name` inside `dir`.
    fn create(&self, dir: FsVnode, name: &str, kind: NodeKind) -> Result<FsVnode, Error>;
    /// Remove `name` from `dir` (a file, or an empty directory).
    fn unlink(&self, dir: FsVnode, name: &str) -> Result<(), Error>;
    /// Move `old` in `odir` to `new` in `ndir`.
    fn rename(&self, odir: FsVnode, old: &str, ndir: FsVnode, new: &str) -> Result<(), Error>;

    /// Iterate a directory. `cookie` is an opaque resume position (`0` = start); returns the
    /// next cookie, or `None` at end of directory.
    fn readdir(&self, dir: FsVnode, cookie: u32, out: &mut DirEntry) -> Result<Option<u32>, Error>;

    /// Flush all dirty state to stable storage (`fsync` / unmount).
    fn sync(&self) -> Result<(), Error>;

    /// Static facts for `statvfs` and policy.
    fn info(&self) -> FsInfo;
}
