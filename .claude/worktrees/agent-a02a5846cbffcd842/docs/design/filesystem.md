# Filesystem

Source: `src/driver/block/` (the block device class, always built) and `src/fs/`
(the VFS, feature `fs`). Research input:
[research/filesystems.md](../research/filesystems.md). This page describes what is
**built** today: the block device class with its simulated media, the VFS core (mount
table, path resolver, open-file table, generation revocation), the RAM filesystem, and
the POSIX wiring. Where the build differs from the research proposal, the differences
are listed in [as built vs. research](#as-built-vs-the-research-proposal).

```text
  apps ── fs:: API (open/read/write/seek/stat/mkdir/...) ── POSIX fds (Kind::File, O_CREAT/O_TRUNC/O_APPEND)
            │                                                           L4 compat::posix::unistd
  ┌─────────▼────────────────────────────────────────────────────────────────────────┐
  │ VFS core (one IrqCell<Vfs>): mount table (longest-prefix) + global open-file table │  L3 fs
  │ iterative path resolver (bounded by FS_PATH_MAX / FS_NAME_MAX; `..` passed to the FS)│
  │ generation-stamped handles (a remount revokes stale File/Dir handles)              │
  ├────────────────────────────────────────────────────────────────────────────────────┤
  │ FileSystem trait (the "superblock"), keyed by FsVnode(u32) / OpenId(u16) integers    │
  │   RamFs<INODES,BLOCKS,BS>: inode table + shared block arena  (littlefs / FAT: Planned)│
  └──────────────────────────────┬───────────────────────────────────────────────────────┘
                                 │ (RamFs needs no device; a flash/disk FS will call down)
  ┌──────────────────────────────▼───────────────────────────────────────────────────────┐
  │ block registry (trusted register/find) + fast path: geometry/read_at/prog_at/erase_blk/sync│ L2 driver::block
  │ BlockDevice trait (read/prog/erase/sync + BlockGeometry, MediaKind)                    │
  │ sim media: SimFlash (erase-before-write + power-cut injection), SimDisk, SimRam        │
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

## Principles

The subsystem is deliberately shaped like the [network subsystem](networking.md): a
single-owner core holds the registries and calls a thin device contract directly on the
fast path, and all heavy per-object state lives outside the core.

- **The vnode is a value, not an object.** Following Kleiman's vnode split and Linux's
  superblock/inode/file model, but adapted to a no-heap MCU: a node is an
  [`FsVnode`](#the-filesystem-trait) — a `u32` the filesystem interprets (an inode index,
  a cluster, a metadata-pair id) — never an allocated object with an embedded vtable. The
  op-table lives on the *mount* (`&'static dyn FileSystem`), not on each file.
- **Per-file state lives in the filesystem, never in the VFS.** `open` returns an
  `OpenId` into the filesystem's own fixed pool. The VFS stores only the mount table and
  a fixed open-file table that maps a handle to `(mount, node, open-id, position, mode,
  generation)`. This is the single most important decision for staying heap-free.
- **The core never calls a device under its lock.** One `IrqCell<Vfs>` holds the tables,
  exactly as `net::Global` holds the interface state, and the `FileSystem` op-tables are
  always called *outside* that lock, so a (possibly blocking) flash operation never runs
  under it. The block registry releases its lock before returning a device reference for
  the same reason.
- **Two planes, as with `/dev/<ifname>`.** A filesystem calls the `BlockDevice` trait on
  a fast path (`block::read_at` and friends), the direct analogue of `net::transmit`.
  Block I/O is offset-addressed and bulk, so it does **not** flow through the `Op` enum or
  the per-device middleware chain; the data-plane layers (cache, partition, read-only,
  wear counter) are *composition wrappers* that implement `BlockDevice` around an inner
  one, not `Op` middleware (the direct analogue of `SoftRing` wrapping a `FrameDevice`) —
  see [composition wrappers](#composition-wrappers-blockcache-partition-readonly-wearcounter).
- **Static bounds.** Mounts, open files, block devices, path and name lengths, and the
  RamFs inode/arena sizes are all compile-time `const`s (see
  [configuration](#configuration-knobs)). Nothing grows at run time.
- **Safe Rust only.** All block *logic* and all filesystem logic is safe Rust. A real
  controller's registers and DMA would live in `arch::mmio` (the TCB), exactly as network
  MAC drivers do; the simulated media contain no `unsafe`.

## Block device class (`driver::block`, L2, always built)

The block class lives at L2 and is compiled unconditionally (it is useful on its own and
must be reachable by the `fs` layer above it). `DeviceClass::Block` has long been a
reserved discriminant in `driver/mod.rs`; this subsystem gives it a trait, a registry and
simulated drivers.

### The `BlockDevice` trait

```rust
pub trait BlockDevice: Sync {
    fn geometry(&self) -> BlockGeometry;
    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error>;
    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error>;
    fn erase(&self, blk: u32) -> Result<(), Error>;
    fn sync(&self) -> Result<(), Error> { Ok(()) }   // default: nothing to flush
}
```

The `read / prog / erase / sync` shape plus `BlockGeometry` is the intersection of
littlefs's `lfs_config` block ops and Rust's `embedded-storage` NOR-flash traits, so one
trait drives raw erase-before-write flash and managed (SD/eMMC) sectors alike. The caller
guarantees alignment and in-block bounds; an implementation may still validate and return
`Error::Invalid` (the simulated devices do, to catch filesystem bugs).

`BlockGeometry` is static per device:

| field | meaning |
|-------|---------|
| `read_size` | minimum/alignment of a read, in bytes |
| `prog_size` | minimum/alignment of a program, in bytes |
| `block_size` | erase-block / sector size, in bytes |
| `block_count` | number of erase blocks |
| `block_cycles` | rated erase cycles (`0` = unknown); feeds the wear policy |
| `kind` | the `MediaKind` |

Helpers: `capacity()` returns `block_size * block_count` as a `u64` (so a >4 GB disk is
addressable while block indices stay 32-bit); `erase_value()` returns the byte a block
holds after an erase (`0` for non-flash media).

`MediaKind` captures how the medium behaves on write:

| variant | behaviour |
|---------|-----------|
| `Flash { erase_value: u8 }` | NOR/NAND: a region must be erased (to `erase_value`, usually `0xFF`) before it can be programmed, and a programmed region cannot be rewritten without an erase |
| `Disk` | managed SD/eMMC/USB-MSC: sectors overwrite in place, `erase` is a no-op, the card's FTL does wear leveling |
| `Ram` | volatile RAM disk: overwrite in place, `sync` is a no-op |

### Simulated media (`driver::block::sim`)

Three sim devices enforce their medium's contract strictly, so filesystem bugs surface in
the simulator rather than in the field. Each is a const-generic `<const BLOCKS: usize,
const BS: usize>` with a `const fn new()` (and a `Default`), so instances are `static`.

| type | geometry | semantics |
|------|----------|-----------|
| `SimFlash<BLOCKS, BS>` | `read_size = prog_size = 1`, `block_size = BS`, `block_cycles = 500`, `Flash { 0xFF }` | byte-programmable; fresh blocks read `0xFF`; programming a byte that is not currently `0xFF` is rejected with `Error::Io` (littlefs's "a word is never written twice"); `erase` restores `0xFF` |
| `SimDisk<BLOCKS, BS>` | `read_size = prog_size = block_size = BS`, `block_cycles = 0`, `Disk` | sector-granular, overwrite-in-place; `erase` is a no-op that leaves data intact; models SD/eMMC |
| `SimRam<BLOCKS, BS>` | `read_size = prog_size = 1`, `block_size = BS`, `block_cycles = 0`, `Ram` | byte-granular, overwrite-in-place; `erase` zeroes a block |

`SimFlash` adds **power-cut injection** for power-loss-recovery tests: `power_cut_after(n)`
arms the *n*-th following mutating op (prog or erase, `1` = the next one) to apply only its
first half and then fail with `Error::Io` — a classic torn write. Injection is one-shot;
the op after the torn one is clean. `peek(blk, off)` and `is_erased(blk)` let a test
inspect the raw medium. `SimDisk` also exposes `peek`.

### Registry and fast path

Block devices register into a small static registry (`MAX_BLOCKDEVS` slots) and are
addressed by a `BlockId(pub u8)`:

```rust
pub fn register(name: &'static str, dev: &'static dyn BlockDevice) -> Result<BlockId, Error>;
pub fn find(name: &str) -> Option<BlockId>;

// Fast path a filesystem uses (no Op, no middleware chain — like net::transmit):
pub fn geometry(id: BlockId) -> Result<BlockGeometry, Error>;
pub fn read_at(id: BlockId, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error>;
pub fn prog_at(id: BlockId, blk: u32, off: u32, data: &[u8]) -> Result<(), Error>;
pub fn erase_blk(id: BlockId, blk: u32) -> Result<(), Error>;
pub fn sync(id: BlockId) -> Result<(), Error>;
```

`register` is **trusted-only** (like `net::register`): an isolated domain gets
`PermissionDenied`. A duplicate name is `Exists`, a full registry is `NoResources`. The
fast-path functions resolve the id to its `&'static dyn BlockDevice`, **releasing the
registry lock before the device call** so no caller ever holds the lock across a
(possibly blocking) device operation; an unknown id is `NotFound`.

There is **no `/dev/<name>` block control node yet**, and the `0x09xx` block ioctl page is
reserved but unimplemented — see [as built vs. research](#as-built-vs-the-research-proposal).

### Composition wrappers (`BlockCache`, `Partition`, `ReadOnly`, `WearCounter`)

Because block I/O bypasses the `Op` enum, the data-plane layers are `BlockDevice`
*wrappers* around an inner `BlockDevice` (`src/driver/block/cache.rs`), composed at build
time. Each is `const`-constructible, statically sized and safe, and forwards `geometry`
and the data ops to the inner device:

| wrapper | behaviour |
|---------|-----------|
| `Partition<D>::new(inner, base, count)` | exposes blocks `base..base+count` as a device of `count` blocks, with relative offsets; an out-of-range relative block is `Invalid`. Geometry reports the reduced `block_count` |
| `ReadOnly<D>::new(inner)` | passes reads through; every `prog`/`erase` returns `Error::ReadOnly` (e.g. a signed firmware image) |
| `WearCounter<D, BLOCKS>::new(inner)` | passes everything through and counts erases per block; `erases(blk)`, `total()` and `peak()` report the spread, for telemetry and wear-leveling tests |
| `BlockCache<D, N, BS>::new(inner, write_through)` | caches `N` whole blocks of `BS` bytes (`BS` must equal the inner `block_size`) with LRU eviction. Dirty lines are written back on eviction and on `sync()`; `write_through = true` flushes each write immediately. Over `MediaKind::Flash` a flush erases the block before reprogramming it, so the cache can rewrite a region that raw program-once flash would reject |

They compose at build time, for example
`static ROOT: Partition<SimFlash<256, 4096>> = Partition::new(SimFlash::new(), 0, 64);`.

Two caveats the module records and callers must respect:

- **Write-through under a power-safe filesystem.** `BlockCache` must be constructed
  write-through when a power-safe filesystem (littlefs, when it lands) sits on top:
  littlefs owns its own caching, and a write-back layer between it and the medium would
  turn a committed CRC into a promise still only in volatile RAM. Write-back is for
  `MediaKind::Disk` and read-mostly mounts, where a torn write is already the medium's
  problem.
- **The cache holds its line lock across the inner device call**, so it is intended for
  non-blocking / polled media; a backend whose `prog`/`erase` can block for hundreds of
  milliseconds should not sit under it unchanged.

## VFS core (`fs`, L3, feature `fs`)

`src/fs/mod.rs` is the superblock registry: one `IrqCell<Vfs>` holding the mount table,
a per-slot generation counter, and the global open-file table.

```rust
static VFS: IrqCell<Vfs> = IrqCell::new(Vfs {
    mounts: [const { None }; MAX_MOUNTS],
    gens:   [0; MAX_MOUNTS],
    open:   [const { None }; MAX_OPEN_FILES],
});
```

### The `FileSystem` trait

Every mounted filesystem is a `&'static dyn FileSystem` (`src/fs/vnode.rs`), keyed
entirely by integers it chooses:

```rust
pub trait FileSystem: Sync {
    fn root(&self) -> FsVnode;
    fn lookup(&self, dir: FsVnode, name: &str) -> Result<FsVnode, Error>;
    fn stat(&self, v: FsVnode) -> Result<Stat, Error>;

    fn open(&self, v: FsVnode, mode: OpenMode) -> Result<OpenId, Error>;
    fn read(&self, f: OpenId, off: u64, buf: &mut [u8]) -> Result<usize, Error>;
    fn write(&self, f: OpenId, off: u64, buf: &[u8]) -> Result<usize, Error>;
    fn truncate(&self, f: OpenId, len: u64) -> Result<(), Error>;
    fn close(&self, f: OpenId);

    fn create(&self, dir: FsVnode, name: &str, kind: NodeKind) -> Result<FsVnode, Error>;
    fn unlink(&self, dir: FsVnode, name: &str) -> Result<(), Error>;
    fn rename(&self, odir: FsVnode, old: &str, ndir: FsVnode, new: &str) -> Result<(), Error>;

    fn readdir(&self, dir: FsVnode, cookie: u32, out: &mut DirEntry) -> Result<Option<u32>, Error>;
    fn sync(&self) -> Result<(), Error>;
    fn info(&self) -> FsInfo;
}
```

Value types:

- `FsVnode(pub u32)` — a filesystem-defined node identity, stable for the life of the
  mount. `OpenId(pub u16)` — a filesystem-defined open-file identity into the filesystem's
  own pool.
- `NodeKind::{File, Dir}` (defaults to `File`).
- `OpenMode(pub u8)` is a small flag set: `READ`, `WRITE`, `CREATE`, `TRUNC`, `APPEND`,
  `EXCL` (bits 0–5) plus `RDWR = READ | WRITE`. `contains(flag)` and `with(flag)` are
  `const`.
- `Stat { kind, size: u64, blocks: u32, mtime: u64, vnode }`.
- `DirEntry { name: [u8; FS_NAME_MAX], name_len: u8, kind, vnode }`, filled in place by
  `readdir` (no allocation); `name()` returns the UTF-8 slice and `set_name(s)` truncates
  to `FS_NAME_MAX`.
- `FsInfo { name, read_only, power_safe, block_size, case_sensitive }` — static facts for
  `statvfs` and policy.

Two design points make this re-entrant and heap-free: `read`/`write` take an explicit
`off`, so the VFS owns the file position (in the open-file table) and two handles can share
one open file; and `readdir` fills a caller-provided `DirEntry` and returns an opaque
resume `cookie` (`0` starts, `None` ends), the `getdents` shape without allocation.

### Mount table and path resolution

```rust
pub fn mount(path: &'static str, fs: &'static dyn FileSystem) -> Result<(), Error>;
pub fn unmount(path: &str) -> Result<(), Error>;
```

`mount` is **trusted-only** and requires an absolute `path` (`Invalid` otherwise); a
duplicate mount point is `Exists` and a full table is `NoResources`. `unmount` is
trusted-only too, fails with `Busy` if any file on the mount is still open, and otherwise
takes the slot and calls `fs.sync()`.

Path resolution (`resolve`) is **iterative, recursion-free and bounded** — a constant
stack depth is a hard MCU requirement:

1. A path longer than `FS_PATH_MAX` is `NameTooLong`.
2. `mount_of` picks the mount whose point is the **longest prefix** of the path (so the
   innermost of nested mounts wins).
3. Starting at `fs.root()`, each remaining component is walked one at a time. Empty
   components and `.` are skipped by the resolver; every other component — including `..` —
   is passed to `fs.lookup(dir, comp)`, so the filesystem resolves `..` against its own
   root and **`..` cannot escape the mount root** (important for the planned per-domain
   namespaces). A component longer than `FS_NAME_MAX` is `NameTooLong`.

`resolve_parent` returns the parent directory plus the final component, and is used by the
namespace operations (`mkdir`, `unlink`, `rmdir`, `rename`); it rejects a trailing `.` /
`..` / empty name with `Invalid`.

### Open-file table and generation revocation

An open handle (`File`, or `Dir` for directory iteration) is an index into the global
open-file table. Each slot records `(mount, node, open-id, position, mode, generation)`.

Each mount slot carries a generation counter that is bumped on every `mount` into that
slot. A handle records the generation at open time, and `snapshot` — run at the start of
every file operation — validates both that the slot is still mounted and that its
generation still matches, returning `BadHandle` otherwise. So a handle can never act on a
different filesystem later mounted in the same slot: a remount **revokes** every stale
handle. This is the `Device { index, generation }` and `security::Handle` pattern applied
to files.

### The `fs::` API

| function | behaviour |
|----------|-----------|
| `open(path, mode) -> File` | resolve `path`; `CREATE` makes a missing file (and `CREATE\|EXCL` on an existing one is `Exists`); opening a directory as a file is `IsADirectory`; `TRUNC`+`WRITE` empties it; `APPEND` starts the position at end of file |
| `read(f, buf) -> usize` | read at the current position and advance it; a handle without `READ` is `PermissionDenied` |
| `write(f, buf) -> usize` | write at the current position (or at end of file under `APPEND`) and advance it; a handle without `WRITE` is `PermissionDenied` |
| `seek(f, SeekFrom) -> u64` | `Start(u64)` / `Current(i64)` / `End(i64)`; a negative result is `Invalid`, an arithmetic wrap is `Overflow` |
| `ftruncate(f, len)` | resize an open file (needs `WRITE`) |
| `fsync(f)` | flush the file's filesystem to stable storage |
| `fstat(f) -> Stat` / `stat(path) -> Stat` | metadata of an open file / of a path |
| `close(f)` | release the handle and the filesystem's open-file state |
| `mkdir(path)` | create a directory (`Exists` if the name is taken) |
| `unlink(path)` | remove a file (`IsADirectory` on a directory) |
| `rmdir(path)` | remove an **empty** directory (`NotADirectory` / `NotEmpty` otherwise) |
| `rename(old, new)` | rename within one mount; a cross-mount rename is `Unsupported` |
| `opendir(path) -> Dir` / `readdir(d, &mut DirEntry) -> bool` / `closedir(d)` | iterate a directory; `readdir` returns `false` at end of directory |

## RamFs (`fs::ramfs`)

`RamFs<const INODES: usize, const BLOCKS: usize, const BS: usize>` is a fixed inode table
plus a shared fixed-block arena — no heap, no backing device. It is the bring-up vehicle
for the whole VFS (it proves the trait, the mount table, the resolver and the POSIX wiring
before any block driver exists) and the natural implementation of `/tmp`.

- **Directories are sibling-linked lists of inode indices.** A directory holds
  `first_child`; each child holds `next_sibling`. `readdir`'s cookie is derived from the
  next sibling index, so iteration needs no allocation.
- **File data is a chain of fixed `BS`-byte arena blocks**, allocated from a shared
  `block_used` bitmap exactly as `net::PacketPool` allocates packet blocks. Growth past the
  arena's capacity returns `NoSpace`. Total memory is bounded by
  `INODES·sizeof(Inode) + BLOCKS·BS`.
- `FsVnode(index)` is the inode index; the root is inode `0`. RamFs keeps no per-open
  state (position lives in the VFS open-file table), so `OpenId` mirrors the inode and
  `close` is a no-op.
- `info()` reports `name = "ramfs"`, `read_only = false`, `power_safe = false` (it is
  volatile, but it has no torn-write hazard, which makes it a clean oracle for VFS tests),
  `case_sensitive = true`.

Construction is `const`: `RamFs::new()` makes an empty filesystem that lazily initialises a
root directory on first use, and `format()` resets it to one empty root (useful between
tests). Both the kernel API and a board place a `RamFs` in a `static`.

## POSIX wiring (`compat::posix::unistd`, L4, features `posix` + `fs`)

With the `fs` feature on, the POSIX fd layer gained a `Kind::File(fs::File)` descriptor, so
`open` now resolves any **non-`/dev/`** path through the VFS (a `/dev/<name>` path still
goes to a device as before):

- `open(path, flags)` maps the low two bits (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) and
  `O_CREAT`/`O_TRUNC`/`O_APPEND`/`O_EXCL` onto an `OpenMode`, then calls `fs::open`.
- `read`/`write`/`close` route a `Kind::File` fd to `fs::read`/`fs::write`/`fs::close`.
- New calls, all `#[cfg(feature = "fs")]`: `lseek` (with `SEEK_SET`/`SEEK_CUR`/`SEEK_END`),
  `ftruncate`, `fsync`, `fstat`, `stat`, `mkdir` (the mode argument is accepted but
  ignored — Bismuth uses capabilities, not permission bits), `rmdir`, `unlink`, `rename`.
- A minimal `struct stat { st_mode, st_size, st_blocks, st_mtime }` with the file-type
  bits `S_IFMT`, `S_IFREG`, `S_IFDIR`. `poll` treats a regular file as always ready.

Because these functions are gated on `fs` inside the `posix` module, the POSIX file API
needs **both** the `posix` and `fs` features. On a build without `fs`, a non-`/dev/` path
returns `ENOENT` as it always did.

## Configuration knobs

All are build-time `BISMUTH_*` variables; see
[configuration](../reference/configuration.md#filesystems-fs).

| variable | constant | MCU default | host default | meaning |
|----------|----------|------------:|-------------:|---------|
| `BISMUTH_MAX_BLOCKDEVS` | `MAX_BLOCKDEVS` | 4 | 4 | registered block devices |
| `BISMUTH_MAX_MOUNTS` | `MAX_MOUNTS` | 4 | 4 | simultaneously mounted filesystems |
| `BISMUTH_MAX_OPEN_FILES` | `MAX_OPEN_FILES` | 8 | 32 | global open-file table slots (files + directories) |
| `BISMUTH_FS_PATH_MAX` | `FS_PATH_MAX` | 128 | 128 | longest absolute path the resolver accepts |
| `BISMUTH_FS_NAME_MAX` | `FS_NAME_MAX` | 64 | 64 | longest single component / filename |
| `BISMUTH_RAMFS_INODES` | `RAMFS_INODES` | 16 | 64 | RamFs inodes (files + directories) |
| `BISMUTH_RAMFS_BLOCKS` | `RAMFS_BLOCKS` | 16 | 128 | RamFs data blocks in the shared arena |
| `BISMUTH_RAMFS_BLOCK` | `RAMFS_BLOCK` | 256 | 256 | bytes per RamFs data block |

`FS_NAME_MAX` sizes the `DirEntry` name buffer and the resolver's per-component limit. The
`RAMFS_*` knobs only set the defaults the kernel uses for its own RamFs; a
`RamFs<INODES, BLOCKS, BS>` is instantiated with whatever const generics you pass (the
test suite uses small sizes like `RamFs<32, 64, 64>`).

## Security interplay

- `block::register` and `fs::{mount, unmount}` require a **trusted** caller (kernel or a
  `trusted` domain); isolated domains get `PermissionDenied`, exactly as with
  `net::register`.
- File operations themselves (`open`, `read`, `write`, …) carry no capability check yet:
  any caller can open any path on a mounted filesystem. The planned per-domain mount
  namespaces and directory-subtree capabilities (`FileCap`/`DirCap`, manifest `dirs = […]`)
  are **not** built — see below. Treat the current VFS as a single, trusted, global
  namespace.
- An operation on a stale handle returns `BadHandle`. In an isolated domain `BadHandle` is
  also a security violation under `BadHandlePolicy::Kill` (see
  [security](security.md#violations-and-the-bad-handle-policy)), so generation revocation
  on remount is enforced the same way as for devices and security handles.

## As built vs. the research proposal

[research/filesystems.md](../research/filesystems.md) is the fuller design rationale. This
first part implements the block class, the VFS core, RamFs and the POSIX wiring. The rest
is designed but **not yet built**:

| research proposal | as built |
|-------------------|----------|
| `BlockDevice` trait + `BlockGeometry` + `MediaKind`, sim flash/disk/ram | built, with `SimFlash` power-cut injection |
| `/dev/<name>` block control node (`DeviceClass::Block`) with a `0x09xx` ioctl page and raw `dd`-style fd access | **Planned.** `register` adds to the registry only; no control device, no block ioctls, no raw fd path |
| data-plane `BlockDevice` wrappers: `BlockCache`, `Partition`, `ReadOnly`, `WearCounter` | built (`src/driver/block/cache.rs`), composed at build time; `BlockCache` is write-back or write-through |
| `FileSystem` trait, mount table, iterative resolver, global open-file table | built |
| generation-checked file/dir handles | built (per-mount generation; revoked on remount) |
| RamFs over a static inode table + shared block arena | built |
| littlefs subset (power-safe flash FS, re-implemented in safe Rust) | **Planned** |
| FAT12/16/32 + VFAT (managed-media interop) | **Planned** |
| hot-file residency cache (Layer 2) + block cache (Layer 1), capability-governed | **Planned** |
| per-domain mount namespaces, directory-subtree capabilities, manifest `dirs = […]` | **Planned.** File ops are currently unchecked within the global namespace |
| symlinks, nested-mount traversal beyond the mount point, cross-directory/cross-mount rename | **Planned / limited.** No symlinks; cross-mount `rename` is `Unsupported` |

## Classification and files

| file | classification |
|------|----------------|
| `src/driver/block/mod.rs` | `L2 devices · block device class · safe · always` |
| `src/driver/block/cache.rs` | `L2 devices · block: write-back cache / wrappers · safe · always` |
| `src/driver/block/sim.rs` | `L2 devices · block driver: simulated flash/disk · safe · always` |
| `src/fs/mod.rs` | `L3 services · fs: vfs core and mount table · safe · fs` |
| `src/fs/vnode.rs` | `L3 services · fs: vfs contract · safe · fs` |
| `src/fs/ramfs.rs` | `L3 services · fs: ram filesystem · safe · fs` |

`tests/structure.rs` adds `crate::fs` to the forbidden-import list for `L0 port`,
`L1 kernel` and `L2 devices`, so nothing below L3 can reach up into the filesystem (the
block class at L2 stays reachable by `fs` from above). See the
[module map](../reference/module-map.md).
