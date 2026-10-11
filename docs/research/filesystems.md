# Bismuth Filesystem Subsystem: Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: how the classic Unix vnode layer, Linux's VFS, littlefs, FAT and the MCU-class
> filesystems (SPIFFS, FatFs, Zephyr FS, Tock) are built, and an opinionated design for a
> Bismuth `fs` subsystem that fits Cortex-M / RISC-V MCUs with tens to hundreds of KB of
> RAM, static allocation, no heap, safe Rust only, and the existing `Driver` /
> `Middleware` / `DeviceCap` / domain model.
>
> Current Bismuth baseline (read from the tree): there is **no filesystem at all**. The
> only path namespace is `/dev/<name>`, resolved by `Device::find` (trusted) or
> `DeviceCap::open` (isolated domains) in `compat/posix/unistd.rs`; `open()` returns
> `ENOENT` for anything that does not start with `/dev/`. `DeviceClass::Block` is a
> reserved variant in `driver/mod.rs` with no trait, no registry and no driver behind it.
> The POSIX fd table knows `Console`, `Device`, `Cap` and `Socket` descriptors, no files.
> The pieces we build on already exist and are strong: fixed-block pools
> (`kernel::mem::Pool`, `net::PacketPool`), the generation-checked handle pattern
> (`Device { index, generation }`, `security::Handle`), rights-checked capabilities
> (`DeviceCap`), per-domain namespaces (`grant_device` + `DeviceCap::open`), a
> compile-time-validated manifest, and the deterministic host simulator with
> fault-injecting sim devices (`net::drivers::Wire`).

---

## 0. TL;DR

- **Copy the vnode split, not the vnode object.** Take Kleiman's filesystem-independent /
  filesystem-dependent boundary ([Vnodes, 1986][vnode-kleiman]) and Linux's four-object
  model (superblock / inode / dentry / file, [Linux VFS][linux-vfs]). But on a no-heap MCU
  the vnode is **not** an allocated object with an embedded op-table pointer. It is a small
  `(MountId, FsVnode)` pair where `FsVnode` is a `u32` the filesystem itself interprets
  (an inode number, a cluster, a metadata-pair id). The heavy per-file state lives inside
  each filesystem's own statically-sized pool, never in the VFS. This is the single most
  important decision for staying heap-free.
- **One `FileSystem` trait, integer-keyed.** A mount is a `&'static dyn FileSystem`
  implementing `lookup / open / read / write / close / stat / create / unlink / readdir /
  rename / truncate / sync` over `FsVnode` / `OpenId` integers. The VFS owns only a tiny
  mount table and a global open-file table that maps a handle to `(MountId, OpenId, pos)`.
  This mirrors how the net core owns interface state and calls `NetDevice` ring ops.
- **Block device class = L2 `driver::block`, modelled on `NetDevice`.** A `BlockDevice`
  trait with littlefs/`embedded-storage`-shaped ops (`read / prog / erase / sync`) and a
  `BlockGeometry` (`read_size / prog_size / block_size / block_count / block_cycles /
  kind`). One trait covers both NOR/NAND **flash** (erase-before-write) and **managed
  disks** (SD/eMMC, 512-byte sectors, no erase) via a `MediaKind`. Filesystems call the
  trait directly (fast path); a `/dev/<name>` *control* node of `DeviceClass::Block`
  exposes geometry/sync/erase ioctls and admin, exactly the two-plane split the net
  subsystem uses.
- **Block "middleware" is trait composition, not `Op` middleware.** Because block I/O is
  offset-addressed and never flows through the `Op` enum, the data-plane cache / wear
  counter / read-only / partition layers are `BlockDevice` *wrappers* (like `SoftRing`
  wraps `FrameDevice`), composed at build time. The existing `Op`-based middleware
  (`Stats`, `Trace`, `Exclusive`, `AccessPolicy`) still applies to the control node for
  audit and admin.
- **RAM FS first.** A `RamFs` over a static inode table plus a shared fixed-block arena is
  the bring-up vehicle for the whole VFS: it needs no hardware, is trivially
  host-testable, and proves the POSIX wiring before any block driver exists.
- **littlefs is the model for the flash FS, re-implemented in safe Rust.** We do **not**
  FFI to the C library (that would import `unsafe`). We port the on-disk format: metadata
  pairs (two-block logs with a revision count and CRC-committed entries, compaction and
  split), CTZ skip-lists for file data, inline small files, directories as a threaded
  linked list of metadata pairs, a free-list-free allocator with a fixed lookahead bitmap,
  dynamic wear leveling and read-back bad-block relocation, and commit-or-ignore power-loss
  recovery ([littlefs DESIGN][lfs-design], [SPEC][lfs-spec]). RAM is bounded by three
  static buffers (read cache, prog cache, lookahead) plus a per-open-file cache pool —
  the heap-free mapping of `lfs_config`'s buffers. Target **exact v2 on-disk compatibility**
  so the C reference (`littlefs-fuse`, `mklittlefs`) is a free differential oracle in CI.
- **FAT is for interop, on managed media only.** A read/write FAT12/16/32 driver with
  VFAT long names, for SD cards and host interchange (pull the card, read it on a PC).
  Plain 8.3 FAT was never patented; the Microsoft VFAT LFN patents have expired and the
  key one was invalidated by the German Federal Patent Court in 2013 ([ruling][fat-patent-de]),
  so a read/write LFN implementation is now unencumbered to ship. exFAT stays under active
  Microsoft licensing and is **not** implemented. FAT is neither power-fail-safe nor
  wear-levelled; it is explicitly documented as managed-media-only, which is why littlefs
  exists for raw flash.
- **File handles are capabilities; mounts are per-domain namespaces.** A file/dir handle
  is a rights-checked, generation-checked `Object::Dir` / `Object::File` in the caller's
  handle table, resolved *before* any filesystem logic runs — the `DeviceCap` pattern
  applied to storage. An isolated domain sees only the subtrees granted in the manifest
  (static per-domain namespaces, a compile-time chroot), which is cleaner than Zircon
  (routed at run time) and than every RTOS FS surveyed (ambient global namespace).
- **POSIX gets real paths.** Extend `open` to resolve non-`/dev/` paths through the VFS and
  add `lseek / stat / fstat / mkdir / rmdir / unlink / rename / opendir / readdir / fsync /
  ftruncate` plus `O_CREAT|O_TRUNC|O_APPEND`. A handful of new `Error` variants
  (`NotADirectory`, `IsADirectory`, `NotEmpty`, `ReadOnly`, `NameTooLong`, `NoSpace`) and
  their errno mappings, plus a `0x09xx` block-ioctl page.
- **Caching is a fixed budget, not growth (§4).** Two statically-sized layers: a block
  cache (the `BlockCache<D>` wrapper, write-through under a power-safe FS) and an optional
  *hot-file residency* cache that promotes whole hot small files into a fixed RAM pool
  (LFU/LRU, evict-coldest, never load a file that does not fit). Both are capability-gated:
  a per-domain byte budget and a per-mount/per-file `cacheable` bit, and caching the
  *plaintext* of an encrypted mount is opt-in only.
- **Do not build:** a Linux-style demand-paging page cache that grows to fill free RAM
  (needs a heap; `mmap` needs an MMU), a dentry hash cache, generic extended attributes,
  journaling on top of FAT, uid/gid/mode permission bits (capabilities replace them),
  hard links, an FTL for raw NAND (we target NOR + managed NAND), or exFAT.

---

## 1. Problem statement: where Bismuth is today

Bismuth can talk to UARTs, sensors, GPIO, I2C, displays, input devices and the network, all
through one clean `Driver` + `Middleware` + `DeviceCap` model with a `/dev/<name>`
namespace per domain. What it cannot do is **name or store a byte stream that outlives a
single `read`/`write`** — there is no file, no directory, no mount, no persistence beyond
whatever a driver keeps in its own registers.

Concretely, the gap shows up in three places:

1. **`compat/posix/unistd.rs::open`** hard-codes `path.strip_prefix("/dev/")` and returns
   `ENOENT` for everything else. There is no path resolver, no mount table, and the fd
   `Entry::Kind` enumerates `Console | Device(Device) | Cap(DeviceCap) | Socket(Sock)` —
   no `File`. `lseek`, `stat`, `mkdir`, `unlink`, `readdir`, `rename`, `fsync` do not
   exist.
2. **`driver/mod.rs`** reserves `DeviceClass::Block` but nothing implements it. There is no
   `BlockDevice` trait, no block registry, no geometry, no sim block/flash device. Every
   other class (`Char`, `Gpio`, `I2c`, `Sensor`, `Display`, `Input`, `Net`) has a trait or
   a class wrapper; `Block` is a stub.
3. **`security`** can grant a *device* to a domain (`grant_device` → `DeviceCap::open`) but
   has no notion of a *directory subtree* capability, so there is no way to give the
   `ota` domain write access to `/firmware` and nothing else.

The design below fills all three, in that order, re-using the subsystem shapes Bismuth
already ships rather than inventing new ones. The structural template throughout is the
**network subsystem** (`src/net/`): a single-owner core that holds the registries and calls
a thin device contract (`NetDevice`) directly on the fast path, with a `/dev/<name>`
control node and the normal middleware chain on the slow path. Filesystems are the same
shape with storage in place of packets.

### 1.1 The layering the design must respect

`tests/structure.rs` enforces `//! Classification: <layer> · <category> · <safety> ·
<feature>` on every source file, that `unsafe` appears only in the five-module TCB
(`arch/cortex_m.rs`, `arch/mmio.rs`, `kernel/cell.rs`, `kernel/stack.rs`,
`kernel/usermem.rs`), and that imports only go downward. The layers are `L0 port`,
`L1 kernel`, `L2 devices`, `L3 services`, `L4 personalities`, `support`.

The forbidden-import table today is:

```rust
("L2 devices", &["crate::net::", "crate::compat", "crate::edge"]),
("L3 services", &["crate::compat::posix", "crate::compat::freertos"]),
```

The design places the **block device class at L2** (`src/driver/block/`), the **VFS and the
three filesystems at L3** (`src/fs/`), and the **POSIX path wiring at L4**
(`src/compat/posix/`). That means `tests/structure.rs` must gain one rule: add
`"crate::fs"` to the banned list for `L0 port`, `L1 kernel` and `L2 devices`, so nothing
below L3 can reach up into the filesystem. L3 `fs` may use other L3 services (notably
`security`, for namespace capabilities) and everything below it, the same way `net` uses
`security::current_is_trusted` today. This is the one load-bearing test change the
subsystem requires.

Why Block at L2 and not L3 like `NetDevice`? Because a block device is a generic *device*
(like `Char` or `Sensor`, both L2 class wrappers) that is useful on its own and must be
reachable by the FS layer above it; the net device contract sits at L3 only because it is
inseparable from the net core. Keeping Block at L2 matches the `DeviceClass::Block` tag's
home in `driver/mod.rs` and lets a filesystem (L3) call down into it.

---

## 2. VFS core design

### 2.1 What the classic designs teach, and what to drop

The **vnode layer** (Kleiman, Sun, 1986 — [summary][vnode-kleiman]) split the kernel's file
code into a filesystem-independent half and a per-filesystem half at the inode boundary.
Two objects carry op-tables: a `vfs` (one per mounted filesystem) and a `vnode` (one per
active file), each pointing at a vtable for its concrete type. **Linux's VFS**
([docs][linux-vfs]) refines this into four objects: the **superblock** (a mounted
filesystem), the **inode** (a file's metadata, keyed by inode number), the **dentry** (a
cached name→inode link, the thing that makes path walks fast), and the **file** (an open
file description with a position and mode). Each has an `*_operations` vtable.

What to keep: the independent/dependent split, the superblock/inode/file triad, and
op-tables as Rust traits. What to drop on an MCU:

- **Dynamically allocated vnodes/inodes with embedded vtable pointers.** No heap. The
  "vnode" becomes a value type, and the vtable lives on the *mount*, not on each file.
- **The dentry cache.** It is a heap-resident hash table whose whole purpose is to avoid
  re-walking paths on a system with millions of files. On an MCU with a handful of mounts
  and short paths, we walk the path every time; it costs microseconds and saves kilobytes.
  (A tiny fixed last-lookup cache can be added later if profiling demands it.)
- **The page cache / address-space objects.** Reads and writes go to the filesystem, which
  owns whatever small block cache it needs. No `mmap`, no readahead machinery.
- **Reference-counted shared inodes across processes.** Capabilities and generations give
  us revocation without a global refcounted inode table.

### 2.2 The `FileSystem` trait (the superblock)

A mounted filesystem is a `&'static dyn FileSystem`. It is keyed entirely by integers it
chooses, so the VFS stores no per-file memory:

```rust
//! Classification: L3 services · fs: vfs contract · safe · fs

/// A filesystem-defined node identity, stable for the life of the mount.
/// RamFs: an inode-table index. FAT: the directory-entry location (or first cluster).
/// littlefs: the metadata-pair id / inline-file locator.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct FsVnode(pub u32);

/// A filesystem-defined open-file identity (index into the FS's own open-file pool).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OpenId(pub u16);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NodeKind { File, Dir }

bitflags_like! { pub struct OpenMode: u8 {
    const READ   = 1 << 0;
    const WRITE  = 1 << 1;
    const CREATE = 1 << 2;   // O_CREAT
    const TRUNC  = 1 << 3;   // O_TRUNC
    const APPEND = 1 << 4;   // O_APPEND
    const EXCL   = 1 << 5;   // O_EXCL
}}

#[derive(Copy, Clone, Default, Debug)]
pub struct Stat {
    pub kind: NodeKind,
    pub size: u64,
    pub blocks: u32,
    pub mtime: u64,          // kernel ticks or RTC seconds; 0 if unknown
    pub vnode: FsVnode,
}

/// One directory entry, filled in place (no allocation).
pub struct DirEntry {
    pub name: [u8; crate::config::FS_NAME_MAX],
    pub name_len: u8,
    pub kind: NodeKind,
    pub vnode: FsVnode,
}

/// A mounted filesystem instance. One `&'static dyn FileSystem` per mount.
pub trait FileSystem: Sync {
    fn root(&self) -> FsVnode;

    /// Resolve one path component inside a directory.
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

    /// Iterate a directory. `cookie` is an opaque resume position (0 = start).
    /// Returns the next cookie, or `None` at end of directory.
    fn readdir(&self, dir: FsVnode, cookie: u32, out: &mut DirEntry) -> Result<Option<u32>, Error>;

    /// Flush all dirty state to stable storage (fsync / unmount).
    fn sync(&self) -> Result<(), Error>;

    /// Static facts for `statvfs` and policy (read-only, power-safe, block size).
    fn info(&self) -> FsInfo;
}

#[derive(Copy, Clone, Debug)]
pub struct FsInfo {
    pub name: &'static str,        // "ramfs" | "littlefs" | "fat"
    pub read_only: bool,
    pub power_safe: bool,          // littlefs/ramfs: true; fat: false
    pub block_size: u32,
    pub case_sensitive: bool,      // ramfs/littlefs: true; fat: false
}
```

Design notes, each a deliberate no-heap choice:

- **`FsVnode` is a value, not a pointer.** The filesystem decides what `u32` means. This is
  exactly how the net core uses `IfIndex(u8)` and the driver registry uses `Device { index,
  generation }`: an integer the owner interprets. No allocation, trivially `Copy`.
- **Per-file state lives in the FS, not the VFS.** `open` returns an `OpenId` into the
  filesystem's *own* fixed open-file pool (littlefs needs a per-file cache buffer; FAT
  needs a cached current-cluster cursor; RamFs needs almost nothing). The VFS never
  allocates per-file memory. `read/write` take an explicit `off`, so the VFS owns the
  position (in the fd/handle), not the FS — this keeps the FS re-entrant and lets two
  handles share one open file cleanly.
- **`readdir` fills a caller `DirEntry` in place** with a bounded name buffer and returns a
  resume cookie, the POSIX `readdir`/`getdents` shape without allocation.
- **No trait method ever allocates or blocks on a lock it holds across hardware.** Flash
  erases take hundreds of milliseconds (§6); the implementation rule is that a filesystem
  must not hold any `IrqCell`/registry lock across a `BlockDevice::erase`, exactly as the
  net core never holds `NET` across a device call.

### 2.3 Mount table, path resolution and the open-file table

The VFS core (`src/fs/mod.rs`, the "superblock registry") is a direct analogue of
`net::mod.rs`'s `Global`:

```rust
//! Classification: L3 services · fs: vfs core and mount table · safe · fs

pub struct MountId(pub u8);

struct Mount {
    path: &'static str,              // mount point, e.g. "/", "/tmp", "/sd"
    fs: &'static dyn FileSystem,
    generation: u16,                 // bumped on unmount → revokes stale handles
    lock: RawMutex,                  // serializes ops on this mount (erases can block)
}

struct Vfs {
    mounts: [Option<Mount>; MAX_MOUNTS],
    open: [Option<OpenFile>; MAX_OPEN_FILES],   // global open-file table
}

#[derive(Copy, Clone)]
struct OpenFile {
    mount: MountId,
    id: OpenId,
    pos: u64,                        // file position (lseek target)
    mode: OpenMode,
    generation: u16,                 // matches Mount.generation at open time
}

static VFS: IrqCell<Vfs> = IrqCell::new(Vfs {
    mounts: [const { None }; MAX_MOUNTS],
    open:   [const { None }; MAX_OPEN_FILES],
});
```

**Path resolution** is iterative, bounded, and recursion-free (bounded stack is a hard MCU
requirement):

1. Pick the mount whose `path` is the longest prefix of the absolute path (longest-prefix
   match over `MAX_MOUNTS` entries — at most a handful).
2. Start at `fs.root()`. Walk the remaining components one at a time, copying each into a
   fixed `[u8; FS_NAME_MAX]` buffer, calling `fs.lookup(dir, name)`. Reject a path longer
   than `FS_PATH_MAX` or a component longer than `FS_NAME_MAX` with `NameTooLong`.
3. Cross-mount is handled at step 1 (the longest-prefix match already selects the
   innermost mount); nested mounts beyond the mount point are out of scope for v1 and a
   documented limitation.
4. `.` and `..` are resolved lexically against the mount root (so `..` cannot escape a
   per-domain namespace root — important for §9). No symlink following in v1 (documented
   limitation; a bounded `FS_MAX_SYMLINK_DEPTH` follow can be added behind the same loop
   later).

The whole resolver is one `fn resolve(path) -> Result<(MountId, FsVnode), Error>` with a
`for` loop over components; nothing is heap-allocated and the stack depth is constant.

The **open-file table** (`VFS.open`) is the POSIX-independent core that the fd layer (§8)
and the isolated-domain syscall path both sit on. Opening does: resolve → rights check
(§9) → `fs.open()` → allocate an `OpenFile` slot → return a handle (for trusted callers, an
index the fd layer stores; for isolated callers, a generation-stamped `security::Handle`).

### 2.4 Static bounds and config knobs

Following `config.rs`'s `parse_or(option_env!(...))` + `mcu_or_host` idiom:

```rust
// ----- filesystems (feature `fs`) -----
/// Registered block devices.
pub const MAX_BLOCKDEVS: usize = parse_or(option_env!("BISMUTH_MAX_BLOCKDEVS"), 4);
/// Simultaneously mounted filesystems.
pub const MAX_MOUNTS: usize = parse_or(option_env!("BISMUTH_MAX_MOUNTS"), 4);
/// Globally open files/directories (VFS open-file table).
pub const MAX_OPEN_FILES: usize = parse_or(option_env!("BISMUTH_MAX_OPEN_FILES"), mcu_or_host(8, 32));
/// Longest absolute path the resolver accepts.
pub const FS_PATH_MAX: usize = parse_or(option_env!("BISMUTH_FS_PATH_MAX"), 128);
/// Longest single path component / filename (long names).
pub const FS_NAME_MAX: usize = parse_or(option_env!("BISMUTH_FS_NAME_MAX"), 64);
```

Per-filesystem knobs (RamFs inode/byte budgets, littlefs cache/lookahead/open-file sizes,
FAT sector-cache depth, the block-cache size) live with their modules in §§3–7.

### 2.5 Classification

| file | classification |
|---|---|
| `src/fs/mod.rs` | `L3 services · fs: vfs core and mount table · safe · fs` |
| `src/fs/vnode.rs` | `L3 services · fs: vfs contract · safe · fs` |

---

## 3. Block device class

### 3.1 The trait shape (iflib-lite for storage)

The Block class lives in `src/driver/block/` at **L2 devices**, structured like
`driver/sensor/` (a class module + a sim driver + a typed wrapper). The core contract is a
`BlockDevice` trait whose shape is the intersection of littlefs's `lfs_config` block-device
ops ([DESIGN][lfs-design]) and Rust's `embedded-storage` NOR-flash traits
([nor_flash][es-norflash]); it covers both erase-before-write flash and managed disks:

```rust
//! Classification: L2 devices · block device class · safe · always

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaKind {
    /// NOR/NAND flash: must be erased (to `erase_value`, usually 0xFF) before programming;
    /// a programmed region cannot be rewritten without an erase.
    Flash { erase_value: u8 },
    /// Managed disk (SD/eMMC/USB-MSC): sectors can be overwritten in place; `erase` is a
    /// no-op. The card's own FTL does wear leveling.
    Disk,
    /// Volatile RAM disk (the ramfs backing / tests): overwrite in place, `sync` no-op.
    Ram,
}

/// Static geometry. Mirrors lfs_config {read,prog,block}_size/block_count/block_cycles and
/// embedded-storage READ_SIZE / WRITE_SIZE / ERASE_SIZE.
#[derive(Copy, Clone, Debug)]
pub struct BlockGeometry {
    pub read_size: u32,     // min/alignment of a read  (lfs read_size; es READ_SIZE)
    pub prog_size: u32,     // min/alignment of a program (lfs prog_size; es WRITE_SIZE)
    pub block_size: u32,    // erase-block / sector size (lfs block_size; es ERASE_SIZE)
    pub block_count: u32,   // number of erase blocks
    pub block_cycles: u32,  // rated erase cycles (0 = unknown); feeds wear policy
    pub kind: MediaKind,
}

impl BlockGeometry {
    pub const fn capacity(&self) -> u64 { self.block_size as u64 * self.block_count as u64 }
}

/// A block/flash storage device. Logic is 100% safe Rust; a real controller's register and
/// DMA access lives in `arch::mmio` (the TCB), exactly as net MAC drivers do.
pub trait BlockDevice: Sync {
    fn geometry(&self) -> BlockGeometry;

    /// Read into `buf` from block `blk` starting at `off`. `off` and `buf.len()` are
    /// multiples of `read_size` and stay within one block.
    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error>;

    /// Program `data` into block `blk` at `off` (multiples of `prog_size`). For `Flash`,
    /// the target region must already be erased; writing a word twice is rejected.
    fn prog(&self, blk: u32, off: u32, data: &[u8]) -> Result<(), Error>;

    /// Erase one block (sets it to `erase_value`). `Disk`/`Ram`: Ok(()) no-op.
    fn erase(&self, blk: u32) -> Result<(), Error>;

    /// Flush any volatile write buffer to stable storage.
    fn sync(&self) -> Result<(), Error> { Ok(()) }
}
```

Why this exact shape:

- **`read/prog/erase/sync` + `{read,prog,block}_size/block_count/block_cycles` is
  precisely `lfs_config`'s block-device interface.** Porting littlefs on top of it is then
  a mechanical mapping, and the same trait drives FAT (set `read_size = prog_size =
  block_size = 512`, `MediaKind::Disk`, `erase` is a no-op) and the RAM disk.
- **It matches `embedded-storage`** ([nor_flash][es-norflash]): `READ_SIZE`/`WRITE_SIZE`/
  `ERASE_SIZE` ↔ `read_size`/`prog_size`/`block_size`; `read(off,buf)` / `write` / `erase(from,to)`.
  A thin adapter can wrap any existing `embedded-storage` driver (nRF `Flash`, RP2040
  `Flash`, Embassy `Partition`) into a Bismuth `BlockDevice`, which immediately gives the
  flash FS real hardware to run on. The power-loss semantics `embedded-storage` documents
  (after a torn erase the block is undefined; after a torn program the written words are
  undefined but the rest of the page is intact; a word must not be written twice) are
  exactly the invariants littlefs is built to tolerate, so the contract composes.
- **`off: u32` within a block, block index `u32`.** Capacity is `u64` via
  `block_size * block_count`, so >4 GB disks work for FAT32 while individual addressing
  stays 32-bit (right for the MCU and for littlefs's own 32-bit block addressing).

**No `unsafe` anywhere in block *logic*.** A sim device is pure safe Rust. A real QSPI/OSPI
or SDMMC controller reads/writes registers and programs DMA descriptors through
`arch::mmio` (the TCB) and is registered like any driver; the `BlockDevice` impl itself
contains no `unsafe`, just as `net::drivers` MAC drivers contain none. The one temptation
to flag (see §11) is casting on-disk structures with `transmute`/`bytemuck`; the house rule
(already followed by `net::csum`'s hand-rolled frame parsing) is explicit
`from_le_bytes`/`to_le_bytes`.

### 3.2 The block registry and the `/dev/<name>` control node

Mirroring `net::register`/`net::control_device`, block devices register into a small static
registry and simultaneously appear as a `DeviceClass::Block` control node:

```rust
pub fn register(name: &'static str, dev: &'static dyn BlockDevice) -> Result<BlockId, Error> {
    if !crate::security::current_is_trusted() { return Err(Error::PermissionDenied); }
    // ... insert into a MAX_BLOCKDEVS registry, register a BlockControl driver as /dev/<name> ...
}

// Fast path used by filesystems (no Op, no middleware chain — like net::transmit):
pub(crate) fn read_at(id: BlockId, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error>;
pub(crate) fn prog_at(id: BlockId, blk: u32, off: u32, data: &[u8]) -> Result<(), Error>;
pub(crate) fn erase_blk(id: BlockId, blk: u32) -> Result<(), Error>;
pub(crate) fn sync(id: BlockId) -> Result<(), Error>;
pub(crate) fn geometry(id: BlockId) -> Result<BlockGeometry, Error>;
```

The control node is a `Driver` (like net's `ControlDriver`) exposing a new ioctl page and
*optional* raw whole-device access:

```rust
// ioctl page 0x09xx (block), added to driver/ioctl.rs
pub const BLOCK_GET_BLOCK_SIZE:  u32 = 0x0901;  // CONTROL
pub const BLOCK_GET_BLOCK_COUNT: u32 = 0x0902;  // CONTROL
pub const BLOCK_GET_READ_SIZE:   u32 = 0x0903;  // CONTROL
pub const BLOCK_GET_PROG_SIZE:   u32 = 0x0904;  // CONTROL
pub const BLOCK_GET_KIND:        u32 = 0x0905;  // CONTROL
pub const BLOCK_SYNC:            u32 = 0x0906;  // CONFIG  (flush to stable storage)
pub const BLOCK_ERASE_ALL:       u32 = 0x0907;  // CONFIG  (format/chip-erase; dangerous)
```

`required_right` places the queries under `CONTROL` and the mutating `SYNC`/`ERASE_ALL`
under `CONFIG`, matching the existing rule in `driver/ioctl.rs` ("queries and normal
operation need `CONTROL`; anything that reconfigures the device needs `CONFIG`"). A
filesystem never goes through this node — it uses the `read_at`/`prog_at` fast path — but
the node gives `dd`-style host tooling, format utilities and audit a handle, and it slots
into the capability model for free (a domain with a `DeviceCap` of rights `READ` can read
the raw device; `CONFIG` is required to erase it).

Offset-addressed raw access (`dd if=/dev/mtd0 bs=4096 skip=...`) is provided by the POSIX
fd layer keeping a `pos` in its `Entry` and calling `block::read_at`; the `Op` enum is
**not** extended (it has no offset and `Op::Transfer`'s `addr` is only `u16`). This keeps
the generic device model untouched, the same way packets never became an `Op`.

### 3.3 Data-plane "middleware": `BlockDevice` wrappers

Because block I/O never flows through `Op`, the data-plane layers are **composition
wrappers** that implement `BlockDevice` around an inner `BlockDevice`, the direct analogue
of `SoftRing<F>` wrapping a `FrameDevice`. Each is a const-generic, statically-sized,
safe-Rust type:

```rust
/// Write-back block cache: N blocks of BS bytes. Absorbs repeated small writes before they
/// hit flash (fewer erase cycles) and serves hot reads. `sync()` writes back dirty blocks.
pub struct BlockCache<D, const N: usize, const BS: usize> { inner: D, /* N lines + dirty bits */ }

/// Caps a device to a sub-range of blocks (a partition / MTD region). Offsets are relative.
pub struct Partition<D> { inner: D, base: u32, count: u32 }

/// Refuses all prog/erase; exposes the device read-only (e.g. a signed firmware image).
pub struct ReadOnly<D> { inner: D }

/// Counts erases per block for telemetry and to validate wear-leveling in tests.
pub struct WearCounter<D, const BLOCKS: usize> { inner: D, erases: [AtomicU32; BLOCKS] }
```

These compose at build time: `static ROOT: Partition<QspiFlash> = ...;
static CACHED: BlockCache<Partition<QspiFlash>, 4, 4096> = BlockCache::new(ROOT);`. The
recommendation is **write-back caching only above `MediaKind::Disk`** (SD/eMMC, where a
torn write is already unsafe) and **either write-through or no cache above
`MediaKind::Flash`**, because littlefs already owns its own read/prog caches and a
write-back layer underneath it would break littlefs's power-loss guarantee (littlefs
assumes a program is either durable or ignored; a volatile cache in between violates that).
This is the one place the two planes interact dangerously, and the rule is: **a
power-safe filesystem must sit on a device whose `prog`/`erase` are synchronous to stable
storage** (cache write-through, or no cache). The `/dev`-node `Op` middleware (`Stats`,
`Trace`, `Exclusive`, `AccessPolicy`) still applies to admin traffic on the control plane.

### 3.4 Classification

| file | classification |
|---|---|
| `src/driver/block/mod.rs` | `L2 devices · block device class · safe · always` |
| `src/driver/block/cache.rs` | `L2 devices · block: write-back cache / wrappers · safe · always` |
| `src/driver/block/sim.rs` | `L2 devices · block driver: simulated flash/disk · safe · always` |

---

## 4. Caching & hot-file residency

The user asked for two related things: ordinary **disk caching**, and **dynamically loading
frequently accessed files into memory "if allowed."** Both are worth doing on an edge
device — they cut flash wear and read latency and keep a hot config or model file one memcpy
away — but both must obey Bismuth's two non-negotiables: **no heap** (so a cache is a
*fixed RAM budget with dynamic occupancy*, never a structure that grows to fill memory) and
**capabilities** (so "if allowed" is a real, enforced answer, not a hope). The design is two
independent cache layers plus a governance layer.

### 4.1 Two-layer cache model

**Layer 1 — the block cache (raw/ciphertext blocks, below the FS).** This is the
`BlockCache<D, N, BS>` wrapper from §3.3: a statically-allocated pool of `N` lines of `BS`
bytes with LRU/CLOCK (or LFU) eviction over the `N` lines, implementing `BlockDevice`
transparently under any filesystem. It absorbs the repeated small reads every filesystem
makes — directory scans, littlefs metadata-pair re-reads, FAT table sectors — and short,
bursty writes. The hard rule from §3.3 and §6 stands: **write-through only under a
power-safe filesystem** (littlefs), because a write-back cache between littlefs and the
medium turns a "committed" CRC into a promise that is still only in volatile RAM and
silently breaks the power-loss guarantee; **write-back is allowed only over managed media
(`MediaKind::Disk`) or read-mostly mounts**, where a torn write is already the medium's
problem. Layer 1 is always safe to enable and its RAM (`N·BS`) is fixed at build time.

**Layer 2 — hot-file residency (whole decoded files, above the FS).** This is new. It sits
in the VFS, above the `FileSystem` trait, and keeps *whole small files* resident when they
are accessed often enough to be worth it. It is a fixed pool of `K` slabs (the
`PacketPool` idiom): each slab holds at most one file of up to `FS_RESIDENT_MAX_FILE` bytes.
A file is promoted only if it is hot *and* it fits; the coldest resident file is evicted to
make room. A file larger than the per-file cap is **never** promoted — it stays served by
Layer 1 or uncached — so "load a frequently accessed file into memory" can never blow the
budget. Total Layer-2 RAM is exactly `FS_RESIDENT_SLOTS · FS_RESIDENT_MAX_FILE`, fixed at
build time; setting the slot count to zero (the MCU default) compiles Layer 2 out entirely.

```rust
//! Classification: L3 services · fs: hot-file residency cache · safe · fs

/// Zero slots (the MCU default) disables Layer 2 — block cache only, no cost.
pub const FS_RESIDENT_SLOTS:    usize = parse_or(option_env!("BISMUTH_FS_RESIDENT_SLOTS"), mcu_or_host(0, 8));
pub const FS_RESIDENT_MAX_FILE: usize = parse_or(option_env!("BISMUTH_FS_RESIDENT_MAX_FILE"), mcu_or_host(0, 8192));
/// Accesses before a file becomes a promotion candidate (LFU threshold).
pub const FS_RESIDENT_PROMOTE:  u32   = parse_or(option_env!("BISMUTH_FS_RESIDENT_PROMOTE"), 4) as u32;

struct Resident {
    key:   (MountId, FsVnode),   // which file
    gen:   u16,                  // mount generation at promotion; stale ⇒ invalid
    owner: DomainId,             // promotion charged against this domain's byte budget
    len:   u32,                  // valid bytes in this slab (≤ FS_RESIDENT_MAX_FILE)
    score: u32, last: u64,       // LFU count (aged) + LRU tick, for eviction ranking
    dirty: bool,                 // stays false under the recommended write-through policy
}

pub struct Residency {
    slabs: [TaskCell<[u8; FS_RESIDENT_MAX_FILE]>; FS_RESIDENT_SLOTS],  // like PacketPool blocks
    meta:  IrqCell<[Option<Resident>; FS_RESIDENT_SLOTS]>,
}
```

Promotion / eviction honours the no-blocking-under-a-lock rule (§2.2): claim a slab under
the `meta` lock, **release it, copy via `fs.read` outside the lock** (the read can block on
flash), then publish:

```rust
fn on_read(k: (MountId, FsVnode), dom: DomainId, size: u32) -> Source {
    // 1. Resident & generation-valid? bump score, serve from the slab. Done.
    // 2. Not resident: bump a tiny per-file frequency estimate. Promote iff
    //       score ≥ FS_RESIDENT_PROMOTE  &&  size ≤ FS_RESIDENT_MAX_FILE
    //       &&  cacheable(k, dom) == Resident           (the "if allowed" gate, §4.2)
    //    Reserve a slab: use a free one, else evict the coldest resident file whose score
    //    is below this candidate's; if none is colder, leave it block-cached (NEVER grow).
    // 3. Charge `size` to `dom`'s cache budget; refuse promotion if it would exceed it.
    // 4. Release the lock → fs.read the whole file into the slab → publish the slot.
    //    On any failure, serve this read straight from the FS / Layer 1.
}
```

The resident copy is kept coherent by making writes **write-through**: a write to a resident
file goes to the `FileSystem` first and then refreshes (or invalidates) the slab, so the
authoritative copy is always on stable storage and the residency cache never holds a
dirty-only state to lose on power failure. (A resident file is keyed by `(MountId, FsVnode)`
and read-shared across domains that may both cache it; whether a shared file is charged to
its promoter or split across readers is a policy knob — see §11.)

### 4.2 "If allowed": capability governance of caching

Three gates decide whether a byte may live in RAM, all in the existing static/manifest
style:

- **Per-domain cache budget (bytes).** Declared in the manifest in the same fixed-budget
  style as the container CPU budget (`CpuBudget` in `security/container.rs`) and the
  existing `DomainSpec` task/priority quotas. The residency allocator charges every
  promotion against the promoting domain's budget and refuses to exceed it. A domain with
  **no cache budget — the untrusted default — gets Layer-1 block caching only** (shared,
  raw/ciphertext, below the FS) and **no hot-file residency at all**. This bounds not just
  total RAM but each domain's share, so one domain cannot evict another's hot files by
  flooding, exactly as the CPU budget bounds a domain's share of the core.
- **Per-mount / per-file `cacheable` policy.** A mount carries a default in its `FsInfo`,
  and a dir grant may narrow it, consistent with the `FileCap`/`DirCap` + `dirs = [...]`
  model (§9):
  ```toml
  dirs = [
    { mount="flash", path="/models", at="/", rights=["READ"],  cache="resident" },
    { mount="flash", path="/log",    at="/", rights=["WRITE"], cache="none"     },
  ]
  ```
  `cacheable(k, dom)` is the AND of the mount default, the domain's dir-cap for that
  subtree, and a non-zero budget. Caching is thus itself a right, revoked with the handle.
- **Encrypted storage: default-deny plaintext residency.** This is the load-bearing
  interaction with the sealed-secret design (the `CryptBlock<D>` wrapper in the
  trusted-platform companion doc). The two caches live on **opposite sides of the
  decryption boundary**:

  ```text
  app ── VFS ──[ Layer 2: hot-file residency — PLAINTEXT, above the FS ]── opt-in only (encrypted mounts)
                   │
                FileSystem (littlefs / fat)              plaintext logical blocks
                   │
                CryptBlock<D>                            ← decrypt on read / encrypt on write
                   │                                       ciphertext blocks
                [ Layer 1: BlockCache — CIPHERTEXT, below CryptBlock ]  ← safe to persist in RAM
                   │
                raw BlockDevice (flash / SD)
  ```

  Layer 1 sits **below** `CryptBlock`, so it caches **ciphertext** — exactly the bytes
  already on the medium — and is safe to hold in RAM freely; the only cost is paying the
  (cheap, ChaCha20) AEAD on each hit rather than on each raw read. Layer 2 sits **above** the
  FS, so it caches **plaintext** whole files, which for a `CryptBlock`-backed mount *widens
  the plaintext exposure window* the TPM-unseal design works to keep narrow. Hot-file
  residency of an encrypted mount is therefore **default-deny** and requires an explicit
  `cache="resident"` grant that the manifest surfaces as an acknowledged risk. Resident
  plaintext slabs are **zeroized** (`zeroize`, already a dep) on eviction, on unmount, on
  domain kill and on power-state suspend, so plaintext never outlives its need; the DEK
  lifecycle itself is the companion doc's concern.

### 4.3 Classification

| file | classification |
|---|---|
| `src/fs/resident.rs` | `L3 services · fs: hot-file residency cache · safe · fs` |

(Layer 1 is already covered by `src/driver/block/cache.rs`, §3.4.)

---

## 5. RAM FS (first target)

RamFs is the bring-up vehicle: it proves the VFS trait, the mount table, path resolution,
the open-file table and the whole POSIX wiring **before any block driver exists**, and it
is the obvious implementation of `/tmp`. It needs no hardware, so it is the first thing a
host test can exercise end to end.

### 5.1 Static layout

```rust
//! Classification: L3 services · fs: ram filesystem · safe · fs

/// A fixed inode table plus a shared fixed-block arena. No heap, no backing device.
pub struct RamFs<const INODES: usize, const BLOCKS: usize, const BS: usize> {
    inodes: IrqCell<[Inode; INODES]>,
    arena:  [TaskCell<[u8; BS]>; BLOCKS],     // data blocks, like PacketPool's blocks
    used:   IrqCell<[bool; BLOCKS]>,
}

struct Inode {
    kind: NodeKind,
    name: [u8; FS_NAME_MAX],
    name_len: u8,
    parent: u16,                 // inode index; root is its own parent
    // File: a singly-linked chain of arena block indices + total size.
    // Dir : the head of a sibling list (first child inode index).
    first_block: u16,            // or u16::MAX
    first_child: u16,            // dirs
    next_sibling: u16,           // directory listing is a sibling walk
    size: u32,
}
```

- **Directories are sibling-linked lists of inode indices** (a dir holds `first_child`;
  children hold `next_sibling`). `readdir`'s cookie is the next sibling index. No
  allocation.
- **File data is a chain of fixed `BS`-byte arena blocks**, allocated from the shared
  `used` bitmap exactly like `PacketPool` allocates packet blocks. Files grow up to the
  arena's capacity; growth failure returns `NoSpace`. This gives real `write`/`truncate`
  semantics without a heap, and bounds total RamFs memory to
  `INODES·sizeof(Inode) + BLOCKS·BS`.
- `FsVnode(inode_index)`; `OpenId` is trivial (RamFs keeps no per-open state — position
  lives in the VFS open-file table).

### 5.2 Config and classification

```rust
pub const RAMFS_INODES: usize = parse_or(option_env!("BISMUTH_RAMFS_INODES"), mcu_or_host(16, 64));
pub const RAMFS_BLOCKS: usize = parse_or(option_env!("BISMUTH_RAMFS_BLOCKS"), mcu_or_host(16, 128));
pub const RAMFS_BLOCK:  usize = parse_or(option_env!("BISMUTH_RAMFS_BLOCK"), 256);
```

`src/fs/ramfs.rs` — `L3 services · fs: ram filesystem · safe · fs`.

RamFs is `power_safe: false` only in the sense that it is volatile; it has no torn-write
hazard, so it is the clean oracle for VFS correctness tests.

---

## 6. Flash FS: a littlefs subset

littlefs is the right model for Bismuth's power-fail-safe flash store: it is designed for
exactly our constraints — bounded RAM independent of filesystem size, power-loss resilience
by construction, and dynamic wear leveling — and its block-device interface is already the
shape of our `BlockDevice` trait. We re-implement its **on-disk format** in safe Rust (no
FFI; the C library would pull `unsafe` into the TCB, and the format is the valuable part).

### 6.1 The on-disk model ([DESIGN][lfs-design], [SPEC][lfs-spec])

- **Metadata pairs.** Every directory is a two-block *log*. One block holds the last
  committed state while the other is written; a per-block **revision count** (compared with
  sequence arithmetic to dodge overflow) picks the newer block. Entries are appended as
  commits, each ending in a single **32-bit CRC**, so a commit becomes valid only when its
  checksum lands — the atomicity primitive. When a block fills, **compaction** copies the
  live entries into the sibling block, bumps the revision and erases the old one; the old
  block stays intact until the new commit's CRC is written. When a compacted pair exceeds
  ~50% capacity it **splits**, keeping compaction amortized O(1) at the cost of
  half-full pairs.
- **CTZ skip-lists for file data.** File blocks are copy-on-write and linked *backwards*:
  block *n* stores `ctz(n)+1` pointers to earlier blocks (ctz = count-trailing-zeros, hence
  the name). Appends are O(1), traversal uses constant RAM, and a file is located by just a
  **head pointer + size** (block index and offset derive from the size in O(1) by a
  closed-form formula). Average overhead is ~2 pointers per block.
- **Inline files.** Files smaller than ~¼ of a block live directly inside the directory's
  metadata pair, so tiny config/state files cost no data block at all.
- **Directories threaded into one list.** The directory tree is also threaded as a single
  linked list of metadata pairs, so the whole filesystem can be traversed in constant RAM
  (needed by the allocator and `fsck`).
- **Allocator with no on-disk free list.** Deallocation is a no-op; the filesystem tree
  *is* the record of which blocks are used. The allocator keeps a fixed-size **lookahead
  bitmap** window and rescans the tree from an increasing offset when it empties. The scan
  start offset is randomized per mount from the XOR of metadata CRCs already on disk, which
  spreads allocation — **statistical dynamic wear leveling**. Limiting erases per block per
  allocation (`block_cycles`) forces metadata pairs to relocate periodically so no block
  wears out early.
- **Bad-block handling.** No ECC of its own; every program is read back and compared to the
  RAM copy, and a failing block is relocated through the copy-on-write path.
- **Power-loss recovery.** Any torn write is either fully committed (its CRC is present) or
  ignored, and the previous data survives until then. Interrupted directory add/remove can
  leave an **orphan**, detected on the first allocation after mount; an interrupted move is
  resolved via a small bounded **global state** (deltas XORed across metadata pairs,
  reconstructed at mount).

### 6.2 Bounded RAM — the heap-free mapping of `lfs_config`

littlefs's RAM is three fixed buffers plus per-open-file buffers; all become const-generic
static storage, mirroring how `net` sizes its pools:

```rust
//! Classification: L3 services · fs: littlefs (flash) · safe · fs

pub struct LittleFs<const CACHE: usize, const LOOKAHEAD: usize, const MAX_OPEN: usize> {
    dev: BlockId,
    geom: BlockGeometry,
    read_cache:  IrqCell<[u8; CACHE]>,          // lfs_config.read_buffer
    prog_cache:  IrqCell<[u8; CACHE]>,          // lfs_config.prog_buffer
    lookahead:   IrqCell<[u8; LOOKAHEAD]>,      // lfs_config.lookahead_buffer (bitmap)
    files:       [TaskCell<FileState<CACHE>>; MAX_OPEN],  // per-file cache buffers
    files_used:  IrqCell<[bool; MAX_OPEN]>,
    state:       IrqCell<LfsState>,             // mount state, global-move XOR, alloc cursor
}

struct FileState<const CACHE: usize> {
    head: u32, size: u32, pos: u32,
    cache: [u8; CACHE],                          // lfs_file_config.buffer
}
```

Config knobs:

```rust
pub const LFS_CACHE:     usize = parse_or(option_env!("BISMUTH_LFS_CACHE"), 256);   // ≥ prog_size, divides block_size
pub const LFS_LOOKAHEAD: usize = parse_or(option_env!("BISMUTH_LFS_LOOKAHEAD"), 16); // bytes → 128 blocks
pub const LFS_MAX_OPEN:  usize = parse_or(option_env!("BISMUTH_LFS_MAX_OPEN"), mcu_or_host(4, 8));
pub const LFS_BLOCK_CYCLES: u32 = parse_or(option_env!("BISMUTH_LFS_BLOCK_CYCLES"), 500) as u32;
```

Total RAM is `2·CACHE + LOOKAHEAD + MAX_OPEN·(CACHE + overhead)` — independent of flash
size, as littlefs promises.

### 6.3 What we implement vs defer

- **Implement:** mount/format, `lookup`, `stat`, `open`/`read`/`write`/`close`,
  `create`/`unlink`, `mkdir`, `readdir`, `truncate`, `sync`, inline files, CTZ file data,
  metadata compaction + split, the lookahead allocator, dynamic wear leveling, read-back
  bad-block relocation, and commit-or-ignore power-loss recovery including orphan detection.
- **Implement carefully (highest risk):** `rename` across directories, which uses
  littlefs's XOR global-move state — the subtlest part of the format. Land it behind the
  differential oracle (§6.4) or ship same-directory rename first and document cross-dir
  rename as a follow-up.
- **Defer / limit:** custom on-disk attributes (`lfs_setattr`), filesystem resizing /
  shrinking, on-disk ECC (rely on the device), and >2 GB volumes. These are documented
  limitations, not silent gaps.

### 6.4 On-disk compatibility as a test oracle

Strong recommendation: **target exact littlefs v2 on-disk compatibility.** The payoff is a
free differential oracle — a CI step mounts our image with the reference `littlefs-fuse` /
`mklittlefs`, and mounts a reference-created image with ours, so every format bug surfaces
as a mismatch rather than lurking until a field power-loss. The cost is matching the tag
and commit encoding byte-for-byte (the part of SPEC.md the web survey could not fully
extract — it must be read directly). The documented alternative, if exact compat proves too
costly, is a Bismuth-native power-safe format that only round-trips with itself; it loses
the oracle and the "pull the chip and read it with standard tools" benefit, so it is the
fallback, not the plan.

### 6.5 Safe-Rust discipline

All littlefs logic is safe Rust: CRC-32 (table-driven, safe), CTZ via `u32::trailing_zeros`,
and on-disk (de)serialization via explicit `from_le_bytes`/`to_le_bytes` — never
`transmute`, `bytemuck`-with-unsafe, or pointer casts over the flash buffer. This matches
`net::csum`'s existing hand-rolled, `unsafe`-free frame parsing. The only hardware touched
is the flash controller, behind `arch::mmio`.

`src/fs/littlefs.rs` (or `src/fs/lfs/`) — `L3 services · fs: littlefs (flash) · safe · fs`.

---

## 7. FAT driver

FAT exists for **interoperability on managed media**: SD cards, eMMC and USB mass storage,
where you want to pull the card and read it on a PC, or accept a card a PC wrote. It is
**not** power-fail-safe and **not** wear-levelled ([ESP-IDF comparison][esp-fs] rates FAT
"low resilience against sudden power-off"), so it is documented as managed-media-only; raw
NOR/NAND gets littlefs instead.

### 7.1 On-disk layout ([FAT32 spec 1.03][fatspec], [design][fat-wiki])

A FAT volume is: a **reserved region** beginning with the boot sector and its **BIOS
Parameter Block** (BPB: bytes/sector, sectors/cluster, reserved sector count, number of
FATs, root-entry count for FAT12/16, total sectors, FAT size, and for FAT32 the extended
BPB with the root-directory first cluster); one or two copies of the **File Allocation
Table** (entries 12/16/32 bits wide — the width names the variant); the **root directory**
(a fixed-size area for FAT12/16, a normal cluster chain for FAT32); and the **data region**
of clusters. The FAT is a singly-linked next-cluster map: each slot holds the next cluster
of a file, terminated by an end-of-chain marker; `0x000…` means free, and a reserved value
marks bad clusters. Directory entries are 32 bytes: 8.3 name, attribute byte, first-cluster
(split hi/lo on FAT32) and size.

**VFAT long filenames** are a sequence of long-name entries (attribute `0x0F`,
ordinal-tagged) placed immediately *before* the 8.3 short entry, each carrying 13 UTF-16
code units and a checksum tying them to the short entry.

### 7.2 Read + write path

- **Read:** parse BPB → determine variant from cluster count → walk the FAT chain from a
  file's first cluster, mapping cluster→sector→`BlockDevice::read`. Directory lookup scans
  32-byte entries, assembling LFN runs and falling back to the 8.3 name; comparison is
  case-insensitive (ASCII-fold; full Unicode case folding is out of scope and documented).
- **Write / create:** allocate clusters by scanning the FAT for a free slot, link them,
  **update every FAT copy** (both FATs if `num_fats == 2`), write/extend the directory
  entry, and on create synthesize the LFN run + a unique 8.3 alias. `truncate` frees the
  tail of a chain. `unlink` marks the directory entry `0xE5` and frees the chain.
- **Static bounds:** a small FAT/sector cache (a `FAT_SECTOR_CACHE`-deep window of 512-byte
  sectors, reusing the §3.3 `BlockCache` above the disk), a fixed open-file table
  (`FAT_MAX_OPEN`, each holding the current-cluster cursor to avoid re-walking the chain on
  sequential I/O), and a bounded `readdir` cursor. No heap.

```rust
pub const FAT_SECTOR_CACHE: usize = parse_or(option_env!("BISMUTH_FAT_SECTOR_CACHE"), 4);
pub const FAT_MAX_OPEN:     usize = parse_or(option_env!("BISMUTH_FAT_MAX_OPEN"), mcu_or_host(4, 8));
```

### 7.3 Interop and testing

FAT's whole value is the host round-trip, so its tests are differential against standard
tools: create an image with `mkfs.fat` + `mtools`/loopback mount on the host, mount it with
the Bismuth FAT driver over a `SimDisk` backed by that image, read the files; then write
files with Bismuth and verify them with `mtools` on the host. FAT12, FAT16 and FAT32 each
get a case (chosen by sizing the `SimDisk`). LFN round-trips are checked both directions.

### 7.4 Patent / licensing note

Plain 8.3 FAT has **never** been patented and is free to implement. The VFAT long-name
patents (US 5,579,517 "common name space for long and short filenames", and the related
5,745,902 / 5,758,352 / 6,286,013) have **expired** — the earliest around 2013, the latest
(6,286,013, issued 2001) by 2019 on the standard 20-year term — and the key patent was
**invalidated by the German Federal Patent Court in 2013** ([ruling][fat-patent-de];
patent list per [NuttX notice][nuttx-notice]). As of 2026 a read/write FAT with VFAT LFN is
unencumbered to ship. **exFAT is different**: Microsoft still actively licenses it, so
Bismuth does **not** implement exFAT. (This is a factual summary, not legal advice; a
shipping product should confirm for its jurisdictions.)

`src/fs/fat.rs` (or `src/fs/fat/`) — `L3 services · fs: FAT (interop) · safe · fs`.

---

## 8. POSIX integration

### 8.1 fd table changes (`compat/posix/unistd.rs`)

Add a `File` arm to the fd `Kind` and carry a position for `lseek`:

```rust
enum Kind {
    Free, Console, Device(Device), Cap(DeviceCap),
    #[cfg(feature = "net-ip")] Socket(Sock),
    #[cfg(feature = "fs")] File(FileHandle),     // index into the VFS open-file table
}
// Entry already has `flags`; add `pos: u64` for File entries (lseek target).
```

`open` stops hard-coding `/dev/`: a `/dev/…` path resolves as today (device or cap); any
other absolute path goes to the VFS resolver (§2.3), honouring `O_CREAT | O_TRUNC |
O_APPEND | O_EXCL` and the read/write mode bits. `read`/`write` gain a `Kind::File` arm that
calls `fs::read`/`fs::write` at the fd's `pos` and advances it; `close` calls `fs::close`.

### 8.2 New calls

| call | maps to |
|---|---|
| `lseek(fd, off, whence)` | adjust `Entry.pos` against `Stat.size` for `SEEK_END` |
| `stat(path)` / `fstat(fd)` | resolve + `fs::stat` |
| `mkdir(path)` / `rmdir(path)` | `fs::create(.., Dir)` / `fs::unlink` (reject non-empty) |
| `unlink(path)` | `fs::unlink` |
| `rename(old, new)` | `fs::rename` (same-mount only; cross-mount → `EXDEV`) |
| `opendir`/`readdir`/`closedir` | `fs::readdir` with the cookie in a small `DIR` handle |
| `fsync(fd)` | `fs::sync` on the fd's mount |
| `ftruncate(fd, len)` / `truncate(path, len)` | `fs::truncate` |
| `statvfs(path)` | `FsInfo` + free-block count |

A small `mount(path, fs)` / `unmount(path)` admin API (trusted / `CONFIG` on the block
device) lives in `fs::mod` and is called at boot, not a POSIX syscall.

### 8.3 New errors and errno

`error.rs`'s `Error` gains the filesystem variants and `errno()` mappings
(`errno.rs` already defines the numbers, several of which are currently unused):

| `Error` | errno | notes |
|---|---|---|
| `NotADirectory` | `ENOTDIR` (20 — add) | component of a path is a file |
| `IsADirectory` | `EISDIR` (21 — add) | `read`/`write` on a directory |
| `NotEmpty` | `ENOTEMPTY` (39 — add) | `rmdir` on a non-empty dir |
| `ReadOnly` | `EROFS` (30 — add) | write to a read-only mount / `ReadOnly` device |
| `NameTooLong` | `ENAMETOOLONG` (36 — exists) | component > `FS_NAME_MAX` |
| `NoSpace` | `ENOSPC` (28 — exists) | arena/flash/disk full |
| `CrossDevice` | `EXDEV` (18 — add) | cross-mount `rename` |

`NoResources`/`NoMemory`/`NotFound`/`Exists`/`Invalid`/`Io`/`PermissionDenied`/`BadHandle`
already exist and cover the rest (`EMFILE` on a full open-file table, `ENOENT`, `EEXIST`,
`EACCES`, `EBADF`, `EIO`). The six additions are the only new ones.

### 8.4 Isolated-domain syscalls

Hardware-isolated domains reach files only through `SVC`, so `security/syscall.rs` gains FS
calls alongside the existing 12 (the allow-mask is a `u32`, so there is room up to 32):

```
nr::FS_OPEN, FS_READ, FS_WRITE, FS_CLOSE, FS_LSEEK, FS_STAT, FS_READDIR,
nr::FS_MKDIR, FS_UNLINK          // ~9 new; total stays < 32
```

Each resolves a path (or a file handle) against the **calling domain's** namespace (§9),
validates the user buffer via `kernel::usermem` exactly as `DEV_READ`/`DEV_WRITE` do, and
returns `isize` (`-errno` on failure). The user-side `bismuth-user` crate wraps these into
the POSIX library so application code is identical across trusted and sandboxed domains.

---

## 9. Security: rights-checked file handles and per-domain mount namespaces

This is where Bismuth can be cleaner than Zircon and than every RTOS FS surveyed. The model
is the `DeviceCap` pattern, extended to storage.

### 9.1 File/dir handles are capabilities

Add two `Object` variants and resolve them before any filesystem logic, mirroring
`DeviceCap::resolve`:

```rust
pub enum Object {
    Device(Device),
    Key { slot: u8, generation: u16 },
    /// A directory subtree: the root of what a domain may name. (A per-domain chroot.)
    Dir  { mount: MountId, vnode: FsVnode, generation: u16 },
    /// An open file description with rights.
    File { mount: MountId, open: OpenId, generation: u16 },
}
```

Rights reuse the existing bitset with filesystem meanings, so no new rights are strictly
required for v1:

| right | filesystem meaning |
|---|---|
| `READ` | `read`, `readdir`, `stat`, `lookup` |
| `WRITE` | `write`, `create`, `unlink`, `rename`, `truncate`, `mkdir` |
| `CONTROL` | `fsync`, `statvfs`, open-for-read |
| `CONFIG` | mount/unmount admin, `BLOCK_SYNC`/`ERASE_ALL` on the device |
| `INSPECT` | listing, stats |
| `DUPLICATE` | hand a sub-handle to a child with ⊆ rights |

A `FileCap` / `DirCap` (like `DeviceCap`) re-validates the handle (generation → immediate
revocation on unmount) and checks the required right **before** calling the filesystem,
with the same bad-handle policy (`Deny` vs `Kill`) and violation accounting the device path
already uses. Opening a file through a `DirCap` yields a `File` handle whose rights are the
intersection of the `DirCap`'s rights and the open mode — rights only ever narrow, the
property the whole security model is built on.

### 9.2 Per-domain mount namespaces (static chroot)

Today `grant_device(d, dev, rights, name)` makes a device visible as `/dev/<name>` in
*that domain's* namespace, resolved by `DeviceCap::open`. The filesystem analogue is
`grant_dir`:

```rust
pub fn grant_dir(d: DomainId, mount: MountId, sub: FsVnode, rights: Rights, at: &'static str) -> Result<Handle, Error>;
```

so the manifest can give a domain a subtree and nothing else:

```toml
[domain.ota]
# ... quotas ...
dirs = [ { mount = "flash", path = "/firmware", at = "/", rights = ["READ", "WRITE"] } ]

[domain.telemetry]
dirs = [ { mount = "flash", path = "/log",      at = "/", rights = ["WRITE"] } ]
```

An isolated domain's `open("/x")` resolves `/x` **relative to its granted root**, and `..`
is clamped at that root (§2.3), so the `ota` domain physically cannot name `/log` or
`/etc` — a compile-time chroot. The `manifest::validate` `const fn` is extended to check
the FS grants the same way it checks device grants today (every referenced mount/path
exists in a declared mount set, rights are a subset of what the mount supports, isolated
domains never get `CONFIG` mount-admin or write to a `read_only` mount, and names are
unique in a domain's namespace). Because this is validated at build time and frozen at
`seal()`, the capability graph over the filesystem is auditable before the device ever
boots.

### 9.3 How this beats the typical RTOS and Zircon

- **FatFs / FreeRTOS+FAT / SPIFFS**: a single global namespace, no per-task access control
  — any task that can call the FS API can open any path ([ESP-IDF][esp-fs],
  [FatFs][fatfs-chan]).
- **Zephyr VFS**: `fs_mount`/`fs_open` over a global mount table ([Zephyr FS][zephyr-fs],
  [littlefs integration][zephyr-lfs]); user-mode adds per-object permissions but the
  namespace is still global and granted at run time.
- **Zircon/Fuchsia**: the right idea (capability-routed namespaces, no ambient authority)
  but routed *at run time* through the component framework, on a system with an MMU and GB
  of RAM.
- **Bismuth**: per-domain namespaces and rights-checked handles, **declared statically and
  validated at compile time**, enforced before the filesystem logic runs, with revocation
  via object generations — the Zircon model's good parts, minus the run-time machinery,
  sized for an MPU.

---

## 10. Proposed module layout, config and staged plan

### 10.1 File tree

```
src/
  driver/
    block/
      mod.rs        L2 devices · block device class · safe · always
      cache.rs      L2 devices · block: write-back cache / wrappers · safe · always
      sim.rs        L2 devices · block driver: simulated flash/disk · safe · always
    ioctl.rs        (+ 0x09xx block ioctl page, + required_right arms)
    mod.rs          (DeviceClass::Block already present; add FACTORIES entries)
  fs/
    mod.rs          L3 services · fs: vfs core and mount table · safe · fs
    vnode.rs        L3 services · fs: vfs contract · safe · fs
    ramfs.rs        L3 services · fs: ram filesystem · safe · fs
    littlefs.rs     L3 services · fs: littlefs (flash) · safe · fs   (or fs/lfs/)
    fat.rs          L3 services · fs: FAT (interop) · safe · fs       (or fs/fat/)
  compat/posix/
    unistd.rs       (+ Kind::File, open() VFS path, read/write/close File arm, lseek)
    fs.rs           L4 personalities · POSIX: stat/mkdir/readdir/rename/fsync · safe · posix
  security/
    mod.rs          (+ Object::Dir/File, grant_dir, FileCap/DirCap)
    manifest.rs     (+ DirGrant, validate() FS checks)
    syscall.rs      (+ nr::FS_* and dispatch arms)
  config.rs         (+ MAX_BLOCKDEVS/MAX_MOUNTS/MAX_OPEN_FILES/FS_* and per-FS knobs)
  lib.rs            (+ #[cfg(feature="fs")] pub mod fs;)
tests/
  block.rs, vfs.rs, ramfs.rs, littlefs.rs, fat.rs, fs_security.rs
```

`Cargo.toml` features (matching the existing `net`/`net-ip`/`net-filter` granularity):

```toml
fs          = []                 # VFS core + RAM FS (no device needed)
fs-block    = []                 # block device class + sim devices
fs-littlefs = ["fs", "fs-block"] # flash FS
fs-fat      = ["fs", "fs-block"] # FAT interop
```

### 10.2 `tests/structure.rs` change (required)

Add `"crate::fs"` to the banned-import lists for `L0 port`, `L1 kernel` and `L2 devices`.
L3 `fs` may use `crate::security` (same-layer, as `net` does) and everything below; it must
not use `crate::compat::*` (already enforced for L3).

### 10.3 Staged implementation order, with the sim test per stage

Every stage is validated in the host simulator (`sim::run_to_completion`) with
fault-injecting sim devices, exactly like `tests/net.rs` drives `Wire`/`WireEnd` with
`corrupt_next` / `drop_every` / `set_link`.

1. **Block class + sim devices.** `driver/block` + a `SimFlash<BLOCKS, BS>` (erase-to-0xFF,
   program-once-per-word enforcement, and fault knobs: `fail_prog_after(n)`,
   `power_cut_mid_erase`, `wear_out(block)`) and a `SimDisk` (byte-addressable image). Test:
   geometry, read/prog/erase/sync round-trips, that programming a non-erased word fails,
   and that a simulated power cut leaves a block in the documented "undefined" state.
2. **VFS core + RamFs + POSIX.** Mount RamFs at `/tmp`; wire `open/read/write/close/lseek/
   stat/mkdir/unlink/readdir/rename`. Test (sim): full file lifecycle, directory listing,
   path-too-long and name-too-long rejection, `ENOENT`/`EEXIST`/`ENOTDIR`/`EISDIR`,
   open-file-table exhaustion → `EMFILE`, arena exhaustion → `ENOSPC`.
3. **Block cache + wrappers.** `BlockCache`/`Partition`/`ReadOnly`/`WearCounter`. Test:
   cache hit/miss counts, write-back flush on `sync`, that `ReadOnly` refuses `prog`,
   partition offset correctness, wear counts.
4. **littlefs on `SimFlash`.** Mount/format, CRUD, inline files, large (multi-block) files.
   Power-loss test: cut power mid-commit (via the sim flash) and assert the mount recovers
   to the last committed state with no corruption. Wear test: write a hot file many times
   and assert `WearCounter` shows the erases spread across blocks, not concentrated. CI
   differential: mount a reference `littlefs-fuse` image and vice-versa.
5. **FAT on `SimDisk`.** Read a host `mkfs.fat` image; write files and verify with host
   `mtools`; LFN round-trip; one case each for FAT12/16/32. Assert FAT is reported
   `power_safe: false` and that a write-while-cut leaves the documented (possibly
   inconsistent) state — i.e. the limitation is explicit and tested, not hidden.
6. **Per-domain namespaces + capabilities.** Manifest `dirs` grants; `FileCap`/`DirCap`.
   Test (sim, modelled on `tests/sandbox.rs`/`security.rs`): a sandboxed domain opens its
   granted subtree and is denied (`EACCES`, with the `Kill` policy actually killing) on a
   path outside it or a `..` escape; a rights-short handle is refused before the FS runs;
   unmount bumps the generation and every outstanding handle fails `EBADF`.

---

## 11. Open questions, risks, and where unsafe would tempt

**Risks / design tensions**

- **Flash erase latency vs lock scope.** A NOR sector erase is tens-to-hundreds of
  milliseconds. The filesystem must never hold an `IrqCell`/registry lock across a
  `BlockDevice::erase`/`prog`; it takes the per-mount `RawMutex` (priority-inheritance) and
  releases all core locks first, the same discipline the net core follows (never holding
  `NET` across a device call). This bounds priority inversion to one mount and is the single
  biggest correctness constraint in the subsystem.
- **Cache vs power-safety.** A write-back `BlockCache` under littlefs silently breaks
  littlefs's power-loss guarantee (a "committed" CRC that is still only in volatile cache).
  Rule: power-safe filesystems run on synchronous (write-through or uncached) devices;
  write-back caching is for `MediaKind::Disk` only. This must be enforced at mount time (a
  littlefs mount on a write-back-cached device should warn or refuse).
- **`u64` offsets on a 32-bit MCU.** The VFS API uses `u64` offsets/sizes for FAT32 (4 GB
  files) and large SD cards, but littlefs and the MCU address space are 32-bit; sizes are
  clamped per-filesystem and the 64-bit arithmetic is confined to the VFS edge. Document
  the real limits (littlefs ≤ 2 GB, FAT32 file < 4 GB).
- **littlefs on-disk exactness.** Matching the tag/commit encoding byte-for-byte is the
  hardest part and the web survey could not fully extract it from DESIGN.md — SPEC.md must
  be read directly. If exact v2 compat slips, fall back to a native format (losing the
  differential oracle) rather than shipping an almost-compatible one.
- **Timestamps need a clock.** FAT directory entries and `Stat.mtime` want wall-clock time;
  MCUs often lack an RTC. Mtime uses the RTC if present, else kernel ticks since boot, else
  a fixed epoch — documented, and never a reason to block a write.
- **DMA bypasses the MPU.** An SD/eMMC or QSPI controller with bus-master DMA can read/write
  all of RAM, so (per the security doc's net-MAC rule) a DMA-capable storage controller is
  **never** granted as raw MMIO to an isolated domain; the filesystem and the block driver
  run in D0 and validate every user buffer via `kernel::usermem`.
- **32-bit syscall allow-mask.** The ~9 FS syscalls fit the remaining room in the `u32`
  mask (12 used today), but the subsystem spends a meaningful chunk of a finite budget;
  beyond this, the mask would need widening to `u64`.

**Where `unsafe` would tempt, and the safe answer**

- **On-disk struct casting.** The obvious `transmute`/`bytemuck`/pointer-cast over a flash
  buffer to a `#[repr(C)]` struct is forbidden (it is `unsafe` and would have to live
  outside the TCB). Use explicit `from_le_bytes`/`to_le_bytes` field-by-field, as
  `net::csum` already does for Ethernet/IP/UDP headers. This is the only place the design
  pushes toward `unsafe`, and the house style already rejects it.
- **FFI to the littlefs C library.** Tempting (it is mature and the format is tricky) but it
  drags `unsafe` and a C toolchain into a `#![deny(unsafe_code)]` kernel. Re-implement in
  safe Rust; use the C library only as the *test* oracle (§6.4), out of tree.
- **Zero-copy DMA into user slices.** Handled by the existing `kernel::usermem` TCB that
  already validates user buffers at the syscall boundary; the filesystem sees ordinary
  `&[u8]`/`&mut [u8]` and needs no `unsafe`.

**Documented-limitation candidates** (the project already ships "documented limitations"
rather than silent gaps): no symlinks or hard links in v1; no uid/gid/mode permission bits
(capabilities replace them); FAT is managed-media-only, not power-safe, not wear-levelled;
littlefs is single-writer per mount; exFAT not supported (licensing); no `mmap` (needs an
MMU) and **no demand-paging page cache that grows to fill free RAM** — caching is always a
declared fixed budget (§4), even on the x86-64 port, which stays no-heap; nested mounts
below a mount point not supported in v1; case-insensitive-ASCII only on FAT (no full Unicode
folding); timestamps depend on an RTC.

---

## References

**Classic VFS / vnode**
- [vnode-kleiman]: S. Kleiman, "Vnodes: An Architecture for Multiple File System Types in
  Sun UNIX", USENIX 1986 (summary). https://carlstrom.com/stanford/quals/mirror/www.stanford.edu/~emrek/quals/summaries/Vnodes-Kleiman-1986.txt
- Sun VFS/Vnode architecture (Pate, *UNIX Filesystems*). https://www.oreilly.com/library/view/unix-filesystems-evolution/9780471456759/chap07-sec005.html
- [linux-vfs]: Linux kernel, "Overview of the Linux Virtual File System" (superblock /
  inode / dentry / file). https://docs.kernel.org/filesystems/vfs.html

**littlefs**
- [lfs-design]: littlefs DESIGN.md (metadata pairs, CTZ skip-lists, allocator, wear
  leveling, power-loss). https://github.com/littlefs-project/littlefs/blob/master/DESIGN.md
- [lfs-spec]: littlefs SPEC.md (on-disk byte layout, tags, commits). https://github.com/littlefs-project/littlefs/blob/master/SPEC.md
- littlefs repository / `lfs_config`. https://github.com/littlefs-project/littlefs

**Flash / block device traits**
- [es-norflash]: `embedded-storage` `nor_flash` (`ReadNorFlash`/`NorFlash`, `READ_SIZE`/
  `WRITE_SIZE`/`ERASE_SIZE`, power-loss semantics). https://docs.rs/embedded-storage/latest/embedded_storage/nor_flash/index.html
- `embedded-storage` `ReadStorage`/`Storage` (byte-addressed). https://docs.rs/embedded-storage/latest/embedded_storage/
- Embassy flash drivers implementing the traits (nRF, RP2040, Partition). https://docs.embassy.dev/

**FAT**
- [fatspec]: Microsoft Extensible Firmware Initiative FAT32 File System Specification v1.03,
  2000-12-06. https://course.khoury.northeastern.edu/csg256/handouts/fat32_spec_1.03.pdf
- [fat-wiki]: "Design of the FAT file system" (Wikipedia). https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
- [fat-patent-de]: "German Court Invalidates Microsoft FAT Patent" (Slashdot, 2013-12-07).
  https://hardware.slashdot.org/story/13/12/07/1241221/german-court-invalidates-microsoft-fat-patent
- [nuttx-notice]: Apache NuttX NOTICE (FAT LFN patent list 5,579,517 / 5,745,902 /
  5,758,352 / 6,286,013). https://apache.googlesource.com/nuttx/+/refs/heads/master/NOTICE
- [fatfs-chan]: ChaN FatFs (the canonical embedded FAT). http://elm-chan.org/fsw/ff/00index_e.html
- FreeRTOS+FAT. https://www.freertos.org/Documentation/03-Libraries/02-FreeRTOS-plus/03-FreeRTOS-plus-FAT/01-FreeRTOS-plus-FAT

**RTOS filesystems (comparison)**
- [zephyr-fs]: Zephyr File Systems / VFS (`fs_mount_t`, `fs_file_t`, `fs_register`). https://docs.zephyrproject.org/latest/services/storage/file_system/index.html
- [zephyr-lfs]: Zephyr LittleFS integration. https://docs.zephyrproject.org/latest/services/storage/file_system/littlefs.html
- [esp-fs]: ESP-IDF "File System Considerations" (SPIFFS vs LittleFS vs FatFS; resilience,
  wear leveling, RAM). https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/file-system-considerations.html
- [spiffs]: SPIFFS (wear-levelled SPI flash FS; no directories). https://github.com/pellepl/spiffs
- Tock TicKV / storage (key-value for MCUs). https://github.com/tock/tock/tree/master/libraries/tickv

**Bismuth internals cited**
- `src/net/` (the structural template: `NetDevice`, `PacketPool`, single-owner core,
  `/dev/<ifname>` control node), `src/driver/mod.rs` (`DeviceClass::Block`, `Op`,
  `Middleware`), `src/security/mod.rs` (`DeviceCap`, `grant_device`, generations),
  `src/security/manifest.rs` (compile-time `validate`), `src/compat/posix/unistd.rs` (fd
  table), `src/config.rs` (static sizing), `tests/structure.rs` (layer/classification
  rules), `tests/net.rs` (sim-test idiom), `docs/research/networking.md`,
  `docs/research/security.md`.
