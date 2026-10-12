# Using the filesystem

This guide registers a block device, mounts a RAM filesystem, and reads and writes files
through both the `fs::` API and the POSIX file API. All snippets are built from the
current tree; sections 2–4 mirror `tests/fs.rs` and section 1 mirrors `tests/block.rs`,
which pass. Concepts, bounds and the planned pieces (littlefs, FAT, caching, per-domain
namespaces): [design/filesystem.md](../design/filesystem.md). The `fs::` API needs the
`fs` feature (on by default); the POSIX file API needs `posix` + `fs`.

## 1. Drive a block device

A `BlockDevice` enforces its medium's contract. You can exercise one directly — no
simulator, no registration — because the raw trait calls do not touch the trusted
registry:

```rust
use bismuth::driver::block::{BlockDevice, MediaKind, SimFlash};

let f: SimFlash<4, 64> = SimFlash::new();   // 4 blocks of 64 bytes, erased to 0xFF
let g = f.geometry();
assert_eq!((g.block_count, g.block_size, g.capacity()), (4, 64, 256));
assert!(matches!(g.kind, MediaKind::Flash { erase_value: 0xFF }));

// A fresh flash reads back all 0xFF; program, then read back.
f.prog(1, 4, b"hello").unwrap();
let mut back = [0u8; 5];
f.read(1, 4, &mut back).unwrap();
assert_eq!(&back, b"hello");

// Programming an already-written byte is rejected (erase-before-write).
assert_eq!(f.prog(1, 4, b"x"), Err(bismuth::Error::Io));

// Erase restores 0xFF and re-enables programming.
f.erase(1).unwrap();
assert!(f.is_erased(1));
```

`SimDisk<BLOCKS, BS>` (managed media: overwrite in place, `erase` is a no-op) and
`SimRam<BLOCKS, BS>` (volatile, `erase` zeroes) have the same trait. To model a power
loss, arm `SimFlash::power_cut_after(n)` — the *n*-th following `prog`/`erase` applies
only its first half and then returns `Error::Io`:

```rust
let f: SimFlash<2, 16> = SimFlash::new();
f.power_cut_after(1);                                  // tear the next write
assert_eq!(f.prog(0, 0, &[0xAA; 8]), Err(bismuth::Error::Io));
assert_eq!(f.peek(0, 0), 0xAA);                        // first half landed
assert_eq!(f.peek(0, 4), 0xFF);                        // second half still erased
```

### Compose wrappers over a device

The data-plane layers are `BlockDevice` wrappers you stack at build time — `Partition`,
`ReadOnly`, `WearCounter` and `BlockCache`, all safe and `const`-constructible:

```rust
use bismuth::driver::block::{BlockDevice, BlockCache, Partition, ReadOnly, SimDisk, SimRam};

// A partition remaps block 0 of the view to block 2 of the disk.
let p: Partition<SimDisk<8, 512>> = Partition::new(SimDisk::new(), 2, 3);
assert_eq!(p.geometry().block_count, 3);

// A read-only view refuses every mutation.
let r: ReadOnly<SimRam<4, 32>> = ReadOnly::new(SimRam::new());
assert_eq!(r.prog(0, 0, b"x"), Err(bismuth::Error::ReadOnly));

// A write-back cache (2 lines of 64 B) holds writes until sync().
let c: BlockCache<SimDisk<4, 64>, 2, 64> = BlockCache::new(SimDisk::new(), false);
c.prog(1, 0, b"cached").unwrap();
assert_eq!(c.inner().peek(1, 0), 0);                   // not on the disk yet
c.sync().unwrap();
assert_eq!(c.inner().peek(1, 0), b'c');                // flushed through
```

Construct `BlockCache` **write-through** (`BlockCache::new(inner, true)`) whenever a
power-safe filesystem sits on top; write-back is for managed (`MediaKind::Disk`) or
read-mostly media. The cache holds its line lock across the inner call, so keep it over
non-blocking / polled media.

## 2. Register a block device

To publish a device under a name, call `block::register`. It is **trusted-only**, so it
runs in the kernel domain — inside the simulator in a test. Filesystems then use the fast
path (`geometry` / `read_at` / `prog_at` / `erase_blk` / `sync`):

```rust
use bismuth::driver::block::{self, SimDisk};
use bismuth::sim;

static DISK: SimDisk<8, 512> = SimDisk::new();

sim::run_to_completion(|| {
    let sd = block::register("sd0", &DISK).unwrap();
    assert_eq!(block::find("sd0"), Some(sd));

    assert_eq!(block::geometry(sd).unwrap().block_size, 512);
    let mut sector = [0u8; 512];
    sector[..3].copy_from_slice(b"fs!");
    block::prog_at(sd, 0, 0, &sector).unwrap();
    let mut back = [0u8; 512];
    block::read_at(sd, 0, 0, &mut back).unwrap();
    assert_eq!(&back[..3], b"fs!");
    block::sync(sd).unwrap();
});
```

RamFs (below) needs no block device; a future flash or disk filesystem is the consumer of
this fast path.

## 3. Mount a RamFs and use the `fs::` API

A filesystem is a `static`. Mount it at an absolute path (trusted-only), then open, write,
seek, read and truncate:

```rust
use bismuth::fs::{self, NodeKind, OpenMode, RamFs, SeekFrom};
use bismuth::sim;

static TMP: RamFs<32, 64, 64> = RamFs::new();   // 32 inodes, 64 blocks of 64 bytes

sim::run_to_completion(|| {
    TMP.format();                               // start from one empty root
    fs::mount("/", &TMP).unwrap();

    let create = OpenMode::RDWR.with(OpenMode::CREATE);
    let f = fs::open("/hello.txt", create).unwrap();
    assert_eq!(fs::write(f, b"hello world").unwrap(), 11);
    assert_eq!(fs::fstat(f).unwrap().size, 11);

    fs::seek(f, SeekFrom::Start(0)).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(fs::read(f, &mut buf).unwrap(), 11);
    assert_eq!(&buf[..11], b"hello world");

    fs::ftruncate(f, 5).unwrap();
    assert_eq!(fs::fstat(f).unwrap().size, 5);
    fs::close(f);

    // Re-open read-only; writing it is refused.
    let r = fs::open("/hello.txt", OpenMode::READ).unwrap();
    assert_eq!(fs::write(r, b"x"), Err(bismuth::Error::PermissionDenied));
    fs::close(r);
});
```

`OpenMode` is a flag set: `READ`, `WRITE`, `RDWR`, and `CREATE` / `TRUNC` / `APPEND` /
`EXCL`, combined with `.with(...)`. `CREATE | EXCL` on an existing file is `Exists`;
`TRUNC` empties a file on open; `APPEND` always writes at end of file.

### Directories

`mkdir`, `stat`, and `opendir`/`readdir`/`closedir` cover the namespace. `readdir` fills a
caller `DirEntry` in place and returns `false` at end of directory; entry order is not
specified:

```rust
use bismuth::fs::DirEntry;

fs::mkdir("/dir").unwrap();
fs::close(fs::open("/dir/a", create).unwrap());
fs::close(fs::open("/dir/b", create).unwrap());
fs::mkdir("/dir/sub").unwrap();

// `.` and `..` resolve.
assert_eq!(fs::stat("/dir/./a").unwrap().kind, NodeKind::File);
assert_eq!(fs::stat("/dir/sub/../a").unwrap().kind, NodeKind::File);

let d = fs::opendir("/dir").unwrap();
let mut e = DirEntry::default();
while fs::readdir(d, &mut e).unwrap() {
    bismuth::kprintln!("{} ({:?})", e.name(), e.kind);   // a, b, sub — in some order
}
fs::closedir(d);

// rmdir refuses a non-empty directory.
assert_eq!(fs::rmdir("/dir"), Err(bismuth::Error::NotEmpty));
fs::rmdir("/dir/sub").unwrap();
fs::unlink("/dir/a").unwrap();
fs::unlink("/dir/b").unwrap();
fs::rmdir("/dir").unwrap();
```

`rename(old, new)` works within one mount (a cross-mount rename is `Unsupported`), and
`unmount("/")` is refused with `Busy` while any file on the mount is still open.

## 4. The POSIX file API

With `posix` + `fs`, any non-`/dev/` path resolves through the VFS. The familiar calls
work on an `fd`:

```rust
use bismuth::compat::{errno, posix};

let fd = posix::open("/etc.conf", posix::O_CREAT | posix::O_RDWR);
assert!(fd >= 0);
assert_eq!(posix::write(fd, b"key=value"), 9);
assert_eq!(posix::lseek(fd, 0, posix::SEEK_SET), 0);
let mut buf = [0u8; 16];
assert_eq!(posix::read(fd, &mut buf), 9);

// fstat reports a regular file of the right size.
let mut st = posix::stat::default();
assert_eq!(posix::fstat(fd, &mut st), 0);
assert_eq!(st.st_mode & posix::S_IFMT, posix::S_IFREG);
assert_eq!(st.st_size, 9);

assert_eq!(posix::ftruncate(fd, 3), 0);
assert_eq!(posix::close(fd), 0);

// mkdir + stat; opening a directory as a file fails with EISDIR.
assert_eq!(posix::mkdir("/var", 0o755), 0);        // the mode is accepted but ignored
assert_eq!(posix::open("/var", posix::O_RDONLY), -1);
assert_eq!(posix::errno(), errno::EISDIR);

// A missing file without O_CREAT fails with ENOENT.
assert_eq!(posix::open("/missing", posix::O_RDONLY), -1);
assert_eq!(posix::errno(), errno::ENOENT);

assert_eq!(posix::unlink("/etc.conf"), 0);
```

`lseek` takes `SEEK_SET` / `SEEK_CUR` / `SEEK_END`; `stat`/`fstat` fill the minimal
`struct stat { st_mode, st_size, st_blocks, st_mtime }`. `mkdir`, `rmdir`, `unlink`,
`rename` and `fsync` are available too. The `mkdir` mode argument is ignored: Bismuth
uses capabilities, not permission bits.

## 5. Sizing and limits

| knob | default (MCU / host) | effect |
|------|---------------------:|--------|
| `BISMUTH_MAX_MOUNTS` | 4 / 4 | mounted filesystems at once |
| `BISMUTH_MAX_OPEN_FILES` | 8 / 32 | open files **and** directories together (one slot each) |
| `BISMUTH_FS_PATH_MAX` | 128 / 128 | longest absolute path (else `NameTooLong`) |
| `BISMUTH_FS_NAME_MAX` | 64 / 64 | longest component, and the `DirEntry` name buffer |
| `BISMUTH_MAX_BLOCKDEVS` | 4 / 4 | registered block devices |

A `RamFs<INODES, BLOCKS, BS>` takes its own sizes as const generics (total memory
≈ `INODES·sizeof(Inode) + BLOCKS·BS`); the `BISMUTH_RAMFS_*` variables only set the
defaults the kernel uses for its own instances. Growing a file past the arena returns
`NoSpace`. See [configuration](../reference/configuration.md#filesystems-fs).

## 6. Not available yet

Persistent filesystems (littlefs for flash, FAT for SD cards), hot-file residency (whole
files kept in RAM; the block cache above already exists), per-domain mount namespaces and
directory-subtree capabilities, a `/dev/<name>` block control node with raw `dd`-style
access, symlinks, and cross-mount rename. See
[design/filesystem.md](../design/filesystem.md#as-built-vs-the-research-proposal).
