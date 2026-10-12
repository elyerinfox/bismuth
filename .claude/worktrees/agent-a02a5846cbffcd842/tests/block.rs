//! Block device class: simulated flash/disk/ram semantics and the device registry.

use std::sync::Mutex as StdMutex;

use bismuth::driver::block::{
    self, BlockCache, BlockDevice, BlockId, MediaKind, Partition, ReadOnly, SimDisk, SimFlash, SimRam, WearCounter,
};
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn flash_erase_program_once_semantics() {
    let f: SimFlash<4, 64> = SimFlash::new();
    let g = f.geometry();
    assert_eq!(g.block_count, 4);
    assert_eq!(g.block_size, 64);
    assert_eq!(g.capacity(), 256);
    assert!(matches!(g.kind, MediaKind::Flash { erase_value: 0xFF }));

    // A fresh flash reads back all 0xFF.
    let mut buf = [0u8; 8];
    f.read(1, 0, &mut buf).unwrap();
    assert_eq!(buf, [0xFF; 8]);

    // Program, then read back.
    f.prog(1, 4, b"hello").unwrap();
    let mut back = [0u8; 5];
    f.read(1, 4, &mut back).unwrap();
    assert_eq!(&back, b"hello");

    // Programming over an already-written (non-erased) byte is rejected.
    assert_eq!(f.prog(1, 4, b"x"), Err(bismuth::Error::Io));

    // Erase restores 0xFF and re-enables programming.
    f.erase(1).unwrap();
    assert!(f.is_erased(1));
    f.prog(1, 4, b"world").unwrap();
    f.read(1, 4, &mut back).unwrap();
    assert_eq!(&back, b"world");

    // Out-of-range access is rejected.
    assert_eq!(f.read(9, 0, &mut buf), Err(bismuth::Error::Invalid));
    assert_eq!(f.prog(0, 60, &[0; 8]), Err(bismuth::Error::Invalid));
}

#[test]
fn flash_power_cut_tears_a_write() {
    let f: SimFlash<2, 16> = SimFlash::new();
    // The next program is cut after its first half.
    f.power_cut_after(1);
    assert_eq!(f.prog(0, 0, &[0xAA; 8]), Err(bismuth::Error::Io));
    // First half landed, second half is still erased — a classic torn write.
    assert_eq!(f.peek(0, 0), 0xAA);
    assert_eq!(f.peek(0, 3), 0xAA);
    assert_eq!(f.peek(0, 4), 0xFF);
    assert_eq!(f.peek(0, 7), 0xFF);
    // Injection is one-shot: the following op is clean.
    f.erase(0).unwrap();
    assert!(f.is_erased(0));
}

#[test]
fn disk_overwrites_in_place_and_erase_is_noop() {
    let d: SimDisk<4, 512> = SimDisk::new();
    let g = d.geometry();
    assert_eq!((g.read_size, g.prog_size, g.block_size), (512, 512, 512));
    assert!(matches!(g.kind, MediaKind::Disk));

    let mut sector = [0u8; 512];
    sector[..4].copy_from_slice(b"ABCD");
    d.prog(2, 0, &sector).unwrap();
    // Overwrite in place (no erase needed) — unlike flash.
    sector[..4].copy_from_slice(b"WXYZ");
    d.prog(2, 0, &sector).unwrap();
    let mut back = [0u8; 512];
    d.read(2, 0, &mut back).unwrap();
    assert_eq!(&back[..4], b"WXYZ");
    // erase is a no-op that leaves data intact.
    d.erase(2).unwrap();
    d.read(2, 0, &mut back).unwrap();
    assert_eq!(&back[..4], b"WXYZ");
}

#[test]
fn ram_disk_round_trips_and_erases() {
    let r: SimRam<4, 32> = SimRam::new();
    assert!(matches!(r.geometry().kind, MediaKind::Ram));
    r.prog(0, 8, b"edge").unwrap();
    let mut back = [0u8; 4];
    r.read(0, 8, &mut back).unwrap();
    assert_eq!(&back, b"edge");
    r.erase(0).unwrap();
    r.read(0, 8, &mut back).unwrap();
    assert_eq!(&back, &[0, 0, 0, 0]);
}

#[test]
fn partition_maps_a_subrange() {
    let p: Partition<SimDisk<8, 512>> = Partition::new(SimDisk::new(), 2, 3);
    assert_eq!(p.geometry().block_count, 3);
    // Writing block 0 of the partition lands on block 2 of the disk.
    let mut sector = [0u8; 512];
    sector[..3].copy_from_slice(b"PRT");
    p.prog(0, 0, &sector).unwrap();
    assert_eq!(p.inner().peek(2, 0), b'P');
    // Out-of-range relative block is rejected.
    assert_eq!(p.prog(3, 0, &sector), Err(bismuth::Error::Invalid));
    let mut back = [0u8; 512];
    p.read(0, 0, &mut back).unwrap();
    assert_eq!(&back[..3], b"PRT");
}

#[test]
fn read_only_refuses_mutation() {
    let r: ReadOnly<SimRam<4, 32>> = ReadOnly::new(SimRam::new());
    let mut buf = [0u8; 8];
    r.read(0, 0, &mut buf).unwrap(); // reads are fine
    assert_eq!(r.prog(0, 0, b"x"), Err(bismuth::Error::ReadOnly));
    assert_eq!(r.erase(0), Err(bismuth::Error::ReadOnly));
}

#[test]
fn wear_counter_tracks_erases() {
    let w: WearCounter<SimFlash<4, 32>, 4> = WearCounter::new(SimFlash::new());
    w.erase(0).unwrap();
    w.erase(0).unwrap();
    w.erase(1).unwrap();
    assert_eq!(w.erases(0), 2);
    assert_eq!(w.erases(1), 1);
    assert_eq!(w.erases(2), 0);
    assert_eq!(w.total(), 3);
    assert_eq!(w.peak(), 2);
}

#[test]
fn block_cache_write_back_and_write_through() {
    // Write-back over a managed disk: writes stay in cache until sync.
    let wb: BlockCache<SimDisk<4, 64>, 2, 64> = BlockCache::new(SimDisk::new(), false);
    wb.prog(1, 0, b"cached").unwrap();
    // Served from cache immediately.
    let mut buf = [0u8; 6];
    wb.read(1, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"cached");
    // Not yet on the backing disk.
    assert_eq!(wb.inner().peek(1, 0), 0);
    // sync() flushes it through.
    wb.sync().unwrap();
    assert_eq!(wb.inner().peek(1, 0), b'c');

    // Write-through flushes each write immediately.
    let wt: BlockCache<SimDisk<4, 64>, 2, 64> = BlockCache::new(SimDisk::new(), true);
    wt.prog(0, 0, b"now").unwrap();
    assert_eq!(wt.inner().peek(0, 0), b'n');
}

#[test]
fn block_cache_eviction_flushes_dirty() {
    // Two lines, three hot blocks: the LRU eviction must write back the dirty victim.
    let c: BlockCache<SimDisk<8, 32>, 2, 32> = BlockCache::new(SimDisk::new(), false);
    c.prog(0, 0, b"AAA").unwrap();
    c.prog(1, 0, b"BBB").unwrap();
    // Touch block 0 so block 1 is the LRU victim.
    let mut b = [0u8; 3];
    c.read(0, 0, &mut b).unwrap();
    // Accessing a third block evicts block 1, flushing it to the disk.
    c.prog(2, 0, b"CCC").unwrap();
    assert_eq!(c.inner().peek(1, 0), b'B');
    // Block 0 is still cached (not yet flushed).
    assert_eq!(c.inner().peek(0, 0), 0);
}

#[test]
fn block_cache_over_flash_erases_before_flush() {
    // Over flash, a dirty flush must erase then reprogram the whole block.
    let c: BlockCache<SimFlash<4, 32>, 2, 32> = BlockCache::new(SimFlash::new(), true);
    c.prog(0, 0, b"first").unwrap();
    assert_eq!(&{ let mut x = [0u8; 5]; c.read(0, 0, &mut x).unwrap(); x }, b"first");
    // Rewriting the same region would fail on raw flash (program-once); through the cache
    // it succeeds because the flush erases the block first.
    c.prog(0, 0, b"secnd").unwrap();
    let mut back = [0u8; 5];
    c.read(0, 0, &mut back).unwrap();
    assert_eq!(&back, b"secnd");
}

// The registry needs the trusted kernel domain, so it runs inside the simulator.
static DISK: SimDisk<8, 512> = SimDisk::new();
static FLASH: SimFlash<16, 128> = SimFlash::new();

#[test]
fn registry_register_find_and_fast_path() {
    let _g = serial();
    sim::run_to_completion(|| {
        let disk = block::register("sd0", &DISK).unwrap();
        let flash = block::register("mtd0", &FLASH).unwrap();
        assert_ne!(disk, flash);

        // Duplicate name is rejected.
        assert_eq!(block::register("sd0", &DISK), Err(bismuth::Error::Exists));

        // Lookup by name resolves to the same id.
        assert_eq!(block::find("sd0"), Some(disk));
        assert_eq!(block::find("mtd0"), Some(flash));
        assert_eq!(block::find("nope"), None);

        // Fast path (what a filesystem uses).
        assert_eq!(block::geometry(disk).unwrap().block_size, 512);
        let mut sector = [0u8; 512];
        sector[..3].copy_from_slice(b"fs!");
        block::prog_at(disk, 0, 0, &sector).unwrap();
        let mut back = [0u8; 512];
        block::read_at(disk, 0, 0, &mut back).unwrap();
        assert_eq!(&back[..3], b"fs!");
        block::sync(disk).unwrap();

        // An unregistered id fails cleanly.
        assert_eq!(block::geometry(BlockId(200)), Err(bismuth::Error::NotFound));
    });
}

// ----- the /dev control node (DeviceClass::Block) -----

static FLASHC: SimFlash<8, 128> = SimFlash::new();
static CTRL: bismuth::driver::block::BlockControl = bismuth::driver::block::BlockControl::new(&FLASHC);

#[test]
fn block_control_node_exposes_geometry_and_admin() {
    use bismuth::driver::{self, DeviceClass, ioctl};
    let _g = serial();
    sim::run_to_completion(|| {
        let dev = driver::register("mtd0", &CTRL).unwrap();
        assert_eq!(dev.class(), Ok(DeviceClass::Block));
        assert_eq!(dev.ioctl(ioctl::BLOCK_GET_BLOCK_SIZE, 0), Ok(128));
        assert_eq!(dev.ioctl(ioctl::BLOCK_GET_BLOCK_COUNT, 0), Ok(8));
        assert_eq!(dev.ioctl(ioctl::BLOCK_GET_READ_SIZE, 0), Ok(1));
        assert_eq!(dev.ioctl(ioctl::BLOCK_GET_KIND, 0), Ok(0)); // Flash
        assert_eq!(dev.ioctl(ioctl::BLOCK_SYNC, 0), Ok(0));
        // Dirty a block, then whole-device erase restores it.
        FLASHC.prog(2, 0, b"dirty").unwrap();
        assert!(!FLASHC.is_erased(2));
        assert_eq!(dev.ioctl(ioctl::BLOCK_ERASE_ALL, 0), Ok(0));
        assert!(FLASHC.is_erased(2));
        // Bulk data access is not exposed on the control node.
        assert_eq!(dev.ioctl(0xDEAD, 0), Err(bismuth::Error::Unsupported));
    });
}
