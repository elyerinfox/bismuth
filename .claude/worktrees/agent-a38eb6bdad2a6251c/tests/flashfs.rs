//! The flash filesystem's power-safety core: the copy-on-write metadata pair, including
//! torn-erase and torn-program recovery via SimFlash power-cut injection.

use std::sync::Mutex as StdMutex;

use bismuth::driver::block::SimFlash;
use bismuth::fs::flash::{FlashFs, MetaPair, crc32};
use bismuth::fs::{self, OpenMode};
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const CREATE: OpenMode = OpenMode::RDWR.with(OpenMode::CREATE);

#[test]
fn crc32_matches_known_vector() {
    // CRC-32/IEEE of "123456789" is 0xCBF43926.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

static F_BASIC: SimFlash<8, 256> = SimFlash::new();

#[test]
fn metapair_format_commit_remount() {
    let dev = &F_BASIC;
    let mut mp = MetaPair::<256>::format(dev, 0, 1).unwrap();
    assert_eq!(mp.revision(), 1);
    mp.commit(dev, b"alpha").unwrap();
    mp.commit(dev, b"beta").unwrap();
    assert_eq!(mp.revision(), 3);

    // A fresh mount recovers the latest committed payload.
    let m = MetaPair::<256>::mount(dev, 0, 1).unwrap();
    let mut buf = [0u8; 32];
    let n = m.read(dev, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"beta");
    assert_eq!(m.revision(), 3);
}

static F_ERASE: SimFlash<8, 256> = SimFlash::new();

#[test]
fn metapair_survives_torn_erase() {
    let dev = &F_ERASE;
    let mut mp = MetaPair::<256>::format(dev, 0, 1).unwrap();
    mp.commit(dev, b"first").unwrap();
    mp.commit(dev, b"second").unwrap();
    // Tear the very next mutating op (the erase of the target block).
    dev.power_cut_after(1);
    assert!(mp.commit(dev, b"third").is_err());
    // The prior committed state is intact on remount.
    let m = MetaPair::<256>::mount(dev, 0, 1).unwrap();
    let mut buf = [0u8; 32];
    let n = m.read(dev, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"second");
}

static F_PROG: SimFlash<8, 256> = SimFlash::new();

#[test]
fn metapair_survives_torn_program() {
    let dev = &F_PROG;
    let mut mp = MetaPair::<256>::format(dev, 0, 1).unwrap();
    mp.commit(dev, b"one").unwrap();
    mp.commit(dev, b"two").unwrap();
    // Let the erase (op 1) succeed but tear the program (op 2) of the next commit.
    dev.power_cut_after(2);
    assert!(mp.commit(dev, b"three").is_err());
    // The half-written target fails its CRC, so remount keeps the prior state.
    let m = MetaPair::<256>::mount(dev, 0, 1).unwrap();
    let mut buf = [0u8; 32];
    let n = m.read(dev, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"two");
}

static F_FULL: SimFlash<4, 64> = SimFlash::new();

#[test]
fn metapair_rejects_oversized_payload() {
    let dev = &F_FULL;
    let mut mp = MetaPair::<64>::format(dev, 0, 1).unwrap();
    // Payload cap is block_size - header(8) - crc(4) = 52 bytes.
    assert_eq!(MetaPair::<64>::MAX_PAYLOAD, 52);
    assert!(mp.commit(dev, &[0u8; 52]).is_ok());
    assert_eq!(mp.commit(dev, &[0u8; 53]), Err(bismuth::Error::NoSpace));
}

static F_UNFMT: SimFlash<4, 256> = SimFlash::new();

#[test]
fn mount_of_unformatted_pair_fails() {
    let dev = &F_UNFMT;
    // An erased (all-0xFF) pair has no valid revision.
    assert_eq!(MetaPair::<256>::mount(dev, 0, 1).unwrap_err(), bismuth::Error::Integrity);
}

// ----- the flash filesystem mounted through the VFS -----

static DEV_A: SimFlash<64, 512> = SimFlash::new();
static FFS_A: FlashFs<64, 512> = FlashFs::new(&DEV_A);

#[test]
fn flashfs_files_dirs_and_remount() {
    let _g = serial();
    FFS_A.format().unwrap();
    // A multi-block file (block data capacity is 508 bytes; 1200 spans 3 blocks).
    let data: Vec<u8> = (0..1200u32).map(|i| (i % 253) as u8).collect();
    sim::run_to_completion(|| {
        fs::mount("/", &FFS_A).unwrap();
        let f = fs::open("/boot.cfg", CREATE).unwrap();
        assert_eq!(fs::write(f, &data).unwrap(), 1200);
        assert_eq!(fs::fstat(f).unwrap().size, 1200);
        fs::close(f);

        fs::mkdir("/etc").unwrap();
        let g = fs::open("/etc/hosts", CREATE).unwrap();
        fs::write(g, b"127.0.0.1").unwrap();
        fs::close(g);

        // readdir the root: a file and a directory.
        let d = fs::opendir("/").unwrap();
        let mut names = Vec::new();
        let mut e = bismuth::fs::DirEntry::default();
        while fs::readdir(d, &mut e).unwrap() {
            names.push((e.name().to_string(), e.kind));
        }
        fs::closedir(d);
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            names,
            vec![
                ("boot.cfg".to_string(), bismuth::fs::NodeKind::File),
                ("etc".to_string(), bismuth::fs::NodeKind::Dir),
            ]
        );

        // Read the multi-block file straight back.
        let r = fs::open("/boot.cfg", OpenMode::READ).unwrap();
        let mut back = vec![0u8; 1200];
        assert_eq!(fs::read(r, &mut back).unwrap(), 1200);
        assert_eq!(back, data);
        fs::close(r);
        fs::unmount("/").unwrap();
    });

    // Remount by rescanning the device: everything persists across the mount cycle.
    FFS_A.mount().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/", &FFS_A).unwrap();
        let r = fs::open("/etc/hosts", OpenMode::READ).unwrap();
        let mut b = [0u8; 16];
        let n = fs::read(r, &mut b).unwrap();
        assert_eq!(&b[..n], b"127.0.0.1");
        fs::close(r);
        assert_eq!(fs::stat("/boot.cfg").unwrap().size, 1200);
        let r2 = fs::open("/boot.cfg", OpenMode::READ).unwrap();
        let mut back = vec![0u8; 1200];
        assert_eq!(fs::read(r2, &mut back).unwrap(), 1200);
        assert_eq!(back, data);
        fs::close(r2);
    });
}

static DEV_B: SimFlash<64, 512> = SimFlash::new();
static FFS_B: FlashFs<64, 512> = FlashFs::new(&DEV_B);

#[test]
fn flashfs_power_cut_preserves_old_file() {
    let _g = serial();
    FFS_B.format().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/", &FFS_B).unwrap();
        let f = fs::open("/data", CREATE).unwrap();
        fs::write(f, b"ORIGINAL").unwrap();
        fs::fsync(f).unwrap();
        fs::close(f);

        // Tear the data-block program of the next rewrite (erase = op1, program = op2).
        DEV_B.power_cut_after(2);
        let f2 = fs::open("/data", OpenMode::RDWR).unwrap();
        assert!(fs::write(f2, b"NEWDATA!!").is_err());
        fs::close(f2);
        fs::unmount("/").unwrap();
    });

    // After a rescan the committed metadata still points at the old chain; the torn blocks
    // are orphans, absent from the rebuilt used-set.
    FFS_B.mount().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/", &FFS_B).unwrap();
        let r = fs::open("/data", OpenMode::READ).unwrap();
        let mut b = [0u8; 16];
        let n = fs::read(r, &mut b).unwrap();
        assert_eq!(&b[..n], b"ORIGINAL");
        fs::close(r);
        // The filesystem is still writable (orphans reclaimed, space not leaked).
        let w = fs::open("/again", CREATE).unwrap();
        fs::write(w, b"ok").unwrap();
        fs::close(w);
    });
}

static DEV_C: SimFlash<48, 512> = SimFlash::new();
static FFS_C: FlashFs<48, 512> = FlashFs::new(&DEV_C);

#[test]
fn flashfs_truncate_unlink_and_rename() {
    let _g = serial();
    FFS_C.format().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/", &FFS_C).unwrap();
        let f = fs::open("/f", CREATE).unwrap();
        fs::write(f, &[0xABu8; 1000]).unwrap();
        assert_eq!(fs::fstat(f).unwrap().size, 1000);
        // Truncate shorter.
        fs::ftruncate(f, 100).unwrap();
        assert_eq!(fs::fstat(f).unwrap().size, 100);
        fs::close(f);

        // Same-directory rename.
        fs::rename("/f", "/g").unwrap();
        assert_eq!(fs::stat("/f"), Err(bismuth::Error::NotFound));
        assert_eq!(fs::stat("/g").unwrap().size, 100);

        // Unlink frees it.
        fs::unlink("/g").unwrap();
        assert_eq!(fs::stat("/g"), Err(bismuth::Error::NotFound));

        // rmdir on a populated dir is refused, then succeeds once empty.
        fs::mkdir("/d").unwrap();
        fs::close(fs::open("/d/x", CREATE).unwrap());
        assert_eq!(fs::rmdir("/d"), Err(bismuth::Error::NotEmpty));
        fs::unlink("/d/x").unwrap();
        fs::rmdir("/d").unwrap();
    });
}
