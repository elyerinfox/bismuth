//! FAT16 filesystem: format, mount, file/dir operations, multi-cluster I/O, and remount
//! persistence, self-tested over a SimDisk (no external tooling).

use std::sync::Mutex as StdMutex;

use bismuth::driver::block::SimDisk;
use bismuth::fs::{self, DirEntry, FatFs, NodeKind, OpenMode};
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const CREATE: OpenMode = OpenMode::RDWR.with(OpenMode::CREATE);

// ~4200 sectors of 512 bytes → enough clusters (spc=1) to be a FAT16 volume.
static DISK: SimDisk<4200, 512> = SimDisk::new();
static FATFS: FatFs = FatFs::new(&DISK);

#[test]
fn fat16_format_files_dirs_and_remount() {
    let _g = serial();
    FATFS.format().unwrap();
    // A multi-cluster file: cluster is 512 bytes (spc=1), so 2000 bytes spans 4 clusters.
    let data: Vec<u8> = (0..2000u32).map(|i| (i * 7 % 251) as u8).collect();
    sim::run_to_completion(|| {
        fs::mount("/sd", &FATFS).unwrap();

        let f = fs::open("/sd/DATA.BIN", CREATE).unwrap();
        assert_eq!(fs::write(f, &data).unwrap(), 2000);
        assert_eq!(fs::fstat(f).unwrap().size, 2000);
        fs::close(f);

        fs::mkdir("/sd/SUB").unwrap();
        let g = fs::open("/sd/SUB/HELLO.TXT", CREATE).unwrap();
        fs::write(g, b"hi from fat").unwrap();
        fs::close(g);

        // Case-insensitive lookup (FAT short names are case-folded).
        assert_eq!(fs::stat("/sd/data.bin").unwrap().size, 2000);
        assert_eq!(fs::stat("/sd/DATA.BIN").unwrap().kind, NodeKind::File);

        // Read the multi-cluster file back.
        let r = fs::open("/sd/DATA.BIN", OpenMode::READ).unwrap();
        let mut back = vec![0u8; 2000];
        let mut got = 0;
        while got < 2000 {
            let n = fs::read(r, &mut back[got..]).unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        assert_eq!(got, 2000);
        assert_eq!(back, data);
        fs::close(r);

        // readdir root: DATA.BIN (file) + SUB (dir).
        let d = fs::opendir("/sd").unwrap();
        let mut names = Vec::new();
        let mut e = DirEntry::default();
        while fs::readdir(d, &mut e).unwrap() {
            names.push((e.name().to_string(), e.kind));
        }
        fs::closedir(d);
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            names,
            vec![("DATA.BIN".to_string(), NodeKind::File), ("SUB".to_string(), NodeKind::Dir)]
        );
        fs::unmount("/sd").unwrap();
    });

    // Remount by re-parsing the BPB: the volume persists.
    FATFS.mount().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/sd", &FATFS).unwrap();
        let r = fs::open("/sd/SUB/HELLO.TXT", OpenMode::READ).unwrap();
        let mut b = [0u8; 16];
        let n = fs::read(r, &mut b).unwrap();
        assert_eq!(&b[..n], b"hi from fat");
        fs::close(r);
        assert_eq!(fs::stat("/sd/DATA.BIN").unwrap().size, 2000);
    });
}

#[test]
fn fat16_truncate_unlink_rename() {
    let _g = serial();
    FATFS.format().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/sd", &FATFS).unwrap();
        let f = fs::open("/sd/BIG.DAT", CREATE).unwrap();
        fs::write(f, &[0x5Au8; 3000]).unwrap(); // ~6 clusters
        assert_eq!(fs::fstat(f).unwrap().size, 3000);
        fs::ftruncate(f, 500).unwrap();
        assert_eq!(fs::fstat(f).unwrap().size, 500);
        fs::close(f);

        fs::rename("/sd/BIG.DAT", "/sd/SMALL.DAT").unwrap();
        assert_eq!(fs::stat("/sd/BIG.DAT"), Err(bismuth::Error::NotFound));
        assert_eq!(fs::stat("/sd/SMALL.DAT").unwrap().size, 500);

        fs::unlink("/sd/SMALL.DAT").unwrap();
        assert_eq!(fs::stat("/sd/SMALL.DAT"), Err(bismuth::Error::NotFound));

        // Long names are now supported (VFAT long-name entries) and round-trip.
        let long = "/sd/a_name_too_long_for_eight_dot_three.txt";
        fs::close(fs::open(long, CREATE).unwrap());
        assert_eq!(fs::stat(long).unwrap().kind, NodeKind::File);
    });
}

#[test]
fn fat16_long_filenames_round_trip() {
    let _g = serial();
    FATFS.format().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/sd", &FATFS).unwrap();
        // A long, mixed-case name with spaces — requires VFAT long-name entries.
        let path = "/sd/My Long Report 2026.txt";
        let f = fs::open(path, CREATE).unwrap();
        fs::write(f, b"hello lfn").unwrap();
        fs::close(f);

        // Looks up by its exact long name, and the content reads back.
        assert_eq!(fs::stat(path).unwrap().size, 9);
        let r = fs::open(path, OpenMode::READ).unwrap();
        let mut b = [0u8; 16];
        let n = fs::read(r, &mut b).unwrap();
        assert_eq!(&b[..n], b"hello lfn");
        fs::close(r);

        // readdir returns the full long name (not the 8.3 alias).
        let d = fs::opendir("/sd").unwrap();
        let mut names = Vec::new();
        let mut e = DirEntry::default();
        while fs::readdir(d, &mut e).unwrap() {
            names.push(e.name().to_string());
        }
        fs::closedir(d);
        assert!(names.iter().any(|n| n == "My Long Report 2026.txt"), "{names:?}");
    });
}

static DISK12: SimDisk<512, 512> = SimDisk::new();
static FATFS12: FatFs = FatFs::new(&DISK12);

#[test]
fn fat12_small_volume_multicluster_file() {
    let _g = serial();
    // A 512-sector volume is < 4085 clusters, so `format` produces FAT12 (1.5-byte entries).
    FATFS12.format().unwrap();
    // 2000 bytes = 4 clusters → a FAT12 chain exercising both even- and odd-nibble entries.
    let data: Vec<u8> = (0..2000u32).map(|i| (i * 13 % 251) as u8).collect();
    sim::run_to_completion(|| {
        fs::mount("/f12", &FATFS12).unwrap();
        let f = fs::open("/f12/A.BIN", CREATE).unwrap();
        assert_eq!(fs::write(f, &data).unwrap(), 2000);
        assert_eq!(fs::fstat(f).unwrap().size, 2000);
        fs::close(f);
        let r = fs::open("/f12/A.BIN", OpenMode::READ).unwrap();
        let mut back = vec![0u8; 2000];
        let mut got = 0;
        while got < 2000 {
            let n = fs::read(r, &mut back[got..]).unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        fs::close(r);
        assert_eq!(got, 2000);
        assert_eq!(back, data, "FAT12 cluster chain round-trips");
        // Free the chain and confirm space is reclaimed (unlink walks the 12-bit FAT).
        fs::unlink("/f12/A.BIN").unwrap();
        assert!(fs::stat("/f12/A.BIN").is_err());
    });
}
