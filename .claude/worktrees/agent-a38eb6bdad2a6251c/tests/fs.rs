//! VFS core + RamFs: mounting, path resolution, file I/O, directories, and error cases,
//! all host-tested with no hardware.

use std::sync::Mutex as StdMutex;

use bismuth::compat::posix;
use bismuth::fs::{self, DirEntry, NodeKind, OpenMode, RamFs, SeekFrom};
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const RW: OpenMode = OpenMode::RDWR;
const CREATE: OpenMode = OpenMode::RDWR.with(OpenMode::CREATE);

static FS1: RamFs<32, 64, 64> = RamFs::new();

#[test]
fn file_create_write_read_seek_truncate() {
    let _g = serial();
    FS1.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS1).unwrap();

        // Create, write, and stat.
        let f = fs::open("/hello.txt", CREATE).unwrap();
        assert_eq!(fs::write(f, b"hello world").unwrap(), 11);
        assert_eq!(fs::fstat(f).unwrap().size, 11);
        assert_eq!(fs::fstat(f).unwrap().kind, NodeKind::File);

        // Seek back and read it all.
        assert_eq!(fs::seek(f, SeekFrom::Start(0)).unwrap(), 0);
        let mut buf = [0u8; 16];
        assert_eq!(fs::read(f, &mut buf).unwrap(), 11);
        assert_eq!(&buf[..11], b"hello world");

        // Seek relative / from end.
        assert_eq!(fs::seek(f, SeekFrom::End(-5)).unwrap(), 6);
        assert_eq!(fs::read(f, &mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"world");

        // Truncate shorter.
        fs::ftruncate(f, 5).unwrap();
        assert_eq!(fs::fstat(f).unwrap().size, 5);
        fs::seek(f, SeekFrom::Start(0)).unwrap();
        assert_eq!(fs::read(f, &mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");
        fs::close(f);

        // Re-open read-only and confirm persistence across handles.
        let r = fs::open("/hello.txt", OpenMode::READ).unwrap();
        let mut b2 = [0u8; 8];
        assert_eq!(fs::read(r, &mut b2).unwrap(), 5);
        assert_eq!(&b2[..5], b"hello");
        // Writing a read-only handle is refused.
        assert_eq!(fs::write(r, b"x"), Err(bismuth::Error::PermissionDenied));
        fs::close(r);
    });
}

static FS2: RamFs<32, 64, 32> = RamFs::new();

#[test]
fn large_file_spans_multiple_blocks() {
    let _g = serial();
    FS2.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS2).unwrap();
        let f = fs::open("/big", CREATE).unwrap();
        // 200 bytes across 32-byte blocks (7 blocks).
        let data: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(fs::write(f, &data).unwrap(), 200);
        assert_eq!(fs::fstat(f).unwrap().size, 200);
        fs::seek(f, SeekFrom::Start(0)).unwrap();
        let mut back = vec![0u8; 200];
        // Read in two chunks to exercise mid-block offsets.
        let n1 = fs::read(f, &mut back[..70]).unwrap();
        let n2 = fs::read(f, &mut back[70..]).unwrap();
        assert_eq!(n1 + n2, 200);
        assert_eq!(back, data);
        fs::close(f);
    });
}

static FS3: RamFs<32, 64, 64> = RamFs::new();

#[test]
fn directories_create_list_and_remove() {
    let _g = serial();
    FS3.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS3).unwrap();
        fs::mkdir("/dir").unwrap();
        assert_eq!(fs::mkdir("/dir"), Err(bismuth::Error::Exists));
        assert_eq!(fs::stat("/dir").unwrap().kind, NodeKind::Dir);

        // Nested files.
        fs::close(fs::open("/dir/a", CREATE).unwrap());
        fs::close(fs::open("/dir/b", CREATE).unwrap());
        fs::mkdir("/dir/sub").unwrap();

        // Dotted paths resolve.
        assert_eq!(fs::stat("/dir/./a").unwrap().kind, NodeKind::File);
        assert_eq!(fs::stat("/dir/sub/../a").unwrap().kind, NodeKind::File);

        // readdir enumerates all three entries (order-independent).
        let d = fs::opendir("/dir").unwrap();
        let mut names = Vec::new();
        let mut e = DirEntry::default();
        while fs::readdir(d, &mut e).unwrap() {
            names.push((e.name().to_string(), e.kind));
        }
        fs::closedir(d);
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            names,
            vec![
                ("a".to_string(), NodeKind::File),
                ("b".to_string(), NodeKind::File),
                ("sub".to_string(), NodeKind::Dir),
            ]
        );

        // rmdir refuses a non-empty directory, accepts an empty one.
        assert_eq!(fs::rmdir("/dir"), Err(bismuth::Error::NotEmpty));
        fs::rmdir("/dir/sub").unwrap();
        fs::unlink("/dir/a").unwrap();
        fs::unlink("/dir/b").unwrap();
        fs::rmdir("/dir").unwrap();
        assert_eq!(fs::stat("/dir"), Err(bismuth::Error::NotFound));
    });
}

static FS4: RamFs<32, 64, 64> = RamFs::new();

#[test]
fn rename_and_error_paths() {
    let _g = serial();
    FS4.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS4).unwrap();

        // Open-without-create of a missing file fails.
        assert_eq!(fs::open("/nope", OpenMode::READ).err(), Some(bismuth::Error::NotFound));
        // O_EXCL on an existing file fails.
        fs::close(fs::open("/x", CREATE).unwrap());
        assert_eq!(fs::open("/x", CREATE.with(OpenMode::EXCL)).err(), Some(bismuth::Error::Exists));
        // Opening a directory as a file fails.
        fs::mkdir("/d").unwrap();
        assert_eq!(fs::open("/d", OpenMode::READ).err(), Some(bismuth::Error::IsADirectory));
        // Walking through a file as if it were a directory fails.
        assert_eq!(fs::stat("/x/y").err(), Some(bismuth::Error::NotADirectory));

        // Rename within the mount.
        let f = fs::open("/x", RW).unwrap();
        fs::write(f, b"data").unwrap();
        fs::close(f);
        fs::rename("/x", "/y").unwrap();
        assert_eq!(fs::stat("/x"), Err(bismuth::Error::NotFound));
        let r = fs::open("/y", OpenMode::READ).unwrap();
        let mut b = [0u8; 4];
        assert_eq!(fs::read(r, &mut b).unwrap(), 4);
        assert_eq!(&b, b"data");
        fs::close(r);
    });
}

static FS5: RamFs<16, 32, 64> = RamFs::new();

#[test]
fn mount_lifecycle_and_truncate_on_open() {
    let _g = serial();
    FS5.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS5).unwrap();
        // Duplicate mount point is rejected.
        assert_eq!(fs::mount("/", &FS5), Err(bismuth::Error::Exists));

        let f = fs::open("/cfg", CREATE).unwrap();
        fs::write(f, b"0123456789").unwrap();
        fs::close(f);

        // O_TRUNC empties on open.
        let f = fs::open("/cfg", RW.with(OpenMode::TRUNC)).unwrap();
        assert_eq!(fs::fstat(f).unwrap().size, 0);
        fs::write(f, b"new").unwrap();
        fs::close(f);
        assert_eq!(fs::stat("/cfg").unwrap().size, 3);

        // Unmount is refused while a file is open, allowed once closed.
        let held = fs::open("/cfg", OpenMode::READ).unwrap();
        assert_eq!(fs::unmount("/"), Err(bismuth::Error::Busy));
        fs::close(held);
        fs::unmount("/").unwrap();
        // After unmount the path no longer resolves.
        assert_eq!(fs::stat("/cfg"), Err(bismuth::Error::NotFound));
    });
}

static FS_POSIX: RamFs<32, 64, 64> = RamFs::new();

#[test]
fn posix_file_api_through_vfs() {
    let _g = serial();
    FS_POSIX.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS_POSIX).unwrap();

        // open(O_CREAT|O_RDWR), write, lseek, read — all through the POSIX fd layer.
        let fd = posix::open("/etc.conf", posix::O_CREAT | posix::O_RDWR);
        assert!(fd >= 0);
        assert_eq!(posix::write(fd, b"key=value"), 9);
        assert_eq!(posix::lseek(fd, 0, posix::SEEK_SET), 0);
        let mut buf = [0u8; 16];
        let n = posix::read(fd, &mut buf);
        assert_eq!(n, 9);
        assert_eq!(&buf[..9], b"key=value");

        // fstat reports a regular file of the right size.
        let mut st = posix::stat::default();
        assert_eq!(posix::fstat(fd, &mut st), 0);
        assert_eq!(st.st_mode & posix::S_IFMT, posix::S_IFREG);
        assert_eq!(st.st_size, 9);

        // lseek SEEK_END, truncate, and re-stat by path.
        assert_eq!(posix::lseek(fd, -4, posix::SEEK_END), 5);
        assert_eq!(posix::ftruncate(fd, 3), 0);
        assert_eq!(posix::close(fd), 0);
        let mut st2 = posix::stat::default();
        assert_eq!(posix::stat("/etc.conf", &mut st2), 0);
        assert_eq!(st2.st_size, 3);

        // mkdir + stat a directory; opening it as a file fails with EISDIR.
        assert_eq!(posix::mkdir("/var", 0o755), 0);
        let mut sd = posix::stat::default();
        assert_eq!(posix::stat("/var", &mut sd), 0);
        assert_eq!(sd.st_mode & posix::S_IFMT, posix::S_IFDIR);
        assert_eq!(posix::open("/var", posix::O_RDONLY), -1);
        assert_eq!(posix::errno(), bismuth::compat::errno::EISDIR);

        // Opening a missing file without O_CREAT fails with ENOENT.
        assert_eq!(posix::open("/missing", posix::O_RDONLY), -1);
        assert_eq!(posix::errno(), bismuth::compat::errno::ENOENT);

        // unlink removes it.
        assert_eq!(posix::unlink("/etc.conf"), 0);
        assert_eq!(posix::stat("/etc.conf", &mut st2), -1);
    });
}

static FS_APP: RamFs<16, 64, 32> = RamFs::new();

#[test]
fn append_mode_writes_at_end() {
    let _g = serial();
    FS_APP.format();
    sim::run_to_completion(|| {
        fs::mount("/", &FS_APP).unwrap();
        let f = fs::open("/log", CREATE).unwrap();
        fs::write(f, b"aaa").unwrap();
        fs::close(f);
        // APPEND always writes at the current end, ignoring the position.
        let a = fs::open("/log", OpenMode::WRITE.with(OpenMode::APPEND)).unwrap();
        fs::write(a, b"bbb").unwrap();
        fs::write(a, b"ccc").unwrap();
        fs::close(a);
        let r = fs::open("/log", OpenMode::READ).unwrap();
        let mut buf = [0u8; 16];
        let n = fs::read(r, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"aaabbbccc");
        fs::close(r);
    });
}

// ----- per-domain mount namespaces (capability-confined subtrees) -----

use bismuth::security::{self, DirCap, DomainSpec, Rights};
use bismuth::task;

static NS_FS: RamFs<32, 64, 64> = RamFs::new();
static NOTE: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
fn note(s: String) {
    NOTE.lock().unwrap().push(s);
}

#[test]
fn per_domain_namespace_confines_and_enforces_rights() {
    let _g = serial();
    NS_FS.format();
    NOTE.lock().unwrap().clear();
    sim::run_to_completion(|| {
        fs::mount("/", &NS_FS).unwrap();
        // A jailed subtree with a file, plus a secret the domain must never see.
        fs::mkdir("/jail").unwrap();
        let f = fs::open("/jail/ok.txt", CREATE).unwrap();
        fs::write(f, b"data").unwrap();
        fs::close(f);
        let s = fs::open("/secret", CREATE).unwrap();
        fs::write(s, b"top").unwrap();
        fs::close(s);

        // Grant an isolated domain READ-only on /jail, then freeze policy.
        let dom = security::create_domain(DomainSpec::isolated("app", 8, 2)).unwrap();
        fs::grant_dir(dom, "/jail", Rights::READ, "root").unwrap();
        security::seal().unwrap();

        task::Builder::new("app").priority(4).domain(dom).spawn(|_| {
            let cap = DirCap::open("root").unwrap();
            // Read within the subtree works.
            match fs::cap_open(&cap, "ok.txt", OpenMode::READ) {
                Ok(f) => {
                    let mut b = [0u8; 8];
                    let n = fs::read(f, &mut b).unwrap();
                    note(format!("read={:?}", &b[..n]));
                    fs::close(f);
                }
                Err(e) => note(format!("read_err={e:?}")),
            }
            // Write is refused: the capability carries only READ.
            note(format!("write={:?}", fs::cap_open(&cap, "ok.txt", OpenMode::WRITE).err()));
            // `..` cannot escape the jail (the secret stays invisible).
            note(format!("escape={:?}", fs::cap_stat(&cap, "../secret").err()));
            note(format!("secret={:?}", fs::cap_stat(&cap, "secret").err()));
            // A file inside the jail stats fine.
            note(format!("ok_size={:?}", fs::cap_stat(&cap, "ok.txt").map(|s| s.size)));
        }, 0).unwrap();
    });
    let n = NOTE.lock().unwrap().clone();
    assert!(n.iter().any(|x| x == "read=[100, 97, 116, 97]"), "{n:?}"); // b"data"
    assert!(n.iter().any(|x| x.starts_with("write=Some(PermissionDenied")), "{n:?}");
    assert!(n.iter().any(|x| x.starts_with("escape=Some(NotFound")), "{n:?}");
    assert!(n.iter().any(|x| x.starts_with("secret=Some(NotFound")), "{n:?}");
    assert!(n.iter().any(|x| x == "ok_size=Ok(4)"), "{n:?}");
}

// ----- hot-file residency cache -----

static CACHE_FS: RamFs<32, 64, 64> = RamFs::new();

#[test]
fn hot_file_residency_promotes_serves_and_invalidates() {
    let _g = serial();
    CACHE_FS.format();
    sim::run_to_completion(|| {
        fs::mount("/", &CACHE_FS).unwrap();
        {
            let f = fs::open("/hot", CREATE).unwrap();
            fs::write(f, b"HOT").unwrap();
            fs::close(f);
        }
        // Read it past the promotion threshold; it becomes resident.
        for _ in 0..(bismuth::config::FS_RESIDENT_PROMOTE + 2) {
            let f = fs::open("/hot", OpenMode::READ).unwrap();
            let mut b = [0u8; 8];
            let n = fs::read(f, &mut b).unwrap();
            assert_eq!(&b[..n], b"HOT");
            fs::close(f);
        }
        let (hits, promos) = fs::resident::stats();
        assert!(promos >= 1, "expected a promotion, got {promos}");
        assert!(hits >= 1, "expected cache hits, got {hits}");
        assert_eq!(fs::resident::resident_count(), 1);

        // A write invalidates the resident copy (write-through coherency).
        {
            let f = fs::open("/hot", OpenMode::WRITE).unwrap();
            fs::write(f, b"NEW").unwrap();
            fs::close(f);
        }
        assert_eq!(fs::resident::resident_count(), 0);
        // The next read sees the new content (never stale cache).
        let f = fs::open("/hot", OpenMode::READ).unwrap();
        let mut b = [0u8; 8];
        let n = fs::read(f, &mut b).unwrap();
        assert_eq!(&b[..n], b"NEW");
        fs::close(f);
    });
}
