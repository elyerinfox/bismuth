//! The overlay (union) filesystem: a read-only lower (image) under a writable upper (container
//! layer), with merge reads, copy-up on write, and whiteout on delete. Driven through the
//! `FileSystem` trait directly.

#![cfg(feature = "fs")]

use bismuth::fs::vnode::FileSystem;
use bismuth::fs::{NodeKind, OpenMode, OverlayFs, RamFs};

static LOWER: RamFs<32, 64, 64> = RamFs::new();
static UPPER: RamFs<32, 64, 64> = RamFs::new();

fn write_file(fs: &dyn FileSystem, root_name: &str, data: &[u8]) {
    let r = fs.root();
    let v = fs.create(r, root_name, NodeKind::File).unwrap();
    let o = fs.open(v, OpenMode::WRITE).unwrap();
    let mut off = 0;
    while off < data.len() {
        off += fs.write(o, off as u64, &data[off..]).unwrap();
    }
    fs.close(o);
}

fn read_via(fs: &dyn FileSystem, v: bismuth::fs::FsVnode) -> Vec<u8> {
    let o = fs.open(v, OpenMode::READ).unwrap();
    let mut buf = [0u8; 64];
    let n = fs.read(o, 0, &mut buf).unwrap();
    fs.close(o);
    buf[..n].to_vec()
}

#[test]
fn overlay_merges_copies_up_and_whiteouts() {
    LOWER.format();
    UPPER.format();
    // The image (lower) ships one file.
    write_file(&LOWER, "base.txt", b"image");

    let ov = OverlayFs::new(&LOWER, &UPPER);
    let root = ov.root();

    // Merge read: the lower file is visible through the overlay.
    let bv = ov.lookup(root, "base.txt").unwrap();
    assert_eq!(read_via(&ov, bv), b"image");

    // Copy-up: writing the lower file copies it into the upper and modifies only that copy.
    let wv = ov.lookup(root, "base.txt").unwrap();
    let w = ov.open(wv, OpenMode::RDWR).unwrap();
    ov.write(w, 0, b"DIRTY").unwrap();
    ov.close(w);
    // Overlay now reads the modified copy...
    let bv2 = ov.lookup(root, "base.txt").unwrap();
    assert_eq!(read_via(&ov, bv2), b"DIRTY");
    // ...but the lower image is untouched.
    let lower_base = LOWER.lookup(LOWER.root(), "base.txt").unwrap();
    assert_eq!(read_via(&LOWER, lower_base), b"image");

    // New files land in the upper layer.
    let nv = ov.create(root, "scratch.txt", NodeKind::File).unwrap();
    let o = ov.open(nv, OpenMode::WRITE).unwrap();
    ov.write(o, 0, b"new").unwrap();
    ov.close(o);
    assert!(UPPER.lookup(UPPER.root(), "scratch.txt").is_ok());

    // Whiteout: deleting hides the lower entry from the overlay, lower still has it.
    ov.unlink(root, "base.txt").unwrap();
    assert!(ov.lookup(root, "base.txt").is_err());
    assert!(LOWER.lookup(LOWER.root(), "base.txt").is_ok());
}
