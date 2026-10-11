//! A FAT16/FAT32 filesystem for interoperability on managed media (SD/eMMC/USB): pull the
//! card and read it on a PC, or accept a card a PC wrote.
//!
//! FAT is overwrite-in-place (not copy-on-write) and **not power-fail-safe** — a torn write
//! can corrupt it — so it is managed-media-only; raw NOR/NAND flash uses the power-safe
//! [`flash`](super::flash) filesystem instead. Plain 8.3 FAT was never patented and the
//! VFAT long-name patents have expired, so a read/write implementation is unencumbered;
//! exFAT stays under active licensing and is deliberately **not** implemented.
//!
//! v1 scope: FAT16 and FAT32 (FAT12 is rejected at mount), 512-byte sectors, 8.3 names for
//! create, and VFAT long-name **reading** (assembled on lookup/readdir). Long-name
//! *writing* and FAT12 are documented limitations.
//!
//! `FsVnode` is the absolute 32-byte directory-entry slot (`sector * 16 + index`); the root
//! is the sentinel [`ROOT`]. A node's kind/size/first-cluster are read from that entry.
//!
//! Classification: L3 services · fs: FAT (interop) · safe · fs

use super::vnode::{DirEntry, FileSystem, FsInfo, FsVnode, NodeKind, OpenId, OpenMode, Stat};
use crate::Error;
use crate::config::LFS_MAX_OPEN;
use crate::driver::block::BlockDevice;
use crate::kernel::cell::IrqCell;

const SECTOR: usize = 512;
const ENTRIES_PER_SECTOR: u32 = (SECTOR / 32) as u32;
const ROOT: u32 = u32::MAX;

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_LFN: u8 = 0x0F;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Variant {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Copy, Clone)]
struct Geom {
    variant: Variant,
    spc: u32,          // sectors per cluster
    reserved: u32,     // reserved sector count
    num_fats: u32,
    fat_size: u32,     // sectors per FAT
    root_entries: u32, // FAT16 fixed root entry count
    root_cluster: u32, // FAT32 root first cluster
    first_root_sector: u32,
    first_data_sector: u32,
    total_clusters: u32,
}

impl Geom {
    fn fat_start(&self) -> u32 {
        self.reserved
    }
    fn cluster_sector(&self, cluster: u32) -> u32 {
        self.first_data_sector + (cluster - 2) * self.spc
    }
    fn eoc(&self) -> u32 {
        match self.variant {
            Variant::Fat12 => 0xFF8,
            Variant::Fat16 => 0xFFF8,
            Variant::Fat32 => 0x0FFF_FFF8,
        }
    }
    fn is_eoc(&self, c: u32) -> bool {
        c >= self.eoc()
    }
}

struct State {
    geom: Option<Geom>,
    open: [Option<u32>; LFS_MAX_OPEN],
}

/// A FAT filesystem over a managed block device (512-byte sectors).
pub struct FatFs {
    dev: &'static dyn BlockDevice,
    st: IrqCell<State>,
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

impl FatFs {
    /// Bind to a block device. Call [`mount`](Self::mount) (or [`format`](Self::format)
    /// then `mount`) before mounting into the VFS.
    pub const fn new(dev: &'static dyn BlockDevice) -> Self {
        FatFs { dev, st: IrqCell::new(State { geom: None, open: [None; LFS_MAX_OPEN] }) }
    }

    fn geom(&self) -> Result<Geom, Error> {
        self.st.lock(|s| s.geom).ok_or(Error::NotReady)
    }

    fn read_sector(&self, sector: u32, buf: &mut [u8; SECTOR]) -> Result<(), Error> {
        self.dev.read(sector, 0, buf)
    }
    fn write_sector(&self, sector: u32, buf: &[u8; SECTOR]) -> Result<(), Error> {
        self.dev.prog(sector, 0, buf)
    }

    // ----- FAT table -----

    /// Read one byte of FAT copy 0 at byte offset `off` within the FAT (handles the sector it
    /// falls in — a FAT12 entry can straddle a sector boundary, so bytes are read singly).
    fn fat_byte(&self, g: &Geom, off: u32) -> Result<u8, Error> {
        let mut buf = [0u8; SECTOR];
        self.read_sector(g.fat_start() + off / SECTOR as u32, &mut buf)?;
        Ok(buf[(off % SECTOR as u32) as usize])
    }

    /// Read-modify-write one FAT byte in every FAT copy: `byte = (byte & !mask) | bits`.
    fn fat_byte_rmw(&self, g: &Geom, off: u32, mask: u8, bits: u8) -> Result<(), Error> {
        for copy in 0..g.num_fats {
            let sector = g.fat_start() + copy * g.fat_size + off / SECTOR as u32;
            let within = (off % SECTOR as u32) as usize;
            let mut buf = [0u8; SECTOR];
            self.read_sector(sector, &mut buf)?;
            buf[within] = (buf[within] & !mask) | bits;
            self.write_sector(sector, &buf)?;
        }
        Ok(())
    }

    fn fat_get(&self, g: &Geom, cluster: u32) -> Result<u32, Error> {
        if g.variant == Variant::Fat12 {
            let off = cluster + cluster / 2; // 1.5 bytes per entry
            let raw = self.fat_byte(g, off)? as u32 | (self.fat_byte(g, off + 1)? as u32) << 8;
            return Ok(if cluster & 1 == 0 { raw & 0x0FFF } else { raw >> 4 });
        }
        let (off, width) = match g.variant {
            Variant::Fat16 => (cluster * 2, 2),
            _ => (cluster * 4, 4),
        };
        let sector = g.fat_start() + off / SECTOR as u32;
        let within = (off % SECTOR as u32) as usize;
        let mut buf = [0u8; SECTOR];
        self.read_sector(sector, &mut buf)?;
        Ok(if width == 2 { rd16(&buf, within) as u32 } else { rd32(&buf, within) & 0x0FFF_FFFF })
    }

    fn fat_set(&self, g: &Geom, cluster: u32, value: u32) -> Result<(), Error> {
        if g.variant == Variant::Fat12 {
            let off = cluster + cluster / 2;
            let v = value & 0x0FFF;
            if cluster & 1 == 0 {
                // even: low byte = bits[7:0], next byte's low nibble = bits[11:8].
                self.fat_byte_rmw(g, off, 0xFF, v as u8)?;
                self.fat_byte_rmw(g, off + 1, 0x0F, (v >> 8) as u8)?;
            } else {
                // odd: this byte's high nibble = bits[3:0], next byte = bits[11:4].
                self.fat_byte_rmw(g, off, 0xF0, ((v & 0x0F) << 4) as u8)?;
                self.fat_byte_rmw(g, off + 1, 0xFF, (v >> 4) as u8)?;
            }
            return Ok(());
        }
        let (off, width) = match g.variant {
            Variant::Fat16 => (cluster * 2, 2usize),
            _ => (cluster * 4, 4usize),
        };
        for copy in 0..g.num_fats {
            let base = g.fat_start() + copy * g.fat_size;
            let sector = base + off / SECTOR as u32;
            let within = (off % SECTOR as u32) as usize;
            let mut buf = [0u8; SECTOR];
            self.read_sector(sector, &mut buf)?;
            if width == 2 {
                buf[within..within + 2].copy_from_slice(&(value as u16).to_le_bytes());
            } else {
                let keep = rd32(&buf, within) & 0xF000_0000;
                buf[within..within + 4].copy_from_slice(&(keep | (value & 0x0FFF_FFFF)).to_le_bytes());
            }
            self.write_sector(sector, &buf)?;
        }
        Ok(())
    }

    /// Allocate one free cluster, mark it end-of-chain. Returns its number.
    fn alloc_cluster(&self, g: &Geom) -> Result<u32, Error> {
        for c in 2..g.total_clusters + 2 {
            if self.fat_get(g, c)? == 0 {
                self.fat_set(g, c, g.eoc() | 0xF)?;
                // Zero the cluster's data sectors (dirs require clean entries).
                let base = g.cluster_sector(c);
                let zero = [0u8; SECTOR];
                for s in 0..g.spc {
                    self.write_sector(base + s, &zero)?;
                }
                return Ok(c);
            }
        }
        Err(Error::NoSpace)
    }

    fn free_chain(&self, g: &Geom, mut cluster: u32) -> Result<(), Error> {
        let mut n = 0;
        while cluster >= 2 && !g.is_eoc(cluster) && cluster != 0 {
            let next = self.fat_get(g, cluster)?;
            self.fat_set(g, cluster, 0)?;
            cluster = next;
            n += 1;
            if n > g.total_clusters {
                break;
            }
        }
        Ok(())
    }

    // ----- directory-entry access -----

    fn read_entry(&self, slot: u32) -> Result<[u8; 32], Error> {
        let sector = slot / ENTRIES_PER_SECTOR;
        let idx = (slot % ENTRIES_PER_SECTOR) as usize;
        let mut buf = [0u8; SECTOR];
        self.read_sector(sector, &mut buf)?;
        let mut e = [0u8; 32];
        e.copy_from_slice(&buf[idx * 32..idx * 32 + 32]);
        Ok(e)
    }

    fn write_entry(&self, slot: u32, entry: &[u8; 32]) -> Result<(), Error> {
        let sector = slot / ENTRIES_PER_SECTOR;
        let idx = (slot % ENTRIES_PER_SECTOR) as usize;
        let mut buf = [0u8; SECTOR];
        self.read_sector(sector, &mut buf)?;
        buf[idx * 32..idx * 32 + 32].copy_from_slice(entry);
        self.write_sector(sector, &buf)
    }

    /// First cluster of a directory given its vnode (`ROOT` → root cluster/area).
    fn dir_first_cluster(&self, g: &Geom, dir: FsVnode) -> Result<u32, Error> {
        if dir.0 == ROOT {
            Ok(match g.variant {
                Variant::Fat32 => g.root_cluster,
                _ => 0, // FAT12/FAT16 use a fixed root area, handled specially
            })
        } else {
            let e = self.read_entry(dir.0)?;
            Ok(((rd16(&e, 20) as u32) << 16) | rd16(&e, 26) as u32)
        }
    }

    /// The `n`-th 32-byte-entry slot of a directory, or `None` past the end.
    fn dir_slot(&self, g: &Geom, dir: FsVnode, n: u32) -> Result<Option<u32>, Error> {
        // FAT16 fixed root.
        if dir.0 == ROOT && g.variant != Variant::Fat32 {
            if n >= g.root_entries {
                return Ok(None);
            }
            return Ok(Some(g.first_root_sector * ENTRIES_PER_SECTOR + n));
        }
        // Cluster-chain directory.
        let per_cluster = g.spc * ENTRIES_PER_SECTOR;
        let cluster_idx = n / per_cluster;
        let within = n % per_cluster;
        let mut cluster = self.dir_first_cluster(g, dir)?;
        for _ in 0..cluster_idx {
            cluster = self.fat_get(g, cluster)?;
            if g.is_eoc(cluster) || cluster < 2 {
                return Ok(None);
            }
        }
        if cluster < 2 {
            return Ok(None);
        }
        let sector = g.cluster_sector(cluster) + within / ENTRIES_PER_SECTOR;
        Ok(Some(sector * ENTRIES_PER_SECTOR + within % ENTRIES_PER_SECTOR))
    }

    /// Grow a cluster-chain directory by one cluster so slot `n` exists; returns its slot.
    fn dir_grow_to(&self, g: &Geom, dir: FsVnode, n: u32) -> Result<u32, Error> {
        if dir.0 == ROOT && g.variant != Variant::Fat32 {
            return Err(Error::NoSpace); // fixed root cannot grow
        }
        let per_cluster = g.spc * ENTRIES_PER_SECTOR;
        let mut cluster = self.dir_first_cluster(g, dir)?;
        let want = n / per_cluster;
        for _ in 0..want {
            let next = self.fat_get(g, cluster)?;
            if g.is_eoc(next) || next < 2 {
                let nc = self.alloc_cluster(g)?;
                self.fat_set(g, cluster, nc)?;
                cluster = nc;
            } else {
                cluster = next;
            }
        }
        let within = n % per_cluster;
        let sector = g.cluster_sector(cluster) + within / ENTRIES_PER_SECTOR;
        Ok(sector * ENTRIES_PER_SECTOR + within % ENTRIES_PER_SECTOR)
    }

    // ----- name handling -----

    /// Decode an 8.3 short name into `out`, returning its length.
    fn short_name(e: &[u8; 32], out: &mut [u8; 12]) -> usize {
        let mut n = 0;
        for i in 0..8 {
            if e[i] == b' ' {
                break;
            }
            out[n] = e[i];
            n += 1;
        }
        if e[8] != b' ' {
            out[n] = b'.';
            n += 1;
            for i in 8..11 {
                if e[i] == b' ' {
                    break;
                }
                out[n] = e[i];
                n += 1;
            }
        }
        n
    }

    /// Encode `name` as an 8.3 entry name (uppercased). Fails if it doesn't fit 8.3.
    fn make_short(name: &str, out: &mut [u8; 11]) -> Result<(), Error> {
        *out = [b' '; 11];
        let bytes = name.as_bytes();
        let dot = name.rfind('.');
        let (base, ext) = match dot {
            Some(d) => (&bytes[..d], &bytes[d + 1..]),
            None => (bytes, &[][..]),
        };
        if base.is_empty() || base.len() > 8 || ext.len() > 3 {
            return Err(Error::NameTooLong);
        }
        for (i, &b) in base.iter().enumerate() {
            if b == b'.' {
                return Err(Error::NameTooLong);
            }
            out[i] = b.to_ascii_uppercase();
        }
        for (i, &b) in ext.iter().enumerate() {
            out[8 + i] = b.to_ascii_uppercase();
        }
        Ok(())
    }

    /// Assemble the long name from the LFN run stored in `lfn` (reversed order on disk),
    /// writing UTF-8 into `out`; returns its length, or `0` if no LFN.
    fn decode_lfn(lfn: &[[u8; 32]], count: usize, out: &mut [u8]) -> usize {
        // Entries are collected in on-disk order (last-to-first); walk them in reverse to
        // get chars in order. Each holds 13 UTF-16 code units at offsets 1,3,5,7,9 / 14,16,18,20,22,24 / 28,30.
        let mut utf16 = [0u16; 13 * 20];
        let mut units = 0;
        for k in (0..count).rev() {
            let e = &lfn[k];
            let offs = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            for &o in offs.iter() {
                let u = rd16(e, o);
                if u == 0x0000 || u == 0xFFFF {
                    break;
                }
                if units < utf16.len() {
                    utf16[units] = u;
                    units += 1;
                }
            }
        }
        let mut n = 0;
        for ch in char::decode_utf16(utf16[..units].iter().copied()) {
            let c = ch.unwrap_or('\u{FFFD}');
            let mut tmp = [0u8; 4];
            let s = c.encode_utf8(&mut tmp);
            if n + s.len() <= out.len() {
                out[n..n + s.len()].copy_from_slice(s.as_bytes());
                n += s.len();
            }
        }
        n
    }

    /// Scan a directory, invoking `f(slot, &entry, &name)` for each live file/subdir entry
    /// (long name assembled when present). Stops when `f` returns `Some`.
    fn scan_dir<R>(&self, g: &Geom, dir: FsVnode, mut f: impl FnMut(u32, &[u8; 32], &str) -> Option<R>) -> Result<Option<R>, Error> {
        let mut n = 0u32;
        let mut lfn: [[u8; 32]; 20] = [[0u8; 32]; 20];
        let mut lfn_n = 0usize;
        loop {
            let Some(slot) = self.dir_slot(g, dir, n)? else { return Ok(None) };
            let e = self.read_entry(slot)?;
            n += 1;
            if e[0] == 0x00 {
                return Ok(None); // end of directory
            }
            if e[0] == 0xE5 {
                lfn_n = 0;
                continue; // deleted
            }
            if e[11] == ATTR_LFN {
                if lfn_n < lfn.len() {
                    lfn[lfn_n] = e;
                    lfn_n += 1;
                }
                continue;
            }
            if e[11] & ATTR_VOLUME_ID != 0 {
                lfn_n = 0;
                continue; // volume label
            }
            // A real 8.3 entry (optionally preceded by its LFN run).
            let mut namebuf = [0u8; 260];
            let len = if lfn_n > 0 { Self::decode_lfn(&lfn, lfn_n, &mut namebuf) } else { 0 };
            lfn_n = 0;
            let name: &str = if len > 0 {
                core::str::from_utf8(&namebuf[..len]).unwrap_or("")
            } else {
                let mut sn = [0u8; 12];
                let l = Self::short_name(&e, &mut sn);
                namebuf[..l].copy_from_slice(&sn[..l]);
                core::str::from_utf8(&namebuf[..l]).unwrap_or("")
            };
            if let Some(r) = f(slot, &e, name) {
                return Ok(Some(r));
            }
        }
    }

    fn find_free_slot(&self, g: &Geom, dir: FsVnode) -> Result<u32, Error> {
        let mut n = 0u32;
        loop {
            match self.dir_slot(g, dir, n)? {
                Some(slot) => {
                    let e = self.read_entry(slot)?;
                    if e[0] == 0x00 || e[0] == 0xE5 {
                        return Ok(slot);
                    }
                    n += 1;
                }
                None => return self.dir_grow_to(g, dir, n),
            }
        }
    }

    // ----- long filenames (VFAT) -----

    /// A name needs a long-name entry when it is not a plain upper-case 8.3 name (so a
    /// mixed-case or long name round-trips with its real spelling).
    fn needs_lfn(name: &str) -> bool {
        let mut s = [0u8; 11];
        Self::make_short(name, &mut s).is_err() || name.bytes().any(|b| b.is_ascii_lowercase())
    }

    fn lfn_checksum(short: &[u8; 11]) -> u8 {
        let mut sum = 0u8;
        for &b in short.iter() {
            sum = (((sum & 1) << 7) | (sum >> 1)).wrapping_add(b);
        }
        sum
    }

    /// Whether some live entry already uses the raw 8.3 name `short`.
    fn short_exists(&self, g: &Geom, dir: FsVnode, short: &[u8; 11]) -> Result<bool, Error> {
        let mut n = 0u32;
        while let Some(slot) = self.dir_slot(g, dir, n)? {
            let e = self.read_entry(slot)?;
            if e[0] == 0x00 {
                break;
            }
            if e[0] != 0xE5 && e[11] != ATTR_LFN && &e[0..11] == short {
                return Ok(true);
            }
            n += 1;
        }
        Ok(false)
    }

    /// Generate a unique `BASE~N.EXT` 8.3 alias for a long name.
    fn gen_alias(&self, g: &Geom, dir: FsVnode, name: &str) -> Result<[u8; 11], Error> {
        let trimmed = name.trim_matches('.');
        let (base, ext) = match trimmed.rsplit_once('.') {
            Some((b, e)) => (b, e),
            None => (trimmed, ""),
        };
        let valid = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'~';
        let mut root = [b' '; 6];
        let mut ri = 0;
        for &b in base.as_bytes() {
            if ri == 6 {
                break;
            }
            if valid(b) {
                root[ri] = b.to_ascii_uppercase();
                ri += 1;
            }
        }
        if ri == 0 {
            root[0] = b'_';
        }
        let mut short = [b' '; 11];
        short[0..6].copy_from_slice(&root);
        short[6] = b'~';
        for (i, &b) in ext.as_bytes().iter().take(3).enumerate() {
            short[8 + i] = b.to_ascii_uppercase();
        }
        for n in 1..=9u8 {
            short[7] = b'0' + n;
            if !self.short_exists(g, dir, &short)? {
                return Ok(short);
            }
        }
        Err(Error::Exists)
    }

    /// Find `count` consecutive free directory entries (growing the directory if needed),
    /// returning the first entry's *logical index* (resolve each with [`Self::dir_slot`]).
    fn find_free_run(&self, g: &Geom, dir: FsVnode, count: u32) -> Result<u32, Error> {
        let mut n = 0u32;
        let mut run_start = 0u32;
        let mut run = 0u32;
        loop {
            match self.dir_slot(g, dir, n)? {
                Some(slot) => {
                    let e0 = self.read_entry(slot)?[0];
                    if e0 == 0x00 {
                        // End-of-directory marker: every entry from here is free. The slots
                        // may already exist (the fixed FAT16 root, or the current cluster);
                        // only grow if the run would run off the end.
                        let start = if run > 0 { run_start } else { n };
                        if self.dir_slot(g, dir, start + count - 1)?.is_none() {
                            self.dir_grow_to(g, dir, start + count - 1)?;
                        }
                        return Ok(start);
                    } else if e0 == 0xE5 {
                        if run == 0 {
                            run_start = n;
                        }
                        run += 1;
                        if run == count {
                            return Ok(run_start);
                        }
                    } else {
                        run = 0;
                    }
                    n += 1;
                }
                None => {
                    let start = if run > 0 { run_start } else { n };
                    self.dir_grow_to(g, dir, start + count - 1)?;
                    return Ok(start);
                }
            }
        }
    }

    /// Write one long-name entry carrying 13 UTF-16 units for `ordinal` (1-based).
    fn write_lfn_entry(&self, slot: u32, ordinal: usize, last: bool, checksum: u8, units: &[u16], len: usize) -> Result<(), Error> {
        let mut e = [0u8; 32];
        e[0] = ordinal as u8 | if last { 0x40 } else { 0 };
        e[11] = ATTR_LFN;
        e[13] = checksum;
        let offs = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (j, &o) in offs.iter().enumerate() {
            let global = (ordinal - 1) * 13 + j;
            let u = if global < len {
                units[global]
            } else if global == len {
                0x0000
            } else {
                0xFFFF
            };
            e[o..o + 2].copy_from_slice(&u.to_le_bytes());
        }
        self.write_entry(slot, &e)
    }

    // ----- format (for host self-tests) -----

    /// Format the device as FAT12 (small volumes) or FAT16 (for testing and SD provisioning).
    /// Overwrites everything.
    pub fn format(&self) -> Result<(), Error> {
        let geo = self.dev.geometry();
        if geo.block_size as usize != SECTOR {
            return Err(Error::Invalid);
        }
        let total = geo.block_count;
        let spc: u32 = 1;
        let reserved: u32 = 1;
        let num_fats: u32 = 2;
        let root_entries: u32 = 512;
        let root_dir_sectors = (root_entries * 32).div_ceil(SECTOR as u32);
        let approx_clusters = total / spc;
        // Size the FAT as FAT12 first; if the resulting cluster count is in FAT16 range, size
        // as FAT16 instead. (FAT12 = 1.5 bytes/entry, FAT16 = 2.)
        let f12_fat_size = (approx_clusters * 3).div_ceil(2 * SECTOR as u32).max(1);
        let f12_data_start = reserved + num_fats * f12_fat_size + root_dir_sectors;
        let f12_clusters = total.saturating_sub(f12_data_start) / spc;
        let (fat12, fat_size) = if f12_clusters < 4085 {
            (true, f12_fat_size)
        } else {
            (false, (approx_clusters * 2).div_ceil(SECTOR as u32).max(1))
        };
        // Zero reserved + FAT + root area.
        let data_start = reserved + num_fats * fat_size + root_dir_sectors;
        if data_start + spc >= total || total < 128 {
            return Err(Error::NoSpace);
        }
        let zero = [0u8; SECTOR];
        for s in 0..data_start {
            self.write_sector(s, &zero)?;
        }
        // Boot sector / BPB.
        let mut boot = [0u8; SECTOR];
        boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        boot[3..11].copy_from_slice(b"BISMUTH ");
        boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        boot[13] = spc as u8;
        boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        boot[16] = num_fats as u8;
        boot[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
        if total < 0x10000 {
            boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
        } else {
            boot[32..36].copy_from_slice(&total.to_le_bytes());
        }
        boot[21] = 0xF8; // media
        boot[22..24].copy_from_slice(&(fat_size as u16).to_le_bytes());
        boot[510] = 0x55;
        boot[511] = 0xAA;
        self.write_sector(0, &boot)?;
        // FAT[0], FAT[1] reserved entries (media byte + end-of-chain), per variant width.
        for copy in 0..num_fats {
            let mut fat = [0u8; SECTOR];
            if fat12 {
                fat[0..3].copy_from_slice(&[0xF8, 0xFF, 0xFF]); // two 12-bit entries: FF8, FFF
            } else {
                fat[0..2].copy_from_slice(&0xFFF8u16.to_le_bytes());
                fat[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes());
            }
            self.write_sector(reserved + copy * fat_size, &fat)?;
        }
        self.mount()
    }

    /// Parse the BPB and compute geometry.
    pub fn mount(&self) -> Result<(), Error> {
        if self.dev.geometry().block_size as usize != SECTOR {
            return Err(Error::Invalid);
        }
        let mut b = [0u8; SECTOR];
        self.read_sector(0, &mut b)?;
        if rd16(&b, 11) as usize != SECTOR {
            return Err(Error::Invalid);
        }
        let spc = b[13] as u32;
        let reserved = rd16(&b, 14) as u32;
        let num_fats = b[16] as u32;
        let root_entries = rd16(&b, 17) as u32;
        let total_16 = rd16(&b, 19) as u32;
        let fat_16 = rd16(&b, 22) as u32;
        let total_32 = rd32(&b, 32);
        let fat_32 = rd32(&b, 36);
        let total = if total_16 != 0 { total_16 } else { total_32 };
        let fat_size = if fat_16 != 0 { fat_16 } else { fat_32 };
        if spc == 0 || num_fats == 0 || fat_size == 0 || total == 0 {
            return Err(Error::Invalid);
        }
        let root_dir_sectors = (root_entries * 32).div_ceil(SECTOR as u32);
        let first_root_sector = reserved + num_fats * fat_size;
        let first_data_sector = first_root_sector + root_dir_sectors;
        if first_data_sector >= total {
            return Err(Error::Invalid);
        }
        let total_clusters = (total - first_data_sector) / spc;
        let variant = if total_clusters < 4085 {
            Variant::Fat12
        } else if total_clusters < 65525 {
            Variant::Fat16
        } else {
            Variant::Fat32
        };
        let root_cluster = if variant == Variant::Fat32 { rd32(&b, 44) } else { 0 };
        let g = Geom {
            variant,
            spc,
            reserved,
            num_fats,
            fat_size,
            root_entries,
            root_cluster,
            first_root_sector,
            first_data_sector,
            total_clusters,
        };
        self.st.lock(|s| {
            s.geom = Some(g);
            s.open = [None; LFS_MAX_OPEN];
        });
        Ok(())
    }

    fn open_vnode(&self, f: OpenId) -> Result<FsVnode, Error> {
        self.st.lock(|s| s.open.get(f.0 as usize).copied().flatten()).map(FsVnode).ok_or(Error::BadHandle)
    }
}

impl FileSystem for FatFs {
    fn root(&self) -> FsVnode {
        FsVnode(ROOT)
    }

    fn lookup(&self, dir: FsVnode, name: &str) -> Result<FsVnode, Error> {
        let g = self.geom()?;
        match name {
            "." => return Ok(dir),
            ".." if dir.0 == ROOT => return Ok(dir),
            _ => {}
        }
        let found = self.scan_dir(&g, dir, |slot, _e, n| n.eq_ignore_ascii_case(name).then_some(slot))?;
        found.map(FsVnode).ok_or(Error::NotFound)
    }

    fn stat(&self, v: FsVnode) -> Result<Stat, Error> {
        if v.0 == ROOT {
            return Ok(Stat { kind: NodeKind::Dir, size: 0, blocks: 0, mtime: 0, vnode: v });
        }
        let e = self.read_entry(v.0)?;
        let is_dir = e[11] & ATTR_DIRECTORY != 0;
        let size = rd32(&e, 28);
        Ok(Stat {
            kind: if is_dir { NodeKind::Dir } else { NodeKind::File },
            size: size as u64,
            blocks: size.div_ceil(SECTOR as u32),
            mtime: 0,
            vnode: v,
        })
    }

    fn open(&self, v: FsVnode, _mode: OpenMode) -> Result<OpenId, Error> {
        self.st.lock(|s| {
            for (i, slot) in s.open.iter_mut().enumerate() {
                if slot.is_none() {
                    *slot = Some(v.0);
                    return Ok(OpenId(i as u16));
                }
            }
            Err(Error::NoResources)
        })
    }

    fn read(&self, f: OpenId, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let g = self.geom()?;
        let v = self.open_vnode(f)?;
        let e = self.read_entry(v.0)?;
        let size = rd32(&e, 28) as u64;
        if off >= size {
            return Ok(0);
        }
        let first = ((rd16(&e, 20) as u32) << 16) | rd16(&e, 26) as u32;
        let csize = g.spc * SECTOR as u32; // bytes per cluster
        let avail = (size - off).min(buf.len() as u64) as usize;
        // Walk to the starting cluster.
        let mut cluster = first;
        let mut skip = off / csize as u64;
        while skip > 0 {
            cluster = self.fat_get(&g, cluster)?;
            if g.is_eoc(cluster) || cluster < 2 {
                return Ok(0);
            }
            skip -= 1;
        }
        let mut done = 0;
        let mut pos = off;
        while done < avail && cluster >= 2 && !g.is_eoc(cluster) {
            let within = (pos % csize as u64) as u32;
            let sector = g.cluster_sector(cluster) + within / SECTOR as u32;
            let soff = (within % SECTOR as u32) as usize;
            let mut sec = [0u8; SECTOR];
            self.read_sector(sector, &mut sec)?;
            let n = (SECTOR - soff).min(avail - done);
            buf[done..done + n].copy_from_slice(&sec[soff..soff + n]);
            done += n;
            pos += n as u64;
            if pos % csize as u64 == 0 {
                cluster = self.fat_get(&g, cluster)?;
            }
        }
        Ok(done)
    }

    fn write(&self, f: OpenId, off: u64, buf: &[u8]) -> Result<usize, Error> {
        let g = self.geom()?;
        let v = self.open_vnode(f)?;
        let mut e = self.read_entry(v.0)?;
        let csize = (g.spc * SECTOR as u32) as u64;
        let mut first = ((rd16(&e, 20) as u32) << 16) | rd16(&e, 26) as u32;
        if first < 2 {
            first = self.alloc_cluster(&g)?;
            e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
            e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        }
        // Walk/extend to the starting cluster.
        let mut cluster = first;
        let mut skip = off / csize;
        while skip > 0 {
            let next = self.fat_get(&g, cluster)?;
            cluster = if g.is_eoc(next) || next < 2 {
                let nc = self.alloc_cluster(&g)?;
                self.fat_set(&g, cluster, nc)?;
                nc
            } else {
                next
            };
            skip -= 1;
        }
        let mut done = 0;
        let mut pos = off;
        while done < buf.len() {
            let within = (pos % csize) as u32;
            let sector = g.cluster_sector(cluster) + within / SECTOR as u32;
            let soff = (within % SECTOR as u32) as usize;
            let mut sec = [0u8; SECTOR];
            self.read_sector(sector, &mut sec)?;
            let n = (SECTOR - soff).min(buf.len() - done);
            sec[soff..soff + n].copy_from_slice(&buf[done..done + n]);
            self.write_sector(sector, &sec)?;
            done += n;
            pos += n as u64;
            if done < buf.len() && pos % csize == 0 {
                let next = self.fat_get(&g, cluster)?;
                cluster = if g.is_eoc(next) || next < 2 {
                    let nc = self.alloc_cluster(&g)?;
                    self.fat_set(&g, cluster, nc)?;
                    nc
                } else {
                    next
                };
            }
        }
        let new_size = (off + buf.len() as u64) as u32;
        if new_size > rd32(&e, 28) {
            e[28..32].copy_from_slice(&new_size.to_le_bytes());
        }
        self.write_entry(v.0, &e)?;
        Ok(buf.len())
    }

    fn truncate(&self, f: OpenId, len: u64) -> Result<(), Error> {
        let g = self.geom()?;
        let v = self.open_vnode(f)?;
        let mut e = self.read_entry(v.0)?;
        let first = ((rd16(&e, 20) as u32) << 16) | rd16(&e, 26) as u32;
        if len == 0 {
            if first >= 2 {
                self.free_chain(&g, first)?;
            }
            e[20..22].copy_from_slice(&0u16.to_le_bytes());
            e[26..28].copy_from_slice(&0u16.to_le_bytes());
            e[28..32].copy_from_slice(&0u32.to_le_bytes());
            return self.write_entry(v.0, &e);
        }
        // Shrink: free clusters past the one holding the last retained byte.
        let csize = (g.spc * SECTOR as u32) as u64;
        let keep = ((len - 1) / csize) as u32; // index of last kept cluster
        let mut cluster = first;
        for _ in 0..keep {
            cluster = self.fat_get(&g, cluster)?;
            if g.is_eoc(cluster) || cluster < 2 {
                break;
            }
        }
        let tail = self.fat_get(&g, cluster)?;
        if !g.is_eoc(tail) && tail >= 2 {
            self.free_chain(&g, tail)?;
        }
        self.fat_set(&g, cluster, g.eoc() | 0xF)?;
        if (len as u32) < rd32(&e, 28) {
            e[28..32].copy_from_slice(&(len as u32).to_le_bytes());
        }
        self.write_entry(v.0, &e)
    }

    fn close(&self, f: OpenId) {
        self.st.lock(|s| {
            if let Some(slot) = s.open.get_mut(f.0 as usize) {
                *slot = None;
            }
        });
    }

    fn create(&self, dir: FsVnode, name: &str, kind: NodeKind) -> Result<FsVnode, Error> {
        let g = self.geom()?;
        if self.scan_dir(&g, dir, |_s, _e, n| n.eq_ignore_ascii_case(name).then_some(()))?.is_some() {
            return Err(Error::Exists);
        }
        // Build the 8.3 entry name (an alias when a long name is needed), and emit the
        // VFAT long-name run before the short entry.
        let lfn = Self::needs_lfn(name);
        let mut short = [0u8; 11];
        if lfn {
            short = self.gen_alias(&g, dir, name)?;
        } else {
            Self::make_short(name, &mut short)?;
        }
        let slot = if lfn {
            let mut units = [0u16; 256];
            let mut len = 0usize;
            for c in name.chars() {
                if len < units.len() {
                    units[len] = c as u16;
                    len += 1;
                }
            }
            let n_lfn = len.div_ceil(13).max(1);
            let run = self.find_free_run(&g, dir, (n_lfn + 1) as u32)?;
            let checksum = Self::lfn_checksum(&short);
            // On disk the highest ordinal (with the 0x40 "last" flag) comes first; ordinal 1
            // sits just before the 8.3 entry.
            for p in 0..n_lfn {
                let ordinal = n_lfn - p;
                let eslot = self.dir_slot(&g, dir, run + p as u32)?.ok_or(Error::NoSpace)?;
                self.write_lfn_entry(eslot, ordinal, p == 0, checksum, &units, len)?;
            }
            self.dir_slot(&g, dir, run + n_lfn as u32)?.ok_or(Error::NoSpace)?
        } else {
            self.find_free_slot(&g, dir)?
        };
        let mut e = [0u8; 32];
        e[0..11].copy_from_slice(&short);
        if kind == NodeKind::Dir {
            e[11] = ATTR_DIRECTORY;
            let c = self.alloc_cluster(&g)?;
            e[20..22].copy_from_slice(&((c >> 16) as u16).to_le_bytes());
            e[26..28].copy_from_slice(&(c as u16).to_le_bytes());
            // "." and ".." entries.
            let mut dot = [0u8; 32];
            dot[0..11].copy_from_slice(b".          ");
            dot[11] = ATTR_DIRECTORY;
            dot[20..22].copy_from_slice(&((c >> 16) as u16).to_le_bytes());
            dot[26..28].copy_from_slice(&(c as u16).to_le_bytes());
            let base = g.cluster_sector(c) * ENTRIES_PER_SECTOR;
            self.write_entry(base, &dot)?;
            let pc = if dir.0 == ROOT { 0 } else { self.dir_first_cluster(&g, dir)? };
            let mut dotdot = [0u8; 32];
            dotdot[0..11].copy_from_slice(b"..         ");
            dotdot[11] = ATTR_DIRECTORY;
            dotdot[20..22].copy_from_slice(&((pc >> 16) as u16).to_le_bytes());
            dotdot[26..28].copy_from_slice(&(pc as u16).to_le_bytes());
            self.write_entry(base + 1, &dotdot)?;
        }
        self.write_entry(slot, &e)?;
        Ok(FsVnode(slot))
    }

    fn unlink(&self, dir: FsVnode, name: &str) -> Result<(), Error> {
        let g = self.geom()?;
        let slot = self.scan_dir(&g, dir, |s, _e, n| n.eq_ignore_ascii_case(name).then_some(s))?.ok_or(Error::NotFound)?;
        let mut e = self.read_entry(slot)?;
        let first = ((rd16(&e, 20) as u32) << 16) | rd16(&e, 26) as u32;
        e[0] = 0xE5;
        self.write_entry(slot, &e)?;
        if first >= 2 {
            self.free_chain(&g, first)?;
        }
        Ok(())
    }

    fn rename(&self, odir: FsVnode, old: &str, ndir: FsVnode, new: &str) -> Result<(), Error> {
        let g = self.geom()?;
        if odir.0 != ndir.0 {
            return Err(Error::Unsupported); // cross-directory rename is a v1 limitation
        }
        let slot = self.scan_dir(&g, odir, |s, _e, n| n.eq_ignore_ascii_case(old).then_some(s))?.ok_or(Error::NotFound)?;
        if self.scan_dir(&g, odir, |_s, _e, n| n.eq_ignore_ascii_case(new).then_some(()))?.is_some() {
            return Err(Error::Exists);
        }
        let mut short = [0u8; 11];
        Self::make_short(new, &mut short)?;
        let mut e = self.read_entry(slot)?;
        e[0..11].copy_from_slice(&short);
        self.write_entry(slot, &e)
    }

    fn readdir(&self, dir: FsVnode, cookie: u32, out: &mut DirEntry) -> Result<Option<u32>, Error> {
        let g = self.geom()?;
        // Resume the scan at logical entry `cookie`, counting live entries.
        let mut seen = 0u32;
        let result = self.scan_dir(&g, dir, |slot, e, name| {
            let here = seen;
            seen += 1;
            if here < cookie {
                return None;
            }
            out.set_name(name);
            out.kind = if e[11] & ATTR_DIRECTORY != 0 { NodeKind::Dir } else { NodeKind::File };
            out.vnode = FsVnode(slot);
            Some(())
        })?;
        Ok(result.map(|_| seen))
    }

    fn sync(&self) -> Result<(), Error> {
        self.dev.sync()
    }

    fn info(&self) -> FsInfo {
        let ro = false;
        FsInfo { name: "fat", read_only: ro, power_safe: false, block_size: SECTOR as u32, case_sensitive: false }
    }
}

// silence an unused constant on some builds
const _: u8 = ATTR_READ_ONLY;
