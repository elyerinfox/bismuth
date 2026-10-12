//! A minimal ELF64 loader for `aarch64` Linux executables: parse the header and `PT_LOAD`
//! program headers, yielding the entry point and the segments to map. Pure, bounded (a fixed
//! segment table, no heap) safe Rust — it only *describes* what to load; mapping the segments
//! into an EL0 address space is the port's MMU step.
//!
//! Classification: L4 personalities · linux ELF loader · safe · linux-abi

use crate::Error;

/// Largest number of `PT_LOAD` segments handled (static binaries have a handful).
pub const MAX_SEGMENTS: usize = 8;

/// Segment permission flags (ELF `p_flags`).
pub const PF_X: u8 = 1;
pub const PF_W: u8 = 2;
pub const PF_R: u8 = 4;

/// One loadable segment: copy `filesz` bytes from `offset` to `vaddr`, zero up to `memsz`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub offset: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub flags: u8,
}

/// A parsed ELF image: the entry point and its loadable segments.
#[derive(Copy, Clone)]
pub struct Elf {
    pub entry: u64,
    pub segments: [Segment; MAX_SEGMENTS],
    pub n_segments: usize,
    /// `true` if the ELF is position-independent (`ET_DYN`) rather than fixed (`ET_EXEC`).
    pub pie: bool,
}

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;

fn u16_at(b: &[u8], o: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes([*b.get(o).ok_or(Error::Invalid)?, b[o + 1]]))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32, Error> {
    let s = b.get(o..o + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64, Error> {
    let s = b.get(o..o + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

impl Elf {
    /// Parse a little-endian 64-bit `aarch64` ELF.
    pub fn parse(bin: &[u8]) -> Result<Elf, Error> {
        // e_ident: magic 0x7F 'E' 'L' 'F', class 2 (64-bit), data 1 (little-endian).
        if bin.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
            return Err(Error::Invalid);
        }
        if *bin.get(4).ok_or(Error::Invalid)? != 2 || *bin.get(5).ok_or(Error::Invalid)? != 1 {
            return Err(Error::Unsupported); // 64-bit little-endian only
        }
        let e_type = u16_at(bin, 16)?;
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(Error::Unsupported);
        }
        if u16_at(bin, 18)? != EM_AARCH64 {
            return Err(Error::Unsupported);
        }
        let entry = u64_at(bin, 24)?;
        let phoff = u64_at(bin, 32)? as usize;
        let phentsize = u16_at(bin, 54)? as usize;
        let phnum = u16_at(bin, 56)? as usize;
        if phentsize < 56 {
            return Err(Error::Invalid);
        }

        let mut segments = [Segment::default(); MAX_SEGMENTS];
        let mut n = 0;
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            if u32_at(bin, ph)? != PT_LOAD {
                continue;
            }
            if n >= MAX_SEGMENTS {
                return Err(Error::NoResources);
            }
            let flags = u32_at(bin, ph + 4)? as u8;
            let offset = u64_at(bin, ph + 8)? as usize;
            let vaddr = u64_at(bin, ph + 16)?;
            let filesz = u64_at(bin, ph + 32)? as usize;
            let memsz = u64_at(bin, ph + 40)? as usize;
            // The file contents must exist; memsz (the zero-extended size) must cover filesz.
            if offset + filesz > bin.len() || memsz < filesz {
                return Err(Error::Invalid);
            }
            segments[n] = Segment { vaddr, offset, filesz, memsz, flags };
            n += 1;
        }
        if n == 0 {
            return Err(Error::Invalid);
        }
        Ok(Elf { entry, segments, n_segments: n, pie: e_type == ET_DYN })
    }

    /// The loadable segments.
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.n_segments]
    }

    /// The span `[lowest vaddr, highest vaddr+memsz)` the image occupies — what an address space
    /// must provide before the segments are mapped.
    pub fn address_span(&self) -> (u64, u64) {
        let mut lo = u64::MAX;
        let mut hi = 0;
        for s in self.segments() {
            lo = lo.min(s.vaddr);
            hi = hi.max(s.vaddr + s.memsz as u64);
        }
        (lo, hi)
    }
}
