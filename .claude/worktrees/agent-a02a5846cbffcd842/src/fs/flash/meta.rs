//! The power-safety primitive of the flash filesystem: a copy-on-write **metadata pair**.
//!
//! A metadata pair is two erase blocks used as a ping-pong journal. At any moment one
//! block holds the last committed state; a [`commit`](MetaPair::commit) erases the *other*
//! block and writes the new state there with an incremented revision and a trailing
//! CRC-32, then switches to it. A torn erase or torn program leaves that other block
//! failing its CRC, so [`mount`](MetaPair::mount) simply keeps the older, still-valid
//! block — any interrupted write is therefore atomically all-or-nothing, which is the
//! power-loss guarantee the whole filesystem rests on. (This is littlefs's metadata-pair
//! idea; the byte layout is Bismuth-native, not upstream-v2-compatible.)
//!
//! On-disk block layout: `rev:u32 · len:u16 · pad:u16 · payload[len] · crc32:u32`, little
//! endian, CRC-32/IEEE over the bytes preceding it.
//!
//! Classification: L3 services · fs: flash metadata pairs · safe · fs

use crate::Error;
use crate::driver::block::BlockDevice;

const HEADER: usize = 8; // rev(4) + len(2) + pad(2)
const CRC: usize = 4;

/// Sequence-arithmetic "is `b` a newer revision than `a`?", wraparound-safe (RFC 1982
/// style). A plain `b > a` would silently pick the *older* block once the 32-bit revision
/// counter wraps or the two blocks straddle the boundary — a power-safety defeater.
fn seq_newer(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) > 0
}

/// CRC-32/IEEE (polynomial 0xEDB88320), table-free and safe.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A ping-pong metadata pair over blocks `b0`/`b1` of a device, each `BS` bytes.
#[derive(Copy, Clone, Debug)]
pub struct MetaPair<const BS: usize> {
    b0: u32,
    b1: u32,
    rev: u32,
    /// `false` = `b0` is current, `true` = `b1`.
    cur_is_b1: bool,
}

impl<const BS: usize> MetaPair<BS> {
    /// Maximum payload a pair can hold.
    pub const MAX_PAYLOAD: usize = BS - HEADER - CRC;

    fn check_geom(dev: &dyn BlockDevice) -> Result<(), Error> {
        if dev.geometry().block_size as usize == BS { Ok(()) } else { Err(Error::Invalid) }
    }

    /// Parse a block buffer, returning `(rev, payload_len)` if its CRC validates.
    fn validate(buf: &[u8; BS]) -> Option<(u32, usize)> {
        let rev = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let len = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        if len > Self::MAX_PAYLOAD {
            return None;
        }
        let end = HEADER + len;
        let stored = u32::from_le_bytes([buf[end], buf[end + 1], buf[end + 2], buf[end + 3]]);
        (crc32(&buf[..end]) == stored).then_some((rev, len))
    }

    fn block(&self) -> u32 {
        if self.cur_is_b1 { self.b1 } else { self.b0 }
    }

    fn other(&self) -> u32 {
        if self.cur_is_b1 { self.b0 } else { self.b1 }
    }

    /// The current revision number.
    pub fn revision(&self) -> u32 {
        self.rev
    }

    /// Format a fresh, empty pair (erases both blocks, writes an empty revision 1 to `b0`).
    pub fn format(dev: &dyn BlockDevice, b0: u32, b1: u32) -> Result<Self, Error> {
        Self::check_geom(dev)?;
        dev.erase(b0)?;
        dev.erase(b1)?;
        let mut mp = MetaPair { b0, b1, rev: 0, cur_is_b1: true };
        // Commit an empty payload; this writes rev 1 to b0 and makes it current.
        mp.commit(dev, &[])?;
        Ok(mp)
    }

    /// Mount an existing pair, selecting the valid block with the higher revision.
    pub fn mount(dev: &dyn BlockDevice, b0: u32, b1: u32) -> Result<Self, Error> {
        Self::check_geom(dev)?;
        let mut buf = [0u8; BS];
        dev.read(b0, 0, &mut buf)?;
        let v0 = Self::validate(&buf);
        dev.read(b1, 0, &mut buf)?;
        let v1 = Self::validate(&buf);
        match (v0, v1) {
            (Some((r0, _)), Some((r1, _))) if seq_newer(r0, r1) => Ok(MetaPair { b0, b1, rev: r1, cur_is_b1: true }),
            (Some((r0, _)), _) => Ok(MetaPair { b0, b1, rev: r0, cur_is_b1: false }),
            (None, Some((r1, _))) => Ok(MetaPair { b0, b1, rev: r1, cur_is_b1: true }),
            (None, None) => Err(Error::Integrity),
        }
    }

    /// Read the current payload into `out`; returns the true payload length (which may
    /// exceed `out.len()`, in which case `out` holds a prefix).
    pub fn read(&self, dev: &dyn BlockDevice, out: &mut [u8]) -> Result<usize, Error> {
        let mut buf = [0u8; BS];
        dev.read(self.block(), 0, &mut buf)?;
        let (_, len) = Self::validate(&buf).ok_or(Error::Integrity)?;
        let n = len.min(out.len());
        out[..n].copy_from_slice(&buf[HEADER..HEADER + n]);
        Ok(len)
    }

    /// Atomically replace the payload. Writes to the non-current block and only switches to
    /// it once the CRC has landed, so a power loss during this call preserves the prior
    /// payload.
    pub fn commit(&mut self, dev: &dyn BlockDevice, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > Self::MAX_PAYLOAD {
            return Err(Error::NoSpace);
        }
        let target = self.other();
        dev.erase(target)?;
        let len = payload.len();
        let end = HEADER + len;
        let next_rev = self.rev.wrapping_add(1);
        let mut buf = [0u8; BS];
        buf[0..4].copy_from_slice(&next_rev.to_le_bytes());
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());
        buf[HEADER..end].copy_from_slice(payload);
        let crc = crc32(&buf[..end]);
        buf[end..end + CRC].copy_from_slice(&crc.to_le_bytes());
        dev.prog(target, 0, &buf[..end + CRC])?;
        // Only now is the new state durable: switch to it.
        self.cur_is_b1 = !self.cur_is_b1;
        self.rev = next_rev;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::seq_newer;

    #[test]
    fn sequence_arithmetic_is_wraparound_safe() {
        // Normal case.
        assert!(seq_newer(1, 2));
        assert!(!seq_newer(2, 1));
        assert!(!seq_newer(5, 5));
        // Across the u32 boundary: MAX is OLDER than 0 (a plain `>` would get this wrong).
        assert!(seq_newer(u32::MAX, 0));
        assert!(!seq_newer(0, u32::MAX));
        assert!(seq_newer(u32::MAX - 1, u32::MAX));
        assert!(seq_newer(u32::MAX, 1));
    }
}
