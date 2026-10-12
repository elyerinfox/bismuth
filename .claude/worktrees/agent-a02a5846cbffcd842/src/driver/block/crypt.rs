//! `CryptBlock<D>`: a transparently-encrypted [`BlockDevice`] wrapper — the storage-at-rest
//! form of the trusted-platform design, and where a TPM-sealed key meets the filesystem.
//!
//! Each logical block is sealed with ChaCha20-Poly1305 under a data-encryption key (DEK):
//! a fresh random 96-bit nonce per write, authenticated with the block's logical address
//! (LBA binding), and the `(nonce, tag)` kept in a reserved out-of-band (OOB) region so the
//! logical block size stays a power of two (what FAT needs). The DEK is injected by trusted
//! mount code after a TPM unseal (`set_dek`) and zeroized on unmount (`clear_dek`); with no
//! DEK the device fails closed ([`Error::NotReady`]), and a wrong key or tampered block
//! fails authentication ([`Error::Integrity`]) — ciphertext is never silently accepted.
//!
//! This is a composition wrapper (the crypto sibling of [`BlockCache`](super::BlockCache)),
//! for overwrite-in-place media (`MediaKind::Disk`/`Ram`); raw flash encrypts above the FS.
//! A LUKS-style split keeps the DEK here (off the keystore hot path) while the key *release*
//! stays TPM-gated in the trusted mount code.
//!
//! Classification: L2 devices · block: encrypted wrapper · safe · crypto

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{BlockDevice, BlockGeometry};
use crate::Error;
use crate::kernel::cell::IrqCell;

const OOB: usize = 28; // nonce(12) + tag(16)

struct Dek {
    key: [u8; 32],
    nonce_seed: [u8; 32],
    counter: u64,
}

/// An encrypting wrapper around an overwrite-in-place block device of `BS`-byte blocks.
pub struct CryptBlock<D, const BS: usize> {
    inner: D,
    dek: IrqCell<Option<Dek>>,
}

impl<D: BlockDevice, const BS: usize> CryptBlock<D, BS> {
    /// Wrap `inner`. No DEK is set, so operations fail closed until [`set_dek`](Self::set_dek).
    pub const fn new(inner: D) -> Self {
        CryptBlock { inner, dek: IrqCell::new(None) }
    }

    /// The wrapped (ciphertext) device.
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Install the data-encryption key and a random nonce seed (from the TPM), unlocking the
    /// device. The seed makes each mount session's nonces unique without a durable counter.
    pub fn set_dek(&self, key: [u8; 32], nonce_seed: [u8; 32]) {
        self.dek.lock(|d| *d = Some(Dek { key, nonce_seed, counter: 0 }));
    }

    /// Forget and zeroize the key (e.g. on unmount / suspend). The device fails closed after.
    pub fn clear_dek(&self) {
        self.dek.lock(|d| {
            if let Some(dek) = d.as_mut() {
                dek.key.zeroize();
                dek.nonce_seed.zeroize();
            }
            *d = None;
        });
    }

    /// Whether a DEK is installed.
    pub fn is_unlocked(&self) -> bool {
        self.dek.lock(|d| d.is_some())
    }

    fn key(&self) -> Result<[u8; 32], Error> {
        self.dek.lock(|d| d.as_ref().map(|k| k.key)).ok_or(Error::NotReady)
    }

    fn draw_nonce(&self) -> Result<[u8; 12], Error> {
        self.dek.lock(|d| {
            let dek = d.as_mut().ok_or(Error::NotReady)?;
            let mut h = Sha256::new();
            h.update(dek.nonce_seed);
            h.update(dek.counter.to_le_bytes());
            dek.counter = dek.counter.wrapping_add(1);
            let out: [u8; 32] = h.finalize().into();
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&out[..12]);
            Ok(nonce)
        })
    }

    /// `(data_block_count, oob_start_block)`.
    fn layout(&self) -> (u32, u32) {
        let total = self.inner.geometry().block_count;
        let epo = (BS / OOB) as u32; // OOB entries per OOB block
        let oob_blocks = total.div_ceil(epo + 1);
        let data = total - oob_blocks;
        (data, data)
    }

    fn oob_loc(&self, blk: u32, oob_start: u32) -> (u32, usize) {
        let epo = (BS / OOB) as u32;
        (oob_start + blk / epo, ((blk % epo) as usize) * OOB)
    }

    fn read_oob(&self, blk: u32, oob_start: u32) -> Result<([u8; 12], [u8; 16]), Error> {
        let (ob, off) = self.oob_loc(blk, oob_start);
        let mut buf = [0u8; BS];
        self.inner.read(ob, 0, &mut buf)?;
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        nonce.copy_from_slice(&buf[off..off + 12]);
        tag.copy_from_slice(&buf[off + 12..off + 28]);
        Ok((nonce, tag))
    }

    fn write_oob(&self, blk: u32, oob_start: u32, nonce: &[u8; 12], tag: &[u8; 16]) -> Result<(), Error> {
        let (ob, off) = self.oob_loc(blk, oob_start);
        let mut buf = [0u8; BS];
        self.inner.read(ob, 0, &mut buf)?;
        buf[off..off + 12].copy_from_slice(nonce);
        buf[off + 12..off + 28].copy_from_slice(tag);
        self.inner.prog(ob, 0, &buf)
    }

    /// Decrypt whole block `blk` into `out`. An unwritten block (zero nonce) reads as zeros.
    fn decrypt_block(&self, blk: u32, oob_start: u32, out: &mut [u8; BS]) -> Result<(), Error> {
        let (nonce, tag) = self.read_oob(blk, oob_start)?;
        if nonce == [0u8; 12] {
            *out = [0u8; BS];
            return Ok(());
        }
        self.inner.read(blk, 0, out)?;
        let key = self.key()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &blk.to_le_bytes(), out, Tag::from_slice(&tag))
            .map_err(|_| Error::Integrity)
    }

    /// Encrypt `buf` (plaintext in, ciphertext out) as block `blk` and store its OOB.
    fn encrypt_block(&self, blk: u32, oob_start: u32, buf: &mut [u8; BS]) -> Result<(), Error> {
        let key = self.key()?;
        let nonce = self.draw_nonce()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &blk.to_le_bytes(), buf)
            .map_err(|_| Error::Integrity)?;
        self.inner.prog(blk, 0, buf)?;
        let mut tagb = [0u8; 16];
        tagb.copy_from_slice(tag.as_slice());
        self.write_oob(blk, oob_start, &nonce, &tagb)
    }
}

impl<D: BlockDevice, const BS: usize> BlockDevice for CryptBlock<D, BS> {
    fn geometry(&self) -> BlockGeometry {
        let (data, _) = self.layout();
        BlockGeometry { block_count: data, ..self.inner.geometry() }
    }

    fn read(&self, blk: u32, off: u32, buf: &mut [u8]) -> Result<(), Error> {
        let (data, oob_start) = self.layout();
        let o = off as usize;
        if blk >= data || o + buf.len() > BS {
            return Err(Error::Invalid);
        }
        let mut scratch = [0u8; BS];
        self.decrypt_block(blk, oob_start, &mut scratch)?;
        buf.copy_from_slice(&scratch[o..o + buf.len()]);
        Ok(())
    }

    fn prog(&self, blk: u32, off: u32, data_in: &[u8]) -> Result<(), Error> {
        let (data, oob_start) = self.layout();
        let o = off as usize;
        if blk >= data || o + data_in.len() > BS {
            return Err(Error::Invalid);
        }
        // Read-modify-write the whole block (AEAD covers the entire block).
        let mut scratch = [0u8; BS];
        self.decrypt_block(blk, oob_start, &mut scratch)?;
        scratch[o..o + data_in.len()].copy_from_slice(data_in);
        self.encrypt_block(blk, oob_start, &mut scratch)
    }

    fn erase(&self, blk: u32) -> Result<(), Error> {
        let (data, oob_start) = self.layout();
        if blk >= data {
            return Err(Error::Invalid);
        }
        // Mark the block unwritten (reads as zeros) by clearing its OOB entry.
        self.write_oob(blk, oob_start, &[0u8; 12], &[0u8; 16])
    }

    fn sync(&self) -> Result<(), Error> {
        self.inner.sync()
    }
}
