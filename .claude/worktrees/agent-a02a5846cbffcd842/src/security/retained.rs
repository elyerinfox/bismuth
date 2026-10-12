//! Retained-RAM: a region whose contents survive a deep-sleep cycle (where peripherals power
//! down but RAM is retained) **confidentiality- and integrity-protected**. Before sleep the
//! region is AEAD-encrypted in place under a fresh key that the root of trust seals to the
//! current PCRs; on resume the key is unsealed (failing closed if the measured state changed)
//! and the region decrypted (failing closed if it was tampered with while the device slept).
//!
//! This is the last software step before RAM may be left unattended, and the first on wake —
//! the `trust::retained::pre_sleep`/`post_resume` hooks the power sequence (`power` §4.3) and
//! the trusted-platform design call for. It reuses [`RootOfTrust`] sealing (key, PCR-bound)
//! and ChaCha20-Poly1305 (the bulk data), so one measured root protects an arbitrarily large
//! region.
//!
//! Classification: L3 services · security: retained RAM · safe · tpm
#![cfg_attr(not(feature = "tpm"), allow(dead_code))]

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use zeroize::Zeroize;

use super::trust::{RootOfTrust, Sealed};
use crate::Error;
use crate::kernel::cell::IrqCell;

/// Additional authenticated data binding the ciphertext to its purpose.
const AAD: &[u8] = b"bismuth-retained-ram";

struct Meta {
    /// The data key, sealed to the PCRs selected at `pre_sleep`.
    sealed_key: Sealed,
    nonce: [u8; 12],
    tag: [u8; 16],
    len: usize,
}

/// A statically-sized retained region. Plaintext while awake; ciphertext (plus sealed key,
/// nonce and tag) across a sleep.
pub struct RetainedRegion<const N: usize> {
    buf: IrqCell<[u8; N]>,
    len: IrqCell<usize>,
    meta: IrqCell<Option<Meta>>,
}

impl<const N: usize> Default for RetainedRegion<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RetainedRegion<N> {
    pub const fn new() -> Self {
        RetainedRegion { buf: IrqCell::new([0; N]), len: IrqCell::new(0), meta: IrqCell::new(None) }
    }

    /// Place plaintext into the region (while awake). Fails if it does not fit.
    pub fn write(&self, data: &[u8]) -> Result<(), Error> {
        if data.len() > N {
            return Err(Error::NoSpace);
        }
        self.buf.lock(|b| b[..data.len()].copy_from_slice(data));
        self.len.lock(|l| *l = data.len());
        Ok(())
    }

    /// Copy out the current plaintext (only meaningful while awake / after `post_resume`).
    pub fn read(&self, out: &mut [u8]) -> usize {
        let len = self.len.lock(|l| *l).min(out.len());
        self.buf.lock(|b| out[..len].copy_from_slice(&b[..len]));
        len
    }

    /// Seal the region for sleep: encrypt it in place under a fresh key sealed to the PCRs in
    /// `pcr_mask`. After this the buffer holds ciphertext and the key exists only sealed.
    pub fn pre_sleep(&self, root: &dyn RootOfTrust, pcr_mask: u32) -> Result<(), Error> {
        let mut key = [0u8; 32];
        super::entropy::fill(&mut key)?;
        let mut nonce = [0u8; 12];
        super::entropy::fill(&mut nonce)?;
        let sealed_key = root.seal(&key, pcr_mask)?;
        let len = self.len.lock(|l| *l);
        let tag = self.buf.lock(|b| {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), AAD, &mut b[..len])
                .map(|t| {
                    let mut out = [0u8; 16];
                    out.copy_from_slice(&t);
                    out
                })
        });
        key.zeroize(); // wipe the plaintext key regardless of outcome
        let tag = tag.map_err(|_| Error::Integrity)?;
        self.meta.lock(|m| *m = Some(Meta { sealed_key, nonce, tag, len }));
        Ok(())
    }

    /// On resume: unseal the key (fails if the measured state changed) and decrypt the region
    /// (fails if it was tampered with). Leaves the buffer as plaintext on success.
    pub fn post_resume(&self, root: &dyn RootOfTrust) -> Result<(), Error> {
        let meta = self.meta.lock(|m| m.take()).ok_or(Error::NotReady)?;
        let mut key = [0u8; 32];
        let n = root.unseal(&meta.sealed_key, &mut key)?;
        if n != 32 {
            key.zeroize();
            return Err(Error::Integrity);
        }
        let r = self.buf.lock(|b| {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            cipher.decrypt_in_place_detached(Nonce::from_slice(&meta.nonce), AAD, &mut b[..meta.len], Tag::from_slice(&meta.tag))
        });
        key.zeroize();
        match r {
            Ok(()) => {
                self.len.lock(|l| *l = meta.len);
                Ok(())
            }
            Err(_) => {
                // Tampered: drop the plaintext so a failed resume never exposes stale data.
                self.buf.lock(|b| *b = [0; N]);
                self.len.lock(|l| *l = 0);
                Err(Error::Integrity)
            }
        }
    }

    /// Whether the region is currently sealed (ciphertext in the buffer).
    pub fn is_sealed(&self) -> bool {
        self.meta.lock(|m| m.is_some())
    }
}
