//! Trusted-platform root of trust: measured boot (PCRs), sealing/unsealing bound to that
//! measurement, and attestation quotes.
//!
//! The [`RootOfTrust`] trait abstracts a hardware TPM 2.0 / secure element (future, over
//! SPI/I2C) from the in-memory [`SoftTpm`] reference used for host testing and bring-up.
//! The design is **TPM gates, keystore derives**: the root releases a key sealed to the
//! boot measurement, and the existing keystore derives the per-domain/per-volume hierarchy
//! from it. Sealing binds data to PCR state — if the measured boot differs (different
//! firmware/workload), the derived key differs and unsealing fails closed with
//! [`Error::Integrity`], never exposing the plaintext.
//!
//! All protocol and crypto here is 100% safe Rust over the vetted RustCrypto primitives
//! already in the tree (SHA-256 for PCRs, HKDF-SHA-256 for key derivation,
//! ChaCha20-Poly1305 for sealing, HMAC-SHA-256 for quotes). `security::seal()` is *policy*
//! sealing; TPM object sealing is [`RootOfTrust::seal`]/[`unseal`] (always PCR-qualified).
//!
//! Classification: L3 services · trusted platform · safe · tpm

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::config::{TPM_PCRS, TPM_SEAL_MAX};
use crate::kernel::cell::IrqCell;

/// Derive a per-volume (or per-domain) key from an unsealed root KEK, bound to `label`.
/// Uses the same HKDF-SHA-256 the keystore derives with: distinct labels yield independent
/// keys, so one TPM-sealed root protects many volumes. The root is the TPM's to release
/// (via [`RootOfTrust::unseal`]); this is the "keystore derives" half of the design.
pub fn derive_volume_key(root_kek: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root_kek);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out).expect("hkdf expand to 32 bytes never fails");
    out
}

/// A blob sealed to a selection of PCRs. Opaque; only the issuing root can unseal it, and
/// only while the selected PCRs match their values at seal time.
#[derive(Copy, Clone)]
pub struct Sealed {
    pcr_mask: u32,
    nonce: [u8; 12],
    tag: [u8; 16],
    len: u16,
    ct: [u8; TPM_SEAL_MAX],
}

impl Default for Sealed {
    fn default() -> Self {
        Sealed { pcr_mask: 0, nonce: [0; 12], tag: [0; 16], len: 0, ct: [0; TPM_SEAL_MAX] }
    }
}

/// A hardware or software root of trust.
pub trait RootOfTrust: Sync {
    /// Extend PCR `index` with `data` (`pcr = SHA-256(pcr || SHA-256(data))`).
    fn extend(&self, index: usize, data: &[u8]) -> Result<(), Error>;
    /// Read PCR `index`.
    fn pcr(&self, index: usize) -> Result<[u8; 32], Error>;
    /// Fill `out` with random bytes.
    fn random(&self, out: &mut [u8]) -> Result<(), Error>;
    /// Seal `data` to the PCRs selected by `pcr_mask` (bit `i` selects PCR `i`).
    fn seal(&self, data: &[u8], pcr_mask: u32) -> Result<Sealed, Error>;
    /// Unseal, succeeding only if the selected PCRs still match. Returns the plaintext len.
    fn unseal(&self, blob: &Sealed, out: &mut [u8]) -> Result<usize, Error>;
    /// Produce an attestation quote over the selected PCRs and a challenge `nonce`.
    fn quote(&self, pcr_mask: u32, nonce: &[u8], out: &mut [u8; 32]) -> Result<(), Error>;
}

/// A deterministic in-memory root of trust: the reference implementation and the host-test
/// double for a real TPM. The device secret seeds both key derivation and the RNG, so a
/// second `SoftTpm` with a different secret models a *different physical device* (its
/// sealed blobs cannot be unsealed here), exactly as hardware binding would behave.
pub struct SoftTpm {
    st: IrqCell<State>,
}

struct State {
    pcrs: [[u8; 32]; TPM_PCRS],
    device_secret: [u8; 32],
    rng_counter: u64,
}

impl SoftTpm {
    /// A fresh root with all PCRs zero and the given 32-byte device secret.
    pub const fn new(device_secret: [u8; 32]) -> Self {
        SoftTpm { st: IrqCell::new(State { pcrs: [[0; 32]; TPM_PCRS], device_secret, rng_counter: 0 }) }
    }

    /// Reset PCRs to zero (a simulated reboot). Keeps the device secret.
    pub fn reboot(&self) {
        self.st.lock(|s| s.pcrs = [[0; 32]; TPM_PCRS]);
    }

    /// Derive the sealing key for `pcr_mask` from the device secret and the *current* PCRs.
    fn derive_key(s: &State, pcr_mask: u32) -> [u8; 32] {
        let mut info = [0u8; TPM_PCRS * 32];
        let mut n = 0;
        for i in 0..TPM_PCRS {
            if pcr_mask & (1 << i) != 0 {
                info[n..n + 32].copy_from_slice(&s.pcrs[i]);
                n += 32;
            }
        }
        let hk = Hkdf::<Sha256>::new(None, &s.device_secret);
        let mut key = [0u8; 32];
        // info is bounded; expand cannot fail for a 32-byte output.
        hk.expand(&info[..n], &mut key).expect("hkdf expand");
        key
    }
}

impl RootOfTrust for SoftTpm {
    fn extend(&self, index: usize, data: &[u8]) -> Result<(), Error> {
        if index >= TPM_PCRS {
            return Err(Error::Invalid);
        }
        let measure = Sha256::digest(data);
        self.st.lock(|s| {
            let mut h = Sha256::new();
            h.update(s.pcrs[index]);
            h.update(measure);
            s.pcrs[index] = h.finalize().into();
        });
        Ok(())
    }

    fn pcr(&self, index: usize) -> Result<[u8; 32], Error> {
        if index >= TPM_PCRS {
            return Err(Error::Invalid);
        }
        Ok(self.st.lock(|s| s.pcrs[index]))
    }

    fn random(&self, out: &mut [u8]) -> Result<(), Error> {
        self.st.lock(|s| {
            for chunk in out.chunks_mut(32) {
                let mut h = Sha256::new();
                h.update(s.device_secret);
                h.update(b"rng");
                h.update(s.rng_counter.to_le_bytes());
                s.rng_counter = s.rng_counter.wrapping_add(1);
                let block: [u8; 32] = h.finalize().into();
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
        });
        Ok(())
    }

    fn seal(&self, data: &[u8], pcr_mask: u32) -> Result<Sealed, Error> {
        if data.len() > TPM_SEAL_MAX {
            return Err(Error::NoSpace);
        }
        let mut blob = Sealed { pcr_mask, len: data.len() as u16, ..Sealed::default() };
        self.random(&mut blob.nonce)?;
        blob.ct[..data.len()].copy_from_slice(data);
        let tag = self.st.lock(|s| {
            let key = Self::derive_key(s, pcr_mask);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            cipher.encrypt_in_place_detached(Nonce::from_slice(&blob.nonce), &[], &mut blob.ct[..data.len()])
        });
        let tag = tag.map_err(|_| Error::Integrity)?;
        blob.tag.copy_from_slice(tag.as_slice());
        Ok(blob)
    }

    fn unseal(&self, blob: &Sealed, out: &mut [u8]) -> Result<usize, Error> {
        let len = blob.len as usize;
        if len > out.len() || len > TPM_SEAL_MAX {
            return Err(Error::Invalid);
        }
        out[..len].copy_from_slice(&blob.ct[..len]);
        self.st
            .lock(|s| {
                let key = Self::derive_key(s, blob.pcr_mask);
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
                cipher.decrypt_in_place_detached(Nonce::from_slice(&blob.nonce), &[], &mut out[..len], Tag::from_slice(&blob.tag))
            })
            .map_err(|_| Error::Integrity)?;
        Ok(len)
    }

    fn quote(&self, pcr_mask: u32, nonce: &[u8], out: &mut [u8; 32]) -> Result<(), Error> {
        self.st.lock(|s| {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&s.device_secret).expect("hmac key");
            for i in 0..TPM_PCRS {
                if pcr_mask & (1 << i) != 0 {
                    mac.update(&s.pcrs[i]);
                }
            }
            mac.update(nonce);
            out.copy_from_slice(&mac.finalize().into_bytes());
        });
        Ok(())
    }
}
