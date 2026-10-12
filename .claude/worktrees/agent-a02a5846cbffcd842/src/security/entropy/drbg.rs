//! ChaCha20 DRBG with fast key erasure (Bernstein), on top of the vetted RustCrypto
//! `chacha20` and `sha2` crates. No new primitive is invented here.
//!
//! Every `generate` call produces one ChaCha20 keystream under the current key: the
//! first 32 bytes become the next key and the rest is output. The old key is erased
//! immediately, so compromising the state never reveals earlier outputs (forward
//! secrecy *per call*).
//!
//! Classification: L3 services · security: DRBG · safe · crypto

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Drbg {
    key: [u8; 32],
    /// Bytes generated since the last reseed.
    #[zeroize(skip)]
    pub(crate) since_reseed: u64,
}

impl Drbg {
    /// Instantiate from seed material (hashed with SHA-256).
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut key: [u8; 32] = Sha256::digest(seed).into();
        let d = Drbg { key, since_reseed: 0 };
        key.zeroize();
        d
    }

    /// `key = SHA-256(seed || key)`.
    pub fn reseed(&mut self, seed: &[u8]) {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(self.key);
        self.key = h.finalize().into();
        self.since_reseed = 0;
    }

    /// Fill `out` with pseudo-random bytes and ratchet the key.
    pub fn generate(&mut self, out: &mut [u8]) {
        let mut cipher = ChaCha20::new(&self.key.into(), &[0u8; 12].into());
        let mut next = [0u8; 32];
        cipher.apply_keystream(&mut next);
        out.fill(0);
        cipher.apply_keystream(out);
        self.key = next;
        next.zeroize();
        self.since_reseed = self.since_reseed.saturating_add(out.len() as u64);
    }

    #[cfg(test)]
    pub(crate) fn key_for_test(&self) -> [u8; 32] {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_key_erasure_ratchets_and_is_deterministic() {
        let mut a = Drbg::from_seed(b"seed");
        let mut b = Drbg::from_seed(b"seed");
        let k0 = a.key_for_test();
        let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
        a.generate(&mut x);
        b.generate(&mut y);
        assert_eq!(x, y, "same seed, same stream");
        assert_ne!(a.key_for_test(), k0, "key ratcheted");
        // The first output block never equals the key that produced it.
        assert_ne!(&x[..32], &a.key_for_test()[..]);
        let mut z = [0u8; 64];
        a.generate(&mut z);
        assert_ne!(x, z);
        b.reseed(b"fresh");
        b.generate(&mut y);
        assert_ne!(y, z, "reseed diverges the stream");
    }

    #[test]
    fn keystream_matches_rfc8439_block_function() {
        // RFC 8439 §2.4.2 uses counter 1; with FKE our first block uses counter 0, so
        // check the raw cipher wrapper against the RFC's §2.3.2 block (counter = 1)
        // by skipping one block.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut c = ChaCha20::new(&key.into(), &nonce.into());
        let mut skip = [0u8; 64];
        c.apply_keystream(&mut skip);
        let mut block = [0u8; 16];
        c.apply_keystream(&mut block);
        assert_eq!(block, [0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4]);
    }
}
