//! Keystore: PSA-style key handles over vetted RustCrypto primitives.
//!
//! * Key material lives only in the keystore's table; domains hold **handles** whose
//!   rights (`K_ENCRYPT`, `K_SIGN`, ...) are checked together with the key's own usage
//!   policy and algorithm binding, so a MAC key can never be used for encryption and a
//!   key is never exported unless it was created exportable *and* the handle allows it.
//! * Material is zeroized on destroy; destroyed keys bump their generation so stale
//!   handles fail.
//! * [`self_test`] runs known-answer tests (RFC 8439, FIPS 180-4, RFC 4231); if any fails
//!   the keystore refuses to operate.
//!
//! Algorithms: ChaCha20-Poly1305 AEAD, HMAC-SHA-256, HKDF-SHA-256, SHA-256.
//! Hardware accelerators can implement the same operations behind this API later; the
//! software implementations remain the reference.
//!
//! Classification: L3 services · security: keystore · safe · crypto

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{DomainId, Handle, Object, Rights, current, grant_object, with_domain};
use crate::Error;
use crate::kernel::cell::IrqCell;

const MAX_KEYS: usize = 16;

/// Algorithm a key is bound to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// 256-bit ChaCha20-Poly1305 AEAD key.
    ChaCha20Poly1305,
    /// HMAC-SHA-256 key.
    HmacSha256,
    /// HKDF-SHA-256 input keying material (can only derive new keys).
    HkdfSha256,
}

/// Key attributes (PSA-style): algorithm binding and permitted usage.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyAttrs {
    pub ty: KeyType,
    /// Permitted operations (`K_*` rights). The handle granted to the creator carries
    /// exactly these rights.
    pub usage: Rights,
}

impl KeyAttrs {
    pub const fn aead() -> Self {
        KeyAttrs { ty: KeyType::ChaCha20Poly1305, usage: Rights(Rights::K_ENCRYPT.0 | Rights::K_DECRYPT.0) }
    }

    pub const fn mac() -> Self {
        KeyAttrs { ty: KeyType::HmacSha256, usage: Rights(Rights::K_SIGN.0 | Rights::K_VERIFY.0) }
    }

    pub const fn kdf() -> Self {
        KeyAttrs { ty: KeyType::HkdfSha256, usage: Rights::K_DERIVE }
    }

    fn valid(&self) -> bool {
        let allowed = match self.ty {
            KeyType::ChaCha20Poly1305 => Rights::K_ENCRYPT.0 | Rights::K_DECRYPT.0,
            KeyType::HmacSha256 => Rights::K_SIGN.0 | Rights::K_VERIFY.0,
            KeyType::HkdfSha256 => Rights::K_DERIVE.0,
        } | Rights::K_EXPORT.0
            | Rights::DUPLICATE.0;
        self.usage.0 & !allowed == 0 && self.usage.0 != 0
    }
}

struct KeySlot {
    in_use: bool,
    generation: u16,
    owner: DomainId,
    attrs: KeyAttrs,
    material: [u8; 32],
}

impl KeySlot {
    const EMPTY: KeySlot = KeySlot {
        in_use: false,
        generation: 0,
        owner: DomainId::KERNEL,
        attrs: KeyAttrs { ty: KeyType::HmacSha256, usage: Rights::NONE },
        material: [0; 32],
    };
}

static KEYS: IrqCell<[KeySlot; MAX_KEYS]> = IrqCell::new([const { KeySlot::EMPTY }; MAX_KEYS]);
static STATE: IrqCell<Option<bool>> = IrqCell::new(None); // None = self-test not yet run

/// Destroy every key owned by domain `d` (called when the domain is killed), zeroizing
/// the material. Outstanding handles are already invalid once the domain is gone.
pub(crate) fn purge_domain(d: DomainId) {
    KEYS.lock(|k| {
        for s in k.iter_mut() {
            if s.in_use && s.owner == d {
                s.material.zeroize();
                s.in_use = false;
                s.generation = s.generation.wrapping_add(1);
            }
        }
    });
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    KEYS.lock(|k| {
        for s in k.iter_mut() {
            s.material.zeroize();
            *s = KeySlot::EMPTY;
        }
    });
    STATE.lock(|s| *s = None);
}

fn ensure_ready() -> Result<(), Error> {
    let st = STATE.lock(|s| *s);
    match st {
        Some(true) => Ok(()),
        Some(false) => Err(Error::NotReady),
        None => {
            self_test()?;
            Ok(())
        }
    }
}

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    core::array::from_fn(|i| {
        let v = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        };
        (v(b[2 * i]) << 4) | v(b[2 * i + 1])
    })
}

/// Known-answer self-tests for every algorithm. Runs automatically before first use;
/// on failure the keystore stays disabled.
pub fn self_test() -> Result<(), Error> {
    let ok = kat_sha256() && kat_hmac() && kat_aead();
    STATE.lock(|s| *s = Some(ok));
    if ok { Ok(()) } else { Err(Error::Integrity) }
}

fn kat_sha256() -> bool {
    // FIPS 180-4 example "abc".
    let d: [u8; 32] = Sha256::digest(b"abc").into();
    d == hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
}

fn kat_hmac() -> bool {
    // RFC 4231 test case 2.
    let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(b"Jefe") else { return false };
    m.update(b"what do ya want for nothing?");
    let t: [u8; 32] = m.finalize().into_bytes().into();
    t == hex::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
}

fn kat_aead() -> bool {
    // RFC 8439 §2.8.2.
    let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce = hex::<12>("070000004041424344454647");
    let aad = hex::<12>("50515253c0c1c2c3c4c5c6c7");
    let mut buf = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let cipher = ChaCha20Poly1305::new(&key.into());
    let Ok(tag) = cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut buf) else { return false };
    let ok = buf[..16] == hex::<16>("d31a8d34648e60db7b86afbc53ef7ec2")
        && tag.as_slice() == hex::<16>("1ae10b594f09e26a7e902ecbd0600691");
    ok && cipher.decrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut buf, &tag).is_ok()
}

fn insert(attrs: KeyAttrs, material: &[u8; 32]) -> Result<Handle, Error> {
    let owner = current();
    let (slot, generation) = KEYS.lock(|k| {
        let i = k.iter().position(|s| !s.in_use).ok_or(Error::NoResources)?;
        let s = &mut k[i];
        s.in_use = true;
        s.generation = s.generation.wrapping_add(1);
        s.owner = owner;
        s.attrs = attrs;
        s.material = *material;
        Ok::<_, Error>((i as u8, s.generation))
    })?;
    match grant_object(owner, Object::Key { slot, generation }, attrs.usage, "key") {
        Ok(h) => Ok(h),
        Err(e) => {
            wipe(slot as usize);
            Err(e)
        }
    }
}

fn wipe(i: usize) {
    KEYS.lock(|k| {
        k[i].material.zeroize();
        k[i].in_use = false;
        k[i].generation = k[i].generation.wrapping_add(1);
    });
}

/// Generate a fresh random key from the calling domain's DRBG.
pub fn generate(attrs: KeyAttrs) -> Result<Handle, Error> {
    ensure_ready()?;
    if !attrs.valid() {
        return Err(Error::Invalid);
    }
    let mut m = [0u8; 32];
    super::entropy::fill(&mut m)?;
    let h = insert(attrs, &m);
    m.zeroize();
    h
}

/// Import existing key material (32 bytes).
pub fn import(attrs: KeyAttrs, material: &[u8]) -> Result<Handle, Error> {
    ensure_ready()?;
    if !attrs.valid() || material.len() != 32 {
        return Err(Error::Invalid);
    }
    let mut m = [0u8; 32];
    m.copy_from_slice(material);
    let h = insert(attrs, &m);
    m.zeroize();
    h
}

/// Resolve a key handle in the caller's domain and check both the handle's rights and
/// the key's usage policy and type. Returns a copy of the material for the operation.
fn use_key(h: Handle, need: Rights, ty: KeyType) -> Result<(usize, [u8; 32]), Error> {
    ensure_ready()?;
    let d = current();
    let slot = with_domain(d, |s| s.handles.get(h))?.map_err(|e| super::violation(d, e))?;
    let Object::Key { slot: i, generation } = slot.object else { return Err(super::violation(d, Error::BadHandle)) };
    if !slot.rights.contains(need) {
        return Err(super::violation(d, Error::PermissionDenied));
    }
    KEYS.lock(|k| {
        let s = &k[i as usize];
        if !s.in_use || s.generation != generation || s.owner != d {
            return Err(Error::BadHandle);
        }
        if s.attrs.ty != ty || !s.attrs.usage.contains(need) {
            return Err(Error::PermissionDenied);
        }
        Ok((i as usize, s.material))
    })
}

/// Encrypt `buf` in place; returns the 16-byte authentication tag.
pub fn aead_seal(h: Handle, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<[u8; 16], Error> {
    let (_, mut key) = use_key(h, Rights::K_ENCRYPT, KeyType::ChaCha20Poly1305)?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    key.zeroize();
    let tag = cipher.encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buf).map_err(|_| Error::Invalid)?;
    Ok(tag.into())
}

/// Verify and decrypt `buf` in place. On authentication failure `buf` is wiped and
/// `Error::Integrity` returned.
pub fn aead_open(h: Handle, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> Result<(), Error> {
    let (_, mut key) = use_key(h, Rights::K_DECRYPT, KeyType::ChaCha20Poly1305)?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    key.zeroize();
    cipher.decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buf, Tag::from_slice(tag)).map_err(|_| {
        buf.zeroize();
        Error::Integrity
    })
}

/// HMAC-SHA-256 of `data`.
pub fn mac(h: Handle, data: &[u8]) -> Result<[u8; 32], Error> {
    let (_, mut key) = use_key(h, Rights::K_SIGN, KeyType::HmacSha256)?;
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|_| Error::Invalid)?;
    key.zeroize();
    m.update(data);
    Ok(m.finalize().into_bytes().into())
}

/// Verify an HMAC-SHA-256 tag in constant time.
pub fn mac_verify(h: Handle, data: &[u8], tag: &[u8; 32]) -> Result<(), Error> {
    let (_, mut key) = use_key(h, Rights::K_VERIFY, KeyType::HmacSha256)?;
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|_| Error::Invalid)?;
    key.zeroize();
    m.update(data);
    m.verify_slice(tag).map_err(|_| Error::Integrity)
}

/// Derive a new key (HKDF-SHA-256 expand with `info`) into a fresh key handle. The
/// derived bytes never leave the keystore.
pub fn derive(h: Handle, info: &[u8], attrs: KeyAttrs) -> Result<Handle, Error> {
    if !attrs.valid() {
        return Err(Error::Invalid);
    }
    let (_, mut ikm) = use_key(h, Rights::K_DERIVE, KeyType::HkdfSha256)?;
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    ikm.zeroize();
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| Error::Invalid)?;
    let r = insert(attrs, &okm);
    okm.zeroize();
    r
}

/// Export raw key material. Requires `K_EXPORT` on both the handle and the key policy.
pub fn export(h: Handle, out: &mut [u8; 32]) -> Result<(), Error> {
    let ty = key_type(h)?;
    let (_, key) = use_key(h, Rights::K_EXPORT, ty)?;
    *out = key;
    Ok(())
}

/// The algorithm of a key the caller holds.
pub fn key_type(h: Handle) -> Result<KeyType, Error> {
    let d = current();
    let slot = with_domain(d, |s| s.handles.get(h))??;
    let Object::Key { slot: i, generation } = slot.object else { return Err(Error::BadHandle) };
    KEYS.lock(|k| {
        let s = &k[i as usize];
        if s.in_use && s.generation == generation && s.owner == d { Ok(s.attrs.ty) } else { Err(Error::BadHandle) }
    })
}

/// Destroy a key: zeroize its material and invalidate every handle to it.
pub fn destroy(h: Handle) -> Result<(), Error> {
    let d = current();
    let slot = with_domain(d, |s| s.handles.remove(h))??;
    let Object::Key { slot: i, generation } = slot.object else { return Err(Error::BadHandle) };
    let owned = KEYS.lock(|k| k[i as usize].in_use && k[i as usize].generation == generation && k[i as usize].owner == d);
    if owned {
        wipe(i as usize);
    }
    Ok(())
}

/// SHA-256 (no key needed).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Whether any live key slot still holds non-zero material for a destroyed key
/// (test hook: verifies zeroization).
#[doc(hidden)]
pub fn residual_material() -> bool {
    KEYS.lock(|k| k.iter().any(|s| !s.in_use && s.material.iter().any(|b| *b != 0)))
}
