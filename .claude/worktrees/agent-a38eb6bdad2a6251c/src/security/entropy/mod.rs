//! Entropy collection and per-domain cryptographic random number generators.
//!
//! ```text
//!  TRNG / sources ──► SP 800-90B health tests ──► SHA-256 conditioner ──► root DRBG
//!  (credited by assessed min-entropy; start-up test discards the first 1024 samples)
//!                                                                          │ derive
//!                       ┌──────────────────────────┬───────────────────────┤
//!                       ▼                          ▼                       ▼
//!                 domain 0 DRBG             domain 1 DRBG           domain N DRBG
//! ```
//!
//! * The system is **unseeded** until at least 256 bits of credited entropy from
//!   healthy sources have been collected; until then [`fill`] returns `NotReady` (it
//!   never silently falls back to a weak seed).
//! * Each domain has its **own** ChaCha20 fast-key-erasure DRBG derived from the root,
//!   re-derived whenever the domain is (re)created or killed, so restarted domains
//!   never replay a stream. Domain generators reseed from the root every 1 MiB.
//! * A failing source stops being credited and raises a security event.
//!
//! Classification: L3 services · security: entropy and CSPRNG · safe · crypto

pub mod drbg;
pub mod health;
pub mod sources;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use self::drbg::Drbg;
use self::health::{HealthTests, STARTUP_SAMPLES};
pub use self::sources::{EntropySource, Fault, FaultySource, SimTrng, Stm32Rng};
use super::{DomainId, MAX_DOMAINS};
use crate::Error;
use crate::kernel::cell::IrqCell;

const MAX_SOURCES: usize = 4;
/// Credited bits required before the root generator is (re)seeded.
pub const SEED_BITS: u32 = 256;
/// Domain DRBGs reseed from the root after this many output bytes.
const DOMAIN_RESEED_BYTES: u64 = 1 << 20;

#[derive(Copy, Clone)]
struct Src {
    src: &'static dyn EntropySource,
    health: HealthTests,
    startup_left: u32,
    healthy: bool,
    failures: u32,
}

struct Pool {
    sources: [Option<Src>; MAX_SOURCES],
    conditioner: Option<Sha256>,
    credited_bits: u32,
    root: Option<Drbg>,
    reseeds: u32,
    health_failures: u32,
}

impl Pool {
    const fn new() -> Self {
        Pool { sources: [None; MAX_SOURCES], conditioner: None, credited_bits: 0, root: None, reseeds: 0, health_failures: 0 }
    }
}

static POOL: IrqCell<Pool> = IrqCell::new(Pool::new());
static DOMAIN_RNG: IrqCell<[Option<Drbg>; MAX_DOMAINS]> = IrqCell::new([const { None }; MAX_DOMAINS]);

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    POOL.lock(|p| *p = Pool::new());
    DOMAIN_RNG.lock(|d| *d = [const { None }; MAX_DOMAINS]);
}

/// Register an entropy source (kernel domain only).
pub fn add_source(src: &'static dyn EntropySource) -> Result<(), Error> {
    if !super::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    let h = src.min_entropy_bits().clamp(1, 8) as u32;
    POOL.lock(|p| {
        let slot = p.sources.iter_mut().find(|s| s.is_none()).ok_or(Error::NoResources)?;
        *slot = Some(Src { src, health: HealthTests::new(h), startup_left: STARTUP_SAMPLES, healthy: true, failures: 0 });
        Ok(())
    })
}

/// Mix uncredited material (device-unique IDs, boot counters, timestamps, SRAM noise).
/// It strengthens the pool but never counts towards seeding.
pub fn mix(data: &[u8]) {
    POOL.lock(|p| p.conditioner.get_or_insert_with(Sha256::new).update(data));
}

/// Pull samples from every healthy source, run health tests, condition, and (re)seed
/// the root once enough entropy has been credited. Returns whether the system is seeded.
pub fn collect() -> bool {
    for i in 0..MAX_SOURCES {
        let Some(src) = POOL.lock(|p| p.sources[i].filter(|s| s.healthy).map(|s| s.src)) else { continue };
        let mut buf = [0u8; 64];
        let n = match src.read(&mut buf) {
            Ok(n) => n,
            Err(_) => {
                fail_source(i);
                continue;
            }
        };
        let ok = POOL.lock(|p| {
            let Some(s) = p.sources[i].as_mut() else { return true };
            let mut credited = 0u32;
            let h = s.src.min_entropy_bits() as u32;
            for &b in &buf[..n] {
                if s.health.feed(b).is_err() {
                    return false;
                }
                if s.startup_left > 0 {
                    s.startup_left -= 1; // start-up samples are tested, then discarded
                } else {
                    credited += h.min(8);
                    p.conditioner.get_or_insert_with(Sha256::new).update([b]);
                }
            }
            p.credited_bits = p.credited_bits.saturating_add(credited);
            true
        });
        if !ok {
            fail_source(i);
        }
        buf.zeroize();
    }
    POOL.lock(|p| {
        if p.credited_bits >= SEED_BITS {
            let mut seed: [u8; 32] = p.conditioner.take().unwrap_or_default().finalize().into();
            match p.root.as_mut() {
                Some(r) => r.reseed(&seed),
                None => p.root = Some(Drbg::from_seed(&seed)),
            }
            seed.zeroize();
            p.credited_bits = 0;
            p.reseeds += 1;
        }
        p.root.is_some()
    })
}

fn fail_source(i: usize) {
    POOL.lock(|p| {
        if let Some(s) = p.sources[i].as_mut() {
            s.healthy = false;
            s.failures += 1;
        }
        p.health_failures += 1;
    });
}

/// Whether the root generator has been seeded from healthy credited entropy.
pub fn is_seeded() -> bool {
    POOL.lock(|p| p.root.is_some())
}

/// Entropy subsystem status, for diagnostics and attestation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub seeded: bool,
    pub healthy_sources: u8,
    pub health_failures: u32,
    pub root_reseeds: u32,
}

pub fn status() -> Status {
    POOL.lock(|p| Status {
        seeded: p.root.is_some(),
        healthy_sources: p.sources.iter().flatten().filter(|s| s.healthy).count() as u8,
        health_failures: p.health_failures,
        root_reseeds: p.reseeds,
    })
}

/// Collect until seeded or `rounds` collection rounds have run.
pub fn seed(rounds: usize) -> Result<(), Error> {
    for _ in 0..rounds {
        if collect() {
            return Ok(());
        }
    }
    Err(Error::NotReady)
}

/// Draw from the root generator (kernel-internal).
fn root_draw(out: &mut [u8]) -> Result<(), Error> {
    POOL.lock(|p| p.root.as_mut().map(|r| r.generate(out)).ok_or(Error::NotReady))
}

/// A domain was created, killed or restarted: its generator will be re-derived from the
/// root on next use, so no output stream is ever replayed.
pub(crate) fn domain_created(d: DomainId) {
    DOMAIN_RNG.lock(|t| t[d.0 as usize] = None);
}

fn derive_domain(d: DomainId) -> Result<Drbg, Error> {
    let mut fresh = [0u8; 32];
    root_draw(&mut fresh)?;
    let mut h = Sha256::new();
    h.update(b"bismuth/drbg/v1");
    h.update([d.0]);
    h.update(super::domain_generation(d).to_le_bytes());
    h.update(fresh);
    fresh.zeroize();
    let mut seed: [u8; 32] = h.finalize().into();
    let drbg = Drbg::from_seed(&seed);
    seed.zeroize();
    Ok(drbg)
}

/// Fill `buf` with cryptographically secure random bytes from the **calling domain's**
/// generator. Fails with `NotReady` until the system has been seeded.
pub fn fill(buf: &mut [u8]) -> Result<(), Error> {
    fill_for(super::current(), buf)
}

pub(crate) fn fill_for(d: DomainId, buf: &mut [u8]) -> Result<(), Error> {
    if !is_seeded() && !collect() {
        return Err(Error::NotReady);
    }
    let i = d.0 as usize;
    if i >= MAX_DOMAINS {
        return Err(Error::Invalid);
    }
    let need_derive = DOMAIN_RNG.lock(|t| t[i].as_ref().is_none_or(|g| g.since_reseed >= DOMAIN_RESEED_BYTES));
    if need_derive {
        let mut g = derive_domain(d)?;
        DOMAIN_RNG.lock(|t| {
            if let Some(old) = t[i].as_mut() {
                // Keep continuity but fold in fresh root output.
                let mut extra = [0u8; 32];
                g.generate(&mut extra);
                old.reseed(&extra);
                extra.zeroize();
            } else {
                t[i] = Some(g);
            }
        });
    }
    // Generate in bounded chunks to keep interrupt-masked sections short.
    for chunk in buf.chunks_mut(256) {
        DOMAIN_RNG.lock(|t| t[i].as_mut().map(|g| g.generate(chunk)).ok_or(Error::NotReady))?;
    }
    Ok(())
}

/// `rand_core` RNG backed by the calling domain's generator, so ecosystem crates
/// (`rand`, key generation in RustCrypto, UUIDs, ...) work unmodified.
#[derive(Copy, Clone, Debug, Default)]
pub struct DomainRng;

impl rand_core::RngCore for DomainRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill(dest).expect("entropy not seeded");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill(dest).map_err(|_| {
            rand_core::Error::from(core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap())
        })
    }
}

impl rand_core::CryptoRng for DomainRng {}
