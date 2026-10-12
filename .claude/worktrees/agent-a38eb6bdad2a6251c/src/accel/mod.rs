//! Hardware offload with software fallback.
//!
//! Many edge MCUs carry fixed-function engines: CRC units, DMA controllers, DSP/MAC
//! accelerators. Drivers register them here; kernel services and applications call
//! the generic functions ([`crc32`], [`dot_q15`], [`copy`]) and get the accelerator
//! when one is present and healthy, or the software implementation otherwise. This is
//! the same pattern the network core uses for checksum offload.
//!
//! * **Vetted before use:** an engine is accepted only after it reproduces the software
//!   reference on known-answer vectors, so buggy silicon or drivers are rejected.
//! * **Fallback on error:** if an engine reports an error at run time, the call
//!   transparently falls back to software (and is counted).
//! * **SIMD without `unsafe`:** the software kernels are written in shapes LLVM lowers to
//!   the Cortex-M4/M7/M33 DSP extension (`SMLAD`/`SMLALD`: dual 16-bit multiply-
//!   accumulate) and to SSE/AVX on the host simulator; no intrinsics are needed.
//!
//! Classification: L2 devices · hardware offload · safe · always

use crate::Error;
use crate::kernel::cell::IrqCell;

/// A CRC-32 (IEEE 802.3, reflected, init/xorout `0xFFFF_FFFF`) engine.
pub trait CrcEngine: Sync {
    fn name(&self) -> &'static str;
    /// Continue a CRC: `state` is the running (non-inverted) register value.
    fn crc32_update(&self, state: u32, data: &[u8]) -> Result<u32, Error>;
}

/// A fixed-point multiply-accumulate engine (DSP / NPU-style).
pub trait MacEngine: Sync {
    fn name(&self) -> &'static str;
    /// `Σ a[i] * b[i]` over Q15 samples, exact (64-bit accumulator).
    fn dot_q15(&self, a: &[i16], b: &[i16]) -> Result<i64, Error>;
}

/// A memory-to-memory copy engine (DMA).
pub trait CopyEngine: Sync {
    fn name(&self) -> &'static str;
    fn copy(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error>;
}

/// Offload statistics.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub offloaded: u32,
    pub software: u32,
    pub fallbacks: u32,
    pub rejected_engines: u32,
}

struct Engines {
    crc: Option<&'static dyn CrcEngine>,
    mac: Option<&'static dyn MacEngine>,
    copy: Option<&'static dyn CopyEngine>,
    stats: Stats,
}

static ENGINES: IrqCell<Engines> =
    IrqCell::new(Engines { crc: None, mac: None, copy: None, stats: Stats { offloaded: 0, software: 0, fallbacks: 0, rejected_engines: 0 } });

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    ENGINES.lock(|e| {
        e.crc = None;
        e.mac = None;
        e.copy = None;
        e.stats = Stats::default();
    });
}

pub fn stats() -> Stats {
    ENGINES.lock(|e| e.stats)
}

fn reject() -> Error {
    ENGINES.lock(|e| e.stats.rejected_engines += 1);
    Error::Integrity
}

fn require_kernel() -> Result<(), Error> {
    if crate::security::current_is_trusted() { Ok(()) } else { Err(Error::PermissionDenied) }
}

// ----- CRC-32 -----

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// Software CRC-32 register update (table-driven).
pub fn crc32_update_sw(mut state: u32, data: &[u8]) -> u32 {
    for &b in data {
        state = CRC_TABLE[((state ^ b as u32) & 0xFF) as usize] ^ (state >> 8);
    }
    state
}

/// CRC-32 of `data` (offloaded when a healthy engine is registered).
pub fn crc32(data: &[u8]) -> u32 {
    let engine = ENGINES.lock(|e| e.crc);
    if let Some(e) = engine {
        if let Ok(v) = e.crc32_update(0xFFFF_FFFF, data) {
            ENGINES.lock(|x| x.stats.offloaded += 1);
            return !v;
        }
        ENGINES.lock(|x| x.stats.fallbacks += 1);
    } else {
        ENGINES.lock(|x| x.stats.software += 1);
    }
    !crc32_update_sw(0xFFFF_FFFF, data)
}

/// Register a CRC engine after verifying it against the software reference.
pub fn register_crc(engine: &'static dyn CrcEngine) -> Result<(), Error> {
    require_kernel()?;
    let vectors: [&[u8]; 3] = [b"", b"123456789", &[0xA5; 61]];
    for v in vectors {
        if engine.crc32_update(0xFFFF_FFFF, v) != Ok(crc32_update_sw(0xFFFF_FFFF, v)) {
            return Err(reject());
        }
    }
    ENGINES.lock(|e| e.crc = Some(engine));
    Ok(())
}

// ----- fixed-point dot product -----

/// Software Q15 dot product. Products of sign-extended 16-bit pairs are accumulated two
/// at a time into a 64-bit accumulator: the dual-MAC (`SMLALD`) shape of Cortex-M DSP
/// cores, and exact for every input (no intermediate overflow).
pub fn dot_q15_sw(a: &[i16], b: &[i16]) -> i64 {
    let n = a.len().min(b.len());
    let (a, b) = (&a[..n], &b[..n]);
    let mut acc: i64 = 0;
    let mut ca = a.chunks_exact(2);
    let mut cb = b.chunks_exact(2);
    for (x, y) in (&mut ca).zip(&mut cb) {
        // Each 16x16 product fits in 32 bits, but the pair sum can exceed i32 for
        // (-32768)² + (-32768)², so the pair is accumulated in 64 bits.
        acc += x[0] as i64 * y[0] as i64 + x[1] as i64 * y[1] as i64;
    }
    for (x, y) in ca.remainder().iter().zip(cb.remainder()) {
        acc += *x as i64 * *y as i64;
    }
    acc
}

/// `Σ a[i] * b[i]` (offloaded when a healthy MAC engine is registered).
pub fn dot_q15(a: &[i16], b: &[i16]) -> i64 {
    let engine = ENGINES.lock(|e| e.mac);
    if let Some(e) = engine {
        if let Ok(v) = e.dot_q15(a, b) {
            ENGINES.lock(|x| x.stats.offloaded += 1);
            return v;
        }
        ENGINES.lock(|x| x.stats.fallbacks += 1);
    } else {
        ENGINES.lock(|x| x.stats.software += 1);
    }
    dot_q15_sw(a, b)
}

/// Register a MAC engine after verifying it on known vectors, including extremes.
pub fn register_mac(engine: &'static dyn MacEngine) -> Result<(), Error> {
    require_kernel()?;
    let ramp: [i16; 17] = core::array::from_fn(|i| (i as i16 - 8) * 4001);
    let extreme = [i16::MIN; 9];
    for (a, b) in [(&ramp[..], &ramp[..]), (&extreme[..], &extreme[..]), (&ramp[..9], &extreme[..])] {
        if engine.dot_q15(a, b) != Ok(dot_q15_sw(a, b)) {
            return Err(reject());
        }
    }
    ENGINES.lock(|e| e.mac = Some(engine));
    Ok(())
}

// ----- copy -----

/// Copy `src` into `dst` (lengths must match), via DMA when available.
pub fn copy(dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
    if dst.len() != src.len() {
        return Err(Error::Invalid);
    }
    let engine = ENGINES.lock(|e| e.copy);
    if let Some(e) = engine {
        if e.copy(dst, src).is_ok() && dst == src {
            ENGINES.lock(|x| x.stats.offloaded += 1);
            return Ok(());
        }
        ENGINES.lock(|x| x.stats.fallbacks += 1);
    } else {
        ENGINES.lock(|x| x.stats.software += 1);
    }
    dst.copy_from_slice(src);
    Ok(())
}

pub fn register_copy(engine: &'static dyn CopyEngine) -> Result<(), Error> {
    require_kernel()?;
    let src: [u8; 37] = core::array::from_fn(|i| i as u8 ^ 0x5A);
    let mut dst = [0u8; 37];
    if engine.copy(&mut dst, &src).is_err() || dst != src {
        return Err(reject());
    }
    ENGINES.lock(|e| e.copy = Some(engine));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        // The standard CRC-32 check value for "123456789".
        assert_eq!(!crc32_update_sw(0xFFFF_FFFF, b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn dot_product_matches_naive() {
        let a: [i16; 33] = core::array::from_fn(|i| (i as i16 * 997) ^ 0x1234);
        let b: [i16; 33] = core::array::from_fn(|i| (i as i16 * -313) | 7);
        let naive: i64 = a.iter().zip(&b).map(|(x, y)| *x as i64 * *y as i64).sum();
        assert_eq!(dot_q15_sw(&a, &b), naive);
        assert_eq!(dot_q15_sw(&[i16::MIN; 2], &[i16::MIN; 2]), 2 * (1i64 << 30));
    }
}
