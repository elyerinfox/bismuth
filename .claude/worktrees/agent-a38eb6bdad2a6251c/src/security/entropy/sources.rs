//! Entropy sources: a hardware TRNG driver and simulator sources for testing.
//!
//! Classification: L3 services · security: entropy sources · safe · crypto

use core::sync::atomic::{AtomicU32, Ordering};

use crate::Error;
use crate::arch::mmio::Mmio;
use crate::kernel::cell::IrqCell;

/// A raw noise source producing 8-bit samples.
pub trait EntropySource: Sync {
    fn name(&self) -> &'static str;
    /// Assessed min-entropy per 8-bit sample in whole bits (1..=8), from an SP 800-90B
    /// assessment of this source on this part. 0 = mix in, but never credit.
    fn min_entropy_bits(&self) -> u8;
    /// Read raw samples; returns how many bytes were produced.
    fn read(&self, out: &mut [u8]) -> Result<usize, Error>;
}

/// STM32-family RNG peripheral (`RNG_CR` / `RNG_SR` / `RNG_DR`), used through a safe
/// [`Mmio`] window. Health is also checked in hardware (seed/clock error flags).
pub struct Stm32Rng {
    regs: Mmio,
    min_entropy_bits: u8,
}

impl Stm32Rng {
    const CR: usize = 0x0;
    const SR: usize = 0x4;
    const DR: usize = 0x8;
    const CR_RNGEN: u32 = 1 << 2;
    const SR_DRDY: u32 = 1 << 0;
    const SR_CECS: u32 = 1 << 1;
    const SR_SECS: u32 = 1 << 2;

    pub const fn new(regs: Mmio, min_entropy_bits: u8) -> Self {
        Stm32Rng { regs, min_entropy_bits }
    }

    pub fn enable(&self) {
        self.regs.modify32(Self::CR, |v| v | Self::CR_RNGEN);
    }
}

impl EntropySource for Stm32Rng {
    fn name(&self) -> &'static str {
        "stm32-rng"
    }

    fn min_entropy_bits(&self) -> u8 {
        self.min_entropy_bits
    }

    fn read(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut n = 0;
        while n < out.len() {
            let sr = self.regs.read32(Self::SR);
            if sr & (Self::SR_CECS | Self::SR_SECS) != 0 {
                return Err(Error::Io); // hardware health failure
            }
            if sr & Self::SR_DRDY == 0 {
                break;
            }
            let w = self.regs.read32(Self::DR).to_le_bytes();
            let k = (out.len() - n).min(4);
            out[n..n + k].copy_from_slice(&w[..k]);
            n += k;
        }
        Ok(n)
    }
}

/// Simulated healthy TRNG (xorshift noise). Deterministic for reproducible tests;
/// never use outside the simulator.
pub struct SimTrng {
    state: IrqCell<u64>,
    claimed: u8,
}

impl SimTrng {
    pub const fn new(seed: u64, claimed_min_entropy: u8) -> Self {
        SimTrng { state: IrqCell::new(seed | 1), claimed: claimed_min_entropy }
    }
}

impl EntropySource for SimTrng {
    fn name(&self) -> &'static str {
        "sim-trng"
    }

    fn min_entropy_bits(&self) -> u8 {
        self.claimed
    }

    fn read(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.state.lock(|x| {
            for b in out.iter_mut() {
                *x ^= *x << 13;
                *x ^= *x >> 7;
                *x ^= *x << 17;
                *b = (*x >> 24) as u8;
            }
        });
        Ok(out.len())
    }
}

/// Simulated faulty TRNG: stuck at a value, or biased towards zero.
pub struct FaultySource {
    mode: Fault,
    counter: AtomicU32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    StuckAt(u8),
    /// Every other sample is zero.
    Biased,
}

impl FaultySource {
    pub const fn new(mode: Fault) -> Self {
        FaultySource { mode, counter: AtomicU32::new(0) }
    }
}

impl EntropySource for FaultySource {
    fn name(&self) -> &'static str {
        "faulty"
    }

    fn min_entropy_bits(&self) -> u8 {
        4
    }

    fn read(&self, out: &mut [u8]) -> Result<usize, Error> {
        for b in out.iter_mut() {
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            *b = match self.mode {
                Fault::StuckAt(v) => v,
                Fault::Biased if n % 2 == 0 => 0,
                Fault::Biased => (n.wrapping_mul(2_654_435_761) >> 24) as u8 | 1,
            };
        }
        Ok(out.len())
    }
}
