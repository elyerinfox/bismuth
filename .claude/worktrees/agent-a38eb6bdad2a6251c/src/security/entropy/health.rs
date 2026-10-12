//! NIST SP 800-90B §4.4 continuous health tests for 8-bit noise samples.
//!
//! * **Repetition Count Test (RCT):** fails when one value repeats `C` times in a row,
//!   `C = 1 + ⌈-log2(α) / H⌉`.
//! * **Adaptive Proportion Test (APT):** over windows of `W = 1024` samples, fails when
//!   the window's first value occurs at least `C` times, where `C` is the smallest count
//!   whose binomial upper tail `P[X ≥ C]` (X ~ Bin(W, 2^-H)) is at most α.
//!
//! α = 2^-30. `H` is the source's assessed min-entropy per 8-bit sample, in whole bits
//! (1..=8). Cutoffs are computed exactly at compile time.
//!
//! Classification: L3 services · security: entropy health tests · safe · crypto

/// -log2(α): false-positive probability 2^-30 per test.
pub const ALPHA_EXP: u32 = 30;
/// APT window for non-binary sources.
pub const APT_WINDOW: u32 = 1024;
/// Samples examined (and discarded) by the start-up test.
pub const STARTUP_SAMPLES: u32 = 1024;

/// RCT cutoff for min-entropy `h` bits per sample.
pub const fn rct_cutoff(h: u32) -> u32 {
    assert!(h >= 1 && h <= 8);
    1 + ALPHA_EXP.div_ceil(h)
}

/// APT cutoff for min-entropy `h` bits per sample (exact binomial tail, evaluated in
/// scaled floating point at compile time).
pub const fn apt_cutoff(h: u32) -> u32 {
    assert!(h >= 1 && h <= 8);
    const W: usize = APT_WINDOW as usize;
    let p = 1.0 / (1u32 << h) as f64;
    let ratio = p / (1.0 - p);
    let alpha = 1.0 / (1u64 << ALPHA_EXP) as f64;
    // r[k] = C(W,k) * ratio^k, scaled by 2^-64 so neither the largest term nor the sum
    // can overflow, while terms near the α-tail stay far above the subnormal range.
    let mut r = [0.0f64; W + 1];
    r[0] = 1.0 / 18446744073709551616.0; // 2^-64
    let mut total = r[0];
    let mut k = 0;
    while k < W {
        r[k + 1] = r[k] * ((W - k) as f64) / ((k + 1) as f64) * ratio;
        total += r[k + 1];
        k += 1;
    }
    // Walk down from the top until the tail mass exceeds α.
    let mut tail = 0.0;
    let mut c = W + 1;
    while c > 0 {
        tail += r[c - 1];
        if tail / total > alpha {
            return c as u32;
        }
        c -= 1;
    }
    1
}

/// Why a health test failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HealthFailure {
    Repetition,
    Proportion,
}

/// Running state of both continuous tests for one source.
#[derive(Copy, Clone, Debug)]
pub struct HealthTests {
    rct_c: u32,
    apt_c: u32,
    last: Option<u8>,
    run: u32,
    apt_first: u8,
    apt_count: u32,
    apt_seen: u32,
}

impl HealthTests {
    pub const fn new(min_entropy_bits: u32) -> Self {
        HealthTests {
            rct_c: rct_cutoff(min_entropy_bits),
            apt_c: apt_cutoff(min_entropy_bits),
            last: None,
            run: 0,
            apt_first: 0,
            apt_count: 0,
            apt_seen: 0,
        }
    }

    pub fn cutoffs(&self) -> (u32, u32) {
        (self.rct_c, self.apt_c)
    }

    /// Feed one sample through both tests.
    pub fn feed(&mut self, s: u8) -> Result<(), HealthFailure> {
        // RCT
        if self.last == Some(s) {
            self.run += 1;
            if self.run >= self.rct_c {
                return Err(HealthFailure::Repetition);
            }
        } else {
            self.last = Some(s);
            self.run = 1;
        }
        // APT
        if self.apt_seen == 0 {
            self.apt_first = s;
            self.apt_count = 1;
        } else if s == self.apt_first {
            self.apt_count += 1;
            if self.apt_count >= self.apt_c {
                return Err(HealthFailure::Proportion);
            }
        }
        self.apt_seen += 1;
        if self.apt_seen == APT_WINDOW {
            self.apt_seen = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutoffs_match_sp800_90b() {
        // RCT: C = 1 + ceil(30 / H).
        assert_eq!(rct_cutoff(1), 31);
        assert_eq!(rct_cutoff(4), 9);
        assert_eq!(rct_cutoff(8), 5);
        // APT cutoffs are monotone in H and sit far above the expected count W/2^H.
        let mut prev = u32::MAX;
        for h in 1..=8 {
            let c = apt_cutoff(h);
            let mean = APT_WINDOW >> h;
            assert!(c > mean && c < prev, "h={h} c={c}");
            prev = c;
        }
        // Sanity for a fair binary-valued symbol (H = 1): mean 512, sd 16, α = 2^-30
        // corresponds to roughly six standard deviations above the mean.
        let c1 = apt_cutoff(1);
        assert!((600..=620).contains(&c1), "c1={c1}");
    }

    #[test]
    fn stuck_source_trips_rct() {
        let mut t = HealthTests::new(4);
        let mut r = Ok(());
        for _ in 0..20 {
            r = t.feed(0x42);
            if r.is_err() {
                break;
            }
        }
        assert_eq!(r, Err(HealthFailure::Repetition));
    }

    #[test]
    fn biased_source_trips_apt() {
        let mut t = HealthTests::new(4);
        let mut x: u32 = 1;
        let mut failed = None;
        for i in 0..4096 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            // Half of all samples are 0 (far more than 1/16 for H = 4).
            let s = if i % 2 == 0 { 0 } else { (x as u8) | 1 };
            if let Err(e) = t.feed(s) {
                failed = Some(e);
                break;
            }
        }
        assert_eq!(failed, Some(HealthFailure::Proportion));
    }

    #[test]
    fn good_source_passes() {
        let mut t = HealthTests::new(4);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            assert!(t.feed((x >> 32) as u8).is_ok());
        }
    }
}
