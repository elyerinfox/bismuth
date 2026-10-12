//! Fixed-point signal processing stages for edge analytics.
//!
//! Integer arithmetic throughout (Q15 coefficients/samples, 64-bit accumulators): it is
//! exact, deterministic across targets, fast on FPU-less cores, and maps onto the
//! Cortex-M DSP extension. Every stage implements [`Stage`], so stages compose into
//! pipelines.
//!
//! Classification: L3 services · edge: DSP stages · safe · edge

use crate::accel;

/// A streaming processing stage: one input sample in, zero or one output sample out.
pub trait Stage {
    fn process(&mut self, x: i32) -> Option<i32>;

    /// Chain another stage after this one.
    fn then<B: Stage>(self, next: B) -> Chain<Self, B>
    where
        Self: Sized,
    {
        Chain { a: self, b: next }
    }
}

/// Two stages in sequence (built with [`Stage::then`]).
#[derive(Clone, Debug)]
pub struct Chain<A, B> {
    a: A,
    b: B,
}

impl<A: Stage, B: Stage> Stage for Chain<A, B> {
    fn process(&mut self, x: i32) -> Option<i32> {
        self.a.process(x).and_then(|y| self.b.process(y))
    }
}

/// Saturate to the Q15 range.
pub const fn sat_q15(x: i64) -> i16 {
    if x > i16::MAX as i64 {
        i16::MAX
    } else if x < i16::MIN as i64 {
        i16::MIN
    } else {
        x as i16
    }
}

/// FIR filter with `T` Q15 taps. The history is kept twice (a mirrored ring), so the
/// current window is always one contiguous slice and the convolution is a single dot
/// product, which [`accel::dot_q15`] can offload to a MAC engine.
#[derive(Clone, Debug)]
pub struct Fir<const T: usize> {
    taps: [i16; T],
    hist: [[i16; T]; 2],
    pos: usize,
}

impl<const T: usize> Fir<T> {
    /// `taps[0]` multiplies the newest sample.
    pub const fn new(taps: [i16; T]) -> Self {
        // Store taps reversed so the window (oldest → newest) lines up with them.
        let mut rev = [0i16; T];
        let mut i = 0;
        while i < T {
            rev[i] = taps[T - 1 - i];
            i += 1;
        }
        Fir { taps: rev, hist: [[0; T]; 2], pos: 0 }
    }

    /// Moving-average taps (1/T each, rounded).
    pub const fn moving_average() -> Self {
        Self::new([(32768 / T) as i16; T])
    }

    fn window(&self) -> [i16; T] {
        // Oldest → newest, assembled from the mirrored halves.
        let mut w = [0i16; T];
        let mut i = 0;
        while i < T {
            let idx = (self.pos + i) % T;
            w[i] = self.hist[0][idx];
            i += 1;
        }
        w
    }
}

impl<const T: usize> Stage for Fir<T> {
    fn process(&mut self, x: i32) -> Option<i32> {
        let s = sat_q15(x as i64);
        self.hist[0][self.pos] = s;
        self.hist[1][self.pos] = s;
        self.pos = (self.pos + 1) % T;
        let w = self.window();
        Some((accel::dot_q15(&w, &self.taps) >> 15) as i32)
    }
}

/// Second-order IIR section (biquad), direct form I, Q14 coefficients
/// (`b0 b1 b2 a1 a2`, with `a0 = 1`).
#[derive(Clone, Debug)]
pub struct Biquad {
    b: [i32; 3],
    a: [i32; 2],
    x: [i32; 2],
    y: [i32; 2],
}

impl Biquad {
    pub const fn new(b: [i32; 3], a: [i32; 2]) -> Self {
        Biquad { b, a, x: [0; 2], y: [0; 2] }
    }
}

impl Stage for Biquad {
    fn process(&mut self, x: i32) -> Option<i32> {
        let acc = self.b[0] as i64 * x as i64 + self.b[1] as i64 * self.x[0] as i64 + self.b[2] as i64 * self.x[1] as i64
            - self.a[0] as i64 * self.y[0] as i64
            - self.a[1] as i64 * self.y[1] as i64;
        let y = (acc >> 14) as i32;
        self.x = [x, self.x[0]];
        self.y = [y, self.y[0]];
        Some(y)
    }
}

/// Exponential moving average: `y += (x - y) * alpha`, alpha in Q16 (65536 = 1.0).
#[derive(Clone, Debug)]
pub struct Ema {
    alpha_q16: i64,
    y: Option<i64>,
}

impl Ema {
    pub const fn new(alpha_q16: u32) -> Self {
        Ema { alpha_q16: alpha_q16 as i64, y: None }
    }
}

impl Stage for Ema {
    fn process(&mut self, x: i32) -> Option<i32> {
        let x = (x as i64) << 16;
        let y = match self.y {
            None => x,
            Some(y) => y + (((x - y) * self.alpha_q16) >> 16),
        };
        self.y = Some(y);
        Some((y >> 16) as i32)
    }
}

/// Keep one of every `N` samples.
#[derive(Clone, Debug, Default)]
pub struct Decimate<const N: usize> {
    n: usize,
}

impl<const N: usize> Stage for Decimate<N> {
    fn process(&mut self, x: i32) -> Option<i32> {
        self.n += 1;
        if self.n >= N {
            self.n = 0;
            Some(x)
        } else {
            None
        }
    }
}

/// Running mean and variance, exact: 128-bit sum and sum of squares (no drift from
/// repeated rounding, unlike an integer Welford update).
#[derive(Clone, Debug, Default)]
pub struct RunningStats {
    n: u64,
    sum: i128,
    sum_sq: i128,
}

/// Round-to-nearest signed division.
fn div_round(a: i128, b: i128) -> i128 {
    if (a < 0) == (b < 0) { (a + b / 2) / b } else { (a - b / 2) / b }
}

impl RunningStats {
    pub const fn new() -> Self {
        RunningStats { n: 0, sum: 0, sum_sq: 0 }
    }

    pub fn push(&mut self, x: i32) {
        self.n += 1;
        self.sum += x as i128;
        self.sum_sq += x as i128 * x as i128;
    }

    pub fn count(&self) -> u64 {
        self.n
    }

    /// Mean, rounded to the nearest integer.
    pub fn mean(&self) -> i32 {
        if self.n == 0 { 0 } else { div_round(self.sum, self.n as i128) as i32 }
    }

    /// Population variance (in input units squared), rounded.
    pub fn variance(&self) -> i64 {
        if self.n == 0 {
            return 0;
        }
        let n = self.n as i128;
        div_round(self.sum_sq * n - self.sum * self.sum, n * n) as i64
    }
}

/// Anomaly detector: passes a sample through only when it lies more than `k` standard
/// deviations from the running mean (after a warm-up), i.e. *report by exception*.
#[derive(Clone, Debug)]
pub struct ZScore {
    k: i64,
    warmup: u64,
    stats: RunningStats,
}

impl ZScore {
    pub const fn new(k: u32, warmup: u64) -> Self {
        ZScore { k: k as i64, warmup, stats: RunningStats::new() }
    }

    pub fn stats(&self) -> &RunningStats {
        &self.stats
    }
}

impl Stage for ZScore {
    fn process(&mut self, x: i32) -> Option<i32> {
        let anomalous = self.stats.count() >= self.warmup && {
            let d = (x - self.stats.mean()) as i64;
            d * d > self.k * self.k * self.stats.variance().max(1)
        };
        // Anomalies are not folded into the baseline.
        if !anomalous {
            self.stats.push(x);
        }
        anomalous.then_some(x)
    }
}

/// Root-mean-square over non-overlapping windows of `N` samples (vibration energy).
#[derive(Clone, Debug)]
pub struct Rms<const N: usize> {
    acc: i128,
    n: usize,
}

impl<const N: usize> Default for Rms<N> {
    fn default() -> Self {
        Rms { acc: 0, n: 0 }
    }
}

impl<const N: usize> Stage for Rms<N> {
    fn process(&mut self, x: i32) -> Option<i32> {
        self.acc += x as i128 * x as i128;
        self.n += 1;
        if self.n < N {
            return None;
        }
        let mean_sq = (self.acc / N as i128) as u128;
        self.acc = 0;
        self.n = 0;
        Some(isqrt(mean_sq) as i32)
    }
}

/// Integer square root (floor).
pub fn isqrt(v: u128) -> u128 {
    if v < 2 {
        return v;
    }
    let mut x = 1u128 << ((128 - v.leading_zeros()).div_ceil(2));
    loop {
        let y = (x + v / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fir_moving_average_settles() {
        let mut f = Fir::<4>::moving_average();
        let out: std::vec::Vec<i32> = [1000, 1000, 1000, 1000, 1000].iter().map(|&x| f.process(x).unwrap()).collect();
        assert_eq!(out, [250, 500, 750, 1000, 1000]);
    }

    #[test]
    fn fir_taps_order() {
        // y[n] = x[n] (newest tap = 1.0 in Q15 ≈ 32767).
        let mut f = Fir::new([32767, 0, 0]);
        assert_eq!(f.process(100), Some(99));
        assert_eq!(f.process(-50), Some(-50));
    }

    #[test]
    fn ema_and_chain() {
        let mut s = Ema::new(32768).then(Decimate::<2>::default());
        assert_eq!(s.process(100), None);
        assert_eq!(s.process(200), Some(150));
    }

    #[test]
    fn running_stats_and_zscore() {
        let mut st = RunningStats::new();
        for x in [2, 4, 4, 4, 5, 5, 7, 9] {
            st.push(x);
        }
        assert_eq!(st.mean(), 5);
        assert_eq!(st.variance(), 4);
        let mut z = ZScore::new(3, 8);
        for i in 0..100 {
            assert_eq!(z.process(1000 + (i % 5) - 2), None);
        }
        assert_eq!(z.process(1100), Some(1100));
        assert_eq!(z.process(1001), None);
    }

    #[test]
    fn rms_of_square_wave() {
        let mut r = Rms::<4>::default();
        let out: std::vec::Vec<_> = [300, -300, 300, -300].iter().filter_map(|&x| r.process(x)).collect();
        assert_eq!(out, [300]);
        assert_eq!(isqrt(1 << 40), 1 << 20);
    }

    #[test]
    fn biquad_passthrough() {
        let mut b = Biquad::new([1 << 14, 0, 0], [0, 0]);
        assert_eq!(b.process(1234), Some(1234));
    }
}
