# Edge compute and hardware offload

Source: `src/edge/mod.rs`, `src/edge/dsp.rs` (feature `edge`), `src/accel/mod.rs`
(always built). Tests: `tests/edge.rs`.

The goal is to process sensor data on the device and transmit only what matters. Raw
samples flow through middleware (calibration, deadband) and then through fixed-point
DSP stages. Only the results are published to other tasks, and eventually to the
network.

```text
 sensor driver ─► driver middleware (calibrate) ─► user middleware (deadband, …)
                                                          │ DeviceCap::read (rights-checked)
                                         run_pipeline: sleep_until(period) → read → Stage chain
                                                          │ Some(y)
                                                     Topic<Sample, S, D>::publish
                                                  ┌───────┴────────┐
                                             Subscriber        Subscriber   (uplink, logger, …)
```

## DSP stages (`edge::dsp`)

All arithmetic is integer: Q15 or Q14 coefficients, with 64-bit or 128-bit accumulators.
That makes it exact and deterministic across targets, fast on cores without an FPU, and
a good fit for the Cortex-M DSP extension. Every stage implements:

```rust
pub trait Stage {
    fn process(&mut self, x: i32) -> Option<i32>;      // zero or one output per input
    fn then<B: Stage>(self, next: B) -> Chain<Self, B>; // compose
}
```

| stage | constructor | behaviour |
|-------|-------------|-----------|
| `Fir<T>` | `Fir::new([i16; T])` (`taps[0]` multiplies the newest sample), `Fir::moving_average()` | Input is saturated to Q15. Output is `Σ taps·window >> 15`. It keeps a mirrored ring so the window is contiguous, which lets the convolution run as **one `accel::dot_q15`** call (offloadable). |
| `Biquad` | `Biquad::new([b0, b1, b2], [a1, a2])`, Q14, `a0 = 1` | second-order IIR, direct form I |
| `Ema` | `Ema::new(alpha_q16)` (65536 = 1.0) | `y += (x − y)·α`; the first sample initialises `y` |
| `Decimate<N>` | `Decimate::<N>::default()` | outputs every N-th sample |
| `ZScore` | `ZScore::new(k, warmup)` | After `warmup` samples, passes a sample through only if `(x − mean)² > k²·variance`. Anomalies are not added to the baseline. This is *report by exception*. |
| `Rms<N>` | `Rms::<N>::default()` | RMS over non-overlapping windows of N samples (vibration energy); one output per window |
| `RunningStats` | `RunningStats::new()` | helper, not a stage: exact mean and population variance from 128-bit sums |

Helpers: `sat_q15(i64) -> i16` and `isqrt(u128) -> u128`.

## Pipelines and topics (`edge`)

- **`Topic<T: Copy, S, D>`** is publish/subscribe with up to `S` subscribers. Each
  subscriber has its own queue of depth `D`.
  - `subscribe()` returns a `Subscriber`, or `NoResources` when the topic is full.
    Dropping the subscriber unsubscribes it.
  - `publish(v)` **never blocks**. It returns how many subscribers received the value.
    A subscriber whose queue is full misses the sample; `dropped()` counts the misses.
  - `Subscriber::recv(timeout)` waits for the next value.
  - `published()` counts all publishes.
- **`Sample { tick, value }`** is the value type that pipelines publish.
- **`run_pipeline(cap: DeviceCap, period_ticks, iterations: Option<u32>, &mut stages,
  &topic) -> PipelineStats`** runs the periodic sense → process → publish loop:
  - The sampling rate is fixed and does not drift (`sleep_until`).
  - It reads channel 0 through a `DeviceCap`, so the device's middleware chain and the
    caller's rights both apply. That means the loop works unchanged in an isolated
    domain.
  - `Ok(0)` reads, meaning the middleware suppressed the sample (for example a
    deadband), are skipped.
  - `PipelineStats` reports `samples`, `published` and `read_errors`.

Example, from `tests/edge.rs`, running inside an isolated `analytics` domain that holds
only `READ` on the sensor:

```rust
static ANOMALIES: Topic<Sample, 2, 8> = Topic::new();

let cap = DeviceCap::open("vib")?;
let mut stages = Fir::<4>::moving_average().then(ZScore::new(4, 32));
let stats = run_pipeline(cap, 10, Some(120), &mut stages, &ANOMALIES);
```

## Hardware offload (`accel`)

Many edge MCUs have fixed-function engines: CRC units, DMA controllers, and DSP or MAC
accelerators. `accel` offers generic functions that use an engine when a healthy one is
registered, and software otherwise. This is the same pattern the network core uses for
checksum offload.

| function | engine trait | software reference |
|----------|--------------|--------------------|
| `crc32(data) -> u32` (IEEE 802.3, reflected, init/xorout `0xFFFF_FFFF`) | `CrcEngine::crc32_update(state, data)` | `crc32_update_sw` (table-driven) |
| `dot_q15(a, b) -> i64` (exact, 64-bit accumulator) | `MacEngine::dot_q15(a, b)` | `dot_q15_sw`, written in the dual-MAC (`SMLALD`) shape |
| `copy(dst, src)` (equal lengths, else `Invalid`) | `CopyEngine::copy(dst, src)` | `copy_from_slice` |

- **Vetted before use.** `register_crc`, `register_mac` and `register_copy` are trusted
  domains only. Before accepting an engine, they run known-answer vectors against the
  software reference, including extremes such as `i16::MIN` products for the MAC. An
  engine that disagrees is rejected with `Integrity` and counted in
  `rejected_engines`. This catches buggy silicon and buggy drivers.
- **Fallback on error.** If an engine returns `Err` at run time, the call quietly falls
  back to software and counts a fallback. `copy` also checks `dst == src` after a
  hardware copy.
- **Statistics.** `accel::stats()` returns `Stats { offloaded, software, fallbacks,
  rejected_engines }`.
- One engine of each kind can be registered at a time; registering again replaces it.
- **SIMD without `unsafe`.** There are no SIMD intrinsics, by design: intrinsics would
  need `unsafe`, which the safe-Rust rule forbids outside the TCB. Instead, the
  software kernels are written in shapes that LLVM lowers to the Cortex-M4/M7/M33 DSP
  extension (`SMLAD`/`SMLALD`) and to SSE/AVX on the host.

## Status

The pieces described here are built and tested in `tests/edge.rs`, which covers engine
vetting and fallback, and an isolated anomaly pipeline using a MAC engine. No real
hardware engine driver ships yet (STM32 CRC unit, DMA): **Planned**. Neither do
network publishers that send `Topic` samples upstream: **Planned**.
