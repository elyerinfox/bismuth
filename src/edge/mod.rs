//! Edge-compute building blocks: process sensor data on the device and publish only
//! what matters.
//!
//! * [`dsp`]: fixed-point stages (FIR, biquad, EMA, decimation, running statistics,
//!   z-score anomaly detection, RMS) that compose with [`dsp::Stage::then`].
//! * [`Topic`]: bounded publish/subscribe fan-out between tasks.
//! * [`run_pipeline`]: the periodic sense → process → publish loop for a sensor task,
//!   reading through a [`DeviceCap`] so the device's middleware chain and the caller's
//!   rights apply.
//!
//! Classification: L3 services · edge compute · safe · edge

pub mod dsp;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::Error;
use crate::kernel::cell::IrqCell;
use crate::kernel::task;
use crate::kernel::time::{self, Timeout};
use crate::security::DeviceCap;
use crate::sync::Queue;
use dsp::Stage;

/// A timestamped value flowing through a topic.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub tick: u64,
    pub value: i32,
}

/// Publish/subscribe topic with up to `S` subscribers, each with a queue of depth `D`.
/// Publishing never blocks: a subscriber that falls behind loses the sample (counted).
pub struct Topic<T, const S: usize, const D: usize> {
    queues: [Queue<T, D>; S],
    claimed: IrqCell<[bool; S]>,
    published: AtomicU32,
    dropped: AtomicU32,
}

impl<T: Copy, const S: usize, const D: usize> Default for Topic<T, S, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const S: usize, const D: usize> Topic<T, S, D> {
    pub const fn new() -> Self {
        Topic {
            queues: [const { Queue::new() }; S],
            claimed: IrqCell::new([false; S]),
            published: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
        }
    }

    pub fn subscribe(&self) -> Result<Subscriber<'_, T, S, D>, Error> {
        let i = self.claimed.lock(|c| {
            let i = c.iter().position(|x| !*x)?;
            c[i] = true;
            Some(i)
        });
        i.map(|index| Subscriber { topic: self, index }).ok_or(Error::NoResources)
    }

    /// Deliver `v` to every subscriber; returns how many received it.
    pub fn publish(&self, v: T) -> usize {
        self.published.fetch_add(1, Ordering::Relaxed);
        let claimed = self.claimed.lock(|c| *c);
        let mut n = 0;
        for (q, _) in self.queues.iter().zip(claimed).filter(|(_, c)| *c) {
            if q.try_send(v).is_ok() {
                n += 1;
            } else {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        n
    }

    pub fn published(&self) -> u32 {
        self.published.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u32 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A subscription to a [`Topic`]; unsubscribes on drop.
pub struct Subscriber<'a, T: Copy, const S: usize, const D: usize> {
    topic: &'a Topic<T, S, D>,
    index: usize,
}

impl<T: Copy, const S: usize, const D: usize> Subscriber<'_, T, S, D> {
    pub fn recv(&self, timeout: Timeout) -> Result<T, Error> {
        self.topic.queues[self.index].recv(timeout)
    }
}

impl<T: Copy, const S: usize, const D: usize> Drop for Subscriber<'_, T, S, D> {
    fn drop(&mut self) {
        while self.topic.queues[self.index].try_recv().is_ok() {}
        self.topic.claimed.lock(|c| c[self.index] = false);
    }
}

/// Pipeline statistics returned by [`run_pipeline`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PipelineStats {
    pub samples: u32,
    pub published: u32,
    pub read_errors: u32,
}

/// Periodically read channel 0 of a sensor, run it through `stages`, and publish every
/// produced value. Runs `iterations` times (or forever with `None`) at a fixed rate of
/// one sample per `period_ticks`, without drift.
pub fn run_pipeline<St: Stage, const S: usize, const D: usize>(
    sensor: DeviceCap,
    period_ticks: u64,
    iterations: Option<u32>,
    stages: &mut St,
    topic: &Topic<Sample, S, D>,
) -> PipelineStats {
    let mut st = PipelineStats::default();
    let mut last = time::ticks();
    let mut n = 0;
    while iterations.is_none_or(|it| n < it) {
        n += 1;
        task::sleep_until(&mut last, period_ticks);
        let mut raw = [0u8; 4];
        match sensor.read(&mut raw) {
            Ok(4) => {
                st.samples += 1;
                if let Some(y) = stages.process(i32::from_le_bytes(raw)) {
                    topic.publish(Sample { tick: time::ticks(), value: y });
                    st.published += 1;
                }
            }
            Ok(_) => {} // suppressed by middleware (e.g. deadband)
            Err(_) => st.read_errors += 1,
        }
    }
    st
}
