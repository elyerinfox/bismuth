//! # Bismuth
//!
//! A modular, lightweight real-time kernel for edge-computing IoT devices.
//!
//! * **RTOS core**: fixed-priority preemptive scheduler with O(1) task selection,
//!   round-robin time slicing, priority-inheritance mutexes, semaphores, condition
//!   variables, message queues, event flags, task notifications, software timers and
//!   fixed-block memory pools. No heap; every table is statically sized ([`config`]).
//! * **Driver framework**: every device is a [`driver::Driver`] whose I/O flows through
//!   a chain of [`driver::Middleware`] layers (global → per-device → driver-provided).
//! * **Networking**: FreeBSD iflib/netmap and Linux NAPI ideas sized for MCUs, with an
//!   IP stack (smoltcp) and sockets.
//! * **Security**: domains with handles and rights, entropy with health tests,
//!   per-domain CSPRNGs and a keystore over vetted RustCrypto primitives.
//! * **Compatibility layers**: POSIX, FreeRTOS and `embedded-hal`/`embedded-io`.
//! * **Ports**: Cortex-M (ARMv7-M / ARMv8-M Mainline) and a deterministic host simulator.
//!
//! ## Module map
//!
//! Modules are organised in layers; a layer only depends on the layers below it.
//!
//! | layer | module | category | feature |
//! |-------|--------|----------|---------|
//! | 0 · port | [`arch`] | CPU ports, MMIO (trusted computing base) | always |
//! | 1 · kernel | [`kernel`] | scheduler, tasks, time, timers, memory pools, cells | always |
//! | 1 · kernel | [`sync`] | mutex, semaphore, condvar, queue, event flags | always |
//! | 2 · devices | [`driver`] | driver model, middleware, device classes, drivers | always |
//! | 2 · devices | [`accel`] | hardware offload with software fallback | always |
//! | 2 · devices | [`console`] | kernel log output (`kprintln!`) | always |
//! | 3 · services | [`security`] | domains, rights, policy; entropy + keystore (`crypto`) | always / `crypto` |
//! | 3 · services | `net` | packet buffers, net core, hooks, rings, IP, sockets | `net`, `net-ip` |
//! | 3 · services | `edge` | edge-compute stages and pipelines | `edge` |
//! | 4 · personalities | [`compat`] | POSIX, FreeRTOS, embedded-hal / embedded-io | `posix`, `freertos-compat`, `hal-compat` |
//! | 4 · personalities | [`user`] | system-call client for hardware-isolated tasks | always |
//! | support | [`config`], [`Error`], `sim` | configuration, errors, host simulator | always / host |
//!
//! Every source file carries a `Classification:` line stating its layer, category,
//! safety status and feature gate; `tests/structure.rs` enforces it, together with the
//! trusted-computing-base allow-list below.
//!
//! ## Safety
//!
//! The crate is `#![deny(unsafe_code)]`. `unsafe` is permitted only in the trusted
//! computing base: `arch::cortex_m` (assembly), `arch::mmio` (volatile registers),
//! `kernel::cell` (the shared-state cells), `kernel::stack` (raw stack memory) and
//! `kernel::usermem` (validated user buffers at the syscall boundary).
//!
//! Classification: support · crate root · safe · always
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

// The opt-in bounded heap (see `kernel::heap`) makes the `alloc` crate available to subsystems
// that need it; the core kernel never uses it (so it may be unused until such a subsystem,
// e.g. a Wasm container, is also enabled).
#[cfg(feature = "heap")]
#[allow(unused_extern_crates)]
extern crate alloc;

// ----- layer 0: ports -----
pub mod arch;

// ----- layer 1: kernel -----
pub mod kernel;
pub mod sync;

// ----- layer 2: devices -----
pub mod accel;
pub mod console;
pub mod driver;

// ----- layer 3: services -----
#[cfg(feature = "edge")]
pub mod edge;
#[cfg(feature = "extensions")]
pub mod ext;
#[cfg(feature = "fs")]
pub mod fs;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "power")]
pub mod power;
pub mod security;

// ----- layer 4: personalities -----
pub mod compat;
#[cfg(feature = "shell")]
pub mod shell;
pub mod user;

// ----- support -----
pub mod config;
mod error;
#[cfg(not(target_os = "none"))]
pub mod sim;

pub use error::Error;
pub use kernel::TaskState;
pub use kernel::stack::{Stack, StackRef, UserStack1K, UserStack2K, UserStack4K};
pub use kernel::task::{self, TaskId};
pub use kernel::time::{self, Instant, Timeout};
pub use kernel::{mem, timer};

/// Start the scheduler. Never returns.
///
/// `core_hz` is the frequency of the clock feeding the system tick timer.
#[cfg(target_os = "none")]
pub fn start(core_hz: u32) -> ! {
    arch::port::start(core_hz)
}

/// Common imports for applications.
pub mod prelude {
    pub use crate::driver::{self, Device, Driver, Middleware};
    pub use crate::kernel::task::{self, TaskId};
    pub use crate::kernel::time::{self, Timeout};
    pub use crate::security::DeviceCap;
    pub use crate::sync::{CondVar, EventFlags, Mutex, Queue, Semaphore};
    pub use crate::{Error, Stack, kprintln};
}
