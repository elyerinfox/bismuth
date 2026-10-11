//! Compatibility layers: the same kernel and drivers, exposed through familiar APIs.
//!
//! * [`posix`] — pthreads, semaphores, message queues, clocks and file descriptors
//!   on `/dev/*` devices (optionally exported under the real C symbol names).
//! * [`hal`] — adapters in both directions between Bismuth devices and the
//!   `embedded-hal` / `embedded-io` ecosystems.
//! * [`freertos`] — FreeRTOS-flavoured task/queue/semaphore API for porting code.
//!
//! Classification: L4 personalities · compatibility layers · safe · always

pub mod errno;
#[cfg(feature = "freertos-compat")]
pub mod freertos;
#[cfg(feature = "hal-compat")]
pub mod hal;
#[cfg(feature = "posix")]
pub mod posix;
