//! Architecture ports.
//!
//! A port provides a small, fixed surface to the portable kernel:
//!
//! | function           | purpose                                                         |
//! |--------------------|-----------------------------------------------------------------|
//! | `critical(f)`      | run `f` with interrupts masked (nestable)                       |
//! | `request_switch()` | pend a context switch that fires when the critical section ends |
//! | `in_isr()`         | whether we are in interrupt context                             |
//! | `init_task(k, i)`  | build the initial execution context for task `i`                |
//! | `exit_current(c)`  | terminate the running task                                      |
//! | `idle()`           | idle-task body (sleep the CPU)                                  |
//! | `sleep_until(d)`   | tickless light sleep until kernel-tick `d` or an interrupt (`target_os = "none"`) |
//!
//! Adding a new architecture means implementing these functions in a new module.
//!
//! Classification: L0 port · port interface · safe · always

pub mod mmio;

#[cfg(all(target_arch = "arm", target_os = "none", not(feature = "cortex-a")))]
pub mod cortex_m;
#[cfg(all(target_arch = "arm", target_os = "none", not(feature = "cortex-a")))]
pub use cortex_m as port;

#[cfg(all(target_arch = "arm", target_os = "none", feature = "cortex-a"))]
pub mod cortex_a;
#[cfg(all(target_arch = "arm", target_os = "none", feature = "cortex-a"))]
pub use cortex_a as port;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod x86_64;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use x86_64 as port;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod aarch64;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use aarch64 as port;

#[cfg(not(target_os = "none"))]
pub mod host;
#[cfg(not(target_os = "none"))]
pub use host as port;

#[cfg(all(target_os = "none", not(target_arch = "arm"), not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
compile_error!("bismuth: no port for this architecture yet (supported: Cortex-M3/M4/M7/M33, x86-64, aarch64 Cortex-A, host simulator)");
