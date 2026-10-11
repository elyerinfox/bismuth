//! Inter-task synchronization and communication.
//!
//! All primitives are `const`-constructible so they can live in `static`s, never
//! allocate, and wake waiters in priority order (FIFO among equal priorities).
//!
//! Classification: L1 kernel · synchronization · safe · always

mod condvar;
mod event;
mod mutex;
mod queue;
mod semaphore;

pub use crate::kernel::cell::{IrqCell, TaskCell, TaskRef};
pub use condvar::CondVar;
pub use event::{EventFlags, WaitMode};
pub use mutex::{Mutex, MutexGuard, RawMutex};
pub use queue::{Queue, SendError};
pub use semaphore::Semaphore;
