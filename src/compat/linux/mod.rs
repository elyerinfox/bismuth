//! A Linux-ABI personality (`linux-abi` feature): the beginning of running Linux `aarch64`
//! executables — the path toward hosting real OCI/Linux container images rather than only the
//! WASM model. This is a large, staged subsystem; the pieces land green one at a time:
//!
//! 1. **ELF loading** ([`elf`]) — parse a static `aarch64` ELF's `PT_LOAD` segments and entry
//!    point (done, host-tested).
//! 2. executable user mapping — map a loaded image's segments EL0-RX/RW at their virtual
//!    addresses (the port's MMU step; pending).
//! 3. the Linux syscall surface — interpret `svc` with Linux `aarch64` numbers (`write`, `exit`,
//!    `brk`, …) against Bismuth services (pending).
//! 4. process start — enter the entry at EL0 with a Linux initial stack (argv/envp/auxv; pending).
//!
//! Classification: L4 personalities · linux ABI · safe · linux-abi

pub mod elf;
pub mod stack;
pub mod syscall;
