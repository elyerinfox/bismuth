//! A Linux-ABI personality (`linux-abi` feature): the beginning of running Linux `aarch64`
//! executables — the path toward hosting real OCI/Linux container images rather than only the
//! WASM model. This is a large, staged subsystem; the pieces land green one at a time:
//!
//! 1. **ELF loading** ([`elf`]) — parse a static `aarch64` ELF's `PT_LOAD` segments and entry
//!    point.
//! 2. **the initial stack** ([`stack`]) — lay out the SysV `argc`/`argv`/`envp`/`auxv` block.
//! 3. **the syscall surface** ([`syscall`]) — interpret `svc` with Linux `aarch64` numbers
//!    (`write`/`writev`/`read`/`exit`/`brk`/…) against Bismuth services.
//! 4. **load + run** ([`load`]) — copy the image into an EL0-exec buffer, open its pages, build
//!    the stack, and enter the entry at EL0 as a confined task whose `svc` traps route here.
//!
//! All four land green and are demonstrated end-to-end on QEMU `virt` (the board's `linux-demo`
//! flow runs a hand-assembled ELF that does `write`+`exit`). Still a preview: one image at a
//! time, a static binary (no dynamic linking), and only the start-up syscall subset.
//!
//! Classification: L4 personalities · linux ABI · safe · linux-abi

pub mod elf;
pub mod load;
pub mod stack;
pub mod syscall;
