# Porting Bismuth to a new board

A *board crate* is a small binary crate. It links the kernel, describes the hardware,
spawns tasks and calls `bismuth::start`. Start by copying
`boards/qemu-lm3s6965`, the reference board crate for QEMU's Cortex-M3 machine.

```text
boards/my-board/
  Cargo.toml          # depends on bismuth-kernel; standalone [workspace]
  .cargo/config.toml  # target, runner, linker script flag, optional BISMUTH_* limits
  build.rs            # puts memory.x on the linker search path
  memory.x            # FLASH / RAM layout for cortex-m-rt
  src/main.rs         # board description, devices, tasks, bismuth::start
```

## 1. Pick the target

| core | Rust target | notes |
|------|-------------|-------|
| Cortex-M3 | `thumbv7m-none-eabi` | used by the QEMU demo |
| Cortex-M4 / M7 without FPU use | `thumbv7em-none-eabi` | integer-only context frames |
| Cortex-M4F / M7 with FPU | `thumbv7em-none-eabihf` | PendSV saves `s16`–`s31` only for tasks that used the FPU (lazy stacking) |
| Cortex-M33 (ARMv8-M Mainline) | `thumbv8m.main-none-eabi[hf]` | the port targets it; not yet exercised by a board crate |
| Cortex-M0/M0+ (ARMv6-M) | n/a | **not supported**: the PendSV assembly uses ARMv7-M instructions |
| RISC-V and others | n/a | **Planned**: `src/arch/mod.rs` raises `compile_error!` for bare-metal non-ARM targets |

## 2. `Cargo.toml`

```toml
[package]
name = "bismuth-board-my-board"
version = "0.1.0"
edition = "2024"
publish = false

[workspace]          # standalone: built for the MCU target, independent of the kernel's host workspace

[dependencies]
bismuth-kernel = { path = "../..", default-features = false, features = ["edge"] }
cortex-m-rt = "0.7.5"
cortex-m-semihosting = "0.5"   # only if you want semihosting output/exit

[profile.release]
opt-level = "s"
lto = true
codegen-units = 1
debug = true
```

Choose kernel features to fit the part's RAM. `net` and `net-ip` with the MCU defaults
need roughly 45 KiB or more; see [networking](../design/networking.md#configuration-knobs).

## 3. `.cargo/config.toml`

```toml
[build]
target = "thumbv7m-none-eabi"

[target.thumbv7m-none-eabi]
runner = "probe-rs run --chip <CHIP>"      # or the QEMU command line from the reference board
rustflags = ["-C", "link-arg=-Tlink.x"]

[env]                                       # optional: size the kernel for this board
BISMUTH_MAX_TASKS = "10"
BISMUTH_POOL_STACKS = "2"
BISMUTH_TICK_HZ = "1000"
```

Every `BISMUTH_*` variable is read with `option_env!` while the kernel compiles, and
Cargo's `[env]` table reaches dependency crates. See
[configuration](../reference/configuration.md).

## 4. `build.rs` and `memory.x`

Copy them from the reference board and change the memory sizes:

```text
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 512K
  RAM   : ORIGIN = 0x20000000, LENGTH = 128K
}
```

## 5. The board description: the one `unsafe` boundary

Drivers never touch raw addresses. They receive an `arch::mmio::Mmio` window. Creating
that window is the **only** `unsafe` a board needs. It is where the board asserts:

> `base..base+len` is this peripheral's register block, valid for volatile 32-bit
> access, and not accessed through any other `Mmio` or pointer.

`Mmio::new` is a `const fn`, so the whole board description can be a `static`. Keep
`#![deny(unsafe_code)]` on the crate and allow `unsafe` on exactly this item:

```rust
#![no_std]
#![no_main]
#![deny(unsafe_code)]

use bismuth::arch::mmio::Mmio;
use bismuth::driver::{self, Device, DeviceDesc};
use bismuth::driver::FACTORIES;
use bismuth::driver::char::pl011;

/// Board description: the only place hardware addresses are asserted.
#[allow(unsafe_code)]
static BOARD: [DeviceDesc; 1] = [DeviceDesc {
    name: "uart0",
    compatible: "arm,pl011",
    // SAFETY: UART0 lives at 0x4000_C000 on this SoC and is used only via this window.
    mmio: Some(unsafe { Mmio::new(0x4000_C000, pl011::REGISTER_SPAN) }),
    irq: 5,
    params: &[("baud", 115_200)],
}];
```

`Mmio::new` panics (at compile time in a `static`) if `base` is not 4-byte aligned.
After that, every `read32`, `write32` and `modify32` checks bounds and alignment and is
safe.

If a driver for your peripheral does not exist yet, write one: see
[writing a driver](writing-a-driver.md). The bundled factories' `create` functions are
crate-private, so you cannot merge your factory into `FACTORIES`. Call `probe_all` once
per factory list instead. Descriptions that have no matching factory are skipped, so
this is safe:

```rust
driver::probe_all(&BOARD, FACTORIES);              // bundled drivers
driver::probe_all(&BOARD, &[my_driver::FACTORY]);  // your own
```

## 6. `main`

```rust
use bismuth::{Stack, kprintln, task};
use cortex_m_rt::entry;

const CORE_HZ: u32 = 64_000_000;   // the clock feeding SysTick (the processor clock)

static APP_STACK: Stack<2048> = Stack::new();

#[entry]
fn main() -> ! {
    // Clocks, pin muxing and so on: do these first, with your PAC/HAL.
    driver::probe_all(&BOARD, FACTORIES);
    if let Ok(uart) = Device::find("uart0") {
        bismuth::console::set_device(uart);       // kprintln! now goes through the UART's middleware
    }
    kprintln!("my-board up");
    task::spawn("app", 4, &APP_STACK, app_main, 0).unwrap();
    bismuth::start(CORE_HZ)                       // never returns
}

fn app_main(_: usize) { /* ... */ }

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // Report however the board can (semihosting, a UART polled directly, an LED), then halt or reset.
    loop {}
}
```

`bismuth::start(core_hz)` programs SysTick with `core_hz / TICK_HZ − 1` using the
processor clock (`SYST_CSR = 0b111`). It sets PendSV and SysTick to the lowest
priority, and switches to the first task.

### Things the kernel already defines

- The kernel exports these exception handlers (`#[unsafe(no_mangle)]` in
  `src/arch/cortex_m.rs`): `PendSV`, `SysTick`, `SVCall`, `MemoryManagement`,
  `BusFault` and `UsageFault`. **Do not** define them in the board with
  `#[exception]`, or linking fails with a duplicate symbol.
- `start` enables the MPU when the core has one (`MPU_TYPE.DREGION ≥ 2`). It maps
  region 0 (flash) and leaves the default memory map for privileged code
  (`PRIVDEFENA`), so normal tasks are unaffected. If you use sandboxed tasks, the code
  must live below `0x2000_0000`. On a core without an MPU, `spawn_user` returns
  `Error::Unsupported` (`port::supports_user_tasks()`).
- Leave the stack pointer setup and the vector table to `cortex-m-rt`. Tasks use PSP;
  the boot code and handlers use MSP.

## 7. Interrupt handlers

- Kernel critical sections mask **all** interrupts with PRIMASK. Any interrupt priority
  may therefore call ISR-safe kernel APIs, and there is no `BASEPRI` threshold to
  configure. The cost is that critical sections add latency to every interrupt, so
  they are kept short.
- The ISR-safe APIs are `Semaphore::give`, `EventFlags::set`, `Queue::try_send` and
  `try_recv`, `task::notify`, `net::schedule` and `PacketPool::try_alloc`. Blocking
  calls return `WouldBlock` from an ISR. Never use mutexes from an ISR. See the
  [scheduler](../design/scheduler.md#interrupt-service-routine-rules).
- The usual pattern is for the ISR to acknowledge and mask the device interrupt, then
  call `task::notify(driver_task, bit)` or `sem.give()`. A driver task does the rest
  in thread context.
- A network driver's RX interrupt should mask itself and call `net::schedule()`. The
  net task re-enables it through `NetDevice::irq_enable(true)` once a poll round
  finishes within its budget.

## 8. Entropy (if you enable `crypto`)

Register a hardware TRNG during boot and seed the pool before anything needs random
numbers (keys, TCP initial sequence numbers):

```rust
use bismuth::security::entropy::{self, Stm32Rng};

#[allow(unsafe_code)]
// SAFETY: RNG peripheral register block of this STM32 part, used only via this window.
static RNG: Stm32Rng = Stm32Rng::new(unsafe { Mmio::new(0x5006_0800, 0x10) }, 4); // assessed H = 4 bits/byte

// in main, before net::start():
RNG.enable();
entropy::add_source(&RNG).unwrap();
entropy::mix(&device_unique_id_bytes);   // uncredited, but strengthens the pool
entropy::seed(1000).expect("TRNG did not pass health tests");
```

The min-entropy figure must come from an SP 800-90B assessment of *your* part. Do not
copy the `4`.

## 9. Bring-up checklist

- [ ] `cargo build` succeeds for your target. Check the RAM budget with
      `cargo size` or the map file.
- [ ] `kprintln!` output appears. If it does not, check the console device and the
      UART clocks and pins.
- [ ] A periodic task drifts by 0 ticks over a minute (`sleep_until`). This confirms
      that `CORE_HZ` is right.
- [ ] `task::list` shows a healthy `stack_free` for every task after a soak test.
      Overflows are detected at context switch with a panic; see
      [stack painting](../design/scheduler.md#stacks-painting-and-overflow-detection).
- [ ] With an FPU target, two tasks doing floating point concurrently produce correct
      results (exercises lazy stacking).
- [ ] With `crypto`, `entropy::status().seeded` is true before `net::start()`.
