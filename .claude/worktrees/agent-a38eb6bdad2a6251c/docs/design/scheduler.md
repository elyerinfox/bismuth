# Scheduler and tasks

Source: `src/kernel/mod.rs` (scheduler core), `src/kernel/task.rs` (task API),
`src/kernel/time.rs`, `src/kernel/timer.rs`, `src/kernel/stack.rs`, `src/sync/*`,
`src/arch/cortex_m.rs`.

## Tasks and priorities

- `config::PRIORITIES = 32` priority levels. The number is fixed because the ready
  bitmap is a `u32`. **Higher numbers are more urgent.**
- Priority 0 belongs to the idle task. User tasks use `task::MIN_PRIORITY = 1` through
  `task::MAX_PRIORITY = 31`. The software-timer service task runs at 31, and the `net`
  task at `BISMUTH_NET_PRIORITY` (default 20).
- The task table holds `config::MAX_TASKS` slots (default 16, between 2 and 255),
  including idle. Slot 0 is always the idle task.
- A `TaskId` packs the slot index (8 bits) and a 16-bit generation. A stale `TaskId`,
  whose slot has since been reused, is rejected with `Error::NotFound`.

```rust
static STACK: Stack<2048> = Stack::new();

let id = task::Builder::new("sensor")
    .priority(5)
    .stack(&STACK)        // omit to take a stack from the shared pool
    .spawn(sensor_main, 0)?;              // entry: fn(usize), plus one word of argument

task::spawn("sensor", 5, &STACK, sensor_main, 0)?;   // shorthand
```

`Builder` options:

| option | effect |
|--------|--------|
| `priority(p)` | 1..=31, else `Error::Invalid` |
| `stack(&'static S)` where `S: StackSource` (`Stack<N>`, `UserStack1K/2K/4K`) / `stack_ref(StackRef)` | dedicated stack. Without one, a stack comes from the pool (`POOL_STACKS × POOL_STACK_SIZE`). |
| `detached(true)` | the slot and stack are reclaimed automatically on exit; the task cannot be joined |
| `daemon(true)` | system task that does not keep the simulator alive |
| `domain(d)` | run in security domain `d` (only trusted creators may target another domain; the ceiling and quota of `d` apply) |

`spawn(entry: fn(usize), arg)` creates a normal (privileged) task.
`spawn_user(entry: extern "C-unwind" fn(usize), arg)` creates a **sandboxed** task: it
runs unprivileged under the MPU, needs an MPU-mappable stack (`UserStack*`), and may
only use `bismuth::user` system calls; see
[hardware isolation](security.md#hardware-isolation-sandboxed-tasks).

`spawn` returns these errors:

| error | cause |
|-------|-------|
| `Invalid` | priority out of range, or a stack under 256 bytes |
| `Busy` | the static stack is already in use |
| `NoMemory` | the stack pool is empty |
| `NoResources` | the task table is full |
| `PermissionDenied` | the domain's priority ceiling was exceeded, or a cross-domain spawn came from an untrusted domain |
| `NoResources` (from security) | the domain's task quota is used up |

### Task states

```text
          spawn                 block_current (wait key / timeout)
  Free ─────────► Ready ◄──────────────────────────────► Blocked
                  │  ▲              wake / timeout / abort
          suspend │  │ resume
                  ▼  │
               Suspended   (suspending a Blocked task aborts its wait)

  Ready/Blocked/Suspended ──exit / return / domain kill──► Dead ──join / detach / reap──► Free
```

- `task::exit(code)`, or returning from the entry function, moves the task to `Dead`.
  `task::join(id, timeout)` returns the exit code and frees the slot.
  `task::detach(id)` frees it immediately if the task is already dead, and otherwise at
  exit. Detached dead tasks are reaped lazily the next time a slot is allocated.
- `task::suspend(id)` on a blocked task cancels the wait. Once the task is resumed, its
  blocking call returns `Error::Interrupted`.
- `task::set_priority(id, p)` changes the base priority but keeps any
  priority-inheritance boost that is higher.
- Introspection: `task::list(&mut [TaskInfo])` and `task::info(id)` report name, state,
  effective and base priority, run ticks, stack size and stack never touched.

## The ready queue: O(1) selection

`Kernel` keeps one doubly linked list per priority, threaded through the `next`/`prev`
fields of each `Tcb`, plus a `ready_bitmap: u32` in which bit `p` is set while level `p`
has a ready task. The running task stays in the ready list.

```text
ready_bitmap = 0b..0010_0101_0001
                      │    │ │   └─ p0: idle
                      │    │ └───── p4: [sampler]
                      │    └─────── p6: [high]          ← highest_ready() = head of p6
                      └──────────── p9: (empty level, bit clear)

highest_ready() = ready_head[31 - ready_bitmap.leading_zeros()]
```

`Kernel::schedule()`, called by the port at switch time, picks `highest_ready()` and
makes it current. When the task changes, it counts a context switch and refills the time
slice.

**Preemption.** Making a task ready (`make_ready`, `wake`, `install_task`) calls
`preempt_check`. That requests a switch if the new task has a higher priority than the
current one, or if the current task is no longer `Ready`. The switch happens when the
enclosing critical section ends, which is PendSV on Cortex-M.

**Round-robin time slicing.** With `TIME_SLICE_TICKS` > 0 (default 10, set with
`BISMUTH_TIME_SLICE`; 0 disables slicing), `Kernel::tick()` decrements the slice. When it
reaches zero, and the current task is at the head of its level with other tasks behind
it, the current task rotates to the back and a switch is requested.
`task::yield_now()` performs the same rotation voluntarily.

## Blocking and wake-up via keys

Objects keep no wait lists. A blocked task stores:

| `Tcb` field | meaning |
|-------------|---------|
| `wait_key: usize` | what it waits for: an object address, or a reserved key |
| `wait_seq: u32` | global sequence number, for FIFO order among equal priorities |
| `wake_at: u64` | absolute timeout tick (`u64::MAX` = forever) |
| `wake_reason` | `Signaled`, `Handoff`, `Timeout` or `Aborted` |

Keys in use:

| key | used by |
|-----|---------|
| `1` (`KEY_SLEEP`) | `sleep_ticks` |
| `2` (`KEY_NOTIFY`) | `notify_wait` |
| object address | mutex, semaphore, condvar, event flags, pool, packet pool, pipe (data), queue (not-empty) |
| object address + 1 | queue (not-full), pipe (space), POSIX mqueue / FreeRTOS queue (not-full) |
| address of a per-slot static | `join` |

Waking (`highest_waiter(key)`) scans the task table. It picks the highest effective
priority, and the oldest `wait_seq` among equals. `wake_all(key)` wakes every waiter.

### `block_on`: the one blocking primitive

Every blocking call (except `CondVar::wait_raw`) is built on
`kernel::block_on(key, timeout, attempt, on_handoff, before_block)`:

```text
deadline = timeout.deadline(now)
loop:
  critical section:
    attempt(k) → Some(r)?                  done: Ok(r)
    deadline Now?                          Err(WouldBlock)
    deadline passed?                       Err(Timeout)
    !k.can_block() (ISR, idle, pre-start)? Err(WouldBlock)
    before_block(k)                        (e.g. priority inheritance)
    block_current(key, remaining)          (switch when the section ends)
  (task runs again)
  wake_reason == Handoff → Ok(on_handoff)  (the waker completed the operation)
  wake_reason == Aborted → Err(Interrupted)
  otherwise (Signaled/Timeout) → retry attempt
```

`Timeout` values (`bismuth::Timeout`): `NoWait`, `Ticks(n)`, `Forever`.
`Timeout::ms(ms)` rounds up to whole ticks. `Timeout::ms(0)` is `NoWait`.

**Timeout processing.** `Kernel.next_wake` caches the earliest `wake_at`. The cache may
be early but never late. `tick()` only scans the table when `tick >= next_wake`.

**Handoff vs. signal.** `Semaphore::give` and `RawMutex::unlock` hand the unit or the
ownership *directly* to the chosen waiter (`WakeReason::Handoff`), so a running task
cannot barge in and steal it. Queues, event flags and pools signal instead
(`Signaled`), and the woken task retries.

## Priority inheritance

`sync::RawMutex` and `sync::Mutex<T>` (also behind `pthread_mutex_t` and the FreeRTOS
mutexes) implement priority inheritance:

1. **On block.** A waiter whose priority is higher than the owner's raises the owner's
   effective priority (`Tcb.prio`) to its own (`before_block` hook).
2. **On unlock.** When the owner releases its *last* held mutex (`mutexes_held == 0`),
   it returns to its base priority. Ownership then passes directly to the
   highest-priority waiter (`Handoff`). The new owner inherits the priority of the
   highest task still waiting.
3. `task::set_priority` never lowers a task below an active boost.

Limitations of the current implementation:

- Inheritance is **not transitive**. If the owner is itself blocked on a second mutex,
  that mutex's owner is not boosted.
- A task holding several mutexes keeps its boost until it releases all of them. This is
  conservative: the priority can stay too high, never too low.

Other mutex rules:

- Locking a non-recursive mutex twice returns `Error::Deadlock`.
- `RawMutex::new_recursive()` and `set_recursive(true)` allow nesting.
- Unlocking a mutex the caller does not own returns `Error::NotOwner`.
- `CondVar::wait_raw` requires the mutex to be held exactly once (recursion depth 1),
  and otherwise returns `NotOwner`.

The QEMU demo in `boards/qemu-lm3s6965` checks priority inheritance on real hardware.
`high` takes the lock at t=20, before the CPU-bound `medium` finishes at t=62. `low`
runs at priority 6 while it holds the lock.

## Interrupt service routine rules

- Interrupt context is detected through `port::in_isr()`: IPSR ≠ 0 on Cortex-M, or any
  non-task thread on the host.
- Blocking from an ISR is never allowed. Any `block_on`-based call returns
  `Error::WouldBlock` there instead of waiting.
- These are safe from ISRs: `Semaphore::give`, `EventFlags::set` and `clear`,
  `Queue::try_send` and `try_recv`, `task::notify`, `net::schedule`,
  `PacketPool::try_alloc`, and `IrqCell::lock`.
- Mutexes cannot be used from ISRs. `RawMutex::lock`/`try_lock` return `WouldBlock`
  in interrupt context, because a mutex has no owner there.
- Kernel calls from an ISR run as the kernel security domain.
- A context switch requested from an ISR takes effect when the outermost critical
  section ends (PendSV on hardware; the next kernel call on the host).

## Time

- `SysTick` (Cortex-M) calls `Kernel::tick()` at `TICK_HZ`, which defaults to 1000.
  `tick()` advances `tick`, charges `run_ticks` to the running task, processes
  timeouts, and does round-robin slicing.
- `time::ticks()`, `time::uptime()`, `Instant::{now, elapsed, elapsed_ticks}`,
  `time::ms_to_ticks` (rounds up) and `time::ticks_to_ms`.
- `task::sleep_ticks(n)` and `sleep_ms(ms)`. `sleep_ticks(0)` is a yield.
- `task::sleep_until(&mut last, period)` is a periodic delay without drift. If the
  deadline has already passed, it catches up without sleeping.
- `task::set_idle_hook(fn())` installs a function that the idle task calls before each
  `WFI`. Use it to feed a watchdog or enter a low-power state.
- **Planned: tickless idle on MCUs.** `Kernel::advance_to` already exists, but only the
  simulator uses it. On Cortex-M the idle task executes `WFI` and SysTick keeps running.

### Software timers (`bismuth::timer`, `src/kernel/timer.rs`)

`static T: Timer = Timer::new(callback, arg)` creates a timer. `T.start(delay, period)`
starts it (period 0 means one-shot), and `start_ms`, `stop` and `is_active` do what
their names say. A timer can deliver to a `TimerHandler` object
(`set_handler(&'static dyn TimerHandler)`) instead of a `fn(usize)`. Callbacks run in
the **`timers` service task**, not in an ISR. That task runs at priority 31 as a daemon
in the kernel domain, and it is created on the first `start` with a
`TIMER_STACK_SIZE`-byte stack. At most `MAX_TIMERS` (default 8) timers can be active
at once. Keep callbacks short and non-blocking.

### Task notifications

`task::notify(id, bits)` ORs `bits` into the target's notification word and wakes it
if it is waiting in `task::notify_wait(timeout)`. `notify_wait` returns the accumulated
bits and clears them. `notify` is ISR-safe.

## Cortex-M context switch (`src/arch/cortex_m.rs`)

- Critical sections save PRIMASK, run `cpsid i`, and restore it. They nest.
- Tasks run in thread mode on **PSP**. Handlers use **MSP**.
- PendSV and SysTick are configured at the **lowest** exception priority
  (`SHPR3 |= 0xFFFF_0000`). A switch requested anywhere therefore runs only after every
  other handler has finished.
- `request_switch()` writes `ICSR.PENDSVSET`.

PendSV, a naked handler:

```text
mrs   r0, psp
(FPU builds: if EXC_RETURN bit 4 == 0, vstmdb r0!, {s16-s31})
stmdb r0!, {r4-r11, lr}          ; lr = EXC_RETURN
bl    bismuth_switch_context     ; save sp in the TCB, check the stack, schedule(), return new sp
ldmia r0!, {r4-r11, lr}
(FPU builds: if EXC_RETURN bit 4 == 0, vldmia r0!, {s16-s31})
msr   psp, r0
bx    lr
```

**Lazy FPU stacking** (`thumbv7em-none-eabihf`, selected by `target_abi = "eabihf"`):
the hardware stacks `s0`–`s15`/`FPSCR` lazily for tasks that used the FPU. PendSV saves
`s16`–`s31` only when EXC_RETURN bit 4 shows an extended frame, so tasks that never
touch the FPU pay nothing.

**Initial frame.** `init_task` writes 17 words below the top of the stack (8-byte
aligned): `r4`–`r11` = 0, EXC_RETURN = `0xFFFF_FFFD` (thread mode, PSP, no FP), then the
hardware frame, with `xPSR` = Thumb bit. For a normal task the frame holds `r0` = slot
index, `lr` = a trap function and `pc` = `task_trampoline`; the trampoline calls the
task's entry and then `exit_current(0)`. For a user task it holds `r0` = the argument,
`pc` = the user entry and `lr` = `user::user_task_return`, which exits through a system
call.

**Privilege and MPU at switch time.** After `schedule()`, `bismuth_switch_context`
reprograms MPU region 1 to the incoming task's stack, and sets or clears
`CONTROL.nPRIV`, depending on whether that task is a user task currently outside a
system call. Kernel tasks always run privileged.

**Other exceptions the port defines:**

- `SVCall`: system-call entry and return for user tasks.
- `MemoryManagement`, `BusFault` and `UsageFault`: a fault in user code kills the
  task's domain; a fault in kernel code panics.

`start` also initialises the MPU (`mpu_init`) when the core has one.

**Start-up.** `start(core_hz)` sets `SYST_RVR = core_hz / TICK_HZ − 1`, points PSP at a
small static scratch area so the first PendSV has somewhere to "save" the boot context
(discarded through `FIRST_SWITCH`), pends PendSV and enables interrupts.

## Stacks: painting and overflow detection

- `Stack<N>` is 8-byte aligned. When a task is installed, its whole stack is painted
  with `0xA5` (`STACK_PAINT`).
- `StackRef::unused()` counts the painted bytes at the bottom of the stack. That is the
  high-water mark, reported as `TaskInfo::stack_free`.
- **Overflow detection (Cortex-M).** On every switch away from a task,
  `bismuth_switch_context` panics with `stack overflow in task '<name>'` if the saved SP
  is below the stack base or the guard word (the lowest 4 bytes) is no longer painted.
  This *detects* an overflow after the fact; it does not prevent the damage. A user
  task inside a system call is checked against its private kernel stack. A user task
  that overflows its *own* stack is retired, and its domain is killed at the next tick
  instead of panicking the system. (A user stack is also bounded by its MPU region.)
- **Planned:** hardware stack limits (`PSPLIM` on ARMv8-M) and MPU guard regions, as
  part of the hardware isolation phase in [security](security.md#hardware-isolation-sandboxed-tasks).
- **Host simulator:** each task executes on its own 1 MiB OS-thread stack. The
  `Stack<N>` is claimed and painted but never executed on. `stack_free` therefore reads
  close to the full size, and overflow checks do not apply.

## Synchronization primitives (`bismuth::sync`)

| type | notes |
|------|-------|
| `Mutex<T>` / `MutexGuard` | priority inheritance; `lock()`, `lock_timeout(t)`, `try_lock()`; data held in a `TaskCell` |
| `RawMutex` | the same lock without data; `new_recursive()` |
| `Semaphore` | `new(initial, max)`, `binary()`; `take(t)`, `give()` (ISR-safe, hands off to a waiter, `Overflow` at max), `give_bounded(max)` (the same, with a tighter per-call cap, atomically), `reset`, `count` |
| `CondVar` | `wait(guard, t)`, `wait_while(guard, cond)`, `wait_raw(&RawMutex, t)`, `notify_one/all` |
| `Queue<T, N>` | bounded FIFO stored inline; `send`, `send_front`, `try_send`, `recv`, `try_recv`; a failed send returns the item in `SendError` |
| `EventFlags` | 32 bits; `set` (wakes all waiters), `clear`, `get`, `wait(mask, Any/All, clear, t)` |
| `mem::Pool<T, N>` | fixed-block allocator; `alloc(value, t)` returns a `PoolBox` that frees the block on drop |

All of them are `const`-constructible, never allocate, and wake waiters in priority
order (FIFO among equal priorities).
