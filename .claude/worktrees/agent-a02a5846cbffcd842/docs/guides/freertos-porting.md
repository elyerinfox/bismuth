# Porting FreeRTOS code

Module: `bismuth::compat::freertos` (feature `freertos-compat`, on by default). Source:
`src/compat/freertos.rs`.

The layer keeps FreeRTOS **names, argument order, return conventions and tick-based
timeouts**, so application logic ports with mostly mechanical changes. It is safe Rust:
buffers are slices and handles are small `Copy` values. Objects that FreeRTOS allocates
dynamically come from **fixed pools**, so there is still no heap.

```rust
use bismuth::compat::freertos::*;
```

## Types and constants

| FreeRTOS | Bismuth |
|----------|---------|
| `BaseType_t` / `UBaseType_t` | `i32` / `u32` |
| `TickType_t`, `EventBits_t` | `u32` (the kernel tick counter is 64-bit; `xTaskGetTickCount` truncates) |
| `pdTRUE`/`pdPASS` = 1, `pdFALSE`/`pdFAIL` = 0 | same |
| `errQUEUE_FULL`, `errQUEUE_EMPTY` | 0 |
| `errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY` | -1 |
| `portMAX_DELAY` | `u32::MAX`, which waits forever |
| `configMAX_PRIORITIES` | 32 |
| `tskIDLE_PRIORITY` | 0 |
| `pdMS_TO_TICKS(ms)` | `const fn`, rounds up |

A timeout of `0` means "don't block", `portMAX_DELAY` means forever, and anything else
is a number of ticks. The tick rate is `BISMUTH_TICK_HZ` (default 1000).

## Supported API

### Tasks

| function | notes / differences |
|----------|---------------------|
| `xTaskCreate(fn, name, usStackDepth, param, prio, Option<&mut handle>)` | The entry is `fn(usize)`, with `param: usize`. Stacks come from the kernel stack pool, so `usStackDepth × 4` must be ≤ `POOL_STACK_SIZE` (otherwise `errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY`). Every task gets a full pool stack. The priority is clamped to 1..=31. Tasks are created **detached**. |
| `vTaskDelete(None \| Some(h))` | Deleting yourself exits the task. Deleting **another task only suspends it**: its slot and stack are not reclaimed. |
| `vTaskDelay(ticks)`, `vTaskDelayUntil(&mut prev, inc)` | `vTaskDelayUntil` catches up without sleeping if the deadline has already passed |
| `xTaskGetTickCount`, `xTaskGetCurrentTaskHandle` | |
| `vTaskSuspend(Option<h>)`, `vTaskResume(h)` | Suspending a blocked task aborts its wait. |
| `uxTaskPriorityGet(Option<h>)`, `vTaskPrioritySet(Option<h>, p)` | `Get` returns the *effective* priority, including any inheritance boost. |
| `taskYIELD()` | |

`TaskHandle_t` is `bismuth::TaskId`, so FreeRTOS tasks and native tasks can be mixed
freely.

### Task notifications

| function | notes / differences |
|----------|---------------------|
| `xTaskNotifyGive(h)` | ORs bit 0 into the notification word. **It does not count**: two gives before a take are seen once. |
| `ulTaskNotifyTake(clear, ticks)` | Returns the accumulated bits (0 on timeout) and always clears them. `xClearCountOnExit` is ignored. |
| `xTaskNotify(h, value)` | Always behaves like `eSetBits` (OR). There is no `eAction` parameter. |

`xTaskNotifyWait`, `xTaskNotifyFromISR` and `vTaskNotifyGiveFromISR` are not provided.
The native `task::notify` is ISR-safe, so call it directly from interrupt handlers.

### Queues

Queues are byte-oriented and copy `uxItemSize` bytes per item, as in FreeRTOS. There are
8 queues in the pool, each with 512 bytes of storage, so `length × item_size` must be
≤ 512.

| function | notes / differences |
|----------|---------------------|
| `xQueueCreate(len, item_size) -> Option<QueueHandle_t>` | `None` when the pool is exhausted or the size is invalid |
| `vQueueDelete(q)` | Resets the slot. Tasks blocked on the queue are **not** woken. |
| `xQueueSend`, `xQueueSendToBack`, `xQueueSendToFront(q, &[u8], ticks)` | A short item is zero-padded to `item_size`; a long one is truncated. Returns `pdPASS` or `errQUEUE_FULL`. |
| `xQueueSendFromISR(q, &[u8], _woken)` | never blocks; `pxHigherPriorityTaskWoken` is ignored (see the ISR notes below) |
| `xQueueReceive(q, &mut [u8], ticks)` | the buffer must hold at least `item_size` bytes; returns `pdPASS` or `errQUEUE_EMPTY` |
| `uxQueueMessagesWaiting`, `uxQueueSpacesAvailable` | |

For new Rust code, prefer the typed `bismuth::sync::Queue<T, N>`.

### Semaphores and mutexes

16 handles in the pool, shared by every kind.

| function | notes / differences |
|----------|---------------------|
| `xSemaphoreCreateBinary()` | Created empty (count 0) and capped at 1: a second give before a take fails with `pdFAIL`, as in FreeRTOS. |
| `xSemaphoreCreateCounting(max, initial)` | `initial > max` returns `None`. Gives beyond `max` fail with `pdFAIL`. The check and the increment happen atomically (`Semaphore::give_bounded`), so an ISR give cannot overshoot. |
| `xSemaphoreCreateMutex()`, `xSemaphoreCreateRecursiveMutex()` | Kernel `RawMutex` with priority inheritance and ownership checks: giving a mutex you do not own fails. |
| `xSemaphoreTake(s, ticks)`, `xSemaphoreGive(s)` | `pdPASS` / `pdFAIL` |
| `xSemaphoreTakeRecursive`, `xSemaphoreGiveRecursive` | aliases of take and give |
| `xSemaphoreGiveFromISR(s, _woken)` | Same as give. **Do not use it on a mutex from an ISR.** |
| `uxSemaphoreGetCount(s)` | For mutexes: 1 when unlocked, 0 when locked. |
| `vSemaphoreDelete(s)` | frees the handle |

### Event groups

8 groups in the pool, with 32 bits each (FreeRTOS reserves the top byte; Bismuth does
not).

| function | notes |
|----------|-------|
| `xEventGroupCreate`, `vEventGroupDelete` | |
| `xEventGroupSetBits` | returns the new value |
| `xEventGroupClearBits` | returns the value *before* clearing, as in FreeRTOS |
| `xEventGroupGetBits` | |
| `xEventGroupWaitBits(g, bits, clear_on_exit, wait_all, ticks)` | Returns the bits that satisfied the wait, or the current bits on timeout. A zero mask returns the current bits immediately (the kernel rejects it). |

`xEventGroupSync` and the `FromISR` variants are not provided. The native
`EventFlags::set` is ISR-safe.

### Software timers

8 timers in the pool.

| function | notes / differences |
|----------|---------------------|
| `xTimerCreate(name, period, auto_reload, id, callback) -> Option<TimerHandle_t>` | The callback is `fn(TimerHandle_t)`; a period of 0 returns `None`. |
| `xTimerStart`, `xTimerReset`, `xTimerChangePeriod` | Start or restart takes effect immediately; `xTicksToWait` is ignored because there is no timer command queue. |
| `xTimerStop`, `xTimerDelete` | |
| `xTimerIsTimerActive`, `pvTimerGetTimerID` | the ID is a `usize` |

Callbacks run in the kernel's `timers` service task, at priority 31, in task context:
the same model as the FreeRTOS timer daemon. Keep them short and non-blocking.

## ISR conventions

- `...FromISR` functions take `pxHigherPriorityTaskWoken`, but **ignore it**. There is
  no `portYIELD_FROM_ISR`. If a woken task outranks the interrupted one, the kernel pends
  the context switch itself, and it happens as soon as the interrupt returns (PendSV at
  the lowest priority).
- A blocking call made from an ISR fails immediately with `WouldBlock`, so a FreeRTOS
  function returns `pdFAIL` or the queue error instead of blocking.
- There is no `configMAX_SYSCALL_INTERRUPT_PRIORITY`. Kernel critical sections mask
  all interrupts, so an ISR at any priority may call ISR-safe functions.

## What is not provided

- Stream and message buffers. Use `sync::Queue` or a `Pipe` device.
- Static-allocation variants such as `xTaskCreateStatic`. Use the native
  `task::Builder::stack(&STATIC_STACK)`.
- Queue sets, co-routines, MPU wrappers, `vTaskList`/run-time stats strings, and
  `vTaskStartScheduler`/`vTaskEndScheduler`. To start the scheduler, call
  `bismuth::start(core_hz)` on MCUs or `sim::run` on the host. For task listings, use
  `task::list`.
- The heap API (`pvPortMalloc`, `vPortFree`). For fixed-size blocks, use
  `bismuth::mem::Pool`.
- `configASSERT` and the hook functions. For the idle hook, use `task::set_idle_hook`.

## Porting checklist

1. Replace `void *pvParameters` with a `usize`, pointing at a `static` or carrying an
   index or small value.
2. Replace `xQueueSend(q, &item, t)` with `xQueueSend(q, bytes_of(&item), t)`, or move to
   a typed `sync::Queue<T, N>`.
3. Check notifications used as counters (`xTaskNotifyGive`/`ulTaskNotifyTake`): they
   do not count here. Also check any `vTaskDelete` of another task, and any
   `vQueueDelete` while tasks wait on the queue.
4. Check pool sizes against what the application creates: 8 queues, 16
   semaphores/mutexes, 8 event groups, 8 timers, and `POOL_STACKS` task stacks.
5. Map `configTICK_RATE_HZ` to `BISMUTH_TICK_HZ`, and `configMAX_PRIORITIES` (32 is
   fixed). Bismuth priorities run 1..=31, higher is more urgent, the same direction as
   FreeRTOS.
6. Run the ported code in the [simulator](testing-with-the-simulator.md) first.
