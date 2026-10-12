//! FreeRTOS-flavoured API for porting existing firmware.
//!
//! Function names, argument order, return conventions (`pdPASS` / `pdFAIL` /
//! `errQUEUE_FULL`, `portMAX_DELAY`, tick-based timeouts) follow FreeRTOS. Objects that
//! FreeRTOS allocates dynamically (`xQueueCreate`, `xSemaphoreCreate*`,
//! `xEventGroupCreate`, `xTimerCreate`) come from fixed pools here, so there is still no
//! heap. Byte-oriented queues copy `uxItemSize` bytes per item, exactly like FreeRTOS.
//!
//! Safe Rust only: buffers are slices and handles are small `Copy` values.
//!
//! Classification: L4 personalities · FreeRTOS API · safe · freertos-compat

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::Error;
use crate::kernel::cell::IrqCell;
use crate::kernel::task::{self, TaskId};
use crate::kernel::time::{self, Timeout};
use crate::kernel::{WakeReason, block_on};
use crate::sync::{EventFlags, RawMutex, Semaphore, WaitMode};
use crate::kernel::timer::{Timer, TimerHandler};

pub type BaseType_t = i32;
pub type UBaseType_t = u32;
pub type TickType_t = u32;
pub type EventBits_t = u32;

pub const pdTRUE: BaseType_t = 1;
pub const pdFALSE: BaseType_t = 0;
pub const pdPASS: BaseType_t = 1;
pub const pdFAIL: BaseType_t = 0;
pub const errQUEUE_FULL: BaseType_t = 0;
pub const errQUEUE_EMPTY: BaseType_t = 0;
pub const errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY: BaseType_t = -1;
pub const portMAX_DELAY: TickType_t = u32::MAX;
pub const configMAX_PRIORITIES: UBaseType_t = crate::config::PRIORITIES as u32;
pub const tskIDLE_PRIORITY: UBaseType_t = 0;

/// Convert milliseconds to ticks.
pub const fn pdMS_TO_TICKS(ms: u32) -> TickType_t {
    time::ms_to_ticks(ms as u64) as TickType_t
}

fn to_timeout(ticks: TickType_t) -> Timeout {
    match ticks {
        0 => Timeout::NoWait,
        portMAX_DELAY => Timeout::Forever,
        t => Timeout::Ticks(t as u64),
    }
}

fn pass(r: Result<(), Error>) -> BaseType_t {
    if r.is_ok() { pdPASS } else { pdFAIL }
}

// ----- tasks -----

pub type TaskHandle_t = TaskId;
pub type TaskFunction_t = fn(usize);

/// Create a task. `usStackDepth` is in words as in FreeRTOS; stacks come from the
/// kernel pool, so requests larger than the pool stack size fail.
pub fn xTaskCreate(
    pxTaskCode: TaskFunction_t,
    pcName: &'static str,
    usStackDepth: u16,
    pvParameters: usize,
    uxPriority: UBaseType_t,
    pxCreatedTask: Option<&mut TaskHandle_t>,
) -> BaseType_t {
    if usStackDepth as usize * 4 > crate::config::POOL_STACK_SIZE {
        return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;
    }
    let prio = (uxPriority as u8).clamp(task::MIN_PRIORITY, task::MAX_PRIORITY);
    match task::Builder::new(pcName).priority(prio).detached(true).spawn(pxTaskCode, pvParameters) {
        Ok(id) => {
            if let Some(h) = pxCreatedTask {
                *h = id;
            }
            pdPASS
        }
        Err(_) => errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY,
    }
}

/// Delete a task; `None` deletes the calling task.
pub fn vTaskDelete(xTask: Option<TaskHandle_t>) {
    match xTask {
        None => task::exit(0),
        Some(t) if t == task::current() => task::exit(0),
        Some(t) => {
            let _ = task::suspend(t);
        }
    }
}

pub fn vTaskDelay(xTicksToDelay: TickType_t) {
    task::sleep_ticks(xTicksToDelay as u64);
}

pub fn vTaskDelayUntil(pxPreviousWakeTime: &mut TickType_t, xTimeIncrement: TickType_t) {
    let mut last = *pxPreviousWakeTime as u64;
    task::sleep_until(&mut last, xTimeIncrement as u64);
    *pxPreviousWakeTime = last as TickType_t;
}

pub fn xTaskGetTickCount() -> TickType_t {
    time::ticks() as TickType_t
}

pub fn xTaskGetCurrentTaskHandle() -> TaskHandle_t {
    task::current()
}

pub fn vTaskSuspend(xTask: Option<TaskHandle_t>) {
    let _ = task::suspend(xTask.unwrap_or_else(task::current));
}

pub fn vTaskResume(xTask: TaskHandle_t) {
    let _ = task::resume(xTask);
}

pub fn uxTaskPriorityGet(xTask: Option<TaskHandle_t>) -> UBaseType_t {
    task::priority(xTask.unwrap_or_else(task::current)).map_or(0, |p| p as u32)
}

pub fn vTaskPrioritySet(xTask: Option<TaskHandle_t>, uxNewPriority: UBaseType_t) {
    let _ = task::set_priority(xTask.unwrap_or_else(task::current), uxNewPriority as u8);
}

pub fn taskYIELD() {
    task::yield_now();
}

// ----- task notifications -----

pub fn xTaskNotifyGive(xTaskToNotify: TaskHandle_t) -> BaseType_t {
    pass(task::notify(xTaskToNotify, 1))
}

/// Wait for a notification; returns the accumulated notification bits (0 on timeout).
pub fn ulTaskNotifyTake(_xClearCountOnExit: BaseType_t, xTicksToWait: TickType_t) -> u32 {
    task::notify_wait(to_timeout(xTicksToWait)).unwrap_or(0)
}

pub fn xTaskNotify(xTaskToNotify: TaskHandle_t, ulValue: u32) -> BaseType_t {
    pass(task::notify(xTaskToNotify, ulValue))
}

// ----- queues -----

const QUEUE_POOL: usize = 8;
const QUEUE_BYTES: usize = 512;

struct QState {
    in_use: bool,
    item: usize,
    cap: usize,
    head: usize,
    len: usize,
    data: [u8; QUEUE_BYTES],
}

impl QState {
    const EMPTY: QState = QState { in_use: false, item: 0, cap: 0, head: 0, len: 0, data: [0; QUEUE_BYTES] };
}

static QUEUES: [IrqCell<QState>; QUEUE_POOL] = [const { IrqCell::new(QState::EMPTY) }; QUEUE_POOL];

/// Handle to a pool-allocated queue.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueueHandle_t(usize);

fn qkey(q: QueueHandle_t, full: bool) -> usize {
    &QUEUES[q.0] as *const _ as usize + full as usize
}

pub fn xQueueCreate(uxQueueLength: UBaseType_t, uxItemSize: UBaseType_t) -> Option<QueueHandle_t> {
    let (len, item) = (uxQueueLength as usize, uxItemSize as usize);
    if len == 0 || item == 0 || len * item > QUEUE_BYTES {
        return None;
    }
    QUEUES.iter().position(|q| {
        q.lock(|s| {
            if s.in_use {
                return false;
            }
            *s = QState { in_use: true, item, cap: len, ..QState::EMPTY };
            true
        })
    })
    .map(QueueHandle_t)
}

pub fn vQueueDelete(xQueue: QueueHandle_t) {
    QUEUES[xQueue.0].lock(|s| *s = QState::EMPTY);
}

fn q_send(q: QueueHandle_t, item: &[u8], ticks: TickType_t, front: bool) -> BaseType_t {
    let r = block_on(
        qkey(q, true),
        to_timeout(ticks),
        |k| {
            let ok = QUEUES[q.0].lock(|s| {
                if !s.in_use || s.len == s.cap {
                    return false;
                }
                let slot = if front {
                    s.head = (s.head + s.cap - 1) % s.cap;
                    s.head
                } else {
                    (s.head + s.len) % s.cap
                };
                let n = item.len().min(s.item);
                let off = slot * s.item;
                s.data[off..off + s.item].fill(0);
                s.data[off..off + n].copy_from_slice(&item[..n]);
                s.len += 1;
                true
            });
            ok.then(|| {
                k.wake_one(qkey(q, false), WakeReason::Signaled);
            })
        },
        |_| (),
        |_| {},
    );
    if r.is_ok() { pdPASS } else { errQUEUE_FULL }
}

/// Copy one item (`uxItemSize` bytes) into the queue.
pub fn xQueueSend(xQueue: QueueHandle_t, pvItemToQueue: &[u8], xTicksToWait: TickType_t) -> BaseType_t {
    q_send(xQueue, pvItemToQueue, xTicksToWait, false)
}

pub fn xQueueSendToBack(xQueue: QueueHandle_t, pvItemToQueue: &[u8], xTicksToWait: TickType_t) -> BaseType_t {
    q_send(xQueue, pvItemToQueue, xTicksToWait, false)
}

pub fn xQueueSendToFront(xQueue: QueueHandle_t, pvItemToQueue: &[u8], xTicksToWait: TickType_t) -> BaseType_t {
    q_send(xQueue, pvItemToQueue, xTicksToWait, true)
}

/// ISR-safe send (never blocks).
pub fn xQueueSendFromISR(xQueue: QueueHandle_t, pvItemToQueue: &[u8], _pxHigherPriorityTaskWoken: Option<&mut BaseType_t>) -> BaseType_t {
    q_send(xQueue, pvItemToQueue, 0, false)
}

/// Receive one item into `pvBuffer` (which must hold at least `uxItemSize` bytes).
pub fn xQueueReceive(xQueue: QueueHandle_t, pvBuffer: &mut [u8], xTicksToWait: TickType_t) -> BaseType_t {
    let r = block_on(
        qkey(xQueue, false),
        to_timeout(xTicksToWait),
        |k| {
            let ok = QUEUES[xQueue.0].lock(|s| {
                if !s.in_use || s.len == 0 || pvBuffer.len() < s.item {
                    return false;
                }
                let off = s.head * s.item;
                pvBuffer[..s.item].copy_from_slice(&s.data[off..off + s.item]);
                s.head = (s.head + 1) % s.cap;
                s.len -= 1;
                true
            });
            ok.then(|| {
                k.wake_one(qkey(xQueue, true), WakeReason::Signaled);
            })
        },
        |_| (),
        |_| {},
    );
    if r.is_ok() { pdPASS } else { errQUEUE_EMPTY }
}

pub fn uxQueueMessagesWaiting(xQueue: QueueHandle_t) -> UBaseType_t {
    QUEUES[xQueue.0].lock(|s| s.len as u32)
}

pub fn uxQueueSpacesAvailable(xQueue: QueueHandle_t) -> UBaseType_t {
    QUEUES[xQueue.0].lock(|s| (s.cap - s.len) as u32)
}

// ----- semaphores and mutexes -----

const SEM_POOL: usize = 16;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SemKind {
    Free,
    Counting,
    Mutex,
    Recursive,
}

static SEM_KINDS: IrqCell<[SemKind; SEM_POOL]> = IrqCell::new([SemKind::Free; SEM_POOL]);
static SEMS: [Semaphore; SEM_POOL] = [const { Semaphore::new(0, u32::MAX) }; SEM_POOL];
/// Per-handle maximum count (FreeRTOS caps binary at 1 and counting at `uxMaxCount`).
static SEM_MAX: IrqCell<[u32; SEM_POOL]> = IrqCell::new([0; SEM_POOL]);
static MUTEXES: [RawMutex; SEM_POOL] = [const { RawMutex::new() }; SEM_POOL];

/// Handle to a pool-allocated semaphore or mutex.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SemaphoreHandle_t(usize);

fn sem_alloc(kind: SemKind) -> Option<SemaphoreHandle_t> {
    SEM_KINDS.lock(|k| {
        let i = k.iter().position(|x| *x == SemKind::Free)?;
        k[i] = kind;
        Some(SemaphoreHandle_t(i))
    })
}

fn sem_kind(s: SemaphoreHandle_t) -> SemKind {
    SEM_KINDS.lock(|k| k[s.0])
}

pub fn xSemaphoreCreateBinary() -> Option<SemaphoreHandle_t> {
    let s = sem_alloc(SemKind::Counting)?;
    SEMS[s.0].reset(0).ok()?;
    SEM_MAX.lock(|m| m[s.0] = 1);
    Some(s)
}

pub fn xSemaphoreCreateCounting(uxMaxCount: UBaseType_t, uxInitialCount: UBaseType_t) -> Option<SemaphoreHandle_t> {
    if uxInitialCount > uxMaxCount || uxMaxCount == 0 {
        return None;
    }
    let s = sem_alloc(SemKind::Counting)?;
    SEMS[s.0].reset(uxInitialCount).ok()?;
    SEM_MAX.lock(|m| m[s.0] = uxMaxCount);
    Some(s)
}

/// Priority-inheritance mutex.
pub fn xSemaphoreCreateMutex() -> Option<SemaphoreHandle_t> {
    let s = sem_alloc(SemKind::Mutex)?;
    MUTEXES[s.0].set_recursive(false).ok()?;
    Some(s)
}

pub fn xSemaphoreCreateRecursiveMutex() -> Option<SemaphoreHandle_t> {
    let s = sem_alloc(SemKind::Recursive)?;
    MUTEXES[s.0].set_recursive(true).ok()?;
    Some(s)
}

pub fn vSemaphoreDelete(xSemaphore: SemaphoreHandle_t) {
    SEM_KINDS.lock(|k| k[xSemaphore.0] = SemKind::Free);
}

pub fn xSemaphoreTake(xSemaphore: SemaphoreHandle_t, xBlockTime: TickType_t) -> BaseType_t {
    let t = to_timeout(xBlockTime);
    match sem_kind(xSemaphore) {
        SemKind::Counting => pass(SEMS[xSemaphore.0].take(t)),
        SemKind::Mutex | SemKind::Recursive => pass(MUTEXES[xSemaphore.0].lock(t)),
        SemKind::Free => pdFAIL,
    }
}

pub fn xSemaphoreGive(xSemaphore: SemaphoreHandle_t) -> BaseType_t {
    match sem_kind(xSemaphore) {
        SemKind::Counting => {
            // Atomic check-and-give against the handle's maximum count.
            match SEMS[xSemaphore.0].give_bounded(SEM_MAX.lock(|m| m[xSemaphore.0])) {
                Ok(()) => pdPASS,
                Err(_) => pdFAIL,
            }
        }
        SemKind::Mutex | SemKind::Recursive => pass(MUTEXES[xSemaphore.0].unlock()),
        SemKind::Free => pdFAIL,
    }
}

pub fn xSemaphoreTakeRecursive(xMutex: SemaphoreHandle_t, xBlockTime: TickType_t) -> BaseType_t {
    xSemaphoreTake(xMutex, xBlockTime)
}

pub fn xSemaphoreGiveRecursive(xMutex: SemaphoreHandle_t) -> BaseType_t {
    xSemaphoreGive(xMutex)
}

pub fn xSemaphoreGiveFromISR(xSemaphore: SemaphoreHandle_t, _pxHigherPriorityTaskWoken: Option<&mut BaseType_t>) -> BaseType_t {
    xSemaphoreGive(xSemaphore)
}

pub fn uxSemaphoreGetCount(xSemaphore: SemaphoreHandle_t) -> UBaseType_t {
    match sem_kind(xSemaphore) {
        SemKind::Counting => SEMS[xSemaphore.0].count(),
        SemKind::Mutex | SemKind::Recursive => (!MUTEXES[xSemaphore.0].is_locked()) as u32,
        SemKind::Free => 0,
    }
}

// ----- event groups -----

const EVENT_POOL: usize = 8;
static EVENT_USED: IrqCell<[bool; EVENT_POOL]> = IrqCell::new([false; EVENT_POOL]);
static EVENTS: [EventFlags; EVENT_POOL] = [const { EventFlags::new() }; EVENT_POOL];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventGroupHandle_t(usize);

pub fn xEventGroupCreate() -> Option<EventGroupHandle_t> {
    let i = EVENT_USED.lock(|u| {
        let i = u.iter().position(|x| !*x)?;
        u[i] = true;
        Some(i)
    })?;
    EVENTS[i].clear(u32::MAX);
    Some(EventGroupHandle_t(i))
}

pub fn vEventGroupDelete(xEventGroup: EventGroupHandle_t) {
    EVENT_USED.lock(|u| u[xEventGroup.0] = false);
}

pub fn xEventGroupSetBits(xEventGroup: EventGroupHandle_t, uxBitsToSet: EventBits_t) -> EventBits_t {
    EVENTS[xEventGroup.0].set(uxBitsToSet)
}

pub fn xEventGroupClearBits(xEventGroup: EventGroupHandle_t, uxBitsToClear: EventBits_t) -> EventBits_t {
    let before = EVENTS[xEventGroup.0].get();
    EVENTS[xEventGroup.0].clear(uxBitsToClear);
    before
}

pub fn xEventGroupGetBits(xEventGroup: EventGroupHandle_t) -> EventBits_t {
    EVENTS[xEventGroup.0].get()
}

/// Returns the bits at the time the wait was satisfied, or the current bits on timeout.
pub fn xEventGroupWaitBits(
    xEventGroup: EventGroupHandle_t,
    uxBitsToWaitFor: EventBits_t,
    xClearOnExit: BaseType_t,
    xWaitForAllBits: BaseType_t,
    xTicksToWait: TickType_t,
) -> EventBits_t {
    let mode = if xWaitForAllBits != pdFALSE { WaitMode::All } else { WaitMode::Any };
    EVENTS[xEventGroup.0]
        .wait(uxBitsToWaitFor, mode, xClearOnExit != pdFALSE, to_timeout(xTicksToWait))
        .unwrap_or_else(|_| EVENTS[xEventGroup.0].get())
}

// ----- software timers -----

const TIMER_POOL: usize = 8;

pub type TimerCallbackFunction_t = fn(TimerHandle_t);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimerHandle_t(usize);

#[derive(Copy, Clone)]
struct TimerSlot {
    used: bool,
    period: TickType_t,
    auto_reload: bool,
    callback: Option<TimerCallbackFunction_t>,
    id: usize,
}

static TIMER_SLOTS: IrqCell<[TimerSlot; TIMER_POOL]> =
    IrqCell::new([TimerSlot { used: false, period: 0, auto_reload: false, callback: None, id: 0 }; TIMER_POOL]);

struct FrTimer {
    index: usize,
    timer: Timer,
}

impl TimerHandler for FrTimer {
    fn expired(&'static self) {
        let cb = TIMER_SLOTS.lock(|t| t[self.index].callback);
        if let Some(cb) = cb {
            cb(TimerHandle_t(self.index));
        }
    }
}

static TIMERS: [FrTimer; TIMER_POOL] = {
    let mut i = 0;
    let mut a = [const { FrTimer { index: 0, timer: Timer::new(|_| {}, 0) } }; TIMER_POOL];
    while i < TIMER_POOL {
        a[i].index = i;
        i += 1;
    }
    a
};

pub fn xTimerCreate(
    _pcTimerName: &'static str,
    xTimerPeriodInTicks: TickType_t,
    uxAutoReload: BaseType_t,
    pvTimerID: usize,
    pxCallbackFunction: TimerCallbackFunction_t,
) -> Option<TimerHandle_t> {
    if xTimerPeriodInTicks == 0 {
        return None;
    }
    let i = TIMER_SLOTS.lock(|t| {
        let i = t.iter().position(|s| !s.used)?;
        t[i] = TimerSlot {
            used: true,
            period: xTimerPeriodInTicks,
            auto_reload: uxAutoReload != pdFALSE,
            callback: Some(pxCallbackFunction),
            id: pvTimerID,
        };
        Some(i)
    })?;
    TIMERS[i].timer.set_handler(&TIMERS[i]);
    Some(TimerHandle_t(i))
}

pub fn xTimerStart(xTimer: TimerHandle_t, _xTicksToWait: TickType_t) -> BaseType_t {
    let s = TIMER_SLOTS.lock(|t| t[xTimer.0]);
    if !s.used {
        return pdFAIL;
    }
    let period = if s.auto_reload { s.period as u64 } else { 0 };
    pass(TIMERS[xTimer.0].timer.start(s.period as u64, period))
}

pub fn xTimerStop(xTimer: TimerHandle_t, _xTicksToWait: TickType_t) -> BaseType_t {
    TIMERS[xTimer.0].timer.stop();
    pdPASS
}

pub fn xTimerReset(xTimer: TimerHandle_t, xTicksToWait: TickType_t) -> BaseType_t {
    xTimerStart(xTimer, xTicksToWait)
}

pub fn xTimerChangePeriod(xTimer: TimerHandle_t, xNewPeriod: TickType_t, xTicksToWait: TickType_t) -> BaseType_t {
    if xNewPeriod == 0 {
        return pdFAIL;
    }
    TIMER_SLOTS.lock(|t| t[xTimer.0].period = xNewPeriod);
    xTimerStart(xTimer, xTicksToWait)
}

pub fn xTimerIsTimerActive(xTimer: TimerHandle_t) -> BaseType_t {
    TIMERS[xTimer.0].timer.is_active() as BaseType_t
}

pub fn pvTimerGetTimerID(xTimer: TimerHandle_t) -> usize {
    TIMER_SLOTS.lock(|t| t[xTimer.0].id)
}

pub fn xTimerDelete(xTimer: TimerHandle_t, _xTicksToWait: TickType_t) -> BaseType_t {
    TIMERS[xTimer.0].timer.stop();
    TIMER_SLOTS.lock(|t| t[xTimer.0].used = false);
    pdPASS
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    for q in QUEUES.iter() {
        q.lock(|s| *s = QState::EMPTY);
    }
    SEM_KINDS.lock(|k| *k = [SemKind::Free; SEM_POOL]);
    SEM_MAX.lock(|m| *m = [0; SEM_POOL]);
    EVENT_USED.lock(|u| *u = [false; EVENT_POOL]);
    TIMER_SLOTS.lock(|t| {
        for s in t.iter_mut() {
            s.used = false;
            s.callback = None;
        }
    });
}
