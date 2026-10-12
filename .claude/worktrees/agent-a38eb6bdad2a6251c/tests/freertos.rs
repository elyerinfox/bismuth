//! FreeRTOS compatibility layer, used the way FreeRTOS firmware is written.

#![allow(non_snake_case)]

use std::sync::Mutex as StdMutex;

use bismuth::compat::freertos::*;
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
fn log(s: impl Into<String>) {
    LOG.lock().unwrap().push(s.into());
}
fn take() -> Vec<String> {
    std::mem::take(&mut *LOG.lock().unwrap())
}

fn run(main: fn(usize)) {
    sim::run_to_completion(|| {
        assert_eq!(xTaskCreate(main, "main", 256, 0, 5, None), pdPASS);
    });
}

static Q: StdMutex<Option<QueueHandle_t>> = StdMutex::new(None);

#[test]
fn tasks_queues_and_delays() {
    let _s = serial();
    take();
    run(|_| {
        let q = xQueueCreate(4, 4).unwrap();
        *Q.lock().unwrap() = Some(q);
        assert_eq!(xTaskCreate(|_| {
            let q = Q.lock().unwrap().unwrap();
            let mut last = xTaskGetTickCount();
            for i in 0u32..6 {
                vTaskDelayUntil(&mut last, pdMS_TO_TICKS(10));
                xQueueSend(q, &i.to_le_bytes(), portMAX_DELAY);
            }
        }, "producer", 256, 0, 3, None), pdPASS);
        let mut buf = [0u8; 4];
        for _ in 0..6 {
            assert_eq!(xQueueReceive(q, &mut buf, portMAX_DELAY), pdPASS);
            log(format!("{}@{}", u32::from_le_bytes(buf), xTaskGetTickCount()));
        }
        assert_eq!(xQueueReceive(q, &mut buf, 5), errQUEUE_EMPTY);
        // Front insertion and capacity.
        for i in 0u32..4 {
            xQueueSend(q, &i.to_le_bytes(), 0);
        }
        assert_eq!(xQueueSend(q, &9u32.to_le_bytes(), 0), errQUEUE_FULL);
        assert_eq!(uxQueueMessagesWaiting(q), 4);
        xQueueReceive(q, &mut buf, 0);
        xQueueSendToFront(q, &7u32.to_le_bytes(), 0);
        xQueueReceive(q, &mut buf, 0);
        assert_eq!(u32::from_le_bytes(buf), 7);
        vQueueDelete(q);
    });
    assert_eq!(take(), ["0@10", "1@20", "2@30", "3@40", "4@50", "5@60"]);
}

static SEM: StdMutex<Option<SemaphoreHandle_t>> = StdMutex::new(None);

#[test]
fn binary_semaphore_from_isr_and_mutexes() {
    let _s = serial();
    take();
    run(|_| {
        let s = xSemaphoreCreateBinary().unwrap();
        *SEM.lock().unwrap() = Some(s);
        assert_eq!(xSemaphoreTake(s, 0), pdFAIL);
        // A simulated interrupt gives the semaphore from a non-task context.
        std::thread::spawn(move || {
            sim::interrupt(|| xSemaphoreGiveFromISR(s, None));
        })
        .join()
        .unwrap();
        assert_eq!(xSemaphoreTake(s, 10), pdPASS);

        let m = xSemaphoreCreateMutex().unwrap();
        assert_eq!(xSemaphoreTake(m, portMAX_DELAY), pdPASS);
        assert_eq!(uxSemaphoreGetCount(m), 0);
        assert_eq!(xSemaphoreGive(m), pdPASS);
        let r = xSemaphoreCreateRecursiveMutex().unwrap();
        assert_eq!(xSemaphoreTakeRecursive(r, 0), pdPASS);
        assert_eq!(xSemaphoreTakeRecursive(r, 0), pdPASS);
        assert_eq!(xSemaphoreGiveRecursive(r), pdPASS);
        assert_eq!(xSemaphoreGiveRecursive(r), pdPASS);
        let c = xSemaphoreCreateCounting(3, 2).unwrap();
        assert_eq!(uxSemaphoreGetCount(c), 2);
        log("ok");
    });
    assert_eq!(take(), ["ok"]);
}

static EG: StdMutex<Option<EventGroupHandle_t>> = StdMutex::new(None);

#[test]
fn event_groups_and_notifications() {
    let _s = serial();
    take();
    run(|_| {
        let eg = xEventGroupCreate().unwrap();
        *EG.lock().unwrap() = Some(eg);
        let mut me = xTaskGetCurrentTaskHandle();
        let main = me;
        xTaskCreate(|main| {
            let eg = EG.lock().unwrap().unwrap();
            vTaskDelay(5);
            xEventGroupSetBits(eg, 0b01);
            vTaskDelay(5);
            xEventGroupSetBits(eg, 0b10);
            vTaskDelay(5);
            xTaskNotifyGive(bismuth::TaskId::from_raw(main as u32));
        }, "setter", 256, main.as_raw() as usize, 4, Some(&mut me));
        let bits = xEventGroupWaitBits(eg, 0b11, pdTRUE, pdTRUE, portMAX_DELAY);
        log(format!("bits={bits:#b} t={}", xTaskGetTickCount()));
        assert_eq!(xEventGroupGetBits(eg), 0);
        let n = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        log(format!("notified={n} t={}", xTaskGetTickCount()));
        assert_eq!(ulTaskNotifyTake(pdTRUE, 3), 0);
    });
    assert_eq!(take(), ["bits=0b11 t=10", "notified=1 t=15"]);
}

static FIRED: StdMutex<Vec<(usize, u32)>> = StdMutex::new(Vec::new());

#[test]
fn software_timers() {
    let _s = serial();
    FIRED.lock().unwrap().clear();
    run(|_| {
        let auto = xTimerCreate("auto", 10, pdTRUE, 7, |t| {
            FIRED.lock().unwrap().push((pvTimerGetTimerID(t), xTaskGetTickCount()));
        })
        .unwrap();
        let once = xTimerCreate("once", 25, pdFALSE, 9, |t| {
            FIRED.lock().unwrap().push((pvTimerGetTimerID(t), xTaskGetTickCount()));
        })
        .unwrap();
        xTimerStart(auto, 0);
        xTimerStart(once, 0);
        vTaskDelay(35);
        assert_eq!(xTimerIsTimerActive(once), pdFALSE);
        xTimerStop(auto, 0);
        xTimerDelete(auto, 0);
        xTimerDelete(once, 0);
    });
    assert_eq!(*FIRED.lock().unwrap(), [(7, 10), (7, 20), (9, 25), (7, 30)]);
}
