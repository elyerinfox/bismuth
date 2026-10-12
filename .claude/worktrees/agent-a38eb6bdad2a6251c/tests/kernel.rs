//! RTOS core behaviour, exercised in the deterministic host simulator.

use std::sync::Mutex as StdMutex;

use bismuth::sim::{self, Config, Outcome};
use bismuth::sync::{CondVar, EventFlags, Mutex, Queue, Semaphore, WaitMode};
use bismuth::task::{self, Builder};
use bismuth::timer::Timer;
use bismuth::{Error, Stack, Timeout, time};

/// Tests in this file share global logs; run them one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

fn log(s: impl Into<String>) {
    LOG.lock().unwrap().push(s.into());
}

fn take_log() -> Vec<String> {
    std::mem::take(&mut *LOG.lock().unwrap())
}

#[test]
fn higher_priority_runs_first_and_preempts() {
    let _serial = serial();
    sim::run_to_completion(|| {
        take_log();
        task::Builder::new("low").priority(2).spawn(|_| {
            log("low start");
            // Spawning a higher-priority task preempts us immediately.
            Builder::new("high").priority(5).spawn(|_| log("high"), 0).unwrap();
            log("low end");
        }, 0).unwrap();
        task::Builder::new("mid").priority(3).spawn(|_| log("mid"), 0).unwrap();
    });
    assert_eq!(take_log(), ["mid", "low start", "high", "low end"]);
}

#[test]
fn sleep_advances_virtual_time() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::Builder::new("sleeper").priority(3).spawn(|_| {
            let t0 = time::ticks();
            task::sleep_ticks(100);
            assert_eq!(time::ticks() - t0, 100);
            task::sleep_ms(250);
            assert_eq!(time::ticks() - t0, 100 + time::ms_to_ticks(250));
        }, 0).unwrap();
    });
}

#[test]
fn periodic_sleep_until_has_no_drift() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::Builder::new("periodic").priority(3).spawn(|_| {
            let mut last = time::ticks();
            for i in 1..=5 {
                // Simulate variable work by sleeping a little first.
                task::sleep_ticks(i);
                task::sleep_until(&mut last, 20);
                assert_eq!(time::ticks(), 20 * i);
            }
        }, 0).unwrap();
    });
}

static SEM: Semaphore = Semaphore::binary();

#[test]
fn semaphore_signals_between_tasks() {
    let _serial = serial();
    sim::run_to_completion(|| {
        take_log();
        task::Builder::new("waiter").priority(4).spawn(|_| {
            log("wait");
            SEM.take(Timeout::Forever).unwrap();
            log(format!("got at {}", time::ticks()));
        }, 0).unwrap();
        task::Builder::new("giver").priority(2).spawn(|_| {
            task::sleep_ticks(50);
            log("give");
            SEM.give().unwrap();
            log("after give");
        }, 0).unwrap();
    });
    // The higher-priority waiter preempts the giver as soon as the semaphore is given.
    assert_eq!(take_log(), ["wait", "give", "got at 50", "after give"]);
}

static SEM_TO: Semaphore = Semaphore::binary();

#[test]
fn semaphore_timeout() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::Builder::new("t").priority(3).spawn(|_| {
            assert_eq!(SEM_TO.take(Timeout::Ticks(30)), Err(Error::Timeout));
            assert_eq!(time::ticks(), 30);
            assert_eq!(SEM_TO.try_take(), Err(Error::WouldBlock));
        }, 0).unwrap();
    });
}

static PI_LOCK: Mutex<u32> = Mutex::new(0);

#[test]
fn mutex_priority_inheritance() {
    let _serial = serial();
    sim::run_to_completion(|| {
        take_log();
        let low = task::Builder::new("low").priority(2).spawn(|_| {
            let mut g = PI_LOCK.lock().unwrap();
            log("low locked");
            // Hold the lock across a sleep so `high` blocks on it.
            task::sleep_ticks(10);
            // While `high` waits, we run at its priority.
            log(format!("low prio while held = {}", task::priority(task::current()).unwrap()));
            *g += 1;
            drop(g);
            log(format!("low prio after = {}", task::priority(task::current()).unwrap()));
        }, 0).unwrap();
        let _ = low;
        task::Builder::new("high").priority(6).spawn(|_| {
            task::sleep_ticks(5);
            log("high wants lock");
            let mut g = PI_LOCK.lock().unwrap();
            *g += 10;
            log(format!("high got lock, value {}", *g));
        }, 0).unwrap();
    });
    assert_eq!(
        take_log(),
        ["low locked", "high wants lock", "low prio while held = 6", "high got lock, value 11", "low prio after = 2"]
    );
}

static REC: bismuth::sync::RawMutex = bismuth::sync::RawMutex::new_recursive();
static NONREC: bismuth::sync::RawMutex = bismuth::sync::RawMutex::new();

#[test]
fn mutex_recursion_rules() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::Builder::new("t").priority(3).spawn(|_| {
            REC.lock(Timeout::Forever).unwrap();
            REC.lock(Timeout::Forever).unwrap();
            REC.unlock().unwrap();
            REC.unlock().unwrap();
            assert_eq!(REC.unlock(), Err(Error::NotOwner));
            NONREC.lock(Timeout::Forever).unwrap();
            assert_eq!(NONREC.lock(Timeout::Forever), Err(Error::Deadlock));
            NONREC.unlock().unwrap();
        }, 0).unwrap();
    });
}

static Q: Queue<u32, 4> = Queue::new();

#[test]
fn queue_blocks_producer_when_full() {
    let _serial = serial();
    sim::run_to_completion(|| {
        take_log();
        task::Builder::new("producer").priority(4).spawn(|_| {
            for i in 0..10 {
                Q.send(i, Timeout::Forever).unwrap();
            }
            log("producer done");
        }, 0).unwrap();
        task::Builder::new("consumer").priority(2).spawn(|_| {
            let mut got = Vec::new();
            for _ in 0..10 {
                got.push(Q.recv(Timeout::Forever).unwrap());
            }
            assert_eq!(got, (0..10).collect::<Vec<_>>());
            log("consumer done");
        }, 0).unwrap();
    });
    assert_eq!(take_log(), ["producer done", "consumer done"]);
}

static QF: Queue<&'static str, 2> = Queue::new();

#[test]
fn queue_send_front_and_errors() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::Builder::new("t").priority(3).spawn(|_| {
            QF.try_send("b").unwrap();
            QF.send_front("a", Timeout::NoWait).unwrap();
            let e = QF.try_send("c").unwrap_err();
            assert_eq!((e.error, e.item), (Error::WouldBlock, "c"));
            assert_eq!(QF.try_recv(), Ok("a"));
            assert_eq!(QF.try_recv(), Ok("b"));
            assert_eq!(QF.recv(Timeout::Ticks(5)), Err(Error::Timeout));
        }, 0).unwrap();
    });
}

static EV: EventFlags = EventFlags::new();

#[test]
fn event_flags_all_and_any() {
    let _serial = serial();
    sim::run_to_completion(|| {
        take_log();
        task::Builder::new("all").priority(5).spawn(|_| {
            let v = EV.wait(0b011, WaitMode::All, true, Timeout::Forever).unwrap();
            log(format!("all {v:#b} at {}", time::ticks()));
        }, 0).unwrap();
        task::Builder::new("any").priority(4).spawn(|_| {
            let v = EV.wait(0b100, WaitMode::Any, false, Timeout::Forever).unwrap();
            log(format!("any {v:#b} at {}", time::ticks()));
        }, 0).unwrap();
        task::Builder::new("setter").priority(2).spawn(|_| {
            task::sleep_ticks(10);
            EV.set(0b001);
            task::sleep_ticks(10);
            EV.set(0b110);
        }, 0).unwrap();
    });
    assert_eq!(take_log(), ["all 0b111 at 20", "any 0b100 at 20"]);
    assert_eq!(EV.get(), 0b100);
}

static CV_STATE: Mutex<(bool, u32)> = Mutex::new((false, 0));
static CV: CondVar = CondVar::new();

#[test]
fn condvar_wait_and_notify() {
    let _serial = serial();
    sim::run_to_completion(|| {
        for _ in 0..3 {
            task::Builder::new("waiter").priority(4).spawn(|_| {
                let g = CV_STATE.lock().unwrap();
                let mut g = CV.wait_while(g, |s| !s.0).unwrap();
                g.1 += 1;
            }, 0).unwrap();
        }
        task::Builder::new("notifier").priority(2).spawn(|_| {
            task::sleep_ticks(5);
            CV_STATE.lock().unwrap().0 = true;
            CV.notify_all();
            task::sleep_ticks(1);
            assert_eq!(CV_STATE.lock().unwrap().1, 3);
        }, 0).unwrap();
    });
}

#[test]
fn join_returns_exit_code() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::Builder::new("parent").priority(3).spawn(|_| {
            let child = task::Builder::new("child").priority(4).spawn(|x| {
                task::sleep_ticks(7);
                task::exit(x * 2);
            }, 21).unwrap();
            assert_eq!(task::join(child, Timeout::Forever), Ok(42));
            // The handle is stale after join.
            assert_eq!(task::join(child, Timeout::NoWait), Err(Error::NotFound));
        }, 0).unwrap();
    });
}

static NEVER: Semaphore = Semaphore::binary();

#[test]
fn deadlock_is_detected() {
    let _serial = serial();
    let outcome = sim::run(Config::default(), || {
        task::Builder::new("stuck").priority(3).spawn(|_| {
            let _ = NEVER.take(Timeout::Forever);
        }, 0).unwrap();
    });
    assert_eq!(outcome, Outcome::Deadlock);
}

#[test]
fn task_panic_is_reported() {
    let _serial = serial();
    let outcome = sim::run(Config::default(), || {
        task::Builder::new("bad").priority(3).spawn(|_| panic!("boom"), 0).unwrap();
    });
    match outcome {
        Outcome::Panic(msg) => assert!(msg.contains("boom"), "{msg}"),
        other => panic!("unexpected outcome {other:?}"),
    }
}

#[test]
fn tick_limit_stops_endless_systems() {
    let _serial = serial();
    let outcome = sim::run(Config { tick_limit: Some(500), realtime: false }, || {
        task::Builder::new("forever").priority(3).spawn(|_| loop {
            task::sleep_ticks(10);
        }, 0).unwrap();
    });
    assert_eq!(outcome, Outcome::TickLimit);
}

static TICKS_FIRED: StdMutex<Vec<u64>> = StdMutex::new(Vec::new());
static PERIODIC: Timer = Timer::new(|_| TICKS_FIRED.lock().unwrap().push(time::ticks()), 0);
static ONESHOT: Timer = Timer::new(|n| TICKS_FIRED.lock().unwrap().push(1_000_000 + n as u64), 7);

#[test]
fn software_timers() {
    let _serial = serial();
    TICKS_FIRED.lock().unwrap().clear();
    sim::run_to_completion(|| {
        task::Builder::new("t").priority(3).spawn(|_| {
            PERIODIC.start(10, 25).unwrap();
            ONESHOT.start(30, 0).unwrap();
            task::sleep_ticks(80);
            PERIODIC.stop();
            assert!(!ONESHOT.is_active());
        }, 0).unwrap();
    });
    assert_eq!(*TICKS_FIRED.lock().unwrap(), [10, 1_000_007, 35, 60]);
}

static NOTIFY_TARGET: StdMutex<Option<task::TaskId>> = StdMutex::new(None);

#[test]
fn task_notifications_accumulate_bits() {
    let _serial = serial();
    sim::run_to_completion(|| {
        let id = task::Builder::new("rx").priority(3).spawn(|_| {
            task::sleep_ticks(10);
            assert_eq!(task::notify_wait(Timeout::Forever), Ok(0b101));
            assert_eq!(task::notify_wait(Timeout::Ticks(3)), Err(Error::Timeout));
        }, 0).unwrap();
        *NOTIFY_TARGET.lock().unwrap() = Some(id);
        task::Builder::new("tx").priority(2).spawn(|_| {
            let id = NOTIFY_TARGET.lock().unwrap().unwrap();
            task::notify(id, 0b001).unwrap();
            task::notify(id, 0b100).unwrap();
        }, 0).unwrap();
    });
}

static SUSPEND_ME: StdMutex<Option<task::TaskId>> = StdMutex::new(None);
static SUSP_SEM: Semaphore = Semaphore::binary();

#[test]
fn suspend_interrupts_wait_and_resume_restarts() {
    let _serial = serial();
    sim::run_to_completion(|| {
        take_log();
        let id = task::Builder::new("victim").priority(4).spawn(|_| {
            let r = SUSP_SEM.take(Timeout::Forever);
            log(format!("victim woke {r:?} at {}", time::ticks()));
        }, 0).unwrap();
        *SUSPEND_ME.lock().unwrap() = Some(id);
        task::Builder::new("ctl").priority(2).spawn(|_| {
            let id = SUSPEND_ME.lock().unwrap().unwrap();
            task::sleep_ticks(5);
            task::suspend(id).unwrap();
            task::sleep_ticks(5);
            log("resuming");
            task::resume(id).unwrap();
        }, 0).unwrap();
    });
    assert_eq!(take_log(), ["resuming", "victim woke Err(Interrupted) at 10"]);
}

static ST_A: Stack<1024> = Stack::new();

#[test]
fn static_stack_is_exclusive_and_reusable() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::spawn("a", 3, &ST_A, |_| {}, 0).unwrap();
        assert_eq!(task::spawn("b", 3, &ST_A, |_| {}, 0), Err(Error::Busy));
    });
    // After the run the stack is released and can be used again.
    sim::run_to_completion(|| {
        task::spawn("a2", 3, &ST_A, |_| {}, 0).unwrap();
    });
}

#[test]
fn task_list_reports_stack_usage() {
    let _serial = serial();
    sim::run_to_completion(|| {
        task::Builder::new("ps").priority(3).spawn(|_| {
            let mut infos = [task::TaskInfo {
                id: task::current(),
                name: "",
                state: bismuth::TaskState::Free,
                priority: 0,
                base_priority: 0,
                run_ticks: 0,
                stack_size: 0,
                stack_free: 0,
            }; 16];
            let n = task::list(&mut infos);
            let names: Vec<_> = infos[..n].iter().map(|t| t.name).collect();
            assert!(names.contains(&"idle") && names.contains(&"ps"), "{names:?}");
            let me = infos[..n].iter().find(|t| t.name == "ps").unwrap();
            assert_eq!(me.priority, 3);
            assert!(me.stack_size > 0 && me.stack_free <= me.stack_size);
        }, 0).unwrap();
    });
}
