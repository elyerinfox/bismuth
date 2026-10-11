//! POSIX compatibility layer, written the way a C programmer would use the API.

use std::net::Ipv4Addr;
use std::sync::Mutex as StdMutex;

use bismuth::compat::posix::*;
use bismuth::driver;
use bismuth::driver::char::Pipe;
use bismuth::net::drivers::{Wire, WireEnd};
use bismuth::net::ip::{self, IpConfig};
use bismuth::net::{self, SoftRing};
use bismuth::sim;
use bismuth::task;

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

/// Run `main` as the single initial task.
fn run_main(main: fn(usize)) {
    sim::run_to_completion(|| {
        task::Builder::new("main").priority(5).spawn(main, 0).unwrap();
    });
}

static COUNTER_LOCK: pthread_mutex_t = PTHREAD_MUTEX_INITIALIZER;
static COUNTER: StdMutex<u32> = StdMutex::new(0);

fn worker(n: usize) -> usize {
    for _ in 0..100 {
        assert_eq!(pthread_mutex_lock(&COUNTER_LOCK), 0);
        *COUNTER.lock().unwrap() += 1;
        sched_yield();
        assert_eq!(pthread_mutex_unlock(&COUNTER_LOCK), 0);
    }
    n * 10
}

#[test]
fn pthread_create_join_and_mutex() {
    let _serial = serial();
    *COUNTER.lock().unwrap() = 0;
    run_main(|_| {
        let mut threads = [0 as pthread_t; 3];
        let mut attr = pthread_attr_t::default();
        pthread_attr_init(&mut attr);
        pthread_attr_setschedparam(&mut attr, &sched_param { sched_priority: 3 });
        for (i, t) in threads.iter_mut().enumerate() {
            assert_eq!(pthread_create(t, Some(&attr), worker, i + 1), 0);
        }
        for (i, t) in threads.iter().enumerate() {
            let mut ret = 0;
            assert_eq!(pthread_join(*t, Some(&mut ret)), 0);
            assert_eq!(ret, (i + 1) * 10);
        }
        assert_eq!(*COUNTER.lock().unwrap(), 300);
        assert_eq!(pthread_join(threads[0], None), ESRCH);
        let mut policy = 0;
        let mut p = sched_param { sched_priority: 0 };
        assert_eq!(pthread_getschedparam(pthread_self(), &mut policy, &mut p), 0);
        assert_eq!(p.sched_priority, 5);
    });
}

static REC: pthread_mutex_t = PTHREAD_MUTEX_INITIALIZER;
static PLAIN: pthread_mutex_t = PTHREAD_MUTEX_INITIALIZER;

#[test]
fn mutex_types_and_trylock() {
    let _serial = serial();
    run_main(|_| {
        let mut a = pthread_mutexattr_t::default();
        pthread_mutexattr_init(&mut a);
        pthread_mutexattr_settype(&mut a, PTHREAD_MUTEX_RECURSIVE);
        assert_eq!(pthread_mutexattr_setprotocol(&mut a, PTHREAD_PRIO_INHERIT), 0);
        assert_eq!(pthread_mutex_init(&REC, Some(&a)), 0);
        assert_eq!(pthread_mutex_lock(&REC), 0);
        assert_eq!(pthread_mutex_lock(&REC), 0);
        assert_eq!(pthread_mutex_unlock(&REC), 0);
        assert_eq!(pthread_mutex_unlock(&REC), 0);
        assert_eq!(pthread_mutex_unlock(&REC), EPERM);

        assert_eq!(pthread_mutex_init(&PLAIN, None), 0);
        assert_eq!(pthread_mutex_lock(&PLAIN), 0);
        assert_eq!(pthread_mutex_lock(&PLAIN), EDEADLK);
        let mut t = 0;
        pthread_create(&mut t, None, |_| pthread_mutex_trylock(&PLAIN) as usize, 0);
        let mut r = 0;
        pthread_join(t, Some(&mut r));
        assert_eq!(r as i32, EBUSY);
        assert_eq!(pthread_mutex_destroy(&PLAIN), EBUSY);
        pthread_mutex_unlock(&PLAIN);
    });
}

static Q_LOCK: pthread_mutex_t = PTHREAD_MUTEX_INITIALIZER;
static Q_COND: pthread_cond_t = PTHREAD_COND_INITIALIZER;
static ITEMS: StdMutex<Vec<u32>> = StdMutex::new(Vec::new());

#[test]
fn condition_variable_producer_consumer_and_timedwait() {
    let _serial = serial();
    ITEMS.lock().unwrap().clear();
    run_main(|_| {
        let mut c = 0;
        pthread_create(&mut c, None, |_| {
            let mut got = 0;
            while got < 5 {
                pthread_mutex_lock(&Q_LOCK);
                while ITEMS.lock().unwrap().is_empty() {
                    pthread_cond_wait(&Q_COND, &Q_LOCK);
                }
                got += ITEMS.lock().unwrap().drain(..).count();
                pthread_mutex_unlock(&Q_LOCK);
            }
            got
        }, 0);
        for i in 0..5 {
            usleep(2000);
            pthread_mutex_lock(&Q_LOCK);
            ITEMS.lock().unwrap().push(i);
            pthread_cond_signal(&Q_COND);
            pthread_mutex_unlock(&Q_LOCK);
        }
        let mut got = 0;
        pthread_join(c, Some(&mut got));
        assert_eq!(got, 5);

        // Timed wait that expires.
        let mut now = timespec::default();
        clock_gettime(CLOCK_REALTIME, &mut now);
        let deadline = timespec { tv_sec: now.tv_sec, tv_nsec: now.tv_nsec + 30_000_000 };
        let deadline = timespec { tv_sec: deadline.tv_sec + deadline.tv_nsec / 1_000_000_000, tv_nsec: deadline.tv_nsec % 1_000_000_000 };
        pthread_mutex_lock(&Q_LOCK);
        assert_eq!(pthread_cond_timedwait(&Q_COND, &Q_LOCK, &deadline), ETIMEDOUT);
        assert_eq!(pthread_mutex_unlock(&Q_LOCK), 0, "mutex re-acquired after timeout");
    });
}

static SEM: sem_t = SEM_INITIALIZER;

#[test]
fn semaphores() {
    let _serial = serial();
    run_main(|_| {
        assert_eq!(sem_init(&SEM, 0, 2), 0);
        assert_eq!(sem_init(&SEM, 1, 0), -1);
        assert_eq!(errno(), EINVAL);
        assert_eq!(sem_trywait(&SEM), 0);
        assert_eq!(sem_wait(&SEM), 0);
        assert_eq!(sem_trywait(&SEM), -1);
        assert_eq!(errno(), EAGAIN);
        let mut t = 0;
        pthread_create(&mut t, None, |_| {
            usleep(5000);
            sem_post(&SEM) as usize
        }, 0);
        assert_eq!(sem_wait(&SEM), 0);
        let mut v = -1;
        sem_getvalue(&SEM, &mut v);
        assert_eq!(v, 0);
        pthread_join(t, None);
    });
}

#[test]
fn clocks_and_sleep() {
    let _serial = serial();
    run_main(|_| {
        let mut a = timespec::default();
        let mut b = timespec::default();
        assert_eq!(clock_gettime(CLOCK_MONOTONIC, &mut a), 0);
        assert_eq!(nanosleep(&timespec { tv_sec: 1, tv_nsec: 500_000_000 }, None), 0);
        clock_gettime(CLOCK_MONOTONIC, &mut b);
        let elapsed_ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1_000_000;
        assert_eq!(elapsed_ms, 1500);
        // Set wall-clock time (e.g. after SNTP) and read it back.
        assert_eq!(clock_settime(CLOCK_REALTIME, &timespec { tv_sec: 1_700_000_000, tv_nsec: 0 }), 0);
        assert_eq!(time(None), 1_700_000_000);
        sleep(2);
        assert_eq!(time(None), 1_700_000_002);
        assert_eq!(clock_settime(CLOCK_MONOTONIC, &a), -1);
        assert_eq!(errno(), EINVAL);
        assert_eq!(nanosleep(&timespec { tv_sec: 0, tv_nsec: 2_000_000_000 }, None), -1);
        let mut res = timespec::default();
        clock_getres(CLOCK_MONOTONIC, &mut res);
        assert_eq!(res, timespec { tv_sec: 0, tv_nsec: 1_000_000 });
    });
}

#[test]
fn message_queues_priority_order_and_errors() {
    let _serial = serial();
    run_main(|_| {
        let attr = mq_attr { mq_flags: 0, mq_maxmsg: 4, mq_msgsize: 16, mq_curmsgs: 0 };
        let q = mq_open("/sensors", O_CREAT | O_RDWR, Some(&attr));
        assert!(q >= 0);
        assert_eq!(mq_open("/sensors", O_CREAT | O_EXCL | O_RDWR, Some(&attr)), -1);
        assert_eq!(errno(), EEXIST);
        assert_eq!(mq_send(q, b"low", 1), 0);
        assert_eq!(mq_send(q, b"high", 9), 0);
        assert_eq!(mq_send(q, b"low2", 1), 0);
        assert_eq!(mq_send(q, &[0u8; 17], 0), -1);
        assert_eq!(errno(), EMSGSIZE);
        let mut a = mq_attr::default();
        mq_getattr(q, &mut a);
        assert_eq!(a.mq_curmsgs, 3);
        let mut buf = [0u8; 16];
        let mut prio = 0;
        let n = mq_receive(q, &mut buf, Some(&mut prio));
        assert_eq!((&buf[..n as usize], prio), (&b"high"[..], 9));
        let n = mq_receive(q, &mut buf, Some(&mut prio));
        assert_eq!(&buf[..n as usize], b"low");
        let n = mq_receive(q, &mut buf, None);
        assert_eq!(&buf[..n as usize], b"low2");
        // A second task opens the same queue by name and fills it while we block.
        let mut t = 0;
        pthread_create(&mut t, None, |_| {
            let q = mq_open("/sensors", O_WRONLY, None);
            for i in 0..6u8 {
                mq_send(q, &[i], 0); // blocks when full (maxmsg = 4)
            }
            mq_close(q) as usize
        }, 0);
        let mut seen = Vec::new();
        for _ in 0..6 {
            let n = mq_receive(q, &mut buf, None);
            seen.push(buf[..n as usize][0]);
        }
        assert_eq!(seen, [0, 1, 2, 3, 4, 5]);
        pthread_join(t, None);
        // Non-blocking empty receive.
        let qn = mq_open("/sensors", O_RDONLY | O_NONBLOCK, None);
        assert_eq!(mq_receive(qn, &mut buf, None), -1);
        assert_eq!(errno(), EAGAIN);
        assert_eq!(mq_unlink("/sensors"), 0);
        assert_eq!(mq_open("/sensors", O_RDONLY, None), -1);
        assert_eq!(errno(), ENOENT);
    });
}

static KEY: StdMutex<pthread_key_t> = StdMutex::new(0);
static ONCE: pthread_once_t = PTHREAD_ONCE_INIT;
static ONCE_RUNS: StdMutex<u32> = StdMutex::new(0);

#[test]
fn thread_specific_data_and_once() {
    let _serial = serial();
    *ONCE_RUNS.lock().unwrap() = 0;
    run_main(|_| {
        let mut k = 0;
        assert_eq!(pthread_key_create(&mut k, None), 0);
        *KEY.lock().unwrap() = k;
        pthread_setspecific(k, 111);
        let mut ts = [0; 3];
        for (i, t) in ts.iter_mut().enumerate() {
            pthread_create(t, None, |i| {
                let k = *KEY.lock().unwrap();
                pthread_once(&ONCE, || *ONCE_RUNS.lock().unwrap() += 1);
                pthread_setspecific(k, i);
                usleep(1000);
                pthread_getspecific(k)
            }, 200 + i);
        }
        for (i, t) in ts.iter().enumerate() {
            let mut r = 0;
            pthread_join(*t, Some(&mut r));
            assert_eq!(r, 200 + i, "each thread sees its own value");
        }
        assert_eq!(pthread_getspecific(k), 111);
        assert_eq!(*ONCE_RUNS.lock().unwrap(), 1);
    });
}

static TTY: Pipe<64> = Pipe::new();

#[test]
fn file_descriptors_on_devices_and_poll() {
    let _serial = serial();
    take_log();
    sim::run_to_completion(|| {
        driver::register("ttyS0", &TTY).unwrap();
        task::Builder::new("main").priority(5).spawn(|_| {
            let fd = open("/dev/ttyS0", O_RDWR);
            assert!(fd >= 3, "fds 0-2 are the console");
            assert_eq!(isatty(fd), 1);
            assert_eq!(open("/dev/nope", O_RDWR), -1);
            assert_eq!(errno(), ENOENT);
            // Nothing to read yet: poll times out, non-blocking read fails with EAGAIN.
            let mut p = [pollfd { fd, events: POLLIN, revents: 0 }];
            assert_eq!(poll(&mut p, 10), 0);
            fcntl(fd, F_SETFL, O_NONBLOCK);
            let mut buf = [0u8; 16];
            assert_eq!(read(fd, &mut buf), -1);
            assert_eq!(errno(), EAGAIN);
            assert_eq!(write(fd, b"hello"), 5);
            assert_eq!(poll(&mut p, -1), 1);
            assert_eq!(p[0].revents, POLLIN);
            assert_eq!(ioctl(fd, bismuth::driver::ioctl::SERIAL_RX_AVAILABLE, 0), 5);
            assert_eq!(read(fd, &mut buf), 5);
            assert_eq!(&buf[..5], b"hello");
            assert_eq!(ioctl(fd, 0xDEAD, 0), -1);
            assert_eq!(errno(), ENOTTY);
            assert_eq!(close(fd), 0);
            assert_eq!(read(fd, &mut buf), -1);
            assert_eq!(errno(), EBADF);
            assert_eq!(write(STDOUT_FILENO, b"posix stdout ok\n"), 16);
            log("done");
        }, 0).unwrap();
    });
    assert_eq!(take_log(), ["done"]);
}

static WIRE: Wire = Wire::new();
static ETH_A: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 0, [2, 0, 0, 0, 0, 1]));
static ETH_B: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 1, [2, 0, 0, 0, 0, 2]));

#[test]
fn bsd_sockets_tcp_and_udp() {
    let _serial = serial();
    sim::run_to_completion(|| {
        // Only the first IP interface is the default for BSD sockets; give it the
        // server role and talk to it from the native API on the other interface.
        let a = net::register("eth0", &ETH_A).unwrap();
        let b = net::register("eth1", &ETH_B).unwrap();
        ip::configure(a, IpConfig { addr: [192, 168, 1, 10], prefix_len: 24, gateway: None }).unwrap();
        ip::configure(b, IpConfig { addr: [192, 168, 1, 20], prefix_len: 24, gateway: None }).unwrap();
        net::start().unwrap();
        task::Builder::new("server").priority(6).spawn(|_| {
            let s = socket(AF_INET, SOCK_STREAM, 0);
            assert_eq!(bind(s, &sockaddr_in::new(Ipv4Addr::UNSPECIFIED, 7000)), 0);
            assert_eq!(listen(s, 1), 0);
            let c = accept(s, None);
            assert!(c >= 0);
            let mut buf = [0u8; 64];
            let n = recv(c, &mut buf, 0);
            assert_eq!(&buf[..n as usize], b"GET /temp");
            assert_eq!(send(c, b"21.5C", 0), 5);
            close(c);
            close(s);

            let u = socket(AF_INET, SOCK_DGRAM, 0);
            bind(u, &sockaddr_in::new(Ipv4Addr::UNSPECIFIED, 7001));
            setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, 1000);
            let mut from = sockaddr_in::default();
            let n = recvfrom(u, &mut buf, 0, Some(&mut from));
            assert_eq!(&buf[..n as usize], b"ping");
            assert_eq!(ntohs(from.sin_port), 5555);
            sendto(u, b"pong", 0, &from);
            close(u);
        }, 0).unwrap();
        task::Builder::new("client").priority(5).spawn(|b| {
            use bismuth::net::socket::{TcpStream, UdpSocket};
            use bismuth::Timeout;
            use std::net::SocketAddrV4;
            let b = bismuth::net::IfIndex(b as u8);
            let srv = |p| SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), p);
            let c = TcpStream::connect_on(b, srv(7000), Timeout::ms(2000)).unwrap();
            c.write_all(b"GET /temp").unwrap();
            let mut buf = [0u8; 16];
            let n = c.read(&mut buf, Timeout::ms(2000)).unwrap();
            assert_eq!(&buf[..n], b"21.5C");
            drop(c);
            task::sleep_ms(50);
            let u = UdpSocket::bind_on(b, 5555).unwrap();
            u.send_to(b"ping", srv(7001)).unwrap();
            let (n, _) = u.recv_from(&mut buf, Timeout::ms(2000)).unwrap();
            assert_eq!(&buf[..n], b"pong");
        }, b.0 as usize).unwrap();
    });
}
