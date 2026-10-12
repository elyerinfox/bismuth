# POSIX compatibility

Module: `bismuth::compat::posix` (feature `posix`, on by default). Source:
`src/compat/posix/`. It is a PSE51/PSE52-style subset for embedded systems, built on the
same kernel objects and drivers as the native API.

```rust
use bismuth::compat::posix::*;
```

## Conventions

- **Safe Rust signatures, not a C ABI.** Out-parameters are `&mut T`, buffers are slices,
  paths and names are `&str`, and optional arguments are `Option<..>`. A thread start
  routine is `fn(usize) -> usize`, not `void *(*)(void *)`.
  **Planned:** the `posix-abi` feature, which would export `extern "C"` symbols
  (`pthread_create`, `open`, ...). It is declared in `Cargo.toml` but not implemented.
- **Return values follow POSIX.** `pthread_*` functions return `0` or an error number.
  Other functions return `-1` (or a negative `isize`) and set `errno`.
- **`errno` is per task** (stored in the TCB). Read it with `errno()` and set it with
  `set_errno(e)`. The values are the Linux/newlib numbers in `compat::errno`. See
  [errors](../reference/errors.md).
- **One process.** All tasks share one address space and **one global file-descriptor
  table**, like the threads of a single POSIX process.
- **Security domains.** In an isolated domain, `open("/dev/x")` resolves `x` in the
  domain's own namespace through `DeviceCap`, so rights are checked on every operation.
  See [security](../design/security.md#devicecap-flow).

## `<pthread.h>` and `<sched.h>`

| function / item | notes |
|-----------------|-------|
| `pthread_t` | `u32`, the raw `TaskId` |
| `pthread_attr_init`, `_destroy` | default: joinable, priority 1, name `"pthread"`, stack `POOL_STACK_SIZE` |
| `pthread_attr_setdetachstate`, `_getdetachstate` | `PTHREAD_CREATE_JOINABLE` / `PTHREAD_CREATE_DETACHED` |
| `pthread_attr_setstacksize`, `_getstacksize` | Accepts 256..=`POOL_STACK_SIZE`, else `EINVAL`. The value is only recorded: every pthread runs on a pool stack of exactly `POOL_STACK_SIZE` bytes. |
| `pthread_attr_setschedparam`, `_getschedparam` | `sched_priority` in 1..=31, higher is more urgent |
| `pthread_attr_setname_np` | thread name for diagnostics (`&'static str`) |
| `pthread_create(&mut t, Option<&attr>, start, arg)` | runs on a pool stack. `EAGAIN` when the task table or start-record table is full, `ENOMEM` when the stack pool is empty. |
| `pthread_join(t, Option<&mut usize>)`, `pthread_detach`, `pthread_exit` | `ESRCH` for an unknown thread; `EDEADLK` when joining yourself |
| `pthread_self`, `pthread_equal` | `pthread_equal` returns `bool` |
| `pthread_setschedparam`, `pthread_getschedparam` | the policy argument is ignored; `get` always reports `SCHED_FIFO` |
| `sched_yield`, `sched_get_priority_min/max` | 1 / 31 |

**Mutexes** (`pthread_mutex_t`, always priority-inheriting):

| function / item | notes |
|-----------------|-------|
| `PTHREAD_MUTEX_INITIALIZER`, `PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP` | static initialisers |
| `pthread_mutexattr_init`, `_settype` | `PTHREAD_MUTEX_NORMAL`, `_RECURSIVE`, `_ERRORCHECK`, `_DEFAULT` |
| `pthread_mutexattr_setprotocol` | `PTHREAD_PRIO_INHERIT` only, anything else is `ENOTSUP` |
| `pthread_mutex_init(&m, Option<&attr>)` | sets the recursive flag; `EBUSY` if locked |
| `pthread_mutex_destroy` | `EBUSY` if locked |
| `pthread_mutex_lock`, `_trylock`, `_timedlock(&m, &abstime)`, `_unlock` | `trylock` returns `EBUSY`; `unlock` by a non-owner returns `EPERM` |

**Condition variables** (`pthread_cond_t`):

| function / item | notes |
|-----------------|-------|
| `PTHREAD_COND_INITIALIZER`, `pthread_cond_init`, `_destroy` | `init` and `destroy` are no-ops |
| `pthread_cond_wait`, `_timedwait(&c, &m, &abstime)` | `timedwait` returns `ETIMEDOUT`; the mutex must be held exactly once |
| `pthread_cond_signal`, `_broadcast` | |

**Thread-specific data and once:**

| function / item | notes |
|-----------------|-------|
| `pthread_key_create`, `_delete`, `pthread_setspecific`, `pthread_getspecific` | 4 keys system-wide and 4 slots per task; values are `usize`; **destructors are ignored** |
| `PTHREAD_ONCE_INIT`, `pthread_once(&once, fn())` | |

```rust
static LOCK: pthread_mutex_t = PTHREAD_MUTEX_INITIALIZER;

fn worker(n: usize) -> usize {
    pthread_mutex_lock(&LOCK);
    /* ... */
    pthread_mutex_unlock(&LOCK);
    n * 10
}

let mut attr = pthread_attr_t::default();
pthread_attr_init(&mut attr);
pthread_attr_setschedparam(&mut attr, &sched_param { sched_priority: 3 });
let mut t: pthread_t = 0;
assert_eq!(pthread_create(&mut t, Some(&attr), worker, 1), 0);
let mut ret = 0;
pthread_join(t, Some(&mut ret));   // ret == 10
```

## `<semaphore.h>`

| function / item | notes |
|-----------------|-------|
| `sem_t`, `SEM_INITIALIZER` | initial value 0 |
| `SEM_VALUE_MAX` | `i32::MAX` |
| `sem_init(&s, pshared, value)` | `pshared` must be 0 (there is a single address space) |
| `sem_destroy` | no-op |
| `sem_wait`, `sem_trywait`, `sem_timedwait(&s, &abstime)` | `trywait` returns `EAGAIN`; `timedwait` returns `ETIMEDOUT` |
| `sem_post`, `sem_getvalue` | `post` returns `EOVERFLOW` at the maximum |

Named semaphores (`sem_open`) are not provided.

## `<time.h>`

| function / item | notes |
|-----------------|-------|
| `timespec { tv_sec: i64, tv_nsec: i64 }`, `clockid_t`, `time_t` | |
| `CLOCK_MONOTONIC` | ticks since start |
| `CLOCK_REALTIME` | monotonic + offset; the offset is set by `clock_settime`, for example after SNTP |
| `clock_gettime`, `clock_settime` | `clock_settime` accepts `CLOCK_REALTIME` only |
| `clock_getres` | one tick |
| `nanosleep(&req, Option<&mut rem>)` | Rounds up to whole ticks. Never interrupted, so `rem` is always zero. |
| `time(Option<&mut time_t>)` | |

Absolute timeouts (`*_timedwait`, `*_timedlock`, `mq_timed*`) are `CLOCK_REALTIME`
deadlines, converted to ticks when the call is made.

## `<unistd.h>`, `<fcntl.h>`, `<sys/ioctl.h>`, `<poll.h>`

One descriptor table (`MAX_FDS`, default 16) covers the console, devices and sockets.

| function / item | notes |
|-----------------|-------|
| fds 0, 1, 2 (`STDIN_FILENO` …) | The console. Writes go to `kprint` output. Reads and ioctls go to the console device, if one is set (`console::set_device`); with none, reads fail with `EAGAIN`. |
| `open(path, flags)` | Only `/dev/<name>` paths; anything else is `ENOENT`. Flags are `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_NONBLOCK`. There is no file system, so `O_CREAT` and similar flags are ignored. |
| `close`, `read`, `write` | Go through the device's middleware chain. `read` on an `O_WRONLY` fd, or `write` on an `O_RDONLY` one, returns `EBADF`. |
| `ioctl(fd, cmd: u32, arg: usize) -> isize` | Returns the driver's value. An unsupported command returns `ENOTTY`. Numbers are in the [ioctl reference](../reference/ioctl.md). |
| `fcntl(fd, F_GETFL \| F_SETFL, arg)` | Only `O_NONBLOCK` can be changed. |
| `isatty` | 1 for the console and for `Char`-class devices |
| `sleep(s)`, `usleep(us)` | `usleep` rounds up to whole milliseconds, then to ticks |
| `poll(&mut [pollfd], timeout_ms)` | `POLLIN` and `POLLOUT`; `POLLNVAL` for a bad fd; `timeout_ms < 0` waits forever |

`poll` details:

- It **re-checks readiness every tick**; it is not event-driven, so wake-up latency is
  up to one tick.
- Character devices are readable when `SERIAL_RX_AVAILABLE > 0`. Other device classes
  always report ready.
- Sockets report readable when data is waiting, a connection is pending, or the peer
  has closed.
- `POLLERR` and `POLLHUP` are defined but never reported.

`select`, `dup`, `pipe()`, `lseek` and file-system calls are not provided. For an
in-memory pipe, register a `driver::char::Pipe` device and `open` it.

## `<termios.h>`

`tcgetattr`, `tcsetattr` (`TCSANOW`/`TCSADRAIN`/`TCSAFLUSH`), the `cf*speed`
functions, `cfmakeraw`, `tcflush` and `tcdrain` work on fds whose device has a `Tty`
line discipline attached, and only from **trusted** code; other fds, and isolated
domains, get `ENOTTY`. `TCSADRAIN` and `TCSAFLUSH` currently behave like `TCSANOW`, and
speeds are not applied to hardware. The type is `Termios`; there is no lowercase alias. Details and
limitations: [design/tty.md](../design/tty.md).

## `<mqueue.h>`

| function / item | notes |
|-----------------|-------|
| `mq_open(name, oflag, Option<&mq_attr>)` | Name starts with `/` and has at most 32 bytes. `O_CREAT`, `O_EXCL`, access mode, `O_NONBLOCK`. The default attributes are 8 messages × 64 bytes. |
| `mq_close`, `mq_unlink` | Unlinking defers destruction until the last descriptor is closed. |
| `mq_getattr` | |
| `mq_send`, `mq_timedsend` | priority below `MQ_PRIO_MAX` (32); a message longer than `mq_msgsize` is `EMSGSIZE` |
| `mq_receive`, `mq_timedreceive` | Delivers the highest priority first, FIFO within a priority. The buffer must hold at least `mq_msgsize` bytes, else `EMSGSIZE`. |

Limits:

- `MAX_MQUEUES` queues (default 4), each with `MQUEUE_BYTES` (default 512) of storage.
- `mq_maxmsg` ≤ 32, and `mq_maxmsg × mq_msgsize` ≤ `MQUEUE_BYTES`.
- `mqd_t` descriptors come from their own table (`2 × MAX_MQUEUES + 4` entries), so they
  cannot be passed to `poll`.
- `mq_setattr` and `mq_notify` are not provided.

## Sockets

`<sys/socket.h>`, available with the `net-ip` feature, built on `net::socket`.

| function / item | notes |
|-----------------|-------|
| `socket(AF_INET, SOCK_STREAM \| SOCK_DGRAM, _)` | IPv4 only; anything else is `ENOTSUP` |
| `bind(fd, &sockaddr_in)` | The port is used; the address is ignored. UDP binds immediately; TCP remembers the port for `listen`. |
| `listen(fd, _backlog)` | Needs a prior `bind` to a non-zero port. The backlog is ignored: one pending connection at a time. |
| `accept(fd, Option<&mut sockaddr_in>)` | Returns a new fd. **The peer address is not filled in** (it is zeroed). |
| `connect(fd, &sockaddr_in)` | TCP only, with a fixed 30-second timeout |
| `send`, `recv`, `sendto`, `recvfrom` | Flags are ignored. A UDP `sendto` on an unbound socket binds an ephemeral port implicitly. A TCP `send` accepts at most one 1536-byte block per call (short write). |
| `setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, ms)` | The only supported option; the value is milliseconds as a `u32`, not a `timeval` |
| `sockaddr_in { sin_family, sin_port, sin_addr }`, `sockaddr_in::new(Ipv4Addr, port)` | port and address in network byte order |
| `htons`, `ntohs`, `htonl`, `ntohl`, `INADDR_ANY` | |

More limitations:

- Sockets always use the **first** IP interface. The native API
  (`UdpSocket::bind_on`, `TcpStream::connect_on`) can choose an interface.
- Not provided: `shutdown`, `getsockname`, `getpeername`, `select`, `getaddrinfo` and
  DNS, `SO_REUSEADDR`, IPv6.
- Every bind, connect and listen is checked against the calling domain's network
  policy.

## Known deviations from POSIX

- `PTHREAD_MUTEX_NORMAL` relocking returns `EDEADLK` rather than deadlocking. Normal
  mutexes behave like `ERRORCHECK` ones.
- `pthread_attr_setstacksize` does not change the actual stack size.
- `pthread_key_create` destructors never run.
- There are no signals, so `EINTR` only comes from a suspended or aborted wait.
- There is no `fork` or `exec`, no processes, and no file system.
