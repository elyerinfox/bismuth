# Errors

Bismuth has one error type, `bismuth::Error` (`src/error.rs`). It is `Copy`, implements
`Display` and `core::error::Error`, and maps one-to-one onto a POSIX `errno` through
`Error::errno()`. The numbers are the Linux/newlib values defined in
`bismuth::compat::errno`.

## `Error` ↔ `errno`

| `Error` | `errno` | value | typical sources |
|---------|---------|------:|-----------------|
| `Timeout` | `ETIMEDOUT` | 110 | a blocking call reached its `Timeout::Ticks` deadline |
| `WouldBlock` | `EAGAIN` | 11 | `Timeout::NoWait` and the operation could not complete; a blocking call from an ISR or before `start`; `O_NONBLOCK` |
| `Invalid` | `EINVAL` | 22 | bad argument (priority out of range, stack < 256 B, bad attrs, zero mask) |
| `NoResources` | `EAGAIN` | 11 | a fixed table is full (tasks, devices, fds, timers, layers, handles, domains, sockets) |
| `NoMemory` | `ENOMEM` | 12 | a pool is exhausted (stack pool, packet pools via `try_alloc`) |
| `NotFound` | `ENOENT` | 2 | unknown device or name; stale `TaskId`; not in the domain namespace |
| `Exists` | `EEXIST` | 17 | name already registered; `O_CREAT \| O_EXCL` on an existing queue |
| `Busy` | `EBUSY` | 16 | resource claimed (static stack in use, locked mutex reconfigured) |
| `NotOwner` | `EPERM` | 1 | unlocking a mutex you do not own; condvar wait without holding the mutex exactly once |
| `Deadlock` | `EDEADLK` | 35 | relocking a non-recursive mutex; joining yourself |
| `Interrupted` | `EINTR` | 4 | the wait was cancelled (task suspended while blocked) |
| `Unsupported` | `ENOTSUP` | 95 | driver or device does not support the op or ioctl (POSIX `ioctl` reports `ENOTTY` instead) |
| `PermissionDenied` | `EACCES` | 13 | missing handle right; no ambient authority; middleware policy; domain policy (ceiling, network, seal) |
| `Io` | `EIO` | 5 | hardware or transfer error; I2C NACK; TCP connection refused or reset |
| `NotReady` | `ENODEV` | 19 | device powered down or unbound; entropy unseeded; keystore self-test failed; IP stack not running |
| `Overflow` | `EOVERFLOW` | 75 | value out of range (semaphore at max, header does not fit, datagram too big) |
| `BadHandle` | `EBADF` | 9 | bad fd, stale `Device`, forged, stale or revoked security handle |
| `Integrity` | `EBADMSG` | 74 | AEAD tag or MAC mismatch; failed known-answer self-test |
| `NotADirectory` | `ENOTDIR` | 20 | a path component used as a directory is not one (walking through a file; `rmdir`/`opendir` on a non-directory) |
| `IsADirectory` | `EISDIR` | 21 | a directory where a file was required (`open` or `unlink` on a directory) |
| `NotEmpty` | `ENOTEMPTY` | 39 | `rmdir` on a populated directory |
| `ReadOnly` | `EROFS` | 30 | a mutation on a read-only device or mount (`block::ReadOnly`'s `prog`/`erase`) |
| `NameTooLong` | `ENAMETOOLONG` | 36 | a path over `FS_PATH_MAX` or a component over `FS_NAME_MAX` |
| `NoSpace` | `ENOSPC` | 28 | a filesystem or medium is out of space (the RamFs arena is full) |

Two notes on this table:

- `WouldBlock` and `NoResources` both map to `EAGAIN`, because POSIX uses `EAGAIN` for
  "temporarily out of resources".
- In an isolated domain, `BadHandle` is also a **security violation**. Under
  `BadHandlePolicy::Kill`, it terminates the whole domain. See
  [security](../design/security.md#violations-and-the-bad-handle-policy).

## Other error numbers used by the compatibility layers

These come from `compat::errno` without a matching `Error` variant:

| `errno` | value | returned by |
|---------|------:|-------------|
| `ESRCH` | 3 | `pthread_join`, `pthread_detach`, `pthread_getschedparam` on an unknown thread |
| `ENOTTY` | 25 | `ioctl` on a device that does not support the command; `isatty` on a non-terminal |
| `EMSGSIZE` | 90 | `mq_send` with a message over `mq_msgsize`; `mq_receive` with a buffer under `mq_msgsize` |

`compat::errno` also defines constants that nothing returns today, for C compatibility:
`EFAULT` (14), `EMFILE` (24), `ENOSYS` (38). (`ENOSPC`, `ENAMETOOLONG`, `ENOTDIR`,
`EISDIR`, `EROFS` and `ENOTEMPTY` are now produced by the filesystem — see the table
above.)

## Ecosystem error mappings (`hal-compat`)

`Error` implements the error traits of `embedded-io` and `embedded-hal`, so Bismuth
devices can be used directly by ecosystem drivers.

`embedded_io::Error::kind`:

| `Error` | `embedded_io::ErrorKind` |
|---------|--------------------------|
| `Timeout` | `TimedOut` |
| `Interrupted` | `Interrupted` |
| `Invalid`, `BadHandle`, `Overflow` | `InvalidInput` |
| `NotFound`, `NotReady` | `NotFound` |
| `PermissionDenied`, `NotOwner` | `PermissionDenied` |
| `Exists` | `AlreadyExists` |
| `NoMemory`, `NoResources` | `OutOfMemory` |
| `Unsupported` | `Unsupported` |
| everything else | `Other` |

`embedded_hal::i2c::Error::kind`:

| `Error` | `embedded_hal::i2c::ErrorKind` |
|---------|--------------------------------|
| `Io` | `NoAcknowledge(Unknown)` |
| `Busy` | `ArbitrationLoss` |
| everything else | `Other` |

`embedded_hal::digital::Error::kind` is always `Other`.

In the other direction, `HalI2cDriver` maps a HAL `NoAcknowledge` to `Io` and
`ArbitrationLoss` to `Busy`. Every other HAL error becomes `Io`.

## FreeRTOS layer

The FreeRTOS layer does not expose `Error`. Its functions return `pdPASS`, `pdFAIL`,
`errQUEUE_FULL`/`errQUEUE_EMPTY` (0) or `errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY` (−1),
as FreeRTOS does. See [FreeRTOS porting](../guides/freertos-porting.md).
