# ioctl numbers

Defined in `bismuth::driver::ioctl` (`src/driver/ioctl.rs`). The high byte of a
command selects its class. An ioctl travels as `Op::Ioctl { cmd: u32, arg: usize }`
through the device's middleware chain, and the driver's value comes back as
`Ok(usize)`.

**Required rights.** An isolated domain goes through `DeviceCap`, and its handle must
carry the right returned by `ioctl::required_right(cmd)` **before** the chain runs.
Commands that query state or perform ordinary operations need `CONTROL`. Commands that
reconfigure a device need `CONFIG`, and so does **any command not in the list**, which
makes new or driver-specific ioctls deny-by-default. Trusted domains are not checked.

## Generic (0x00xx)

| command | value | arg | returns | right | implemented by |
|---------|-------|-----|---------|-------|----------------|
| `GET_CLASS` | `0x0001` | none | `DeviceClass` discriminant (see below) | CONTROL | all bundled drivers, `/dev/<ifname>`, `compat::hal` drivers |

`DeviceClass` discriminants: `Char` = 0, `Gpio` = 1, `I2c` = 2, `Spi` = 3, `Sensor` = 4,
`Block` = 5, `Net` = 6, `Display` = 7, `Input` = 8, `Other` = 9. `Other` was 7 before
`Display` and `Input` were added.

## Serial (0x01xx)

| command | value | arg | returns | right | implemented by |
|---------|-------|-----|---------|-------|----------------|
| `SERIAL_SET_BAUD` | `0x0101` | baud rate | 0 | **CONFIG** | `Pl011` (records the value only) |
| `SERIAL_GET_BAUD` | `0x0102` | none | baud rate | CONTROL | `Pl011` |
| `SERIAL_RX_AVAILABLE` | `0x0103` | none | bytes waiting (`Pl011`, `HalSerialDriver`: 0/1) | CONTROL | `Pipe`, `Pl011`, `HalSerialDriver` |
| `SERIAL_FLUSH` | `0x0104` | none | 0 (discards buffered input) | CONTROL | `Pipe` |

Wrappers: `char::Serial::{set_baud, available}`. POSIX `poll` uses
`SERIAL_RX_AVAILABLE` to decide whether a character device is readable.

## GPIO (0x02xx)

`arg` is a pin mask (bit *n* = pin *n*) unless noted.

| command | value | arg | returns | right | implemented by |
|---------|-------|-----|---------|-------|----------------|
| `GPIO_SET` | `0x0201` | mask | 0 | CONTROL | `SimGpio`, `HalOutputPinDriver` (bit 0) |
| `GPIO_CLEAR` | `0x0202` | mask | 0 | CONTROL | `SimGpio`, `HalOutputPinDriver` |
| `GPIO_TOGGLE` | `0x0203` | mask | 0 | CONTROL | `SimGpio`, `HalOutputPinDriver` |
| `GPIO_GET` | `0x0204` | none | pin levels (outputs: latch; inputs: debounced level) | CONTROL | `SimGpio` (+ `Debounce`), `HalOutputPinDriver` |
| `GPIO_CONFIG_OUTPUT` | `0x0205` | mask | 0 | **CONFIG** | `SimGpio`, `HalOutputPinDriver` (no-op) |
| `GPIO_CONFIG_INPUT` | `0x0206` | mask | 0 | **CONFIG** | `SimGpio` |

Wrappers: `gpio::Gpio::{set, clear, toggle, get, is_high, configure_output,
configure_input}` and `compat::hal::Pin`.

## Sensor (0x03xx)

| command | value | arg | returns | right | implemented by |
|---------|-------|-----|---------|-------|----------------|
| `SENSOR_CHANNELS` | `0x0301` | none | channel count (each sample is one LE `i32` per channel) | CONTROL | `SimSensor` |
| `SENSOR_SET_RATE_HZ` | `0x0302` | rate in Hz (non-zero) | 0 | **CONFIG** | `SimSensor` (records the value) |
| `SENSOR_GET_RATE_HZ` | `0x0303` | none | rate in Hz | CONTROL | `SimSensor` |

Wrappers: `sensor::Sensor::{channels, set_rate_hz}`.

## I2C / SPI buses (0x04xx)

| command | value | arg | returns | right | implemented by |
|---------|-------|-----|---------|-------|----------------|
| `BUS_SET_SPEED_HZ` | `0x0401` | bus clock in Hz | 0 | **CONFIG** | `SimI2c` |
| `BUS_GET_SPEED_HZ` | `0x0402` | none | bus clock in Hz | CONTROL | `SimI2c` |

Bus transactions themselves are `Op::Transfer { addr, tx, rx }`, which needs the
`TRANSFER` right. They are not ioctls.

## Network interfaces (0x05xx)

These are served by the `/dev/<ifname>` control device that `net::register` creates
(`src/net/mod.rs`, `ControlDriver`).

| command | value | arg | returns | right |
|---------|-------|-----|---------|-------|
| `NET_GET_MTU` | `0x0501` | none | IP MTU | CONTROL |
| `NET_GET_HWADDR` | `0x0502` | none | MAC address in the low 48 bits | CONTROL |
| `NET_GET_LINK` | `0x0503` | none | bit 0 = link up, bits 16.. = speed in Mb/s | CONTROL |
| `NET_SET_UP` | `0x0504` | non-zero = up | 0 | **CONFIG** |
| `NET_GET_OFFLOADS` | `0x0505` | none | enabled `NetCaps` bits | CONTROL |
| `NET_SET_OFFLOADS` | `0x0506` | requested `NetCaps` bits | bits actually enabled (masked by hardware support) | **CONFIG** |
| `NET_GET_RX_PACKETS` | `0x0507` | none | `IfStats::rx_packets` | CONTROL |
| `NET_GET_TX_PACKETS` | `0x0508` | none | `IfStats::tx_packets` | CONTROL |
| `NET_GET_RX_DROPPED` | `0x0509` | none | `rx_dropped + rx_csum_errors + hook_drops` | CONTROL |

`NetCaps` bits:

| bit | value | capability |
|-----|------:|------------|
| 0 | `0x001` | `TX_CSUM_IPV4` |
| 1 | `0x002` | `TX_CSUM_L4` |
| 2 | `0x004` | `RX_CSUM` |
| 3 | `0x008` | `SG` |
| 4 | `0x010` | `VLAN_INSERT` |
| 5 | `0x020` | `VLAN_STRIP` |
| 6 | `0x040` | `MCAST_FILTER` |
| 7 | `0x080` | `PROMISC` |
| 8 | `0x100` | `HW_TIMESTAMP` |

## TTY line discipline (0x06xx)

These are handled by the `driver::char::Tty` middleware, not by drivers. See
[design/tty.md](../design/tty.md). Termios itself is configured through the typed
`TtyControl` interface, never by passing a pointer in `arg`.

| command | value | arg | returns | right | implemented by |
|---------|-------|-----|---------|-------|----------------|
| `TTY_FLUSH` | `0x0605` | queue selector (ignored) | 0 | CONTROL | `Tty`: discards its line buffer |
| `TTY_DRAIN` | `0x0606` | none | 0 | CONTROL | `Tty`: forwards; effectively a no-op today |
| `TTY_SET_SIGTARGET` | `0x0609` | none | none | **CONFIG** | **not handled by anything**; use `TtyControl::set_signal_target` |

## Display (0x07xx) and input (0x08xx)

The research proposed `0x06xx`/`0x07xx` for these classes, but `0x06xx` is the TTY
block, so the code uses `0x07xx` and `0x08xx`. The full tables, with argument packing,
are in [design/human-interface.md](../design/human-interface.md).

| command | value | right | | command | value | right |
|---------|-------|-------|-|---------|-------|-------|
| `DISPLAY_GET_GEOMETRY` | `0x0701` | CONTROL | | `INPUT_GET_CAPS` | `0x0801` | CONTROL |
| `DISPLAY_GET_FORMAT` | `0x0702` | CONTROL | | `INPUT_EVENTS_AVAILABLE` | `0x0802` | CONTROL |
| `DISPLAY_GET_CAPS` | `0x0703` | CONTROL | | `INPUT_FLUSH` | `0x0803` | CONTROL |
| `DISPLAY_SET_COL` | `0x0704` | CONTROL | | `INPUT_GET_ID` | `0x0804` | CONTROL |
| `DISPLAY_SET_ROW` | `0x0705` | CONTROL | | `INPUT_GET_ABS_INFO` | `0x0805` | CONTROL |
| `DISPLAY_FLUSH` | `0x0706` | CONTROL | | `INPUT_GRAB` | `0x0806` | CONTROL |
| `DISPLAY_WAIT_VSYNC` | `0x0707` | CONTROL | | `INPUT_SET_REPEAT` | `0x0807` | **CONFIG** |
| `DISPLAY_SET_BACKLIGHT` | `0x0708` | CONTROL | | | | |
| `DISPLAY_BLANK` | `0x0709` | CONTROL | | | | |
| `DISPLAY_SET_ORIENTATION` | `0x070A` | **CONFIG** | | | | |
| `DISPLAY_SET_FORMAT` | `0x070B` | **CONFIG** | | | | |

## Block devices (0x09xx) — reserved, planned

The block device class (`driver::block`) is built, but a block device is reached through
the `BlockDevice` fast path, **not** through an `Op`/ioctl device: there is no
`/dev/<name>` block control node yet, so the `0x09xx` page is reserved but unimplemented.
The research design ([research/filesystems.md](../research/filesystems.md)) reserves it for
a future control node:

| command | value | right | status |
|---------|-------|-------|--------|
| `BLOCK_GET_BLOCK_SIZE` / `_COUNT` / `_READ_SIZE` / `_PROG_SIZE` / `_KIND` | `0x0901`–`0x0905` | CONTROL | **Planned** |
| `BLOCK_SYNC` | `0x0906` | **CONFIG** | **Planned** |
| `BLOCK_ERASE_ALL` | `0x0907` | **CONFIG** | **Planned** |

Until then, geometry and sync are reached in-process through `driver::block::geometry` and
`driver::block::sync`; see [design/filesystem.md](../design/filesystem.md).

## Rights for non-ioctl operations

For completeness, `security::rights_for(&op)`:

| operation | right |
|-----------|-------|
| `Op::Read` | `READ` |
| `Op::Write` | `WRITE` |
| `Op::Transfer` | `TRANSFER` |
| `Op::Power` | `POWER` |
| `Op::Ioctl { cmd }` | `ioctl::required_right(cmd)` |
| `DeviceCap::attach` / `detach` | `MANAGE` |

## Adding an ioctl

1. Add a constant in the right class range in `driver::ioctl`, or start a new
   class byte.
2. If it only queries state, or is a normal operation that must not need configuration
   rights, add it to the `CONTROL` arm of `required_right`. Otherwise it defaults to
   `CONFIG`.
3. Handle it in the driver, answer `Unsupported` elsewhere, and document it here.

## Errors

- Unsupported commands return `Error::Unsupported`, which POSIX `ioctl` turns into
  `errno = ENOTTY`.
- An isolated caller without the required right gets `PermissionDenied` before any
  driver code runs.
