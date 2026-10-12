//! ioctl command numbers (the high byte selects the device class) and the rights
//! each command requires. One central registry keeps the per-class `0x0Nxx` pages
//! from colliding.
//!
//! Classification: L2 devices · ioctl registry · safe · always

// generic (0x00xx)
/// Returns the [`crate::driver::DeviceClass`] discriminant.
pub const GET_CLASS: u32 = 0x0001;

// serial (0x01xx)
pub const SERIAL_SET_BAUD: u32 = 0x0101;
pub const SERIAL_GET_BAUD: u32 = 0x0102;
/// Returns the number of bytes waiting to be read.
pub const SERIAL_RX_AVAILABLE: u32 = 0x0103;
/// Discard buffered input.
pub const SERIAL_FLUSH: u32 = 0x0104;

// gpio (0x02xx) — `arg` is a pin mask unless noted
pub const GPIO_SET: u32 = 0x0201;
pub const GPIO_CLEAR: u32 = 0x0202;
pub const GPIO_TOGGLE: u32 = 0x0203;
/// Returns the input/output levels of all pins.
pub const GPIO_GET: u32 = 0x0204;
pub const GPIO_CONFIG_OUTPUT: u32 = 0x0205;
pub const GPIO_CONFIG_INPUT: u32 = 0x0206;

// sensor (0x03xx)
/// Returns the number of channels (each read sample is one `i32` per channel).
pub const SENSOR_CHANNELS: u32 = 0x0301;
pub const SENSOR_SET_RATE_HZ: u32 = 0x0302;
pub const SENSOR_GET_RATE_HZ: u32 = 0x0303;

// i2c / spi (0x04xx)
pub const BUS_SET_SPEED_HZ: u32 = 0x0401;
pub const BUS_GET_SPEED_HZ: u32 = 0x0402;

// network interfaces (0x05xx)
pub const NET_GET_MTU: u32 = 0x0501;
/// Returns the MAC address in the low 48 bits.
pub const NET_GET_HWADDR: u32 = 0x0502;
/// Returns bit 0 = link up, bits 16.. = speed in Mb/s.
pub const NET_GET_LINK: u32 = 0x0503;
/// `arg` != 0 brings the interface up.
pub const NET_SET_UP: u32 = 0x0504;
pub const NET_GET_OFFLOADS: u32 = 0x0505;
/// Enable the offloads in `arg` (masked by hardware support); returns the result.
pub const NET_SET_OFFLOADS: u32 = 0x0506;
pub const NET_GET_RX_PACKETS: u32 = 0x0507;
pub const NET_GET_TX_PACKETS: u32 = 0x0508;
pub const NET_GET_RX_DROPPED: u32 = 0x0509;

// tty line discipline (0x06xx)
pub const TTY_FLUSH: u32 = 0x0605;
pub const TTY_DRAIN: u32 = 0x0606;
/// Bind the controlling task that receives terminal-signal notifications.
pub const TTY_SET_SIGTARGET: u32 = 0x0609;

// display (0x07xx)
pub const DISPLAY_GET_GEOMETRY: u32 = 0x0701;
pub const DISPLAY_GET_FORMAT: u32 = 0x0702;
pub const DISPLAY_GET_CAPS: u32 = 0x0703;
pub const DISPLAY_SET_COL: u32 = 0x0704;
pub const DISPLAY_SET_ROW: u32 = 0x0705;
pub const DISPLAY_FLUSH: u32 = 0x0706;
pub const DISPLAY_WAIT_VSYNC: u32 = 0x0707;
pub const DISPLAY_SET_BACKLIGHT: u32 = 0x0708;
pub const DISPLAY_BLANK: u32 = 0x0709;
pub const DISPLAY_SET_ORIENTATION: u32 = 0x070A;
pub const DISPLAY_SET_FORMAT: u32 = 0x070B;

// block storage (0x09xx)
/// Erase-block / sector size in bytes.
pub const BLOCK_GET_BLOCK_SIZE: u32 = 0x0901;
/// Number of erase blocks.
pub const BLOCK_GET_BLOCK_COUNT: u32 = 0x0902;
/// Minimum/alignment of a read, in bytes.
pub const BLOCK_GET_READ_SIZE: u32 = 0x0903;
/// Minimum/alignment of a program, in bytes.
pub const BLOCK_GET_PROG_SIZE: u32 = 0x0904;
/// Media kind discriminant (0 = Flash, 1 = Disk, 2 = Ram).
pub const BLOCK_GET_KIND: u32 = 0x0905;
/// Flush volatile write buffers to stable storage.
pub const BLOCK_SYNC: u32 = 0x0906;
/// Erase the whole device (format; dangerous).
pub const BLOCK_ERASE_ALL: u32 = 0x0907;

// input (0x08xx)
pub const INPUT_GET_CAPS: u32 = 0x0801;
pub const INPUT_EVENTS_AVAILABLE: u32 = 0x0802;
pub const INPUT_FLUSH: u32 = 0x0803;
pub const INPUT_GET_ID: u32 = 0x0804;
pub const INPUT_GET_ABS_INFO: u32 = 0x0805;
pub const INPUT_GRAB: u32 = 0x0806;
pub const INPUT_SET_REPEAT: u32 = 0x0807;

/// The right a handle needs to issue `cmd`: queries and normal operation need
/// `CONTROL`; anything that reconfigures the device (or is unknown) needs `CONFIG`.
pub const fn required_right(cmd: u32) -> crate::security::Rights {
    use crate::security::Rights;
    match cmd {
        GET_CLASS | SERIAL_GET_BAUD | SERIAL_RX_AVAILABLE | SERIAL_FLUSH | GPIO_SET | GPIO_CLEAR | GPIO_TOGGLE
        | GPIO_GET | SENSOR_CHANNELS | SENSOR_GET_RATE_HZ | BUS_GET_SPEED_HZ | NET_GET_MTU | NET_GET_HWADDR
        | NET_GET_LINK | NET_GET_OFFLOADS | NET_GET_RX_PACKETS | NET_GET_TX_PACKETS | NET_GET_RX_DROPPED | TTY_FLUSH | TTY_DRAIN
        | DISPLAY_GET_GEOMETRY | DISPLAY_GET_FORMAT | DISPLAY_GET_CAPS | DISPLAY_SET_COL | DISPLAY_SET_ROW
        | DISPLAY_FLUSH | DISPLAY_WAIT_VSYNC | DISPLAY_SET_BACKLIGHT | DISPLAY_BLANK
        | INPUT_GET_CAPS | INPUT_EVENTS_AVAILABLE | INPUT_FLUSH | INPUT_GET_ID | INPUT_GET_ABS_INFO | INPUT_GRAB
        | BLOCK_GET_BLOCK_SIZE | BLOCK_GET_BLOCK_COUNT | BLOCK_GET_READ_SIZE | BLOCK_GET_PROG_SIZE | BLOCK_GET_KIND => {
            Rights::CONTROL
        }
        _ => Rights::CONFIG,
    }
}
