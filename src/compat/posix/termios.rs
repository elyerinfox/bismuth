//! `<termios.h>`: the POSIX General Terminal Interface.
//!
//! These operate on a file descriptor that refers to a device with a
//! [`Tty`](crate::driver::char::tty::Tty) line discipline attached (see
//! [`crate::driver::char::tty`]). The `termios` structure and its flag constants are the
//! TTY module's [`Termios`] and flags, re-exported here under POSIX names.
//!
//! Classification: L4 personalities · POSIX termios · safe · posix

use super::{c_int, fail};
use crate::Error;
use crate::driver::char::tty::{self, Apply};

pub use crate::driver::char::tty::{
    ECHO, ECHOE, ECHOK, ECHONL, ICANON, ICRNL, IGNCR, INLCR, ISIG, ISTRIP, IXON, NOFLSH, OCRNL, ONLCR, OPOST, Termios,
    VEOF, VERASE, VINTR, VKILL, VMIN, VQUIT, VSUSP, VTIME,
};

/// `tcsetattr` optional actions.
pub const TCSANOW: c_int = 0;
pub const TCSADRAIN: c_int = 1;
pub const TCSAFLUSH: c_int = 2;

/// `tcflush` queue selectors.
pub const TCIFLUSH: c_int = 0;
pub const TCOFLUSH: c_int = 1;
pub const TCIOFLUSH: c_int = 2;

fn control(fd: c_int) -> Result<&'static dyn tty::TtyControl, Error> {
    let dev = super::unistd::fd_device(fd).ok_or(Error::BadHandle)?;
    tty::control(dev).ok_or(Error::NotReady) // ENOTTY-ish: not a terminal
}

/// Get the terminal attributes of `fd` into `t`.
pub fn tcgetattr(fd: c_int, t: &mut Termios) -> c_int {
    match control(fd) {
        Ok(c) => {
            *t = c.get_termios();
            0
        }
        Err(_) => {
            super::set_errno(crate::compat::errno::ENOTTY);
            -1
        }
    }
}

/// Set the terminal attributes of `fd`.
pub fn tcsetattr(fd: c_int, optional_actions: c_int, t: &Termios) -> c_int {
    let when = match optional_actions {
        TCSANOW => Apply::Now,
        TCSADRAIN => Apply::Drain,
        TCSAFLUSH => Apply::Flush,
        _ => return fail(Error::Invalid),
    };
    match control(fd) {
        Ok(c) => {
            c.set_termios(t, when);
            0
        }
        Err(_) => {
            super::set_errno(crate::compat::errno::ENOTTY);
            -1
        }
    }
}

pub fn cfgetospeed(t: &Termios) -> u32 {
    t.c_ospeed
}

pub fn cfgetispeed(t: &Termios) -> u32 {
    t.c_ispeed
}

pub fn cfsetospeed(t: &mut Termios, speed: u32) -> c_int {
    t.c_ospeed = speed;
    0
}

pub fn cfsetispeed(t: &mut Termios, speed: u32) -> c_int {
    t.c_ispeed = speed;
    0
}

pub fn cfsetspeed(t: &mut Termios, speed: u32) -> c_int {
    t.c_ispeed = speed;
    t.c_ospeed = speed;
    0
}

/// Put the terminal into raw mode (`cfmakeraw`).
pub fn cfmakeraw(t: &mut Termios) {
    *t = Termios::raw();
}

/// Discard queued input and/or output.
pub fn tcflush(fd: c_int, queue: c_int) -> c_int {
    if !matches!(queue, TCIFLUSH | TCOFLUSH | TCIOFLUSH) {
        return fail(Error::Invalid);
    }
    match super::unistd::ioctl(fd, crate::driver::ioctl::TTY_FLUSH, queue as usize) {
        r if r >= 0 => 0,
        _ => -1,
    }
}

/// Wait for queued output to drain (`tcdrain`).
pub fn tcdrain(fd: c_int) -> c_int {
    match super::unistd::ioctl(fd, crate::driver::ioctl::TTY_DRAIN, 0) {
        r if r >= 0 => 0,
        _ => -1,
    }
}
