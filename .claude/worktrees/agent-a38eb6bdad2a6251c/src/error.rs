//! The kernel-wide [`Error`] type and its POSIX `errno` mapping.
//!
//! Classification: support · errors · safe · always
use core::fmt;

/// Kernel-wide error type. Every variant maps to a POSIX `errno` value.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The operation timed out.
    Timeout,
    /// The operation would block and blocking was not allowed.
    WouldBlock,
    /// An argument was invalid.
    Invalid,
    /// A fixed-size kernel table (tasks, devices, fds, ...) is full.
    NoResources,
    /// A memory pool is exhausted.
    NoMemory,
    /// The named object does not exist.
    NotFound,
    /// The object already exists.
    Exists,
    /// The resource is busy (e.g. already claimed).
    Busy,
    /// The caller does not own the object (e.g. unlocking someone else's mutex).
    NotOwner,
    /// The operation would deadlock.
    Deadlock,
    /// The wait was interrupted (task suspended, object destroyed).
    Interrupted,
    /// The device or driver does not support this operation.
    Unsupported,
    /// Access denied by a middleware policy.
    PermissionDenied,
    /// A hardware or transfer error.
    Io,
    /// The device is not ready / powered down.
    NotReady,
    /// Value out of range or overflow.
    Overflow,
    /// Bad file descriptor or handle.
    BadHandle,
    /// Authentication / integrity check failed (bad MAC or AEAD tag, failed self-test).
    Integrity,
    /// A path component expected to be a directory is not one.
    NotADirectory,
    /// The target is a directory where a file was required.
    IsADirectory,
    /// A directory is not empty (e.g. `rmdir` on a populated directory).
    NotEmpty,
    /// The filesystem or mount is read-only.
    ReadOnly,
    /// A path or path component is too long.
    NameTooLong,
    /// The storage medium or filesystem is out of space.
    NoSpace,
}

impl Error {
    /// The equivalent POSIX `errno` value.
    pub const fn errno(self) -> i32 {
        use crate::compat::errno::*;
        match self {
            Error::Timeout => ETIMEDOUT,
            Error::WouldBlock => EAGAIN,
            Error::Invalid => EINVAL,
            Error::NoResources => EAGAIN,
            Error::NoMemory => ENOMEM,
            Error::NotFound => ENOENT,
            Error::Exists => EEXIST,
            Error::Busy => EBUSY,
            Error::NotOwner => EPERM,
            Error::Deadlock => EDEADLK,
            Error::Interrupted => EINTR,
            Error::Unsupported => ENOTSUP,
            Error::PermissionDenied => EACCES,
            Error::Io => EIO,
            Error::NotReady => ENODEV,
            Error::Overflow => EOVERFLOW,
            Error::BadHandle => EBADF,
            Error::Integrity => EBADMSG,
            Error::NotADirectory => ENOTDIR,
            Error::IsADirectory => EISDIR,
            Error::NotEmpty => ENOTEMPTY,
            Error::ReadOnly => EROFS,
            Error::NameTooLong => ENAMETOOLONG,
            Error::NoSpace => ENOSPC,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for Error {}
