//! `<unistd.h>`, `<fcntl.h>`, `<poll.h>`, `<sys/ioctl.h>` and `<sys/socket.h>`.
//!
//! One descriptor table unifies the console (fds 0–2), devices opened by path
//! (`/dev/<name>`, through their middleware chains) and sockets.
//!
//! Classification: L4 personalities · POSIX file descriptors and sockets · safe · posix

#[cfg(feature = "net-ip")]
use core::mem::ManuallyDrop;

use super::{c_int, fail};
use crate::Error;
use crate::config::MAX_FDS;
use crate::driver::ioctl as ioc;
use crate::driver::{Device, DeviceClass, FLAG_NONBLOCK, Op, Request};
use crate::kernel::cell::IrqCell;
use crate::kernel::task;
use crate::kernel::time::{Instant, Timeout};
use crate::security::{self, DeviceCap};

pub const STDIN_FILENO: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;
pub const STDERR_FILENO: c_int = 2;

pub use super::mqueue::{O_CREAT, O_EXCL, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY};
pub const O_TRUNC: c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;

/// `lseek` origin.
pub const SEEK_SET: c_int = 0;
pub const SEEK_CUR: c_int = 1;
pub const SEEK_END: c_int = 2;

// `st_mode` file-type bits.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;

/// Minimal `struct stat` (the fields a no-heap filesystem can fill).
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct stat {
    pub st_mode: u32,
    pub st_size: u64,
    pub st_blocks: u32,
    pub st_mtime: u64,
}

pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const POLLNVAL: i16 = 0x020;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct pollfd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Kind {
    Free,
    Console,
    Device(Device),
    /// A device opened through the calling domain's namespace (rights-checked).
    Cap(DeviceCap),
    /// A file opened on a mounted filesystem through the VFS.
    #[cfg(feature = "fs")]
    File(crate::fs::File),
    #[cfg(feature = "net-ip")]
    Socket(Sock),
}

#[cfg(feature = "net-ip")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Sock {
    /// Created by `socket()`, not yet bound/connected.
    New { stream: bool, port: u16 },
    Udp { slot: usize, port: u16 },
    Tcp { slot: usize },
    Listener { idx: u8, port: u16, slot: Option<usize> },
}

#[derive(Copy, Clone, Debug)]
struct Entry {
    kind: Kind,
    flags: c_int,
    /// Receive timeout (SO_RCVTIMEO); `None` = block forever.
    rcv_timeout: Option<u64>,
}

impl Entry {
    const FREE: Entry = Entry { kind: Kind::Free, flags: 0, rcv_timeout: None };
    const CONSOLE: Entry = Entry { kind: Kind::Console, flags: O_RDWR, rcv_timeout: None };

    fn timeout(&self) -> Timeout {
        if self.flags & O_NONBLOCK != 0 {
            Timeout::NoWait
        } else {
            self.rcv_timeout.map_or(Timeout::Forever, Timeout::Ticks)
        }
    }
}

const fn initial_table() -> [Entry; MAX_FDS] {
    let mut t = [Entry::FREE; MAX_FDS];
    t[0] = Entry::CONSOLE;
    t[1] = Entry::CONSOLE;
    t[2] = Entry::CONSOLE;
    t
}

static FDS: IrqCell<[Entry; MAX_FDS]> = IrqCell::new(initial_table());

fn get(fd: c_int) -> Result<Entry, Error> {
    let i = usize::try_from(fd).map_err(|_| Error::BadHandle)?;
    FDS.lock(|t| t.get(i).copied())
        .filter(|e| e.kind != Kind::Free)
        .ok_or(Error::BadHandle)
}

fn put(fd: c_int, e: Entry) {
    FDS.lock(|t| t[fd as usize] = e);
}

fn alloc(e: Entry) -> Result<c_int, Error> {
    FDS.lock(|t| {
        let i = t.iter().position(|x| x.kind == Kind::Free).ok_or(Error::NoResources)?;
        t[i] = e;
        Ok(i as c_int)
    })
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    FDS.lock(|t| *t = initial_table());
}

/// Open a device by path (`/dev/<name>`).
/// The device an fd refers to (console, device, or cap-opened device), for the termios
/// layer. Sockets and free fds return None.
pub(crate) fn fd_device(fd: c_int) -> Option<Device> {
    match get(fd).ok()?.kind {
        Kind::Console => crate::console::device(),
        Kind::Device(d) => Some(d),
        #[cfg(feature = "fs")]
        Kind::File(_) => None,
        #[cfg(feature = "net-ip")]
        Kind::Socket(_) => None,
        Kind::Cap(_) | Kind::Free => None,
    }
}

pub fn open(path: &str, flags: c_int) -> c_int {
    let Some(name) = path.strip_prefix("/dev/") else {
        // Non-device paths resolve through the VFS (a mounted filesystem).
        #[cfg(feature = "fs")]
        return open_file(path, flags);
        #[cfg(not(feature = "fs"))]
        return fail(Error::NotFound);
    };
    // Isolated domains resolve names in their own namespace (no ambient authority).
    let kind = if security::current_is_trusted() {
        match Device::find(name) {
            Ok(d) => Kind::Device(d),
            Err(e) => return fail(e),
        }
    } else {
        match DeviceCap::open(name) {
            Ok(c) => Kind::Cap(c),
            Err(e) => return fail(e),
        }
    };
    match alloc(Entry { kind, flags, rcv_timeout: None }) {
        Ok(fd) => fd,
        Err(e) => fail(e),
    }
}

#[cfg(feature = "fs")]
fn open_file(path: &str, flags: c_int) -> c_int {
    use crate::fs::OpenMode;
    let mut mode = match flags & 3 {
        x if x == O_WRONLY => OpenMode::WRITE,
        x if x == O_RDWR => OpenMode::RDWR,
        _ => OpenMode::READ,
    };
    for (bit, flag) in [(O_CREAT, OpenMode::CREATE), (O_TRUNC, OpenMode::TRUNC), (O_APPEND, OpenMode::APPEND), (O_EXCL, OpenMode::EXCL)] {
        if flags & bit != 0 {
            mode = mode.with(flag);
        }
    }
    match crate::fs::open(path, mode) {
        Ok(f) => match alloc(Entry { kind: Kind::File(f), flags, rcv_timeout: None }) {
            Ok(fd) => fd,
            Err(e) => {
                crate::fs::close(f);
                fail(e)
            }
        },
        Err(e) => fail(e),
    }
}

pub fn close(fd: c_int) -> c_int {
    let e = match get(fd) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    #[cfg(feature = "net-ip")]
    if let Kind::Socket(s) = e.kind {
        close_socket(s);
    }
    #[cfg(feature = "fs")]
    if let Kind::File(f) = e.kind {
        crate::fs::close(f);
    }
    let _ = e;
    put(fd, Entry::FREE);
    0
}

// ----- filesystem files (feature `fs`) -----

#[cfg(feature = "fs")]
fn ok_or_fail(r: Result<(), Error>) -> c_int {
    match r {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

#[cfg(feature = "fs")]
fn file_of(fd: c_int) -> Result<crate::fs::File, Error> {
    match get(fd)?.kind {
        Kind::File(f) => Ok(f),
        _ => Err(Error::BadHandle),
    }
}

#[cfg(feature = "fs")]
fn to_stat(s: crate::fs::Stat) -> stat {
    stat {
        st_mode: if s.kind == crate::fs::NodeKind::Dir { S_IFDIR } else { S_IFREG },
        st_size: s.size,
        st_blocks: s.blocks,
        st_mtime: s.mtime,
    }
}

/// Reposition the file offset. Returns the new absolute offset, or `-1`.
#[cfg(feature = "fs")]
pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    let f = match file_of(fd) {
        Ok(f) => f,
        Err(e) => return fail(e) as i64,
    };
    let from = match whence {
        x if x == SEEK_SET && offset >= 0 => crate::fs::SeekFrom::Start(offset as u64),
        x if x == SEEK_CUR => crate::fs::SeekFrom::Current(offset),
        x if x == SEEK_END => crate::fs::SeekFrom::End(offset),
        _ => return fail(Error::Invalid) as i64,
    };
    match crate::fs::seek(f, from) {
        Ok(p) => p as i64,
        Err(e) => fail(e) as i64,
    }
}

/// Truncate an open file to `length` bytes.
#[cfg(feature = "fs")]
pub fn ftruncate(fd: c_int, length: u64) -> c_int {
    match file_of(fd) {
        Ok(f) => ok_or_fail(crate::fs::ftruncate(f, length)),
        Err(e) => fail(e),
    }
}

/// Flush an open file's filesystem to stable storage.
#[cfg(feature = "fs")]
pub fn fsync(fd: c_int) -> c_int {
    match file_of(fd) {
        Ok(f) => ok_or_fail(crate::fs::fsync(f)),
        Err(e) => fail(e),
    }
}

/// Fill `out` with metadata of an open file.
#[cfg(feature = "fs")]
pub fn fstat(fd: c_int, out: &mut stat) -> c_int {
    let f = match file_of(fd) {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    match crate::fs::fstat(f) {
        Ok(s) => {
            *out = to_stat(s);
            0
        }
        Err(e) => fail(e),
    }
}

/// Fill `out` with metadata of the node at `path`.
#[cfg(feature = "fs")]
pub fn stat(path: &str, out: &mut stat) -> c_int {
    match crate::fs::stat(path) {
        Ok(s) => {
            *out = to_stat(s);
            0
        }
        Err(e) => fail(e),
    }
}

/// Create a directory (the mode argument is accepted but ignored — capabilities, not bits).
#[cfg(feature = "fs")]
pub fn mkdir(path: &str, _mode: c_int) -> c_int {
    ok_or_fail(crate::fs::mkdir(path))
}

/// Remove an empty directory.
#[cfg(feature = "fs")]
pub fn rmdir(path: &str) -> c_int {
    ok_or_fail(crate::fs::rmdir(path))
}

/// Remove a file.
#[cfg(feature = "fs")]
pub fn unlink(path: &str) -> c_int {
    ok_or_fail(crate::fs::unlink(path))
}

/// Rename a file or directory (same mount only).
#[cfg(feature = "fs")]
pub fn rename(old: &str, new: &str) -> c_int {
    ok_or_fail(crate::fs::rename(old, new))
}

fn device_io(dev: Device, e: &Entry, op: Op<'_>) -> Result<usize, Error> {
    let flags = if e.flags & O_NONBLOCK != 0 { FLAG_NONBLOCK } else { 0 };
    dev.request(&mut Request::new(op).with_flags(flags).with_timeout(e.timeout()))
}

fn cap_io(cap: DeviceCap, e: &Entry, op: Op<'_>) -> Result<usize, Error> {
    let flags = if e.flags & O_NONBLOCK != 0 { FLAG_NONBLOCK } else { 0 };
    cap.request(&mut Request::new(op).with_flags(flags).with_timeout(e.timeout()))
}

pub fn read(fd: c_int, buf: &mut [u8]) -> isize {
    let e = match get(fd) {
        Ok(e) => e,
        Err(err) => return fail(err) as isize,
    };
    if e.flags & 3 == O_WRONLY {
        return fail(Error::BadHandle) as isize;
    }
    let r = match e.kind {
        Kind::Console => match crate::console::device() {
            Some(d) => device_io(d, &e, Op::Read(buf)),
            None => Err(Error::WouldBlock),
        },
        Kind::Device(d) => device_io(d, &e, Op::Read(buf)),
        Kind::Cap(c) => cap_io(c, &e, Op::Read(buf)),
        #[cfg(feature = "fs")]
        Kind::File(f) => crate::fs::read(f, buf),
        #[cfg(feature = "net-ip")]
        Kind::Socket(s) => sock_recv(s, buf, e.timeout()).map(|(n, _)| n),
        Kind::Free => Err(Error::BadHandle),
    };
    match r {
        Ok(n) => n as isize,
        Err(err) => fail(err) as isize,
    }
}

pub fn write(fd: c_int, buf: &[u8]) -> isize {
    let e = match get(fd) {
        Ok(e) => e,
        Err(err) => return fail(err) as isize,
    };
    if e.flags & 3 == O_RDONLY && e.kind != Kind::Console {
        return fail(Error::BadHandle) as isize;
    }
    let r = match e.kind {
        Kind::Console => {
            crate::console::write_bytes(buf);
            Ok(buf.len())
        }
        Kind::Device(d) => device_io(d, &e, Op::Write(buf)),
        Kind::Cap(c) => cap_io(c, &e, Op::Write(buf)),
        #[cfg(feature = "fs")]
        Kind::File(f) => crate::fs::write(f, buf),
        #[cfg(feature = "net-ip")]
        Kind::Socket(s) => sock_send(fd, s, buf, None),
        Kind::Free => Err(Error::BadHandle),
    };
    match r {
        Ok(n) => n as isize,
        Err(err) => fail(err) as isize,
    }
}

/// Device control. Returns the driver's result value (>= 0) or -1.
pub fn ioctl(fd: c_int, request: u32, arg: usize) -> isize {
    let r = match get(fd) {
        Ok(Entry { kind: Kind::Device(d), .. }) => d.ioctl(request, arg),
        Ok(Entry { kind: Kind::Cap(c), .. }) => c.ioctl(request, arg),
        Ok(Entry { kind: Kind::Console, .. }) => match crate::console::device() {
            Some(d) => d.ioctl(request, arg),
            None => Err(Error::Unsupported),
        },
        Ok(_) => Err(Error::Unsupported),
        Err(e) => Err(e),
    };
    match r {
        Ok(v) => v as isize,
        Err(Error::Unsupported) => {
            super::set_errno(crate::compat::errno::ENOTTY);
            -1
        }
        Err(e) => fail(e) as isize,
    }
}

pub fn fcntl(fd: c_int, cmd: c_int, arg: c_int) -> c_int {
    let mut e = match get(fd) {
        Ok(e) => e,
        Err(err) => return fail(err),
    };
    match cmd {
        F_GETFL => e.flags,
        F_SETFL => {
            e.flags = (e.flags & 3) | (arg & O_NONBLOCK);
            put(fd, e);
            0
        }
        _ => fail(Error::Invalid),
    }
}

pub fn isatty(fd: c_int) -> c_int {
    match get(fd) {
        Ok(Entry { kind: Kind::Console, .. }) => 1,
        Ok(Entry { kind: Kind::Device(d), .. }) if d.class() == Ok(DeviceClass::Char) => 1,
        Ok(Entry { kind: Kind::Cap(c), .. }) if c.ioctl(ioc::GET_CLASS, 0) == Ok(DeviceClass::Char as usize) => 1,
        Ok(_) => {
            super::set_errno(crate::compat::errno::ENOTTY);
            0
        }
        Err(e) => {
            fail(e);
            0
        }
    }
}

pub fn sleep(seconds: u32) -> u32 {
    task::sleep_ms(seconds as u64 * 1000);
    0
}

pub fn usleep(usec: u32) -> c_int {
    task::sleep_ms((usec as u64).div_ceil(1000));
    0
}

fn poll_one(p: &mut pollfd) {
    p.revents = 0;
    let Ok(e) = get(p.fd) else {
        p.revents = POLLNVAL;
        return;
    };
    let (r, w) = match e.kind {
        Kind::Console => (crate::console::device().is_some_and(|d| d.ioctl(ioc::SERIAL_RX_AVAILABLE, 0).unwrap_or(0) > 0), true),
        Kind::Device(d) => match d.class() {
            Ok(DeviceClass::Char) => (d.ioctl(ioc::SERIAL_RX_AVAILABLE, 0).unwrap_or(0) > 0, true),
            Ok(DeviceClass::Input) => (d.ioctl(ioc::INPUT_EVENTS_AVAILABLE, 0).unwrap_or(0) > 0, false),
            _ => (true, true),
        },
        Kind::Cap(c) => match c.ioctl(ioc::GET_CLASS, 0) {
            Ok(x) if x == DeviceClass::Char as usize => (c.ioctl(ioc::SERIAL_RX_AVAILABLE, 0).unwrap_or(0) > 0, true),
            Ok(x) if x == DeviceClass::Input as usize => (c.ioctl(ioc::INPUT_EVENTS_AVAILABLE, 0).unwrap_or(0) > 0, false),
            _ => (true, true),
        },
        #[cfg(feature = "fs")]
        Kind::File(_) => (true, true), // a regular file is always ready
        #[cfg(feature = "net-ip")]
        Kind::Socket(s) => sock_readiness(s),
        Kind::Free => (false, false),
    };
    if r && p.events & POLLIN != 0 {
        p.revents |= POLLIN;
    }
    if w && p.events & POLLOUT != 0 {
        p.revents |= POLLOUT;
    }
}

/// Wait for readiness on any of `fds`. `timeout_ms < 0` waits forever.
/// Returns the number of descriptors with non-zero `revents`.
pub fn poll(fds: &mut [pollfd], timeout_ms: c_int) -> c_int {
    let start = Instant::now();
    let limit = (timeout_ms >= 0).then(|| crate::kernel::time::ms_to_ticks(timeout_ms as u64));
    loop {
        for p in fds.iter_mut() {
            poll_one(p);
        }
        let n = fds.iter().filter(|p| p.revents != 0).count() as c_int;
        if n > 0 || limit.is_some_and(|l| start.elapsed_ticks() >= l) {
            return n;
        }
        task::sleep_ticks(1);
    }
}

// ----- sockets -----

#[cfg(feature = "net-ip")]
pub use sockets::*;

#[cfg(feature = "net-ip")]
use crate::net::socket::{self as ns, TcpListener, TcpStream, UdpSocket};

#[cfg(feature = "net-ip")]
fn close_socket(s: Sock) {
    match s {
        Sock::New { .. } => {}
        Sock::Udp { slot, port } => drop(UdpSocket { slot, port }),
        Sock::Tcp { slot } => drop(TcpStream { slot }),
        Sock::Listener { idx, port, slot } => drop(TcpListener { idx: crate::net::IfIndex(idx), port, slot }),
    }
}

#[cfg(feature = "net-ip")]
fn sock_readiness(s: Sock) -> (bool, bool) {
    match s {
        Sock::New { .. } => (false, false),
        Sock::Udp { slot, .. } | Sock::Tcp { slot } => ns::readiness(slot),
        Sock::Listener { slot, .. } => (slot.is_some_and(ns::acceptable), false),
    }
}

#[cfg(feature = "net-ip")]
fn sock_recv(s: Sock, buf: &mut [u8], t: Timeout) -> Result<(usize, Option<core::net::SocketAddrV4>), Error> {
    match s {
        Sock::Udp { slot, port } => {
            let u = ManuallyDrop::new(UdpSocket { slot, port });
            u.recv_from(buf, t).map(|(n, a)| (n, Some(a)))
        }
        Sock::Tcp { slot } => {
            let c = ManuallyDrop::new(TcpStream { slot });
            c.read(buf, t).map(|n| (n, None))
        }
        _ => Err(Error::Invalid),
    }
}

#[cfg(feature = "net-ip")]
fn sock_send(fd: c_int, s: Sock, buf: &[u8], to: Option<core::net::SocketAddrV4>) -> Result<usize, Error> {
    match (s, to) {
        (Sock::Udp { slot, port }, Some(to)) => ManuallyDrop::new(UdpSocket { slot, port }).send_to(buf, to),
        (Sock::New { stream: false, port }, Some(to)) => {
            // Implicit bind on first send, as with BSD sockets.
            let u = UdpSocket::bind(port)?;
            let n = u.send_to(buf, to);
            let (slot, port) = (u.slot, u.port);
            core::mem::forget(u);
            let mut e = get(fd)?;
            e.kind = Kind::Socket(Sock::Udp { slot, port });
            put(fd, e);
            n
        }
        (Sock::Tcp { slot }, _) => ManuallyDrop::new(TcpStream { slot }).write(buf, Timeout::Forever),
        (Sock::Udp { .. }, None) => Err(Error::Invalid), // no default destination
        _ => Err(Error::Invalid),
    }
}

#[cfg(feature = "net-ip")]
mod sockets {
    use core::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    pub const AF_INET: c_int = 2;
    pub const SOCK_STREAM: c_int = 1;
    pub const SOCK_DGRAM: c_int = 2;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_RCVTIMEO: c_int = 20;
    pub const INADDR_ANY: u32 = 0;

    /// IPv4 socket address. `sin_port` and `sin_addr` are in network byte order.
    #[allow(non_camel_case_types)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct sockaddr_in {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32,
    }

    impl sockaddr_in {
        pub fn new(addr: Ipv4Addr, port: u16) -> Self {
            sockaddr_in { sin_family: AF_INET as u16, sin_port: htons(port), sin_addr: u32::from(addr).to_be() }
        }

        fn to_std(self) -> SocketAddrV4 {
            SocketAddrV4::new(Ipv4Addr::from(u32::from_be(self.sin_addr)), ntohs(self.sin_port))
        }

        fn from_std(a: SocketAddrV4) -> Self {
            Self::new(*a.ip(), a.port())
        }
    }

    pub fn htons(v: u16) -> u16 {
        v.to_be()
    }

    pub fn ntohs(v: u16) -> u16 {
        u16::from_be(v)
    }

    pub fn htonl(v: u32) -> u32 {
        v.to_be()
    }

    pub fn ntohl(v: u32) -> u32 {
        u32::from_be(v)
    }

    fn sock(fd: c_int) -> Result<(Entry, Sock), Error> {
        match get(fd)? {
            e @ Entry { kind: Kind::Socket(s), .. } => Ok((e, s)),
            _ => Err(Error::Invalid),
        }
    }

    fn set_sock(fd: c_int, mut e: Entry, s: Sock) {
        e.kind = Kind::Socket(s);
        put(fd, e);
    }

    fn ret(r: Result<(), Error>) -> c_int {
        match r {
            Ok(()) => 0,
            Err(e) => fail(e),
        }
    }

    pub fn socket(domain: c_int, ty: c_int, _protocol: c_int) -> c_int {
        if domain != AF_INET || (ty != SOCK_STREAM && ty != SOCK_DGRAM) {
            return fail(Error::Unsupported);
        }
        let s = Sock::New { stream: ty == SOCK_STREAM, port: 0 };
        match alloc(Entry { kind: Kind::Socket(s), flags: O_RDWR, rcv_timeout: None }) {
            Ok(fd) => fd,
            Err(e) => fail(e),
        }
    }

    pub fn bind(fd: c_int, addr: &sockaddr_in) -> c_int {
        ret((|| {
            let (e, s) = sock(fd)?;
            let port = ntohs(addr.sin_port);
            match s {
                Sock::New { stream: false, .. } => {
                    let u = UdpSocket::bind(port)?;
                    let n = Sock::Udp { slot: u.slot, port: u.port };
                    core::mem::forget(u);
                    set_sock(fd, e, n);
                }
                Sock::New { stream: true, .. } => set_sock(fd, e, Sock::New { stream: true, port }),
                _ => return Err(Error::Invalid),
            }
            Ok(())
        })())
    }

    pub fn listen(fd: c_int, _backlog: c_int) -> c_int {
        ret((|| {
            let (e, s) = sock(fd)?;
            let Sock::New { stream: true, port } = s else { return Err(Error::Invalid) };
            if port == 0 {
                return Err(Error::Invalid);
            }
            let l = TcpListener::bind(port)?;
            let n = Sock::Listener { idx: l.idx.0, port: l.port, slot: l.slot };
            core::mem::forget(l);
            set_sock(fd, e, n);
            Ok(())
        })())
    }

    /// Accept a connection; returns the new descriptor.
    pub fn accept(fd: c_int, addr: Option<&mut sockaddr_in>) -> c_int {
        let r = (|| {
            let (e, s) = sock(fd)?;
            let Sock::Listener { idx, port, slot } = s else { return Err(Error::Invalid) };
            let mut l = TcpListener { idx: crate::net::IfIndex(idx), port, slot };
            let r = l.accept(e.timeout());
            let n = Sock::Listener { idx, port: l.port, slot: l.slot };
            core::mem::forget(l);
            set_sock(fd, e, n);
            let stream = r?;
            let slot = stream.slot;
            core::mem::forget(stream);
            alloc(Entry { kind: Kind::Socket(Sock::Tcp { slot }), flags: O_RDWR, rcv_timeout: None })
        })();
        match r {
            Ok(nfd) => {
                if let Some(a) = addr {
                    *a = sockaddr_in::default();
                }
                nfd
            }
            Err(e) => fail(e),
        }
    }

    pub fn connect(fd: c_int, addr: &sockaddr_in) -> c_int {
        ret((|| {
            let (e, s) = sock(fd)?;
            match s {
                Sock::New { stream: true, .. } => {
                    let c = TcpStream::connect(addr.to_std(), Timeout::ms(30_000))?;
                    let slot = c.slot;
                    core::mem::forget(c);
                    set_sock(fd, e, Sock::Tcp { slot });
                    Ok(())
                }
                _ => Err(Error::Invalid),
            }
        })())
    }

    pub fn send(fd: c_int, buf: &[u8], _flags: c_int) -> isize {
        write(fd, buf)
    }

    pub fn recv(fd: c_int, buf: &mut [u8], _flags: c_int) -> isize {
        read(fd, buf)
    }

    pub fn sendto(fd: c_int, buf: &[u8], _flags: c_int, to: &sockaddr_in) -> isize {
        let r = sock(fd).and_then(|(_, s)| sock_send(fd, s, buf, Some(to.to_std())));
        match r {
            Ok(n) => n as isize,
            Err(e) => fail(e) as isize,
        }
    }

    pub fn recvfrom(fd: c_int, buf: &mut [u8], _flags: c_int, from: Option<&mut sockaddr_in>) -> isize {
        let r = sock(fd).and_then(|(e, s)| sock_recv(s, buf, e.timeout()));
        match r {
            Ok((n, a)) => {
                if let (Some(out), Some(a)) = (from, a) {
                    *out = sockaddr_in::from_std(a);
                }
                n as isize
            }
            Err(e) => fail(e) as isize,
        }
    }

    /// Supported: `SOL_SOCKET`/`SO_RCVTIMEO` with the timeout in milliseconds.
    pub fn setsockopt(fd: c_int, level: c_int, name: c_int, value_ms: u32) -> c_int {
        ret((|| {
            let (mut e, _) = sock(fd)?;
            if level != SOL_SOCKET || name != SO_RCVTIMEO {
                return Err(Error::Unsupported);
            }
            e.rcv_timeout = (value_ms > 0).then(|| crate::kernel::time::ms_to_ticks(value_ms as u64));
            put(fd, e);
            Ok(())
        })())
    }
}
