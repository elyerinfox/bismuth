//! `<mqueue.h>`: named message queues with priorities.
//!
//! Queues live in a static table of `MAX_MQUEUES` entries, each with `MQUEUE_BYTES` of
//! storage split into `mq_maxmsg` slots of `mq_msgsize` bytes. Receivers always get the
//! oldest message of the highest priority.
//!
//! Classification: L4 personalities · POSIX message queues · safe · posix

use super::time::{timespec, timeout_from_abstime};
use super::{c_int, fail};
use crate::Error;
use crate::config::{MAX_MQUEUES, MQUEUE_BYTES};
use crate::kernel::cell::IrqCell;
use crate::kernel::time::Timeout;
use crate::kernel::{WakeReason, block_on};

#[allow(non_camel_case_types)]
pub type mqd_t = c_int;

pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 1;
pub const O_RDWR: c_int = 2;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_NONBLOCK: c_int = 0o4000;

pub const MQ_PRIO_MAX: u32 = 32;
const MAX_MSGS: usize = 32;
const NAME_MAX: usize = 32;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct mq_attr {
    pub mq_flags: c_int,
    pub mq_maxmsg: c_int,
    pub mq_msgsize: c_int,
    pub mq_curmsgs: c_int,
}

#[derive(Copy, Clone)]
struct Msg {
    len: u16,
    prio: u32,
    seq: u32,
}

struct Mq {
    name: [u8; NAME_MAX],
    name_len: usize,
    in_use: bool,
    unlinked: bool,
    opens: u32,
    maxmsg: usize,
    msgsize: usize,
    msgs: [Option<Msg>; MAX_MSGS],
    seq: u32,
    data: [u8; MQUEUE_BYTES],
}

impl Mq {
    const EMPTY: Mq = Mq {
        name: [0; NAME_MAX],
        name_len: 0,
        in_use: false,
        unlinked: false,
        opens: 0,
        maxmsg: 0,
        msgsize: 0,
        msgs: [None; MAX_MSGS],
        seq: 0,
        data: [0; MQUEUE_BYTES],
    };

    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn count(&self) -> usize {
        self.msgs[..self.maxmsg].iter().filter(|m| m.is_some()).count()
    }
}

static QUEUES: [IrqCell<Mq>; MAX_MQUEUES] = [const { IrqCell::new(Mq::EMPTY) }; MAX_MQUEUES];
const MAX_DESCRIPTORS: usize = 2 * MAX_MQUEUES + 4;
/// Open message-queue descriptions: (queue index, open flags).
static DESCS: IrqCell<[Option<(usize, c_int)>; MAX_DESCRIPTORS]> = IrqCell::new([None; MAX_DESCRIPTORS]);

fn new_desc(q: usize, oflag: c_int) -> Result<mqd_t, Error> {
    DESCS.lock(|d| {
        let i = d.iter().position(|x| x.is_none()).ok_or(Error::NoResources)?;
        d[i] = Some((q, oflag));
        Ok(i as mqd_t)
    })
}

fn key_not_empty(q: usize) -> usize {
    &QUEUES[q] as *const _ as usize
}

fn key_not_full(q: usize) -> usize {
    key_not_empty(q) + 1
}

/// Resolve a descriptor to `(queue index, open flags)`.
fn check(mqd: mqd_t) -> Result<(usize, c_int), Error> {
    let i = usize::try_from(mqd).map_err(|_| Error::BadHandle)?;
    DESCS.lock(|d| d.get(i).copied().flatten()).ok_or(Error::BadHandle)
}

/// Open (optionally creating) a queue. Names must start with `/`.
pub fn mq_open(name: &str, oflag: c_int, attr: Option<&mq_attr>) -> mqd_t {
    let n = name.as_bytes();
    if !name.starts_with('/') || n.len() > NAME_MAX {
        return fail(Error::Invalid);
    }
    // Existing queue?
    for (i, q) in QUEUES.iter().enumerate() {
        let found = q.lock(|m| {
            if m.in_use && !m.unlinked && m.name() == n {
                if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                    return Some(Err(Error::Exists));
                }
                m.opens += 1;
                return Some(Ok(()));
            }
            None
        });
        match found {
            Some(Ok(())) => {
                return new_desc(i, oflag).unwrap_or_else(|e| {
                    q.lock(|m| m.opens -= 1);
                    fail(e)
                });
            }
            Some(Err(e)) => return fail(e),
            None => {}
        }
    }
    if oflag & O_CREAT == 0 {
        return fail(Error::NotFound);
    }
    let a = attr.copied().unwrap_or(mq_attr { mq_flags: 0, mq_maxmsg: 8, mq_msgsize: 64, mq_curmsgs: 0 });
    let (maxmsg, msgsize) = (a.mq_maxmsg as usize, a.mq_msgsize as usize);
    if maxmsg == 0 || msgsize == 0 || maxmsg > MAX_MSGS || maxmsg * msgsize > MQUEUE_BYTES || msgsize > u16::MAX as usize {
        return fail(Error::Invalid);
    }
    for (i, q) in QUEUES.iter().enumerate() {
        let created = q.lock(|m| {
            if m.in_use {
                return false;
            }
            *m = Mq::EMPTY;
            m.name[..n.len()].copy_from_slice(n);
            m.name_len = n.len();
            m.in_use = true;
            m.opens = 1;
            m.maxmsg = maxmsg;
            m.msgsize = msgsize;
            true
        });
        if created {
            return new_desc(i, oflag).unwrap_or_else(|e| {
                q.lock(|m| m.in_use = false);
                fail(e)
            });
        }
    }
    fail(Error::NoResources)
}

pub fn mq_close(mqd: mqd_t) -> c_int {
    let q = match check(mqd) {
        Ok((q, _)) => q,
        Err(e) => return fail(e),
    };
    DESCS.lock(|d| d[mqd as usize] = None);
    QUEUES[q].lock(|m| {
        m.opens -= 1;
        if m.opens == 0 && m.unlinked {
            m.in_use = false;
        }
    });
    0
}

/// Remove the name; the queue is destroyed once every descriptor is closed.
pub fn mq_unlink(name: &str) -> c_int {
    for q in QUEUES.iter() {
        let hit = q.lock(|m| {
            if m.in_use && !m.unlinked && m.name() == name.as_bytes() {
                m.unlinked = true;
                if m.opens == 0 {
                    m.in_use = false;
                }
                true
            } else {
                false
            }
        });
        if hit {
            return 0;
        }
    }
    fail(Error::NotFound)
}

pub fn mq_getattr(mqd: mqd_t, attr: &mut mq_attr) -> c_int {
    let (q, flags) = match check(mqd) {
        Ok(x) => x,
        Err(e) => return fail(e),
    };
    QUEUES[q].lock(|m| {
        *attr = mq_attr {
            mq_flags: flags & O_NONBLOCK,
            mq_maxmsg: m.maxmsg as c_int,
            mq_msgsize: m.msgsize as c_int,
            mq_curmsgs: m.count() as c_int,
        }
    });
    0
}

fn timeout_for(flags: c_int, t: Timeout) -> Timeout {
    if flags & O_NONBLOCK != 0 { Timeout::NoWait } else { t }
}

fn send(mqd: mqd_t, msg: &[u8], prio: u32, timeout: Timeout) -> c_int {
    let (q, flags) = match check(mqd) {
        Ok(x) => x,
        Err(e) => return fail(e),
    };
    if prio >= MQ_PRIO_MAX {
        return fail(Error::Invalid);
    }
    if flags & 3 == O_RDONLY {
        return fail(Error::BadHandle);
    }
    if QUEUES[q].lock(|m| msg.len() > m.msgsize) {
        set_msgsize_error();
        return -1;
    }
    let r = block_on(
        key_not_full(q),
        timeout_for(flags, timeout),
        |k| {
            let sent = QUEUES[q].lock(|m| {
                let slot = m.msgs[..m.maxmsg].iter().position(|x| x.is_none())?;
                let off = slot * m.msgsize;
                m.data[off..off + msg.len()].copy_from_slice(msg);
                m.seq = m.seq.wrapping_add(1);
                m.msgs[slot] = Some(Msg { len: msg.len() as u16, prio, seq: m.seq });
                Some(())
            });
            sent.map(|_| {
                k.wake_one(key_not_empty(q), WakeReason::Signaled);
            })
        },
        |_| (),
        |_| {},
    );
    match r {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

fn set_msgsize_error() {
    super::set_errno(crate::compat::errno::EMSGSIZE);
}

fn receive(mqd: mqd_t, buf: &mut [u8], prio: Option<&mut u32>, timeout: Timeout) -> isize {
    let (q, flags) = match check(mqd) {
        Ok(x) => x,
        Err(e) => return fail(e) as isize,
    };
    if flags & 3 == O_WRONLY {
        return fail(Error::BadHandle) as isize;
    }
    if QUEUES[q].lock(|m| buf.len() < m.msgsize) {
        set_msgsize_error();
        return -1;
    }
    let r = block_on(
        key_not_empty(q),
        timeout_for(flags, timeout),
        |k| {
            let got = QUEUES[q].lock(|m| {
                // Highest priority first; oldest (smallest seq) within a priority.
                let (slot, msg) = m.msgs[..m.maxmsg]
                    .iter()
                    .enumerate()
                    .filter_map(|(i, x)| x.map(|x| (i, x)))
                    .max_by(|(_, a), (_, b)| a.prio.cmp(&b.prio).then((b.seq.wrapping_sub(a.seq) as i32).cmp(&0)))?;
                let off = slot * m.msgsize;
                buf[..msg.len as usize].copy_from_slice(&m.data[off..off + msg.len as usize]);
                m.msgs[slot] = None;
                Some((msg.len as usize, msg.prio))
            });
            got.inspect(|_| {
                k.wake_one(key_not_full(q), WakeReason::Signaled);
            })
        },
        |_| (0, 0),
        |_| {},
    );
    match r {
        Ok((n, p)) => {
            if let Some(out) = prio {
                *out = p;
            }
            n as isize
        }
        Err(e) => fail(e) as isize,
    }
}

pub fn mq_send(mqd: mqd_t, msg: &[u8], prio: u32) -> c_int {
    send(mqd, msg, prio, Timeout::Forever)
}

pub fn mq_timedsend(mqd: mqd_t, msg: &[u8], prio: u32, abstime: &timespec) -> c_int {
    let blocking = check(mqd).is_ok_and(|(_, f)| f & O_NONBLOCK == 0);
    let r = send(mqd, msg, prio, timeout_from_abstime(abstime));
    if blocking && r == -1 && super::errno() == crate::compat::errno::EAGAIN {
        super::set_errno(crate::compat::errno::ETIMEDOUT);
    }
    r
}

/// Returns the message length, or -1. `buf` must be at least `mq_msgsize` bytes.
pub fn mq_receive(mqd: mqd_t, buf: &mut [u8], prio: Option<&mut u32>) -> isize {
    receive(mqd, buf, prio, Timeout::Forever)
}

pub fn mq_timedreceive(mqd: mqd_t, buf: &mut [u8], prio: Option<&mut u32>, abstime: &timespec) -> isize {
    let blocking = check(mqd).is_ok_and(|(_, f)| f & O_NONBLOCK == 0);
    let r = receive(mqd, buf, prio, timeout_from_abstime(abstime));
    if blocking && r == -1 && super::errno() == crate::compat::errno::EAGAIN {
        super::set_errno(crate::compat::errno::ETIMEDOUT);
    }
    r
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    for q in QUEUES.iter() {
        q.lock(|m| *m = Mq::EMPTY);
    }
    DESCS.lock(|d| *d = [None; MAX_DESCRIPTORS]);
}
