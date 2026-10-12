//! Sockets: UDP and TCP for application tasks.
//!
//! The IP stack is owned by the net task. Applications talk to it through
//! * a command queue (bind / connect / listen / close), answered via per-socket event
//!   flags, and
//! * per-socket packet queues carrying [`PacketBuf`]s from the `APP_POOL` in each
//!   direction (bounded, so a slow reader applies TCP flow control instead of exhausting
//!   memory).
//!
//! Classification: L3 services · net: sockets · safe · net-ip

use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicU16, Ordering};

use smoltcp::socket::{icmp, tcp, udp};

use super::buf::{MAX_FRAME, PacketBuf};
use super::ip::{self, Stack};
use super::{APP_POOL, IfIndex, schedule};
use crate::Error;
use crate::config::{NET_ICMP_SOCKETS, NET_IP_IFACES, NET_TCP_SOCKETS, NET_UDP_SOCKETS};
use crate::kernel::cell::IrqCell;
use crate::kernel::time::Timeout;
use crate::sync::{EventFlags, Queue, WaitMode};

const PER_IFACE: usize = NET_UDP_SOCKETS + NET_TCP_SOCKETS + NET_ICMP_SOCKETS;
const MAX_SLOTS: usize = NET_IP_IFACES * PER_IFACE;
const SLOT_QUEUE: usize = 4;

const EV_DONE: u32 = 1 << 0;
const EV_CONNECTED: u32 = 1 << 1;
const EV_CLOSED: u32 = 1 << 2;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Kind {
    Udp,
    Tcp,
    Icmp,
}

#[derive(Copy, Clone)]
struct SlotState {
    in_use: bool,
    result: Result<(), Error>,
    connected: bool,
    eof_sent: bool,
    closing: bool,
    local_port: u16,
}

impl SlotState {
    const FREE: SlotState =
        SlotState { in_use: false, result: Ok(()), connected: false, eof_sent: false, closing: false, local_port: 0 };
}

struct Slot {
    state: IrqCell<SlotState>,
    events: EventFlags,
    rx: Queue<PacketBuf, SLOT_QUEUE>,
    tx: Queue<PacketBuf, SLOT_QUEUE>,
    leftover: IrqCell<Option<PacketBuf>>,
}

static SLOTS: [Slot; MAX_SLOTS] = [const {
    Slot {
        state: IrqCell::new(SlotState::FREE),
        events: EventFlags::new(),
        rx: Queue::new(),
        tx: Queue::new(),
        leftover: IrqCell::new(None),
    }
}; MAX_SLOTS];

#[derive(Copy, Clone, Debug)]
enum Cmd {
    UdpBind { slot: u8, port: u16 },
    TcpConnect { slot: u8, remote: SocketAddrV4, local_port: u16 },
    TcpListen { slot: u8, port: u16 },
    IcmpBind { slot: u8, ident: u16 },
    Close { slot: u8 },
}

static CMDQ: Queue<Cmd, 16> = Queue::new();
static EPHEMERAL: AtomicU16 = AtomicU16::new(49152);

/// `(instance, kind, index within kind)` of a slot.
fn decode(slot: usize) -> (usize, Kind, usize) {
    let (inst, off) = (slot / PER_IFACE, slot % PER_IFACE);
    if off < NET_UDP_SOCKETS {
        (inst, Kind::Udp, off)
    } else if off < NET_UDP_SOCKETS + NET_TCP_SOCKETS {
        (inst, Kind::Tcp, off - NET_UDP_SOCKETS)
    } else {
        (inst, Kind::Icmp, off - NET_UDP_SOCKETS - NET_TCP_SOCKETS)
    }
}

fn free_slot(slot: usize) {
    let s = &SLOTS[slot];
    while s.rx.try_recv().is_ok() {}
    while s.tx.try_recv().is_ok() {}
    s.leftover.lock(|l| *l = None);
    // Events are deliberately left alone: a task may still be about to observe the
    // final `EV_DONE`. They are cleared when the slot is next claimed.
    s.state.lock(|st| *st = SlotState::FREE);
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    while CMDQ.try_recv().is_ok() {}
    for i in 0..MAX_SLOTS {
        free_slot(i);
    }
    EPHEMERAL.store(49152, Ordering::Relaxed);
}

// ----- application side -----

fn claim(idx: IfIndex, kind: Kind) -> Result<usize, Error> {
    let inst = ip::instance_of(idx)?;
    for slot in inst * PER_IFACE..(inst + 1) * PER_IFACE {
        if decode(slot).1 != kind {
            continue;
        }
        let got = SLOTS[slot].state.lock(|st| {
            if st.in_use {
                false
            } else {
                *st = SlotState { in_use: true, ..SlotState::FREE };
                true
            }
        });
        if got {
            SLOTS[slot].events.clear(u32::MAX);
            return Ok(slot);
        }
    }
    Err(Error::NoResources)
}

/// Send a command to the net task and wait for its completion.
fn command(slot: usize, cmd: Cmd) -> Result<(), Error> {
    let s = &SLOTS[slot];
    s.events.clear(EV_DONE);
    CMDQ.send(cmd, Timeout::Forever).map_err(|e| e.error)?;
    schedule();
    s.events.wait(EV_DONE, WaitMode::Any, true, Timeout::Forever)?;
    s.state.lock(|st| st.result)
}

fn ephemeral_port() -> u16 {
    let p = EPHEMERAL.fetch_add(1, Ordering::Relaxed);
    if p == u16::MAX {
        EPHEMERAL.store(49152, Ordering::Relaxed);
    }
    p
}

/// Copy as much as possible from the slot's receive side into `buf`.
/// Returns `Ok(None)` if nothing is available within the timeout.
fn read_stream(slot: usize, buf: &mut [u8], timeout: Timeout) -> Result<usize, Error> {
    let s = &SLOTS[slot];
    let mut pkt = match s.leftover.lock(|l| l.take()) {
        Some(p) => p,
        None => s.rx.recv(timeout)?,
    };
    if pkt.is_empty() {
        // End-of-stream marker: keep it so later reads also see EOF.
        s.leftover.lock(|l| *l = Some(pkt));
        return Ok(0);
    }
    let n = pkt.len().min(buf.len());
    buf[..n].copy_from_slice(&pkt.data()[..n]);
    if n < pkt.len() {
        pkt.pull_header(n)?;
        s.leftover.lock(|l| *l = Some(pkt));
    }
    Ok(n)
}

/// A UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    pub(crate) slot: usize,
    pub(crate) port: u16,
}

impl UdpSocket {
    /// Bind to `port` on the first IP interface (0 = pick an ephemeral port).
    pub fn bind(port: u16) -> Result<Self, Error> {
        Self::bind_on(ip::default_iface()?, port)
    }

    pub fn bind_on(idx: IfIndex, port: u16) -> Result<Self, Error> {
        crate::security::check_net(Some(port), None, false)?;
        let port = if port == 0 { ephemeral_port() } else { port };
        let slot = claim(idx, Kind::Udp)?;
        if let Err(e) = command(slot, Cmd::UdpBind { slot: slot as u8, port }) {
            free_slot(slot);
            return Err(e);
        }
        Ok(UdpSocket { slot, port })
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// Send one datagram (at most one packet block).
    pub fn send_to(&self, data: &[u8], to: SocketAddrV4) -> Result<usize, Error> {
        if data.len() > MAX_FRAME - 64 {
            return Err(Error::Overflow);
        }
        crate::security::check_net(None, Some(to.ip().octets()), false)?;
        let mut p = APP_POOL.alloc_from(data, Timeout::Forever)?;
        p.meta.peer = Some((to.ip().octets(), to.port()));
        SLOTS[self.slot].tx.send(p, Timeout::Forever).map_err(|e| e.error)?;
        schedule();
        Ok(data.len())
    }

    /// Receive one datagram; excess bytes beyond `buf` are discarded.
    pub fn recv_from(&self, buf: &mut [u8], timeout: Timeout) -> Result<(usize, SocketAddrV4), Error> {
        let p = SLOTS[self.slot].rx.recv(timeout)?;
        let n = p.len().min(buf.len());
        buf[..n].copy_from_slice(&p.data()[..n]);
        let (ip, port) = p.meta.peer.unwrap_or(([0; 4], 0));
        Ok((n, SocketAddrV4::new(Ipv4Addr::from(ip), port)))
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let _ = command(self.slot, Cmd::Close { slot: self.slot as u8 });
        free_slot(self.slot);
    }
}

/// A connected TCP stream.
#[derive(Debug)]
pub struct TcpStream {
    pub(crate) slot: usize,
}

impl TcpStream {
    /// Connect via the first IP interface.
    pub fn connect(to: SocketAddrV4, timeout: Timeout) -> Result<Self, Error> {
        Self::connect_on(ip::default_iface()?, to, timeout)
    }

    pub fn connect_on(idx: IfIndex, to: SocketAddrV4, timeout: Timeout) -> Result<Self, Error> {
        crate::security::check_net(None, Some(to.ip().octets()), false)?;
        let slot = claim(idx, Kind::Tcp)?;
        let stream = TcpStream { slot };
        command(slot, Cmd::TcpConnect { slot: slot as u8, remote: to, local_port: ephemeral_port() })?;
        let ev = SLOTS[slot].events.wait(EV_CONNECTED | EV_CLOSED, WaitMode::Any, false, timeout)?;
        if ev & EV_CONNECTED == 0 {
            return Err(Error::Io); // refused / reset
        }
        Ok(stream)
    }

    /// Read available bytes, waiting up to `timeout` for some. `Ok(0)` means the peer
    /// closed the connection.
    pub fn read(&self, buf: &mut [u8], timeout: Timeout) -> Result<usize, Error> {
        read_stream(self.slot, buf, timeout)
    }

    /// Queue `data` for sending; returns the number of bytes accepted (at most one block).
    pub fn write(&self, data: &[u8], timeout: Timeout) -> Result<usize, Error> {
        if SLOTS[self.slot].events.get() & EV_CLOSED != 0 {
            return Err(Error::Io);
        }
        let n = data.len().min(MAX_FRAME);
        let p = APP_POOL.alloc_from(&data[..n], timeout)?;
        SLOTS[self.slot].tx.send(p, timeout).map_err(|e| e.error)?;
        schedule();
        Ok(n)
    }

    pub fn write_all(&self, mut data: &[u8]) -> Result<(), Error> {
        while !data.is_empty() {
            let n = self.write(data, Timeout::Forever)?;
            data = &data[n..];
        }
        Ok(())
    }

    /// Whether the peer is still connected.
    pub fn is_connected(&self) -> bool {
        SLOTS[self.slot].events.get() & EV_CLOSED == 0
    }

    /// Gracefully close (pending data is sent first).
    pub fn close(self) {}
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = command(self.slot, Cmd::Close { slot: self.slot as u8 });
    }
}

/// A TCP listening socket.
#[derive(Debug)]
pub struct TcpListener {
    pub(crate) idx: IfIndex,
    pub(crate) port: u16,
    pub(crate) slot: Option<usize>,
}

impl TcpListener {
    pub fn bind(port: u16) -> Result<Self, Error> {
        Self::bind_on(ip::default_iface()?, port)
    }

    pub fn bind_on(idx: IfIndex, port: u16) -> Result<Self, Error> {
        crate::security::check_net(Some(port), None, true)?;
        let mut l = TcpListener { idx, port, slot: None };
        l.arm()?;
        Ok(l)
    }

    fn arm(&mut self) -> Result<(), Error> {
        let slot = claim(self.idx, Kind::Tcp)?;
        if let Err(e) = command(slot, Cmd::TcpListen { slot: slot as u8, port: self.port }) {
            free_slot(slot);
            return Err(e);
        }
        self.slot = Some(slot);
        Ok(())
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// Wait for an incoming connection. The listener re-arms itself on a fresh socket.
    pub fn accept(&mut self, timeout: Timeout) -> Result<TcpStream, Error> {
        if self.slot.is_none() {
            self.arm()?;
        }
        let slot = self.slot.ok_or(Error::NoResources)?;
        SLOTS[slot].events.wait(EV_CONNECTED, WaitMode::Any, false, timeout)?;
        self.slot = None;
        let _ = self.arm(); // best effort; retried on the next accept
        Ok(TcpStream { slot })
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            let _ = command(slot, Cmd::Close { slot: slot as u8 });
        }
    }
}

/// An ICMP socket — ping, and other ICMP echo exchanges. Bound to an identifier so the stack
/// routes matching echo replies to it.
pub struct IcmpSocket {
    slot: usize,
    ident: u16,
}

impl IcmpSocket {
    /// Open an ICMP socket bound to `ident` on the first IP interface.
    pub fn open(ident: u16) -> Result<Self, Error> {
        Self::open_on(ip::default_iface()?, ident)
    }

    pub fn open_on(idx: IfIndex, ident: u16) -> Result<Self, Error> {
        crate::security::check_net(None, None, false)?;
        let slot = claim(idx, Kind::Icmp)?;
        if let Err(e) = command(slot, Cmd::IcmpBind { slot: slot as u8, ident }) {
            free_slot(slot);
            return Err(e);
        }
        Ok(IcmpSocket { slot, ident })
    }

    /// Send one ICMP echo request (a ping) to `dst` with sequence `seq` and `payload`.
    pub fn ping(&self, dst: Ipv4Addr, seq: u16, payload: &[u8]) -> Result<(), Error> {
        use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};
        let repr = Icmpv4Repr::EchoRequest { ident: self.ident, seq_no: seq, data: payload };
        let len = repr.buffer_len();
        let mut buf = [0u8; 128];
        if len > buf.len() {
            return Err(Error::Overflow);
        }
        // Emit with checksum left zero; the net core fills ICMP/IP checksums for non-offload NICs.
        let mut pkt = Icmpv4Packet::new_unchecked(&mut buf[..len]);
        repr.emit(&mut pkt, &smoltcp::phy::ChecksumCapabilities::ignored());
        let mut p = APP_POOL.alloc_from(&buf[..len], Timeout::Forever)?;
        p.meta.peer = Some((dst.octets(), 0));
        SLOTS[self.slot].tx.send(p, Timeout::Forever).map_err(|e| e.error)?;
        schedule();
        Ok(())
    }

    /// Receive one raw ICMP packet; returns its length and source address.
    pub fn recv(&self, buf: &mut [u8], timeout: Timeout) -> Result<(usize, Ipv4Addr), Error> {
        let p = SLOTS[self.slot].rx.recv(timeout)?;
        let n = p.len().min(buf.len());
        buf[..n].copy_from_slice(&p.data()[..n]);
        let (ip, _) = p.meta.peer.unwrap_or(([0; 4], 0));
        Ok((n, Ipv4Addr::from(ip)))
    }

    /// Wait for an echo reply whose sequence is `seq`; returns the responder's address.
    pub fn recv_reply(&self, seq: u16, timeout: Timeout) -> Result<Ipv4Addr, Error> {
        use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};
        let mut buf = [0u8; 128];
        let (n, from) = self.recv(&mut buf, timeout)?;
        let pkt = Icmpv4Packet::new_checked(&buf[..n]).map_err(|_| Error::Io)?;
        let repr = Icmpv4Repr::parse(&pkt, &smoltcp::phy::ChecksumCapabilities::ignored()).map_err(|_| Error::Io)?;
        match repr {
            Icmpv4Repr::EchoReply { seq_no, .. } if seq_no == seq => Ok(from),
            _ => Err(Error::NotReady),
        }
    }
}

impl Drop for IcmpSocket {
    fn drop(&mut self) {
        let _ = command(self.slot, Cmd::Close { slot: self.slot as u8 });
        free_slot(self.slot);
    }
}

/// Readiness of a socket slot for `poll()`: (readable, writable).
pub(crate) fn readiness(slot: usize) -> (bool, bool) {
    let s = &SLOTS[slot];
    let ev = s.events.get();
    let readable = !s.rx.is_empty() || s.leftover.lock(|l| l.is_some()) || ev & EV_CLOSED != 0;
    (readable, !s.tx.is_full())
}

/// Whether a listening slot has a connection ready to accept.
pub(crate) fn acceptable(slot: usize) -> bool {
    SLOTS[slot].events.get() & EV_CONNECTED != 0
}

// ----- net task side -----

/// Socket bookkeeping owned by the net task.
pub(crate) struct NetSide {
    /// A TCP send packet only partially accepted by smoltcp: (packet, bytes sent).
    partial: [Option<(PacketBuf, usize)>; MAX_SLOTS],
    busy: bool,
}

impl NetSide {
    pub(crate) fn new() -> Self {
        NetSide { partial: [const { None }; MAX_SLOTS], busy: false }
    }

    /// Whether data is still waiting to move (poll again soon instead of sleeping).
    pub(crate) fn busy(&self) -> bool {
        self.busy
    }

    pub(crate) fn service(&mut self, stacks: &mut [Option<Stack<'_>>]) {
        while let Ok(cmd) = CMDQ.try_recv() {
            self.command(stacks, cmd);
        }
        self.busy = false;
        for slot in 0..MAX_SLOTS {
            let st = SLOTS[slot].state.lock(|s| *s);
            if !st.in_use {
                continue;
            }
            let (inst, kind, i) = decode(slot);
            let Some(Some(stack)) = stacks.get_mut(inst) else { continue };
            match kind {
                Kind::Udp if st.closing => {}
                Kind::Udp => self.udp(stack, slot, i),
                Kind::Tcp => self.tcp(stack, slot, i, st),
                Kind::Icmp if st.closing => {}
                Kind::Icmp => self.icmp(stack, slot, i),
            }
        }
    }

    fn finish(slot: usize, r: Result<(), Error>) {
        SLOTS[slot].state.lock(|s| s.result = r);
        SLOTS[slot].events.set(EV_DONE);
    }

    fn command(&mut self, stacks: &mut [Option<Stack<'_>>], cmd: Cmd) {
        let slot = match cmd {
            Cmd::UdpBind { slot, .. }
            | Cmd::TcpConnect { slot, .. }
            | Cmd::TcpListen { slot, .. }
            | Cmd::IcmpBind { slot, .. }
            | Cmd::Close { slot } => slot as usize,
        };
        let (inst, kind, i) = decode(slot);
        let Some(Some(stack)) = stacks.get_mut(inst) else {
            Self::finish(slot, Err(Error::NotReady));
            return;
        };
        let r = match (cmd, kind) {
            (Cmd::UdpBind { port, .. }, Kind::Udp) => {
                SLOTS[slot].state.lock(|s| s.local_port = port);
                stack.sockets.get_mut::<udp::Socket<'_>>(stack.udp[i]).bind(port).map_err(|_| Error::Exists)
            }
            (Cmd::TcpConnect { remote, local_port, .. }, Kind::Tcp) => {
                let ep = ip::endpoint(remote.ip().octets(), remote.port());
                let cx = stack.iface.context();
                stack.sockets.get_mut::<tcp::Socket<'_>>(stack.tcp[i]).connect(cx, ep, local_port).map_err(|_| Error::Invalid)
            }
            (Cmd::TcpListen { port, .. }, Kind::Tcp) => {
                SLOTS[slot].state.lock(|s| s.local_port = port);
                stack.sockets.get_mut::<tcp::Socket<'_>>(stack.tcp[i]).listen(port).map_err(|_| Error::Invalid)
            }
            (Cmd::IcmpBind { ident, .. }, Kind::Icmp) => {
                stack.sockets.get_mut::<icmp::Socket<'_>>(stack.icmp[i]).bind(icmp::Endpoint::Ident(ident)).map_err(|_| Error::Exists)
            }
            (Cmd::Close { .. }, Kind::Udp) => {
                stack.sockets.get_mut::<udp::Socket<'_>>(stack.udp[i]).close();
                // Stop servicing it; the closing task frees the slot after `EV_DONE`.
                SLOTS[slot].state.lock(|s| s.closing = true);
                Ok(())
            }
            (Cmd::Close { .. }, Kind::Tcp) => {
                SLOTS[slot].state.lock(|s| s.closing = true);
                Ok(())
            }
            (Cmd::Close { .. }, Kind::Icmp) => {
                SLOTS[slot].state.lock(|s| s.closing = true);
                Ok(())
            }
            _ => Err(Error::Invalid),
        };
        Self::finish(slot, r);
    }

    fn udp(&mut self, stack: &mut Stack<'_>, slot: usize, i: usize) {
        let s = &SLOTS[slot];
        let sock = stack.sockets.get_mut::<udp::Socket<'_>>(stack.udp[i]);
        while sock.can_send() {
            let Ok(p) = s.tx.try_recv() else { break };
            if let Some((addr, port)) = p.meta.peer {
                let _ = sock.send_slice(p.data(), ip::endpoint(addr, port));
            }
        }
        while sock.can_recv() && !s.rx.is_full() {
            let Ok(mut p) = APP_POOL.try_alloc() else {
                self.busy = true;
                break;
            };
            match sock.recv_slice(p.rx_space()) {
                Ok((n, meta)) => {
                    let _ = p.set_len(n);
                    #[allow(irrefutable_let_patterns)]
                    if let smoltcp::wire::IpAddress::Ipv4(a) = meta.endpoint.addr {
                        p.meta.peer = Some((a.octets(), meta.endpoint.port));
                    }
                    let _ = s.rx.try_send(p);
                }
                Err(_) => break,
            }
        }
    }

    fn icmp(&mut self, stack: &mut Stack<'_>, slot: usize, i: usize) {
        let s = &SLOTS[slot];
        let sock = stack.sockets.get_mut::<icmp::Socket<'_>>(stack.icmp[i]);
        // Application -> wire: each queued buffer is a fully-formed ICMP packet for `peer`.
        while sock.can_send() {
            let Ok(p) = s.tx.try_recv() else { break };
            if let Some((addr, _)) = p.meta.peer {
                let _ = sock.send_slice(p.data(), ip::endpoint(addr, 0).addr);
            }
        }
        // Wire -> application: deliver received ICMP packets (e.g. echo replies).
        while sock.can_recv() && !s.rx.is_full() {
            let Ok(mut p) = APP_POOL.try_alloc() else {
                self.busy = true;
                break;
            };
            match sock.recv_slice(p.rx_space()) {
                Ok((n, addr)) => {
                    let _ = p.set_len(n);
                    #[allow(irrefutable_let_patterns)]
                    if let smoltcp::wire::IpAddress::Ipv4(a) = addr {
                        p.meta.peer = Some((a.octets(), 0));
                    }
                    let _ = s.rx.try_send(p);
                }
                Err(_) => break,
            }
        }
    }

    fn tcp(&mut self, stack: &mut Stack<'_>, slot: usize, i: usize, st: SlotState) {
        let s = &SLOTS[slot];
        let sock = stack.sockets.get_mut::<tcp::Socket<'_>>(stack.tcp[i]);

        // Application -> socket, honouring partial acceptance.
        while sock.can_send() {
            let (p, off) = match self.partial[slot].take() {
                Some(x) => x,
                None => match s.tx.try_recv() {
                    Ok(p) => (p, 0),
                    Err(_) => break,
                },
            };
            match sock.send_slice(&p.data()[off..]) {
                Ok(n) if off + n < p.len() => {
                    self.partial[slot] = Some((p, off + n));
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        if self.partial[slot].is_some() || !s.tx.is_empty() {
            self.busy |= sock.can_send();
        }

        // Socket -> application (bounded: a full queue closes the TCP window).
        while sock.can_recv() && !s.rx.is_full() {
            let Ok(mut p) = APP_POOL.try_alloc() else {
                self.busy = true;
                break;
            };
            match sock.recv_slice(p.rx_space()) {
                Ok(n) if n > 0 => {
                    let _ = p.set_len(n);
                    let _ = s.rx.try_send(p);
                }
                _ => break,
            }
        }

        let state = sock.state();
        if !st.connected && matches!(state, tcp::State::Established | tcp::State::CloseWait) {
            s.state.lock(|x| x.connected = true);
            s.events.set(EV_CONNECTED);
        }
        let peer_done = st.connected && !sock.may_recv() && !sock.can_recv();
        let dead = matches!(state, tcp::State::Closed | tcp::State::TimeWait)
            && (st.connected || s.state.lock(|x| x.result.is_ok()) && !sock.is_listening() && st.local_port == 0);
        if (peer_done || dead) && !st.eof_sent {
            if let Ok(eof) = APP_POOL.try_alloc() {
                if s.rx.try_send(eof).is_ok() {
                    s.state.lock(|x| x.eof_sent = true);
                    s.events.set(EV_CLOSED);
                }
            } else {
                self.busy = true;
            }
        }
        if !st.connected && state == tcp::State::Closed && !sock.is_listening() && st.local_port == 0 {
            // Connection attempt failed (refused / timed out).
            s.events.set(EV_CLOSED);
        }

        if st.closing {
            let drained = self.partial[slot].is_none() && s.tx.is_empty();
            if drained && sock.is_open() && !matches!(state, tcp::State::FinWait1 | tcp::State::FinWait2 | tcp::State::Closing | tcp::State::LastAck | tcp::State::TimeWait) {
                sock.close();
            }
            let finished = matches!(state, tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen)
                || (state == tcp::State::SynSent);
            if finished {
                sock.abort();
                self.partial[slot] = None;
                free_slot(slot);
            }
        }
    }
}
