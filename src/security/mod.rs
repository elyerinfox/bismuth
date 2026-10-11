//! Security contexts: domains, handles and rights (see `docs/research/security.md`).
//!
//! * A **domain** is the unit of isolation: a group of tasks with its own handle table,
//!   policy (priority ceiling, task quota, network policy, bad-handle policy) and its own
//!   random-number generator. Domain 0 is the kernel domain.
//! * A **handle** names a kernel object *in one domain's table* and carries **rights**.
//!   Rights can only ever be reduced (duplicate/drop), never widened, and every handle
//!   is checked against the object's generation, so revoking an object invalidates all
//!   outstanding handles at once.
//! * **No ambient authority:** tasks in an isolated (non-trusted) domain cannot use the
//!   raw device API; they act only through handles granted to them, and rights are
//!   checked *before* the middleware chain runs ([`DeviceCap`]). Middleware sees an
//!   unforgeable [`Caller`] on every request.
//! * Policy only tightens after [`seal`]: no new domains or grants, only
//!   self-restriction ([`drop_rights`], [`restrict`]).
//!
//! Everything here is safe Rust; enforcement on hardware (unprivileged mode + MPU) builds
//! on these same checks.
//!
//! Classification: L3 services · security: domains, handles, rights · safe · always

#[cfg(feature = "crypto")]
pub mod entropy;
#[cfg(feature = "crypto")]
pub mod keystore;
#[cfg(feature = "tpm")]
pub mod trust;
#[cfg(feature = "tpm")]
pub mod retained;
#[cfg(all(feature = "containers", feature = "crypto"))]
pub mod bundle;
#[cfg(feature = "containers")]
pub mod container;
pub mod manifest;
pub mod syscall;

use core::fmt;
use core::ops::{BitAnd, BitOr};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::Error;
use crate::driver::{Device, IoResult, Middleware, Op, PowerState, Request};
use crate::kernel::cell::IrqCell;
use crate::kernel::time::Timeout;

/// Maximum number of security domains (including the kernel domain).
pub const MAX_DOMAINS: usize = 8;
/// Handle-table capacity per domain.
pub const HANDLES: usize = 16;

/// Identifies a security domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainId(pub u8);

impl DomainId {
    /// The privileged kernel domain.
    pub const KERNEL: DomainId = DomainId(0);
}

/// Access rights carried by a handle.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct Rights(pub u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    /// `Op::Read`, receive.
    pub const READ: Rights = Rights(1 << 0);
    /// `Op::Write`, send.
    pub const WRITE: Rights = Rights(1 << 1);
    /// `Op::Transfer` (bus transactions).
    pub const TRANSFER: Rights = Rights(1 << 2);
    /// Operational ioctls (queries, GPIO set/clear, ...).
    pub const CONTROL: Rights = Rights(1 << 3);
    /// Configuration ioctls (baud rate, pin direction, sample rate, offloads, ...).
    pub const CONFIG: Rights = Rights(1 << 4);
    /// `Op::Power`.
    pub const POWER: Rights = Rights(1 << 5);
    /// Duplicate the handle (with equal or fewer rights).
    pub const DUPLICATE: Rights = Rights(1 << 8);
    /// Attach/detach middleware.
    pub const MANAGE: Rights = Rights(1 << 10);
    /// Statistics and descriptive information.
    pub const INSPECT: Rights = Rights(1 << 12);
    // key objects
    pub const K_ENCRYPT: Rights = Rights(1 << 16);
    pub const K_DECRYPT: Rights = Rights(1 << 17);
    pub const K_SIGN: Rights = Rights(1 << 18);
    pub const K_VERIFY: Rights = Rights(1 << 19);
    pub const K_DERIVE: Rights = Rights(1 << 20);
    /// Read raw key material out of the keystore. Almost never granted.
    pub const K_EXPORT: Rights = Rights(1 << 21);

    pub const DEVICE_RW: Rights = Rights(Self::READ.0 | Self::WRITE.0 | Self::CONTROL.0 | Self::INSPECT.0);
    pub const ALL: Rights = Rights(u32::MAX);

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }
}

impl BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        self.union(rhs)
    }
}

impl BitAnd for Rights {
    type Output = Rights;
    fn bitand(self, rhs: Rights) -> Rights {
        self.intersect(rhs)
    }
}

impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rights({:#x})", self.0)
    }
}

/// The rights required to perform `op` on a device.
pub fn rights_for(op: &Op<'_>) -> Rights {
    match op {
        Op::Read(_) => Rights::READ,
        Op::Write(_) => Rights::WRITE,
        Op::Transfer { .. } => Rights::TRANSFER,
        Op::Power(_) => Rights::POWER,
        Op::Ioctl { cmd, .. } => crate::driver::ioctl::required_right(*cmd),
    }
}

/// Who issued a request, as seen by middleware and drivers. Set by the kernel; cannot
/// be forged or altered by middleware.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub domain: DomainId,
    /// Rights of the handle used (all rights for kernel-domain direct calls).
    pub rights: Rights,
}

impl Caller {
    pub const KERNEL: Caller = Caller { domain: DomainId::KERNEL, rights: Rights::ALL };
}

/// A per-domain reference to a kernel object: `[index:6 | generation:10]`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Handle(u16);

impl Handle {
    fn new(index: usize, generation: u16) -> Self {
        Handle(((generation & 0x3FF) << 6) | index as u16)
    }

    fn index(self) -> usize {
        (self.0 & 0x3F) as usize
    }

    fn generation(self) -> u16 {
        self.0 >> 6
    }

    pub fn raw(self) -> u16 {
        self.0
    }

    pub fn from_raw(v: u16) -> Self {
        Handle(v)
    }
}

/// The object a handle refers to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Device(Device),
    /// A keystore slot and its generation.
    Key { slot: u8, generation: u16 },
    /// A directory-subtree capability: the root of what a domain may name, as a
    /// `(MountId, FsVnode, mount-generation)` triple in raw form (the `fs` layer interprets
    /// it). This is the per-domain static chroot.
    Dir { mount: u8, vnode: u32, generation: u16 },
    /// An open file: the VFS open-file-table index (the `fs` layer interprets it).
    File { open: u16 },
}

#[derive(Copy, Clone, Debug)]
struct Slot {
    object: Object,
    rights: Rights,
    /// Name in the domain's namespace (e.g. `"temp0"` for `/dev/temp0`).
    name: &'static str,
}

/// A fixed-size handle table.
#[derive(Copy, Clone)]
pub(crate) struct HandleTable {
    slots: [Option<Slot>; HANDLES],
    generations: [u16; HANDLES],
}

impl HandleTable {
    const EMPTY: HandleTable = HandleTable { slots: [None; HANDLES], generations: [0; HANDLES] };

    fn insert(&mut self, object: Object, rights: Rights, name: &'static str) -> Result<Handle, Error> {
        let i = self.slots.iter().position(|s| s.is_none()).ok_or(Error::NoResources)?;
        self.generations[i] = (self.generations[i] + 1) & 0x3FF;
        if self.generations[i] == 0 {
            self.generations[i] = 1; // handle value 0 is never valid
        }
        self.slots[i] = Some(Slot { object, rights, name });
        Ok(Handle::new(i, self.generations[i]))
    }

    fn get(&self, h: Handle) -> Result<Slot, Error> {
        let i = h.index();
        match self.slots.get(i) {
            Some(Some(s)) if self.generations[i] == h.generation() => Ok(*s),
            _ => Err(Error::BadHandle),
        }
    }

    fn get_mut(&mut self, h: Handle) -> Result<&mut Slot, Error> {
        let i = h.index();
        if self.generations.get(i) != Some(&h.generation()) {
            return Err(Error::BadHandle);
        }
        self.slots.get_mut(i).and_then(|s| s.as_mut()).ok_or(Error::BadHandle)
    }

    fn remove(&mut self, h: Handle) -> Result<Slot, Error> {
        let s = self.get(h)?;
        self.slots[h.index()] = None;
        Ok(s)
    }

    fn find_name(&self, name: &str) -> Option<Handle> {
        self.slots
            .iter()
            .enumerate()
            .find(|(_, s)| s.is_some_and(|s| s.name == name))
            .map(|(i, _)| Handle::new(i, self.generations[i]))
    }
}

/// What happens when a domain uses an invalid handle (Zircon `ZX_POL_BAD_HANDLE`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BadHandlePolicy {
    /// Return `Error::BadHandle`.
    Deny,
    /// Terminate every task of the domain: a confused domain should die, not probe.
    Kill,
}

/// Which network endpoints a domain may use.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NetPolicy {
    /// Inclusive range of local ports the domain may bind.
    pub local_ports: (u16, u16),
    /// Remote peers the domain may talk to: (network, prefix length).
    pub peers: ([u8; 4], u8),
    /// Whether the domain may accept incoming TCP connections.
    pub listen: bool,
}

impl NetPolicy {
    pub const ANY: NetPolicy = NetPolicy { local_ports: (0, u16::MAX), peers: ([0; 4], 0), listen: true };

    #[cfg_attr(not(feature = "net-ip"), allow(dead_code))]
    fn peer_ok(&self, ip: [u8; 4]) -> bool {
        let (net, len) = self.peers;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len.min(32) as u32) };
        u32::from_be_bytes(ip) & mask == u32::from_be_bytes(net) & mask
    }
}

/// Declarative description of a domain.
#[derive(Copy, Clone, Debug)]
pub struct DomainSpec {
    pub name: &'static str,
    /// Tasks of this domain can never run above this priority.
    pub priority_ceiling: u8,
    /// Maximum simultaneously live tasks.
    pub max_tasks: u8,
    pub bad_handle: BadHandlePolicy,
    /// Network access (`None` = no sockets at all).
    pub net: Option<NetPolicy>,
    /// Trusted domains keep ambient authority (raw device API). For migration only.
    pub trusted: bool,
    /// May log through the kernel console.
    pub console: bool,
    /// Allow-list of system calls (bit `n` = syscall `n`, see [`syscall::nr`]).
    pub syscalls: u32,
    /// Tasks must be hardware-isolated (unprivileged, MPU-confined, syscalls only).
    pub hardware_isolated: bool,
}

impl DomainSpec {
    /// A locked-down default: no network, no ambient authority, killed on bad handles.
    pub const fn isolated(name: &'static str, priority_ceiling: u8, max_tasks: u8) -> Self {
        DomainSpec {
            name,
            priority_ceiling,
            max_tasks,
            bad_handle: BadHandlePolicy::Kill,
            net: None,
            trusted: false,
            console: true,
            syscalls: syscall::ALL,
            hardware_isolated: false,
        }
    }

    /// A domain whose tasks run unprivileged under the MPU.
    pub const fn sandboxed(name: &'static str, priority_ceiling: u8, max_tasks: u8) -> Self {
        DomainSpec { hardware_isolated: true, ..Self::isolated(name, priority_ceiling, max_tasks) }
    }
}

const KERNEL_SPEC: DomainSpec = DomainSpec {
    name: "kernel",
    priority_ceiling: crate::kernel::task::MAX_PRIORITY,
    max_tasks: crate::config::MAX_TASKS as u8,
    bad_handle: BadHandlePolicy::Deny,
    net: Some(NetPolicy::ANY),
    trusted: true,
    console: true,
    syscalls: syscall::ALL,
    hardware_isolated: false,
};

#[derive(Copy, Clone)]
pub(crate) struct DomainState {
    pub(crate) spec: DomainSpec,
    pub(crate) generation: u16,
    handles: HandleTable,
    killed: bool,
    violations: u32,
    faults: u32,
}

impl DomainState {
    fn new(spec: DomainSpec, generation: u16) -> Self {
        DomainState { spec, generation, handles: HandleTable::EMPTY, killed: false, violations: 0, faults: 0 }
    }
}

const fn initial_domains() -> [Option<DomainState>; MAX_DOMAINS] {
    let mut d = [None; MAX_DOMAINS];
    d[0] = Some(DomainState {
        spec: KERNEL_SPEC,
        generation: 1,
        handles: HandleTable::EMPTY,
        killed: false,
        violations: 0,
        faults: 0,
    });
    d
}

static DOMAINS: IrqCell<[Option<DomainState>; MAX_DOMAINS]> = IrqCell::new(initial_domains());
static SEALED: AtomicBool = AtomicBool::new(false);

fn with_domain<R>(d: DomainId, f: impl FnOnce(&mut DomainState) -> R) -> Result<R, Error> {
    DOMAINS.lock(|t| t.get_mut(d.0 as usize).and_then(|x| x.as_mut()).map(f).ok_or(Error::NotFound))
}

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    DOMAINS.lock(|t| *t = initial_domains());
    SEALED.store(false, Ordering::Relaxed);
    #[cfg(feature = "crypto")]
    {
        entropy::reset();
        keystore::reset();
    }
    #[cfg(feature = "containers")]
    container::reset();
}

/// The domain of the calling task (interrupt handlers and boot code are kernel).
pub fn current() -> DomainId {
    if crate::arch::port::in_isr() {
        return DomainId::KERNEL;
    }
    DomainId(crate::kernel::with(|k| k.cur().domain))
}

/// Whether domain `d` has ambient authority.
pub fn is_trusted(d: DomainId) -> bool {
    d == DomainId::KERNEL || with_domain(d, |s| s.spec.trusted).unwrap_or(false)
}

pub(crate) fn current_is_trusted() -> bool {
    is_trusted(current())
}

fn require_kernel() -> Result<(), Error> {
    if current_is_trusted() { Ok(()) } else { Err(Error::PermissionDenied) }
}

fn require_unsealed() -> Result<(), Error> {
    if SEALED.load(Ordering::Acquire) { Err(Error::PermissionDenied) } else { Ok(()) }
}

/// Create a domain (kernel only, before [`seal`]).
pub fn create_domain(spec: DomainSpec) -> Result<DomainId, Error> {
    require_kernel()?;
    require_unsealed()?;
    if spec.priority_ceiling > crate::kernel::task::MAX_PRIORITY || spec.max_tasks == 0 {
        return Err(Error::Invalid);
    }
    let id = DOMAINS.lock(|t| {
        let i = t.iter().position(|d| d.is_none()).ok_or(Error::NoResources)?;
        t[i] = Some(DomainState::new(spec, 1));
        Ok::<_, Error>(i)
    })?;
    #[cfg(feature = "crypto")]
    entropy::domain_created(DomainId(id as u8));
    Ok(DomainId(id as u8))
}

/// Grant domain `d` a handle to `dev` with `rights`, visible as `/dev/<name>` in its
/// namespace (kernel only, before [`seal`]).
pub fn grant_device(d: DomainId, dev: Device, rights: Rights, name: &'static str) -> Result<Handle, Error> {
    require_kernel()?;
    require_unsealed()?;
    with_domain(d, |s| s.handles.insert(Object::Device(dev), rights, name))?
}

#[cfg_attr(not(feature = "crypto"), allow(dead_code))]
pub(crate) fn grant_object(d: DomainId, object: Object, rights: Rights, name: &'static str) -> Result<Handle, Error> {
    with_domain(d, |s| s.handles.insert(object, rights, name))?
}

/// Find a domain by name.
pub fn find_domain(name: &str) -> Option<DomainId> {
    DOMAINS.lock(|t| t.iter().position(|d| d.is_some_and(|d| d.spec.name == name)).map(|i| DomainId(i as u8)))
}

/// Freeze the security configuration: no more domains or grants; policy can only
/// tighten from now on.
pub fn seal() -> Result<(), Error> {
    require_kernel()?;
    SEALED.store(true, Ordering::Release);
    Ok(())
}

pub fn is_sealed() -> bool {
    SEALED.load(Ordering::Acquire)
}

/// Permanently remove `mask` rights from one of the caller's handles.
pub fn drop_rights(h: Handle, mask: Rights) -> Result<(), Error> {
    with_domain(current(), |s| s.handles.get_mut(h).map(|slot| slot.rights = Rights(slot.rights.0 & !mask.0)))?
}

/// Duplicate one of the caller's handles with a subset of its rights.
pub fn duplicate(h: Handle, rights: Rights) -> Result<Handle, Error> {
    let d = current();
    with_domain(d, |s| {
        let slot = s.handles.get(h)?;
        if !slot.rights.contains(Rights::DUPLICATE) {
            return Err(Error::PermissionDenied);
        }
        s.handles.insert(slot.object, slot.rights & rights, slot.name)
    })?
}

/// Close one of the caller's handles.
pub fn close(h: Handle) -> Result<(), Error> {
    with_domain(current(), |s| s.handles.remove(h).map(|_| ()))?
}

/// Rights of one of the caller's handles.
pub fn rights_of(h: Handle) -> Result<Rights, Error> {
    with_domain(current(), |s| s.handles.get(h).map(|x| x.rights))?
}

/// Self-restriction (`pledge`-style): the calling domain gives up network access and/or
/// lowers its priority ceiling. Never widens anything.
pub fn restrict(no_network: bool, priority_ceiling: Option<u8>) -> Result<(), Error> {
    with_domain(current(), |s| {
        if no_network {
            s.spec.net = None;
        }
        if let Some(c) = priority_ceiling {
            s.spec.priority_ceiling = s.spec.priority_ceiling.min(c);
        }
    })
}

/// Record a hardware protection fault (MPU) against a domain.
#[cfg_attr(any(not(target_os = "none"), feature = "cortex-a"), allow(dead_code))]
pub(crate) fn record_fault(d: DomainId) {
    let _ = with_domain(d, |s| {
        s.violations += 1;
        s.faults += 1;
    });
}

/// Hardware protection faults recorded against a domain.
pub fn faults(d: DomainId) -> u32 {
    with_domain(d, |s| s.faults).unwrap_or(0)
}

/// Number of security violations recorded against a domain.
pub fn violations(d: DomainId) -> u32 {
    with_domain(d, |s| s.violations).unwrap_or(0)
}

pub fn is_killed(d: DomainId) -> bool {
    with_domain(d, |s| s.killed).unwrap_or(false)
}

pub fn domain_generation(d: DomainId) -> u16 {
    with_domain(d, |s| s.generation).unwrap_or(0)
}

/// Terminate every task of domain `d`, close all its handles and bump its generation.
/// Only a trusted domain (or the kernel itself) may call this.
pub fn kill(d: DomainId) -> Result<(), Error> {
    require_kernel()?;
    kill_internal(d)
}

/// Unchecked kill, for internal policy enforcement (fault handlers, violations).
pub(crate) fn kill_internal(d: DomainId) -> Result<(), Error> {
    if d == DomainId::KERNEL {
        return Err(Error::Invalid);
    }
    with_domain(d, |s| {
        s.killed = true;
        s.handles = HandleTable::EMPTY;
        s.generation = s.generation.wrapping_add(1);
    })?;
    #[cfg(feature = "crypto")]
    entropy::domain_created(d); // fresh, independent DRBG for any restart
    crate::kernel::with(|k| {
        for i in 0..k.tasks.len() as u8 {
            let t = &k.tasks[i as usize];
            if t.domain != d.0 || matches!(t.state, crate::TaskState::Free) {
                continue;
            }
            if !matches!(t.state, crate::TaskState::Dead) {
                k.retire(i, usize::MAX);
                k.wake_joiners(i); // release anyone blocked in `join`
            }
            // Free the slot and its stack now (both freshly-retired and already-exited
            // tasks), unless it is the running task — that one is reaped once switched
            // out — so a restart can reclaim the stack.
            if i != k.current && matches!(k.tasks[i as usize].state, crate::TaskState::Dead) {
                k.reap(i);
            }
        }
        crate::arch::port::request_switch();
    });
    #[cfg(feature = "crypto")]
    keystore::purge_domain(d);
    Ok(())
}

/// Record a violation; apply the domain's bad-handle policy.
fn violation(d: DomainId, e: Error) -> Error {
    let kill_it = with_domain(d, |s| {
        s.violations += 1;
        !s.spec.trusted && s.spec.bad_handle == BadHandlePolicy::Kill && e == Error::BadHandle
    })
    .unwrap_or(false);
    if kill_it {
        let _ = kill_internal(d);
    }
    e
}

// ----- checks used by other subsystems -----

/// Validate a task spawn: target domain, priority ceiling and task quota.
pub(crate) fn check_spawn(
    creator: DomainId,
    target: DomainId,
    prio: u8,
    live_in_target: usize,
    user: bool,
) -> Result<(), Error> {
    if target != creator && !is_trusted(creator) {
        return Err(Error::PermissionDenied);
    }
    with_domain(target, |s| {
        if user && s.spec.trusted {
            return Err(Error::Invalid); // the kernel domain never runs unprivileged
        }
        if s.spec.hardware_isolated && !user {
            return Err(Error::PermissionDenied); // sandboxed domains run user tasks only
        }
        if s.killed && target != creator {
            s.killed = false; // explicit restart by the kernel
        }
        if prio > s.spec.priority_ceiling {
            return Err(Error::PermissionDenied);
        }
        if live_in_target >= s.spec.max_tasks as usize {
            return Err(Error::NoResources);
        }
        Ok(())
    })?
}

/// Whether the caller may change priority of a task in `target` to `prio`.
pub(crate) fn check_task_control(caller: DomainId, target: DomainId, prio: Option<u8>) -> Result<(), Error> {
    if caller != target && !is_trusted(caller) {
        return Err(Error::PermissionDenied);
    }
    if let Some(p) = prio {
        if p > with_domain(target, |s| s.spec.priority_ceiling)? {
            return Err(Error::PermissionDenied);
        }
    }
    Ok(())
}

/// Network policy check for the calling domain.
#[cfg_attr(not(feature = "net-ip"), allow(dead_code))]
pub(crate) fn check_net(local_port: Option<u16>, peer: Option<[u8; 4]>, listen: bool) -> Result<(), Error> {
    let d = current();
    if d == DomainId::KERNEL {
        return Ok(());
    }
    let policy = with_domain(d, |s| s.spec.net)?;
    let Some(p) = policy else { return Err(violation(d, Error::PermissionDenied)) };
    let ok = local_port.is_none_or(|lp| lp == 0 || (p.local_ports.0..=p.local_ports.1).contains(&lp))
        && peer.is_none_or(|ip| p.peer_ok(ip))
        && (!listen || p.listen);
    if ok { Ok(()) } else { Err(violation(d, Error::PermissionDenied)) }
}

/// Whether domain `d` may issue system call `n`.
pub(crate) fn syscall_allowed(d: DomainId, n: u32) -> bool {
    n < 32 && with_domain(d, |s| s.spec.syscalls & (1 << n) != 0).unwrap_or(false)
}

/// Record a disallowed system call; kills the domain under the `Kill` policy.
pub(crate) fn syscall_violation(d: DomainId) -> Error {
    let kill_it = with_domain(d, |s| {
        s.violations += 1;
        !s.spec.trusted && s.spec.bad_handle == BadHandlePolicy::Kill
    })
    .unwrap_or(false);
    if kill_it {
        let _ = kill_internal(d);
    }
    Error::PermissionDenied
}

/// Whether the calling domain may write to the kernel console.
pub(crate) fn console_allowed() -> bool {
    let d = current();
    d == DomainId::KERNEL || with_domain(d, |s| s.spec.console).unwrap_or(false)
}

// ----- capabilities to devices -----

/// A device capability held by the calling domain. Every operation re-validates the
/// handle (so revocation is immediate) and checks rights *before* any middleware runs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceCap {
    kind: CapKind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CapKind {
    Handle(Handle),
    /// Trusted domains only: ambient authority over a registered device.
    Ambient(Device),
}

impl DeviceCap {
    /// Look `name` up in the calling domain's namespace (`"temp0"` or `"/dev/temp0"`).
    /// The kernel domain may open any registered device with all rights.
    pub fn open(name: &str) -> Result<DeviceCap, Error> {
        let name = name.strip_prefix("/dev/").unwrap_or(name);
        let d = current();
        if let Some(h) = with_domain(d, |s| s.handles.find_name(name))? {
            return Ok(DeviceCap { kind: CapKind::Handle(h) });
        }
        if is_trusted(d) {
            return Ok(DeviceCap { kind: CapKind::Ambient(Device::find(name)?) });
        }
        Err(Error::NotFound)
    }

    pub fn from_handle(handle: Handle) -> DeviceCap {
        DeviceCap { kind: CapKind::Handle(handle) }
    }

    /// The handle, unless this is an ambient (trusted-domain) capability.
    pub fn handle(&self) -> Option<Handle> {
        match self.kind {
            CapKind::Handle(h) => Some(h),
            CapKind::Ambient(_) => None,
        }
    }

    fn resolve(&self, need: Rights) -> Result<(Device, Caller), Error> {
        let d = current();
        let h = match self.kind {
            CapKind::Ambient(dev) if is_trusted(d) => return Ok((dev, Caller { domain: d, rights: Rights::ALL })),
            CapKind::Ambient(_) => return Err(violation(d, Error::PermissionDenied)),
            CapKind::Handle(h) => h,
        };
        let slot = match with_domain(d, |s| s.handles.get(h))? {
            Ok(s) => s,
            Err(e) => return Err(violation(d, e)),
        };
        let Object::Device(dev) = slot.object else { return Err(violation(d, Error::BadHandle)) };
        if !slot.rights.contains(need) {
            return Err(violation(d, Error::PermissionDenied));
        }
        Ok((dev, Caller { domain: d, rights: slot.rights }))
    }

    /// Send a request (rights checked first, then the middleware chain runs).
    pub fn request(&self, req: &mut Request<'_>) -> IoResult {
        let (dev, caller) = self.resolve(rights_for(&req.op))?;
        req.set_caller(caller);
        match dev.request(req) {
            // The device was revoked/unregistered underneath the handle.
            Err(Error::BadHandle) => Err(violation(caller.domain, Error::BadHandle)),
            r => r,
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> IoResult {
        self.request(&mut Request::new(Op::Read(buf)))
    }

    pub fn read_timeout(&self, buf: &mut [u8], t: Timeout) -> IoResult {
        self.request(&mut Request::new(Op::Read(buf)).with_timeout(t))
    }

    pub fn write(&self, buf: &[u8]) -> IoResult {
        self.request(&mut Request::new(Op::Write(buf)))
    }

    pub fn transfer(&self, addr: u16, tx: &[u8], rx: &mut [u8]) -> IoResult {
        self.request(&mut Request::new(Op::Transfer { addr, tx, rx }))
    }

    pub fn ioctl(&self, cmd: u32, arg: usize) -> IoResult {
        self.request(&mut Request::new(Op::Ioctl { cmd, arg }))
    }

    pub fn set_power(&self, state: PowerState) -> Result<(), Error> {
        self.request(&mut Request::new(Op::Power(state))).map(|_| ())
    }

    /// Attach a (kernel-provided, vetted) middleware layer: requires `MANAGE`.
    pub fn attach(&self, m: &'static dyn Middleware) -> Result<(), Error> {
        let (dev, _) = self.resolve(Rights::MANAGE)?;
        dev.attach_privileged(m)
    }

    /// Detach a middleware layer: requires `MANAGE`.
    pub fn detach(&self, name: &str) -> Result<(), Error> {
        let (dev, _) = self.resolve(Rights::MANAGE)?;
        dev.detach_privileged(name)
    }
}

/// Revoke a device for everyone: every outstanding handle (and `Device` value) becomes
/// invalid, while the device itself stays registered under a fresh generation.
pub fn revoke_device(dev: Device) -> Result<Device, Error> {
    require_kernel()?;
    dev.regenerate()
}

// ----- capabilities to directory subtrees (per-domain filesystem namespaces) -----

/// A directory-subtree capability held by the calling domain: the root of what the domain
/// may name in a mounted filesystem. The `fs` layer resolves paths *relative to this root*
/// and never above it. Every use re-validates the handle (immediate revocation) and checks
/// the required right before any filesystem logic runs — the [`DeviceCap`] pattern for
/// storage.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DirCap {
    handle: Handle,
}

impl DirCap {
    /// Look `name` up in the calling domain's namespace (granted by `fs::grant_dir`).
    pub fn open(name: &str) -> Result<DirCap, Error> {
        let d = current();
        let h = with_domain(d, |s| s.handles.find_name(name))?.ok_or(Error::NotFound)?;
        Ok(DirCap { handle: h })
    }

    pub fn from_handle(handle: Handle) -> DirCap {
        DirCap { handle }
    }

    /// The underlying handle (so a sandboxed task can pass it back over the syscall ABI).
    pub fn handle(&self) -> Handle {
        self.handle
    }

    /// Resolve to `(mount, subtree-root vnode, mount-generation, caller)`, checking `need`.
    pub fn resolve(&self, need: Rights) -> Result<(u8, u32, u16, Caller), Error> {
        let d = current();
        let slot = match with_domain(d, |s| s.handles.get(self.handle))? {
            Ok(s) => s,
            Err(e) => return Err(violation(d, e)),
        };
        let Object::Dir { mount, vnode, generation } = slot.object else {
            return Err(violation(d, Error::BadHandle));
        };
        if !slot.rights.contains(need) {
            return Err(violation(d, Error::PermissionDenied));
        }
        Ok((mount, vnode, generation, Caller { domain: d, rights: slot.rights }))
    }
}

/// An open-file capability held by the calling domain: a rights-checked handle to a VFS
/// open-file slot. Granted by `fs::cap_open_for` when a sandboxed task opens a file through
/// a [`DirCap`], and resolved on every `read`/`write`/`close` syscall.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileCap {
    handle: Handle,
}

impl FileCap {
    pub fn from_handle(handle: Handle) -> FileCap {
        FileCap { handle }
    }

    pub fn handle(&self) -> Handle {
        self.handle
    }

    /// Grant the calling domain a file capability over VFS open-file index `open` with
    /// `rights`, returning its handle. (Called by the `fs` layer after a capability open.)
    pub fn grant(open: u16, rights: Rights) -> Result<Handle, Error> {
        with_domain(current(), |s| s.handles.insert(Object::File { open }, rights, "file"))?
    }

    /// Resolve to `(open-file index, caller)`, checking `need`.
    pub fn resolve(&self, need: Rights) -> Result<(u16, Caller), Error> {
        let d = current();
        let slot = match with_domain(d, |s| s.handles.get(self.handle))? {
            Ok(s) => s,
            Err(e) => return Err(violation(d, e)),
        };
        let Object::File { open } = slot.object else {
            return Err(violation(d, Error::BadHandle));
        };
        if !slot.rights.contains(need) {
            return Err(violation(d, Error::PermissionDenied));
        }
        Ok((open, Caller { domain: d, rights: slot.rights }))
    }

    /// Close the capability (remove the handle).
    pub fn close(&self) -> Result<(), Error> {
        with_domain(current(), |s| s.handles.remove(self.handle).map(|_| ()))?
    }
}
