//! Dynamic extension framework: load and unload compiled-in-but-inert extensions
//! (drivers, filesystems, net hooks, edge stages, ...) at runtime.
//!
//! This is the safe answer to "kernel modules" for Bismuth. It is NOT native `.ko` loading
//! — that would import unvetted privileged machine code, breaking the safe-Rust TCB and the
//! capability model, and is a permanent non-goal (see `docs/research/extensions.md`).
//! Instead, an extension is to a *registration* what a container is to a *domain*: the code
//! is vetted and compiled in, but inert until loaded, and its lifecycle (load / unload,
//! with reference counting and generation-checked revocation) is managed at runtime.
//!
//! An [`Extension`] implementation wraps the existing register/unregister, mount/unmount or
//! attach/detach calls in [`load`](Extension::load)/[`unload`](Extension::unload). The
//! registry here tracks which are loaded, refuses to unload one that is still in use
//! ([`Error::Busy`]), and gates load/unload on a trusted caller before `seal` (the default
//! `BootOnly` policy — dynamism in the lifecycle, never in the frozen capability graph).
//!
//! Classification: L3 services · extension framework · safe · extensions

use crate::Error;
use crate::config::MAX_EXTENSIONS;
use crate::kernel::cell::IrqCell;

/// What an extension plugs into.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExtKind {
    Driver,
    Block,
    FileSystem,
    NetHook,
    EdgeStage,
    Middleware,
    /// A sandboxed bytecode program (future).
    Vm,
    /// A userspace driver over IPC (future).
    UserDriver,
}

/// A loadable extension. Implementations wrap existing registration calls; `load` activates
/// the extension (e.g. registers a driver / mounts a filesystem), `unload` reverses it.
/// Both must be idempotent-safe: the framework guarantees `load` is only called on an
/// unloaded extension and `unload` only on a loaded one with no outstanding references.
pub trait Extension: Sync {
    fn name(&self) -> &'static str;
    fn kind(&self) -> ExtKind;
    fn load(&self) -> Result<(), Error>;
    fn unload(&self) -> Result<(), Error>;
}

/// Identifies a registered extension slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtId(u8);

struct Slot {
    ext: &'static dyn Extension,
    loaded: bool,
    refs: u32,
}

struct Registry {
    slots: [Option<Slot>; MAX_EXTENSIONS],
}

static REGISTRY: IrqCell<Registry> = IrqCell::new(Registry { slots: [const { None }; MAX_EXTENSIONS] });

/// Register an available (inert) extension. Trusted callers only.
pub fn register(ext: &'static dyn Extension) -> Result<ExtId, Error> {
    if !crate::security::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    REGISTRY.lock(|r| {
        if r.slots.iter().flatten().any(|s| s.ext.name() == ext.name()) {
            return Err(Error::Exists);
        }
        for (i, slot) in r.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Slot { ext, loaded: false, refs: 0 });
                return Ok(ExtId(i as u8));
            }
        }
        Err(Error::NoResources)
    })
}

fn find(name: &str) -> Option<usize> {
    REGISTRY.lock(|r| r.slots.iter().position(|s| s.as_ref().is_some_and(|s| s.ext.name() == name)))
}

/// Load (activate) the extension named `name`. Trusted callers, before `seal` (the default
/// `BootOnly` policy). Calls [`Extension::load`] outside the registry lock.
pub fn load(name: &str) -> Result<(), Error> {
    if !crate::security::current_is_trusted() || crate::security::is_sealed() {
        return Err(Error::PermissionDenied);
    }
    let i = find(name).ok_or(Error::NotFound)?;
    // Mark intent under the lock; call load() outside it (it may register/mount).
    let already = REGISTRY.lock(|r| {
        let s = r.slots[i].as_mut().unwrap();
        if s.loaded { Some(true) } else { None }
    });
    if already == Some(true) {
        return Err(Error::Busy); // already loaded
    }
    let ext = REGISTRY.lock(|r| r.slots[i].as_ref().unwrap().ext);
    ext.load()?;
    REGISTRY.lock(|r| r.slots[i].as_mut().unwrap().loaded = true);
    Ok(())
}

/// Unload (deactivate) the extension named `name`. Refused with [`Error::Busy`] while any
/// [`ExtGuard`] is outstanding. Trusted callers, before `seal`.
pub fn unload(name: &str) -> Result<(), Error> {
    if !crate::security::current_is_trusted() || crate::security::is_sealed() {
        return Err(Error::PermissionDenied);
    }
    let i = find(name).ok_or(Error::NotFound)?;
    let ext = REGISTRY.lock(|r| {
        let s = r.slots[i].as_ref().unwrap();
        if !s.loaded {
            return Err(Error::NotReady);
        }
        if s.refs > 0 {
            return Err(Error::Busy);
        }
        Ok(s.ext)
    })?;
    ext.unload()?;
    REGISTRY.lock(|r| r.slots[i].as_mut().unwrap().loaded = false);
    Ok(())
}

/// Whether the named extension is currently loaded.
pub fn is_loaded(name: &str) -> bool {
    find(name).is_some_and(|i| REGISTRY.lock(|r| r.slots[i].as_ref().is_some_and(|s| s.loaded)))
}

/// Number of loaded extensions.
pub fn loaded_count() -> usize {
    REGISTRY.lock(|r| r.slots.iter().flatten().filter(|s| s.loaded).count())
}

/// Acquire a use-reference to a loaded extension; it cannot be unloaded until the returned
/// [`ExtGuard`] is dropped.
pub fn acquire(name: &str) -> Result<ExtGuard, Error> {
    let i = find(name).ok_or(Error::NotFound)?;
    REGISTRY.lock(|r| {
        let s = r.slots[i].as_mut().ok_or(Error::NotFound)?;
        if !s.loaded {
            return Err(Error::NotReady);
        }
        s.refs += 1;
        Ok(ExtGuard { id: ExtId(i as u8) })
    })
}

fn release(id: ExtId) {
    REGISTRY.lock(|r| {
        if let Some(Some(s)) = r.slots.get_mut(id.0 as usize) {
            s.refs = s.refs.saturating_sub(1);
        }
    });
}

/// A use-reference that keeps an extension loaded for its lifetime (RAII reference count).
pub struct ExtGuard {
    id: ExtId,
}

impl Drop for ExtGuard {
    fn drop(&mut self) {
        release(self.id);
    }
}

/// Clear the registry (host simulator, between runs).
#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    REGISTRY.lock(|r| {
        for s in r.slots.iter_mut() {
            *s = None;
        }
    });
}
