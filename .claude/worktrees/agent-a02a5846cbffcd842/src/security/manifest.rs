//! Static security manifest: domains and the capabilities granted to them, declared in
//! code and **validated at compile time**.
//!
//! ```ignore
//! static MANIFEST: Manifest = Manifest {
//!     domains: &[DomainDecl {
//!         spec: DomainSpec::isolated("telemetry", 8, 2),
//!         grants: &[GrantDecl { device: "temp0", name: "temp0", rights: Rights::READ }],
//!         dirs: &[DirGrantDecl { path: "/var/telemetry", name: "data", rights: Rights::READ }],
//!     }],
//! };
//! const _: () = manifest::validate(&MANIFEST); // build fails on a policy violation
//! ```
//!
//! [`apply`] then creates the domains and grants at boot, after devices are registered,
//! and the system is [`sealed`](super::seal) so policy can only tighten afterwards.
//!
//! Classification: L3 services · security: static manifest · safe · always

use super::{DomainId, DomainSpec, MAX_DOMAINS, Rights};
use crate::Error;
use crate::config::MAX_TASKS;
use crate::driver::Device;
use crate::kernel::task::MAX_PRIORITY;

/// A device capability granted to a domain.
#[derive(Copy, Clone, Debug)]
pub struct GrantDecl {
    /// Registered device name.
    pub device: &'static str,
    /// Name in the domain's namespace (what `open("/dev/<name>")` resolves).
    pub name: &'static str,
    pub rights: Rights,
}

/// A filesystem directory capability granted to a domain — the declarative form of
/// [`fs::grant_dir`](crate::fs::grant_dir). The domain is confined to `path` and its subtree.
#[derive(Copy, Clone, Debug)]
pub struct DirGrantDecl {
    /// Absolute path in the VFS that becomes the root of the granted subtree.
    pub path: &'static str,
    /// Name in the domain's namespace (what `fs_diropen("<name>")` resolves).
    pub name: &'static str,
    pub rights: Rights,
}

#[derive(Copy, Clone, Debug)]
pub struct DomainDecl {
    pub spec: DomainSpec,
    pub grants: &'static [GrantDecl],
    /// Declarative directory grants (empty `&[]` for none). Applied after device grants, so the
    /// filesystem must be mounted by the time [`apply`] runs. Requires the `fs` feature.
    pub dirs: &'static [DirGrantDecl],
}

#[derive(Copy, Clone, Debug)]
pub struct Manifest {
    pub domains: &'static [DomainDecl],
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Compile-time policy checks. Use in a `const` item so violations fail the build:
///
/// * at most `MAX_DOMAINS - 1` domains, unique names, sane ceilings and quotas;
/// * total task quota fits the task table (leaving room for kernel tasks);
/// * isolated domains never hold `K_EXPORT` or `MANAGE`, and never claim `trusted`;
/// * grant names are unique within a domain.
pub const fn validate(m: &Manifest) {
    let d = m.domains;
    assert!(d.len() < MAX_DOMAINS, "manifest: too many domains");
    let mut total_tasks = 0usize;
    let mut i = 0;
    while i < d.len() {
        let s = &d[i].spec;
        assert!(s.priority_ceiling >= 1 && s.priority_ceiling <= MAX_PRIORITY, "manifest: bad priority ceiling");
        assert!(s.max_tasks >= 1, "manifest: domain needs a task quota");
        assert!(!s.trusted, "manifest: declared domains may not be trusted (ambient authority)");
        total_tasks += s.max_tasks as usize;
        let mut j = i + 1;
        while j < d.len() {
            assert!(!str_eq(s.name, d[j].spec.name), "manifest: duplicate domain name");
            j += 1;
        }
        let g = d[i].grants;
        let mut k = 0;
        while k < g.len() {
            assert!(!g[k].rights.contains(Rights::K_EXPORT), "manifest: K_EXPORT granted to an isolated domain");
            assert!(!g[k].rights.contains(Rights::MANAGE), "manifest: MANAGE granted to an isolated domain");
            assert!(g[k].rights.0 != 0, "manifest: empty grant");
            let mut l = k + 1;
            while l < g.len() {
                assert!(!str_eq(g[k].name, g[l].name), "manifest: duplicate name in a domain namespace");
                l += 1;
            }
            k += 1;
        }
        // Directory grants: non-empty rights, names unique within the domain's namespace
        // (including against device-grant names, since both share `fs_diropen`/`open`).
        let dirs = d[i].dirs;
        let mut p = 0;
        while p < dirs.len() {
            assert!(!dirs[p].rights.contains(Rights::K_EXPORT), "manifest: K_EXPORT granted to an isolated domain");
            assert!(!dirs[p].rights.contains(Rights::MANAGE), "manifest: MANAGE granted to an isolated domain");
            assert!(dirs[p].rights.0 != 0, "manifest: empty directory grant");
            let mut q = p + 1;
            while q < dirs.len() {
                assert!(!str_eq(dirs[p].name, dirs[q].name), "manifest: duplicate name in a domain namespace");
                q += 1;
            }
            let mut r = 0;
            while r < g.len() {
                assert!(!str_eq(dirs[p].name, g[r].name), "manifest: directory grant name collides with a device grant");
                r += 1;
            }
            p += 1;
        }
        i += 1;
    }
    assert!(total_tasks + 4 <= MAX_TASKS, "manifest: task quotas exceed the task table");
}

/// Create every declared domain and grant its capabilities. Devices must already be
/// registered. Returns the domain ids in declaration order.
pub fn apply(m: &Manifest) -> Result<[Option<DomainId>; MAX_DOMAINS], Error> {
    let mut ids = [None; MAX_DOMAINS];
    for (i, decl) in m.domains.iter().enumerate() {
        let id = super::create_domain(decl.spec)?;
        for g in decl.grants {
            let dev = Device::find(g.device)?;
            super::grant_device(id, dev, g.rights, g.name)?;
        }
        #[cfg(feature = "fs")]
        for g in decl.dirs {
            crate::fs::grant_dir(id, g.path, g.rights, g.name)?;
        }
        #[cfg(not(feature = "fs"))]
        if !decl.dirs.is_empty() {
            return Err(Error::Unsupported);
        }
        ids[i] = Some(id);
    }
    Ok(ids)
}
