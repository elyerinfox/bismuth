//! Layer-2 hot-file residency cache: dynamically keep whole, frequently-read small files
//! resident in a fixed RAM budget (above the filesystem, serving plaintext).
//!
//! This is a *fixed budget with dynamic occupancy*, never growth: `FS_RESIDENT_SLOTS` slabs
//! of `FS_RESIDENT_MAX_FILE` bytes. A file is promoted only once it has been read
//! `FS_RESIDENT_PROMOTE` times *and* fits a slab; the coldest resident file is evicted to
//! make room; a file larger than a slab is never promoted. Setting the slot count to `0`
//! (the MCU default) compiles the layer out entirely.
//!
//! Coherency is write-through: any write/truncate/unlink invalidates the resident copy (so
//! the authoritative data is always the filesystem's), and slabs are zeroized on eviction
//! and invalidation so plaintext never lingers (the governance and encrypted-mount
//! default-deny policy from the research are future work; this is the mechanism).
//!
//! Classification: L3 services · fs: hot-file residency cache · safe · fs

use crate::Error;
use crate::config::{FS_RESIDENT_MAX_FILE, FS_RESIDENT_PROMOTE, FS_RESIDENT_SLOTS};
use crate::kernel::cell::IrqCell;

const SLOTS: usize = FS_RESIDENT_SLOTS;
const MAX: usize = FS_RESIDENT_MAX_FILE;
const TRACK: usize = FS_RESIDENT_SLOTS * 2;

/// Whether the residency layer is compiled in.
pub const fn enabled() -> bool {
    SLOTS > 0
}

/// Maximum resident file size.
pub const fn max_file() -> usize {
    MAX
}

#[derive(Copy, Clone)]
struct Slab {
    used: bool,
    mount: u8,
    vnode: u32,
    generation: u16,
    len: u32,
    score: u32,
    data: [u8; MAX],
}

impl Slab {
    const EMPTY: Slab = Slab { used: false, mount: 0, vnode: 0, generation: 0, len: 0, score: 0, data: [0; MAX] };
}

#[derive(Copy, Clone)]
struct Cand {
    used: bool,
    mount: u8,
    vnode: u32,
    generation: u16,
    score: u32,
}

impl Cand {
    const EMPTY: Cand = Cand { used: false, mount: 0, vnode: 0, generation: 0, score: 0 };
}

struct Residency {
    slabs: [Slab; SLOTS],
    cand: [Cand; TRACK],
    hits: u32,
    promotions: u32,
}

static R: IrqCell<Residency> =
    IrqCell::new(Residency { slabs: [Slab::EMPTY; SLOTS], cand: [Cand::EMPTY; TRACK], hits: 0, promotions: 0 });

fn key_eq(s_mount: u8, s_vnode: u32, s_gen: u16, mount: u8, vnode: u32, generation: u16) -> bool {
    s_mount == mount && s_vnode == vnode && s_gen == generation
}

/// Serve a read from a resident copy if one is valid; returns bytes copied, or `None` on a
/// miss. (`off` past end returns `Some(0)`.)
pub fn try_serve(mount: u8, vnode: u32, generation: u16, off: u64, buf: &mut [u8]) -> Option<usize> {
    if !enabled() {
        return None;
    }
    R.lock(|r| {
        let idx = r
            .slabs
            .iter()
            .position(|s| s.used && s.len > 0 && key_eq(s.mount, s.vnode, s.generation, mount, vnode, generation))?;
        let len = r.slabs[idx].len as usize;
        let o = off as usize;
        let n = if o >= len { 0 } else { (len - o).min(buf.len()) };
        buf[..n].copy_from_slice(&r.slabs[idx].data[o..o + n]);
        r.slabs[idx].score = r.slabs[idx].score.saturating_add(1);
        r.hits += 1;
        Some(n)
    })
}

/// Note a read miss of a file of `size` bytes, and promote it if it is now hot enough and
/// fits. `fill` loads the whole file (called at most once, outside the cache lock).
pub fn observe(mount: u8, vnode: u32, generation: u16, size: u32, fill: impl FnOnce(&mut [u8]) -> Result<usize, Error>) {
    if !enabled() || size as usize > MAX {
        return;
    }
    // Phase 1: bump the candidate counter; if it crosses the threshold, reserve a slab.
    let reserved = R.lock(|r| {
        if r.slabs.iter().any(|s| s.used && key_eq(s.mount, s.vnode, s.generation, mount, vnode, generation)) {
            return None; // already resident (or reserved)
        }
        let score = bump_candidate(r, mount, vnode, generation);
        if score < FS_RESIDENT_PROMOTE {
            return None;
        }
        let i = pick_slab(r);
        r.slabs[i] = Slab { used: true, mount, vnode, generation, len: 0, score, data: [0; MAX] };
        Some(i)
    });
    let Some(idx) = reserved else { return };
    // Phase 2: load the file into a local buffer (may block; no lock held).
    let mut tmp = [0u8; MAX];
    let n = match fill(&mut tmp[..size as usize]) {
        Ok(n) => n,
        Err(_) => {
            R.lock(|r| r.slabs[idx].used = false);
            return;
        }
    };
    // Phase 3: publish, unless the slot was invalidated meanwhile.
    R.lock(|r| {
        if r.slabs[idx].used && key_eq(r.slabs[idx].mount, r.slabs[idx].vnode, r.slabs[idx].generation, mount, vnode, generation) {
            r.slabs[idx].data[..n].copy_from_slice(&tmp[..n]);
            r.slabs[idx].len = n as u32;
            r.promotions += 1;
        }
    });
}

fn bump_candidate(r: &mut Residency, mount: u8, vnode: u32, generation: u16) -> u32 {
    if let Some(c) = r.cand.iter_mut().find(|c| c.used && key_eq(c.mount, c.vnode, c.generation, mount, vnode, generation)) {
        c.score = c.score.saturating_add(1);
        return c.score;
    }
    // Insert, evicting the coldest candidate if full.
    let slot = r
        .cand
        .iter()
        .position(|c| !c.used)
        .unwrap_or_else(|| r.cand.iter().enumerate().min_by_key(|(_, c)| c.score).map(|(i, _)| i).unwrap_or(0));
    r.cand[slot] = Cand { used: true, mount, vnode, generation, score: 1 };
    1
}

fn pick_slab(r: &Residency) -> usize {
    r.slabs
        .iter()
        .position(|s| !s.used)
        .unwrap_or_else(|| r.slabs.iter().enumerate().min_by_key(|(_, s)| s.score).map(|(i, _)| i).unwrap_or(0))
}

/// Drop any resident copy of a node (write/truncate/unlink), zeroizing its slab.
pub fn invalidate(mount: u8, vnode: u32) {
    if !enabled() {
        return;
    }
    R.lock(|r| {
        for s in r.slabs.iter_mut() {
            if s.used && s.mount == mount && s.vnode == vnode {
                s.data[..s.len as usize].fill(0);
                *s = Slab::EMPTY;
            }
        }
        for c in r.cand.iter_mut() {
            if c.used && c.mount == mount && c.vnode == vnode {
                *c = Cand::EMPTY;
            }
        }
    });
}

/// Zeroize every resident plaintext slab (e.g. before a power-state suspend, when RAM may
/// be lost or the device left unattended). Available on all targets.
pub fn suspend_flush() {
    if !enabled() {
        return;
    }
    R.lock(|r| {
        for s in r.slabs.iter_mut() {
            s.data[..s.len as usize].fill(0);
            *s = Slab::EMPTY;
        }
        for c in r.cand.iter_mut() {
            *c = Cand::EMPTY;
        }
    });
}

/// `(hits, promotions)` counters (tests / telemetry).
pub fn stats() -> (u32, u32) {
    R.lock(|r| (r.hits, r.promotions))
}

/// Number of currently-resident files.
pub fn resident_count() -> usize {
    R.lock(|r| r.slabs.iter().filter(|s| s.used && s.len > 0).count())
}

/// Clear the cache and counters (host simulator, between runs).
#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    R.lock(|r| {
        r.slabs = [Slab::EMPTY; SLOTS];
        r.cand = [Cand::EMPTY; TRACK];
        r.hits = 0;
        r.promotions = 0;
    });
}
