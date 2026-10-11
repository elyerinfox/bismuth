//! Loadable signed app-bundles (container tier C7): the mechanism for admitting a workload
//! whose code and *requested capabilities* arrive separately from the firmware, verified
//! before it may run. The closest Bismuth gets to "pull and run an image".
//!
//! A bundle is a [`BundleHeader`] + a code blob. Admission into a pre-reserved **app-slot**
//! domain checks, in order:
//!
//! 1. **magic / ABI** — a well-formed bundle for this kernel;
//! 2. **signature** — HMAC-SHA-256 over the header (minus the signature) + the code, under the
//!    slot's verification key (the keystore `K_VERIFY` / a TPM-released key), constant-time;
//! 3. **measurement** — SHA-256 of the code matches the header's `code_hash`;
//! 4. **capability ceiling** — the requested syscall mask and priority are a subset of what
//!    the slot permits (a bundle can never request more authority than its slot grants);
//! 5. **anti-rollback** — the bundle's monotonic counter is at least the slot's floor, which
//!    then advances, so an old (perhaps vulnerable) version cannot be reinstalled.
//!
//! Only then is the code run, in the slot domain, confined to the requested capabilities. The
//! verification/admission half is the security-critical, auditable core implemented and tested
//! here; placing the code bytes at an executable address is the port's MMU-mapping step (the
//! documented "hard tier" on MMU-less targets).
//!
//! Classification: L3 services · security: app-bundle loader · safe · containers
#![cfg(all(feature = "containers", feature = "crypto"))]

use core::sync::atomic::{AtomicU32, Ordering};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::Rights;
use crate::Error;
use crate::kernel::cell::IrqCell;

const MAGIC: u32 = 0x4249_5342; // "BISB"
const ABI: u16 = 1;

/// Why a bundle was refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    Malformed,
    BadSignature,
    BadMeasurement,
    CapabilityExceeded,
    Rollback,
}

/// A bundle's metadata. The signed portion is everything except `signature`.
#[derive(Copy, Clone)]
pub struct BundleHeader {
    pub magic: u32,
    pub abi: u16,
    /// Monotonic anti-rollback counter (and loosely the version).
    pub counter: u32,
    /// Capabilities the bundle requests (checked against the slot ceiling).
    pub req_syscalls: u32,
    pub req_priority: u8,
    pub req_rights: Rights,
    /// SHA-256 of the code blob.
    pub code_hash: [u8; 32],
    /// HMAC-SHA-256 over the signed portion + code.
    pub signature: [u8; 32],
}

impl BundleHeader {
    /// The fixed 19-byte header prefix covered by the signature (the `code_hash` and the code
    /// are fed to the MAC separately).
    fn signed_bytes(&self) -> [u8; 19] {
        let mut b = [0u8; 19];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..6].copy_from_slice(&self.abi.to_le_bytes());
        b[6..10].copy_from_slice(&self.counter.to_le_bytes());
        b[10..14].copy_from_slice(&self.req_syscalls.to_le_bytes());
        b[14] = self.req_priority;
        b[15..19].copy_from_slice(&self.req_rights.0.to_le_bytes());
        b
    }
}

/// A pre-reserved slot a signed bundle may be loaded into: the maximum authority it may
/// request, a verification key, and the anti-rollback floor.
pub struct Slot {
    pub ceiling_syscalls: u32,
    pub ceiling_priority: u8,
    pub ceiling_rights: Rights,
    verify_key: [u8; 32],
    min_counter: AtomicU32,
    lock: IrqCell<()>,
}

impl Slot {
    pub const fn new(ceiling_syscalls: u32, ceiling_priority: u8, ceiling_rights: Rights, verify_key: [u8; 32]) -> Self {
        Slot { ceiling_syscalls, ceiling_priority, ceiling_rights, verify_key, min_counter: AtomicU32::new(0), lock: IrqCell::new(()) }
    }

    /// Verify a bundle against this slot. On success the anti-rollback floor advances, so the
    /// same or an older counter will not verify again.
    pub fn admit(&self, h: &BundleHeader, code: &[u8]) -> Result<(), Reject> {
        self.lock.lock(|_| {
            if h.magic != MAGIC || h.abi != ABI {
                return Err(Reject::Malformed);
            }
            // Signature: HMAC-SHA-256 over the signed header bytes, the full code_hash, and code.
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.verify_key).map_err(|_| Reject::BadSignature)?;
            mac.update(&h.signed_bytes());
            mac.update(&h.code_hash);
            mac.update(code);
            mac.verify_slice(&h.signature).map_err(|_| Reject::BadSignature)?;
            // Measurement.
            let mut hasher = Sha256::new();
            hasher.update(code);
            let digest: [u8; 32] = hasher.finalize().into();
            if digest != h.code_hash {
                return Err(Reject::BadMeasurement);
            }
            // Capability ceiling: requested authority must be a subset of the slot's.
            if h.req_syscalls & !self.ceiling_syscalls != 0
                || h.req_priority > self.ceiling_priority
                || h.req_rights.0 & !self.ceiling_rights.0 != 0
            {
                return Err(Reject::CapabilityExceeded);
            }
            // Anti-rollback.
            let floor = self.min_counter.load(Ordering::Relaxed);
            if h.counter < floor {
                return Err(Reject::Rollback);
            }
            self.min_counter.store(h.counter.saturating_add(1), Ordering::Relaxed);
            Ok(())
        })
    }

    /// Sign a bundle for this slot's key (host/tooling helper): fills `code_hash` and
    /// `signature` so [`admit`](Self::admit) accepts it.
    pub fn sign(&self, h: &mut BundleHeader, code: &[u8]) {
        h.magic = MAGIC;
        h.abi = ABI;
        let mut hasher = Sha256::new();
        hasher.update(code);
        h.code_hash = hasher.finalize().into();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.verify_key).expect("hmac key");
        mac.update(&h.signed_bytes());
        mac.update(&h.code_hash);
        mac.update(code);
        h.signature = mac.finalize().into_bytes().into();
    }
}

/// Verify a bundle and, if admitted, spawn its entry in the slot's domain confined to the
/// requested capabilities. `entry`/`stack` stand for the bundle's (mapped) code on targets
/// that can place it; the admission decision is the security-critical part. Trusted callers.
pub fn load(
    slot: &Slot,
    h: &BundleHeader,
    code: &[u8],
    domain: super::DomainId,
    entry: extern "C-unwind" fn(usize),
    stack: &'static dyn crate::kernel::stack::StackSource,
    priority: u8,
) -> Result<(), Error> {
    if !super::current_is_trusted() {
        return Err(Error::PermissionDenied);
    }
    slot.admit(h, code).map_err(|_| Error::Integrity)?;
    let s = stack.claim().ok_or(Error::Busy)?;
    crate::kernel::task::Builder::new("bundle")
        .priority(priority.min(slot.ceiling_priority))
        .domain(domain)
        .stack_ref(s)
        .detached(true)
        .spawn_user(entry, 0)
        .map(|_| ())
}
