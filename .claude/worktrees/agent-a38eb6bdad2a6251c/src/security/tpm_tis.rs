//! A TPM 2.0 driver over the FIFO (TIS) interface on a SPI bus — the real hardware root of
//! trust, in contrast to [`SoftTpm`](super::trust::SoftTpm) (the software model/test double).
//!
//! It speaks the TCG **TIS-over-SPI** protocol (a 4-byte header — read/write + size, then a
//! 24-bit register address — followed by data) to drive the locality/status/FIFO register file,
//! and marshals TPM 2.0 commands through it. 100% safe Rust: the SPI *controller's* registers
//! live in `arch::mmio` (the TCB) behind the [`SpiBus`] trait; this layer is pure protocol.
//!
//! The measured-boot core — [`extend`](RootOfTrust::extend), [`pcr`](RootOfTrust::pcr) and
//! [`random`](RootOfTrust::random), i.e. `TPM2_PCR_Extend` / `TPM2_PCR_Read` / `TPM2_GetRandom` —
//! is implemented against the real wire protocol. Sealing, unsealing and quoting require the
//! TPM 2.0 object/policy-session command suite (a large future addition); until then they return
//! [`Error::Unsupported`], and software callers use `SoftTpm` for that side of the design.
//!
//! Classification: L3 services · security: TPM 2.0 TIS/SPI · safe · tpm
#![cfg(feature = "tpm")]

use sha2::{Digest, Sha256};

use super::trust::{RootOfTrust, Sealed};
use crate::Error;
use crate::driver::spi::SpiBus;
use crate::kernel::cell::IrqCell;

// TIS register addresses (locality 0 lives at 0x00D4_xxxx).
const ACCESS: u32 = 0x00D4_0000;
const STS: u32 = 0x00D4_0018;
const DATA_FIFO: u32 = 0x00D4_0024;

// ACCESS bits.
const ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
const ACCESS_REQUEST_USE: u8 = 1 << 1;
// STS bits.
const STS_VALID: u8 = 1 << 7;
const STS_COMMAND_READY: u8 = 1 << 6;
const STS_TPM_GO: u8 = 1 << 5;
const STS_DATA_AVAIL: u8 = 1 << 4;

// TPM 2.0 command tags and command codes.
const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_PCR_EXTEND: u32 = 0x0000_0182;
const CC_PCR_READ: u32 = 0x0000_017E;
const CC_GET_RANDOM: u32 = 0x0000_017B;
const RS_PW: u32 = 0x4000_0009; // the password authorization session handle
const ALG_SHA256: u16 = 0x000B;

const CMD_MAX: usize = 128;
const RSP_MAX: usize = 128;
const POLL_LIMIT: u32 = 1_000_000;

/// A TPM 2.0 chip reached over a SPI [`SpiBus`] with the TIS/FIFO protocol.
pub struct TpmTis<B: SpiBus> {
    bus: B,
    lock: IrqCell<()>,
}

impl<B: SpiBus> TpmTis<B> {
    pub const fn new(bus: B) -> Self {
        TpmTis { bus, lock: IrqCell::new(()) }
    }

    fn read_reg(&self, addr: u32, out: &mut [u8]) -> Result<(), Error> {
        let hdr = [0x80 | ((out.len() as u8) - 1), (addr >> 16) as u8, (addr >> 8) as u8, addr as u8];
        self.bus.write_then_read(&hdr, out)
    }

    fn write_reg(&self, addr: u32, data: &[u8]) -> Result<(), Error> {
        let mut buf = [0u8; 4 + 64];
        buf[0] = (data.len() as u8) - 1; // bit7 = 0 → write
        buf[1] = (addr >> 16) as u8;
        buf[2] = (addr >> 8) as u8;
        buf[3] = addr as u8;
        buf[4..4 + data.len()].copy_from_slice(data);
        self.bus.transfer(&mut buf[..4 + data.len()])
    }

    fn sts(&self) -> Result<u8, Error> {
        let mut b = [0u8; 1];
        self.read_reg(STS, &mut b)?;
        Ok(b[0])
    }

    fn poll_sts(&self, bits: u8) -> Result<(), Error> {
        for _ in 0..POLL_LIMIT {
            let s = self.sts()?;
            if s & bits == bits {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::Timeout)
    }

    /// Acquire locality 0, run one command/response exchange, release locality.
    fn transact(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> {
        self.lock.lock(|_| {
            // Request and wait for locality 0.
            self.write_reg(ACCESS, &[ACCESS_REQUEST_USE])?;
            for _ in 0..POLL_LIMIT {
                let mut a = [0u8; 1];
                self.read_reg(ACCESS, &mut a)?;
                if a[0] & ACCESS_ACTIVE_LOCALITY != 0 {
                    break;
                }
            }
            // Ready the command FIFO.
            self.write_reg(STS, &[STS_COMMAND_READY])?;
            self.poll_sts(STS_VALID | STS_COMMAND_READY)?;
            // Write the command (whole-command FIFO; a real burst loop would honour burstCount).
            for chunk in cmd.chunks(64) {
                self.write_reg(DATA_FIFO, chunk)?;
            }
            // Execute and await a response.
            self.write_reg(STS, &[STS_TPM_GO])?;
            self.poll_sts(STS_VALID | STS_DATA_AVAIL)?;
            // Read the 6-byte header first to learn the response size, then the remainder.
            let mut hdr = [0u8; 6];
            self.read_reg(DATA_FIFO, &mut hdr)?;
            let size = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
            if size < 6 || size > rsp.len() {
                return Err(Error::Overflow);
            }
            rsp[..6].copy_from_slice(&hdr);
            let mut off = 6;
            while off < size {
                let n = (size - off).min(64);
                self.read_reg(DATA_FIFO, &mut rsp[off..off + n])?;
                off += n;
            }
            // Return to idle and release the locality.
            self.write_reg(STS, &[STS_COMMAND_READY])?;
            self.write_reg(ACCESS, &[ACCESS_ACTIVE_LOCALITY])?;
            // Check the 4-byte response code (0 = TPM_RC_SUCCESS).
            let rc = u32::from_be_bytes([rsp[6], rsp[7], rsp[8], rsp[9]]);
            if rc != 0 {
                return Err(Error::Io);
            }
            Ok(size)
        })
    }
}

/// Append helper: write a big-endian value into `buf` at `*off`, advancing it.
fn put(buf: &mut [u8], off: &mut usize, bytes: &[u8]) {
    buf[*off..*off + bytes.len()].copy_from_slice(bytes);
    *off += bytes.len();
}

impl<B: SpiBus> RootOfTrust for TpmTis<B> {
    fn extend(&self, index: usize, data: &[u8]) -> Result<(), Error> {
        // Measure the data, then TPM2_PCR_Extend the digest (the chip does pcr = H(pcr||digest)).
        let digest: [u8; 32] = Sha256::digest(data).into();
        let mut body = [0u8; CMD_MAX];
        let mut b = 10; // leave room for the header
        put(&mut body, &mut b, &(index as u32).to_be_bytes()); // pcrHandle
        // Authorization area (9 bytes): one empty password session.
        put(&mut body, &mut b, &9u32.to_be_bytes()); // authorizationSize
        put(&mut body, &mut b, &RS_PW.to_be_bytes()); // session handle
        put(&mut body, &mut b, &0u16.to_be_bytes()); // nonce size 0
        body[b] = 0; // session attributes
        b += 1;
        put(&mut body, &mut b, &0u16.to_be_bytes()); // hmac size 0
        // digests: TPML_DIGEST_VALUES { count=1, {alg, digest} }
        put(&mut body, &mut b, &1u32.to_be_bytes());
        put(&mut body, &mut b, &ALG_SHA256.to_be_bytes());
        put(&mut body, &mut b, &digest);
        finish_and_run(self, ST_SESSIONS, CC_PCR_EXTEND, &mut body, b, &mut [0u8; RSP_MAX]).map(|_| ())
    }

    fn pcr(&self, index: usize) -> Result<[u8; 32], Error> {
        // TPM2_PCR_Read with a single-PCR selection.
        let mut body = [0u8; CMD_MAX];
        let mut b = 10;
        put(&mut body, &mut b, &1u32.to_be_bytes()); // count of selections
        put(&mut body, &mut b, &ALG_SHA256.to_be_bytes());
        body[b] = 3; // sizeofSelect (3 bytes of bitmap)
        b += 1;
        let mut sel = [0u8; 3];
        sel[index / 8] = 1 << (index % 8);
        put(&mut body, &mut b, &sel);
        let mut rsp = [0u8; RSP_MAX];
        let n = finish_and_run(self, ST_NO_SESSIONS, CC_PCR_READ, &mut body, b, &mut rsp)?;
        // Params: pcrUpdateCounter(4), TPML_PCR_SELECTION, TPML_DIGEST{count, TPM2B digest}.
        let mut p = 10 + 4;
        let sel_count = u32::from_be_bytes([rsp[p], rsp[p + 1], rsp[p + 2], rsp[p + 3]]) as usize;
        p += 4;
        for _ in 0..sel_count {
            // {hash(2), sizeofSelect(1), bitmap(sizeofSelect)}
            p += 2;
            let sz = rsp[p] as usize;
            p += 1 + sz;
        }
        let dcount = u32::from_be_bytes([rsp[p], rsp[p + 1], rsp[p + 2], rsp[p + 3]]) as usize;
        p += 4;
        if dcount == 0 {
            return Err(Error::NotFound);
        }
        let dsize = u16::from_be_bytes([rsp[p], rsp[p + 1]]) as usize;
        p += 2;
        if dsize != 32 || p + 32 > n {
            return Err(Error::Integrity);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&rsp[p..p + 32]);
        Ok(out)
    }

    fn random(&self, out: &mut [u8]) -> Result<(), Error> {
        let mut done = 0;
        while done < out.len() {
            let want = (out.len() - done).min(32) as u16;
            let mut body = [0u8; CMD_MAX];
            let mut b = 10;
            put(&mut body, &mut b, &want.to_be_bytes());
            let mut rsp = [0u8; RSP_MAX];
            let n = finish_and_run(self, ST_NO_SESSIONS, CC_GET_RANDOM, &mut body, b, &mut rsp)?;
            // Params: TPM2B_DIGEST { size(2), bytes }.
            let p = 10;
            let sz = u16::from_be_bytes([rsp[p], rsp[p + 1]]) as usize;
            if sz == 0 || p + 2 + sz > n {
                return Err(Error::Integrity);
            }
            let take = sz.min(out.len() - done);
            out[done..done + take].copy_from_slice(&rsp[p + 2..p + 2 + take]);
            done += take;
        }
        Ok(())
    }

    fn seal(&self, _data: &[u8], _pcr_mask: u32) -> Result<Sealed, Error> {
        // Needs the TPM 2.0 object/policy command suite (Create/Load/Unseal with a PCR policy).
        Err(Error::Unsupported)
    }

    fn unseal(&self, _blob: &Sealed, _out: &mut [u8]) -> Result<usize, Error> {
        Err(Error::Unsupported)
    }

    fn quote(&self, _pcr_mask: u32, _nonce: &[u8], _out: &mut [u8; 32]) -> Result<(), Error> {
        // Needs a loaded attestation key (TPM2_Quote over an AK); future work.
        Err(Error::Unsupported)
    }
}

/// Write the TPM command header (tag, size, code) into `body[0..10]` and run the transaction.
fn finish_and_run<B: SpiBus>(tpm: &TpmTis<B>, tag: u16, cc: u32, body: &mut [u8], len: usize, rsp: &mut [u8]) -> Result<usize, Error> {
    body[0..2].copy_from_slice(&tag.to_be_bytes());
    body[2..6].copy_from_slice(&(len as u32).to_be_bytes());
    body[6..10].copy_from_slice(&cc.to_be_bytes());
    tpm.transact(&body[..len], rsp)
}
