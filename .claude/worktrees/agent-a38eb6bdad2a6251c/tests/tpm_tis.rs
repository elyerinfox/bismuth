//! The TPM 2.0 TIS-over-SPI driver, exercised against a mock SPI TPM that implements the TIS
//! register state machine and a minimal TPM (PCR_Extend / PCR_Read / GetRandom). This verifies
//! the driver's wire protocol — locality handshake, status polling, FIFO command/response and
//! TPM 2.0 command marshalling — without real hardware.

#![cfg(feature = "tpm")]

use std::sync::Mutex;

use bismuth::driver::spi::SpiBus;
use bismuth::security::tpm_tis::TpmTis;
use bismuth::security::trust::RootOfTrust;
use sha2::{Digest, Sha256};

const ACCESS: u32 = 0x00D4_0000;
const STS: u32 = 0x00D4_0018;
const FIFO: u32 = 0x00D4_0024;

#[derive(Default)]
struct TpmState {
    active: bool,
    sts_ready: bool,
    data_avail: bool,
    cmd: Vec<u8>,
    rsp: Vec<u8>,
    rsp_pos: usize,
    pcrs: [[u8; 32]; 24],
}

/// A mock SPI TPM: the device side of the TIS protocol plus a tiny TPM 2.0 core.
struct MockTpm(Mutex<TpmState>);

impl MockTpm {
    fn new() -> Self {
        MockTpm(Mutex::new(TpmState::default()))
    }

    fn sts_byte(s: &TpmState) -> u8 {
        let mut v = 1 << 7; // stsValid
        if s.sts_ready {
            v |= 1 << 6;
        }
        if s.data_avail {
            v |= 1 << 4;
        }
        v
    }

    fn execute(s: &mut TpmState) {
        let c = &s.cmd;
        let cc = u32::from_be_bytes([c[6], c[7], c[8], c[9]]);
        let mut r = Vec::new();
        match cc {
            0x0000_0182 => {
                // PCR_Extend: pcrHandle@10, authSize@14, auth@18, then count/alg/digest.
                let handle = u32::from_be_bytes([c[10], c[11], c[12], c[13]]) as usize;
                let auth = u32::from_be_bytes([c[14], c[15], c[16], c[17]]) as usize;
                let doff = 18 + auth + 4 + 2; // skip auth, count(4), alg(2)
                let digest = &c[doff..doff + 32];
                let mut h = Sha256::new();
                h.update(s.pcrs[handle]);
                h.update(digest);
                s.pcrs[handle] = h.finalize().into();
                // Bare success response: tag, size=10, rc=0.
                r.extend_from_slice(&0x8001u16.to_be_bytes());
                r.extend_from_slice(&10u32.to_be_bytes());
                r.extend_from_slice(&0u32.to_be_bytes());
            }
            0x0000_017E => {
                // PCR_Read: selection bitmap at offset 17 (count@10, hash@14, size@16, bitmap@17).
                let bitmap = [c[17], c[18], c[19]];
                let mut idx = 0;
                'f: for (bi, b) in bitmap.iter().enumerate() {
                    for bit in 0..8 {
                        if b & (1 << bit) != 0 {
                            idx = bi * 8 + bit;
                            break 'f;
                        }
                    }
                }
                let mut params = Vec::new();
                params.extend_from_slice(&0u32.to_be_bytes()); // pcrUpdateCounter
                params.extend_from_slice(&1u32.to_be_bytes()); // selection count
                params.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
                params.push(3); // sizeofSelect
                params.extend_from_slice(&bitmap);
                params.extend_from_slice(&1u32.to_be_bytes()); // digest count
                params.extend_from_slice(&32u16.to_be_bytes()); // digest size
                params.extend_from_slice(&s.pcrs[idx]);
                let size = 10 + params.len() as u32;
                r.extend_from_slice(&0x8001u16.to_be_bytes());
                r.extend_from_slice(&size.to_be_bytes());
                r.extend_from_slice(&0u32.to_be_bytes());
                r.extend_from_slice(&params);
            }
            0x0000_017B => {
                // GetRandom: bytesRequested@10.
                let want = u16::from_be_bytes([c[10], c[11]]) as usize;
                let mut params = Vec::new();
                params.extend_from_slice(&(want as u16).to_be_bytes());
                for i in 0..want {
                    params.push(0xA0 ^ i as u8);
                }
                let size = 10 + params.len() as u32;
                r.extend_from_slice(&0x8001u16.to_be_bytes());
                r.extend_from_slice(&size.to_be_bytes());
                r.extend_from_slice(&0u32.to_be_bytes());
                r.extend_from_slice(&params);
            }
            _ => {
                r.extend_from_slice(&0x8001u16.to_be_bytes());
                r.extend_from_slice(&10u32.to_be_bytes());
                r.extend_from_slice(&0x0000_0143u32.to_be_bytes()); // some failure rc
            }
        }
        s.rsp = r;
        s.rsp_pos = 0;
        s.data_avail = true;
        s.sts_ready = false;
    }
}

impl SpiBus for MockTpm {
    fn transfer(&self, buf: &mut [u8]) -> Result<(), bismuth::Error> {
        let read = buf[0] & 0x80 != 0;
        let addr = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;
        let data = &mut buf[4..];
        let mut s = self.0.lock().unwrap();
        match addr {
            ACCESS => {
                if read {
                    data[0] = if s.active { 1 << 5 } else { 0 };
                } else if data[0] & (1 << 1) != 0 {
                    s.active = true; // requestUse
                } else if data[0] & (1 << 5) != 0 {
                    s.active = false; // relinquish activeLocality
                }
            }
            STS => {
                if read {
                    data[0] = Self::sts_byte(&s);
                } else {
                    if data[0] & (1 << 6) != 0 {
                        s.cmd.clear();
                        s.sts_ready = true;
                        s.data_avail = false;
                    }
                    if data[0] & (1 << 5) != 0 {
                        Self::execute(&mut s);
                    }
                }
            }
            FIFO => {
                if read {
                    let start = s.rsp_pos;
                    for (i, b) in data.iter_mut().enumerate() {
                        *b = s.rsp.get(start + i).copied().unwrap_or(0);
                    }
                    s.rsp_pos += data.len();
                } else {
                    s.cmd.extend_from_slice(data);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[test]
fn tis_driver_extends_and_reads_pcrs_over_spi() {
    let tpm = TpmTis::new(MockTpm::new());

    // A freshly reset PCR reads back all-zero.
    assert_eq!(tpm.pcr(0).unwrap(), [0u8; 32]);

    // Extend PCR 0 twice and check the driver + chip agree on the SHA-256 extend chain.
    tpm.extend(0, b"boot-stage-1").unwrap();
    tpm.extend(0, b"boot-stage-2").unwrap();

    let d1: [u8; 32] = Sha256::digest(b"boot-stage-1").into();
    let d2: [u8; 32] = Sha256::digest(b"boot-stage-2").into();
    let mut expect = [0u8; 32];
    for d in [d1, d2] {
        let mut h = Sha256::new();
        h.update(expect);
        h.update(d);
        expect = h.finalize().into();
    }
    assert_eq!(tpm.pcr(0).unwrap(), expect, "TIS PCR_Extend/PCR_Read round-trip matches the chain");

    // A different PCR is independent.
    assert_eq!(tpm.pcr(5).unwrap(), [0u8; 32]);

    // GetRandom fills the whole buffer.
    let mut r = [0u8; 40];
    tpm.random(&mut r).unwrap();
    assert!(r.iter().any(|&b| b != 0), "TPM2_GetRandom returned data");
}

#[test]
fn tis_driver_leaves_seal_and_quote_to_the_object_hierarchy() {
    // The hardware driver implements the measured-boot core; sealing/quoting need the TPM 2.0
    // object/policy command suite and are reported Unsupported (software uses SoftTpm there).
    let tpm = TpmTis::new(MockTpm::new());
    assert_eq!(tpm.seal(b"secret", 1).err(), Some(bismuth::Error::Unsupported));
    let mut q = [0u8; 32];
    assert_eq!(tpm.quote(1, &[0u8; 8], &mut q).err(), Some(bismuth::Error::Unsupported));
}
