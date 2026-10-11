//! Trusted-platform root of trust (SoftTpm): measured boot, sealing bound to PCR state,
//! and attestation quotes — all host-testable with no hardware.

use bismuth::security::trust::{RootOfTrust, SoftTpm};

const SECRET: [u8; 32] = [7u8; 32];
const KEK: [u8; 32] = [0x42u8; 32];
const MASK: u32 = 0b11; // PCR 0 and 1

fn measure(tpm: &SoftTpm, firmware: &[u8], workload: &[u8]) {
    tpm.extend(0, firmware).unwrap();
    tpm.extend(1, workload).unwrap();
}

#[test]
fn seal_unseal_is_bound_to_measured_boot() {
    let tpm = SoftTpm::new(SECRET);
    measure(&tpm, b"firmware-v1", b"workload-A");

    // Seal a root KEK to the current PCR state.
    let sealed = tpm.seal(&KEK, MASK).unwrap();

    // Unsealing in the same state recovers it.
    let mut out = [0u8; 32];
    assert_eq!(tpm.unseal(&sealed, &mut out).unwrap(), 32);
    assert_eq!(out, KEK);

    // Reboot into a DIFFERENT firmware measurement: unsealing fails closed.
    tpm.reboot();
    measure(&tpm, b"firmware-EVIL", b"workload-A");
    let mut bad = [0u8; 32];
    assert_eq!(tpm.unseal(&sealed, &mut bad).unwrap_err(), bismuth::Error::Integrity);

    // Reboot into the ORIGINAL measurement: unsealing succeeds again (deterministic PCRs).
    tpm.reboot();
    measure(&tpm, b"firmware-v1", b"workload-A");
    let mut good = [0u8; 32];
    assert_eq!(tpm.unseal(&sealed, &mut good).unwrap(), 32);
    assert_eq!(good, KEK);
}

#[test]
fn a_different_device_cannot_unseal() {
    let a = SoftTpm::new([1u8; 32]);
    let b = SoftTpm::new([2u8; 32]); // different device secret
    measure(&a, b"fw", b"wl");
    measure(&b, b"fw", b"wl"); // same measurements, different device

    let sealed = a.seal(&KEK, MASK).unwrap();
    let mut out = [0u8; 32];
    assert_eq!(b.unseal(&sealed, &mut out).unwrap_err(), bismuth::Error::Integrity);
    // The issuing device still can.
    assert_eq!(a.unseal(&sealed, &mut out).unwrap(), 32);
    assert_eq!(out, KEK);
}

#[test]
fn quote_attests_pcr_state_and_depends_on_nonce() {
    let tpm = SoftTpm::new(SECRET);
    measure(&tpm, b"fw", b"wl");
    let mut q1 = [0u8; 32];
    let mut q2 = [0u8; 32];
    tpm.quote(MASK, b"challenge-1", &mut q1).unwrap();
    tpm.quote(MASK, b"challenge-2", &mut q2).unwrap();
    assert_ne!(q1, q2, "quote must depend on the challenge nonce");

    // Same state + same nonce reproduces the quote (verifiable by a relying party).
    let mut q1b = [0u8; 32];
    tpm.quote(MASK, b"challenge-1", &mut q1b).unwrap();
    assert_eq!(q1, q1b);

    // Changing a PCR changes the quote.
    tpm.extend(0, b"more").unwrap();
    let mut q3 = [0u8; 32];
    tpm.quote(MASK, b"challenge-1", &mut q3).unwrap();
    assert_ne!(q1, q3);
}

#[test]
fn random_is_nonzero_and_varies() {
    let tpm = SoftTpm::new(SECRET);
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    tpm.random(&mut a).unwrap();
    tpm.random(&mut b).unwrap();
    assert_ne!(a, [0u8; 16]);
    assert_ne!(a, b, "successive draws must differ");
}

#[test]
fn per_volume_keys_derive_independently_from_one_root() {
    use bismuth::security::trust::derive_volume_key;
    let root = [0x5Au8; 32];
    let sd = derive_volume_key(&root, b"volume:sd0");
    let flash = derive_volume_key(&root, b"volume:mtd0");
    // Distinct labels → independent keys; same label → reproducible.
    assert_ne!(sd, flash);
    assert_eq!(sd, derive_volume_key(&root, b"volume:sd0"));
    // A different root yields entirely different keys.
    assert_ne!(sd, derive_volume_key(&[0x5Bu8; 32], b"volume:sd0"));
}

#[test]
fn retained_ram_round_trips_and_fails_closed_on_measurement_change() {
    use bismuth::security::entropy::{self, SimTrng};
    use bismuth::security::retained::RetainedRegion;
    use bismuth::sim;

    static TRNG: SimTrng = SimTrng::new(0x5151, 4);
    static REGION: RetainedRegion<64> = RetainedRegion::new();

    sim::run_to_completion(|| {
        entropy::add_source(&TRNG).unwrap();
        entropy::seed(314).unwrap();
        let tpm = SoftTpm::new(SECRET);
        tpm.extend(0, b"firmware").unwrap();

        REGION.write(b"top secret retained state").unwrap();
        REGION.pre_sleep(&tpm, 1 << 0).unwrap();
        assert!(REGION.is_sealed());

        // Confidentiality: the buffer is ciphertext while sealed.
        let mut ct = [0u8; 64];
        let n = REGION.read(&mut ct);
        assert_ne!(&ct[..n], b"top secret retained state", "sealed region is ciphertext");

        // Same measured state on resume → decrypts.
        REGION.post_resume(&tpm).unwrap();
        let mut pt = [0u8; 64];
        let n = REGION.read(&mut pt);
        assert_eq!(&pt[..n], b"top secret retained state", "retained state recovered");

        // A changed measurement (reboot resets PCRs) → the sealed key will not release.
        REGION.write(b"more secret state").unwrap();
        REGION.pre_sleep(&tpm, 1 << 0).unwrap();
        tpm.reboot();
        assert!(REGION.post_resume(&tpm).is_err(), "fails closed when the measured state changed");
    });
}
