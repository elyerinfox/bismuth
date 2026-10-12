//! Encrypted block device (`CryptBlock`): transparent at-rest encryption, ciphertext on the
//! backing medium, fail-closed without the key, and an end-to-end encrypted FAT volume.

use std::sync::Mutex as StdMutex;

use bismuth::driver::block::{BlockDevice, CryptBlock, SimDisk};
use bismuth::fs::{self, FatFs, OpenMode};
use bismuth::sim;

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const DEK: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];

static CB: CryptBlock<SimDisk<200, 512>, 512> = CryptBlock::new(SimDisk::new());

#[test]
fn encrypts_at_rest_and_fails_closed() {
    let _g = serial();
    CB.set_dek(DEK, SEED);

    let mut plain = [0u8; 512];
    plain[..11].copy_from_slice(b"TOP SECRET!");
    CB.prog(0, 0, &plain).unwrap();

    // Round-trips through the cipher.
    let mut back = [0u8; 512];
    CB.read(0, 0, &mut back).unwrap();
    assert_eq!(&back[..11], b"TOP SECRET!");

    // The backing disk holds ciphertext, not the plaintext.
    let mut raw = [0u8; 11];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = CB.inner().peek(0, i as u32);
    }
    assert_ne!(&raw, b"TOP SECRET!");

    // Without a key: fail closed.
    CB.clear_dek();
    assert_eq!(CB.read(0, 0, &mut back).unwrap_err(), bismuth::Error::NotReady);

    // With the wrong key: authentication fails (never silently wrong plaintext).
    CB.set_dek([0x99; 32], SEED);
    assert_eq!(CB.read(0, 0, &mut back).unwrap_err(), bismuth::Error::Integrity);

    // Right key again: recovers.
    CB.set_dek(DEK, SEED);
    CB.read(0, 0, &mut back).unwrap();
    assert_eq!(&back[..11], b"TOP SECRET!");
}

// A FAT16 volume living on top of the encrypted block device.
static EDISK: CryptBlock<SimDisk<4600, 512>, 512> = CryptBlock::new(SimDisk::new());
static EFS: FatFs = FatFs::new(&EDISK);

#[test]
fn encrypted_fat_end_to_end() {
    let _g = serial();
    EDISK.set_dek(DEK, SEED);
    EFS.format().unwrap();
    sim::run_to_completion(|| {
        fs::mount("/enc", &EFS).unwrap();
        let f = fs::open("/enc/VAULT.TXT", OpenMode::RDWR.with(OpenMode::CREATE)).unwrap();
        fs::write(f, b"classified payload").unwrap();
        fs::close(f);
        let r = fs::open("/enc/VAULT.TXT", OpenMode::READ).unwrap();
        let mut b = [0u8; 32];
        let n = fs::read(r, &mut b).unwrap();
        assert_eq!(&b[..n], b"classified payload");
        fs::close(r);
    });

    // The raw disk shows no FAT signature and not the plaintext — it is fully encrypted.
    assert_ne!(EDISK.inner().peek(0, 510), 0x55); // FAT boot signature is 0x55,0xAA
    let mut found = false;
    for blk in 0..40u32 {
        let mut window = [0u8; 18];
        for (i, w) in window.iter_mut().enumerate() {
            *w = EDISK.inner().peek(blk, 32 + i as u32);
        }
        if &window == b"classified payload" {
            found = true;
        }
    }
    assert!(!found, "plaintext must not appear on the backing disk");
}

// ----- TPM-gated encrypted storage: the sealed key unlocks the volume -----

use bismuth::security::trust::{RootOfTrust, SoftTpm};

static TDISK: CryptBlock<SimDisk<200, 512>, 512> = CryptBlock::new(SimDisk::new());

#[test]
fn tpm_sealed_key_unlocks_encrypted_storage() {
    let _g = serial();
    let tpm = SoftTpm::new([0xABu8; 32]);
    // Measured boot, then seal the volume DEK to that measurement.
    tpm.extend(0, b"bootloader").unwrap();
    tpm.extend(1, b"kernel-image").unwrap();
    let sealed = tpm.seal(&DEK, 0b11).unwrap();

    // "Boot" in the correct state: unseal the DEK and unlock the encrypted volume.
    let mut key = [0u8; 32];
    assert_eq!(tpm.unseal(&sealed, &mut key).unwrap(), 32);
    TDISK.set_dek(key, SEED);
    let mut plain = [0u8; 512];
    plain[..6].copy_from_slice(b"unseal");
    TDISK.prog(0, 0, &plain).unwrap();
    let mut back = [0u8; 512];
    TDISK.read(0, 0, &mut back).unwrap();
    assert_eq!(&back[..6], b"unseal");
    TDISK.clear_dek();

    // "Boot" in a tampered state: the DEK cannot be unsealed, so the volume stays locked.
    tpm.reboot();
    tpm.extend(0, b"evil-bootloader").unwrap();
    tpm.extend(1, b"kernel-image").unwrap();
    let mut key2 = [0u8; 32];
    assert_eq!(tpm.unseal(&sealed, &mut key2).unwrap_err(), bismuth::Error::Integrity);
    // No key released → storage fails closed.
    assert_eq!(TDISK.read(0, 0, &mut back).unwrap_err(), bismuth::Error::NotReady);
}
