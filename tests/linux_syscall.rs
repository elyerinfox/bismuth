//! The Linux aarch64 syscall surface, driven against a mock address-space view.

#![cfg(feature = "linux-abi")]

use bismuth::compat::linux::syscall::{self, Outcome};

const BASE: u64 = 0x1000;

#[test]
fn write_reports_bytes_and_exit_sets_the_code() {
    let mut mem = vec![0u8; 256];
    mem[16..18].copy_from_slice(b"hi"); // a string at vaddr BASE+16

    // write(fd=1, buf=BASE+16, len=2) -> 2 (and "hi" to the console).
    assert_eq!(syscall::dispatch(syscall::WRITE, [1, BASE + 16, 2, 0, 0, 0], BASE, &mut mem), Outcome::Return(2));
    // exit_group(5) -> terminate with 5.
    assert_eq!(syscall::dispatch(syscall::EXIT_GROUP, [5, 0, 0, 0, 0, 0], BASE, &mut mem), Outcome::Exit(5));
    // read from stdin -> 0 (EOF).
    assert_eq!(syscall::dispatch(syscall::READ, [0, BASE, 8, 0, 0, 0], BASE, &mut mem), Outcome::Return(0));
    // an unimplemented syscall -> -ENOSYS.
    assert_eq!(syscall::dispatch(999, [0; 6], BASE, &mut mem), Outcome::Return(-38));
    // a faulting pointer -> -EFAULT.
    assert_eq!(syscall::dispatch(syscall::WRITE, [1, 0, 8, 0, 0, 0], BASE, &mut mem), Outcome::Return(-14));
}

#[test]
fn startup_identity_and_buffer_syscalls() {
    let mut mem = vec![0u8; 512];

    // The id calls report a root-equivalent, single-process identity.
    assert_eq!(syscall::dispatch(syscall::GETUID, [0; 6], BASE, &mut mem), Outcome::Return(0));
    assert_eq!(syscall::dispatch(syscall::GETEGID, [0; 6], BASE, &mut mem), Outcome::Return(0));
    assert_eq!(syscall::dispatch(syscall::GETPID, [0; 6], BASE, &mut mem), Outcome::Return(1));
    assert_eq!(syscall::dispatch(syscall::RT_SIGPROCMASK, [0; 6], BASE, &mut mem), Outcome::Return(0));

    // uname fills six 65-byte fields; sysname must read "Linux".
    assert_eq!(syscall::dispatch(syscall::UNAME, [BASE, 0, 0, 0, 0, 0], BASE, &mut mem), Outcome::Return(0));
    assert_eq!(&mem[0..5], b"Linux");
    assert_eq!(mem[5], 0, "NUL-padded field");
    assert_eq!(&mem[4 * 65..4 * 65 + 7], b"aarch64");

    // getrandom(buf=BASE+128, len=16) returns 16 and writes 16 bytes.
    let before = mem[128..144].to_vec();
    assert_eq!(syscall::dispatch(syscall::GETRANDOM, [BASE + 128, 16, 0, 0, 0, 0], BASE, &mut mem), Outcome::Return(16));
    assert_ne!(mem[128..144], before[..], "the buffer was filled");

    // clock_gettime writes a 16-byte timespec and returns 0.
    assert_eq!(syscall::dispatch(syscall::CLOCK_GETTIME, [1, BASE + 160, 0, 0, 0, 0], BASE, &mut mem), Outcome::Return(0));
}
