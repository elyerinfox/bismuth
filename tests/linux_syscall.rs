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
