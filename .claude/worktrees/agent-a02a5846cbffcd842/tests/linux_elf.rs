//! The Linux-ABI ELF loader: parse a 64-bit aarch64 ELF's header and PT_LOAD segments.

#![cfg(feature = "linux-abi")]

use bismuth::compat::linux::elf::{Elf, PF_R, PF_X};

/// Build a minimal, well-formed aarch64 ELF: 64-byte header + one PT_LOAD program header + a few
/// bytes of "code", linked at vaddr 0x400000 with the entry just past the headers.
fn minimal_elf() -> Vec<u8> {
    let mut b = vec![0u8; 124];
    b[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // little-endian
    b[6] = 1; // version
    b[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    b[18..20].copy_from_slice(&183u16.to_le_bytes()); // e_machine = AArch64
    b[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    b[24..32].copy_from_slice(&0x0040_0078u64.to_le_bytes()); // e_entry
    b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    // Program header at offset 64.
    let ph = 64;
    b[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    b[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    b[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
    b[ph + 16..ph + 24].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // p_vaddr
    b[ph + 24..ph + 32].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // p_paddr
    b[ph + 32..ph + 40].copy_from_slice(&124u64.to_le_bytes()); // p_filesz
    b[ph + 40..ph + 48].copy_from_slice(&124u64.to_le_bytes()); // p_memsz
    b[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
    b
}

#[test]
fn parses_an_aarch64_executable() {
    let img = minimal_elf();
    let elf = Elf::parse(&img).unwrap();
    assert_eq!(elf.entry, 0x0040_0078);
    assert!(!elf.pie);
    assert_eq!(elf.n_segments, 1);
    let s = elf.segments()[0];
    assert_eq!(s.vaddr, 0x0040_0000);
    assert_eq!(s.filesz, 124);
    assert_eq!(s.flags, PF_R | PF_X);
    assert_eq!(elf.address_span(), (0x0040_0000, 0x0040_007c));
}

#[test]
fn rejects_non_elf_and_wrong_arch() {
    assert!(Elf::parse(b"not an elf at all").is_err());
    let mut img = minimal_elf();
    img[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = x86-64, not aarch64
    assert_eq!(Elf::parse(&img).err(), Some(bismuth::Error::Unsupported));
}
