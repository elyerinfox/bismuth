//! The Linux/SysV initial process stack builder.

#![cfg(feature = "linux-abi")]

use bismuth::compat::linux::stack;

const BASE: u64 = 0x8000_0000;

#[test]
fn builds_the_initial_process_stack() {
    let mut buf = vec![0u8; 256];
    let sp = stack::build(&mut buf, BASE, &["prog", "--flag"], &["HOME=/"]).unwrap();

    let rd = |vaddr: u64| -> u64 {
        let o = (vaddr - BASE) as usize;
        u64::from_le_bytes(buf[o..o + 8].try_into().unwrap())
    };
    let string_at = |vaddr: u64| -> String {
        let o = (vaddr - BASE) as usize;
        let end = buf[o..].iter().position(|&b| b == 0).unwrap();
        String::from_utf8(buf[o..o + end].to_vec()).unwrap()
    };

    assert_eq!(sp % 16, 0, "sp is 16-byte aligned");
    assert_eq!(rd(sp), 2, "argc");
    assert_eq!(string_at(rd(sp + 8)), "prog"); // argv[0]
    assert_eq!(string_at(rd(sp + 16)), "--flag"); // argv[1]
    assert_eq!(rd(sp + 24), 0, "argv NULL terminator");
    assert_eq!(string_at(rd(sp + 32)), "HOME=/"); // envp[0]
    assert_eq!(rd(sp + 40), 0, "envp NULL terminator");
    // auxv: AT_PAGESZ (6) = 4096, then AT_NULL (0).
    assert_eq!(rd(sp + 48), 6);
    assert_eq!(rd(sp + 56), 4096);
    assert_eq!(rd(sp + 64), 0);
}
