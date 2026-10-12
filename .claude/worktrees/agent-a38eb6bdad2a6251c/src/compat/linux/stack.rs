//! The Linux/SysV initial process stack for `aarch64`. Before jumping to a Linux executable's
//! entry point the kernel lays out, at the stack pointer: `argc`, the `argv` pointers + NULL, the
//! `envp` pointers + NULL, and the auxiliary vector (`auxv`) terminated by `AT_NULL`, with the
//! argument/environment strings stored just above. `_start` (and the libc that follows) reads
//! exactly this shape. Pure, bounded, safe Rust — it fills a caller-provided buffer that maps to
//! `[base_vaddr, base_vaddr + buf.len())` and returns the initial `sp`.
//!
//! Classification: L4 personalities · linux initial stack · safe · linux-abi

use crate::Error;

// A few auxv entry types (enough for a static binary's start-up).
const AT_NULL: u64 = 0;
const AT_PAGESZ: u64 = 6;
const PAGE_SIZE: u64 = 4096;

fn w64(buf: &mut [u8], at: usize, v: u64) -> Result<(), Error> {
    buf.get_mut(at..at + 8).ok_or(Error::Invalid)?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Lay out the initial stack in `buf` (which maps to `[base_vaddr, base_vaddr+len)`), returning
/// the initial `sp` (a vaddr) pointing at `argc`. Strings go at the top; the pointer vectors sit
/// below them, 16-byte aligned per the aarch64 ABI.
pub fn build(buf: &mut [u8], base_vaddr: u64, argv: &[&str], envp: &[&str]) -> Result<u64, Error> {
    let len = buf.len();

    // 1. Copy the strings to the top of the region, recording each one's vaddr.
    let mut sp_off = len;
    let mut argv_ptrs = [0u64; 32];
    let mut envp_ptrs = [0u64; 32];
    if argv.len() > 32 || envp.len() > 32 {
        return Err(Error::NoResources);
    }
    let mut put_str = |off: &mut usize, s: &str| -> Result<u64, Error> {
        let need = s.len() + 1; // NUL-terminated
        *off = off.checked_sub(need).ok_or(Error::NoResources)?;
        buf[*off..*off + s.len()].copy_from_slice(s.as_bytes());
        buf[*off + s.len()] = 0;
        Ok(base_vaddr + *off as u64)
    };
    for (i, s) in argv.iter().enumerate() {
        argv_ptrs[i] = put_str(&mut sp_off, s)?;
    }
    for (i, s) in envp.iter().enumerate() {
        envp_ptrs[i] = put_str(&mut sp_off, s)?;
    }

    // 2. Size the vector block: argc + argv[] + NULL + envp[] + NULL + auxv(PAGESZ, NULL).
    let words = 1 + (argv.len() + 1) + (envp.len() + 1) + 4;
    let bytes = words * 8;
    // 16-byte align the final sp downward.
    sp_off = (sp_off - bytes) & !0xF;
    let sp = base_vaddr + sp_off as u64;

    // 3. Write the vectors.
    let mut o = sp_off;
    w64(buf, o, argv.len() as u64)?; // argc
    o += 8;
    for i in 0..argv.len() {
        w64(buf, o, argv_ptrs[i])?;
        o += 8;
    }
    w64(buf, o, 0)?; // argv NULL
    o += 8;
    for i in 0..envp.len() {
        w64(buf, o, envp_ptrs[i])?;
        o += 8;
    }
    w64(buf, o, 0)?; // envp NULL
    o += 8;
    // auxv.
    w64(buf, o, AT_PAGESZ)?;
    w64(buf, o + 8, PAGE_SIZE)?;
    w64(buf, o + 16, AT_NULL)?;
    w64(buf, o + 24, 0)?;

    Ok(sp)
}
