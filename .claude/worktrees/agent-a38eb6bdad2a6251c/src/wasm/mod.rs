//! A minimal WebAssembly interpreter — the C8 "Wasm container": it parses a core `wasm32` module
//! and executes its exported functions, so a workload can arrive as portable bytecode rather than
//! native code (the sandbox the signed-bundle loader could not give on an MMU-less target).
//!
//! Scope: the `i32` value type with structured control flow (`block`/`loop`/`if`/`br`/`br_if`/
//! `call`/`return`) and the common integer operators — enough to run real compute kernels
//! (loops, recursion). It needs the [`heap`](crate::kernel::heap) feature (the module, value
//! stack and locals use `alloc`); the engine is pure safe Rust, bounded by a recursion-depth and
//! step budget so a module cannot wedge the system.
//!
//! Classification: L4 personalities · wasm interpreter · safe · wasm
#![cfg(feature = "heap")]

pub mod oci;

use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;

const MAX_CALL_DEPTH: usize = 256;
const MAX_STEPS: u64 = 50_000_000;

/// A WASI host function this engine implements (imported by the module).
#[derive(Copy, Clone, PartialEq, Eq)]
enum Host {
    FdWrite,
    FdRead,
    FdClose,
    FdPrestatGet,
    FdPrestatDirName,
    FdFdstatGet,
    ProcExit,
    EnvironSizesGet,
    EnvironGet,
    ArgsSizesGet,
    ArgsGet,
    ClockTimeGet,
    RandomGet,
    Unknown,
}

/// A parsed module: function signatures (`i32` counts only), function bodies, exports, imported
/// host functions (WASI), and the linear-memory minimum.
pub struct Module {
    /// `(param_count, result_count)` per type.
    types: Vec<(u32, u32)>,
    funcs: Vec<Func>,
    exports: Vec<(String, u32)>,
    /// Imported functions occupy the low function-index space; each is `(host fn, type index)`.
    imports: Vec<(Host, u32)>,
    /// Minimum linear-memory size, in 64 KiB pages (0 = no memory).
    mem_pages: u32,
    /// Initial values of the module's globals (wasm-ld emits a mutable one for the shadow stack).
    globals: Vec<i64>,
    /// Active data segments `(offset, bytes)` copied into linear memory at instantiation.
    data: Vec<(u32, Vec<u8>)>,
}

struct Func {
    type_idx: u32,
    n_locals: u32,
    body: Vec<u8>,
}

/// Mutable per-invocation state: the linear memory, the globals, and a pending `proc_exit` code.
struct Ctx {
    mem: Vec<u8>,
    globals: Vec<i64>,
    steps: u64,
    exit: Option<i32>,
}

const PAGE: usize = 65536;

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0 }
    }
    fn byte(&mut self) -> Result<u8, Error> {
        let v = *self.b.get(self.p).ok_or(Error::Invalid)?;
        self.p += 1;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let s = self.b.get(self.p..self.p + n).ok_or(Error::Invalid)?;
        self.p += n;
        Ok(s)
    }
    /// Unsigned LEB128.
    fn uleb(&mut self) -> Result<u64, Error> {
        let (mut r, mut shift) = (0u64, 0);
        loop {
            let b = self.byte()?;
            r |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(r);
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::Invalid);
            }
        }
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(self.uleb()? as u32)
    }

    /// Read a constant init expression (`i32.const`/`i64.const` … `end`), returning its value.
    fn const_expr(&mut self) -> Result<i64, Error> {
        let op = self.byte()?;
        let v = match op {
            0x41 | 0x42 => {
                let (val, n) = sleb(self.b, self.p)?;
                self.p += n;
                val
            }
            _ => return Err(Error::Unsupported),
        };
        if self.byte()? != 0x0b {
            return Err(Error::Invalid);
        }
        Ok(v)
    }
}

/// Signed LEB128 starting at `body[pc]`; returns the value and the byte length.
fn sleb(body: &[u8], pc: usize) -> Result<(i64, usize), Error> {
    let (mut r, mut shift, mut i) = (0i64, 0u32, 0usize);
    loop {
        let b = *body.get(pc + i).ok_or(Error::Invalid)?;
        r |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        i += 1;
        if b & 0x80 == 0 {
            if shift < 64 && b & 0x40 != 0 {
                r |= -1i64 << shift;
            }
            return Ok((r, i));
        }
        if shift >= 64 {
            return Err(Error::Invalid);
        }
    }
}

/// Unsigned LEB128 starting at `body[pc]`; returns the value and the byte length.
fn uleb_at(body: &[u8], pc: usize) -> Result<(u64, usize), Error> {
    let (mut r, mut shift, mut i) = (0u64, 0u32, 0usize);
    loop {
        let b = *body.get(pc + i).ok_or(Error::Invalid)?;
        r |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        i += 1;
        if b & 0x80 == 0 {
            return Ok((r, i));
        }
        if shift >= 64 {
            return Err(Error::Invalid);
        }
    }
}

impl Module {
    /// Parse a WebAssembly binary module (magic + version + the type/function/export/code
    /// sections; other sections are skipped by length).
    pub fn parse(bin: &[u8]) -> Result<Module, Error> {
        let mut r = Reader::new(bin);
        if r.bytes(4)? != [0x00, 0x61, 0x73, 0x6d] || r.bytes(4)? != [0x01, 0x00, 0x00, 0x00] {
            return Err(Error::Invalid);
        }
        let mut types = Vec::new();
        let mut type_idx = Vec::new();
        let mut codes: Vec<Vec<u8>> = Vec::new();
        let mut exports = Vec::new();
        let mut imports: Vec<(Host, u32)> = Vec::new();
        let mut mem_pages = 0u32;
        let mut globals: Vec<i64> = Vec::new();
        let mut data: Vec<(u32, Vec<u8>)> = Vec::new();
        while r.p < bin.len() {
            let id = r.byte()?;
            let len = r.u32()? as usize;
            let end = r.p + len;
            match id {
                2 => {
                    // Import section: record function imports (they take the low func indices)
                    // and map each to a host function by its field name.
                    let n = r.u32()?;
                    for _ in 0..n {
                        let ml = r.u32()? as usize;
                        let _module = r.bytes(ml)?;
                        let fl = r.u32()? as usize;
                        let field = core::str::from_utf8(r.bytes(fl)?).map_err(|_| Error::Invalid)?;
                        let kind = r.byte()?;
                        match kind {
                            0x00 => {
                                let ti = r.u32()?; // type index
                                let host = match field {
                                    "fd_write" => Host::FdWrite,
                                    "fd_read" => Host::FdRead,
                                    "fd_close" => Host::FdClose,
                                    "fd_prestat_get" => Host::FdPrestatGet,
                                    "fd_prestat_dir_name" => Host::FdPrestatDirName,
                                    "fd_fdstat_get" => Host::FdFdstatGet,
                                    "proc_exit" => Host::ProcExit,
                                    "environ_sizes_get" => Host::EnvironSizesGet,
                                    "environ_get" => Host::EnvironGet,
                                    "args_sizes_get" => Host::ArgsSizesGet,
                                    "args_get" => Host::ArgsGet,
                                    "clock_time_get" => Host::ClockTimeGet,
                                    "random_get" => Host::RandomGet,
                                    _ => Host::Unknown,
                                };
                                imports.push((host, ti));
                            }
                            0x01 => {
                                // table: flags + elemtype + limits
                                let _ = r.byte()?;
                                let f = r.byte()?;
                                let _ = r.u32()?;
                                if f == 1 {
                                    let _ = r.u32()?;
                                }
                            }
                            0x02 => {
                                let f = r.byte()?;
                                let _ = r.u32()?;
                                if f == 1 {
                                    let _ = r.u32()?;
                                }
                            }
                            0x03 => {
                                let _ = r.byte()?; // global valtype
                                let _ = r.byte()?; // mutability
                            }
                            _ => return Err(Error::Unsupported),
                        }
                    }
                }
                5 => {
                    // Memory section: one memory, take its minimum page count.
                    let n = r.u32()?;
                    for i in 0..n {
                        let flags = r.byte()?;
                        let min = r.u32()?;
                        if flags == 1 {
                            let _max = r.u32()?;
                        }
                        if i == 0 {
                            mem_pages = min;
                        }
                    }
                }
                1 => {
                    // Type section: each entry is `0x60 params results` (i32 only).
                    let n = r.u32()?;
                    for _ in 0..n {
                        if r.byte()? != 0x60 {
                            return Err(Error::Unsupported);
                        }
                        let np = r.u32()?;
                        for _ in 0..np {
                            let t = r.byte()?;
                            if !matches!(t, 0x7f | 0x7e | 0x7d | 0x7c) {
                            return Err(Error::Unsupported); // i32 / i64 value types
                            }
                        }
                        let nr = r.u32()?;
                        for _ in 0..nr {
                            let t = r.byte()?;
                            if !matches!(t, 0x7f | 0x7e | 0x7d | 0x7c) {
                            return Err(Error::Unsupported);
                            }
                        }
                        types.push((np, nr));
                    }
                }
                3 => {
                    let n = r.u32()?;
                    for _ in 0..n {
                        type_idx.push(r.u32()?);
                    }
                }
                7 => {
                    let n = r.u32()?;
                    for _ in 0..n {
                        let nl = r.u32()? as usize;
                        let name = core::str::from_utf8(r.bytes(nl)?).map_err(|_| Error::Invalid)?;
                        let kind = r.byte()?;
                        let idx = r.u32()?;
                        if kind == 0x00 {
                            exports.push((String::from(name), idx));
                        }
                    }
                }
                6 => {
                    // Global section: valtype + mutability + a constant init expression.
                    let n = r.u32()?;
                    for _ in 0..n {
                        let _valtype = r.byte()?;
                        let _mutable = r.byte()?;
                        globals.push(r.const_expr()?);
                    }
                }
                10 => {
                    let n = r.u32()?;
                    for _ in 0..n {
                        let sz = r.u32()? as usize;
                        codes.push(Vec::from(r.bytes(sz)?));
                    }
                }
                11 => {
                    // Data section: active segments (mode 0 / 2) are copied into memory at offset.
                    let n = r.u32()?;
                    for _ in 0..n {
                        let mode = r.u32()?;
                        let off = match mode {
                            0 => r.const_expr()? as u32,
                            2 => {
                                let _memidx = r.u32()?;
                                r.const_expr()? as u32
                            }
                            _ => {
                                // Passive segment: size-prefixed bytes, no offset — skip.
                                let sz = r.u32()? as usize;
                                let _ = r.bytes(sz)?;
                                continue;
                            }
                        };
                        let sz = r.u32()? as usize;
                        data.push((off, Vec::from(r.bytes(sz)?)));
                    }
                }
                _ => {}
            }
            r.p = end;
        }
        if type_idx.len() != codes.len() {
            return Err(Error::Invalid);
        }
        let mut funcs = Vec::new();
        for (ti, code) in type_idx.into_iter().zip(codes.into_iter()) {
            // A body is `vec(locals) expr`; parse the local declarations off the front.
            let mut lr = Reader::new(&code);
            let decls = lr.u32()?;
            let mut n_locals = 0u32;
            for _ in 0..decls {
                let cnt = lr.u32()?;
                let t = lr.byte()?;
                if !matches!(t, 0x7f | 0x7e | 0x7d | 0x7c) {
                            return Err(Error::Unsupported);
                }
                n_locals += cnt;
            }
            let body = Vec::from(&code[lr.p..]);
            funcs.push(Func { type_idx: ti, n_locals, body });
        }
        Ok(Module { types, funcs, exports, imports, mem_pages, globals, data })
    }

    /// Build a fresh instance's linear memory with the data segments applied.
    fn new_memory(&self) -> Vec<u8> {
        let mut mem = alloc::vec::from_elem(0u8, self.mem_pages as usize * PAGE);
        for (off, bytes) in &self.data {
            let at = *off as usize;
            if at + bytes.len() <= mem.len() {
                mem[at..at + bytes.len()].copy_from_slice(bytes);
            }
        }
        mem
    }

    /// Invoke an exported function by name with `i32` arguments; returns its single `i32` result
    /// (or `None` if it returns nothing).
    pub fn invoke(&self, name: &str, args: &[i32]) -> Result<Option<i32>, Error> {
        let idx = self.exports.iter().find(|(n, _)| n == name).map(|(_, i)| *i).ok_or(Error::NotFound)?;
        let mut ctx = Ctx { mem: self.new_memory(), globals: self.globals.clone(), steps: 0, exit: None };
        let a64: Vec<i64> = args.iter().map(|&x| x as i64).collect();
        let r = self.call(idx, &a64, 0, &mut ctx)?;
        // A `proc_exit` unwinds to here; surface its code as the result (truncating i64 to i32).
        Ok(ctx.exit.map(Some).unwrap_or(r.map(|v| v as i32)))
    }

    /// Invoke the module's conventional WASI entry point (`_start`), returning the exit code.
    pub fn run_wasi(&self) -> Result<i32, Error> {
        let idx = self.exports.iter().find(|(n, _)| n == "_start").map(|(_, i)| *i).ok_or(Error::NotFound)?;
        let mut ctx = Ctx { mem: self.new_memory(), globals: self.globals.clone(), steps: 0, exit: None };
        self.call(idx, &[], 0, &mut ctx)?;
        Ok(ctx.exit.unwrap_or(0))
    }

    /// Values on the stack are 64-bit cells: `i32` occupies the low word (sign-extended), `i64`
    /// the whole cell. This keeps one interpreter for both widths.
    fn call(&self, fidx: u32, args: &[i64], depth: usize, ctx: &mut Ctx) -> Result<Option<i64>, Error> {
        if depth >= MAX_CALL_DEPTH {
            return Err(Error::NoResources);
        }
        // Imported functions occupy the low index space; dispatch them to the host (WASI).
        let n_imports = self.imports.len() as u32;
        if fidx < n_imports {
            return self.host_call(self.imports[fidx as usize].0, args, ctx);
        }
        let f = self.funcs.get((fidx - n_imports) as usize).ok_or(Error::Invalid)?;
        let (nparams, nresults) = *self.types.get(f.type_idx as usize).ok_or(Error::Invalid)?;
        if args.len() != nparams as usize {
            return Err(Error::Invalid);
        }
        let mut locals: Vec<i64> = Vec::with_capacity(nparams as usize + f.n_locals as usize);
        locals.extend_from_slice(args);
        for _ in 0..f.n_locals {
            locals.push(0);
        }
        let mut stack: Vec<i64> = Vec::new();
        self.run(&f.body, &mut locals, &mut stack, depth, ctx)?;
        if nresults == 0 { Ok(None) } else { Ok(stack.pop()) }
    }

    /// A WASI host call (preview-1 subset): console I/O, exit, empty args/env, clock and random —
    /// enough to run a `wasm32-wasi` program's start-up and a `println!`-style workload.
    fn host_call(&self, which: Host, args: &[i64], ctx: &mut Ctx) -> Result<Option<i64>, Error> {
        // Little-endian stores into linear memory, bounds-checked.
        let put32 = |ctx: &mut Ctx, at: usize, v: u32| {
            if at + 4 <= ctx.mem.len() {
                ctx.mem[at..at + 4].copy_from_slice(&v.to_le_bytes());
            }
        };
        match which {
            Host::ProcExit => {
                ctx.exit = Some(*args.first().unwrap_or(&0) as i32);
                Ok(None)
            }
            // No environment and no args: report zero counts/sizes; the *_get calls are no-ops.
            Host::EnvironSizesGet | Host::ArgsSizesGet => {
                put32(ctx, args[0] as u32 as usize, 0); // count
                put32(ctx, args[1] as u32 as usize, 0); // buffer size
                Ok(Some(0))
            }
            Host::EnvironGet | Host::ArgsGet => Ok(Some(0)),
            Host::ClockTimeGet => {
                // clock_time_get(id, precision, time_ptr) -> errno; write nanoseconds since boot.
                let ns = crate::kernel::time::ms_since_boot().saturating_mul(1_000_000);
                let at = args[2] as u32 as usize;
                if at + 8 <= ctx.mem.len() {
                    ctx.mem[at..at + 8].copy_from_slice(&ns.to_le_bytes());
                }
                Ok(Some(0))
            }
            Host::RandomGet => {
                // random_get(buf, buf_len) -> errno; fill with a SplitMix-style stream seeded from
                // the monotonic clock (adequate for wasm; not a CSPRNG).
                let (buf, len) = (args[0] as u32 as usize, args[1] as u32 as usize);
                let mut x = crate::kernel::time::ms_since_boot().wrapping_add(0x9E37_79B9_7F4A_7C15);
                for i in 0..len {
                    if buf + i >= ctx.mem.len() {
                        break;
                    }
                    x ^= x >> 30;
                    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    x ^= x >> 27;
                    ctx.mem[buf + i] = (x >> 33) as u8;
                }
                Ok(Some(0))
            }
            Host::FdRead => {
                // fd_read(fd, iovs, iovs_len, nread) -> errno; no stdin → report 0 bytes (EOF).
                put32(ctx, args[3] as u32 as usize, 0);
                Ok(Some(0))
            }
            // No preopened directories: EBADF (8) ends wasi-libc's preopen-scan loop at startup.
            Host::FdPrestatGet | Host::FdPrestatDirName => Ok(Some(8)),
            Host::FdFdstatGet => {
                // Write a 24-byte fdstat: filetype=2 (character device, i.e. a tty) for 0/1/2.
                let at = args[1] as u32 as usize;
                if at + 24 <= ctx.mem.len() {
                    for b in &mut ctx.mem[at..at + 24] {
                        *b = 0;
                    }
                    ctx.mem[at] = 2; // fs_filetype = CHARACTER_DEVICE
                }
                Ok(Some(0))
            }
            Host::FdClose => Ok(Some(0)),
            Host::FdWrite => {
                // fd_write(fd, iovs, iovs_len, nwritten) -> errno. Gather the iovecs from linear
                // memory and write stdout/stderr (fd 1/2) to the kernel console.
                let (fd, iovs, iovs_len, nwritten) =
                    (args[0] as i32, args[1] as u32 as usize, args[2] as u32 as usize, args[3] as u32 as usize);
                let mem = &ctx.mem;
                let rd = |o: usize| -> u32 {
                    u32::from_le_bytes([mem[o], mem[o + 1], mem[o + 2], mem[o + 3]])
                };
                let mut total = 0u32;
                for i in 0..iovs_len {
                    let base = iovs + i * 8;
                    if base + 8 > mem.len() {
                        return Ok(Some(28)); // EFAULT-ish
                    }
                    let ptr = rd(base) as usize;
                    let len = rd(base + 4) as usize;
                    if ptr + len > mem.len() {
                        return Ok(Some(28));
                    }
                    if fd == 1 || fd == 2 {
                        if let Ok(s) = core::str::from_utf8(&mem[ptr..ptr + len]) {
                            crate::console::write_bytes(s.as_bytes());
                        }
                    }
                    total += len as u32;
                }
                if nwritten + 4 <= ctx.mem.len() {
                    ctx.mem[nwritten..nwritten + 4].copy_from_slice(&total.to_le_bytes());
                }
                Ok(Some(0))
            }
            Host::Unknown => Ok(Some(52)), // ENOSYS
        }
    }

    /// Execute a function body. Structured control flow is handled with a control stack of
    /// `(is_loop, stack_height_at_entry, start_pc, end_pc)`; `br`/`br_if`/`return` unwind it.
    fn run(&self, body: &[u8], locals: &mut [i64], stack: &mut Vec<i64>, depth: usize, ctx: &mut Ctx) -> Result<(), Error> {
        let mut ctrl: Vec<Ctrl> = Vec::new();
        let mut pc = 0usize;
        loop {
            ctx.steps += 1;
            if ctx.steps > MAX_STEPS {
                return Err(Error::Timeout);
            }
            if ctx.exit.is_some() {
                return Ok(()); // a nested `proc_exit` unwinds the whole call stack
            }
            let op = *body.get(pc).ok_or(Error::Invalid)?;
            pc += 1;
            match op {
                0x00 => return Err(Error::Io), // unreachable
                0x01 => {}                     // nop
                0x02 | 0x03 | 0x04 => {
                    // block / loop / if: read the blocktype, find the matching `end`.
                    let bt = *body.get(pc).ok_or(Error::Invalid)?;
                    pc += 1;
                    // A branch to a loop targets its params (none here); to a block/if, its
                    // results — one value for blocktype `i32` (0x7f), none for empty (0x40).
                    let is_loop = op == 0x03;
                    let br_arity = if !is_loop && matches!(bt, 0x7f | 0x7e | 0x7d | 0x7c) { 1 } else { 0 };
                    if op == 0x04 {
                        // if: pop the condition; on false, jump past `else`/to `end`.
                        let c = stack.pop().ok_or(Error::Invalid)?;
                        let (else_pc, end_pc) = match_if(body, pc)?;
                        ctrl.push(Ctrl { is_loop: false, height: stack.len(), br_arity, start: pc, end: end_pc });
                        if c == 0 {
                            pc = else_pc.map(|e| e + 1).unwrap_or(end_pc);
                        }
                    } else {
                        let end = match_end(body, pc)?;
                        ctrl.push(Ctrl { is_loop, height: stack.len(), br_arity, start: pc, end });
                    }
                }
                0x05 => {
                    // else: reached only by falling out of the taken `then` arm — skip to `end`.
                    let fr = ctrl.last().ok_or(Error::Invalid)?;
                    pc = fr.end;
                }
                0x0b => {
                    // end: leave the innermost block (or finish the function).
                    if ctrl.pop().is_none() {
                        return Ok(());
                    }
                }
                0x0c => {
                    let (l, n) = uleb_at(body, pc)?;
                    pc += n;
                    branch(stack, &mut ctrl, l as usize, &mut pc)?;
                }
                0x0d => {
                    let (l, n) = uleb_at(body, pc)?;
                    pc += n;
                    let c = stack.pop().ok_or(Error::Invalid)?;
                    if c != 0 {
                        branch(stack, &mut ctrl, l as usize, &mut pc)?;
                    }
                }
                0x0f => return Ok(()), // return
                0x10 => {
                    let (f, n) = uleb_at(body, pc)?;
                    pc += n;
                    let f = f as u32;
                    let n_imports = self.imports.len() as u32;
                    let type_idx = if f < n_imports {
                        self.imports[f as usize].1
                    } else {
                        self.funcs.get((f - n_imports) as usize).ok_or(Error::Invalid)?.type_idx
                    };
                    let (np, _) = *self.types.get(type_idx as usize).ok_or(Error::Invalid)?;
                    let at = stack.len().checked_sub(np as usize).ok_or(Error::Invalid)?;
                    let callee_args: Vec<i64> = stack.split_off(at);
                    if let Some(r) = self.call(f, &callee_args, depth + 1, ctx)? {
                        stack.push(r);
                    }
                    if ctx.exit.is_some() {
                        return Ok(());
                    }
                }
                0x1a => {
                    stack.pop().ok_or(Error::Invalid)?; // drop
                }
                0x1b => {
                    let c = stack.pop().ok_or(Error::Invalid)?;
                    let b = stack.pop().ok_or(Error::Invalid)?;
                    let a = stack.pop().ok_or(Error::Invalid)?;
                    stack.push(if c != 0 { a } else { b }); // select
                }
                0x20 => {
                    let (i, n) = uleb_at(body, pc)?;
                    pc += n;
                    stack.push(*locals.get(i as usize).ok_or(Error::Invalid)?);
                }
                0x21 => {
                    let (i, n) = uleb_at(body, pc)?;
                    pc += n;
                    let v = stack.pop().ok_or(Error::Invalid)?;
                    *locals.get_mut(i as usize).ok_or(Error::Invalid)? = v;
                }
                0x22 => {
                    let (i, n) = uleb_at(body, pc)?;
                    pc += n;
                    let v = *stack.last().ok_or(Error::Invalid)?;
                    *locals.get_mut(i as usize).ok_or(Error::Invalid)? = v;
                }
                0x23 => {
                    let (i, n) = uleb_at(body, pc)?;
                    pc += n;
                    stack.push(*ctx.globals.get(i as usize).ok_or(Error::Invalid)?); // global.get
                }
                0x24 => {
                    let (i, n) = uleb_at(body, pc)?;
                    pc += n;
                    let v = stack.pop().ok_or(Error::Invalid)?;
                    *ctx.globals.get_mut(i as usize).ok_or(Error::Invalid)? = v; // global.set
                }
                0x41 => {
                    let (v, n) = sleb(body, pc)?;
                    pc += n;
                    stack.push(v as i32 as i64); // i32.const (sign-extended into the 64-bit cell)
                }
                0x42 => {
                    let (v, n) = sleb(body, pc)?;
                    pc += n;
                    stack.push(v); // i64.const
                }
                0x45 => unary(stack, |a| (a == 0) as i32)?,
                0x46..=0x4f => cmp(stack, op)?,
                0x50 => {
                    let a = stack.pop().ok_or(Error::Invalid)?;
                    stack.push((a == 0) as i64); // i64.eqz
                }
                0x51..=0x5a => cmp64(stack, op)?,
                // Linear-memory loads: memarg = align(uleb) + offset(uleb); addr = base + offset.
                0x28 | 0x2c | 0x2d | 0x2e | 0x2f => {
                    pc += uleb_at(body, pc)?.1; // align (ignored)
                    let (off, n) = uleb_at(body, pc)?;
                    pc += n;
                    let base = stack.pop().ok_or(Error::Invalid)? as u32 as usize;
                    let a = base + off as usize;
                    let m = &ctx.mem;
                    let v = match op {
                        0x28 => i32::from_le_bytes([*m.get(a).ok_or(Error::Invalid)?, m[a + 1], m[a + 2], m[a + 3]]),
                        0x2c => (*m.get(a).ok_or(Error::Invalid)? as i8) as i32,
                        0x2d => *m.get(a).ok_or(Error::Invalid)? as i32,
                        0x2e => (i16::from_le_bytes([*m.get(a).ok_or(Error::Invalid)?, m[a + 1]])) as i32,
                        _ => u16::from_le_bytes([*m.get(a).ok_or(Error::Invalid)?, m[a + 1]]) as i32,
                    };
                    stack.push(v as i64);
                }
                // i64.load (0x29) and its narrowing variants (0x30..=0x35).
                0x29 | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 => {
                    pc += uleb_at(body, pc)?.1;
                    let (off, n) = uleb_at(body, pc)?;
                    pc += n;
                    let base = stack.pop().ok_or(Error::Invalid)? as u32 as usize;
                    let a = base + off as usize;
                    let m = &ctx.mem;
                    let g = |i: usize| m.get(i).copied().ok_or(Error::Invalid);
                    let v: i64 = match op {
                        0x29 => i64::from_le_bytes([g(a)?, g(a + 1)?, g(a + 2)?, g(a + 3)?, g(a + 4)?, g(a + 5)?, g(a + 6)?, g(a + 7)?]),
                        0x30 => (g(a)? as i8) as i64,
                        0x31 => g(a)? as i64,
                        0x32 => i16::from_le_bytes([g(a)?, g(a + 1)?]) as i64,
                        0x33 => u16::from_le_bytes([g(a)?, g(a + 1)?]) as i64,
                        0x34 => i32::from_le_bytes([g(a)?, g(a + 1)?, g(a + 2)?, g(a + 3)?]) as i64,
                        _ => u32::from_le_bytes([g(a)?, g(a + 1)?, g(a + 2)?, g(a + 3)?]) as i64,
                    };
                    stack.push(v);
                }
                // Linear-memory stores (i32: 0x36/0x3a/0x3b, i64: 0x37/0x3c/0x3d/0x3e).
                0x36 | 0x3a | 0x3b | 0x37 | 0x3c | 0x3d | 0x3e => {
                    pc += uleb_at(body, pc)?.1;
                    let (off, n) = uleb_at(body, pc)?;
                    pc += n;
                    let v = stack.pop().ok_or(Error::Invalid)?;
                    let base = stack.pop().ok_or(Error::Invalid)? as u32 as usize;
                    let a = base + off as usize;
                    let w = |mem: &mut Vec<u8>, at: usize, bytes: &[u8]| -> Result<(), Error> {
                        mem.get_mut(at..at + bytes.len()).ok_or(Error::Invalid)?.copy_from_slice(bytes);
                        Ok(())
                    };
                    match op {
                        0x36 => w(&mut ctx.mem, a, &(v as i32).to_le_bytes())?,
                        0x3a | 0x3c => *ctx.mem.get_mut(a).ok_or(Error::Invalid)? = v as u8,
                        0x3b | 0x3d => w(&mut ctx.mem, a, &(v as u16).to_le_bytes())?,
                        0x37 => w(&mut ctx.mem, a, &v.to_le_bytes())?,
                        _ => w(&mut ctx.mem, a, &(v as u32).to_le_bytes())?, // 0x3e i64.store32
                    }
                }
                0x3f => {
                    pc += 1; // memory index 0x00
                    stack.push((ctx.mem.len() / PAGE) as i64);
                }
                0x40 => {
                    pc += 1;
                    let grow = stack.pop().ok_or(Error::Invalid)? as u32 as usize;
                    let old = ctx.mem.len() / PAGE;
                    ctx.mem.resize((old + grow) * PAGE, 0);
                    stack.push(old as i64);
                }
                0x67..=0x69 => unary(stack, |a| match op {
                    0x67 => a.leading_zeros() as i32,
                    0x68 => a.trailing_zeros() as i32,
                    _ => a.count_ones() as i32,
                })?,
                0x6a..=0x78 => binop(stack, op)?,
                0x7c..=0x8a => binop64(stack, op)?,
                0xa7 => {
                    let v = stack.pop().ok_or(Error::Invalid)?;
                    stack.push((v as i32) as i64); // i32.wrap_i64
                }
                0xac => {
                    let v = stack.pop().ok_or(Error::Invalid)?;
                    stack.push((v as i32) as i64); // i64.extend_i32_s
                }
                0xad => {
                    let v = stack.pop().ok_or(Error::Invalid)?;
                    stack.push((v as u32) as i64); // i64.extend_i32_u
                }
                // Floating point. f32 lives in the low 32 bits of the cell, f64 in all 64.
                0x43 => {
                    let bits = u32::from_le_bytes([*body.get(pc).ok_or(Error::Invalid)?, body[pc + 1], body[pc + 2], body[pc + 3]]);
                    pc += 4;
                    stack.push(bits as i64); // f32.const
                }
                0x44 => {
                    let mut b8 = [0u8; 8];
                    b8.copy_from_slice(body.get(pc..pc + 8).ok_or(Error::Invalid)?);
                    pc += 8;
                    stack.push(i64::from_le_bytes(b8)); // f64.const
                }
                0x2a | 0x2b | 0x38 | 0x39 => {
                    // f32/f64 load (0x2a/0x2b) and store (0x38/0x39).
                    pc += uleb_at(body, pc)?.1;
                    let (off, n) = uleb_at(body, pc)?;
                    pc += n;
                    match op {
                        0x2a | 0x2b => {
                            let base = stack.pop().ok_or(Error::Invalid)? as u32 as usize;
                            let a = base + off as usize;
                            if op == 0x2a {
                                let m = ctx.mem.get(a..a + 4).ok_or(Error::Invalid)?;
                                stack.push(u32::from_le_bytes([m[0], m[1], m[2], m[3]]) as i64);
                            } else {
                                let m = ctx.mem.get(a..a + 8).ok_or(Error::Invalid)?;
                                let mut b8 = [0u8; 8];
                                b8.copy_from_slice(m);
                                stack.push(i64::from_le_bytes(b8));
                            }
                        }
                        _ => {
                            let v = stack.pop().ok_or(Error::Invalid)?;
                            let base = stack.pop().ok_or(Error::Invalid)? as u32 as usize;
                            let a = base + off as usize;
                            if op == 0x38 {
                                ctx.mem.get_mut(a..a + 4).ok_or(Error::Invalid)?.copy_from_slice(&(v as u32).to_le_bytes());
                            } else {
                                ctx.mem.get_mut(a..a + 8).ok_or(Error::Invalid)?.copy_from_slice(&v.to_le_bytes());
                            }
                        }
                    }
                }
                0x5b..=0x60 => fcmp32(stack, op)?,
                0x61..=0x66 => fcmp64(stack, op)?,
                0x8b | 0x8c | 0x92..=0x98 => fop32(stack, op)?,
                0x99 | 0x9a | 0xa0..=0xa6 => fop64(stack, op)?,
                // Conversions between the numeric types.
                0xa8 | 0xaa => unary_f32(stack, |x| x as i32)?,           // i32.trunc_f32_s/u
                0xa9 | 0xab => unary_f32(stack, |x| x as u32 as i32)?,
                0xae | 0xb0 => {
                    let x = f32::from_bits(stack.pop().ok_or(Error::Invalid)? as u32);
                    stack.push(x as i64); // i64.trunc_f32_s/u (saturating-ish)
                }
                0xb2 => {
                    let v = stack.pop().ok_or(Error::Invalid)? as i32;
                    stack.push(f32::to_bits(v as f32) as i64); // f32.convert_i32_s
                }
                0xb3 => {
                    let v = stack.pop().ok_or(Error::Invalid)? as u32;
                    stack.push(f32::to_bits(v as f32) as i64); // f32.convert_i32_u
                }
                0xb7 => {
                    let v = stack.pop().ok_or(Error::Invalid)? as i32;
                    stack.push(f64::to_bits(v as f64) as i64); // f64.convert_i32_s
                }
                0xb8 => {
                    let v = stack.pop().ok_or(Error::Invalid)? as u32;
                    stack.push(f64::to_bits(v as f64) as i64); // f64.convert_i32_u
                }
                0xb6 => {
                    let x = f64::from_bits(stack.pop().ok_or(Error::Invalid)? as u64);
                    stack.push(f32::to_bits(x as f32) as i64); // f32.demote_f64
                }
                0xbb => {
                    let x = f32::from_bits(stack.pop().ok_or(Error::Invalid)? as u32);
                    stack.push(f64::to_bits(x as f64) as i64); // f64.promote_f32
                }
                // Reinterpret casts are no-ops on the bit pattern in the cell.
                0xbc | 0xbd | 0xbe | 0xbf => {}
                _ => return Err(Error::Unsupported),
            }
        }
    }
}

// Value cells are 64-bit; `i32` ops read/write the low word (sign-extended back into the cell).
fn unary(stack: &mut Vec<i64>, f: impl Fn(i32) -> i32) -> Result<(), Error> {
    let a = stack.pop().ok_or(Error::Invalid)? as i32;
    stack.push(f(a) as i64);
    Ok(())
}

fn cmp(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    let b = stack.pop().ok_or(Error::Invalid)? as i32;
    let a = stack.pop().ok_or(Error::Invalid)? as i32;
    let r = match op {
        0x46 => a == b,
        0x47 => a != b,
        0x48 => a < b,
        0x49 => (a as u32) < (b as u32),
        0x4a => a > b,
        0x4b => (a as u32) > (b as u32),
        0x4c => a <= b,
        0x4d => (a as u32) <= (b as u32),
        0x4e => a >= b,
        0x4f => (a as u32) >= (b as u32),
        _ => return Err(Error::Unsupported),
    };
    stack.push(r as i64);
    Ok(())
}

fn cmp64(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    let b = stack.pop().ok_or(Error::Invalid)?;
    let a = stack.pop().ok_or(Error::Invalid)?;
    let r = match op {
        0x51 => a == b,
        0x52 => a != b,
        0x53 => a < b,
        0x54 => (a as u64) < (b as u64),
        0x55 => a > b,
        0x56 => (a as u64) > (b as u64),
        0x57 => a <= b,
        0x58 => (a as u64) <= (b as u64),
        0x59 => a >= b,
        0x5a => (a as u64) >= (b as u64),
        _ => return Err(Error::Unsupported),
    };
    stack.push(r as i64);
    Ok(())
}

fn binop(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    let b = stack.pop().ok_or(Error::Invalid)? as i32;
    let a = stack.pop().ok_or(Error::Invalid)? as i32;
    let r: i32 = match op {
        0x6a => a.wrapping_add(b),
        0x6b => a.wrapping_sub(b),
        0x6c => a.wrapping_mul(b),
        0x6d => a.checked_div(b).ok_or(Error::Invalid)?,
        0x6e => (a as u32).checked_div(b as u32).ok_or(Error::Invalid)? as i32,
        0x6f => a.checked_rem(b).ok_or(Error::Invalid)?,
        0x70 => (a as u32).checked_rem(b as u32).ok_or(Error::Invalid)? as i32,
        0x71 => a & b,
        0x72 => a | b,
        0x73 => a ^ b,
        0x74 => a.wrapping_shl(b as u32),
        0x75 => a.wrapping_shr(b as u32),
        0x76 => ((a as u32).wrapping_shr(b as u32)) as i32,
        0x77 => a.rotate_left(b as u32),
        0x78 => a.rotate_right(b as u32),
        _ => return Err(Error::Unsupported),
    };
    stack.push(r as i64);
    Ok(())
}

fn binop64(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    let b = stack.pop().ok_or(Error::Invalid)?;
    let a = stack.pop().ok_or(Error::Invalid)?;
    let r: i64 = match op {
        0x7c => a.wrapping_add(b),
        0x7d => a.wrapping_sub(b),
        0x7e => a.wrapping_mul(b),
        0x7f => a.checked_div(b).ok_or(Error::Invalid)?,
        0x80 => (a as u64).checked_div(b as u64).ok_or(Error::Invalid)? as i64,
        0x81 => a.checked_rem(b).ok_or(Error::Invalid)?,
        0x82 => (a as u64).checked_rem(b as u64).ok_or(Error::Invalid)? as i64,
        0x83 => a & b,
        0x84 => a | b,
        0x85 => a ^ b,
        0x86 => a.wrapping_shl(b as u32),
        0x87 => a.wrapping_shr(b as u32),
        0x88 => ((a as u64).wrapping_shr(b as u32)) as i64,
        0x89 => a.rotate_left(b as u32),
        0x8a => a.rotate_right(b as u32),
        _ => return Err(Error::Unsupported),
    };
    stack.push(r);
    Ok(())
}

fn pop_f32(stack: &mut Vec<i64>) -> Result<f32, Error> {
    Ok(f32::from_bits(stack.pop().ok_or(Error::Invalid)? as u32))
}
fn pop_f64(stack: &mut Vec<i64>) -> Result<f64, Error> {
    Ok(f64::from_bits(stack.pop().ok_or(Error::Invalid)? as u64))
}

fn unary_f32(stack: &mut Vec<i64>, f: impl Fn(f32) -> i32) -> Result<(), Error> {
    let x = pop_f32(stack)?;
    stack.push(f(x) as i64);
    Ok(())
}

fn fcmp32(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    let b = pop_f32(stack)?;
    let a = pop_f32(stack)?;
    let r = match op {
        0x5b => a == b,
        0x5c => a != b,
        0x5d => a < b,
        0x5e => a > b,
        0x5f => a <= b,
        _ => a >= b,
    };
    stack.push(r as i64);
    Ok(())
}

fn fcmp64(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    let b = pop_f64(stack)?;
    let a = pop_f64(stack)?;
    let r = match op {
        0x61 => a == b,
        0x62 => a != b,
        0x63 => a < b,
        0x64 => a > b,
        0x65 => a <= b,
        _ => a >= b,
    };
    stack.push(r as i64);
    Ok(())
}

// f32 abs/neg/copysign are bit operations; +,-,*,/ and min/max avoid libm (no sqrt/ceil/…).
fn fop32(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    if op == 0x8b || op == 0x8c {
        let a = pop_f32(stack)?;
        let r = if op == 0x8b { f32::from_bits(a.to_bits() & 0x7fff_ffff) } else { f32::from_bits(a.to_bits() ^ 0x8000_0000) };
        stack.push(f32::to_bits(r) as i64);
        return Ok(());
    }
    let b = pop_f32(stack)?;
    let a = pop_f32(stack)?;
    let r = match op {
        0x92 => a + b,
        0x93 => a - b,
        0x94 => a * b,
        0x95 => a / b,
        0x96 => if a < b { a } else { b },
        0x97 => if a > b { a } else { b },
        0x98 => f32::from_bits((a.to_bits() & 0x7fff_ffff) | (b.to_bits() & 0x8000_0000)),
        _ => return Err(Error::Unsupported),
    };
    stack.push(f32::to_bits(r) as i64);
    Ok(())
}

fn fop64(stack: &mut Vec<i64>, op: u8) -> Result<(), Error> {
    if op == 0x99 || op == 0x9a {
        let a = pop_f64(stack)?;
        let r = if op == 0x99 {
            f64::from_bits(a.to_bits() & 0x7fff_ffff_ffff_ffff)
        } else {
            f64::from_bits(a.to_bits() ^ 0x8000_0000_0000_0000)
        };
        stack.push(f64::to_bits(r) as i64);
        return Ok(());
    }
    let b = pop_f64(stack)?;
    let a = pop_f64(stack)?;
    let r = match op {
        0xa0 => a + b,
        0xa1 => a - b,
        0xa2 => a * b,
        0xa3 => a / b,
        0xa4 => if a < b { a } else { b },
        0xa5 => if a > b { a } else { b },
        0xa6 => f64::from_bits((a.to_bits() & 0x7fff_ffff_ffff_ffff) | (b.to_bits() & 0x8000_0000_0000_0000)),
        _ => return Err(Error::Unsupported),
    };
    stack.push(f64::to_bits(r) as i64);
    Ok(())
}

/// A control frame on the structured-control stack.
struct Ctrl {
    is_loop: bool,
    /// Value-stack height when the block was entered.
    height: usize,
    /// Values kept on a branch to this label (loop: its params = 0 here; block/if: its results).
    br_arity: usize,
    /// First instruction inside the block (a `loop` branches here).
    start: usize,
    /// Index of the matching `end` byte (a `block`/`if` branches just past here).
    end: usize,
}

/// Branch out of (break) or back into (loop continue) the `l`-th enclosing control frame.
fn branch(stack: &mut Vec<i64>, ctrl: &mut Vec<Ctrl>, l: usize, pc: &mut usize) -> Result<(), Error> {
    let target = ctrl.len().checked_sub(1 + l).ok_or(Error::Invalid)?;
    let (is_loop, height, arity, start, end) = {
        let f = &ctrl[target];
        (f.is_loop, f.height, f.br_arity, f.start, f.end)
    };
    // Keep the top `arity` values; discard everything the block pushed below them.
    let keep_from = stack.len().checked_sub(arity).ok_or(Error::Invalid)?;
    let kept: Vec<i64> = stack.split_off(keep_from);
    stack.truncate(height);
    stack.extend_from_slice(&kept);
    if is_loop {
        ctrl.truncate(target + 1); // keep the loop frame; re-enter it
        *pc = start;
    } else {
        ctrl.truncate(target); // exit this block and everything inside it
        *pc = end + 1;
    }
    Ok(())
}

/// Advance past one full instruction (opcode + immediates) at `pc`.
fn skip(body: &[u8], pc: usize) -> Result<usize, Error> {
    let op = *body.get(pc).ok_or(Error::Invalid)?;
    let mut p = pc + 1;
    match op {
        0x02 | 0x03 | 0x04 => p += 1,                       // blocktype
        0x0c | 0x0d | 0x10 | 0x20 | 0x21 | 0x22 | 0x23 | 0x24 => p += uleb_at(body, p)?.1, // one uleb
        0x41 | 0x42 => p += sleb(body, p)?.1,               // i32.const / i64.const
        0x43 => p += 4,                                     // f32.const
        0x44 => p += 8,                                     // f64.const
        0x28..=0x3e => {
            // load/store memarg: align uleb + offset uleb
            p += uleb_at(body, p)?.1;
            p += uleb_at(body, p)?.1;
        }
        0x3f | 0x40 => p += 1, // memory.size / memory.grow: memory index byte
        _ => {}
    }
    Ok(p)
}

/// Index of the `end` that matches the block whose body starts at `start`.
fn match_end(body: &[u8], start: usize) -> Result<usize, Error> {
    let mut depth = 0usize;
    let mut pc = start;
    loop {
        let op = *body.get(pc).ok_or(Error::Invalid)?;
        if matches!(op, 0x02 | 0x03 | 0x04) {
            depth += 1;
        } else if op == 0x0b {
            if depth == 0 {
                return Ok(pc);
            }
            depth -= 1;
        }
        pc = skip(body, pc)?;
    }
}

/// `(else, end)` positions for an `if` whose body starts at `start` (else is `None` if absent).
fn match_if(body: &[u8], start: usize) -> Result<(Option<usize>, usize), Error> {
    let mut depth = 0usize;
    let mut pc = start;
    let mut els = None;
    loop {
        let op = *body.get(pc).ok_or(Error::Invalid)?;
        if matches!(op, 0x02 | 0x03 | 0x04) {
            depth += 1;
        } else if op == 0x05 && depth == 0 && els.is_none() {
            els = Some(pc);
        } else if op == 0x0b {
            if depth == 0 {
                return Ok((els, pc));
            }
            depth -= 1;
        }
        pc = skip(body, pc)?;
    }
}
