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

use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;

const MAX_CALL_DEPTH: usize = 256;
const MAX_STEPS: u64 = 50_000_000;

/// A parsed module: function signatures (`i32` counts only), function bodies, and exports.
pub struct Module {
    /// `(param_count, result_count)` per type.
    types: Vec<(u32, u32)>,
    funcs: Vec<Func>,
    exports: Vec<(String, u32)>,
}

struct Func {
    type_idx: u32,
    n_locals: u32,
    body: Vec<u8>,
}

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
        while r.p < bin.len() {
            let id = r.byte()?;
            let len = r.u32()? as usize;
            let end = r.p + len;
            match id {
                1 => {
                    // Type section: each entry is `0x60 params results` (i32 only).
                    let n = r.u32()?;
                    for _ in 0..n {
                        if r.byte()? != 0x60 {
                            return Err(Error::Unsupported);
                        }
                        let np = r.u32()?;
                        for _ in 0..np {
                            if r.byte()? != 0x7f {
                                return Err(Error::Unsupported); // i32 only
                            }
                        }
                        let nr = r.u32()?;
                        for _ in 0..nr {
                            if r.byte()? != 0x7f {
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
                10 => {
                    let n = r.u32()?;
                    for _ in 0..n {
                        let sz = r.u32()? as usize;
                        codes.push(Vec::from(r.bytes(sz)?));
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
                if lr.byte()? != 0x7f {
                    return Err(Error::Unsupported);
                }
                n_locals += cnt;
            }
            let body = Vec::from(&code[lr.p..]);
            funcs.push(Func { type_idx: ti, n_locals, body });
        }
        Ok(Module { types, funcs, exports })
    }

    /// Invoke an exported function by name with `i32` arguments; returns its single `i32` result
    /// (or `None` if it returns nothing).
    pub fn invoke(&self, name: &str, args: &[i32]) -> Result<Option<i32>, Error> {
        let idx = self.exports.iter().find(|(n, _)| n == name).map(|(_, i)| *i).ok_or(Error::NotFound)?;
        let mut steps = 0u64;
        self.call(idx, args, 0, &mut steps)
    }

    fn call(&self, fidx: u32, args: &[i32], depth: usize, steps: &mut u64) -> Result<Option<i32>, Error> {
        if depth >= MAX_CALL_DEPTH {
            return Err(Error::NoResources);
        }
        let f = self.funcs.get(fidx as usize).ok_or(Error::Invalid)?;
        let (nparams, nresults) = *self.types.get(f.type_idx as usize).ok_or(Error::Invalid)?;
        if args.len() != nparams as usize {
            return Err(Error::Invalid);
        }
        let mut locals = Vec::with_capacity(nparams as usize + f.n_locals as usize);
        locals.extend_from_slice(args);
        for _ in 0..f.n_locals {
            locals.push(0);
        }
        let mut stack: Vec<i32> = Vec::new();
        self.run(&f.body, &mut locals, &mut stack, depth, steps)?;
        if nresults == 0 { Ok(None) } else { Ok(stack.pop()) }
    }

    /// Execute a function body. Structured control flow is handled with a control stack of
    /// `(is_loop, stack_height_at_entry, start_pc, end_pc)`; `br`/`br_if`/`return` unwind it.
    fn run(&self, body: &[u8], locals: &mut [i32], stack: &mut Vec<i32>, depth: usize, steps: &mut u64) -> Result<(), Error> {
        let mut ctrl: Vec<Ctrl> = Vec::new();
        let mut pc = 0usize;
        loop {
            *steps += 1;
            if *steps > MAX_STEPS {
                return Err(Error::Timeout);
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
                    let br_arity = if !is_loop && bt == 0x7f { 1 } else { 0 };
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
                    let (np, _) = *self.types.get(self.funcs.get(f as usize).ok_or(Error::Invalid)?.type_idx as usize).ok_or(Error::Invalid)?;
                    let at = stack.len().checked_sub(np as usize).ok_or(Error::Invalid)?;
                    let callee_args: Vec<i32> = stack.split_off(at);
                    if let Some(r) = self.call(f as u32, &callee_args, depth + 1, steps)? {
                        stack.push(r);
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
                0x41 => {
                    let (v, n) = sleb(body, pc)?;
                    pc += n;
                    stack.push(v as i32);
                }
                0x45 => unary(stack, |a| (a == 0) as i32)?,
                0x46..=0x4f => cmp(stack, op)?,
                0x67..=0x69 => unary(stack, |a| match op {
                    0x67 => a.leading_zeros() as i32,
                    0x68 => a.trailing_zeros() as i32,
                    _ => a.count_ones() as i32,
                })?,
                0x6a..=0x78 => binop(stack, op)?,
                _ => return Err(Error::Unsupported),
            }
        }
    }
}

fn unary(stack: &mut Vec<i32>, f: impl Fn(i32) -> i32) -> Result<(), Error> {
    let a = stack.pop().ok_or(Error::Invalid)?;
    stack.push(f(a));
    Ok(())
}

fn cmp(stack: &mut Vec<i32>, op: u8) -> Result<(), Error> {
    let b = stack.pop().ok_or(Error::Invalid)?;
    let a = stack.pop().ok_or(Error::Invalid)?;
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
    stack.push(r as i32);
    Ok(())
}

fn binop(stack: &mut Vec<i32>, op: u8) -> Result<(), Error> {
    let b = stack.pop().ok_or(Error::Invalid)?;
    let a = stack.pop().ok_or(Error::Invalid)?;
    let r = match op {
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
    stack.push(r);
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
fn branch(stack: &mut Vec<i32>, ctrl: &mut Vec<Ctrl>, l: usize, pc: &mut usize) -> Result<(), Error> {
    let target = ctrl.len().checked_sub(1 + l).ok_or(Error::Invalid)?;
    let (is_loop, height, arity, start, end) = {
        let f = &ctrl[target];
        (f.is_loop, f.height, f.br_arity, f.start, f.end)
    };
    // Keep the top `arity` values; discard everything the block pushed below them.
    let keep_from = stack.len().checked_sub(arity).ok_or(Error::Invalid)?;
    let kept: Vec<i32> = stack.split_off(keep_from);
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
        0x0c | 0x0d | 0x10 | 0x20 | 0x21 | 0x22 => p += uleb_at(body, p)?.1, // one uleb
        0x41 => p += sleb(body, p)?.1,                      // i32.const
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
