# Copy-on-Write Filesystem Bug Classes, Mapped to Bismuth's Flash FS

> Status: research and design proposal, not yet implemented. A companion to
> [filesystems.md](filesystems.md) (which designs the subsystem) focused narrowly on the
> *failure modes* of copy-on-write (CoW) and log-structured flash filesystems and how to
> design them out of Bismuth's flash FS before the directory/file layer is written.
> Scope: the historically data-destroying bug classes of btrfs, ZFS/OpenZFS, littlefs, LFS
> and flash FTLs; whether each applies to Bismuth's actual design; a concrete safe-Rust,
> no-heap, statically-sized mitigation for each; and the `SimFlash` power-cut test that
> would catch a regression.
>
> Current Bismuth baseline (read from the tree, not guessed):
> * `src/fs/flash/meta.rs` — the **implemented** `MetaPair<BS>`: a two-block ping-pong CoW
>   metadata journal (`format` / `mount` / `read` / `commit`), layout
>   `rev:u32 · len:u16 · pad:u16 · payload · crc32`, committed by a trailing CRC-32/IEEE.
>   A torn erase or torn program leaves the target block failing its CRC, so `mount` keeps
>   the prior block — atomic all-or-nothing. **Two latent hazards already in the code:**
>   `commit` advances the revision with `self.rev.wrapping_add(1)` and `mount` selects the
>   newer block with a plain `r1 > r0`, i.e. **no sequence arithmetic** (the wraparound/ABA
>   hazard of §5), and there is no compaction, split, relocation or global-move state yet.
> * `src/fs/flash/mod.rs` — Bismuth-native, littlefs-*architecture* flash FS (explicitly
>   **not** upstream littlefs-v2 byte-compatible). The dir/file model, allocator and mount
>   scan are **not built**; this document shapes them.
> * `src/fs/vnode.rs` — the `FileSystem` trait and the value type `FsVnode(pub u32)`,
>   documented as "stable for the life of the mount". In a CoW FS a node's physical
>   location moves on every write, so making `FsVnode` stable under relocation is the
>   single most design-shaping decision here (§7).
> * `src/fs/mod.rs` — the VFS does **mount-level** generation revocation (`gens[MAX_MOUNTS]`,
>   checked in `snapshot`) and owns file position; it does **not** revoke a single node
>   rewritten or unlinked under an open handle (§7).
> * `src/driver/block/sim.rs` — `SimFlash::power_cut_after(n)` tears the *n*-th following
>   mutating op (applies ~half, then `Err(Io)`) and enforces program-once (programming a
>   non-`0xFF` byte is `Err(Io)`). Every mitigation below is tested against it.
> * `src/driver/block/cache.rs` — `BlockCache` must be **write-through** under a power-safe
>   FS, or a committed CRC is only a promise in volatile RAM.

---

## 0. TL;DR

CoW is the right foundation — it makes the common failure (a torn write) a non-event by
construction, which is exactly what `MetaPair` already delivers. But CoW relocates data on
every write, and almost every historically data-destroying CoW/LFS bug is a second-order
consequence of that relocation: stale references, mis-ordered commits, a corrupted
free-space picture, an interrupted multi-pair operation, or an "optimization" that broke an
invariant. The good news for Bismuth is that several whole btrfs/ZFS bug families are
**structurally absent** from the design, and the rest are cheap to design in now and
expensive to retrofit.

**MUST-HAVE before first release (design these into the dir/file layer from line one):**

1. **Stable, logical `FsVnode` + a pinned resident-pair table with relocation fixup (§7).**
   The most design-shaping finding. `FsVnode` must be a mount-stable *logical* identity
   `(dir-pair-id, entry-id)`, never a physical block pointer, or every open handle goes
   stale the moment any write relocates its home metadata pair. Because the VFS holds a
   plain `u32` snapshot the FS cannot reach in to patch, the FS translates logical ids
   through its own small fixed table, and relocation updates *that table*, not the handles.
2. **Data-before-metadata commit ordering (§1).** A file's new CoW data chain must be fully
   durable before its new head pointer is committed into the directory pair. `MetaPair`
   already makes the metadata flip atomic; the file-data write hole is the half not yet
   covered.
3. **Sequence-arithmetic revision comparison (§5)** — a one-line fix to the *already-shipped*
   `MetaPair::mount`, which today compares revisions with `>`. Do it before anything else
   is built on top of the pair, because it is a silent, delayed-detonation bug.
4. **Mount-time full tree scan as the sole allocator truth, no on-disk free list (§2, §3).**
   This is already the plan; the obligations are that the scan be *total* (every reference
   source visited) and that allocation exclude in-flight, not-yet-committed blocks.
5. **Bounded, iterative tree walks with a fixed worklist and a cycle cap (§9).** No
   recursion anywhere in mount scan / used-set rebuild / orphan scan; a corrupt on-disk
   cycle must terminate in `Error::Integrity`, never a stack overflow or a hang.
6. **Reserved metadata blocks for ENOSPC (§11).** A CoW volume that is 100% full must still
   be able to `unlink`/`truncate`; that path itself needs to allocate. Reserve a fixed pool.
7. **Write-through/uncached enforcement + `sync` flushes the device (§10).** Refuse a
   power-safe mount on a write-back `BlockCache`; `sync()` must reach stable storage.
8. **Orphan self-cleaning commit order + a bounded deorphan scan (§3).**

**Nice-to-have / stage-two:**

* **Cross-directory atomic `rename` via a bounded single-slot global-move record (§4).** Or
  ship same-directory rename (a single atomic pair commit) first and document cross-dir as
  a follow-up — the same call the FS design doc already makes.
* **Stronger-than-CRC integrity (§6)** — *not* a flash-FS concern. CRC-32 is torn-write and
  random-corruption detection, never tamper resistance; authenticity belongs to the
  trusted-platform per-block AEAD wrapper, not here.

**N/A to Bismuth by design (a whole btrfs/ZFS corpus that does not apply):**

* **The RAID-5/6 write hole (§1).** Single-device, no parity stripes. Does not exist.
* **On-disk reference-count / extent-backref corruption — double-free and double-allocation
  (§2).** Bismuth keeps **no persistent free list or refcount tree** to corrupt; the
  used-set is rebuilt by scan at mount. The class is designed away; only an in-RAM scan bug
  remains, which program-once catches.
* **Snapshot / clone / reflink / dedup / block-cloning corruption (§12).** v1 has none of
  these. This is the single largest family of real btrfs/ZFS data-loss bugs (incl. the
  OpenZFS 2.2.0 incident) and it is simply not in the product.
* **Generational segment-cleaner bugs (LFS).** No separate cleaner; compaction is per-pair
  and wear-relocation is the only mover.

The throughline: **keep v1 boring.** Every optimization CoW filesystems add — dedup,
clones, speculative caching, a persistent free-space tree — is a documented source of
silent corruption. Add them only behind the differential + power-cut harness (§12).

---

## 1. Torn writes, incomplete commits, and the write hole

**Real world.** The classic parity-RAID *write hole*: a stripe's data and parity blocks are
updated non-atomically, so a crash mid-update leaves parity inconsistent with data and a
later degraded-mode rebuild reconstructs garbage. ZFS avoids it by writing whole stripes
copy-on-write; btrfs RAID5/6 has historically remained exposed, and the CoW-stripe fix is
still a proposed patch set, not shipped ([bcachefs-ec], [lwn-btrfs-raid5]). The
filesystem-internal analogue is any multi-block structure updated in place: a crash between
writing the data and writing the pointer that commits it loses or corrupts the record.

**Applies to Bismuth?** The RAID write hole itself: **no** — single device, no parity. The
*metadata* torn-write case: **already solved** by `MetaPair` (the commit is valid only once
its CRC lands; the prior block survives a torn erase or program — this is exactly what
`tests/flashfs.rs::metapair_survives_torn_{erase,program}` prove). The **unsolved** case is
**file data**: a CoW data chain (the CTZ skip-list in the FS design) is several blocks, and
the directory entry's head pointer is what commits them. If the head is committed before the
data blocks are durable, a crash leaves the committed pointer aimed at half-written data.

**Mitigation — data-before-metadata ordering.** Write (and make durable) the entire new
data chain first; commit the new head into the directory `MetaPair` **last**. The pair
commit is the single atomic point.

```rust
// Append/overwrite a file region. Order is the correctness property, not an optimization.
fn write_region(&self, f: &mut FileState, off: u32, data: &[u8]) -> Result<(), Error> {
    // 1. Allocate fresh blocks and program the new CoW data chain. Nothing here is
    //    referenced by any committed pair yet, so a torn write only strands blocks
    //    (reclaimed at next mount, §3) — it can never corrupt live data.
    let new_head = self.write_cow_chain(f, off, data)?;
    // 2. Ensure the data is on the medium before the pointer that commits it.
    self.dev_sync()?;                       // no-op on synchronous NOR; real on buffered ctrls (§10)
    // 3. Atomically swing the directory entry to the new head. MetaPair makes this
    //    all-or-nothing: a crash here keeps the OLD head and the old data.
    self.commit_entry(f.home_pair, f.entry_id, new_head, f.size_after)?;
    Ok(())
}
```

The invariant: **a committed pointer never references a block whose program has not
returned `Ok` (and been synced).** On synchronous NOR this is just call order; on a
controller with a write buffer, step 2 is a real device flush (§10).

**SimFlash test.** Tear the write at two points and assert old content survives both:

```rust
// (a) tear a data-chain program: old file must be fully intact, no partial new data.
dev.power_cut_after(k);                      // k lands inside write_cow_chain's prog calls
assert!(fs.write(h, off, NEW).is_err());
remount(); assert_eq!(read_all(reopen()), OLD);
// (b) tear the entry commit: MetaPair guarantees old head survives (already covered by
//     metapair_survives_torn_program; repeat at the file layer end-to-end).
```

---

## 2. Reference-counting bugs: double-free and double-allocation

**Real world.** Filesystems that track free space with on-disk reference counts corrupt
them and then either free a block that is still referenced (**double-free** → the block is
handed out and overwrites live data) or hand out a block that is still in use
(**double-allocation**). btrfs's extent tree carries explicit backrefs, and in-the-wild
reports show extent items with a backref count of zero and "bad cross ref" allocations of
still-used extents — the kernel now has tree-checker patches that *reject* a zero-count
inline extent and replace a `BUG_ON` with an error in `insert_inline_extent_backref`
([btrfs-tc-zero-ref], [btrfs-badref]). A single flipped bit in a refcount is enough.

**Applies to Bismuth?** **No — by construction.** Following littlefs, Bismuth keeps **no
on-disk free list and no refcount tree** ([lfs-design]): deallocation is a no-op, and the
filesystem tree *is* the authoritative record of which blocks are live. The used-set is
rebuilt by a full tree scan at mount into a fixed **lookahead bitmap** window. There is
simply no persistent counter to corrupt, so the entire class is designed away. (This also
means `fsck` and the allocator are the same walk.)

**Where it can still go wrong — the residual.** The scan and the in-RAM bitmap can still
be wrong:

* **Scan incompleteness (→ double-allocation).** If the tree walk misses a reference source
  — forgets that a metadata pair occupies *both* of its blocks, skips a CTZ chain, or does
  not follow the directory thread — it marks a live block free and re-hands it out.
* **In-flight self-collision (→ double-allocation).** A CoW write allocates new blocks
  *before* the commit that references them exists. If the allocator may return a block the
  current, uncommitted transaction already wrote, it overwrites its own new data.

**Mitigation.** (1) The scan must enumerate **every** reference source; encode that as a
closed checklist the walk asserts it covered (both blocks of every pair; every CTZ data
chain from every file entry; the directory thread; the superblock/global-state blocks; the
reserved pool of §11). (2) The allocator's free-set is `scanned_used ∪ in_flight`, where
`in_flight` is the set of blocks the open transaction has written but not yet committed:

```rust
fn alloc_block(&self, tx: &Txn) -> Result<u32, Error> {
    loop {
        if let Some(b) = self.lookahead.next_free() {
            if !tx.in_flight.contains(b) { return Ok(b); }   // never reuse our own uncommitted block
            continue;
        }
        self.refill_lookahead(tx)?;      // rescan tree from the advancing cursor, re-OR in_flight
        if self.lookahead.is_empty() { return Err(Error::NoSpace); }  // → §11 reserve
    }
}
```

The simulator is a free oracle here: `SimFlash` **rejects any program of a non-`0xFF`
byte**, so a double-allocation that tries to write a still-live block fails loudly as
`Err(Io)` in a test instead of silently clobbering data in the field.

**SimFlash test.** After a randomized sequence of create/write/unlink/truncate ops,
rebuild the used-set a second time and assert it equals the allocator's live bitmap
(differential self-check); separately assert that no sequence ever triggers a program-once
`Err(Io)` (which would mean a double-alloc).

---

## 3. Orphans and space leaks after a crash

**Real world.** A directory change touches several metadata pairs and cannot be committed
atomically, so a crash can leave a metadata pair that **no directory references** — an
**orphan** — or a half-written structure. littlefs documents exactly this: adding a
directory creates an orphan when the new pair is threaded into the linked list but not yet
added to its parent; removing a directory creates one when the parent entry is gone but the
pair is still in the list; a *half-orphan* arises during bad-block eviction when the tree
references the replacement block but the thread still holds the evicted one. Finding them is
expensive — littlefs calls it an "*O(n²)* comparison of every metadata pair with every
directory entry" and runs it only on the first allocation after boot ([lfs-design]).

**Applies to Bismuth?** Yes, but Bismuth's no-free-list design makes most of it
*self-healing*: a block that nothing references is, by definition, **absent from the
rebuilt used-set**, and is therefore implicitly reclaimed at the next mount. A torn data
write (§1) strands blocks that are reachable from nothing → reclaimed. **The reasoning holds
only if the orphaned structure is reachable from nothing.** It breaks precisely when the
orphan is still reachable through the *directory thread* the scan uses to find pairs: then
the scan counts its blocks as used and it leaks (and worse, a stale parent/child pointer
could be followed).

**Mitigation — commit order that makes add/remove self-cleaning, plus a bounded deorphan
scan.** Order the two commits of a directory add/remove so that an interruption leaves the
new/old pair reachable from *neither* the parent nor the thread (so the scan never sees it
and it is reclaimed), rather than from the thread but not the parent (a leak):

```text
mkdir:  1. allocate + program the child pair (reachable from nothing yet)
        2. commit parent entry  -> child (now reachable via parent)
        3. commit thread splice (now in the scan's traversal)
   crash after 1: child reachable from nothing  -> reclaimed at mount  (clean)
   crash after 2: reachable via parent, missing from thread -> deorphan scan splices it in
rmdir:  reverse order; crash leaves at worst a thread entry with no parent -> deorphan removes
```

The residual (half-orphans from bad-block relocation, and the `crash after 2` case) needs a
**bounded, iterative deorphan pass** — but Bismuth can avoid littlefs's *O(n²)* by using the
already-built used-set: a pair in the thread whose parent back-pointer resolves to no live
entry is an orphan. Run it once after mount (or lazily before the first allocation), with a
fixed worklist (§9), never recursively.

**SimFlash test.** `power_cut_after(k)` sweeping `k` across every mutating op of `mkdir` and
`rmdir`; after each, remount and assert: (a) the directory is either fully present or fully
absent (never half), (b) `statvfs` free-block count returns to the pre-op value (no leak),
and (c) a second mount is idempotent (deorphan converged).

---

## 4. Interrupted move / rename across two metadata pairs

**Real world.** A cross-directory rename removes an entry from one pair and adds it to
another — two commits, not atomic. A crash between them loses the file (removed from source,
never added to dest) or duplicates it. littlefs solves this with **global state (gstate)**:
deltas XORed across metadata pairs, reconstructed at mount ("*the actual global state can be
built out of these deltas by xoring together all of the deltas in the filesystem*"; "*we
only need to iterate over our metadata pairs and build the global state when the filesystem
is mounted*"). A move is two commits: the first adds the destination entry **and** records a
"move in progress" in gstate; the second removes the source entry **and** clears the move
state atomically ("*we can clear this move state atomically with the removal of the old
file*"). If mount finds a recorded move, "*we know we lost power during a move and the file
is duplicated*", and the gstate says which copy to drop ([lfs-design]). An earlier littlefs
approach used a per-entry "dirty" tag and was noted as costly ([lfs-move-commit]).

**Applies to Bismuth?** Only to **cross-directory** rename. The VFS already restricts
`rename` to a single mount (`src/fs/mod.rs::rename` returns `Error::Unsupported` across
mounts/generations), and a **same-directory** rename is a single pair commit — atomic for
free, no gstate needed. Cross-dir is the subtle case the FS design doc already flagged as
highest-risk ([filesystems.md] §6.3).

**Mitigation — a minimal bounded single-slot global-move record.** Bismuth does not need
littlefs's fully general XOR-delta gstate for v1. One fixed-size record in the superblock /
global-state block suffices, because there is at most one rename in flight (single-writer
per mount, [filesystems.md] §11):

```rust
#[derive(Copy, Clone, Default)]
struct PendingMove {          // the entire cross-dir-rename recovery state; fixed size
    active: bool,
    src_pair: PairId,         // logical (§7), relocation-stable
    src_entry: u16,
}
// move:  commit#1 = add dest entry + set PendingMove{active, src};
//        commit#2 = remove src entry + clear PendingMove   (atomic within the src pair's commit)
// mount: if PendingMove.active -> the dest copy exists AND the src copy may exist;
//        remove the src copy (roll forward), clear the record. Exactly one copy survives.
```

If even that is deferred, **ship same-directory rename first and document cross-directory
rename as unsupported** (returns `Error::Unsupported`), matching the FS design doc's stated
fallback. Do **not** implement cross-dir rename as "remove-then-add" or "add-then-remove"
without the record — that is precisely the lose-or-duplicate bug.

**SimFlash test.** For a cross-dir move, `power_cut_after(k)` for every `k` between the two
commits; remount and assert the file appears in **exactly one** directory with the correct
name and identical content, and that `statvfs` shows no leak. Add an idempotent-remount
check (the recovery itself must be crash-safe).

---

## 5. Revision-counter wraparound / ABA on the metadata pair

**Real world.** A ping-pong log picks the newer block by its revision count. If that compare
is a plain `>` on a wrapping counter, then after the counter wraps (or when the two blocks
straddle the wrap — e.g. `0xFFFF_FFFF` vs `0x0000_0000`) the comparison selects the **older**
block, silently reverting the filesystem to a stale state — a textbook ABA. littlefs
explicitly compares revisions "*using sequence arithmetic (very handy for avoiding problems
with integer overflow)*" ([lfs-design]).

**Applies to Bismuth?** **Yes — this bug is in the shipped `MetaPair` today.**
`commit` sets `next_rev = self.rev.wrapping_add(1)` (correct — it wraps), but `mount`
selects with `(Some((r0,_)),Some((r1,_))) if r1 > r0` (`src/fs/flash/meta.rs:99`). A plain
`>` over a counter that wraps is wrong at the wrap boundary. It is a *latent, delayed* bug:
invisible for the first ~4 billion commits, then silent data reversion. The FS design doc
even *claims* sequence arithmetic ([filesystems.md] §6.1) — the implementation diverges from
its own spec. Fix it before the dir/file layer is built on top.

**Mitigation — sequence arithmetic (one-line fix).** "Newer" is `b` iff
`b.wrapping_sub(a)` lands in the lower half of the modular range, i.e. interpret the
difference as signed:

```rust
/// True if revision `b` is strictly newer than `a` under wraparound (sequence arithmetic).
#[inline]
fn newer(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) > 0
}
// in mount(), replace `r1 > r0` with `newer(r0, r1)`:
(Some((r0, _)), Some((r1, _))) if newer(r0, r1) => /* pick b1 */,
```

This is valid as long as the two live blocks' revisions never differ by ≥ 2³¹ — trivially
true, since the pair's two revisions differ by exactly 1.

**How to test without 4 billion commits.** Two cheap tests:

1. **Pure comparator unit test** — `newer()` is a free function, so assert the wrap cases
   directly: `newer(0xFFFF_FFFE, 0xFFFF_FFFF)`, `newer(0xFFFF_FFFF, 0x0000_0000)`,
   `!newer(0x0000_0000, 0xFFFF_FFFF)`, and the equal/adjacent cases.
2. **On-disk straddle test** — format a pair, then craft the two blocks' revision fields to
   straddle the wrap (write them via the block device at the known header offset, or add a
   `#[cfg(test)]` constructor that seeds `rev`), remount, and assert the block with the
   logically-newer revision is selected. `SimFlash::peek` and a direct `prog` make the
   on-disk poke straightforward.

---

## 6. Checksum false-accept: what CRC-32 does and does not buy

**Real world.** A CRC detects *accidental* corruption — torn writes, random bit flips, burst
errors — with strong guarantees (CRC-32/IEEE detects all 1–2 bit errors, all odd numbers of
bit errors, and all bursts up to 32 bits). It is **not** a cryptographic hash and **not** a
MAC: it is linear, so an attacker can trivially forge a payload with a matching CRC, and even
accidentally a ~2⁻³² residual false-accept remains for arbitrary corruption. Filesystems that
rely on CRCs catch the crashes they were designed for and nothing more.

**Applies to Bismuth?** `MetaPair` uses CRC-32/IEEE to decide a commit is valid. That is the
**correct** tool for its job — distinguishing a fully-landed commit from a torn one — and the
design should keep it. The honest statement for the docs:

* **CRC-32 buys:** torn-write detection (the commit atomicity primitive) and detection of
  random media corruption / bit-rot with ~2⁻³² escape probability. This is sufficient for
  power-loss safety, which is the FS's job.
* **CRC-32 does NOT buy:** tamper resistance, authenticity, or anti-rollback. An adversary
  with write access to the chip can rewrite a block and its CRC undetectably.

**Where a stronger primitive belongs — not here.** Authenticity and confidentiality are the
**trusted-platform per-block AEAD wrapper's** job, a separate L2 block-device layer
(`L2 devices · block: AEAD wrapper`), where the FS runs *oblivious to encryption* over
ciphertext and "*littlefs's CRCs are torn-write detection, not tamper resistance*"
([trusted-platform.md] §6, which states per-block AEAD is the *only* integrity layer and
anti-rollback is documented future work). **Do not** add a crypto hash to the flash-FS layer:
it would duplicate the AEAD layer, buy nothing against torn writes that CRC-32 does not
already, and (if it pulled in an `unsafe` crypto crate) violate the safe-Rust rule. If pure
accidental bit-rot on large volumes ever becomes a concern, the drop-in is CRC-32C
(Castagnoli, better Hamming distance at large lengths) — still safe, table-free — not a
cryptographic hash.

**SimFlash test.** Keep the existing `crc32_matches_known_vector`. Add a *negative* test:
flip one payload byte on disk (`prog` is program-once, so corrupt a fresh block) and assert
`mount`/`read` returns `Error::Integrity` rather than silently accepting. Document explicitly
(a comment and the limitations list) that CRC is **not** a security control.

---

## 7. Use-after-relocate, stale vnodes, and stale open handles

**This is the single most design-shaping section.** In a CoW FS a node's *physical* location
changes on essentially every write: the directory metadata pair ping-pongs between its two
blocks on each commit, compacts into a sibling when full, and relocates to brand-new blocks
for wear-leveling or bad-block eviction. A file's CTZ head pointer changes on every data
write. Any identity that is a *physical* address is stale almost immediately.

**Real world.** littlefs keeps every open file/dir on an in-RAM linked list (`lfs->mlist`)
and, whenever a metadata pair relocates, walks that list and rewrites the `.pair` pointer in
every open handle. That works because the handles are live, mutable C structs the filesystem
owns.

**The Bismuth tension.** `FsVnode` is a `u32` **value** that the VFS snapshots into its
open-file table (`OpenFile { node: FsVnode, ... }` in `src/fs/mod.rs`) and hands back on
`stat`, `lookup`, `create`, etc. The filesystem **cannot reach in and patch it** — it is a
copy the VFS owns, and a relocation can be triggered by a write to a *completely different*
file. So Bismuth cannot use littlefs's handle-fixup trick directly. And the VFS's existing
generation revocation is **per-mount** (`gens[MAX_MOUNTS]`, bumped on mount/unmount, checked
in `snapshot`) — it does **not** fire when a single node is rewritten, relocated or unlinked
under an open handle. If `FsVnode` were a physical block pointer, every open handle would be
a use-after-relocate waiting to happen.

**Mitigation — logical `FsVnode` + a pinned resident-pair table; relocation patches the
table, not the handles.**

1. **`FsVnode` is a logical identity, never a physical address.** Pack it as
   `(pair_slot, entry_id)`:

   ```rust
   // FsVnode(u32) = pair_slot:u20 | entry_id:u12   (tunable split; both are mount-local).
   //  - A DIRECTORY is identified by its metadata pair (entry_id = SELF sentinel).
   //  - A FILE is identified by (its home directory's pair, its entry id within that pair).
   //  - The ROOT is the reserved constant FsVnode(0) -> the superblock/root pair at a fixed home.
   const ENTRY_SELF: u16 = 0xFFF;          // "this is the pair itself" (a directory)
   fn vnode(pair_slot: u32, entry: u16) -> FsVnode { FsVnode(pair_slot << 12 | entry as u32) }
   ```

2. **A small fixed-size resident-pair table resolves `pair_slot` → current physical
   blocks.** This is the only place a physical address lives, and it is *mutable*:

   ```rust
   struct ResidentPair {
       in_use: bool,
       logical: PairId,       // mount-stable logical id (monotonic, stored in the pair header)
       b0: u32, b1: u32,      // CURRENT physical blocks (change on compaction/relocation)
       cur_is_b1: bool,
       pin: u16,              // refcount of open handles / cached dir references
   }
   // bounded by a config knob, NOT by filesystem size:
   pairs: [ResidentPair; LFS_RESIDENT_PAIRS],   // e.g. mcu_or_host(8, 32)
   ```

3. **Relocation updates the table row, so every outstanding `FsVnode` stays valid.** When a
   pair compacts or relocates, the FS rewrites `b0/b1/cur_is_b1` on its resident row (and the
   parent's on-disk pointer). No `FsVnode` value changes; no VFS state is touched. The cost
   is O(`LFS_RESIDENT_PAIRS`), bounded and heap-free — this is littlefs's `mlist` fixup, but
   applied to a fixed table the FS owns instead of to handles it doesn't.

4. **Pin while referenced; re-resolve otherwise.** A row is pinned while any open file/dir
   references it. Because the VFS re-resolves most namespace ops by `(dir, name)` and only
   `read`/`write`/`truncate` ride an `OpenId` (the FS's own pinned open-file state), the table
   only needs rows for *currently referenced* pairs — RAM scales with open handles, not with
   volume size, preserving littlefs's "RAM independent of FS size" promise. A `FsVnode`
   returned by `lookup` and used once (e.g. in `stat`) resolves immediately; its pair is made
   resident for that call.

**Stale open handle across unlink / rewrite — snapshot-on-open semantics.** Because there is
**no in-flight free list** (§2), a block is only reclaimed at the *next mount's* scan, never
mid-session. This gives a clean, safe semantics for free:

* **Unlink while open:** the directory entry is removed, but the open handle keeps its own
  resolved CTZ head + size, and the data blocks remain un-reclaimed for the session. The
  handle reads the old file until close — POSIX-ish "unlink-on-last-reference", and **safe**
  (no use-after-free) because nothing frees those blocks underneath it.
* **Rewrite by another handle:** handle A holds the head it resolved at open; handle B
  commits a new head. A continues to read its snapshot. This is *snapshot-on-open*, not
  read-your-writes-across-handles — acceptable and, again, safe because B's CoW write
  allocated new blocks and did not touch A's. Document it; do not pretend it is Linux
  page-cache coherency.

**Decision for the lead:** adopt the logical `(pair_slot, entry_id)` `FsVnode`, the pinned
resident-pair table, and snapshot-on-open semantics. This shapes the open-file pool, the
relocation path, and `lookup`/`stat` from line one.

**SimFlash test.**

```rust
// use-after-relocate: hold a handle across a relocation triggered by OTHER activity.
let a = open("/d/a", RDWR);
write_all(a, b"A-original");
// churn file b in the same directory until d's pair compacts/relocates:
for _ in 0..MANY { write(open("/d/b", RDWR|TRUNC), big_blob); }
assert_eq!(read_all(a), b"A-original");    // FsVnode(a) still valid; no stale physical ptr
// stale-handle-across-unlink:
let h = open("/d/c", READ);
unlink("/d/c");
assert_eq!(read_all(h), original_c);       // snapshot survives until close
```

---

## 8. Lookahead-bitmap staleness, allocation-cursor bugs, and wear vs power-safety

**Real world.** A log-structured allocator with a windowed free bitmap (littlefs's
lookahead) and an advancing cursor can mis-track free space if the window is not refreshed
when it empties, if the cursor wraps incorrectly, or if a block is reused before its freeing
is durable. Wear-leveling *moves* live data to spread erases; if a wear relocation frees the
old copy before the new one is committed, a crash in between loses the data — the
optimization breaks the CoW invariant.

**Applies to Bismuth?** Yes — the lookahead allocator and dynamic wear-leveling are both in
the FS design. The bitmap is a RAM window rebuilt by the §2 scan; the hazards are (a)
staleness and (b) the wear/power-safety interaction.

**Mitigation.**

* **Deterministic cursor, rescan on empty.** The cursor advances monotonically; when the
  lookahead window empties, rescan the tree from the cursor for the next window (§2's
  `refill_lookahead`). Randomizing the *mount* start offset from on-disk CRCs gives
  statistical wear spread ([lfs-design]) without a persistent wear map.
* **Never reuse a block whose free is not yet durable.** The free-set excludes in-flight
  blocks (§2); crucially, during a wear relocation the **old copy stays valid and
  allocated until the new commit's CRC lands** — the plain CoW property. Only after the
  parent pointer is swung to the new location (committed) does the old block become
  unreferenced, and even then it is reclaimed at the next scan, not eagerly.

```rust
fn relocate_for_wear(&self, p: &mut ResidentPair) -> Result<(), Error> {
    let (n0, n1) = self.alloc_pair()?;      // new home; old (p.b0,p.b1) still live & referenced
    self.copy_pair_contents(p, n0, n1)?;    // program new blocks (CoW)
    self.dev_sync()?;
    self.commit_parent_pointer(p.logical, n0, n1)?;  // atomic swing; crash before -> old survives
    p.b0 = n0; p.b1 = n1;                    // §7 table fixup; old blocks now unreferenced
    Ok(())
}
```

**SimFlash test.** Use the `WearCounter` wrapper to confirm erases spread (peak vs mean) over
a long write workload; and `power_cut_after(k)` across `relocate_for_wear` asserting the old
copy is still mountable and the content intact for every `k` before the parent commit.

---

## 9. Unbounded recursion / stack overflow walking the tree; cycle detection

**Real world.** A naive recursive directory/tree walk overflows a small MCU stack on a deep
tree, and a *corrupted* on-disk structure with a cyclic pointer (a pair whose tail or child
points back into the path) turns any walk into an infinite loop. On a no-heap kernel with
tiny stacks (`IDLE_STACK_SIZE = 512`, pooled stacks 2 KiB) this is a crash, not a nuisance.

**Applies to Bismuth?** Yes — the mount scan, used-set rebuild (§2), deorphan pass (§3) and
any `fsck` all walk the whole tree. The VFS path resolver is already iterative and bounded
(`src/fs/mod.rs` resolves components in a `for` loop, no recursion); the FS internals must
hold the same line.

**Mitigation — explicit fixed worklist + hard iteration cap.** No recursion anywhere. Use a
statically-sized worklist (the `kernel::mem::Pool` / fixed-array idiom) and bound total
iterations by a value known statically to exceed any valid tree — the device block count —
so a corrupt cycle terminates in `Error::Integrity` instead of a hang or overflow:

```rust
fn scan_used_set(&self) -> Result<Bitmap, Error> {
    let mut work: Worklist<LFS_WALK_STACK> = Worklist::new();   // fixed array, no heap
    work.push(self.root_pair())?;
    let mut visited = 0u32;
    let cap = self.geom.block_count * 2;     // static upper bound on any acyclic traversal
    while let Some(pair) = work.pop() {
        visited += 1;
        if visited > cap { return Err(Error::Integrity); }       // corrupt cycle -> bounded failure
        self.mark_pair_and_data(pair, &mut used)?;
        for child in self.children_of(pair)? {
            work.push(child).map_err(|_| Error::Integrity)?;     // worklist overflow = too deep/corrupt
        }
    }
    Ok(used)
}
```

Both failure modes — a cycle (iteration cap) and an over-deep/over-wide tree (worklist
overflow) — map to `Error::Integrity`, never UB. `LFS_WALK_STACK` is a config knob sized to
the deepest supported tree; exceeding it is a documented limit, not a crash.

**SimFlash test.** Poke a cyclic tail pointer onto a formatted volume (write a pair's tail
field to point at an ancestor via `prog`), then `mount` and assert `Err(Error::Integrity)`
within bounded time — the test itself proves termination. Also a deep-tree test at
`LFS_WALK_STACK + 1` asserting a clean `Error::Integrity` rather than a panic.

---

## 10. Durability and ordering: sync must reach the medium, no write-back cache

**Real world.** Crash-consistency studies repeatedly find that application and FS correctness
hinges on *ordering* and on `fsync` actually reaching stable storage. Pillai et al.'s ALICE
study found 60 crash vulnerabilities across 11 mature applications, many from assuming
ordering or durability the filesystem did not guarantee ([alice-osdi14]); CrashMonkey's
bounded black-box testing later found 10 new crash-consistency bugs in mature Linux
filesystems and even a data-loss bug in the *verified* FSCQ ([crashmonkey-osdi18]). A
"committed" record that is still only in a volatile write-back cache is not committed at all.

**Applies to Bismuth?** Directly. Two rules:

* **No write-back cache under a power-safe FS.** `BlockCache` already documents that it must
  be **write-through** under littlefs, "*because a write-back layer between a power-safe FS
  and the medium would turn a committed CRC into a promise still only in volatile RAM*"
  (`src/driver/block/cache.rs`). This must be **enforced at mount**, not just documented: a
  power-safe mount on a `BlockCache` with `write_through == false` should refuse
  (`Error::Invalid`) or there is no power-safety at all.
* **`sync` reaches the medium, and data precedes metadata.** `FileSystem::sync` →
  `BlockDevice::sync`; `MetaPair`'s atomicity assumes the target program is durable before
  `cur_is_b1` flips, which holds for synchronous NOR (`SimFlash` programs synchronously) and,
  on a buffered controller, requires the `dev_sync()` between data and metadata in §1.

**Mitigation.** Add a mount-time geometry/cache check and make `sync` honest:

```rust
fn mount_power_safe(dev: &dyn BlockDevice, ...) -> Result<Self, Error> {
    // A power-safe FS requires synchronous durability. Refuse a write-back cache.
    if dev.is_write_back_cache() { return Err(Error::Invalid); }   // see FsInfo.power_safe
    // ...
}
fn sync(&self) -> Result<(), Error> {
    self.flush_dirty_pairs()?;     // commit any open transaction
    self.dev.sync()                // reach stable storage
}
```

`FsInfo.power_safe` already exists in the trait (`src/fs/vnode.rs`); wire it so a power-safe
mount cannot be built on a buffering layer that would void it.

**SimFlash test.** Construct the FS over `BlockCache::new(dev, /*write_through=*/false)` and
assert the power-safe mount **refuses**. Separately, a structure/convention test can assert
the mount path rejects a non-write-through cache. (The torn-write tests of §1 already cover
the ordering property end-to-end.)

---

## 11. ENOSPC-during-CoW deadlock

**Real world.** The signature CoW pain: because you cannot overwrite in place, *every* change
— including a **delete** — must first allocate (to write the new, smaller metadata). On a
100%-full volume there is nothing to allocate, so the filesystem wedges: you cannot free
space because freeing needs space. ZFS has hit this for years — a full pool returns `ENOSPC`
on `unlink`, and the documented remedy is a reserved "slop" dataset you drop in an emergency;
an illumos developer's analysis attributes it directly to CoW needing new metadata blocks
even for deletes and proposes a reserved pool that only permits space-freeing operations
([zfs-enospc-bug], [zfs-enospc-nd]). btrfs's ENOSPC handling is likewise notorious.

**Applies to Bismuth?** Yes — Bismuth is pure CoW; `unlink`/`truncate`/`rmdir` all commit new
(smaller) directory pairs, which allocate. Without a reserve, a full edge device could become
permanently un-deletable in the field — a terrible failure mode for an unattended IoT node.

**Mitigation — a fixed reserved block pool for metadata commits.** Reserve a small,
statically-sized set of blocks that the **data** allocator never sees and that only the
commit/free path may draw from. The reserve must be large enough to commit every metadata
pair along the path from a leaf to the root in the worst case (a split can touch the chain up
to the root), bounded by max tree depth × 2 blocks per pair plus the single-slot move record
(§4):

```rust
pub const LFS_RESERVE_BLOCKS: usize =
    parse_or(option_env!("BISMUTH_LFS_RESERVE"), 6);   // >= 2 * max_pair_commit_depth + move slot

fn alloc_data(&self, tx: &Txn)  -> Result<u32, Error> { self.alloc_from(tx, Pool::Data) }      // excludes reserve
fn alloc_meta(&self, tx: &Txn)  -> Result<u32, Error> {                                        // may dip into reserve
    self.alloc_from(tx, Pool::Data).or_else(|_| self.alloc_from(tx, Pool::Reserve))
}
// -> unlink/truncate call alloc_meta, so a delete ALWAYS has room even when data space is 0.
```

Document the reserve in `statvfs` accounting (free-to-user excludes the reserve) so "disk
full" happens a few blocks early, deliberately, leaving headroom to recover.

**SimFlash test.** Fill the volume with `write` until `Error::NoSpace`, then `unlink` a file
and assert it **succeeds** (drawing from the reserve); remount and assert the freed space is
reclaimed and the reserve is whole again. A companion test asserts `statvfs` free never
counts the reserve.

---

## 12. "Optimization-induced" corruption — the cautionary tale

**Real world.** The clearest recent lesson that **CoW optimizations are where corruption
hides**: OpenZFS 2.2.0 (November 2023) shipped **block cloning** (fast reflink-style copies)
and, within weeks, users hit **silent data corruption** — files read back as runs of zeros.
The root cause analyzed by OpenZFS developer Rob Norris was an **incorrect "dirty dnode"
check**: a race in the dirty-tracking logic (not block cloning per se, though cloning and a
newer `cp` made it far easier to trigger) let reads see holes where data existed. The
response was to **disable block cloning** in 2.2.1 and ship fixes in 2.2.2 / 2.1.14, with
developers noting a second suspected cloning bug still unfound ([openzfs-dirty-dnodes],
[openzfs-l1t]). The feature that caused the pain was a performance optimization layered onto
the CoW core.

This rhymes with the whole btrfs/ZFS corruption corpus: extent-backref refcount bugs (§2),
RAID5/6 write-hole (§1), snapshot/clone edge cases. Verification and testing each miss
things the other catches — CrashMonkey found a data-loss bug in the *verified* FSCQ
([crashmonkey-osdi18]); Yggdrasil showed push-button crash-refinement verification is
possible but only for a from-scratch design ([yggdrasil-osdi16]).

**Applies to Bismuth?** The *optimizations* do not exist in v1 — no dedup, no clones, no
reflinks, no snapshots, no speculative/write-back caching under the FS (§10) — so the largest
real-world CoW corruption family is **N/A by omission**. The *lesson* very much applies.

**Mitigation — keep v1 boring, and gate every future optimization behind the harness.**

* **v1 scope discipline:** the only movers are per-pair compaction/split and
  wear/bad-block relocation (§8). No feature that creates *sharing* of blocks between logical
  objects (the precondition for most of these bugs) ships in v1.
* **Earn optimizations with tests, not arguments.** Any later optimization (inline-file
  promotion thresholds, a persistent allocation hint, block sharing, caching) lands only
  behind: (a) the `SimFlash` `power_cut_after` sweep (every mutating op torn, remount,
  assert consistency + no leak + idempotent recovery), and (b) a **differential oracle** —
  run the same op sequence against the simple reference implementation and assert identical
  observable state. This is the discipline the FS design doc already proposes for the riskiest
  features ([filesystems.md] §6.3–6.4) and the lesson OpenZFS 2.2.0 paid for.

**SimFlash test.** The harness *is* the test: a property test that, for a randomized op
sequence, tears the write at every mutating op and asserts the remounted FS is always a
valid prefix of the committed history, never leaks, and converges on a second remount. Any
optimization that cannot pass this does not ship.

---

## 13. Design requirements for the dir/file layer (implementation checklist)

A concrete checklist to implement against. Each maps to a section above and to a `SimFlash`
test.

1. **Stable logical `FsVnode = (pair_slot, entry_id)` (§7).** Never a physical block
   address. Root = `FsVnode(0)`. Directory = pair with `ENTRY_SELF`; file = (home pair,
   entry id). Resolve through a fixed `ResidentPair` table; **relocation updates the table,
   not handles**. Pin resident rows while referenced.
2. **Snapshot-on-open semantics (§7).** Open handles hold their resolved head/size; unlink
   and cross-handle rewrite are safe because blocks are only reclaimed at the next mount
   scan. Document; do not claim page-cache coherency.
3. **Data-before-metadata commit order (§1).** Program + sync the full CoW data chain, then
   commit the new head into the directory pair as the single atomic point.
4. **Fix `MetaPair` revision selection to sequence arithmetic (§5).** Replace `r1 > r0` in
   `mount` with `newer(a,b) = (b.wrapping_sub(a) as i32) > 0`. Do this first.
5. **No on-disk free list; mount-time full tree scan is the only allocator truth (§2, §3).**
   The scan is *total* (both pair blocks, every CTZ chain, the directory thread,
   superblock/global state, reserve). Free-set = `scanned_used ∪ in_flight`.
6. **Orphan self-cleaning commit order + bounded deorphan pass (§3).** Order add/remove so an
   interruption leaves structures reachable from nothing (→ reclaimed) rather than from the
   thread only (→ leak). Deorphan uses the built used-set, not littlefs's *O(n²)*.
7. **Bounded, iterative tree walks only (§9).** Fixed `Worklist<LFS_WALK_STACK>`, hard
   iteration cap = `block_count`, no recursion. Cycle / over-depth → `Error::Integrity`.
8. **Reserved metadata blocks for ENOSPC (§11).** `LFS_RESERVE_BLOCKS`; `alloc_meta` may dip
   into the reserve, `alloc_data` may not; `statvfs` excludes it.
9. **Cross-dir rename via a bounded single-slot `PendingMove`, or same-dir-first + documented
   (§4).** Never remove-then-add without recovery state.
10. **Write-through/uncached enforcement + honest `sync` (§10).** Refuse a power-safe mount on
    a write-back `BlockCache`; `sync()` flushes the device.
11. **Wear relocation keeps the old copy valid until the new commit lands (§8).**
12. **CRC-32 is torn-write/corruption detection only (§6).** No crypto at the FS layer;
    authenticity is the AEAD block wrapper's job.

**New config knobs (follow the `config.rs` `parse_or` / `mcu_or_host` idiom):**

```rust
pub const LFS_RESIDENT_PAIRS: usize = parse_or(option_env!("BISMUTH_LFS_RESIDENT_PAIRS"), mcu_or_host(8, 32));
pub const LFS_WALK_STACK:     usize = parse_or(option_env!("BISMUTH_LFS_WALK_STACK"),     mcu_or_host(16, 64));
pub const LFS_RESERVE_BLOCKS: usize = parse_or(option_env!("BISMUTH_LFS_RESERVE"),        6);
// (plus LFS_CACHE / LFS_LOOKAHEAD / LFS_MAX_OPEN / LFS_BLOCK_CYCLES from filesystems.md §6.2)
```

Classification for the new modules stays `L3 services · fs: <role> · safe · fs`, matching
`meta.rs`.

---

## 14. Open questions, residual risks, and documented-limitation candidates

**Open questions / decisions for the lead**

* **Resident-pair table sizing vs "RAM independent of FS size."** The §7 table scales with
  *open handles*, not volume size, which preserves the promise — but a workload that holds
  more distinct directory pairs resident than `LFS_RESIDENT_PAIRS` must either evict
  (re-resolve on next use) or fail. Confirm eviction-of-unpinned-rows is acceptable, and that
  the knob's default covers the deepest expected open-path set.
* **Deorphan timing.** Run the bounded deorphan pass eagerly at mount (simpler, pay once) or
  lazily before the first allocation (littlefs's choice, faster mount)? Recommendation: eager
  at mount for an edge device, because mounts are rare and predictability beats mount latency.
* **Cross-dir rename in v1 or v2.** The single-slot `PendingMove` (§4) is small and bounded;
  is it worth v1, or ship same-dir-only and document? Recommendation: implement the record —
  it is ~one struct and closes a real data-loss gap — but behind the differential oracle.
* **`MetaPair` sequence-arithmetic fix is a behavior change to shipped code.** It needs its
  own PR + comparator unit tests before the dir/file layer builds on it (§5).

**Residual risks**

* **A scan bug mis-marks a live block free (§2).** Mitigated by program-once catching the
  resulting double-alloc in tests, and by the differential self-check — but the scan's
  completeness is a correctness-critical invariant that must be asserted, not assumed.
* **Real-controller write buffering (§1, §10).** On a flash controller that buffers programs,
  the data-before-metadata guarantee depends on `dev_sync` actually flushing; `SimFlash` is
  synchronous and cannot exercise this. A buffered sim variant (a `power_cut` that also
  drops a pending buffer) would close the gap.
* **CRC-32 residual false-accept (§6).** ~2⁻³² for arbitrary corruption; acceptable for
  power-safety, insufficient for tamper. Not the FS's problem to solve, but state it.

**Documented-limitation candidates** (the project ships documented limitations, not silent
gaps):

* Snapshot-on-open semantics, not cross-handle read-your-writes coherency (§7).
* Cross-directory rename either unsupported in v1 or recovered by rolling the move *forward*
  (the destination copy wins) — pick one and document it (§4).
* Single-writer per mount (inherited from [filesystems.md] §11); the §4 single-slot move
  record relies on it.
* `LFS_WALK_STACK` bounds the deepest traversable tree; a tree deeper than the bound returns
  `Error::Integrity` rather than being supported (§9).
* `LFS_RESIDENT_PAIRS` bounds how many directory pairs may be referenced at once (§7).
* CRC-32 is **not** a security control; integrity/authenticity is the trusted-platform AEAD
  layer, and anti-rollback is future work ([trusted-platform.md] §6) (§6).
* No dedup/clones/reflinks/snapshots in v1 — which is *why* the largest CoW corruption family
  does not apply (§12).

---

## References

**littlefs**
- [lfs-design]: littlefs DESIGN.md — metadata pairs, CTZ skip-lists, the free-list-free
  allocator and lookahead bitmap, revision compare "using sequence arithmetic", orphans /
  half-orphans and the *O(n²)* deorphan check, global-state (gstate) deltas XORed and rebuilt
  at mount, and the atomic global move.
  https://github.com/littlefs-project/littlefs/blob/master/DESIGN.md
- [lfs-spec]: littlefs SPEC.md — on-disk byte layout, tags, commits.
  https://github.com/littlefs-project/littlefs/blob/master/SPEC.md
- [lfs-move-commit]: littlefs commit "Added atomic move using dirty tag in entry type" (the
  earlier, costlier move approach superseded by gstate).
  https://github.com/littlefs-project/littlefs/commit/2936514b5e0e4df519fc853127bb0adde4065249

**btrfs / ZFS / OpenZFS corruption and ENOSPC**
- [openzfs-dirty-dnodes]: Rob Norris, "Dirty deals: the story of a data corruption bug in
  OpenZFS" (AsiaBSDCon 2024) — the 2.2.0 block-cloning / dirty-dnode silent corruption and
  its fix. https://papers.freebsd.org/2024/asiabsdcon/norris_openzfs-dirty-dnodes/
- [openzfs-l1t]: "OpenZFS 2.2.0 Silent Data Corruption Bug" (Level1Techs forum) — timeline,
  the 2.2.1 disable of block cloning, 2.2.2 / 2.1.14 fixes.
  https://forum.level1techs.com/t/openzfs-2-2-0-silent-data-corruption-bug/203797
- [btrfs-tc-zero-ref]: Linux btrfs tree-checker "reject inline extent items with 0 ref count"
  — an on-disk extent backref with a zero refcount (a single bit flip suffices).
  https://patchwork.kernel.org/patch/9809101/
- [btrfs-badref]: btrfs "kill the BUG_ON() in insert_inline_extent_backref()" — allocating an
  extent still in use because of extent-tree cross-ref corruption.
  https://lists.snapcraft.io/archives/kernel-team/2020-October/114409.html
- [zfs-enospc-bug]: FreeBSD bug 154930, "[zfs] cannot delete/unlink file from full volume ->
  ENOSPC" — the CoW-delete-needs-space deadlock and reserved-pool remedy.
  https://bugs.freebsd.org/154930
- [zfs-enospc-nd]: netdata, "ZFS no space left on device" — CoW vs the slop reserve.
  https://www.netdata.cloud/guides/zfs/zfs-no-space-left-on-device/

**RAID write hole**
- [bcachefs-ec]: bcachefs "Erasure coding" — how ZFS avoids the write hole by writing whole
  CoW stripes (competitor source; treat the btrfs claims with care).
  https://bcachefs.org/ErasureCoding/
- [lwn-btrfs-raid5]: LWN, btrfs RAID5/6 CoW-stripe write-hole fix (a proposed patch set, not
  shipped). https://lwn.net/Articles/1078678/

**Crash-consistency studies / verification**
- [alice-osdi14]: Pillai, Chidambaram, Alagappan, Al-Kiswany, Arpaci-Dusseau²,
  "All File Systems Are Not Created Equal: On the Complexity of Crafting Crash-Consistent
  Applications", OSDI 2014 (ALICE / BOB; 60 vulnerabilities across 11 applications).
  https://www.usenix.org/conference/osdi14/technical-sessions/presentation/pillai
- [crashmonkey-osdi18]: Mohan, Martinez, Ponnapalli, Raju, Chidambaram, "Finding
  Crash-Consistency Bugs with Bounded Black-Box Crash Testing", OSDI 2018 (CrashMonkey / Ace;
  10 new bugs in mature FSes, a data-loss bug in verified FSCQ).
  https://www.usenix.org/conference/osdi18/presentation/mohan
- [yggdrasil-osdi16]: Sigurbjarnarson, Bornholt, Torlak, Wang, "Push-Button Verification of
  File Systems via Crash Refinement", OSDI 2016 (Yggdrasil / Yxv6; best paper).
  https://www.usenix.org/conference/osdi16/technical-sessions/presentation/sigurbjarnarson

**Log-structured filesystems**
- [lfs-ro92]: Rosenblum & Ousterhout, "The Design and Implementation of a Log-Structured File
  System", ACM TOCS 10(1), Feb 1992 — the log, segments, and the segment cleaner (the origin
  of cleaner-policy bugs). https://www.scs.stanford.edu/nyu/02fa/sched/lfs.pdf

**Bismuth internals cited**
- `src/fs/flash/meta.rs` (the implemented `MetaPair`; the `wrapping_add` / `r1 > r0` hazard),
  `src/fs/flash/mod.rs`, `src/fs/vnode.rs` (`FileSystem`, `FsVnode`), `src/fs/mod.rs` (VFS,
  mount-level generation revocation), `src/driver/block/sim.rs` (`SimFlash::power_cut_after`,
  program-once), `src/driver/block/mod.rs` (`BlockDevice`), `src/driver/block/cache.rs`
  (write-through rule), `src/kernel/mem.rs` (`Pool`), `src/config.rs` (static sizing),
  `tests/flashfs.rs` (the power-cut test idiom), `tests/structure.rs` (safe-Rust /
  classification rules), [filesystems.md](filesystems.md) (the subsystem design),
  [trusted-platform.md](trusted-platform.md) §6 (per-block AEAD integrity layer).
