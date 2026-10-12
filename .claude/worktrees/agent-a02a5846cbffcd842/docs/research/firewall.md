# Bismuth Packet Filtering: netfilter / pf Research and a Compat-Layer Design

> Status: research and design proposal, not yet implemented.
> Scope: how the real packet filters work (Linux **netfilter/iptables** and **nftables**, BSD **pf**, **eBPF/XDP** for context, and **conntrack** stateful filtering), what of it maps onto an MCU, and an opinionated design for Bismuth: a compact *static rule engine* built **on top of the existing `PacketHook` chain** (`src/net/hook.rs`), an optional fixed-size connection tracker, and three optional *compat front-ends* (iptables-, nftables- and pf-style) that all lower to the **same** hook objects. Targets: Cortex-M / RISC-V MCUs, tens to hundreds of KB of RAM, MPU no MMU, static allocation, `#![deny(unsafe_code)]`.
>
> Current Bismuth baseline (read from the tree): the data plane already has a pfil/XDP-style hook chain. `PacketHook::on_packet(dir, ifindex, pkt) -> Verdict{Pass(pkt)|Drop|Consumed}` (`src/net/hook.rs`), run global → per-interface → driver by `hook::run_chain` inside the single `net` task (`src/net/mod.rs`). Built-in hooks: `Counter`, `Firewall<const N>` (a deny-list of `Match`), `RateLimit`, `Steer` (to a `NetRing`). `Match` is `EtherType(u16) | UdpDstPort(u16) | TcpDstPort(u16)` and parses frames with `csum::{ethertype,l4_dst_port}`. Attachment is trusted-only (`net::attach_hook`/`add_global_hook` call `security::current_is_trusted()`), drops bump `IfStats.hook_drops`. The net design (`docs/research/networking.md` §4.6) explicitly chose **pfil-style compiled hooks over the Linux nftables bytecode VM**; this document respects that and builds the filter *as hooks*.

---

## 0. TL;DR

- **Do not build a second filtering subsystem.** The `PacketHook` chain *is* the enforcement engine. Everything here is either (a) one more built-in hook or (b) a build-time front-end that emits those hooks. This mirrors how Bismuth already has **one driver core with many compat front-ends** (POSIX `/dev`, FreeRTOS, embedded-hal/embedded-io): **one enforcement engine, many rule front-ends.**
- **`RuleSet<const N>`: a compact, first-match-wins rule engine as a `PacketHook`.** An array of `N` fixed-size rules `{ m: MatchExpr, action: Action }` plus a `default` policy, exactly like a pf/iptables chain. `MatchExpr` is a `Copy` struct of *optional* criteria that **extends the existing `Match`** with IPv4 src/dst prefix, L4 protocol, source/dest **port ranges**, interface, direction and an optional connection-state mask. No heap, no VM, ~24 B/rule. Feature-gated (`net-filter`).
- **Parse the 5-tuple once.** Add `csum::inet_tuple(frame) -> Option<InetTuple>` (src/dst IPv4, proto, sport, dport) next to the existing `ethertype`/`l4_dst_port`; the `RuleSet` builds the key once and evaluates all rules against it, the way `Firewall` already borrows `pkt.data()` and returns `Pass`/`Drop` without copying.
- **Optional stateful filtering: `ConnTrack<const C>`.** A fixed-size table (NEW / ESTABLISHED, plus an *invalid* catch-all) that stamps a 1-byte mark into `PacketMeta` so a later `RuleSet` can write `state established accept`. Build-time sized, LRU/timeout eviction, **honest RAM cost** (~24–28 B/entry: C=32 ≈ 0.9 KB, C=64 ≈ 1.8 KB). Leave it out on the smallest parts; a stateless ingress allow-list is enough for most sensors.
- **Three optional compat front-ends, each a `const` builder (feature-gated):**
  - `net-filter-iptables`: `Chain::INPUT.append(Rule::new().proto(Udp).dport(5683).jump(Accept))`, chain `policy(Drop)`; plus an optional tiny parser for a *restricted* `iptables -A` / `iptables-save` subset.
  - `net-filter-nft`: nftables **named sets** (sorted const arrays, binary search) and **verdict maps** (`key → Action`).
  - `net-filter-pf`: `pass`/`block [quick] in/out proto … from … to … port … [keep state]`.
  - All three produce `RuleSet<N>` / `MatchExpr` / `Action` values. Be explicit about what each **cannot** express on an MCU.
- **Rights and domains gate every change.** Reuse the existing trusted-only `attach_hook`/`detach_hook`/`add_global_hook`; the natural MCU shape is **`&'static` const rulesets attached at boot and never mutated**. Runtime edits go through a `MANAGE`-gated control op and are refused after `security::seal()` in hardened builds.
- **LOG / counters reuse what exists.** `Counter` hook, `IfStats.hook_drops`, per-rule `AtomicU32` hit counters inside the `RuleSet`, and a `Steer`-to-`NetRing` **pcap tap** that a logger task drains to UART/USB/flash.
- **What NOT to build:** no nftables bytecode VM, no eBPF/XDP JIT or verifier, no NAT/MASQUERADE (unless the device is explicitly a gateway, §6), no ALG/RELATED helpers, no arbitrary chain-jump graph (flatten at build), no runtime rule-transaction engine, no reassembly. These are the Linux features that cost the most code and RAM for the least MCU benefit.

---

## 1. The real systems, and what maps to an MCU

### 1.1 Linux netfilter / iptables

netfilter places **five hooks** on the IPv4/IPv6 forwarding path ([netfilter architecture][nf-arch]): `PREROUTING` (just after RX), `INPUT` (destined to the host), `FORWARD` (routed through), `OUTPUT` (locally generated), `POSTROUTING` (just before TX). iptables groups rules into **tables** — `filter` (ACCEPT/DROP), `nat` (SNAT/DNAT/MASQUERADE), `mangle` (field rewrite), `raw` (conntrack bypass), `security` (SELinux) — each visible only at the hooks that make sense for it. Inside a table, rules live in **chains** (the built-ins named after the hooks, plus user chains). A packet walks a chain rule-by-rule; the first rule whose **matches** all hold fires its **target**.

- **Matches:** `-p {tcp,udp,icmp}`, `-s`/`-d addr/mask`, `--sport`/`--dport` (single or `a:b` range), `-i`/`-o iface`, and extension matches via `-m` (`-m state`/`-m conntrack --ctstate NEW,ESTABLISHED,RELATED`, `-m multiport`, `-m limit`, …).
- **Targets:** `ACCEPT`, `DROP`, `REJECT` (emit ICMP unreachable or TCP RST), `LOG`, `RETURN` (pop to the calling chain), and `-j USERCHAIN` (jump). Each built-in chain has a **policy** (default verdict) applied if no rule matched.

**Maps to Bismuth.** On a host-class MCU there is no routing, so only two hooks are real: `INPUT` ≡ our `Dir::In` chain and `OUTPUT` ≡ `Dir::Out` chain. (`FORWARD`/`PREROUTING`/`POSTROUTING` matter only for the gateway/bridge case, §6.) "Table × chain × policy × first-match targets" collapses cleanly onto "a `RuleSet` attached to a direction, with a default `Action`." Matches map almost one-for-one onto `MatchExpr` fields (§2). Targets map onto a small `Action` enum; `JUMP`/`RETURN` to user chains are **flattened/inlined at build time** rather than walked at runtime.

### 1.2 nftables (the successor)

nftables ([nftables wiki][nft-wiki]) replaces iptables' fixed tables with a small **bytecode VM** (`nft` compiles rules to instructions the kernel interprets), one unified address family, and first-class **sets and maps**: a named set is a collection (`{ 22, 80, 443 }` or address prefixes) you match against in O(log n); a **verdict map** maps a key directly to a verdict (`tcp dport vmap { 22 : accept, 80 : drop }`), replacing long if-else chains. Sets can be `interval` (ranges/prefixes) or `timeout` (auto-expiring).

**Maps to Bismuth.** Bismuth's networking doc already rejected the **VM** (code size + verifier-like complexity). What is genuinely worth stealing is **sets and verdict maps**, because on an MCU they are just *sorted `const` arrays with binary search* and a parallel `const` array of actions — compact, allocation-free, and far cheaper than many near-duplicate rules. So the nftables front-end (§4.2) offers `Set`/`VerdictMap` that lower into one `RuleSet` rule that does a set lookup, with **no interpreter**.

### 1.3 BSD pf

pf (`pf.conf`, [OpenBSD pf FAQ][pf-faq]) is usually the **cleanest to emulate**. A ruleset is a list of `pass`/`block` rules; by default the **last matching rule wins**, unless a rule says `quick`, which makes it win immediately (first-match). Rules read almost like English: `block in quick on egress proto tcp from <bruteforce> to any port ssh`. It has **tables** (`<name>` = a named set of addresses, the direct ancestor of nft sets), **anchors** (named sub-rulesets, like iptables user chains), and **`keep state`** (pf creates state on the first packet and lets the return traffic through automatically — in modern pf this is the default for `pass`).

**Maps to Bismuth.** The pf front-end (§4.3) adopts pf's **`quick` = first-match** idiom directly (it is exactly what `RuleSet` does) and treats non-`quick`/last-match-wins as the harder case, resolved at build time by rule ordering. `table` → a `Set`. `keep state` → requires the `ConnTrack` feature. Anchors → inlined. pf's readability makes it the front-end to recommend for hand-written edge policies.

### 1.4 eBPF / XDP (context only — rejected for MCUs)

XDP runs an **eBPF** program at the driver's RX hook, before any socket-buffer allocation, returning `XDP_PASS/DROP/TX/REDIRECT` ([XDP docs][xdp]); AF_XDP redirects frames to a userspace ring. This is Linux's fastest drop path and the conceptual sibling of our `Steer` + raw-RX hook. But eBPF needs a bytecode **verifier**, a JIT, maps infrastructure and a stable program ABI — tens of KB of kernel code and a trust model built for *loading untrusted programs at runtime*, which an MCU neither needs nor can afford. Bismuth's answer is the same one the net doc already gave: **hooks are compiled Rust**; the "program" is a `const` `RuleSet`. (A tiny classic-BPF interpreter remains a possible *optional* hook for a management plane that must push filters at runtime — but it is explicitly not part of this design.)

### 1.5 conntrack / stateful filtering

Linux **conntrack** tracks every flow through a hash table keyed by the canonical 5-tuple, assigning each packet a ctstate: `NEW` (first packet of a flow), `ESTABLISHED` (a flow that has seen both directions), `RELATED` (a new flow an ALG tied to an existing one, e.g. FTP data or ICMP errors), and `INVALID`. The classic stateful host policy is three lines: *accept ESTABLISHED/RELATED, accept selected NEW inbound, drop the rest.* TCP tracking follows the state machine (SYN → SYN/ACK → …); UDP/ICMP are pseudo-flows with short timeouts.

**Maps to Bismuth — but sized honestly.** Linux conntrack grows a hash table to hundreds of thousands of entries. An MCU gets a **fixed array** of a few dozen, with build-time capacity, timeouts, and eviction — and **no ALG/RELATED helpers** (those are per-protocol parsers, pure attack surface). Even `NEW`/`ESTABLISHED` alone turns "allow replies to what I started" into one rule, which is the single most useful stateful idiom for an edge client. §3 gives the table and its cost, and the rule for when to omit it entirely.

---

## 2. Design part 1 — the static rule engine `RuleSet<const N>`

### 2.1 `MatchExpr`: extend the real `Match`, keep it `Copy`

The existing `Match` is a single-criterion predicate over `frame: &[u8]`. A firewall rule needs a **conjunction** (proto *and* dport *and* src-prefix). Rather than nest the enum, add a `Copy` struct of optional criteria — `None` means "wildcard / any", which is precisely iptables/pf default-any semantics — and extend `Match` with the new atomic predicates so both styles share one parser.

```rust
// src/net/hook.rs — extends the existing `Match`, `Dir`, `Verdict`, `PacketHook`.

/// An IPv4 address + prefix length. `len == 0` matches anything.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ip4Prefix { pub addr: [u8; 4], pub len: u8 }

impl Ip4Prefix {
    pub const ANY: Ip4Prefix = Ip4Prefix { addr: [0; 4], len: 0 };
    pub const fn host(a: [u8; 4]) -> Self { Ip4Prefix { addr: a, len: 32 } }
    fn contains(&self, ip: [u8; 4]) -> bool {
        let mask = if self.len == 0 { 0 } else { u32::MAX << (32 - self.len.min(32) as u32) };
        u32::from_be_bytes(ip) & mask == u32::from_be_bytes(self.addr) & mask
    }
}

/// An inclusive port range. `(0, 65535)` matches anything (and ports are N/A for non-L4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortRange { pub lo: u16, pub hi: u16 }
impl PortRange {
    pub const ANY: PortRange = PortRange { lo: 0, hi: u16::MAX };
    pub const fn only(p: u16) -> Self { PortRange { lo: p, hi: p } }
    fn contains(&self, p: u16) -> bool { self.lo <= p && p <= self.hi }
}

/// Connection-state mask (set bits = acceptable states); empty = don't care. Needs `ConnTrack`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnMask(pub u8);
impl ConnMask {
    pub const ANY: ConnMask = ConnMask(0);
    pub const NEW: ConnMask = ConnMask(1 << 0);
    pub const ESTABLISHED: ConnMask = ConnMask(1 << 1);
    pub const INVALID: ConnMask = ConnMask(1 << 2);
}

/// A conjunctive match: every `Some`/non-ANY field must hold. ~24 bytes, all `Copy`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MatchExpr {
    pub dir: Option<Dir>,        // usually redundant (sets are attached per-direction)
    pub ifindex: Option<u8>,     // -i / -o / `on <if>`
    pub ethertype: Option<u16>,  // non-IP L2 match (reuses csum::ethertype)
    pub proto: Option<u8>,       // csum::PROTO_{TCP,UDP,ICMP}
    pub src: Ip4Prefix,          // -s / from
    pub dst: Ip4Prefix,          // -d / to
    pub sport: PortRange,        // --sport
    pub dport: PortRange,        // --dport / port
    pub state: ConnMask,         // -m state / keep state
}

impl MatchExpr {
    /// Everything-wildcard base; builders start here and set the fields they constrain.
    pub const ANY: MatchExpr = MatchExpr {
        dir: None, ifindex: None, ethertype: None, proto: None,
        src: Ip4Prefix::ANY, dst: Ip4Prefix::ANY,
        sport: PortRange::ANY, dport: PortRange::ANY, state: ConnMask::ANY,
    };

    fn matches(&self, k: &InetTuple, dir: Dir, ifindex: IfIndex, ct: ConnMask) -> bool {
        self.dir.is_none_or(|d| d == dir)
            && self.ifindex.is_none_or(|i| i == ifindex.0)
            && self.ethertype.is_none_or(|t| Some(t) == k.ethertype)
            && self.proto.is_none_or(|p| Some(p) == k.proto)
            && self.src.contains(k.src) && self.dst.contains(k.dst)
            && self.sport.contains(k.sport) && self.dport.contains(k.dport)
            && (self.state.0 == 0 || self.state.0 & ct.0 != 0)
    }
}
```

`InetTuple` is parsed **once per packet** by a new helper beside the existing frame parsers in `src/net/csum.rs` (it already has a private `ipv4_span` and a public `l4_dst_port`; this generalises them):

```rust
// src/net/csum.rs (sketch of the needed addition)
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InetTuple {
    pub ethertype: Option<u16>,
    pub src: [u8; 4], pub dst: [u8; 4],
    pub proto: Option<u8>,
    pub sport: u16, pub dport: u16,
    pub tcp_flags: u8,   // for ConnTrack (SYN/ACK/FIN/RST); 0 for non-TCP
}
pub fn inet_tuple(frame: &[u8]) -> Option<InetTuple>; // reuses ipv4_span; None for non-IPv4
```

### 2.2 `Action` and the ruleset hook

```rust
/// What a matching rule does. Terminal actions stop evaluation (first-match-wins).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,                 // ACCEPT / pass  -> Verdict::Pass
    Drop,                   // DROP  / block  -> Verdict::Drop
    #[cfg(feature = "net-filter-reject")]
    Reject,                 // REJECT: Drop + emit ICMP unreachable / TCP RST (rate-limited, §4.4)
    Jump(u8),               // -j USERCHAIN: index of an inlined sub-range (bounded; see §2.4)
    Return,                 // RETURN from a jumped range to the caller's next rule
    Continue,               // LOG-only / non-terminal: fall through to the next rule
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub m: MatchExpr,
    pub action: Action,
    pub log: bool,          // side effect: bump this rule's counter / tap the frame
}

/// A first-match-wins rule chain, attached per direction like `Firewall`.
pub struct RuleSet<const N: usize> {
    dir: Dir,
    rules: [Rule; N],
    default: Action,                 // the chain policy (ACCEPT or DROP)
    pub hits: [AtomicU32; N],        // per-rule counters (LOG / stats); const-constructible
    pub dropped: AtomicU32,
    pub passed: AtomicU32,
    tap: Option<&'static dyn RingSink>, // optional pcap/log tap (§5)
}

impl<const N: usize> RuleSet<N> {
    pub const fn new(dir: Dir, rules: [Rule; N], default: Action) -> Self {
        RuleSet {
            dir, rules, default,
            hits: [const { AtomicU32::new(0) }; N],
            dropped: AtomicU32::new(0), passed: AtomicU32::new(0),
            tap: None,
        }
    }
}

impl<const N: usize> PacketHook for RuleSet<N> {
    fn name(&self) -> &'static str { "ruleset" }

    fn on_packet(&self, dir: Dir, ifindex: IfIndex, pkt: PacketBuf) -> Verdict {
        if dir != self.dir {
            return Verdict::Pass(pkt);     // this set only filters its direction
        }
        // Parse the 5-tuple once; non-IPv4 frames yield a tuple with proto == None.
        let key = csum::inet_tuple(pkt.data()).unwrap_or_default();
        let ct = ConnMask(pkt.meta.ct_mark);  // 0 unless a ConnTrack hook ran earlier (§3)

        let mut i = 0;
        let mut act = self.default;
        while i < N {
            let r = &self.rules[i];
            if r.m.matches(&key, dir, ifindex, ct) {
                if r.log { self.hits[i].fetch_add(1, Ordering::Relaxed); }
                match r.action {
                    Action::Continue => { i += 1; continue; }     // LOG-only: keep walking
                    Action::Jump(t) => { i = t as usize; continue; }
                    Action::Return  => { act = self.default; break; }
                    terminal        => { act = terminal; break; }
                }
            }
            i += 1;
        }
        self.apply(act, ifindex, pkt)   // -> Verdict::{Pass,Drop,Consumed}, taps if configured
    }
}
```

This is deliberately the same shape as the existing `Firewall::on_packet`: borrow `pkt.data()`, decide, then move the packet into `Pass`/`Drop`. The hot cost is one 5-tuple parse plus up to `N` cheap struct comparisons — no allocation, no locking (the `net` task owns the chain, as the net doc guarantees).

### 2.3 Attaching, globally or per-interface

No new plumbing: a `RuleSet` is a `PacketHook`, so it uses the existing trusted-only API unchanged.

```rust
static FW_IN: RuleSet<3> = RuleSet::new(Dir::In, [
    // accept replies to flows we started (needs ConnTrack); allow CoAP; drop the rest
    Rule { m: MatchExpr { state: ConnMask::ESTABLISHED, ..MatchExpr::ANY }, action: Action::Accept, log: false },
    Rule { m: MatchExpr { proto: Some(csum::PROTO_UDP), dport: PortRange::only(5683), ..MatchExpr::ANY },
           action: Action::Accept, log: true },
    Rule { m: MatchExpr::ANY, action: Action::Drop, log: true },
], /* default = */ Action::Drop);

net::attach_hook(eth0, Dir::In, &FW_IN)?;   // per-interface
net::add_global_hook(Dir::In, &FW_IN)?;     // or every interface, runs first
```

### 2.4 Honest limits of the engine

- **Flat, bounded chains.** `JUMP`/`RETURN` exist so a front-end can express user chains, but targets are plain indices into the *same* `rules` array; the builder inlines user chains and bounds jumps (a depth counter prevents loops). Arbitrary cross-table jump graphs are not supported — and are not needed when there is no routing.
- **IPv4 first.** `MatchExpr` carries `[u8;4]`. IPv6 (`[u8;16]`) doubles the per-rule size; make it a separate `MatchExpr6` behind `net-filter-ip6` rather than paying for it everywhere.
- **No field rewriting (`mangle`), no NAT** in the core engine (§6).
- **`N` is fixed at build time.** Runtime "add rule" means swapping in a new `&'static` set (§5), not growing an array.

---

## 3. Design part 2 — optional stateful filtering (`ConnTrack<const C>`)

A separate hook, run *before* the `RuleSet` (like Linux conntrack in `PREROUTING`/`raw`), that looks up or creates a flow entry and **stamps a 1-byte mark into `PacketMeta`** so the ruleset can match on it. This keeps the engine stateless and the tracker swappable; it needs one small field added to `PacketMeta` in `src/net/buf.rs` (next to the existing `csum` and `vlan` hints):

```rust
// PacketMeta gains (1 byte): 0 = untracked, else bits of ConnMask (NEW/ESTABLISHED/INVALID).
pub ct_mark: u8,
```

```rust
#[derive(Copy, Clone, Default)]
struct Conn {
    key: CanonTuple,  // 5-tuple normalised so both directions hash the same: 13 B
    state: u8,        // ConnMask bit
    last: u64,        // tick of last packet (for timeout + LRU eviction): 8 B
}

pub struct ConnTrack<const C: usize> {
    table: IrqCell<[Conn; C]>,     // ~ C * 24..28 B
    udp_timeout: u64, tcp_timeout: u64,
    pub created: AtomicU32, pub evicted: AtomicU32, pub hits: AtomicU32,
}

impl<const C: usize> PacketHook for ConnTrack<C> {
    fn name(&self) -> &'static str { "conntrack" }
    fn on_packet(&self, dir: Dir, _if: IfIndex, mut pkt: PacketBuf) -> Verdict {
        let Some(k) = csum::inet_tuple(pkt.data()).map(CanonTuple::from) else {
            return Verdict::Pass(pkt);           // non-IP: untracked
        };
        let now = time::ticks();
        let mark = self.table.lock(|t| self.update(t, &k, dir, now));  // expire, match, insert/evict
        pkt.meta.ct_mark = mark.0;
        Verdict::Pass(pkt)                        // conntrack never drops; policy lives in the RuleSet
    }
}
```

- **State model (minimal):** first packet of a flow → `NEW`; once a packet is seen in the *opposite* direction → `ESTABLISHED`. TCP uses `tcp_flags` from the tuple only to shorten timeouts (RST/FIN → close soon); no full TCP state machine, no window checks. This is a *policy aid*, not a security TCP stack — be clear about that.
- **Eviction:** on a full table, evict the entry with the oldest `last` (LRU), preferring already-expired or non-`ESTABLISHED` entries. Expiry is lazy (checked on the sweep during lookup) plus an optional periodic sweep from the net task's timer tick.
- **RAM cost (the whole point):** `C=16` ≈ 0.4 KB, `C=32` ≈ 0.9 KB, `C=64` ≈ 1.8 KB. That is a lot on a 32 KB part and nothing on a 256 KB part.
- **When to leave it out (default on the smallest parts):** a pure sensor that *initiates* outbound reports and accepts nothing unsolicited needs only a stateless ingress drop-all-but-DHCP/DNS-replies-by-port rule — cheaper and simpler than tracking state. Only reach for `ConnTrack` when "allow replies to arbitrary flows I started" or inbound TCP accept policy is genuinely required. Gate it behind `net-filter-conntrack`; `ConnMask` matching silently sees `ct_mark == 0` (untracked) when the feature is off, so a ruleset written for state degrades to stateless rather than failing to build.

---

## 4. Design part 3 — the compat front-ends (one engine, many syntaxes)

Each front-end is an **optional cargo feature** and a **thin `const` builder** (or, for the parser, a tiny `&str` reader) that *lowers* a familiar rule syntax into the `RuleSet`/`MatchExpr`/`Action` objects above. There is **one enforcement engine**; the front-ends only change how rules are *written*, exactly as `src/compat/hal.rs` (embedded-hal) and the POSIX/FreeRTOS shims change how *one driver core* is called.

### 4.1 iptables-style (`net-filter-iptables`)

A const builder with iptables vocabulary. `Chain::INPUT`/`OUTPUT` map to `Dir::In`/`Out`; `FORWARD` is rejected at build time unless the gateway feature (§6) is on.

```rust
let fw: RuleSet<3> = Chain::INPUT.policy(Drop).rules([
    Rule::new().ctstate(ESTABLISHED).jump(Accept),
    Rule::new().proto(Udp).dport(5683).jump(Accept).log(),
    Rule::new().proto(Tcp).src("10.0.0.0/8").dport_range(8000, 8099).jump(Accept),
]);
net::attach_hook(eth0, Dir::In, Box_static(fw))?;   // attached as a plain PacketHook
```

- **Can express:** `-p`, `-s`/`-d` with prefix, `--sport`/`--dport` (single + range), `-i`/`-o`, `-m state --state`, `ACCEPT`/`DROP`/`REJECT`/`LOG`, chain policy, and user chains (`-j NAME`) via build-time inlining.
- **Cannot express:** NAT targets, `mangle`, most `-m` extension modules (`recent`, `hashlimit`, string match, owner, …), per-packet `limit` beyond the existing `RateLimit` hook, and runtime `-I`/insert-at-index semantics (rules are a fixed array).
- **Optional tiny parser (`net-filter-parse`):** a restricted reader for `iptables -A`/`iptables-save` lines — enough to load a boot-time policy string from flash or a management channel:
  `-A INPUT -p udp --dport 5683 -j ACCEPT` / `-P INPUT DROP`. It accepts only `-A/-P/-p/-s/-d/--sport/--dport/-i/-o/-m state --state/-j {ACCEPT,DROP,REJECT,LOG}` into a `RuleSet` with a build-time cap on rule count. Anything else is a parse error, not a silent no-op. This is a convenience, **not** a general iptables parser, and it is off by default (code size + untrusted-input surface).

### 4.2 nftables-style (`net-filter-nft`)

The valuable nft ideas on an MCU are **sets** and **verdict maps**, implemented as sorted `const` arrays — no VM.

```rust
// `tcp dport { 22, 80, 443 } accept`  — a named set is a sorted const array + binary search.
static WEB: PortSet<3> = PortSet::sorted([22, 80, 443]);

// `tcp dport vmap { 22: accept, 80: drop, 443: accept }` — key -> Action, binary search.
static VM: VerdictMap<3> = VerdictMap::sorted([(22, Accept), (80, Drop), (443, Accept)]);

let fw: RuleSet<2> = nft::chain(Dir::In, Drop)
    .rule(nft::tcp().dport_in(&WEB).accept())
    .rule(nft::tcp().dport_vmap(&VM));
```

- A set-membership rule is one `RuleSet` rule whose `MatchExpr` carries a `Some(&'static PortSet)` reference (or prefix set) tested in the match; a verdict map is one rule that looks the key up and returns the mapped `Action` (implemented as a short `Continue`-chained span, or by letting the match return the action directly in the lowered form).
- **Can express:** named port/address sets, interval sets (prefixes/ranges), verdict maps, and the usual `ip saddr/daddr`, `*port`, `ct state` matches.
- **Cannot express:** nft's full expression language, stateful objects (counters/quotas/limits as first-class named objects — use `Counter`/`RateLimit` hooks instead), concatenated-key maps, dynamic set updates from the data path (`add @set`), and anything requiring the bytecode interpreter. `timeout` sets reduce to the `ConnTrack` timeout, not arbitrary per-set timers.

### 4.3 pf-style (`net-filter-pf`)

The most readable front-end; recommended for hand-authored edge policy. Adopts pf's `quick` = first-match semantics directly.

```rust
let fw: RuleSet<4> = pf::ruleset(Dir::In, /* default */ Block)
    .block()                                              // block all (last-match default)
    .pass().quick().proto(Tcp).to_port(22).keep_state()   // ssh in, stateful
    .pass().quick().proto(Udp).to_port(5683)              // coap
    .pass().quick().proto(Icmp);                          // ping
```

- `table <name> { … }` → a `Set`; `keep state` → sets `ConnMask::NEW` acceptance and relies on `ConnTrack`; `quick` → terminal first-match (native to `RuleSet`); anchors → inlined.
- **Can express:** `pass`/`block [return]`, `in`/`out`, `on <if>`, `proto`, `from`/`to` with prefixes and tables, `port` single/range, `quick`, `keep state`.
- **Cannot express:** `rdr`/`nat`/`binat` (NAT, §6), `scrub`/reassembly, `queue`/ALTQ (use the TX bands + `RateLimit`), `route-to`/`reply-to`, `synproxy`, OS fingerprinting, and the full last-match-wins semantics for *non-`quick`* rules unless the builder reorders them at compile time (it does a best-effort stable reorder; ambiguous cases are a build error, not a silent misorder).

### 4.4 REJECT and generated responses (optional, careful)

`Action::Reject` (feature `net-filter-reject`) turns a drop into an active refusal: build an ICMPv4 *destination unreachable (port)* or, for TCP, a RST, from `TX_POOL`, fill checksums via `csum::fill_frame`, and `net::transmit` it. Because this is a reflection/amplification vector, it is **off by default, rate-limited** (reuse the `RateLimit` hook or an internal token bucket), and never emitted for broadcast/multicast or for packets with a spoofed-looking source. Most MCU policies should prefer silent `Drop`.

---

## 5. Rights, domains, logging and counters

### 5.1 Who may change rules

Rule changes ride the existing trusted-only data-plane API — no new privilege path:

- `net::attach_hook` / `detach_hook` / `add_global_hook` already return `Error::PermissionDenied` unless `security::current_is_trusted()` (`src/net/mod.rs`). A `RuleSet`/`ConnTrack` is just a `PacketHook`, so attaching one is already gated.
- **The natural MCU shape is immutable:** rulesets are `&'static` `const` values attached at boot by a trusted domain, then never mutated — the whole policy is auditable in the image, matching the security doc's "capability graph checked at build time" philosophy.
- **Runtime edits**, where needed, go through a `MANAGE`-gated control op (the security doc already lists "net hook attach" as a `Rights::MANAGE` operation, §4.3 of `security.md`). In hardened builds, refuse all rule mutation after `security::seal()` — `is_sealed()` is already available — so policy can only *tighten* (detach, swap to a stricter set), never widen, after boot. An isolated domain may at most select from a manifest-declared catalogue of vetted rulesets, never supply rule *code*.
- Per-domain socket policy (`NetPolicy`: local ports / peer prefix / listen, enforced in the socket layer) and the packet filter are **complementary**: the filter runs on *frames* before demux (it cannot see which domain owns a socket), while `NetPolicy` runs at bind/connect. Keep both; document that the filter is the coarse edge and `NetPolicy` the per-domain edge.

### 5.2 LOG and counters (reuse, don't reinvent)

- **Counters:** the `Counter` hook already exists; place one before/after a `RuleSet` for aggregate telemetry. Per-rule hits live in `RuleSet::hits[i]`. Drops already bump `IfStats.hook_drops` through `run_chain`'s `Err(true)` path — no change needed.
- **LOG target / pcap tap:** a logged rule (`log: true`, or iptables `LOG`) can, in addition to counting, **tap the frame** to a `NetRing` via the existing `Steer`/`RingSink` mechanism: clone the bytes into an `APP_POOL` buffer and `deliver` to a ring a logger task drains to UART/USB/flash in libpcap format. This is the `bpf(4)`/pcap-tap idea the net doc already anticipated. Cloning costs one buffer + one copy, so the tap is itself rate-limited and bounded by the ring depth (overruns are counted, not blocking). A tap that only needs *metadata* (5-tuple + verdict + timestamp) can log a fixed 16-byte record instead of the frame, which is far cheaper.

---

## 6. NAT and the gateway case (when, and only when, to build it)

NAT is deliberately **excluded** from the core because the common MCU is a *host*, not a router, and NAT needs routing, a port-allocation table, and per-flow rewrite state (another conntrack-sized structure) — a large amount of code for a case most targets never hit. Build it **only** when the device is explicitly a gateway/bridge (a cellular-to-LAN router, a 6LoWPAN border router, an industrial two-port bridge), and then as a *separate* optional feature (`net-filter-nat`) with its own `Nat` hook that reuses the `ConnTrack` table (NAT state is conntrack state plus a rewritten tuple). Even then, prefer the minimal forms: **masquerade/SNAT for an outbound-only edge router**, and static DNAT for one or two published services — not the full `nat`-table expressiveness. The `FORWARD`/`PREROUTING`/`POSTROUTING` chains become real in this build; keep them absent otherwise.

---

## 7. Phased, host-sim-testable plan

Testing mirrors `tests/net.rs`: two stacks over a simulated `Wire`, plus the `Loopback` device; the existing `firewall_hook_drops_matching_inbound_traffic` test is the template (attach a hook, send allowed + blocked datagrams, assert `hook_drops` and per-hook counters). Every phase is pure host `cargo test`, no hardware.

| Phase | Deliverable | Test (sim) |
|---|---|---|
| **P0 engine** | `csum::inet_tuple`; extend `Match`/add `Ip4Prefix`/`PortRange`/`ConnMask`/`MatchExpr`; `RuleSet<N>` + `Action` + per-rule counters; feature `net-filter`. | Port the firewall test to a 3-rule `RuleSet`: assert accept-by-port, drop-by-prefix, default-drop, and that `hits[i]`/`dropped` match. |
| **P1 iptables builder** | `Chain`/`Rule` const builder → `RuleSet`; `net-filter-iptables`. | Build a policy with the builder and a hand-written `RuleSet`; assert identical verdicts over the `Wire`. |
| **P2 conntrack** | `PacketMeta.ct_mark`; `ConnTrack<C>`; stateful rules; `net-filter-conntrack`. | Outbound UDP creates `NEW`→`ESTABLISHED`; the reply passes an `established accept; default drop` set; an *unsolicited* inbound datagram is dropped. Fill the table past `C` and assert eviction counters + that an active flow survives. |
| **P3 nft + pf + parser** | `Set`/`VerdictMap`; pf `quick`/`keep state` builder; restricted `iptables -A` parser; `net-filter-nft`/`-pf`/`-parse`. | Each front-end lowers a known policy to a `RuleSet` equal (verdict-for-verdict) to the P0 reference; parser round-trips a few lines; malformed lines error. |
| **P4 log/tap + rights** | `log` action, per-rule counters, `Steer`-to-`NetRing` pcap tap + a UART logger; `MANAGE`/`seal` gating of edits. | A logged drop taps one pcap record to a ring; a non-trusted domain's `attach_hook` returns `PermissionDenied`; a post-`seal()` edit is refused. |

---

## 8. Summary: what to build, map, and skip

| Real-world feature | Bismuth mapping | Verdict |
|---|---|---|
| netfilter 5 hooks | `Dir::In`≡INPUT, `Dir::Out`≡OUTPUT on the existing chain; FORWARD/PRE/POST only in the gateway build | Build (host); gate (gateway) |
| iptables table/chain/policy/first-match | `RuleSet<N>` attached per direction + default `Action` | Build |
| matches (proto/addr/port/iface/state) | `MatchExpr` (extends `Match`) + `inet_tuple` | Build |
| targets ACCEPT/DROP/LOG/RETURN/JUMP | `Action` + `log` flag; jumps inlined at build | Build |
| REJECT | `Action::Reject`, rate-limited, opt-in | Optional |
| nftables sets / verdict maps | sorted `const` arrays + binary search | Build (front-end) |
| nftables bytecode VM | — | **Skip** |
| pf `quick` / `keep state` / tables | native first-match / `ConnTrack` / `Set` | Build (front-end) |
| eBPF/XDP program + verifier/JIT | compiled-Rust `RuleSet`; (optional cBPF hook only) | **Skip** |
| conntrack NEW/ESTABLISHED | fixed `ConnTrack<C>`, meta `ct_mark`, LRU+timeout | Optional |
| conntrack RELATED / ALG helpers | — | **Skip** |
| NAT / mangle | separate gateway feature, reuses `ConnTrack` | Gateway only |
| LOG / counters / pcap | `Counter`, `IfStats.hook_drops`, per-rule hits, `Steer`→`NetRing` tap | Build (reuse) |
| rule-change authority | trusted-only `attach_hook` + `MANAGE` + `seal()` | Reuse |

The honest bottom line: Bismuth can offer a **genuinely usable, allocation-free, auditable packet filter** with **three familiar syntaxes** on top of the hook chain it already has, for well under the RAM and code budget of porting any one of iptables/nftables/pf. It cannot offer their full expressiveness — no VM, no dynamic sets from the data path, no NAT by default, no ALGs — and should not pretend to. One engine, many front-ends, every verdict tested in the simulator.

---

## References

**Linux netfilter / nftables**
- [nf-arch]: netfilter/iptables project & packet-flow (the five hooks, tables, chains, targets). https://www.netfilter.org/ ; https://netfilter.org/documentation/
- iptables-extensions(8) (matches/targets, `-m state`/`conntrack`, `multiport`, `limit`, REJECT, LOG). https://ipset.netfilter.org/iptables-extensions.man.html
- [nft-wiki]: nftables wiki (rule model, sets, maps, verdict maps, the VM). https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
- conntrack-tools / netfilter conntrack (ctstate NEW/ESTABLISHED/RELATED/INVALID, timeouts). https://conntrack-tools.netfilter.org/ ; https://www.netfilter.org/projects/nf_conntrack/
- Netfilter packet-flow diagram (hook order, table precedence). https://en.wikipedia.org/wiki/Netfilter#/media/File:Netfilter-packet-flow.svg

**BSD pf**
- [pf-faq]: OpenBSD PF FAQ — rule syntax, `quick`, last-match, tables, anchors, `keep state`. https://www.openbsd.org/faq/pf/ ; pf.conf(5): https://man.openbsd.org/pf.conf

**eBPF / XDP (context)**
- [xdp]: Linux XDP / AF_XDP documentation. https://docs.kernel.org/networking/af_xdp.html ; https://docs.cilium.io/en/stable/bpf/

**RFCs**
- RFC 791 (IPv4), RFC 793/9293 (TCP, state machine), RFC 768 (UDP), RFC 792 (ICMP), RFC 5737 (documentation address blocks). https://www.rfc-editor.org/

**Bismuth (in-tree)**
- `src/net/hook.rs` (`PacketHook`, `Verdict`, `Dir`, `Match`, `Firewall`, `Counter`, `RateLimit`, `Steer`), `src/net/mod.rs` (chain order, `attach_hook`/`add_global_hook`, `IfStats`), `src/net/csum.rs` (`ethertype`, `l4_dst_port`, `ipv4_span`), `src/net/buf.rs` (`PacketBuf`, `PacketMeta`), `src/net/ring.rs` (`NetRing`, `RingSink`).
- `src/security/mod.rs` (`Rights`, `DeviceCap`, domains, `NetPolicy`, `seal`), `src/driver/middleware.rs` (control-plane layer model), `tests/net.rs` (two-stacks-over-a-Wire test style).
- `docs/research/networking.md` §4.6 (pfil/XDP hook rationale, "no nftables VM"), `docs/research/security.md` §4.3 (`MANAGE`-gated hook attach, seal-then-tighten).
