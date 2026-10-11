# Packet filter (firewall)

Source: `src/net/filter.rs` (feature `net-filter`, on by default; it implies `net`) and
`csum::inet_tuple` in `src/net/csum.rs`. Tests: `tests/firewall.rs`. Research input:
[research/firewall.md](../research/firewall.md).

## Shape: one engine, several spellings

The firewall is not a new data path. It is two more [`PacketHook`](networking.md#packet-hooks-nethook)s
that plug into the existing hook chain (global → interface → driver, per direction), run
in the single `net` task without locks, and are attached with the existing **trusted-only**
`net::attach_hook` / `net::add_global_hook`.

| piece | role | netfilter / pf analogue |
|-------|------|-------------------------|
| `RuleSet<N>` | first-match-wins array of `Rule`s + default policy, one direction | an iptables chain with a policy / a pf ruleset of `quick` rules |
| `Rule { m: MatchExpr, action, log }` | conjunctive match + action | one `-A` rule / one pf line |
| `ConnTrack<C>` | fixed-size flow table that stamps `PacketMeta.ct_mark` | `nf_conntrack` / pf state (much simpler, see below) |
| `Rule::new()…` const builders | iptables-flavoured spelling | `-p udp --dport 5683 -j ACCEPT` |
| `pass(MatchExpr)` / `block(MatchExpr)` | pf-flavoured spelling | `pass quick …` / `block quick …` |

Both spellings produce the same `Rule` values in a `RuleSet`; there is no bytecode VM and
no heap. Per packet: one 5-tuple parse (`csum::inet_tuple`) then up to `N` comparisons.

## Matching

```rust
pub struct MatchExpr {
    pub ifindex: Option<u8>,      // interface (IfIndex.0)
    pub ethertype: Option<u16>,   // see "IPv4-only by default" below
    pub proto: Option<u8>,        // csum::PROTO_TCP / PROTO_UDP / PROTO_ICMP / any
    pub src: Ip4Prefix,           // Ip4Prefix::{ANY, host([a,b,c,d]), new(addr, len)}
    pub dst: Ip4Prefix,
    pub sport: PortRange,         // PortRange::{ANY, only(p), range(lo, hi)} (inclusive)
    pub dport: PortRange,
    pub state: ConnMask,          // ConnMask::{ANY, NEW, ESTABLISHED, INVALID}; any set bit matches
}
MatchExpr::ANY                    // all wildcards; start here with `..MatchExpr::ANY`
```

Every non-wildcard field must hold (AND). Direction is a property of the `RuleSet`
(`RuleSet::new(Dir::In | Dir::Out, …)`): a set ignores (passes) packets of the other
direction.

`csum::inet_tuple(frame) -> Option<InetTuple { ethertype, src, dst, proto, sport, dport,
tcp_flags }>` parses Ethernet (one VLAN tag is skipped — `ethertype` is the inner type),
IPv4, and the UDP/TCP ports. Ports are only read from the **first fragment**; later
fragments carry port 0. Non-IPv4 frames yield only `ethertype`.

### IPv4-only by default (important)

- A rule with **no explicit `ethertype` matches only IPv4 frames**.
- The **default policy applies only to IPv4 frames**; a non-IPv4 frame (ARP, a custom
  EtherType) that no explicit rule matched is **accepted**.

So a catch-all `block(MatchExpr::ANY)` or a `Drop` default does **not** block ARP — just as
the Linux IPv4 `filter` table never sees ARP. (A default-drop set that killed ARP was a real
bug found and fixed during development.) To filter L2 traffic, write a rule with
`ethertype: Some(…)`, e.g. `block(MatchExpr { ethertype: Some(csum::ETHERTYPE_ARP), ..MatchExpr::ANY })`.

## Actions, policy and counters

| `Action` | effect |
|----------|--------|
| `Accept` | stop; `Verdict::Pass` |
| `Drop` | stop; `Verdict::Drop` (counted in the interface's `hook_drops`) |
| `Continue` | non-terminal (log-only): evaluation continues with the next rule; as a *default policy* it behaves like `Accept` |

- Rules are evaluated in order; the **first** terminal match wins.
- `RuleSet::new(dir, rules, default)` creates a set. `default` applies when no terminal
  rule matched (IPv4 only, see above). The set's hook name is `"ruleset"`.
- `RuleSet::named(name, dir, rules, default)` gives the set its own hook name, so two
  sets on one interface can be detached separately.
- Counters: `passed()`, `dropped()`, and `hits(i)` — **only rules built with `.log()` are
  counted** (`block()` sets `log`, `pass()` does not).
- `with_tap(&'static dyn RingSink)` mirrors **dropped** packets to a `NetRing` (the packet
  is moved there: `Verdict::Consumed`; if the ring is full it is dropped normally) for a
  pcap/logging task. Accepted packets are not mirrored.

### iptables-style builder

```rust
Rule::new()                // wildcard, Action::Continue
    .udp() / .tcp() / .proto(p)
    .dport(p) / .dport_range(lo, hi) / .sport(p)
    .src(Ip4Prefix) / .dst(Ip4Prefix)
    .iface(idx) / .state(ConnMask)
    .log()
    .accept() / .drop()    // the last action call wins
```

There is no builder for `ethertype` (set the field: `Rule { m: MatchExpr { ethertype: …, ..MatchExpr::ANY }, .. }`).

## Connection tracking (`ConnTrack<C>`)

A separate hook, run **before** the `RuleSet` in the same direction, that never drops:

```rust
static CT: ConnTrack<16> = ConnTrack::new(10_000);         // C flows, idle timeout in ticks
net::attach_hook(ifx, Dir::Out, &CT)?;                      // see our own outbound packets
net::attach_hook(ifx, Dir::In,  &CT)?;                      // …and the replies (attach before the RuleSet)
net::attach_hook(ifx, Dir::In,  &FW_STATE)?;                // a RuleSet matching ConnMask::ESTABLISHED
```

- Flows are keyed by a direction-normalised (canonical) 5-tuple, so a request and its
  reply share one entry. The first packet of a flow creates the entry, records which
  direction opened it (`opener_in`), and is marked `NEW`.
- The flow becomes `ESTABLISHED` only when a packet arrives in the **opposite**
  direction from the opener, that is, a real reply. After that, packets in both
  directions are `ESTABLISHED`. More packets from the opener alone stay `NEW`, so an
  unsolicited remote peer cannot promote itself past a "drop NEW, accept ESTABLISHED"
  policy.
- The mark goes into `PacketMeta.ct_mark`, a 1-byte field added for this.
- The tracker has to see **both** directions. Attach the same `ConnTrack` on `Dir::Out`
  and on `Dir::In`, ahead of the `RuleSet`. If it only sees inbound packets, a reply to
  an outbound request looks like a new inbound flow.
- Table full → reuse a free/expired slot, else evict the least recently used one
  (`evicted()`); `created()` counts new flows.
- Non-IP frames are not tracked (`ct_mark` stays 0 = matches only `ConnMask::ANY`).

**This is a minimal policy aid, not a TCP-aware state machine.** It tracks direction but
not TCP flags (`tcp_flags` is parsed but unused), sequence numbers or FIN/RST, so a TCP
flow stays tracked until its idle timeout.

## Out of scope (per the research)

Not built, and not planned for the near term: an nftables-style bytecode VM, eBPF/XDP
programs, NAT / MASQUERADE / port forwarding, `REJECT` (needs ICMP/RST generation),
jump/return user-chain graphs, IP fragment reassembly, and IPv6 (would be a separate
`MatchExpr6`). nftables-style **sets and verdict maps** are noted as a thin future addition.
Rules are static arrays; there is no run-time rule editing API (swap a whole `RuleSet` by
detaching and attaching hooks).

## Limitations and known gaps

- ICMP and other port-less protocols collapse into one flow per host pair.
- `ConnTrack` ignores TCP flags (no SYN/FIN/RST handling); all trackers share the hook
  name `"conntrack"`.
