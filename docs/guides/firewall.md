# Firewalling a device

This guide locks down an edge node's network exposure with `net::filter`. All snippets were compiled
against the current kernel; sections 1–3 mirror `tests/firewall.rs`, which passes. Concepts and
gaps: [design/firewall.md](../design/firewall.md). Requires the `net-filter` feature (on by
default).

## 1. Allow one service, drop the rest (iptables style)

The node serves CoAP on UDP/5683 and nothing else:

```rust
use bismuth::net::{self, Dir};
use bismuth::net::filter::{Action, Rule, RuleSet};

static FW_IN: RuleSet<2> = RuleSet::new(
    Dir::In,
    [
        Rule::new().udp().dport(5683).accept().log(),   // like: -A INPUT -p udp --dport 5683 -j ACCEPT
        Rule::new().drop().log(),                       // like: -A INPUT -j DROP (counted)
    ],
    Action::Drop,                                       // chain policy (IPv4 only)
);

// after net::register(..), before or after net::start():
net::attach_hook(eth0, Dir::In, &FW_IN)?;               // trusted code only
```

ARP keeps working: rules without an `ethertype` match only IPv4, and the default policy
only applies to IPv4. To block an L2 protocol, match its `ethertype` explicitly.

Check it is doing its job:

```rust
FW_IN.passed();     // packets accepted
FW_IN.dropped();    // packets dropped
FW_IN.hits(0);      // CoAP rule hits (rules with .log() only)
net::stats(eth0)?.hook_drops;   // drops by any hook on the interface
```

## 2. The same policy, pf style

```rust
use bismuth::net::csum;
use bismuth::net::filter::{Ip4Prefix, MatchExpr, block, pass};

static PF: RuleSet<2> = RuleSet::new(
    Dir::In,
    [
        // pass in quick proto udp from 10.0.0.0/24
        pass(MatchExpr { proto: Some(csum::PROTO_UDP), src: Ip4Prefix::new([10, 0, 0, 0], 24), ..MatchExpr::ANY }),
        // block in quick all   (block() also turns on hit counting)
        block(MatchExpr::ANY),
    ],
    Action::Drop,
);
```

Every rule is `quick` (first match wins); write the most specific rules first.

## 3. Outbound-only device (stateful)

Allow replies to connections the node opened, drop everything unsolicited:

```rust
use bismuth::net::filter::{ConnMask, ConnTrack};

static CT: ConnTrack<16> = ConnTrack::new(10_000);     // 16 flows, 10 s idle timeout @1 kHz
static FW_STATE: RuleSet<2> = RuleSet::new(
    Dir::In,
    [Rule::new().state(ConnMask::ESTABLISHED).accept(), Rule::new().drop().log()],
    Action::Drop,
);

net::attach_hook(eth0, Dir::In, &CT)?;        // conntrack first…
net::attach_hook(eth0, Dir::In, &FW_STATE)?;  // …then the policy
net::attach_hook(eth0, Dir::Out, &CT)?;       // see our own outbound packets
```

Packets that only come from the remote side stay `NEW` and are dropped. A flow becomes
`ESTABLISHED` only once the node itself has sent in it. `tests/firewall.rs` covers both
cases: `conntrack_allows_established_replies` and
`conntrack_does_not_promote_unsolicited_inbound`. The tracker does not look at TCP
flags, so closed TCP flows linger until the idle timeout.

## 4. Logging drops

Mirror dropped packets to a `NetRing` and let a low-priority task log or export them
(pcap, UART):

```rust
use bismuth::net::NetRing;

static DROP_LOG: NetRing<8> = NetRing::new();
static FW_LOGGED: RuleSet<2> = RuleSet::new(Dir::In, [/* rules */ Rule::new().udp().dport(5683).accept(), Rule::new().drop()], Action::Drop)
    .with_tap(&DROP_LOG);

fn drop_logger(_: usize) {
    while let Ok(p) = DROP_LOG.recv(bismuth::Timeout::Forever) {
        bismuth::kprintln!("fw drop: {} bytes", p.total_len());
    }
}
```

If the ring is full the packet is simply dropped (never stalls the net task).

## 5. Where to attach

| goal | attach with |
|------|-------------|
| one interface, inbound | `net::attach_hook(idx, Dir::In, &SET)` |
| one interface, outbound (egress policy) | `net::attach_hook(idx, Dir::Out, &SET)` with `RuleSet::new(Dir::Out, …)` |
| every interface | `net::add_global_hook(dir, &SET)` (runs before per-interface hooks; cannot be removed) |
| replace a policy at run time | `net::detach_hook(idx, dir, name)` then attach another `static` set. Give sets distinct names with `RuleSet::named("inbound-v2", …)`; `RuleSet::new` uses `"ruleset"`. |

All of these require a trusted caller (kernel or `trusted` domain); isolated domains get
`PermissionDenied`. Per-domain socket restrictions are a separate, complementary mechanism:
`DomainSpec.net` ([security](../design/security.md#network-policy)).

## 6. Not available

NAT/port forwarding, `REJECT`, user chains (jump/return), IPv6 filtering, fragment
reassembly, eBPF, run-time rule editing. See [design/firewall.md](../design/firewall.md#out-of-scope-per-the-research).
