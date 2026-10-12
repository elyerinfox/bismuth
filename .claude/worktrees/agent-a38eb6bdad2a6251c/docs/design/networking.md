# Networking

Source: `src/net/` (features `net` and `net-ip`). Research input:
[research/networking.md](../research/networking.md). This page describes what is
**built**. Where the build differs from that proposal, the differences are listed in
[as built vs. research](#as-built-vs-the-research-proposal).

```text
  apps ── net::socket (UdpSocket, TcpStream, TcpListener) ── POSIX sockets      NetRing apps
            │  command queue + per-socket packet queues (APP_POOL)               ▲ zero-copy
  ┌─────────▼───────────────┐  ┌──────────────────────┐                          │
  │ IP stack (smoltcp)      │  │ protocol nodes       │                   Steer hook
  └─────────▲───────────────┘  │ (NetNode by EtherType)│                         │
            └────────┬─────────┴──────────▲───────────┘                          │
               dispatch by EtherType ─────┘                                      │
  ┌──────────────────┴───────────────────────────────────────────────────────────┴──┐
  │ packet hook chain: global → per-interface → driver   (Verdict: Pass/Drop/Consumed)│
  ├──────────────────────────────────────────────────────────────────────────────────┤
  │ net core (single `net` task): RX poll with budget + refill, checksum software    │
  │ fallback, 2-band TX queues, doorbell batching, reclaim, IfStats                   │
  ├──────────────────────────────────────────────────────────────────────────────────┤
  │ NetDevice (iflib-lite ring ops)  ◄── SoftRing ◄── FrameDevice                      │
  │ PacketPool blocks: RX_POOL / TX_POOL / APP_POOL                                   │
  └──────────────────────────────────────────────────────────────────────────────────┘
  control plane: /dev/<ifname> → driver middleware chain (LinkGuard) → ioctls / raw frame writes
```

## Principles

- **Single owner.** The `net` task owns every interface's rings, the transmit queues,
  pending transmit packets and the smoltcp stacks, including all socket buffers, which
  live on its stack. The data path takes no locks. Interrupt handlers call
  `net::schedule()`, which is `task::notify` on the net task.
- **Two planes.** Control requests to `/dev/<ifname>` go through the normal driver
  middleware chain. Packets go through `PacketHook` chains.
- **Offload with fallback.** Drivers advertise `NetCaps`. Whatever is not enabled
  (checksums, scatter-gather) the core does in software, so upper layers can always
  assume checksums are verified on receive and filled on transmit.
- **Pools by role.** RX, TX and application data come from separate pools, so a
  receive flood cannot starve transmission or sockets.

## Packet buffers (`net::buf`)

| constant | value |
|----------|-------|
| `HEADROOM` | 64 bytes reserved before the data for header prepends |
| `MAX_FRAME` | 1536 bytes after the headroom |
| `BLOCK_SIZE` | 1600 bytes per pool block |

- `PacketPool<const N>` is a static pool of `N` blocks. Each block is a `TaskCell`.
  - `alloc(timeout)` can block; `try_alloc()` is ISR-safe and returns `NoMemory`.
  - `alloc_from(data, timeout)` allocates and copies `data` in.
  - `available()` and `stats()` report usage. `PoolStats` holds `allocs`, `failures`,
    `in_use` and `high_water`.
- The three global pools are `net::RX_POOL`, `TX_POOL` and `APP_POOL`. Their sizes come
  from `BISMUTH_NET_{RX,TX,APP}_BUFS`.
- `PacketBuf` is an **owning handle** to one block. Moving it moves ownership, and
  dropping it returns the block and wakes one waiter. Ownership rules make
  use-after-free impossible without refcounting.
  - Headers: `push_header(n)` (like `skb_push`) and `pull_header(n)`.
  - Data: `append`, `extend(n)`, `truncate`, `reset`.
  - Receive: `rx_space()` and `set_len(n)`.
  - Access: `data()`/`data_mut()`, `len`, `total_len`, `headroom`, `tailroom`,
    `copy_to`.
  - **Zero-copy payload:** `attach_static(&'static [u8])` adds one external segment
    after the linear data, for example a flash-resident asset sent sendfile-style.
    `linearize()` copies it into the block for devices without `SG`.
- `PacketMeta` fields: `ifindex`, `prio` (0–7; ≥ 4 selects the high TX band),
  `csum: CsumState` (`None`/`Verified`/`Bad`), `vlan`, `timestamp` (RX tick), `peer`
  (address and port for socket datagrams) and `ct_mark` (connection state stamped by
  the firewall's `ConnTrack`).

## The driver contract (`net::device`)

Drivers come in two tiers.

**Ring drivers** implement `NetDevice`, an iflib-lite contract. The core owns batching,
refill, reclaim, checksum fallback, hooks and statistics. The driver only moves owned
`PacketBuf`s between its descriptor rings and the core.

```rust
pub trait NetDevice: Sync {
    fn info(&self) -> NetDevInfo;           // name, mtu, caps: NetCaps, rx_ring (descriptors to keep posted)
    fn hw_addr(&self) -> HwAddr;
    fn open(&self) -> Result<(), Error>;    // called by net::register
    fn stop(&self);                         // release every buffer held in the rings
    fn link(&self) -> LinkState;
    fn set_rx_filter(&self, f: RxFilter) -> Result<(), Error>;   // default Unsupported
    fn timer(&self);                        // housekeeping hook, called once per interface per poll round
    fn irq_enable(&self, on: bool);         // NAPI-style: core re-enables after a non-exhausted poll
    fn rx_refill(&self, buf: PacketBuf) -> Result<(), PacketBuf>;  // post an empty buffer
    fn rx_poll(&self) -> Option<PacketBuf>;                        // next completed RX
    fn tx_encap(&self, pkt: PacketBuf) -> Result<(), PacketBuf>;   // queue one TX; Err = ring full
    fn tx_flush(&self);                     // doorbell, once per batch
    fn tx_reclaim(&self) -> usize;          // release completed TX buffers
    fn hooks(&self) -> &'static [&'static dyn PacketHook];         // driver's own hooks (innermost)
}
```

**Frame drivers** implement the much simpler `FrameDevice` (`info`, `hw_addr`, `link`,
`recv(&mut [u8]) -> Option<usize>`, `send(&[u8])`, `stop`, `hooks`). They suit SPI and
UART Ethernet chips, radios and simulators. Wrap one in `SoftRing<F, N>` to get a
`NetDevice`; the posted RX buffers live in an `N`-deep software queue.

`NetCaps` bits are: `TX_CSUM_IPV4`, `TX_CSUM_L4`, `RX_CSUM`, `SG`, `VLAN_INSERT`,
`VLAN_STRIP`, `MCAST_FILTER`, `PROMISC` and `HW_TIMESTAMP`. `ALL_CSUM` is the three
checksum bits together. Only the checksum bits and `SG` affect the core today.

Bundled network drivers (`net::drivers`):

| driver | tier | notes |
|--------|------|-------|
| `Loopback<N>` | ring | Transmitted buffers come straight back as received packets (a buffer swap). It claims `ALL_CSUM \| SG` and posts no RX ring. |
| `Wire` + `WireEnd` | frame | A simulated Ethernet cable between two interfaces, with a private 32-block pool. Fault injection: `set_link`, `drop_every(n)`, `corrupt_next(n)`; counters `frames` and `lost`. `WireEnd::with_caps` fakes hardware offloads. |

## Registering interfaces and starting the net task

```rust
static WIRE: Wire = Wire::new();
static ETH0: SoftRing<WireEnd, 4> = SoftRing::new(WireEnd::new(&WIRE, 0, [2, 0, 0, 0, 0, 1]));

let idx = net::register("eth0", &ETH0)?;   // also creates /dev/eth0 (control plane)
ip::configure(idx, IpConfig { addr: [10, 0, 0, 1], prefix_len: 24, gateway: None })?;
net::start()?;                              // spawn the `net` task; configure IP first
```

`net::register` calls `dev.open()` and registers a control device `/dev/<name>`. That
device's driver middleware is `LinkGuard`. The other interface functions:

| function | purpose |
|----------|---------|
| `net::find(name)` | look an interface up by name |
| `net::info(idx)` | returns `IfInfo`: name, MAC, MTU, link, up, enabled offloads |
| `net::stats(idx)` | returns `IfStats` |
| `net::set_up(idx, up)` | administrative up/down |
| `net::set_offloads(idx, want)` | enables `want ∩ hardware caps` and returns what was enabled |
| `net::control_device(idx)` | the `Device` behind `/dev/<name>` |

`net::start()` spawns the `net` task. It runs at `BISMUTH_NET_PRIORITY` (default 20) on
a static `NET_STACK_SIZE` stack, as a daemon in the kernel domain. IP instances are
created when the task starts, one per interface that has `ip::configure` applied, up to
`NET_IP_IFACES`. **Call `ip::configure` before `net::start`.**

## The net core: one poll round

`Core::round()` (`src/net/mod.rs`) visits every registered interface:

```text
if interface is up:
  RX  refill: keep `info().rx_ring` buffers posted from RX_POOL (pool dry → ring runs short → HW drops)
      poll up to NET_BUDGET packets:
        stamp ifindex + timestamp
        RX_CSUM enabled → meta.csum = Verified
        else software verify: Bad → drop (rx_csum_errors), Good → Verified, NotIp → as is
        hook chain In: global → interface → driver   (Drop → hook_drops; Consumed → gone)
        dispatch: registered NetNode for the EtherType
                  else IPv4/ARP to the IP stack's queue (if IP configured; full → rx_dropped)
                  else rx_no_proto
      budget used up → rx_budget_exhausted++, more work; else irq_enable(true)
  TX  up to NET_BUDGET: the parked packet first, then band 0 (prio ≥ 4), then band 1
        hook chain Out: global → interface → driver
        linearize if there is an external segment and (no SG, or L4 checksum done in software)
        fill IPv4 / L4 checksums in software for whatever is not offloaded
        tx_encap; ring full → park the packet and retry first next round
      tx_flush() once if anything was sent (doorbell batching)
timer() then tx_reclaim() on every interface (also while it is down, so link polling keeps running)
```

The task loop with `net-ip`, in `ip::run`, does the following:

1. A core round.
2. Socket service, which moves commands and data between application queues and
   smoltcp.
3. A smoltcp poll on each instance.
4. A second socket service and a second core round.
5. A sleep until notified or until smoltcp's next deadline (`poll_delay`). While socket
   data is waiting for pool or buffer space, the wait is 1 tick instead of a spin.

`net::transmit(idx, pkt)` queues a complete Ethernet frame into the interface's band 0
or 1 (each `NET_TXQ_LEN` deep) and wakes the net task. If the queue is full, it counts
`tx_dropped` and returns `Err((error, pkt))`.

`IfStats` counters:

| group | counters |
|-------|----------|
| receive | `rx_packets`, `rx_bytes`, `rx_dropped`, `rx_csum_errors`, `rx_no_proto`, `rx_budget_exhausted` |
| transmit | `tx_packets`, `tx_bytes`, `tx_dropped` |
| hooks | `hook_drops` |

### Checksums (`net::csum`)

`checksum` and `sum` implement RFC 1071. `verify_frame(frame) -> Check::{NotIp, Good,
Bad}` and `fill_frame(frame, Fill { ipv4, l4 })` handle IPv4 with ICMP/UDP/TCP and skip
one VLAN tag. `ethertype(frame)` and `l4_dst_port(frame)` are used by the hook matchers.
IPv6 is not handled.

## Packet hooks (`net::hook`)

```rust
pub trait PacketHook: Sync {
    fn name(&self) -> &'static str;
    fn on_packet(&self, dir: Dir, ifindex: IfIndex, pkt: PacketBuf) -> Verdict; // Pass(pkt) | Drop | Consumed
}
```

Attach hooks with:

- `net::attach_hook(idx, Dir::In | Dir::Out, &HOOK)` and `detach_hook(idx, dir, name)`
  for one interface, up to `MAX_LAYERS` per direction;
- `net::add_global_hook(dir, &HOOK)` for every interface (there is no global removal);
- `NetDevice::hooks()` for hooks a driver contributes.

Order: global → interface → driver, in both directions.

Built-in hooks:

| hook | behaviour |
|------|-----------|
| `Counter::new(name)` | packets and bytes per direction (`packets(dir)`) |
| `Firewall::<N>::deny(dir, [Match; N])` | drops matching packets in one direction; `dropped` counter |
| `RateLimit::new(dir, max_packets, window_ticks)` | per-window packet cap (DoS protection); `dropped` counter |
| `Steer::new(Match, &'static dyn RingSink)` | inbound matches go to a `NetRing` (`Consumed`); a full ring gives `Drop` |

`Match` can be `EtherType(u16)`, `UdpDstPort(u16)` or `TcpDstPort(u16)`.

For real packet filtering, with prefixes, port ranges, first-match rule chains, a
default policy, connection state and iptables/pf-style builders, use `net::filter`
(feature `net-filter`). See [firewall](firewall.md).

## Zero-copy rings (`net::NetRing`)

`NetRing<N>` hands *ownership* of pool-backed packets between the net task and an
application task, with no copies:

- `recv(timeout)` takes the next packet;
- `recv_batch(&mut [Option<PacketBuf>])` takes whatever is queued, without waiting;
- `transmit(ifindex, pkt)` forwards the same buffer back out (buffer-swap forwarding);
- `delivered()` and `overruns()` are counters.

Packets enter a ring through a `Steer` hook. `NetRing` implements `RingSink`.

## Protocol nodes

`NetNode { name, receive(ifindex, pkt) }` handles every received frame of one EtherType
in place of the IP stack. Register one with `net::register_protocol(ethertype, &NODE)`
(at most 8, and `Exists` for a duplicate EtherType). Nodes run in the net task and can
reply with `net::transmit`.

## IP stack and sockets (`net-ip`)

`net::ip` wraps **smoltcp 0.14**, which is itself `#![deny(unsafe_code)]`. Enabled
features: Ethernet medium, IPv4 (with ARP), and UDP, TCP and ICMP sockets. smoltcp
answers ICMP echo itself; there is no ICMP socket API. Configure an interface with
`ip::configure(idx, IpConfig { addr, prefix_len, gateway })`.

- smoltcp checksums are switched off (`ChecksumCapabilities::ignored()`) because the
  core verifies and fills them.
- smoltcp's `random_seed` (TCP initial sequence numbers and so on) comes from the
  kernel domain's CSPRNG when `crypto` is enabled and seeded. Otherwise it falls back to
  `MAC ^ ticks`, which is predictable, so seed the entropy pool before `net::start` on
  real deployments.
- If `TX_POOL` is exhausted, a frame smoltcp emits is built into scratch space and
  dropped, the same as a full hardware ring.

Socket API (`net::socket`). Applications never touch smoltcp. A bounded command queue
(16 entries) carries bind, connect, listen and close requests, and per-socket event
flags answer them. Data moves as `PacketBuf`s from `APP_POOL` through per-socket queues,
4 packets each way, so a slow reader applies TCP flow control.

| type | API |
|------|-----|
| `UdpSocket` | `bind(port)` (0 = ephemeral, starting at 49152), `bind_on(idx, port)`, `send_to(data, addr)` (≤ 1472 bytes, one block), `recv_from(buf, timeout)` (excess bytes are discarded), `local_port`; closed on drop |
| `TcpStream` | `connect(addr, timeout)`, `connect_on(idx, ..)`, `read(buf, timeout)` (`Ok(0)` = peer closed), `write(data, timeout)` (accepts at most one 1536-byte block per call), `write_all`, `is_connected`, `close` (graceful; also on drop) |
| `TcpListener` | `bind(port)`, `bind_on`, `accept(timeout)` (re-arms itself on a fresh socket), `local_port` |

Each IP interface has `NET_UDP_SOCKETS + NET_TCP_SOCKETS` socket slots. A listener uses
one TCP slot while armed. Every bind, connect and listen first passes the calling
domain's network policy (`security::check_net`; see [security](security.md#network-policy)).
BSD sockets on top of this API are described in the [POSIX guide](../guides/posix.md#sockets).

## Control plane: `/dev/<ifname>`

`/dev/<ifname>` is a `DeviceClass::Net` device with the usual middleware chain, so user
layers such as `Stats` or `Trace` work. `Op::Write(frame)` copies the frame into a
`TX_POOL` block and transmits it; `LinkGuard` refuses this while the interface is down
or has no link. `Op::Power(On/other)` sets the interface up or down. Ioctls:
`NET_GET_MTU`, `NET_GET_HWADDR`, `NET_GET_LINK`, `NET_SET_UP`, `NET_GET_OFFLOADS`,
`NET_SET_OFFLOADS`, `NET_GET_RX_PACKETS`, `NET_GET_TX_PACKETS`, `NET_GET_RX_DROPPED`
(which sums `rx_dropped`, `rx_csum_errors` and `hook_drops`). See the
[ioctl reference](../reference/ioctl.md#network-interfaces-0x05xx).

## Configuration knobs

All are build-time `BISMUTH_*` variables; see [configuration](../reference/configuration.md).

| variable | MCU default | host default | meaning |
|----------|------------:|-------------:|---------|
| `MAX_NETIFS` | 4 | 4 | interfaces |
| `NET_RX_BUFS` / `NET_TX_BUFS` / `NET_APP_BUFS` | 6 / 6 / 6 | 32 / 32 / 32 | blocks per pool (1600 B each) |
| `NET_BUDGET` | 16 | 16 | packets per interface per direction per round |
| `NET_TXQ_LEN` | 8 | 8 | depth of each of the two TX bands |
| `NET_IP_RXQ` | 8 | 8 | per-interface queue into the IP stack |
| `NET_IP_IFACES` | 1 | 2 | IP stack instances |
| `NET_UDP_SOCKETS` / `NET_TCP_SOCKETS` | 2 / 2 | 4 / 4 | sockets per IP instance |
| `NET_SOCKET_BUF` | 1024 | 4096 | bytes of RX and of TX buffer per socket |
| `NET_STACK_SIZE` | 16384 | 4096 | net task stack (holds smoltcp socket storage on MCUs) |
| `NET_PRIORITY` | 20 | 20 | net task priority |

**RAM estimate (MCU defaults).** The pools take 18 × 1600 B ≈ 28 KiB. The net task
stack takes 16 KiB, and the socket buffers in it are 4 sockets × 2 × 1 KiB = 8 KiB.
That is too much for a 64 KiB part such as the LM3S6965. The QEMU demo is built with
`default-features = false, features = ["edge"]`, so it has no networking at all. Shrink
the pools and the stack for small parts.

## As built vs. the research proposal

| research proposal | as built |
|-------------------|----------|
| `PacketBuf` + `PacketRef`, refcounted chains, `Storage::{Pool, Static, Ext}` | single-owner `PacketBuf`; one block plus at most **one** `'static` external segment; no refcounting or cloning, no multi-block chains |
| SPSC rings | kernel `Queue`s (TX bands, `SoftRing`, `NetRing`, socket queues) |
| netif core with link timer | built: `NetDevice::timer()` is called once per interface per poll round. `set_rx_filter()` is part of the trait, but the core never calls it yet (**Planned**). |
| host TAP / mock device | `Loopback` and the simulated `Wire` (no TAP) |
| smoltcp with DHCPv4 and DNS; `embedded-nal` adapters | IPv4, ARP, ICMP echo, UDP and TCP with static configuration. DHCP, DNS, IPv6 and `embedded-nal` are **Planned**. |
| real MAC drivers (STM32 ETH, W5500/ENC28J60), MDIO/PHY, cache and DMA hygiene (P3) | **Planned.** No hardware network driver ships yet. |
| hook heads LinkIn/Out and IP In/Out, pcap tap | link-level In/Out only; built-in counter, firewall, rate limit and steer hooks; pcap tap **Planned** |
| POSIX: socket fds, `poll`/`select`, `getaddrinfo` | socket fds and `poll`; `select` and `getaddrinfo` are **Planned** |
| NetRing with batch sync and an MPU window | queue-based ring with batch receive and forward; the MPU window is **Planned** (with hardware isolation) |
| netgraph-lite with `net_graph!` static wiring, vlan/bridge/tee/6LoWPAN nodes | `NetNode` per EtherType only; the static graph and its nodes are **Planned** |
| VLAN offloads, HW timestamping, TSN, TLS (P8) | the capability bits exist but are unused; the rest is **Planned** |

## Security interplay

- Socket bind, connect and listen are checked against the calling domain's `NetPolicy`.
- `/dev/<ifname>` requests from isolated domains go through `DeviceCap` like any device.
  Configuration ioctls need `CONFIG`; queries need `CONTROL`.
- The interface-management functions require a **trusted** caller; others get
  `PermissionDenied`. They are `net::register`, `set_up`, `set_offloads`,
  `attach_hook`, `add_global_hook` and `register_protocol`.
- `net::transmit` (and `NetRing::transmit`) stays callable from any domain on purpose,
  because it is the data path used by sockets and rings. `detach_hook` has no check.
