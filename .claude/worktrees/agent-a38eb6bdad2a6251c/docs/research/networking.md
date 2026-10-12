# Bismuth Network Subsystem: Research and Design Recommendation

> Status: research and design proposal, not yet implemented.
> Scope: what makes FreeBSD networking fast and well-structured, how it compares with Linux, what MCU-class stacks do, and a design for Bismuth's `net` subsystem that fits Cortex-M / RISC-V MCUs with tens to hundreds of KB of RAM, static allocation, no MMU, and the existing `Driver` / `Middleware` / compat-layer model.

---

## 0. TL;DR

- **Driver contract: take iflib's split, not `net_device_ops`.** FreeBSD's iflib turns a NIC driver into two small vtables. `ifdi_*` handles the control plane: init, stop, MTU, multicast, interrupt enable. `isc_*` handles descriptor rings: `txd_encap`, `txd_flush`, `txd_credits_update`, `rxd_available`, `rxd_pkt_get`, `rxd_refill`, `rxd_flush`. The framework owns buffers, batching, budgets, and queue state. On an MCU this shrinks an Ethernet MAC driver to a few hundred lines and keeps the policy in one shared place.
- **Packet buffer: an mbuf/pbuf hybrid sized for MCUs.** A small fixed header points into fixed-size, pool-allocated data blocks. Blocks have reserved headroom, a refcount, optional chaining, and a "foreign/external" variant (mbuf `EXT_EXTREF`) for zero-copy DMA, flash, or app memory. Everything is allocated from Bismuth's fixed-block memory pools, which play the role of UMA zones.
- **RX model: NAPI / iflib-style.** The ISR masks the queue interrupt and notifies a net task. The net task polls with a budget, then re-enables the interrupt. This is the biggest win on MCUs too: no packet processing in ISR context, bounded latency, and natural batching.
- **TX path: per-queue software rings, no qdisc zoo.** Use one lock-free SPSC/MPSC ring per HW queue (iflib's `mp_ring` idea) with doorbell coalescing (`txd_flush` once per batch). Add an optional strict-priority 2-band scheduler.
- **Offload flags with software fallback.** Use a `NetCaps` bitflag set (IPv4/L4 checksum TX/RX, VLAN tag, CRC, scatter-gather, …). The stack consults it and fills in software when it is absent, like Linux `NETIF_F_*` and FreeBSD `IFCAP_*` / `CSUM_*`. Do not copy TSO/LRO/GSO.
- **Early hook: pfil/XDP-like `PacketHook` chain.** It is a separate, batch-oriented, data-plane sibling of `Middleware`. The per-request `Middleware` chain stays on the control plane (ioctl-like `Request`s) and slow paths.
- **Composable protocol nodes: a static netgraph-lite.** Nodes with typed hooks are wired at build time (const tables), for example `eth → vlan → ipv4 → udp → coap → app`. This is how 6LoWPAN, CAN-over-IP, or a custom edge protocol plug in without forking the stack.
- **Zero-copy rings for edge-compute apps: netmap-lite.** An app task can attach to a NIC queue (or a hook verdict) and get a shared ring of buffer indices into the same pool. There is no copy, and no socket stack on that path.
- **Upper layers.** Wrap smoltcp as the default L3/L4 engine, behind Bismuth's own `NetDevice`/buffer model. A Bismuth socket API sits on top, and POSIX (`socket/bind/send/recv/poll`) plus FreeRTOS-Plus-TCP-style C APIs are compat shims over it, the same way `/dev/<name>` is a shim over `Driver`.
- **Do not copy:** VNET, the full netisr thread pool, RSS/multi-queue as a hard requirement, epoch reclamation as a general mechanism, pluggable TCP stacks (RACK/BBR) at runtime, kTLS/sendfile page machinery, page_pool/IOMMU DMA mapping, qdisc hierarchy, GSO/TSO/LRO, or netgraph's runtime-reconfigurable node graph with string-addressed control messages.

---

## 1. What makes FreeBSD networking fast and well-structured

### 1.1 mbufs, clusters, and external storage

The `mbuf` is FreeBSD's universal packet container ([mbuf(9)][mbuf9]). Its key properties:

- **Small fixed header plus inline data.** An `MSIZE` (256 B) object holds either `MLEN` bytes of data or, with `M_PKTHDR`, `MHLEN` bytes plus a packet header. The packet header holds total length, rcvif, flowid/RSS hash, `csum_flags`/`csum_data`, VLAN tag, and tags.
- **External storage (`M_EXT`).** Bigger payloads live in *clusters* (`EXT_CLUSTER`, 2 KB) or jumbo clusters (`EXT_JUMBOP` page / `EXT_JUMBO9` / `EXT_JUMBO16`). Other external types include `EXT_SFBUF` (sendfile pages), `EXT_RXRING` (NIC RX ring data), `EXT_PGS` / `M_EXTPG` (arrays of *unmapped* physical pages, used by kTLS and sendfile), and `EXT_EXTREF`, external storage with a caller-supplied refcount and free function. This is the hook for zero-copy foreign memory.
- **Refcounted, copy-on-write sharing.** `m_copym` / `m_copypacket` share clusters by bumping refcounts and produce read-only views. `M_WRITABLE` checks that refcount ≤ 1. `m_unshare` / `m_dup` produce writable copies.
- **Chaining.** `m_next` links buffers within a packet and `m_nextpkt` links packets in a queue. Batches are just mbuf lists.
- **Header manipulation without copies.** `M_PREPEND` uses *leading space*. Drivers and protocols leave headroom so lower layers can push headers in place. `m_pullup` makes the first N bytes contiguous for header parsing. `m_devget` copies from device memory when DMA is not possible.
- **Offload metadata in the packet.** On TX, `CSUM_IP`, `CSUM_TCP`, `CSUM_UDP`, and `CSUM_TSO` ask the driver/HW to finish the checksum or segmentation. Anything unsupported is done in software first. On RX, `CSUM_IP_CHECKED`, `CSUM_IP_VALID`, `CSUM_DATA_VALID`, and `CSUM_PSEUDO_HDR` report verification results so the stack skips its own checksum.

### 1.2 UMA, the zone slab allocator

All mbufs, clusters, sockets, PCBs, and so on come from UMA zones ([uma(9)][uma9]). Fixed-size object caches have **per-CPU buckets**, so allocation and free are lock-free on the fast path, plus NUMA-aware domains. *Packet zones* (`zone_pack`) cache mbuf+cluster pairs that are pre-attached, so the RX refill path costs one allocation instead of two. `uma_zcreate` constructor/destructor and init/fini hooks let objects keep expensive state (for example DMA maps) across reuse. **Takeaway for Bismuth:** fixed-size pools with "pre-constructed" objects are what make packet allocation O(1) and predictable. That is exactly Bismuth's fixed-block memory pool primitive.

### 1.3 ifnet and the `if_*` API

`struct ifnet` ([ifnet(9)][ifnet9]) is the generic interface object. The driver hands the stack packets via `if_input(ifp, m)`. The stack hands the driver packets via `if_transmit(ifp, m)`, which replaced the old `if_start` + `if_snd` single queue so drivers could own multi-queue TX. Capability negotiation uses `if_capabilities` / `if_capenable` (`IFCAP_TXCSUM`, `IFCAP_RXCSUM`, `IFCAP_TSO4/6`, `IFCAP_LRO`, `IFCAP_VLAN_HWTAGGING`, `IFCAP_NETMAP`, `IFCAP_TXRTLMT`, `IFCAP_TXTLS`, …) plus `if_hwassist` (which CSUM_* the HW does). Since FreeBSD 14, `ifnet` is opaque to drivers (`if_t` accessors), which makes it a more stable driver API than Linux's.

### 1.4 iflib, the shared NIC driver framework

iflib ([iflib(9)][iflib9], [iflibdd(9)][iflibdd9], [iflibtxrx(9)][iflibtxrx9], [iflib(4)][iflib4]) is the most relevant FreeBSD idea for Bismuth. It was written because every NIC driver re-implemented the same queue, interrupt, buffer, and netmap logic. iflib owns that logic. The driver supplies:

**Device-dependent (`ifdi_*`, via kobj `DEVMETHOD`s):**
- Lifecycle: `ifdi_attach_pre`, `ifdi_attach_post`, `ifdi_detach`, `ifdi_suspend`, `ifdi_resume`.
- Queues: `ifdi_tx_queues_alloc`, `ifdi_rx_queues_alloc`, `ifdi_queues_free`, optional `ifdi_txq_setup` / `ifdi_rxq_setup`.
- Config: `ifdi_init`, `ifdi_stop`, `ifdi_mtu_set`, `ifdi_multi_set`, `ifdi_promisc_set`, `ifdi_media_status`, `ifdi_media_change`, `ifdi_get_counter`, `ifdi_update_admin_status`.
- Interrupts: `ifdi_intr_enable`, `ifdi_intr_disable`, `ifdi_queue_intr_enable`, `ifdi_link_intr_enable`.
- Service: `ifdi_timer` (~500 ms), `ifdi_watchdog_reset`.

**Ring ops (`struct if_txrx`, the `isc_*` function pointers):**

| op | meaning |
|---|---|
| `isc_txd_encap(sc, if_pkt_info_t pi)` | write descriptors for one packet (segments, offload info) |
| `isc_txd_flush(sc, qid, pidx)` | ring the TX doorbell, called once per batch |
| `isc_txd_credits_update(sc, qid, clear)` | how many descriptors HW has completed (reclaim) |
| `isc_rxd_available(sc, qid, cidx, budget)` | how many RX descriptors are ready |
| `isc_rxd_pkt_get(sc, if_rxd_info_t ri)` | describe one received packet (len, frags, csum, flowid, vlan) |
| `isc_rxd_refill(sc, iru)` | post fresh buffers (paddrs) to the free list |
| `isc_rxd_flush(sc, qid, flid, pidx)` | ring the RX free-list doorbell |

`if_pkt_info` carries `ipi_len`, `ipi_segs`/`ipi_nsegs`, `ipi_qsidx`, `ipi_pidx`/`ipi_new_pidx`, `ipi_csum_flags`, `ipi_tso_segsz`, `ipi_vtag`, and header lengths (`ipi_ehdrlen`, `ipi_ip_hlen`, `ipi_tcp_hlen`, `ipi_ipproto`). `if_rxd_info` carries `iri_len`, `iri_frags`, `iri_flowid`, `iri_rsstype`, `iri_csum_flags`/`iri_csum_data`, `iri_vtag`, and `iri_qsidx`.

**Static description (`if_shared_ctx` / `if_softc_ctx`, `isc_*` fields):** number of queue sets (`isc_ntxqsets`, `isc_nrxqsets`), ring sizes (`isc_ntxd[]`, `isc_nrxd[]`), descriptor sizes, max segments, TSO limits, `isc_capabilities`, and MSI-X vectors.

**What iflib does for the driver:** buffer allocation and refill, DMA mapping, `mp_ring`-based lock-free multi-producer TX queues, interrupt → `gtaskqueue` deferred processing with budgets (the NAPI equivalent), TX reclaim, LRO, **netmap support for free** (iflib implements the netmap adapter generically on top of the same `isc_*` ops), and sysctls and stats. Intel em/igb/ix/ixl/ice, Broadcom bnxt, Chelsio vcxgbe, vmxnet3, and others moved to it. **The pattern is "driver = ring accessor, framework = policy."**

### 1.5 netmap, zero-copy userspace rings

netmap ([netmap(4)][netmap4], [Rizzo, USENIX ATC 2012][netmap-atc]) maps NIC rings and a pre-allocated buffer pool into a process. Packet buffers are fixed-size and **indexed** rather than pointer-addressed. Ring slots hold `{buf_idx, len, flags}`. Apps advance `head`/`cur`, and the kernel advances `tail`. A syscall (`NIOCTXSYNC` / `NIOCRXSYNC`, or `poll`/`kqueue`) does a *batched* sync of many slots. Zero-copy forwarding between ports is done by **swapping buffer indices** between rings (`NS_BUF_CHANGED`). VALE and `ptnet` extend it to software switches and VMs. Netmap reaches line-rate 10G (14.88 Mpps) on one core because it does no per-packet allocation, no metadata, and batched syscalls. **Design lesson for MCUs:** index-addressed fixed buffers plus SPSC head/tail rings plus batch sync is cheap and works without an MMU. In a single address space, "mapping into userspace" becomes "lending ring ownership to a task".

### 1.6 netisr and direct dispatch

netisr ([netisr(9)][netisr9]) is the protocol-dispatch layer between `if_input` and the protocols. It supports `NETISR_DISPATCH_DIRECT` (process in the caller's context, which is the RX taskqueue thread), `DEFERRED` (queue to a netisr thread), and `HYBRID`. Packets are steered to CPUs by `flowid` under policies `NETISR_POLICY_SOURCE`, `FLOW`, or `CPU`. Since FreeBSD 9 or so, IPv4/IPv6 default to **direct dispatch**. One context runs driver RX → IP → TCP → socket buffer without queue handoffs, which is better for cache and latency. **For Bismuth:** direct dispatch in the net task is the default. A deferred queue exists only for re-entrancy (loopback, tunnels) and for handing off to a lower-priority task.

### 1.7 RSS and per-CPU queues

With `options RSS` ([rss(9) overview / FreeBSD wiki][rss]), NICs hash flows with Toeplitz into queues. Each queue's interrupt or taskqueue is bound to a CPU. `flowid` / `M_HASHTYPE` travel with the mbuf. The PCB lookup (`in_pcbgroup`, later RSS-aware lookups), netisr, and TCP timers can all stay on the same CPU, so a flow is touched by one core with no lock contention. **For Bismuth:** mostly irrelevant, because MCUs are single-core or use AMP dual-cores. Keep `flow_hash: u32` in packet metadata anyway. It is useful for demuxing to app rings and for priority, and it is free when the MAC computes it.

### 1.8 net_epoch, lockless read-side reclamation

The network stack enters `net_epoch` (`NET_EPOCH_ENTER(et)` / `NET_EPOCH_EXIT`) around the RX/TX fast paths ([epoch(9)][epoch9]; Matt Macy / Gleb Smirnoff, FreeBSD 12–13). Inside the epoch, readers traverse interface lists, address lists, routing nexthops, and PCB hash chains **without locks**, using CK (Concurrency Kit) lists. Writers unlink entries and free them with `epoch_call()` after a grace period. Entering an epoch never blocks and has no lock ordering. FreeBSD 13 removed most `IF_ADDR_RLOCK`/`INP_INFO_RLOCK` read locks this way, which gave large gains in contention-heavy forwarding. **For Bismuth:** the *idea* matters (readers on the hot path take no lock, and config changes are copy-on-write and published atomically). On single-core MCUs a much simpler scheme achieves it: config is mutated only from the net task, or published as an `AtomicPtr` to a pool block with a generation counter. A general epoch/RCU facility is not worth the code.

### 1.9 pfil hooks

pfil ([pfil(9)][pfil9]) is the packet filter hook framework that ipfw, pf, and ipfilter attach to. *Heads* are registered at points such as link (Ethernet), inet, and inet6, in and out. *Hooks* are added in an ordered list. Each hook returns a verdict: `PFIL_PASS`, `PFIL_DROPPED`, `PFIL_CONSUMED`, or `PFIL_REALLOCED`. FreeBSD 13 redesigned pfil to be epoch-protected (lockless traversal) and to support **`pfil_mem_in`**. Drivers and iflib can run the link-level hook **on raw RX buffer memory before an mbuf is even allocated**. That is FreeBSD's answer to XDP: drop and DoS filtering at near-zero cost. **For Bismuth:** this is the template for the `PacketHook` chain (§4.5), including running it on raw DMA buffers before any metadata is built.

### 1.10 Modular TCP stacks (tcp_function_block), RACK, BBR

FreeBSD can host **multiple complete TCP implementations at once** ([tcp_functions(9)][tcpfunc], [tcp_rack(4)][rack4], [tcp_bbr(4)][bbr4]). A `struct tcp_function_block` contains the function pointers `tfb_tcp_output`, `tfb_do_segment`, `tfb_tcp_timer_*`, `tfb_tcp_fb_init`/`fini`, `tfb_tcp_ctloutput`, and so on. Stacks are registered with `register_tcp_functions()`. They are selected system-wide (`net.inet.tcp.functions_default`) or per socket (`setsockopt(TCP_FUNCTION_BLK)`), and a connection can even be switched mid-life. Netflix built RACK (RFC 8985 loss detection, pacing) and BBR this way and runs them in production. Congestion control is separately pluggable via `cc(4)` modules (newreno, cubic, htcp, …). **For Bismuth:** the lesson is "protocol engines behind a function table". A runtime-switchable multi-TCP is not worth it on an MCU. A compile-time choice of L4 engine (smoltcp TCP vs. a minimal TCP vs. none) behind a trait is.

### 1.11 sendfile, kTLS, and Netflix's 400/800 Gb/s

Netflix serves ~400 Gb/s (2021) and ~800 Gb/s (2022) of TLS video from single FreeBSD boxes ([Gallatin EuroBSDCon 2021][nf400], [EuroBSDCon 2022][nf800], [NUMA 2019][nfnuma]). The ingredients:

- **Asynchronous `sendfile(2)`** ("new sendfile", Gleb Smirnoff). It attaches page-cache pages directly as unmapped mbufs (`M_EXTPG`) and does not block on disk I/O. Completion of the page-in triggers the send. The data never enters user space and is never copied ([sendfile(2)][sendfile2]).
- **kTLS** ([ktls(4)][ktls4]). TLS record framing and encryption happen in the kernel (software) or on the NIC (`IFCAP_TXTLS`, Mellanox ConnectX-6 Dx). Encrypted data flows from page cache to NIC with memory bandwidth used once (or zero times for the CPU with NIC kTLS).
- **Unmapped mbufs** that avoid kernel VA mapping and TLB costs.
- **NUMA locality**: allocate buffers, crypto, and connections on the NIC's domain, with "backing store" domain affinity. LACP egress chooses the NUMA-local port.
- **TCP stack choice (RACK/BBR) with pacing**, plus TSO/LRO and large send buffers.

**Lesson:** the fastest byte is the one never copied or touched. Data stays in a refcounted external buffer from source to wire, and headers are prepended in front of it. This *does* translate to MCUs: send from flash, a sensor DMA buffer, or a const slice with only a header block allocated.

### 1.12 kqueue

`kqueue(2)` / `kevent` ([kqueue(2)][kqueue2]) is an O(1)-per-event, edge- or level-triggered event notification API. A single call both registers changes and harvests events, so batching is built in. Filters cover sockets (`EVFILT_READ`/`WRITE` with low-water marks), files, processes, signals, timers, and user events. It is far more scalable than `select`/`poll`. **For Bismuth:** model the socket readiness API as an event-flag-group-per-socket-set (Bismuth already has event flags). It is a natural kqueue analogue and backs `poll()` in the POSIX shim.

### 1.13 VNET

VNET ([vnet(9)][vnet9]) virtualizes the entire network stack per jail. Every global becomes `VNET_DEFINE(...)` in a per-vnet data region, accessed through `curvnet`. It is powerful for containers. **For Bismuth:** do not copy it (see §6).

### 1.14 netgraph

netgraph ([netgraph(4)][netgraph4], [Elischer & Cobbs / Whistle 1999 paper][netgraph-daemon]) is a graph of **nodes** (types such as `ng_ether`, `ng_vlan`, `ng_bpf`, `ng_ppp`, `ng_mppc`, `ng_ksocket`, `ng_tee`, `ng_bridge`, `ng_l2tp`, `ng_nat`, `ng_netflow`, …) connected through named **hooks**. Data items (mbufs) flow along edges with `NG_SEND_DATA`. Control messages (`ng_mesg`) are addressed by path and configure nodes. The graph is built at runtime with `ngctl`. Each node type is a small module with a fixed set of methods: `constructor`, `rcvmsg`, `newhook`, `rcvdata`, `disconnect`, `shutdown`. Its strengths are composability and protocol experimentation without touching the core stack. It is how FreeBSD did PPPoE, L2TP, ATM, and Bluetooth. **For Bismuth:** keep the node/hook abstraction and the "protocol = small node with `rcv_data`" idea, but make the graph *static* (const-built) with typed edges (§4.7).

### 1.15 Other things that matter

- **LRO / TSO / software segmentation (`tcp_lro`, `tcp_lro_queue_mbuf` with sorting)**: on servers these reduce per-packet costs. They are irrelevant at MCU link speeds.
- **`mp_ring` / `buf_ring(9)`**: lock-free multi-producer rings used by drivers for TX ([buf_ring(9)][bufring9]).
- **`if_snd_tag` / send tags**: per-flow offload tags for rate-limiting and kTLS. These are a model for "per-flow HW resources" if a future MCU MAC has, say, a time-aware shaper for TSN.
- **BPF** ([bpf(4)][bpf4]): the tap point for `tcpdump`. Cheap tap hooks are invaluable for debugging embedded networking too.
- **Driver API stability**: `if_t` opacity plus iflib gives a stabler driver contract than Linux. That matches Bismuth's goal of third-party drivers.

---

## 2. Linux vs FreeBSD on each design axis

| Axis | Linux | FreeBSD | Better fit for Bismuth |
|---|---|---|---|
| **Driver contract** | `net_device` + `net_device_ops` (`ndo_open`/`ndo_stop`/`ndo_start_xmit`/…). Each driver implements full queue/NAPI/buffer logic itself. No stable internal API. | `ifnet` (opaque `if_t`) + `if_transmit`/`if_input`. Modern NICs use **iflib**: the driver supplies only `ifdi_*` control + `isc_*` ring ops, and the framework owns policy. | **FreeBSD/iflib**: a tiny driver surface and shared policy. Use the `ndo_*` naming clarity for the control ops. |
| **Packet buffer** | `sk_buff`: a large (~200+ B) metadata struct with head/data/tail/end pointers into a linear buffer plus `skb_shared_info` frags (page frags). Headroom via `skb_reserve`/`skb_push`. Cloning shares data. | `mbuf`: a 256 B object holding header + small inline data, or `M_EXT` clusters / jumbo / unmapped pages / `EXT_EXTREF`. Chains via `m_next`, refcounted shared clusters. | **Hybrid**: a small header in a pool + fixed-size data blocks with headroom + external variant + chaining. The linear-first common case comes from skb, external refcounted storage from mbuf. |
| **Allocator** | slab/SLUB `kmem_cache`, `page_pool` for RX recycling | UMA zones with per-CPU buckets, packet zone (mbuf+cluster pre-paired) | **Bismuth fixed-block pools** used as UMA zones, with an RX "pre-paired" pool. |
| **RX model** | NAPI: IRQ → `napi_schedule` → softirq poll with budget (64) → `napi_complete_done` re-arms IRQ. GRO aggregation. | iflib: IRQ filter → `gtaskqueue` task polls `rxd_available`/`pkt_get` with budget, then `ifdi_queue_intr_enable`. LRO. Optional `DEVICE_POLLING`. | **Same idea in both**: IRQ masks + notifies the net task, which polls with a budget and re-enables. |
| **Protocol dispatch** | `netif_receive_skb` direct (in softirq); RPS/RFS steer to other CPUs. | netisr direct dispatch by default; deferred/hybrid optional; flowid-based CPU policy. | Direct dispatch in the net task. A deferred queue only for re-entrancy. |
| **TX queueing** | qdisc layer (pfifo_fast, fq, fq_codel, mqprio, HTB, …) above `ndo_start_xmit`. Per-queue `netdev_queue`, BQL (byte queue limits), XPS. | `if_transmit` direct to the driver's per-queue `mp_ring`/`buf_ring`. ALTQ is optional and rarely used. Pacing lives in TCP (RACK/BBR) and HW rate-limit tags. | **FreeBSD**: driver-owned per-queue ring, with optionally a 2-band strict priority. Add a BQL-like in-flight byte cap to bound latency. No qdisc framework. |
| **Offload capabilities** | `NETIF_F_*` features (HW_CSUM, IP_CSUM, SG, TSO, GSO, GRO, RXCSUM, HW_VLAN_*, …). The stack falls back to software (`skb_checksum_help`, GSO segmentation). | `IFCAP_*` (enabled set) + `if_hwassist` + per-packet `CSUM_*` flags. Software fallback in `ip_output`/`tcp_output` (`in_delayed_cksum`). | **Both are equivalent**. Use a single `NetCaps` bitflag + per-packet `csum` metadata, and have the stack do the software fallback. |
| **Shared frameworks** | phylib/MDIO, mac80211/cfg80211, page_pool, ethtool, devlink, XDP, DSA, switchdev | iflib, miibus/mii PHY drivers, net80211, netmap (via iflib), pfil, netgraph, BPF | **iflib + miibus-like PHY layer** (`Mdio` trait + generic PHY), and a small wifi-offload trait for SPI/UART WiFi modules (ESP-AT, Murata, cyw43) that are "full-MAC". |
| **Zero-copy fast path** | XDP (eBPF at driver RX, before skb), AF_XDP (UMEM shared with userspace, fill/completion rings), `MSG_ZEROCOPY`, io_uring zero-copy | netmap (shared rings + buffer index swap), `pfil_mem_in` early hook, async `sendfile` + unmapped mbufs + kTLS | **netmap-style index rings** (simplest, no eBPF), plus an early hook on raw RX buffers (`pfil_mem_in`/XDP). |
| **Extensibility hooks** | netfilter hooks (nftables, iptables), tc ingress/egress BPF, XDP programs | pfil heads/hooks (pf, ipfw), netgraph nodes, pluggable TCP stacks (`tcp_function_block`), cc modules | **pfil-like hook chain** (as data-plane middleware) + **static netgraph-lite nodes** + L4 engine behind a trait. |
| **Concurrency / locking** | RCU throughout (routes, devices, netfilter), per-CPU stats, NAPI single-owner queues, qdisc lock (or lockless qdiscs) | net_epoch (CK lists + epoch_call), per-queue mutexes, RSS-affine processing, `mp_ring` lockless TX | **Single-owner net task** (no locks on the hot path), SPSC rings between ISR, net task, and apps, and copy-on-write config published atomically. |
| **Virtualization** | network namespaces | VNET | Neither (see §6). |
| **Driver distribution** | in-tree, no stable API | in-tree, but iflib/`if_t` give a much more stable contract | Stable, small trait-based contract (Bismuth wants out-of-tree drivers). |

**Summary of "best of both":** take FreeBSD's *structure* (iflib split, mbuf external storage, pfil verdict hooks, netgraph composability, netmap rings, pluggable protocol engines, single-dispatch-context) and Linux's *ergonomics* (NAPI naming/budget semantics, `skb_push`/`skb_pull`-style linear headroom API, feature-flag-with-fallback discipline, BQL latency control, XDP-style early verdicts).

---

## 3. What MCU-class stacks do

### 3.1 smoltcp (Rust, `no_std`)
- **Device trait** ([smoltcp `phy::Device`][smoltcp-device]): `receive(&mut self, ts) -> Option<(RxToken, TxToken)>` and `transmit(&mut self, ts) -> Option<TxToken>`, with `capabilities() -> DeviceCapabilities` (medium, MTU, `max_burst_size`, and `ChecksumCapabilities` per protocol: `Both`/`Tx`/`Rx`/`None`). Tokens use a **closure-based zero-copy lease**. `RxToken::consume(|buf| ...)` and `TxToken::consume(len, |buf| ...)` borrow the driver's own DMA buffer, so the driver keeps buffer ownership and no packet object exists.
- **Interface + SocketSet**: `Interface::poll(ts, &mut device, &mut sockets)` processes everything, with no internal threads. Sockets (TCP/UDP/ICMP/raw/DNS/DHCPv4) have caller-provided ring buffers (`SocketBuffer` over `&mut [u8]` or `Vec`). `poll_delay()` tells you when to poll next. There is no heap requirement.
- **Strengths:** a safe, well-tested TCP; fully static memory; no allocator. **Weaknesses:** no packet object to queue, hold, or inspect, so there is no hook point, no zero-copy across layers, and payload is copied into socket buffers. It is single-threaded by design (you wrap it in a mutex). Checksum offload is the only offload.
- **Implication:** smoltcp is a good *L3/L4 engine* for Bismuth, but it should be fed by Bismuth's own buffer/ring layer, not be the driver model. Bismuth's `NetDevice` → a small adapter that implements `smoltcp::phy::Device` by leasing buffers from the RX ring and TX pool.

### 3.2 lwIP
- **pbuf** ([lwIP pbuf docs][lwip-pbuf]): `PBUF_RAM` (contiguous, heap/pool), `PBUF_POOL` (fixed-size chained pool blocks, the RX default), `PBUF_ROM`/`PBUF_REF` (external/zero-copy references to const or volatile memory), and `PBUF_CUSTOM` (driver-owned with a custom free callback, used for zero-copy RX DMA). It has refcounts, chaining (`next`, `tot_len`), and **layer-based headroom** (`PBUF_TRANSPORT`/`PBUF_IP`/`PBUF_LINK` offsets) via `pbuf_add_header`/`pbuf_remove_header`. It is basically a slimmed-down mbuf.
- **netif** ([lwIP netif][lwip-netif]): `struct netif` with function pointers `input` (stack entry), `output` (IP → link), `linkoutput` (driver TX), `igmp_mac_filter`, and flags; checksum flags (`NETIF_CHECKSUM_GEN_*`/`CHECK_*`) control software checksum per interface. Threading is via `tcpip_thread` (single core-lock owner) + `tcpip_input` mailbox, or `LWIP_TCPIP_CORE_LOCKING`.
- **APIs**: raw/callback API (fastest), netconn (sequential, threaded), and BSD sockets (on top of netconn).
- **Lessons**: the pbuf type taxonomy (pool / RAM / ref / custom) is exactly the right shape for MCUs. The single-owner tcpip thread with a mailbox is the right concurrency model. The pain point is the macro-heavy configuration and C memory unsafety, which Rust fixes.

### 3.3 Zephyr
- **net_if** ([Zephyr net_if][zephyr-netif]): interfaces are bound to an L2 (`NET_L2_INIT`: Ethernet, IEEE 802.15.4, Bluetooth IPSP, CANbus, OpenThread, PPP, virtual, dummy) with `recv`/`send`/`enable`/`get_flags`. The Ethernet driver API is `ethernet_api { iface_api.init, get_capabilities (ETHERNET_HW_TX_CHKSUM_OFFLOAD, HW_VLAN, PTP, TSN qav/qbv, PROMISC, …), set_config, send(dev, net_pkt), get_ptp_clock }`.
- **net_pkt + net_buf** ([net_pkt][zephyr-netpkt], [net_buf][zephyr-netbuf]): a `net_pkt` metadata struct (iface, family, timestamps, priority, …) owns a chain of fixed-size `net_buf` fragments from `NET_BUF_POOL` slabs (static), with headroom and a cursor/access API (`net_pkt_cursor`, `NET_PKT_DATA_ACCESS_DEFINE`) that hides fragmentation from protocol code. Separate RX/TX packet and data pools prevent TX starvation from RX floods.
- **Traffic classes**: configurable RX/TX queues mapped to priority (802.1p), each served by its own thread. This is an MCU-scaled qdisc/RSS. Packet capture, PTP, TSN, socket offload (for modems), and a native POSIX-ish BSD socket API come with it.
- **Lessons**: separate RX/TX pools; a cursor API over fragmented buffers; L2 as a pluggable layer; socket offload for "smart" modems. The trade-off is that its many threads and queues cost RAM, and the config is Kconfig-heavy.

### 3.4 embassy-net
- **`embassy-net-driver::Driver`** ([docs][embassy-driver]): `receive(&mut self, cx: &mut Context) -> Option<(RxToken, TxToken)>`, `transmit(cx) -> Option<TxToken>`, `link_state(cx)`, `capabilities()`, `hardware_address()`. It is smoltcp's token model made **async**: the driver registers the waker from `cx` and wakes the stack runner from its ISR.
- **`embassy-net::Stack` + `Runner`** ([docs][embassy-net]): wraps smoltcp. A single `runner.run().await` task drives `Interface::poll`, and sockets are async (`TcpSocket::read().await`). `StackResources<N>` is static socket storage. `embassy-net-driver-channel` provides a generic channel-based ring between a driver task and the stack, which is a mini-iflib for SPI/UART chips (cyw43, W5500, ESP-hosted).
- **Lessons**: (1) "ISR wakes one stack task which polls everything" is the right MCU model, a cooperative NAPI. (2) A *generic channel/ring adapter* lets simple drivers avoid writing ring logic. (3) Token-closure leases are ergonomic but prevent holding packets, so a real packet type is still needed for hooks, queues, and zero-copy app rings.

---

## 4. Recommended design for Bismuth `net`

### 4.0 Layering overview

```
 ┌──────────────────────────── apps / edge-compute tasks ───────────────────────────┐
 │  POSIX sockets (/dev, fd)   FreeRTOS+TCP-style C API   embedded-nal / embedded-io  │  compat shims
 ├────────────────────────────────────────────────────────────────────────────────────┤
 │  bismuth::net::socket  (TcpSocket/UdpSocket/RawSocket, readiness via event flags)   │
 ├───────────────┬──────────────────────────────────┬─────────────────────────────────┤
 │ L3/L4 engine  │  netgraph-lite protocol nodes    │  NetRing (netmap-lite) zero-copy │
 │ (smoltcp      │  (vlan, 6lowpan, coap, custom…)  │  rings for edge-compute apps     │
 │  adapter)     │                                  │                                 │
 ├───────────────┴──────────────┬───────────────────┴─────────────────────────────────┤
 │  PacketHook chain (pfil/XDP-like, batch verdicts: Pass/Drop/Consume/Redirect)       │
 ├──────────────────────────────┴──────────────────────────────────────────────────────┤
 │  netif core ("iflib-lite"): RX poll w/ budget, refill, TX rings, reclaim, caps,      │
 │  sw offload fallback, stats, link state.  Runs in the `net` task (direct dispatch). │
 ├──────────────────────────────────────────────────────────────────────────────────────┤
 │  NetDevice driver: control ops + ring ops (+ Driver impl for registry/middleware)   │
 │  PacketPool (fixed-block pools): headers, data blocks, ext refs                     │
 └──────────────────────────────────────────────────────────────────────────────────────┘
```

**Two planes, two chains.**
- **Control plane**, low rate: set MAC, MTU, multicast filter, promisc, link up/down, stats, PHY/MDIO, power. It goes through the existing `Driver::handle(&mut Request)` path and therefore the *existing* global → user → driver `Middleware` chain. This gives logging, access control, power gating, and the POSIX `ioctl` / `/dev/eth0` view for free, all consistent with every other Bismuth device.
- **Data plane**, high rate: packets. They do **not** go through `Middleware::call` per packet. A per-packet dynamic `Request` plus chain recursion is too expensive, and middleware semantics (request/response) do not match streaming packets. Instead the data plane has its own `PacketHook` chain, which is batch-oriented and verdict-based (§4.5). Per-device user-attachable hooks mirror the middleware attachment model, so the mental model stays the same.

### 4.1 Packet buffers (`PacketBuf`)

Goals: O(1) static allocation, zero-copy across layers, cheap header push/pop, external memory, chaining when needed, and DMA-friendliness.

```rust
/// One fixed-size data block from a pool. Size chosen per-pool (e.g. 1536 + headroom).
#[repr(C, align(32))]          // cache-line / DMA alignment (configurable)
pub struct Block<const N: usize> { bytes: [u8; N] }

/// Small packet header (~32–40 B), from its own pool. Not the data.
pub struct PacketBuf {
    data: NonNull<u8>,          // start of storage
    cap:  u16,                  // storage capacity
    head: u16,                  // offset of first valid byte (headroom = head)
    len:  u16,                  // valid bytes in this segment
    next: Option<PacketRef>,    // chain (rare on MCUs; jumbo/scatter only)
    storage: Storage,           // where the bytes live + how to free
    pub meta: PacketMeta,
}

pub enum Storage {
    Pool { pool: PoolId, idx: u16 },                    // mbuf cluster / PBUF_POOL
    Static(&'static [u8]),                              // PBUF_ROM: flash/const, read-only
    Ext { rc: &'static AtomicU16, drop: fn(*const ()), ctx: *const () }, // EXT_EXTREF / PBUF_CUSTOM:
                                                        // app/DMA/sensor memory, zero-copy
}

pub struct PacketMeta {
    pub ifindex: u8,
    pub rxq_or_txq: u8,
    pub prio: u8,               // 0..7 (802.1p / traffic class)
    pub flags: PktFlags,        // BCAST, MCAST, VLAN_PRESENT, TIMESTAMP_VALID, ...
    pub csum: CsumState,        // TX: what HW should finish; RX: what HW verified
    pub l2_len: u8, pub l3_len: u8, pub l4_proto: u8,   // filled lazily by parsers
    pub vlan: u16,
    pub flow_hash: u32,         // from HW if available, else lazily computed
    pub timestamp: Option<Instant>, // PTP / latency measurements
}

impl PacketBuf {
    pub fn push_header(&mut self, n: usize) -> Result<&mut [u8], NoHeadroom>; // skb_push / M_PREPEND
    pub fn pull_header(&mut self, n: usize) -> Option<&[u8]>;                 // skb_pull / m_adj
    pub fn contiguous(&mut self, n: usize) -> Result<&[u8], Error>;           // m_pullup
    pub fn payload(&self) -> &[u8];
    pub fn payload_mut(&mut self) -> Option<&mut [u8]>;   // None if shared (refcount>1) or Static
    pub fn share(&self) -> PacketRef;                     // m_copym: refcount bump, read-only
}
```

Rules:
1. **Headroom is configured globally** (`NET_HEADROOM`, for example 64 B = Eth 14 + VLAN 4 + IPv6 40 + pad, or larger with 6LoWPAN/TLS). Every pool block reserves it, so TX never prepends a new block in the common case.
2. **Linear first.** On MCUs one block holds an MTU-size frame, so `next` is `None` 99% of the time. Chaining exists for (a) header-block + `Static`/`Ext` payload zero-copy TX (sendfile-like) and (b) MACs with small RX buffers (some MCUs use 256–512 B descriptors).
3. **Separate pools** for RX blocks, TX blocks, and headers, sized at build time (Zephyr's lesson): an RX flood must not starve TX or sockets. Pools are Bismuth fixed-block pools, statically allocated and placed in a DMA-capable linker section where needed (for example STM32H7 D2 SRAM, non-cacheable MPU region).
4. **Ownership is a Rust type.** `PacketBuf` is an owning handle (it frees on `Drop`), and `PacketRef` is a shared, read-only handle. Moving a packet between layers is a move of a pointer-sized handle.
5. **Cache/DMA hygiene** sits in one place: the netif core calls `dma::clean(&buf)` / `dma::invalidate(&buf)` around ring ops based on a `NetCaps::COHERENT_DMA` flag, never in each driver.
6. **Indices for rings.** Pool blocks are addressable by `(PoolId, u16)`, so netmap-like rings and HW descriptors can store small indices instead of fat pointers.

### 4.2 The `NetDevice` trait (iflib-lite)

The driver implements **control ops + ring ops**. The netif core does everything else. A driver still also implements `Driver`, so it registers like any device, gets a `/dev/<name>` node, power management, and middleware. A blanket helper implements `Driver::handle` by decoding `NetCtl` requests and calling the control ops.

```rust
pub trait NetDevice: Send + Sync {
    // ---- static description (if_shared_ctx / if_softc_ctx) ----
    fn info(&self) -> &'static NetDevInfo;   // name, medium, mtu, max_frags, n_rxq, n_txq,
                                             // ring sizes, caps, headroom needed, dma align

    // ---- control plane (ifdi_* / ndo_*) — called from net task or via Driver::handle ----
    fn open(&self, ctx: &mut NetCtx) -> Result<(), NetError>;      // ifdi_init / ndo_open
    fn stop(&self, ctx: &mut NetCtx);                              // ifdi_stop / ndo_stop
    fn mac_addr(&self) -> HwAddr;
    fn set_mac_addr(&self, a: HwAddr) -> Result<(), NetError> { Err(NetError::Unsupported) }
    fn set_mtu(&self, mtu: u16) -> Result<(), NetError> { Err(NetError::Unsupported) }
    fn set_rx_filter(&self, f: &RxFilter) -> Result<(), NetError>; // promisc/allmulti/mcast list
    fn link_state(&self) -> LinkState;                              // up/down, speed, duplex
    fn set_caps(&self, enable: NetCaps) -> Result<NetCaps, NetError> { Ok(enable & self.info().caps) }
    fn timer(&self, _ctx: &mut NetCtx) {}                            // ifdi_timer: link poll, watchdog

    // ---- interrupts (ifdi_*intr*) ----
    fn irq_enable(&self, q: QueueId);
    fn irq_disable(&self, q: QueueId);

    // ---- RX ring ops (isc_rxd_*) ----
    /// Number of completed RX descriptors starting at consumer index, up to `budget`.
    fn rx_available(&self, q: QueueId, budget: u16) -> u16;
    /// Describe one completed packet (may span frags). Driver returns descriptor indices;
    /// the core owns the buffers it posted, so no allocation happens here.
    fn rx_get(&self, q: QueueId, out: &mut RxInfo) -> Result<(), NetError>;
    /// Post fresh buffers (DMA addresses) to the RX ring at producer index.
    fn rx_refill(&self, q: QueueId, bufs: &[DmaBuf]);
    /// Doorbell / tail pointer update after refill (batched).
    fn rx_flush(&self, q: QueueId);

    // ---- TX ring ops (isc_txd_*) ----
    /// Encode one packet (1..=max_frags segments + offload request) into descriptors.
    fn tx_encap(&self, q: QueueId, pkt: &TxInfo) -> Result<u16 /*descs used*/, TxFull>;
    /// Doorbell — called once per batch.
    fn tx_flush(&self, q: QueueId);
    /// How many descriptors HW has completed since last call (core frees the buffers).
    fn tx_reclaim(&self, q: QueueId) -> u16;
}

pub struct RxInfo { pub frags: [RxFrag; MAX_RX_FRAGS], pub nfrags: u8, pub len: u16,
                    pub csum: CsumState, pub vlan: Option<u16>, pub flow_hash: Option<u32>,
                    pub timestamp: Option<Instant>, pub error: bool }
pub struct RxFrag { pub ring_idx: u16, pub len: u16 }

pub struct TxInfo<'a> { pub segs: &'a [DmaSeg], pub len: u16, pub csum: CsumReq,
                        pub vlan: Option<u16>, pub l2_len: u8, pub l3_len: u8,
                        pub timestamp_req: bool }
```

Notes:
- **Two driver tiers.** (a) *Ring drivers* (Ethernet MACs with descriptor DMA: STM32 ETH, NXP ENET, GD32, ESP32 EMAC, RISC-V SoC GEMs) implement the ring ops above. (b) *Frame drivers* (SPI/UART chips: W5500 in MACRAW, ENC28J60, cyw43, ESP-hosted, LoRa, 802.15.4 radios) implement a much simpler `FrameDevice { fn recv(&self, buf: &mut [u8]) -> Option<usize>; fn send(&self, frame: &PacketBuf) -> Result<(), NetError>; ... }`. A generic `SoftRing<FrameDevice>` adapter turns them into a `NetDevice`, as embassy-net-driver-channel does. Full-MAC / offloaded-TCP modules (ESP-AT, cellular modems) implement a `SocketOffload` trait instead (Zephyr's socket offload) and plug in at the socket layer.
- **PHY layer**: a `Mdio` trait (`read(phy, reg)`, `write`) plus a generic IEEE 802.3 clause-22 PHY driver (autoneg, link poll) and vendor quirk hooks, like Linux phylib and FreeBSD miibus. MAC drivers expose `Mdio`, and the netif core polls link in `timer()`.
- **Statically registered**: `static ETH0: StmEth = ...; net::register(&ETH0, &NETIF0_STORAGE)` with storage (`NetIfStorage<RXQ, TXQ, RING>`) sized by const generics. No heap.

### 4.3 RX model: interrupt → poll with budget (NAPI/iflib)

```
ETH IRQ ──► driver ISR: irq_disable(q); net::schedule(ifindex, q)   // ~10 instructions
                                │  (task notification / event flag to the `net` task)
                                ▼
net task loop (priority configurable, default above app tasks, below hard-RT tasks):
   for each scheduled (if, q):
      n = dev.rx_available(q, BUDGET)          // e.g. BUDGET = 16 on MCU
      for each pkt: dev.rx_get(q,&mut info) → core builds PacketBuf from the pre-posted block
                    → sw csum verify if !caps.RX_CSUM → hooks.run(batch) → dispatch
      refill from RX pool: dev.rx_refill(q, bufs); dev.rx_flush(q)
      if n < BUDGET { dev.irq_enable(q) } else { reschedule (yield to equal prio) }
   run TX reclaim, timers (ARP/ND/TCP), smoltcp poll, deliver socket wakeups
   sleep until notification or next timer deadline (poll_delay)
```

- **Single net task = single owner** of interface state, rings, the L3/L4 engine, and the socket table. This is the lwIP tcpip_thread / embassy runner model and netisr direct dispatch. Apps interact via message queues / SPSC rings and event flags, so there are **no locks on the fast path** and no epoch machinery.
- **Budget plus re-arm** bounds interrupt load under floods (livelock avoidance), the core benefit of NAPI. The budget is a config knob.
- **RX buffers are pre-posted** pool blocks (the packet-zone idea), so the RX path never allocates. If the pool is empty, the core leaves the descriptors un-refilled and the HW drops. That is graceful overload without corrupting state.
- **Optional `poll_mode`**: for very hot devices the IRQ can stay disabled and the net task polls every tick (`DEVICE_POLLING`). This is useful for deterministic, TSN-ish loops.
- **Multi-instance**: on AMP dual-core parts (RP2350, ESP32-S3, STM32H7 dual-core) or multi-queue MACs, *one net task per core/queue set* is allowed (RSS-lite) but is never required.

### 4.4 TX path

```
socket/app ──► net::tx(pkt)   (from net task directly, or via per-app SPSC ring / MPSC queue)
          ──► egress PacketHooks (Out) ──► sw offload fallback ──► TxQueue[prio] (bounded ring)
          ──► net task drains: while descriptors free: dev.tx_encap(q, info) ; batch++
          ──► dev.tx_flush(q)   (one doorbell per batch)
TX-complete IRQ (or opportunistic in net loop) ──► dev.tx_reclaim(q) ──► free / unref buffers
```

- **Rings, not qdiscs.** Each HW TX queue gets a bounded software queue: a const-generic ring of `PacketBuf` handles. **Optional 2-band strict priority** (control/PTP/real-time vs. bulk) uses `meta.prio`, which covers 95% of MCU QoS needs. An optional 802.1Qav/Qbv mapping exists only if the MAC supports TSN queues (`NetCaps::TSN_*`).
- **In-flight byte limit** (BQL-lite): cap the bytes posted to the HW ring so high-priority frames aren't stuck behind a full ring of bulk data.
- **Backpressure** propagates as `WouldBlock` to sockets. Senders can wait on an event flag that the net task sets after reclaim. This is the kqueue `EVFILT_WRITE` analogue.
- **Zero-copy TX** (the sendfile analogue): an app can send `Storage::Static` (a flash-resident web asset or firmware chunk) or `Storage::Ext` (a sensor DMA buffer with a refcount) as payload. The stack allocates only a header block and chains it. If `!caps.SG`, the core linearizes (a software fallback copy).
- **Timestamps**: `TxInfo.timestamp_req`, with the result delivered back through the socket error queue or callback (PTP/gPTP).

### 4.5 Offload capabilities with software fallback

```rust
bitflags! { pub struct NetCaps: u32 {
    const TX_CSUM_IPV4 = 1<<0;  const TX_CSUM_TCP = 1<<1;  const TX_CSUM_UDP = 1<<2;
    const TX_CSUM_ICMP = 1<<3;  const TX_CSUM_V6  = 1<<4;
    const RX_CSUM_IPV4 = 1<<5;  const RX_CSUM_L4  = 1<<6;   // verifies & reports
    const TX_VLAN_INSERT = 1<<7; const RX_VLAN_STRIP = 1<<8; const VLAN_FILTER = 1<<9;
    const SG = 1<<10;           // scatter-gather TX (needed for zero-copy chains)
    const CRC_STRIP = 1<<11; const MCAST_FILTER = 1<<12; const PROMISC = 1<<13;
    const HW_TIMESTAMP = 1<<14; const TSN_QAV = 1<<15; const TSN_QBV = 1<<16;
    const COHERENT_DMA = 1<<17; const RX_HASH = 1<<18; const WAKE_ON_LAN = 1<<19;
}}
```

- The **core enforces fallback**, as in Linux/FreeBSD. On TX, if the packet wants a TCP checksum and `!enabled.TX_CSUM_TCP`, the core computes it in software before `tx_encap`, so drivers never see requests they can't satisfy. On RX, if `!RX_CSUM_*`, the core verifies in software and records the result in `meta.csum`, so smoltcp and the other upper layers can skip work. smoltcp's `ChecksumCapabilities` is derived from `enabled`.
- Enabled caps are a runtime subset (ethtool `-K` / `ifconfig -txcsum` analogue) via a control-plane request, so offloads can be disabled when silicon errata appear. Many MCU MACs have checksum offload errata; STM32 ETH, for example, has issues with ICMP or with odd-length frames.
- **Software crypto offload** later: a `TLS_TX` cap only if a future MCU MAC/crypto engine supports inline TLS. Until then, TLS is a node or library above sockets.

### 4.6 Early hook chain: pfil/XDP as data-plane middleware

```rust
pub enum Verdict { Pass, Drop, Consumed, Redirect(Target) /* other ifindex, NetRing, node */ }

pub trait PacketHook: Sync {
    fn name(&self) -> &'static str;
    /// Called on a batch; hooks may read/modify headers, set meta, or steal packets.
    fn on_batch(&self, dir: Dir, dev: IfIndex, batch: &mut PacketBatch<'_>);  // sets per-pkt verdicts
    /// Optional ultra-early variant on raw RX bytes BEFORE PacketBuf metadata is built
    /// (pfil_mem_in / XDP): return Drop to recycle the descriptor buffer immediately.
    fn on_raw_rx(&self, _dev: IfIndex, _frame: &[u8]) -> RawVerdict { RawVerdict::Pass }
}
```

- **Attachment points** (pfil heads): `LinkIn`, `LinkOut`, `Ip4In/Out`, `Ip6In/Out`, `NodeIn(node)`, with ordering global → user-attached per device → driver-provided. This mirrors the existing middleware ordering, so users learn one model. Hooks are `&'static dyn PacketHook` in a `const`/static array per head, so traversal is a slice walk with no locks (net-task owned). Runtime attach/detach is a control-plane request applied by the net task between batches; that is our epoch, for free.
- **Use cases**: firewall/ACL, rate limiting, DoS drop on the raw path, packet capture tap (a BPF-like pcap writer to a NetRing or UART), VLAN demux, protocol steering to a `NetRing` (Redirect) for edge-compute apps, and telemetry counters.
- **Relationship to `Middleware`**: the control-plane requests (`NetCtl::SetMtu`, `GetStats`, …) still flow through `Middleware` unchanged. A generic `HookFromMiddleware` adapter is **not** recommended, because the semantics differ. Bismuth documentation should present `PacketHook` as "middleware for packets".
- No eBPF. On MCUs, hooks are compiled Rust. A tiny classic-BPF interpreter could be an *optional* hook for runtime-loaded filters (for example from a management plane).

### 4.7 Netgraph-lite: composable protocol nodes

```rust
pub trait NetNode: Sync {
    const NAME: &'static str;            // (or fn name())
    fn hooks(&self) -> &'static [HookDesc];          // named, typed ports: "lower", "upper", "ctl"
    fn rcv_data(&self, ctx: &mut NodeCtx, from: HookId, pkt: PacketBuf);   // ng_rcvdata
    fn rcv_ctl(&self, ctx: &mut NodeCtx, msg: &NodeMsg) -> Result<NodeReply, NetError> { Err(NetError::Unsupported) }
    fn tick(&self, _ctx: &mut NodeCtx) {}           // timers (reassembly, retransmit)
}
// NodeCtx::send(hook, pkt) forwards along the edge; edges are a static table:
static GRAPH: NetGraph<8, 12> = net_graph! {
    eth0.lower <-> ethernet.lower;
    ethernet.vlan100 <-> vlan100.lower;  vlan100.upper <-> ip_stack.lower;   // smoltcp node
    radio0.lower <-> sixlowpan.lower;    sixlowpan.upper <-> ip_stack.lower6;
    ethernet.ethertype(0x88B5) <-> my_edge_proto.lower;                      // custom L2 protocol
};
```

- **Static graph** built at compile time (a macro producing const tables). Edges are typed by medium (Ethernet frame, IPv6 packet, raw bytes) so miswiring is a compile error. Nodes run in the net task.
- **The L3/L4 engine is just a node** (`ip_stack`), so alternative stacks (smoltcp, a minimal UDP-only stack, a future native Bismuth TCP) are swappable, which is the `tcp_function_block` lesson applied at build time.
- **Shipped nodes, eventually**: `ethernet` (ethertype demux), `vlan`, `arp`/`nd` (inside the ip node), `sixlowpan` (802.15.4), `bridge` (2-port L2 forwarding for daisy-chain industrial devices), `tee`/`tap` (capture), `ppp` (cellular), `can_gw` (CAN↔UDP), `coap`/`mqtt-sn` (as upper nodes for edge apps).
- Control messages are typed Rust enums sent through the control plane (`Driver::handle` on a virtual `/dev/net` device), not string paths.

### 4.8 NetRing: netmap-lite zero-copy rings for edge-compute apps

For apps that process raw frames or datagrams at high rate (sensor fusion gateways, protocol converters, ML inference on traffic, industrial Ethernet like EtherCAT/Profinet RT, custom L2), the socket stack is too heavy.

```rust
pub struct NetRing<const N: usize> {   // statically allocated, SPSC each direction
    rx: SpscRing<Slot, N>, tx: SpscRing<Slot, N>,
    notify: EventFlags,                 // RX_READY | TX_SPACE (kqueue/poll analogue)
}
#[derive(Clone, Copy)] pub struct Slot { pub buf: BufIdx /* (pool, idx) */, pub len: u16, pub flags: u16 }

// Binding:
let ring = net::netring::attach(eth0, NetRingSel::Queue(1))?;          // whole HW queue (netmap)
let ring = net::netring::attach(eth0, NetRingSel::Hook(&ETHERTYPE_88A4))?; // steered by a hook (AF_XDP-like)

// App loop (no copies; buffers are pool blocks the app owns until it returns them):
loop {
    ring.wait(RX_READY, timeout)?;
    for slot in ring.rx_iter() {             // batch
        let frame = ring.buf(slot);          // &[u8] view into the pool block
        let out = process(frame);
        ring.tx_push_swap(slot, out_len)?;   // forward same buffer (index swap, netmap NS_BUF_CHANGED)
    }
    ring.sync();                             // one notification to net task (NIOCTXSYNC/RXSYNC)
}
```

- With no MMU and one address space, "mapping" is just handing ownership of buffer indices. Rust lifetimes and handles enforce that the app can't touch a buffer after returning it. On MPU-protected builds, the pool region gets an MPU window for that task.
- Rings carry **indices, not pointers**, which is compact (4–8 B/slot) and pool-validated.
- **Batch sync** amortizes wakeups, the core netmap trick. Forwarding by **buffer swap** gives zero-copy bridging and processing.
- Because iflib makes netmap work generically, NetRing should be implemented once in the netif core on top of the ring ops, not per driver.

### 4.9 Sockets, smoltcp integration, and compat layers

1. **smoltcp adapter (`ip_stack` node)**: implements `smoltcp::phy::Device` with `RxToken` = a `PacketBuf` dequeued from the node's input queue (consume → `&[u8]` view, then drop frees to the pool) and `TxToken` = a `PacketBuf` allocated from the TX pool with headroom (consume writes into it, then `net::tx`). `capabilities()` comes from `NetCaps` (checksum, MTU, `max_burst_size` = ring free). `Interface::poll` runs in the net task loop. `poll_delay()` feeds the net task's software timer. This keeps smoltcp swappable and avoids its single-buffer token limitations below it.
   - Caveat: smoltcp copies payload into socket buffers. That is fine at MCU rates. Zero-copy datapaths use NetRing or a native UDP node.
2. **`bismuth::net::socket`**: a thin, owned-handle API (`TcpSocket`, `UdpSocket`, `RawSocket`, `Dns`). Calls from app tasks become **messages to the net task** (a message queue + reply notification), or, for data, operate on per-socket buffers protected by the net task's ownership plus a short critical section. Readiness is per-socket event flags, and `net::select(&[&dyn Pollable], mask, timeout)` is the kqueue analogue.
3. **POSIX compat** (the existing compat model): `socket()/bind()/connect()/listen()/accept()/send()/recv()/sendto()/recvfrom()/setsockopt()/getsockopt()/close()/poll()/select()/getaddrinfo()` map onto the socket handles in the same fd table as `/dev/<name>`. `ioctl(SIOCGIFADDR, …)` and `/dev/eth0` control requests go through `Driver::handle` and middleware.
4. **FreeRTOS-style C API**: `FreeRTOS_socket`, `FreeRTOS_sendto`, `FreeRTOS_recvfrom`, … (FreeRTOS-Plus-TCP naming) as `extern "C"` shims for porting existing C code. lwIP-compatible `netconn`/raw APIs are **not** recommended (too much surface).
5. **embedded-nal / embedded-nal-async / embedded-io** adapters for socket handles, so ecosystem crates (MQTT, HTTP, CoAP clients like `rust-mqtt`, `reqwless`, `coap-lite`) work unchanged. This matches Bismuth's embedded-hal/embedded-io compat pattern.
6. **Socket offload** for AT-command modems and ESP-AT: a `SocketOffload` impl backs the same socket API without the IP stack.

### 4.10 Concurrency summary

| Who | Runs | Talks to net via | Locking |
|---|---|---|---|
| Driver ISR | IRQ context | `irq_disable` + task notification | none |
| `net` task | single owner of rings, pools (alloc side), graph, ip stack, sockets | — | none on fast path |
| App tasks (sockets) | own priority | message queue / socket buffers + event flags | short critical section or mutex w/ PI on socket buffers |
| App tasks (NetRing) | own priority | SPSC rings + event flags | lock-free |
| Control plane | caller task | `Driver::handle` → middleware → `NetCtl` msg to net task | mutex w/ PI on device control |
| Pool free | any task / ISR | lock-free pool free (atomic freelist) | lock-free |

Config updates (hook lists, routes, addresses) are applied by the net task between batches. Readers on the fast path are the net task itself, so no epoch or RCU is needed. If multi-core net tasks are ever added, publish config as `AtomicPtr` to an immutable snapshot and free old snapshots after every net task has passed a quiescent point (a single-counter epoch, ~50 lines).

---

## 5. Phased implementation plan

| Phase | Deliverable | Why first |
|---|---|---|
| **P0: Foundations** | `PacketBuf` + `PacketRef` + `Storage::{Pool,Static,Ext}` over Bismuth fixed-block pools; headroom push/pull; `NetCaps`; `CsumState`; software checksums (IPv4/TCP/UDP/ICMPv6, with unit tests incl. fallback); SPSC ring. | Everything depends on the buffer type. It is host-testable with no hardware. |
| **P1: netif core + NetDevice** | `NetDevice` trait; netif core (RX poll with budget, refill, TX queue, doorbell batching, reclaim, stats, link timer); `net` task; `FrameDevice` + `SoftRing` adapter; a **loopback** device and a **host TAP / mock** device for tests; the `Driver` impl for control-plane via `NetCtl` requests (middleware-compatible). | Proves the iflib-lite contract with zero hardware. Mock rings exercise budget and backpressure logic. |
| **P2: IP via smoltcp** | `ip_stack` node wrapping smoltcp (IPv4, ARP, DHCPv4, UDP, TCP, ICMP, DNS); `bismuth::net::socket` with event-flag readiness; `embedded-nal(-async)` adapters. | Gets real networking end-to-end. smoltcp gives a trustworthy TCP immediately. |
| **P3: First real drivers** | One descriptor-ring MAC (for example STM32 ETH or ESP32 EMAC, whichever is the primary dev board), `Mdio` + generic PHY; one SPI frame device (W5500 MACRAW or ENC28J60). Cache/DMA hygiene in the core. | Validates both driver tiers and the cache-maintenance placement. |
| **P4: Hooks + capture** | `PacketHook` heads (LinkIn/Out, Ip In/Out), raw-RX early hook, per-device user attachment mirroring middleware; built-in hooks: counters, ACL, rate limiter, pcap tap to UART/USB/NetRing. | Cheap to add once the core exists, and a high debugging payoff. |
| **P5: POSIX + C compat** | Socket fds in the shared fd table, `poll/select`, `getaddrinfo`; FreeRTOS-Plus-TCP-style C shims. | Unlocks porting C code. It depends on stable socket semantics from P2. |
| **P6: NetRing (netmap-lite)** | Queue- and hook-steered rings, buffer swap forwarding, batch sync, MPU window option. | The edge-compute differentiator. It needs stable pools and hooks. |
| **P7: Netgraph-lite** | `NetNode` trait + `net_graph!` static wiring; `ethernet`, `vlan`, `tee`, `bridge`; then `sixlowpan` (802.15.4 radio driver), `ppp`, custom-ethertype nodes. | Generalizes the pipeline once real multi-protocol needs appear; refactors the P2 `ip_stack` into a node. |
| **P8: Advanced, optional** | HW timestamping + gPTP; TSN Qav/Qbv mapping; socket offload (ESP-AT, cellular); IPv6/6LoWPAN hardening; optional native minimal UDP/IP fast path; optional cBPF hook; multi-core net tasks on AMP parts; TLS (embedded-tls / rustls-no_std) as a socket wrapper. | Only when targets need them. |

Test strategy throughout: host-side `cargo test` with the mock/TAP device (std feature for tests only), property tests for checksum fallback vs. offload equivalence and for buffer push/pull/chain invariants, pool-exhaustion and flood tests (to verify the budget and overload drop), and a QEMU target (for example `mps2-an385` with LAN9118 or the `virt` RISC-V with virtio-net, where virtio rings are an excellent iflib-shaped test driver).

---

## 6. What NOT to copy (and why)

| Feature | Origin | Why not for Bismuth |
|---|---|---|
| VNET / network namespaces | FreeBSD / Linux | Per-stack virtualization for jails/containers. There are no multi-tenant workloads on MCUs, and it costs indirection on every global. |
| Full netisr thread pool, RPS/RFS, RSS as a requirement | FreeBSD / Linux | Single-core or AMP MCUs. Keep `flow_hash` metadata and allow optional per-core net tasks only. |
| General epoch/RCU reclamation | FreeBSD net_epoch / Linux RCU | Single-owner net task gives the same lock-free reads. Add a trivial quiescent counter only if multi-core ever appears. |
| qdisc framework (HTB, fq_codel, …), ALTQ | Linux / FreeBSD | Too much code/RAM for KB-scale links. A 2-band priority + BQL-lite cap is enough; TSN shapers come from HW. |
| TSO / GSO / GRO / LRO | both | MCU links are 10/100 Mb/s with small windows; segmentation offload buys nothing and costs complexity and RAM. |
| Runtime-pluggable multiple TCP stacks, RACK/BBR | FreeBSD tcp_function_block | Big code footprint; MCU TCP windows are tiny. Keep the *trait boundary* for compile-time choice only. |
| kTLS, async sendfile with unmapped pages, page cache, NUMA | FreeBSD / Netflix | No page cache, no VM, no NUMA. Keep the *principle* (refcounted external payload + header prepend). |
| `sk_buff` size and field sprawl; `skb_shared_info` page frags | Linux | Too large per packet. Keep headers ≤ ~40 B. |
| page_pool / IOMMU / bus_dma maps & bounce buffers | Linux / FreeBSD | No IOMMU. DMA = physical address of pool block + cache maintenance in one place. |
| eBPF / XDP JIT, nftables VM | Linux | Code size and verifier complexity. Compiled Rust hooks; optional tiny cBPF interpreter at most. |
| Runtime netgraph with `ngctl` string paths, dynamic node loading (KLD) | FreeBSD | No dynamic module loading; static typed graph gives the composability at compile time with zero runtime cost. |
| kobj method dispatch, sysctl tree per queue, ethtool/devlink/netlink | FreeBSD / Linux | Use Rust traits and a compact `NetCtl` request enum through the existing middleware/`/dev` control path instead. |
| Mandatory multi-queue design in drivers | iflib | Most MCU MACs have 1 RX/1 TX queue (some have 2–4 for TSN). Queue count is a const parameter defaulting to 1. |
| In-tree-only, unstable driver API | Linux | Bismuth wants a stable, small, out-of-tree-friendly driver trait, as in FreeBSD `if_t` + iflib. |

---

## 7. Key takeaways mapped to sources

1. *Framework owns policy, driver owns rings* → iflib(9), iflibdd(9), iflibtxrx(9).
2. *Universal, refcounted packet with external storage and headroom* → mbuf(9), lwIP pbuf, Zephyr net_buf.
3. *Interrupt → budgeted poll in one context* → Linux NAPI docs, iflib gtaskqueue, embassy-net runner.
4. *Direct dispatch, single owner* → netisr(9), lwIP tcpip_thread.
5. *Feature flags + software fallback* → mbuf(9) CSUM_*, ifnet(9) IFCAP_*, Linux netdev features.
6. *Verdict hooks before allocation* → pfil(9) (`pfil_mem_in`), XDP.
7. *Batch, index-based, zero-copy rings* → netmap(4), Rizzo ATC'12.
8. *Composable protocol nodes* → netgraph(4).
9. *Protocol engines behind a function table* → tcp_functions(9), tcp_rack(4), tcp_bbr(4).
10. *Never touch the payload* → sendfile(2), ktls(4), Netflix 400/800 Gb/s talks.

---

## References

**FreeBSD manual pages**
- [mbuf9]: mbuf(9). https://man.freebsd.org/cgi/man.cgi?query=mbuf&sektion=9
- [uma9]: uma(9). https://man.freebsd.org/cgi/man.cgi?query=uma&sektion=9
- [ifnet9]: ifnet(9). https://man.freebsd.org/cgi/man.cgi?query=ifnet&sektion=9
- [iflib4]: iflib(4). https://man.freebsd.org/cgi/man.cgi?query=iflib&sektion=4
- [iflib9]: iflib(9). https://man.freebsd.org/cgi/man.cgi?query=iflib&sektion=9
- [iflibdd9]: iflibdd(9). https://man.freebsd.org/cgi/man.cgi?query=iflibdd&sektion=9
- [iflibtxrx9]: iflibtxrx(9). https://man.freebsd.org/cgi/man.cgi?query=iflibtxrx&sektion=9
- iflibdi(9). https://man.freebsd.org/cgi/man.cgi?query=iflibdi&sektion=9
- [netmap4]: netmap(4). https://man.freebsd.org/cgi/man.cgi?query=netmap&sektion=4
- [netisr9]: netisr(9). https://man.freebsd.org/cgi/man.cgi?query=netisr&sektion=9
- [epoch9]: epoch(9). https://man.freebsd.org/cgi/man.cgi?query=epoch&sektion=9
- [pfil9]: pfil(9). https://man.freebsd.org/cgi/man.cgi?query=pfil&sektion=9
- [tcpfunc]: tcp_functions(9). https://man.freebsd.org/cgi/man.cgi?query=tcp_functions&sektion=9
- [rack4]: tcp_rack(4). https://man.freebsd.org/cgi/man.cgi?query=tcp_rack&sektion=4
- [bbr4]: tcp_bbr(4). https://man.freebsd.org/cgi/man.cgi?query=tcp_bbr&sektion=4
- cc(4) (pluggable congestion control). https://man.freebsd.org/cgi/man.cgi?query=cc&sektion=4
- [sendfile2]: sendfile(2). https://man.freebsd.org/cgi/man.cgi?query=sendfile&sektion=2
- [ktls4]: ktls(4). https://man.freebsd.org/cgi/man.cgi?query=ktls&sektion=4
- [kqueue2]: kqueue(2). https://man.freebsd.org/cgi/man.cgi?query=kqueue&sektion=2
- [vnet9]: vnet(9). https://man.freebsd.org/cgi/man.cgi?query=vnet&sektion=9
- [netgraph4]: netgraph(4). https://man.freebsd.org/cgi/man.cgi?query=netgraph&sektion=4
- netgraph(3) / ngctl(8). https://man.freebsd.org/cgi/man.cgi?query=ngctl&sektion=8
- [bufring9]: buf_ring(9). https://man.freebsd.org/cgi/man.cgi?query=buf_ring&sektion=9
- [bpf4]: bpf(4). https://man.freebsd.org/cgi/man.cgi?query=bpf&sektion=4
- [rss]: FreeBSD RSS (wiki / rss options). https://wiki.freebsd.org/NetworkRSS

**Papers and talks**
- [netmap-atc]: L. Rizzo, "netmap: a novel framework for fast packet I/O", USENIX ATC 2012. https://www.usenix.org/conference/atc12/technical-sessions/presentation/rizzo
- netmap project page (Univ. of Pisa). https://info.iet.unipi.it/~luigi/netmap/
- [netgraph-daemon]: A. Cobbs, "All About Netgraph", DaemonNews 2000. https://people.freebsd.org/~julian/netgraph.html
- M. Macy, "iflib: a network driver framework" (BSDCan 2016/2017). https://www.bsdcan.org/2017/schedule/ and https://wiki.freebsd.org/iflib
- [nf400]: D. Gallatin, "Serving Netflix Video at 400Gb/s on FreeBSD", EuroBSDCon 2021. https://papers.freebsd.org/2021/eurobsdcon/gallatin-netflix-freebsd-400gbps/ (slides: https://people.freebsd.org/~gallatin/talks/euro2021.pdf)
- [nf800]: D. Gallatin, "The 'other' FreeBSD optimizations used by Netflix to serve video at 800Gb/s from a single server", EuroBSDCon 2022. https://papers.freebsd.org/2022/eurobsdcon/gallatin-the_other_freebsd_optimizations-netflix/ (slides: https://people.freebsd.org/~gallatin/talks/euro2022.pdf)
- [nfnuma]: D. Gallatin, "NUMA Optimizations in the FreeBSD Network Stack", EuroBSDCon 2019. https://papers.freebsd.org/2019/eurobsdcon/gallatin-numa_optimizations_network_stack/
- D. Gallatin, OpenFest 2023 slides (history to 800 Gb/s). https://people.freebsd.org/~gallatin/talks/OpenFest2023.pdf
- R. Stewart, M. Tüxen, "RACK and Alternate TCP Stacks for FreeBSD", ;login: / BSDCan. https://papers.freebsd.org/ (search "RACK")
- G. Smirnoff, "New sendfile(2)", FreeBSD Journal / BSDCan 2015. https://papers.freebsd.org/

**Linux**
- NAPI. https://docs.kernel.org/networking/napi.html
- Netdev features (NETIF_F_*, software fallback). https://docs.kernel.org/networking/netdev-features.html
- sk_buff. https://docs.kernel.org/networking/skbuff.html
- XDP / AF_XDP. https://docs.kernel.org/networking/af_xdp.html
- page_pool. https://docs.kernel.org/networking/page_pool.html
- Queueing / BQL (scaling). https://docs.kernel.org/networking/scaling.html

**Embedded stacks**
- [smoltcp-device]: smoltcp `phy::Device`. https://docs.rs/smoltcp/latest/smoltcp/phy/trait.Device.html; smoltcp crate: https://docs.rs/smoltcp
- [lwip-pbuf]: lwIP pbuf. https://www.nongnu.org/lwip/2_1_x/group__pbuf.html
- [lwip-netif]: lwIP netif. https://www.nongnu.org/lwip/2_1_x/group__netif.html
- [zephyr-netif]: Zephyr network interface. https://docs.zephyrproject.org/latest/connectivity/networking/api/net_if.html
- [zephyr-netpkt]: Zephyr net_pkt. https://docs.zephyrproject.org/latest/connectivity/networking/api/net_pkt.html
- [zephyr-netbuf]: Zephyr net_buf. https://docs.zephyrproject.org/latest/services/net_buf/index.html
- Zephyr L2 / traffic classes. https://docs.zephyrproject.org/latest/connectivity/networking/net_stack_architecture.html
- [embassy-driver]: embassy-net-driver. https://docs.rs/embassy-net-driver
- [embassy-net]: embassy-net. https://docs.rs/embassy-net
- embassy-net-driver-channel. https://docs.rs/embassy-net-driver-channel
- embedded-nal / embedded-nal-async. https://docs.rs/embedded-nal , https://docs.rs/embedded-nal-async
- FreeRTOS-Plus-TCP API. https://www.freertos.org/Documentation/03-Libraries/02-FreeRTOS-plus/02-FreeRTOS-plus-TCP/09-API-reference/01-FreeRTOS-plus-TCP-APIs

[mbuf9]: https://man.freebsd.org/cgi/man.cgi?query=mbuf&sektion=9
[uma9]: https://man.freebsd.org/cgi/man.cgi?query=uma&sektion=9
[ifnet9]: https://man.freebsd.org/cgi/man.cgi?query=ifnet&sektion=9
[iflib4]: https://man.freebsd.org/cgi/man.cgi?query=iflib&sektion=4
[iflib9]: https://man.freebsd.org/cgi/man.cgi?query=iflib&sektion=9
[iflibdd9]: https://man.freebsd.org/cgi/man.cgi?query=iflibdd&sektion=9
[iflibtxrx9]: https://man.freebsd.org/cgi/man.cgi?query=iflibtxrx&sektion=9
[netmap4]: https://man.freebsd.org/cgi/man.cgi?query=netmap&sektion=4
[netisr9]: https://man.freebsd.org/cgi/man.cgi?query=netisr&sektion=9
[epoch9]: https://man.freebsd.org/cgi/man.cgi?query=epoch&sektion=9
[pfil9]: https://man.freebsd.org/cgi/man.cgi?query=pfil&sektion=9
[tcpfunc]: https://man.freebsd.org/cgi/man.cgi?query=tcp_functions&sektion=9
[rack4]: https://man.freebsd.org/cgi/man.cgi?query=tcp_rack&sektion=4
[bbr4]: https://man.freebsd.org/cgi/man.cgi?query=tcp_bbr&sektion=4
[sendfile2]: https://man.freebsd.org/cgi/man.cgi?query=sendfile&sektion=2
[ktls4]: https://man.freebsd.org/cgi/man.cgi?query=ktls&sektion=4
[kqueue2]: https://man.freebsd.org/cgi/man.cgi?query=kqueue&sektion=2
[vnet9]: https://man.freebsd.org/cgi/man.cgi?query=vnet&sektion=9
[netgraph4]: https://man.freebsd.org/cgi/man.cgi?query=netgraph&sektion=4
[bufring9]: https://man.freebsd.org/cgi/man.cgi?query=buf_ring&sektion=9
[bpf4]: https://man.freebsd.org/cgi/man.cgi?query=bpf&sektion=4
[rss]: https://wiki.freebsd.org/NetworkRSS
[netmap-atc]: https://www.usenix.org/conference/atc12/technical-sessions/presentation/rizzo
[netgraph-daemon]: https://people.freebsd.org/~julian/netgraph.html
[nf400]: https://papers.freebsd.org/2021/eurobsdcon/gallatin-netflix-freebsd-400gbps/
[nf800]: https://papers.freebsd.org/2022/eurobsdcon/gallatin-the_other_freebsd_optimizations-netflix/
[nfnuma]: https://papers.freebsd.org/2019/eurobsdcon/gallatin-numa_optimizations_network_stack/
[smoltcp-device]: https://docs.rs/smoltcp/latest/smoltcp/phy/trait.Device.html
[lwip-pbuf]: https://www.nongnu.org/lwip/2_1_x/group__pbuf.html
[lwip-netif]: https://www.nongnu.org/lwip/2_1_x/group__netif.html
[zephyr-netif]: https://docs.zephyrproject.org/latest/connectivity/networking/api/net_if.html
[zephyr-netpkt]: https://docs.zephyrproject.org/latest/connectivity/networking/api/net_pkt.html
[zephyr-netbuf]: https://docs.zephyrproject.org/latest/services/net_buf/index.html
[embassy-driver]: https://docs.rs/embassy-net-driver
[embassy-net]: https://docs.rs/embassy-net
