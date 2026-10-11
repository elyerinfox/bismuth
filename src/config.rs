//! Compile-time kernel configuration.
//!
//! Every limit can be overridden at build time through an environment variable, e.g.
//! `BISMUTH_MAX_TASKS=8 cargo build`. Keeping these as `const`s lets the kernel size all
//! of its tables statically: Bismuth never allocates at run time unless you ask it to.
//!
//! Classification: support · configuration · safe · always

const fn parse_or(value: Option<&str>, default: usize) -> usize {
    let s = match value {
        Some(s) => s.as_bytes(),
        None => return default,
    };
    if s.is_empty() {
        return default;
    }
    let mut i = 0;
    let mut n = 0usize;
    while i < s.len() {
        let d = s[i];
        assert!(d >= b'0' && d <= b'9', "bismuth config values must be decimal integers");
        n = n * 10 + (d - b'0') as usize;
        i += 1;
    }
    n
}

/// Maximum number of task control blocks, including the idle task.
pub const MAX_TASKS: usize = parse_or(option_env!("BISMUTH_MAX_TASKS"), 16);
/// Number of priority levels. Priority 0 is reserved for the idle task; higher is more urgent.
pub const PRIORITIES: usize = 32;
/// Default tick rate used when the port does not override it.
pub const TICK_HZ: u32 = parse_or(option_env!("BISMUTH_TICK_HZ"), 1000) as u32;
/// Round-robin time slice between equal-priority tasks, in ticks (0 disables slicing).
pub const TIME_SLICE_TICKS: u32 = parse_or(option_env!("BISMUTH_TIME_SLICE"), 10) as u32;
/// Maximum number of registered devices.
pub const MAX_DEVICES: usize = parse_or(option_env!("BISMUTH_MAX_DEVICES"), 16);
/// Maximum number of user-attached middleware layers per device.
pub const MAX_LAYERS: usize = parse_or(option_env!("BISMUTH_MAX_LAYERS"), 6);
/// Maximum number of active software timers.
pub const MAX_TIMERS: usize = parse_or(option_env!("BISMUTH_MAX_TIMERS"), 8);
/// Number of stacks in the shared pool used by dynamically created threads (pthreads).
pub const POOL_STACKS: usize = parse_or(option_env!("BISMUTH_POOL_STACKS"), 4);
/// Size in bytes of each pooled stack.
pub const POOL_STACK_SIZE: usize = parse_or(option_env!("BISMUTH_POOL_STACK_SIZE"), 2048);
/// Size of the idle task's stack.
pub const IDLE_STACK_SIZE: usize = parse_or(option_env!("BISMUTH_IDLE_STACK_SIZE"), 512);
/// Size of the timer-service task's stack.
pub const TIMER_STACK_SIZE: usize = parse_or(option_env!("BISMUTH_TIMER_STACK_SIZE"), 1024);

// --- Tickless idle governor (see `kernel::idle`) ---
/// Idle gaps shorter than this many ticks stay in plain `Idle` (suppressing and re-arming
/// the tick is not worth it for a gap this short). FreeRTOS's `EXPECTED_IDLE_TIME` floor.
pub const IDLE_SLEEP_THRESHOLD: usize = parse_or(option_env!("BISMUTH_IDLE_SLEEP_THRESHOLD"), 2);
/// Exit latency of light `Sleep` (ticks to be running again).
pub const IDLE_SLEEP_LATENCY: usize = parse_or(option_env!("BISMUTH_IDLE_SLEEP_LATENCY"), 1);
/// Minimum residency below which entering light `Sleep` costs more than it saves.
pub const IDLE_SLEEP_RESIDENCY: usize = parse_or(option_env!("BISMUTH_IDLE_SLEEP_RESIDENCY"), 2);
/// Number of simultaneous QoS latency constraints the governor tracks.
pub const IDLE_MAX_CONSTRAINTS: usize = parse_or(option_env!("BISMUTH_IDLE_MAX_CONSTRAINTS"), 4);
/// Number of POSIX file descriptors.
pub const MAX_FDS: usize = parse_or(option_env!("BISMUTH_MAX_FDS"), 16);
/// Number of POSIX message queues that can be opened by name.
pub const MAX_MQUEUES: usize = parse_or(option_env!("BISMUTH_MAX_MQUEUES"), 4);
/// Bytes of backing storage for each POSIX message queue.
pub const MQUEUE_BYTES: usize = parse_or(option_env!("BISMUTH_MQUEUE_BYTES"), 512);

const _: () = assert!(MAX_TASKS >= 2 && MAX_TASKS <= 255, "MAX_TASKS must be in 2..=255");
const _: () = assert!(PRIORITIES <= 32, "the ready bitmap is a u32");
const _: () = assert!(TICK_HZ > 0);

// ----- networking -----

/// Pick a default depending on whether we build for an MCU or the host simulator.
const fn mcu_or_host(mcu: usize, host: usize) -> usize {
    if cfg!(target_os = "none") { mcu } else { host }
}

/// Maximum number of network interfaces.
pub const MAX_NETIFS: usize = parse_or(option_env!("BISMUTH_MAX_NETIFS"), 4);
/// Packet blocks reserved for reception.
pub const NET_RX_BUFS: usize = parse_or(option_env!("BISMUTH_NET_RX_BUFS"), mcu_or_host(6, 32));
/// Packet blocks reserved for transmission.
pub const NET_TX_BUFS: usize = parse_or(option_env!("BISMUTH_NET_TX_BUFS"), mcu_or_host(6, 32));
/// Packet blocks used to hand data to applications (sockets).
pub const NET_APP_BUFS: usize = parse_or(option_env!("BISMUTH_NET_APP_BUFS"), mcu_or_host(6, 32));
/// Maximum packets processed per interface per poll round (NAPI budget).
pub const NET_BUDGET: usize = parse_or(option_env!("BISMUTH_NET_BUDGET"), 16);
/// Depth of each per-interface software transmit queue (two bands each).
pub const NET_TXQ_LEN: usize = parse_or(option_env!("BISMUTH_NET_TXQ_LEN"), 8);
/// Depth of the per-interface queue feeding the IP stack.
pub const NET_IP_RXQ: usize = parse_or(option_env!("BISMUTH_NET_IP_RXQ"), 8);
/// Number of interfaces that can run an IP stack.
pub const NET_IP_IFACES: usize = parse_or(option_env!("BISMUTH_NET_IP_IFACES"), mcu_or_host(1, 2));
/// UDP sockets per IP interface.
pub const NET_UDP_SOCKETS: usize = parse_or(option_env!("BISMUTH_NET_UDP_SOCKETS"), mcu_or_host(2, 4));
/// TCP sockets per IP interface.
pub const NET_TCP_SOCKETS: usize = parse_or(option_env!("BISMUTH_NET_TCP_SOCKETS"), mcu_or_host(2, 4));
/// Bytes of receive and of transmit buffer per socket.
pub const NET_SOCKET_BUF: usize = parse_or(option_env!("BISMUTH_NET_SOCKET_BUF"), mcu_or_host(1024, 4096));
/// Stack size of the net task (holds the IP stack's socket storage).
pub const NET_STACK_SIZE: usize = parse_or(option_env!("BISMUTH_NET_STACK_SIZE"), mcu_or_host(16384, 4096));
/// Priority of the net task (above typical application tasks).
pub const NET_PRIORITY: u8 = parse_or(option_env!("BISMUTH_NET_PRIORITY"), 20) as u8;

// ----- filesystems -----

/// Maximum number of registered block devices.
pub const MAX_BLOCKDEVS: usize = parse_or(option_env!("BISMUTH_MAX_BLOCKDEVS"), 4);
/// Simultaneously mounted filesystems.
pub const MAX_MOUNTS: usize = parse_or(option_env!("BISMUTH_MAX_MOUNTS"), 4);
/// Globally open files/directories (the VFS open-file table).
pub const MAX_OPEN_FILES: usize = parse_or(option_env!("BISMUTH_MAX_OPEN_FILES"), mcu_or_host(8, 32));
/// Longest absolute path the resolver accepts.
pub const FS_PATH_MAX: usize = parse_or(option_env!("BISMUTH_FS_PATH_MAX"), 128);
/// Longest single path component / filename.
pub const FS_NAME_MAX: usize = parse_or(option_env!("BISMUTH_FS_NAME_MAX"), 64);
/// RAM filesystem: number of inodes (files + directories).
pub const RAMFS_INODES: usize = parse_or(option_env!("BISMUTH_RAMFS_INODES"), mcu_or_host(16, 64));
/// RAM filesystem: number of data blocks in the shared arena.
pub const RAMFS_BLOCKS: usize = parse_or(option_env!("BISMUTH_RAMFS_BLOCKS"), mcu_or_host(16, 128));
/// RAM filesystem: bytes per data block.
pub const RAMFS_BLOCK: usize = parse_or(option_env!("BISMUTH_RAMFS_BLOCK"), 256);
/// Flash FS: simultaneously open files per mount.
pub const LFS_MAX_OPEN: usize = parse_or(option_env!("BISMUTH_LFS_MAX_OPEN"), mcu_or_host(4, 8));
/// Flash FS: directory-tree walk worklist depth (bounds the mount scan; no recursion).
pub const LFS_WALK_STACK: usize = parse_or(option_env!("BISMUTH_LFS_WALK_STACK"), mcu_or_host(16, 64));
/// Flash FS: blocks reserved for metadata commits (avoids the CoW-delete ENOSPC deadlock).
pub const LFS_RESERVE_BLOCKS: u32 = parse_or(option_env!("BISMUTH_LFS_RESERVE_BLOCKS"), 6) as u32;
/// Hot-file residency cache: resident whole-file slots (`0` compiles the layer out).
pub const FS_RESIDENT_SLOTS: usize = parse_or(option_env!("BISMUTH_FS_RESIDENT_SLOTS"), mcu_or_host(0, 8));
/// Hot-file residency cache: maximum bytes of a resident file (larger files stay uncached).
pub const FS_RESIDENT_MAX_FILE: usize = parse_or(option_env!("BISMUTH_FS_RESIDENT_MAX_FILE"), mcu_or_host(512, 8192));
/// Hot-file residency cache: accesses before a file is promoted (LFU threshold).
pub const FS_RESIDENT_PROMOTE: u32 = parse_or(option_env!("BISMUTH_FS_RESIDENT_PROMOTE"), 4) as u32;

// ----- extensions -----

/// Maximum registered loadable extensions.
pub const MAX_EXTENSIONS: usize = parse_or(option_env!("BISMUTH_MAX_EXTENSIONS"), 8);

// ----- trusted platform (TPM) -----

/// Number of platform configuration registers (PCRs) for measured boot.
pub const TPM_PCRS: usize = parse_or(option_env!("BISMUTH_TPM_PCRS"), 8);
/// Maximum plaintext bytes a single seal operation holds (e.g. a 32-byte root KEK).
pub const TPM_SEAL_MAX: usize = parse_or(option_env!("BISMUTH_TPM_SEAL_MAX"), 64);
