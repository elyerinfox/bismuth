//! A type-1 hypervisor shim at **EL2** (`hypervisor` feature) — stage 1 of hosting guest VMs.
//!
//! When the `hypervisor` feature is on, the aarch64 reset path stays at EL2 (instead of dropping
//! to EL1) and hands control here. This stage boots EL2, installs an EL2 exception vector table
//! (`VBAR_EL2`), loads a small guest blob into RAM, and `eret`s into it at **EL1**. The guest
//! reaches the hypervisor through a tiny hypercall ABI: `HVC #0` with a command in `x0`
//! (1 = print a string the guest owns, 2 = exit). The guest's output therefore appears *through*
//! the hypervisor, proving the EL1→EL2 trap round-trip.
//!
//! Built out across staged increments (see `docs/research/hypervisor.md`): S1 EL2 boot + the
//! `HVC` hypercall gate; S2 stage-2 translation (the guest's isolated guest-physical RAM); S3
//! the vGIC (GICv2 list-register injection + a virtual CPU interface mapped to the guest); S4 an
//! emulated virtio-mmio console (MMIO trap-and-emulate + virtqueue drain); S5 a guest "OS" using
//! all of it; S6 a **hardware-timer-driven** tick (the EL2 physical timer injects the guest's
//! virtual-timer IRQ on a free-running cadence) and **PSCI-over-SMC** emulation (`VERSION`,
//! `CPU_ON`, `SYSTEM_OFF`/`RESET`, `FEATURES`) so a guest powers itself off the standard way.
//! EL2 runs MMU-off; printing is direct PL011 MMIO (single-threaded, no locks/atomics).
//!
//! Classification: L0 port · aarch64 hypervisor · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::{asm, naked_asm};
use core::ptr::addr_of_mut;

/// QEMU `virt` PL011 UART0. Stage 1 targets QEMU `virt` only; stage 2+ takes this from the
/// board map. The hypervisor owns the UART directly (the guest prints only via hypercalls).
const UART: usize = 0x0900_0000;
const UART_DR: usize = 0x00; // data register
const UART_FR: usize = 0x18; // flag register; TXFF = bit 5

/// Hypercall numbers (the stage-1 ABI; stage 3 adds `HVC_TICK`).
const HVC_PRINT: u64 = 1;
const HVC_EXIT: u64 = 2;
/// Stage 3: the guest asks the hypervisor to inject its next virtual-timer interrupt.
const HVC_TICK: u64 = 3;

// ---- Stage 3: vGIC (GICv2 virtualization) ----
//
// QEMU `virt` GICv2 has, besides GICD (0x0800_0000) / GICC (0x0801_0000), a hypervisor control
// interface GICH (0x0803_0000) and a virtual CPU interface GICV (0x0804_0000). The hypervisor
// enables GICH and injects a virtual interrupt by writing a list register (GICH_LR0); the guest's
// own "GIC CPU interface" is GICV, which stage-2 maps into the guest at the standard GICC address
// (0x0801_0000) — so the guest acknowledges (GICV_IAR) and ends (GICV_EOIR) the virtual interrupt
// exactly as if it were talking to a real GICC, never seeing the host GIC.
const GICH: usize = 0x0803_0000;
const GICH_HCR: usize = 0x000; // hypervisor control; bit0 = En
const GICH_VMCR: usize = 0x008; // virtual machine control (mirrors the guest's GICV_CTLR/PMR)
const GICH_LR0: usize = 0x100; // list register 0
const GICD: usize = 0x0800_0000; // physical distributor
const GICC: usize = 0x0801_0000; // physical CPU interface (host side)
const GICV_PA: u64 = 0x0804_0000; // host-physical virtual CPU interface
const GUEST_GICC_IPA: u64 = 0x0801_0000; // where the guest expects its GIC CPU interface
/// The ARM virtual-timer PPI (`CNTV`), the vINTID we inject as the guest's timer tick.
const VTIMER_INTID: u64 = 27;

// ---- Stage 6: a hardware-timer-driven tick ----
//
// The hypervisor arms the EL2 physical timer (`CNTHP_*_EL2`, PPI INTID 26). Because `HCR_EL2.IMO`
// routes physical IRQs to EL2 while the guest runs at EL1, that timer fires *to EL2* on a
// free-running cadence regardless of what the guest does; the EL2 IRQ handler re-arms it and
// injects the guest's virtual-timer vIRQ (INTID 27) through GICH. The guest therefore receives a
// periodic timer without ever asking for the next tick (replacing the stage-3 `HVC_TICK` cadence).
const GICC_IAR: usize = 0x0C; // interrupt acknowledge (host CPU interface)
const GICC_EOIR: usize = 0x10; // end of interrupt
const GICD_ISENABLER0: usize = 0x100; // set-enable, IRQs 0..31
const CNTHP_INTID: u64 = 26; // non-secure EL2 physical timer PPI
/// Ticks per second: the EL2 timer fires `CNTFRQ/HV_TICK_DIV` apart (≈0.2 s on QEMU `virt`).
const HV_TICK_DIV: u64 = 5;

// ---- Stage 6: PSCI (power state coordination) over SMC ----
//
// A real guest OS powers the machine off, resets, and brings up CPUs via PSCI — `SMC #0` with a
// function id in `x0`. `HCR_EL2.TSC` traps EL1 `SMC` to EL2 (ESR_EL2 EC 0x17); the hypervisor
// emulates the PSCI 1.1 subset a single-vCPU guest needs. Return values follow the PSCI spec.
const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_CPU_ON_32: u64 = 0x8400_0003;
const PSCI_CPU_ON_64: u64 = 0xC400_0003;
const PSCI_MIGRATE_INFO_TYPE: u64 = 0x8400_0006;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_FEATURES: u64 = 0x8400_000A;
const PSCI_NOT_SUPPORTED: i64 = -1;

// ---- Stage 2: the guest's own guest-physical (IPA) address space ----
//
// The guest sees a 2 MiB RAM window at IPA `GUEST_IPA_BASE` (0x4000_0000, like a real `virt`
// board), which stage-2 translation maps to the host-physical [`GUEST_RAM`] arena. Nothing else
// is mapped, so any guest access outside that window faults to EL2. The guest runs at its IPA
// base with its stack at the top of the window; the hypervisor converts a guest pointer back to
// a host address with [`gpa_to_hpa`] before touching it.
const GUEST_IPA_BASE: u64 = 0x4000_0000;
const GUEST_RAM_SIZE: u64 = 0x20_0000; // 2 MiB

/// A 2 MiB-aligned host-physical arena backing the guest's RAM (the blob is copied in at offset 0,
/// the guest runs there at EL1, and its stack lives at the top).
#[repr(C, align(0x200000))]
struct GuestRam([u8; GUEST_RAM_SIZE as usize]);
static mut GUEST_RAM: GuestRam = GuestRam([0; GUEST_RAM_SIZE as usize]);

/// A page-aligned stage-2 translation table (512 × 8-byte descriptors).
#[repr(C, align(4096))]
struct S2Table([u64; 512]);
static mut S2_L1: S2Table = S2Table([0; 512]); // level 1 (1 GiB per entry)
static mut S2_L2: S2Table = S2Table([0; 512]); // level 2 (2 MiB per entry), guest RAM GiB
static mut S2_L2_LOW: S2Table = S2Table([0; 512]); // level 2 for the low GiB (holds the GIC)
static mut S2_L3_GIC: S2Table = S2Table([0; 512]); // level 3 (4 KiB) remapping GICC IPA -> GICV

/// Host-physical base of the guest RAM arena (stable: it is a static).
fn guest_ram_hpa() -> u64 {
    addr_of_mut!(GUEST_RAM) as u64
}

/// Translate a guest-physical address (IPA) to a host-physical address, if it falls in the guest's
/// mapped RAM window. The hypervisor uses this to read/write guest memory a hypercall points at.
fn gpa_to_hpa(ipa: u64) -> Option<u64> {
    if (GUEST_IPA_BASE..GUEST_IPA_BASE + GUEST_RAM_SIZE).contains(&ipa) {
        Some(guest_ram_hpa() + (ipa - GUEST_IPA_BASE))
    } else {
        None
    }
}

/// Build the stage-2 tables mapping `[GUEST_IPA_BASE, +GUEST_RAM_SIZE)` → the guest RAM arena, and
/// program `VTCR_EL2`/`VTTBR_EL2`, enabling stage-2 in `HCR_EL2.VM`. 4 KiB granule, 40-bit IPA,
/// start level 1; the window is a single 2 MiB Normal-WB, read/write/exec block.
fn setup_stage2() {
    let arena = guest_ram_hpa();
    // SAFETY: single-threaded EL2 bring-up; the tables and arena are ours alone.
    unsafe {
        let l1 = addr_of_mut!(S2_L1) as *mut u64;
        let l2 = addr_of_mut!(S2_L2) as *mut u64;
        for i in 0..512 {
            l1.add(i).write_volatile(0);
            l2.add(i).write_volatile(0);
        }
        // L2[0] = 2 MiB block → arena. Lower attrs: valid(1) | MemAttr=0b1111 Normal-WB(<<2) |
        // S2AP=0b11 RW(<<6) | SH=0b11 inner(<<8) | AF(<<10) = 0x7FD; XN=0 (executable).
        l2.add(0).write_volatile(arena | 0x7FD);
        // L1[1] = table descriptor → L2 (IPA 0x4000_0000 has level-1 index 1).
        l1.add(1).write_volatile((l2 as u64) | 0x3);

        // Stage 3: map the guest's GIC CPU interface. IPA GUEST_GICC_IPA (0x0801_0000) lives in the
        // low GiB (L1 index 0), so refine that GiB down to a 4 KiB page that redirects the guest's
        // GICC page to the real GICV. L2_LOW[64] covers 0x0800_0000..0x0820_0000 as a table → L3;
        // L3[16] maps 0x0801_0000 → GICV as Device (nGnRnE, S2AP RW, AF): PA | 0x4C3.
        let l2lo = addr_of_mut!(S2_L2_LOW) as *mut u64;
        let l3 = addr_of_mut!(S2_L3_GIC) as *mut u64;
        for i in 0..512 {
            l2lo.add(i).write_volatile(0);
            l3.add(i).write_volatile(0);
        }
        let l2lo_idx = (GUEST_GICC_IPA >> 21) as usize & 0x1FF; // 64
        let l3_idx = (GUEST_GICC_IPA >> 12) as usize & 0x1FF; // 16
        l3.add(l3_idx).write_volatile(GICV_PA | 0x4C3);
        l2lo.add(l2lo_idx).write_volatile((l3 as u64) | 0x3);
        l1.add(0).write_volatile((l2lo as u64) | 0x3);

        // VTCR_EL2: T0SZ=25 (39-bit IPA), SL0=1 (start L1), IRGN0/ORGN0=WB, SH0=inner, TG0=4KiB,
        // PS=40-bit, bit31 RES1. T0SZ=25 keeps the level-1 lookup to one 512-entry table (9 bits,
        // IPA[38:30]); T0SZ=24 would push it into *concatenated* L1 tables needing an 8 KiB-aligned
        // base, which `S2_L1` (4 KiB-aligned) only satisfied by layout luck — a latent level-1
        // translation fault. A 39-bit IPA still covers the guest's RAM (0x4000_0000) and GIC.
        let vtcr: u64 = 0x8000_0000 | 25 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (2 << 16);
        let vttbr = addr_of_mut!(S2_L1) as u64; // VMID 0
        asm!(
            "dsb ish",
            "msr vtcr_el2, {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "tlbi alle1is",
            "dsb ish",
            "isb",
            vtcr = in(reg) vtcr,
            vttbr = in(reg) vttbr,
            options(nostack, preserves_flags),
        );
    }
}

/// Write a 32-bit MMIO register.
fn write32(addr: usize, val: u32) {
    // SAFETY: MMIO on a GIC register the hypervisor owns.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) };
}

/// Read a 32-bit MMIO register.
fn read32(addr: usize) -> u32 {
    // SAFETY: MMIO on a GIC register the hypervisor owns.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Read `CNTFRQ_EL0` (the generic-timer input frequency).
fn cntfrq() -> u64 {
    let f: u64;
    // SAFETY: reading the counter frequency is side-effect free.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack, preserves_flags)) };
    f
}

/// Arm (or re-arm) the EL2 physical timer to fire one tick from now: reload `CNTHP_TVAL_EL2` and
/// enable it. Writing TVAL both sets the next deadline and clears any pending condition, so this is
/// also how the IRQ handler acknowledges the timer for the next period.
fn arm_el2_timer() {
    let interval = (cntfrq() / HV_TICK_DIV).max(1);
    // SAFETY: EL2 timer registers, accessible at EL2; a one-shot reload with ENABLE=1, IMASK=0.
    unsafe {
        asm!(
            "msr cnthp_tval_el2, {t}",
            "msr cnthp_ctl_el2, {c}",
            "isb",
            t = in(reg) interval,
            c = in(reg) 1u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Emulate one PSCI call (`SMC #0`, function id in `func`). Power-off/reset stop the VM and never
/// return; the rest yield a value for the guest's `x0`. A single-vCPU guest: `CPU_ON` is refused.
fn psci(func: u64, _arg: u64, feat_fn: u64) -> i64 {
    match func {
        PSCI_VERSION => 0x0001_0001, // PSCI v1.1
        PSCI_MIGRATE_INFO_TYPE => 2, // 2 = Trusted OS not present / migration not required
        PSCI_CPU_ON_32 | PSCI_CPU_ON_64 => PSCI_NOT_SUPPORTED, // single vCPU
        PSCI_FEATURES => match feat_fn {
            PSCI_VERSION | PSCI_MIGRATE_INFO_TYPE | PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET
            | PSCI_FEATURES | PSCI_CPU_ON_32 | PSCI_CPU_ON_64 => 0, // supported
            _ => PSCI_NOT_SUPPORTED,
        },
        PSCI_SYSTEM_OFF => {
            puts(b"[hyp] guest PSCI SYSTEM_OFF -- powering the VM off\n");
            hyp_exit(0);
        }
        PSCI_SYSTEM_RESET => {
            puts(b"[hyp] guest PSCI SYSTEM_RESET -- stopping the VM\n");
            hyp_exit(0);
        }
        _ => PSCI_NOT_SUPPORTED,
    }
}

/// Enable the GICv2 hypervisor interface so list-register injections reach the guest's GICV, and
/// seed the virtual CPU-interface control (GICH_VMCR): VENG0+VENG1 (both groups enabled) and
/// VPMR = top priority = 0x1F (accept all) — so a pending list register is actually signalled to
/// the guest even before it touches GICV. (The guest's own GICV_CTLR/PMR writes update VMCR too.)
fn gich_enable() {
    // The virtual CPU interface sits behind the physical GIC, so the host must enable the
    // physical distributor + CPU interface for virtual delivery to work.
    write32(GICD + 0x0, 1); // GICD_CTLR.Enable
    write32(GICD + GICD_ISENABLER0, 1 << CNTHP_INTID); // enable the EL2 physical-timer PPI (26)
    write32(GICC + 0x4, 0xFF); // GICC_PMR = accept all
    write32(GICC + 0x0, 1); // GICC_CTLR.Enable
    write32(GICH + GICH_HCR, 1); // GICH_HCR.En = 1
    write32(GICH + GICH_VMCR, 0xF800_0003); // VPMR=0x1F<<27 | VENG1 | VENG0
}

/// Inject a pending virtual interrupt into list register 0: the guest takes it through its GICV
/// once it unmasks IRQs and enables its CPU interface. GICv2 LR layout: vINTID[9:0],
/// priority[27:23]=0 (highest), State[29:28]=0b01 (pending), Grp1 (bit30=1 → delivered as a
/// non-secure vIRQ, not a Group-0 vFIQ), HW=0 (software). The guest must enable Group 1 on GICV.
fn inject(vintid: u64) {
    write32(GICH + GICH_LR0, (1 << 30) | (1 << 28) | (vintid as u32 & 0x3FF));
}

// ---- Stage 4: an emulated virtio-mmio console (MMIO trap-and-emulate) ----
//
// The guest sees a standard virtio-mmio device at IPA `VIRTIO_MMIO_BASE` (the QEMU `virt` virtio
// slot). That window is deliberately left UNMAPPED in stage-2, so every guest load/store there
// faults to EL2; the abort handler decodes the access from `ESR_EL2` (ISV/SAS/SRT/WnR) and routes
// it to this register-file emulator, then advances the guest past the instruction. When the guest
// kicks the queue (`QueueNotify`), the backend walks the split virtqueue *in guest RAM* (via
// [`gpa_to_hpa`]) and drains the buffers to the real UART — paravirtual console output the way a
// real guest driver does it, with no Bismuth-specific hypercall.
//
// Scope note (see docs/research/hypervisor.md): one queue, modern-mmio register layout but a
// legacy-style zero-feature handshake, polled (no used-buffer IRQ injected), single-shot drain.
const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
const VIRTIO_MMIO_SIZE: u64 = 0x200;
const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_CONSOLE_ID: u32 = 3;

/// The emulated device's register state (single queue). EL2 runs MMU-off and single-threaded, so a
/// plain `static mut` is sound here (no atomics).
struct VirtioConsole {
    status: u32,
    queue_sel: u32,
    queue_num: u32,
    queue_ready: u32,
    desc: u64,
    avail: u64,
    used: u64,
    used_idx: u16,
}
static mut VIRTIO: VirtioConsole =
    VirtioConsole { status: 0, queue_sel: 0, queue_num: 0, queue_ready: 0, desc: 0, avail: 0, used: 0, used_idx: 0 };

// Small physical-memory accessors (EL2 MMU-off ⇒ host-physical == VA). Used to walk guest RAM.
fn rd_u8(a: u64) -> u8 {
    // SAFETY: `a` is a host-physical address inside the guest RAM arena (bounds-checked by caller).
    unsafe { core::ptr::read_volatile(a as *const u8) }
}
fn rd_u16(a: u64) -> u16 {
    (rd_u8(a) as u16) | ((rd_u8(a + 1) as u16) << 8)
}
fn rd_u32(a: u64) -> u32 {
    (rd_u16(a) as u32) | ((rd_u16(a + 2) as u32) << 16)
}
fn rd_u64(a: u64) -> u64 {
    (rd_u32(a) as u64) | ((rd_u32(a + 4) as u64) << 32)
}
fn wr_u16(a: u64, v: u16) {
    // SAFETY: `a` is inside the guest RAM arena (bounds-checked by caller).
    unsafe {
        core::ptr::write_volatile(a as *mut u8, v as u8);
        core::ptr::write_volatile((a + 1) as *mut u8, (v >> 8) as u8);
    }
}
fn wr_u32(a: u64, v: u32) {
    wr_u16(a, v as u16);
    wr_u16(a + 2, (v >> 16) as u16);
}

/// Emulate a guest read of the virtio-mmio register at `off`.
fn virtio_read(off: usize) -> u32 {
    // SAFETY: single-threaded EL2 access to our own device state.
    let v = unsafe { &*addr_of_mut!(VIRTIO) };
    match off {
        0x000 => VIRTIO_MAGIC,
        0x004 => 2,                 // Version (modern mmio)
        0x008 => VIRTIO_CONSOLE_ID, // DeviceID = console
        0x00c => 0x554d_4551,       // VendorID "QEMU"
        0x010 => 0,                 // DeviceFeatures (expose none — legacy-style handshake)
        0x034 => 8,                 // QueueNumMax
        0x044 => v.queue_ready,
        0x060 => 0,                 // InterruptStatus
        0x070 => v.status,
        0x0fc => 0,                 // ConfigGeneration
        _ => 0,
    }
}

/// Emulate a guest write of `val` to the virtio-mmio register at `off`; on `QueueNotify`, drain.
fn virtio_write(off: usize, val: u32) {
    // SAFETY: single-threaded EL2 access to our own device state.
    let v = unsafe { &mut *addr_of_mut!(VIRTIO) };
    match off {
        0x030 => v.queue_sel = val,
        0x038 => v.queue_num = val,
        0x044 => v.queue_ready = val,
        0x050 => virtio_notify(), // QueueNotify: the guest kicked the queue
        0x070 => v.status = val,  // 0 = device reset
        0x080 => v.desc = (v.desc & 0xffff_ffff_0000_0000) | val as u64,
        0x084 => v.desc = (v.desc & 0xffff_ffff) | ((val as u64) << 32),
        0x090 => v.avail = (v.avail & 0xffff_ffff_0000_0000) | val as u64,
        0x094 => v.avail = (v.avail & 0xffff_ffff) | ((val as u64) << 32),
        0x0a0 => v.used = (v.used & 0xffff_ffff_0000_0000) | val as u64,
        0x0a4 => v.used = (v.used & 0xffff_ffff) | ((val as u64) << 32),
        _ => {} // DeviceFeaturesSel/DriverFeatures(Sel)/InterruptACK: accepted, no state needed
    }
}

/// Walk the split virtqueue in guest RAM and drain each newly-available buffer to the UART,
/// marking it used. Descriptor/ring addresses are guest IPAs translated through stage-2.
fn virtio_notify() {
    // SAFETY: single-threaded EL2 access to our own device state.
    let v = unsafe { &mut *addr_of_mut!(VIRTIO) };
    let qsize = if v.queue_num == 0 { 8 } else { v.queue_num as u16 };
    let (Some(desc), Some(avail), Some(used)) =
        (gpa_to_hpa(v.desc), gpa_to_hpa(v.avail), gpa_to_hpa(v.used))
    else {
        puts(b"[hyp] virtio: queue addresses outside guest RAM\n");
        return;
    };
    let avail_idx = rd_u16(avail + 2); // avail.idx
    while v.used_idx != avail_idx {
        let slot = (v.used_idx % qsize) as u64;
        let head = rd_u16(avail + 4 + slot * 2); // desc index for this request
        // Follow the descriptor chain, draining each buffer to the UART.
        let mut di = head;
        let mut total = 0u32;
        loop {
            let Some(d) = gpa_to_hpa(v.desc.wrapping_add(di as u64 * 16)) else { break };
            let _ = desc;
            let buf_ipa = rd_u64(d);
            let len = rd_u32(d + 8);
            let flags = rd_u16(d + 12);
            let next = rd_u16(d + 14);
            if let Some(buf) = gpa_to_hpa(buf_ipa) {
                if buf_ipa + len as u64 <= GUEST_IPA_BASE + GUEST_RAM_SIZE {
                    for i in 0..len as u64 {
                        put(rd_u8(buf + i));
                    }
                    total += len;
                }
            }
            if flags & 0x1 != 0 {
                di = next; // VIRTQ_DESC_F_NEXT
            } else {
                break;
            }
        }
        // Publish the completion in the used ring.
        let uslot = (v.used_idx % qsize) as u64;
        wr_u32(used + 4 + uslot * 8, head as u32); // used.ring[].id
        wr_u32(used + 8 + uslot * 8, total); // used.ring[].len
        v.used_idx = v.used_idx.wrapping_add(1);
        wr_u16(used + 2, v.used_idx); // used.idx
    }
}

/// Write one byte to the PL011, spinning while the TX FIFO is full.
fn put(b: u8) {
    // SAFETY: MMIO on the QEMU `virt` PL011; the hypervisor owns the UART.
    unsafe {
        while core::ptr::read_volatile((UART + UART_FR) as *const u32) & (1 << 5) != 0 {}
        core::ptr::write_volatile((UART + UART_DR) as *mut u32, b as u32);
    }
}

/// Write a byte string to the PL011.
fn puts(s: &[u8]) {
    for &b in s {
        put(b);
    }
}

/// Print a small unsigned decimal.
fn put_dec(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    puts(&buf[i..]);
}

/// Current exception level (`CurrentEL[3:2]`).
fn current_el() -> u64 {
    let el: u64;
    // SAFETY: reading CurrentEL is side-effect free.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack, preserves_flags)) };
    el >> 2
}

/// Exit QEMU via semihosting (works from EL2).
fn hyp_exit(code: u64) -> ! {
    let block = [0x2_0026usize, code as usize];
    // SAFETY: `hlt #0xf000` is the AArch64 semihosting trap; x0 = SYS_EXIT, x1 = &block.
    unsafe {
        asm!("hlt #0xf000", in("x0") 0x18, in("x1") block.as_ptr(), options(nostack, preserves_flags));
    }
    loop {
        // SAFETY: parking if the semihosting host is absent.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

/// The EL2 exception vector table (`VBAR_EL2`): 16 entries × 128 bytes, 2 KiB-aligned. Only the
/// Lower-EL-AArch64 Synchronous slot (the guest's `HVC`/faults) is live; the rest report + halt.
#[unsafe(naked)]
#[unsafe(link_section = ".text.vectors")]
pub extern "C" fn hyp_vectors() {
    naked_asm!(
        ".balign 0x800",
        // Current EL with SP0.
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // Current EL with SPx (EL2 itself).
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // Lower EL using AArch64 (the guest at EL1): Sync = HVC/SMC gate, IRQ = EL2 timer.
        ".balign 0x80", "b {sync}",
        ".balign 0x80", "b {irq}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        // Lower EL using AArch32 (unused).
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        ".balign 0x80", "b {bad}",
        sync = sym hvc_vector,
        irq = sym hyp_irq_vector,
        bad = sym hyp_bad,
    )
}

/// Guest IRQ taken to EL2 (`HCR_EL2.IMO`): the EL2 physical timer. Save/restore all guest GPRs
/// around the handler and `eret` back into the guest.
#[unsafe(naked)]
extern "C" fn hyp_irq_vector() {
    naked_asm!(
        "sub sp, sp, #256",
        "stp x0, x1, [sp, #0]",
        "stp x2, x3, [sp, #16]",
        "stp x4, x5, [sp, #32]",
        "stp x6, x7, [sp, #48]",
        "stp x8, x9, [sp, #64]",
        "stp x10, x11, [sp, #80]",
        "stp x12, x13, [sp, #96]",
        "stp x14, x15, [sp, #112]",
        "stp x16, x17, [sp, #128]",
        "stp x18, x19, [sp, #144]",
        "stp x20, x21, [sp, #160]",
        "stp x22, x23, [sp, #176]",
        "stp x24, x25, [sp, #192]",
        "stp x26, x27, [sp, #208]",
        "stp x28, x29, [sp, #224]",
        "str x30, [sp, #240]",
        "bl {entry}",
        "ldp x0, x1, [sp, #0]",
        "ldp x2, x3, [sp, #16]",
        "ldp x4, x5, [sp, #32]",
        "ldp x6, x7, [sp, #48]",
        "ldp x8, x9, [sp, #64]",
        "ldp x10, x11, [sp, #80]",
        "ldp x12, x13, [sp, #96]",
        "ldp x14, x15, [sp, #112]",
        "ldp x16, x17, [sp, #128]",
        "ldp x18, x19, [sp, #144]",
        "ldp x20, x21, [sp, #160]",
        "ldp x22, x23, [sp, #176]",
        "ldp x24, x25, [sp, #192]",
        "ldp x26, x27, [sp, #208]",
        "ldp x28, x29, [sp, #224]",
        "ldr x30, [sp, #240]",
        "add sp, sp, #256",
        "eret",
        entry = sym hyp_irq_entry,
    )
}

/// Service an EL2 IRQ. Acknowledge via the physical GIC CPU interface; if it is the EL2 physical
/// timer, re-arm it for the next period and inject the guest's virtual-timer vIRQ; then EOI.
extern "C" fn hyp_irq_entry() {
    let iar = read32(GICC + GICC_IAR);
    let intid = (iar & 0x3FF) as u64;
    if intid == CNTHP_INTID {
        arm_el2_timer(); // reload the one-shot and clear the pending condition
        inject(VTIMER_INTID); // hand the guest its virtual-timer tick
    }
    if intid != 0x3FF {
        write32(GICC + GICC_EOIR, iar); // spurious (1023) needs no EOI
    }
}

/// Guest synchronous exception from EL1: save the guest GPRs, service the hypercall, restore, and
/// `eret` back to the guest (for a `print`; `exit` never returns).
#[unsafe(naked)]
extern "C" fn hvc_vector() {
    naked_asm!(
        "sub sp, sp, #256",
        "stp x0, x1, [sp, #0]",
        "stp x2, x3, [sp, #16]",
        "stp x4, x5, [sp, #32]",
        "stp x6, x7, [sp, #48]",
        "stp x8, x9, [sp, #64]",
        "stp x10, x11, [sp, #80]",
        "stp x12, x13, [sp, #96]",
        "stp x14, x15, [sp, #112]",
        "stp x16, x17, [sp, #128]",
        "stp x18, x19, [sp, #144]",
        "stp x20, x21, [sp, #160]",
        "stp x22, x23, [sp, #176]",
        "stp x24, x25, [sp, #192]",
        "stp x26, x27, [sp, #208]",
        "stp x28, x29, [sp, #224]",
        "str x30, [sp, #240]",
        "mov x0, sp",
        "bl {entry}",
        "ldp x0, x1, [sp, #0]",
        "ldp x2, x3, [sp, #16]",
        "ldp x4, x5, [sp, #32]",
        "ldp x6, x7, [sp, #48]",
        "ldp x8, x9, [sp, #64]",
        "ldp x10, x11, [sp, #80]",
        "ldp x12, x13, [sp, #96]",
        "ldp x14, x15, [sp, #112]",
        "ldp x16, x17, [sp, #128]",
        "ldp x18, x19, [sp, #144]",
        "ldp x20, x21, [sp, #160]",
        "ldp x22, x23, [sp, #176]",
        "ldp x24, x25, [sp, #192]",
        "ldp x26, x27, [sp, #208]",
        "ldp x28, x29, [sp, #224]",
        "ldr x30, [sp, #240]",
        "add sp, sp, #256",
        "eret",
        entry = sym hvc_entry,
    )
}

/// Service one guest synchronous trap. `frame` points at the saved GPR image (`x0..x30`); it is
/// mutable so an emulated MMIO read can deliver its result into the guest's destination register.
extern "C" fn hvc_entry(frame: *mut u64) {
    let esr: u64;
    // SAFETY: reading the EL2 syndrome register is side-effect free.
    unsafe { asm!("mrs {}, esr_el2", out(reg) esr, options(nomem, nostack, preserves_flags)) };
    let ec = esr >> 26;
    if ec == 0x17 {
        // SMC from EL1, trapped by HCR_EL2.TSC: emulate PSCI. The function id is in x0, args in
        // x1.. ; a trapped SMC does NOT advance the PC, so bump ELR_EL2 past it before returning.
        // SAFETY: `frame` holds the guest GPR image; x0 = PSCI function, x1 = arg / queried fn.
        let (func, arg) = unsafe { (*frame, *frame.add(1)) };
        let ret = psci(func, arg, arg);
        // SAFETY: deliver the PSCI result in the guest's x0 and skip the `smc` instruction.
        unsafe {
            *frame = ret as u64;
            let elr: u64;
            asm!("mrs {}, elr_el2", out(reg) elr, options(nomem, nostack, preserves_flags));
            asm!("msr elr_el2, {}", in(reg) elr + 4, options(nomem, nostack, preserves_flags));
        }
        return;
    }
    if ec != 0x16 {
        // Not an HVC — a genuine guest fault. A stage-2 abort (EC 0x24 data / 0x20 instruction
        // from a lower EL) carries the faulting guest-physical address in HPFAR_EL2; report it
        // specifically to prove the guest was confined to its mapped RAM, then stop the VM.
        let (elr, far, hpfar): (u64, u64, u64);
        // SAFETY: reading EL2 fault registers is side-effect free.
        unsafe {
            asm!("mrs {}, elr_el2", out(reg) elr, options(nomem, nostack, preserves_flags));
            asm!("mrs {}, far_el2", out(reg) far, options(nomem, nostack, preserves_flags));
            asm!("mrs {}, hpfar_el2", out(reg) hpfar, options(nomem, nostack, preserves_flags));
        }
        if ec == 0x24 || ec == 0x20 {
            // Faulting IPA: HPFAR_EL2[43:4] = IPA[51:12]; combine with FAR_EL2's page offset.
            let ipa = ((hpfar & 0xF_FFFF_FFF0) << 8) | (far & 0xFFF);
            // Stage 4: a data abort inside the emulated virtio-mmio window is not a violation —
            // trap-and-emulate the register access and resume the guest past the instruction.
            if ec == 0x24 && (VIRTIO_MMIO_BASE..VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE).contains(&ipa) {
                let iss = esr & 0x1FF_FFFF;
                if (iss >> 24) & 1 == 1 {
                    // ISV=1: the syndrome describes the access. SRT=reg, WnR=direction.
                    let srt = ((iss >> 16) & 0x1f) as usize;
                    let wnr = (iss >> 6) & 1;
                    let off = (ipa - VIRTIO_MMIO_BASE) as usize;
                    if wnr == 1 {
                        // Store: the value is in the source register (x31 = XZR = 0).
                        let val = if srt == 31 { 0 } else { unsafe { *frame.add(srt) } } as u32;
                        virtio_write(off, val);
                    } else {
                        // Load: deliver the emulated register value into the destination register.
                        let val = virtio_read(off);
                        if srt != 31 {
                            unsafe { *frame.add(srt) = val as u64 };
                        }
                    }
                    // Resume the guest at the next instruction (all loads/stores here are 4 bytes).
                    // SAFETY: advancing the guest's return address past the emulated access.
                    unsafe { asm!("msr elr_el2, {}", in(reg) elr + 4, options(nomem, nostack, preserves_flags)) };
                    return;
                }
                puts(b"[hyp] virtio: un-decodable access (ISV=0) at IPA=");
                put_hex(ipa);
                put(b'\n');
                hyp_exit(1);
            }
            puts(b"[hyp] stage-2 fault: guest ");
            puts(if ec == 0x24 { b"read/write" } else { b"exec" });
            puts(b" of unmapped IPA=");
            put_hex(ipa);
            puts(b" (ELR_EL2=");
            put_hex(elr);
            puts(b") -- guest killed
");
            hyp_exit(1);
        }
        puts(b"[hyp] guest fault: ESR_EL2=");
        put_hex(esr);
        puts(b" ELR_EL2=");
        put_hex(elr);
        puts(b" FAR_EL2=");
        put_hex(far);
        puts(b" -- stopping VM
");
        hyp_exit(1);
    }
    // SAFETY: `frame` is the GPR image the vector just pushed; x0..x2 are the hypercall args.
    let (cmd, a1, a2) = unsafe { (*frame, *frame.add(1), *frame.add(2)) };
    match cmd {
        HVC_PRINT => {
            // `a1` is a guest-physical address (IPA); translate it to a host address through the
            // stage-2 window before reading, and bound the length to the guest's RAM.
            match gpa_to_hpa(a1) {
                Some(hpa) if a1 + a2 <= GUEST_IPA_BASE + GUEST_RAM_SIZE => {
                    // SAFETY: [hpa, hpa+a2) lies within the guest RAM arena (bounds checked above).
                    let s = unsafe { core::slice::from_raw_parts(hpa as *const u8, a2 as usize) };
                    puts(s);
                }
                _ => puts(b"[hyp] rejected print: pointer outside guest RAM\n"),
            }
        }
        HVC_TICK => {
            // The guest asks for its next virtual-timer interrupt: inject it into GICH_LR0. The
            // guest takes it (through GICV) as soon as this `eret` returns to EL1.
            inject(VTIMER_INTID);
        }
        4 => {
            // Diagnostic: print `a1` as hex (used by the guest to dump ESR_EL1 etc.).
            put_hex(a1);
            put(b'\n');
        }
        HVC_EXIT => {
            puts(b"[hyp] guest requested exit, code ");
            put_dec(a1);
            put(b'\n');
            hyp_exit(a1);
        }
        other => {
            puts(b"[hyp] unknown hypercall ");
            put_dec(other);
            put(b'\n');
        }
    }
}

fn put_hex(mut v: u64) {
    puts(b"0x");
    let mut started = false;
    for i in (0..16).rev() {
        let nyb = ((v >> (i * 4)) & 0xf) as u8;
        if nyb != 0 || started || i == 0 {
            started = true;
            put(if nyb < 10 { b'0' + nyb } else { b'a' + nyb - 10 });
        }
    }
    let _ = &mut v;
}

extern "C" fn hyp_bad() -> ! {
    puts(b"[hyp] unexpected EL2 exception -- halted
");
    hyp_exit(2);
}

/// Load `blob` as a guest and run it at EL1, servicing its hypercalls. Never returns: the guest's
/// `HVC_EXIT` ends the run. Called from the board's `hypervisor` flow (at EL2).
pub fn run_guest(blob: &[u8]) -> ! {
    puts(b"\n[hyp] Bismuth hypervisor up at EL");
    put_dec(current_el());
    puts(b" (QEMU virt)\n");
    if current_el() != 2 {
        puts(b"[hyp] not at EL2 (need -M virt,virtualization=on) -- halting
");
        hyp_exit(3);
    }

    // Copy the guest into the host-physical arena (at offset 0); the guest runs at its IPA base
    // under stage-2, with its stack at the top of the IPA window.
    let n = blob.len().min(GUEST_RAM_SIZE as usize);
    // SAFETY: single-threaded EL2 bring-up; the arena is ours alone.
    unsafe {
        let buf = addr_of_mut!(GUEST_RAM) as *mut u8;
        for i in 0..n {
            core::ptr::write_volatile(buf.add(i), blob[i]);
        }
        asm!("dsb ish", options(nostack, preserves_flags));
    }
    let entry = GUEST_IPA_BASE; // guest-physical (IPA) entry
    let gsp = (GUEST_IPA_BASE + GUEST_RAM_SIZE) & !0xf; // guest stack top (IPA)

    // Build and enable the guest's stage-2 address space before entering it.
    setup_stage2();

    puts(b"[hyp] stage-2 on: guest RAM IPA=");
    put_hex(GUEST_IPA_BASE);
    puts(b"..+2MiB -> HPA=");
    put_hex(guest_ram_hpa());
    put(b'\n');
    // Stage 3/6: bring up the vGIC, then arm the EL2 physical timer. Its interrupt fires to EL2 on
    // a free-running cadence (HCR_EL2.IMO routes it up while the guest runs at EL1); the EL2 IRQ
    // handler injects the guest's virtual-timer vIRQ each period — the guest no longer asks for it.
    gich_enable();
    arm_el2_timer();
    puts(b"[hyp] vGIC up (GICH enabled); guest GIC CPU iface = GICV @ IPA ");
    put_hex(GUEST_GICC_IPA);
    puts(b"; EL2 physical timer armed -> injects vINTID ");
    put_dec(VTIMER_INTID);
    puts(b" every ~1/");
    put_dec(HV_TICK_DIV);
    puts(b" s\n");
    puts(b"[hyp] launching guest at EL1, entry IPA=");
    put_hex(entry);
    put(b'\n');

    let vbar = hyp_vectors as *const () as u64;
    // SAFETY: install the EL2 vectors, make the guest AArch64 + enable stage-2 (HCR_EL2.RW|VM),
    // set its stack and return state, and `eret` into it at EL1. Control re-enters only via
    // `VBAR_EL2` on a trap. (No asm outputs/scratch: `noreturn` forbids them.)
    unsafe {
        asm!(
            "msr vbar_el2, {vbar}",
            "isb",
            "msr hcr_el2, {hcr}",     // RW=1 (EL1 AArch64) | VM=1 (stage-2) | IMO=1 (route physical
                                      // IRQs to EL2 + signal vGIC virtual IRQs to EL1) | TSC=1
                                      // (trap the guest's SMC/PSCI to EL2)
            "msr sp_el1, {gsp}",
            "msr elr_el2, {entry}",
            "msr spsr_el2, {spsr}",   // EL1h, DAIF masked
            "isb",
            "eret",
            vbar = in(reg) vbar,
            hcr = in(reg) 0x8008_0011u64,
            gsp = in(reg) gsp,
            entry = in(reg) entry,
            spsr = in(reg) 0x3c5u64,
            options(noreturn),
        )
    }
}
