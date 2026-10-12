//! Minimal PCI access for the x86-64 port: configuration space through the legacy 0xCF8/0xCFC
//! I/O ports, a brute-force bus/slot/function scan to find a device by vendor/device id, and the
//! 16/32-bit port I/O a device's I/O-BAR registers need. Enough to bring up a legacy (I/O-BAR)
//! virtio-pci device without touching the MMIO BARs (which may be outside the mapped physical
//! window). Bounded, no heap.
//!
//! Part of the trusted computing base: raw port I/O. No memory safety is at stake (reads/writes
//! of I/O ports), but it is `unsafe` inline assembly, so it lives with the rest of the port.
//!
//! Classification: L0 port · x86-64 PCI · TCB (unsafe allowed) · target_os = "none"
#![allow(unsafe_code)]

use core::arch::asm;

// ----- 16/32-bit port I/O (the byte variants live in the parent module) -----

pub fn outl(port: u16, val: u32) {
    // SAFETY: a 32-bit write to an I/O port has no memory-safety implications.
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags)) };
}

pub fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: a 32-bit read of an I/O port has no memory-safety implications.
    unsafe { asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn outw(port: u16, val: u16) {
    // SAFETY: a 16-bit write to an I/O port has no memory-safety implications.
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags)) };
}

pub fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: a 16-bit read of an I/O port has no memory-safety implications.
    unsafe { asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
    v
}

/// Byte-wide port writes/reads (the parent module keeps the UART's copies; these let the PCI
/// driver address an I/O-BAR's 8-bit registers without reaching across modules).
pub fn outb_at(port: u16, val: u8) {
    super::outb(port, val);
}

pub fn inb_at(port: u16) -> u8 {
    super::inb(port)
}

// ----- PCI configuration space (mechanism #1: 0xCF8 address / 0xCFC data) -----

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

fn config_address(bus: u8, slot: u8, func: u8, off: u8) -> u32 {
    0x8000_0000 | ((bus as u32) << 16) | ((slot as u32) << 11) | ((func as u32) << 8) | ((off as u32) & 0xFC)
}

/// A PCI function located on the bus, identified by its `(bus, slot, func)` coordinates.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
}

impl PciDevice {
    pub fn read32(&self, off: u8) -> u32 {
        outl(CONFIG_ADDRESS, config_address(self.bus, self.slot, self.func, off));
        inl(CONFIG_DATA)
    }

    pub fn read16(&self, off: u8) -> u16 {
        (self.read32(off & 0xFC) >> ((off & 2) * 8)) as u16
    }

    pub fn write32(&self, off: u8, val: u32) {
        outl(CONFIG_ADDRESS, config_address(self.bus, self.slot, self.func, off));
        outl(CONFIG_DATA, val);
    }

    pub fn write16(&self, off: u8, val: u16) {
        let aligned = off & 0xFC;
        let shift = (off & 2) * 8;
        let cur = self.read32(aligned);
        let merged = (cur & !(0xFFFFu32 << shift)) | ((val as u32) << shift);
        self.write32(aligned, merged);
    }

    pub fn vendor(&self) -> u16 {
        self.read16(0x00)
    }

    pub fn device(&self) -> u16 {
        self.read16(0x02)
    }

    /// The subsystem id (offset 0x2E) — for transitional virtio it carries the device type.
    pub fn subsystem(&self) -> u16 {
        self.read16(0x2E)
    }

    /// Base address register `n` (0..6), at config offset 0x10 + 4n.
    pub fn bar(&self, n: u8) -> u32 {
        self.read32(0x10 + n * 4)
    }

    /// If BAR `n` is an I/O-space BAR, its base port (low two bits masked off).
    pub fn io_bar(&self, n: u8) -> Option<u16> {
        let b = self.bar(n);
        if b & 1 == 1 { Some((b & 0xFFFC) as u16) } else { None }
    }

    /// Enable the device's I/O-space decoding and bus-mastering (DMA) in the command register.
    pub fn enable_io_and_bus_master(&self) {
        let cmd = self.read16(0x04);
        self.write16(0x04, cmd | 0x1 | 0x4); // I/O space | bus master
    }
}

/// Find the first PCI function matching `vendor` and one of `devices`. Scans all buses/slots; a
/// vendor id of 0xFFFF marks an absent function.
pub fn find(vendor: u16, devices: &[u16]) -> Option<PciDevice> {
    for bus in 0u8..=255 {
        for slot in 0u8..32 {
            for func in 0u8..8 {
                let d = PciDevice { bus, slot, func };
                let v = d.vendor();
                if v == 0xFFFF {
                    if func == 0 {
                        break; // no function 0 => slot empty
                    }
                    continue;
                }
                if v == vendor && devices.contains(&d.device()) {
                    return Some(d);
                }
            }
        }
    }
    None
}
