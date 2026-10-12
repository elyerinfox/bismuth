//! Bundled network drivers.
//!
//! | driver       | tier   | purpose                                                  |
//! |--------------|--------|----------------------------------------------------------|
//! | [`Loopback`]  | ring   | frames sent are received back (zero-copy buffer swap)   |
//! | [`WireEnd`]   | frame  | one end of a simulated Ethernet cable ([`Wire`]); wrap in a [`SoftRing`](super::SoftRing) |
//! | [`VirtioNet`] | frame  | virtio-net over virtio-MMIO (QEMU `virt`, SoCs); DMA (TCB), wrap in a [`SoftRing`](super::SoftRing) |
//!
//! Classification: L3 services · net: bundled drivers · safe · net

pub mod loopback;
pub mod virtio_net;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod virtio_net_pci;
pub mod wire;

pub use loopback::Loopback;
pub use virtio_net::VirtioNet;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use virtio_net_pci::VirtioNetPci;
pub use wire::{Wire, WireEnd};

#[cfg(not(target_os = "none"))]
pub(crate) fn reset() {
    wire::reset();
}
