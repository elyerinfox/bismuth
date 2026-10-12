//! SPI bus device class: full-duplex, byte-shifted serial transfers. A controller driver
//! implements [`SpiBus`] (its registers and any DMA live in `arch::mmio`, the TCB); higher
//! layers — like the TPM 2.0 TIS transport (`crate::security::tpm_tis`) — drive peripherals
//! over it in 100% safe Rust, exactly as the block and net stacks sit over their device traits.
//!
//! Classification: L2 devices · SPI bus class · safe · always

use crate::Error;

/// A SPI master. One in-flight transaction at a time; the implementation serialises concurrent
/// callers (like the other device classes).
pub trait SpiBus: Sync {
    /// Full-duplex transfer: every byte in `buf` is shifted out MSB-first and replaced, in
    /// place, by the byte simultaneously shifted in. Chip-select is asserted for the whole call.
    fn transfer(&self, buf: &mut [u8]) -> Result<(), Error>;

    /// Transmit `tx` then clock in `rx.len()` bytes into `rx`, as one chip-select transaction
    /// (the half-duplex pattern most register protocols use). The default composes [`transfer`]
    /// over a scratch split; controllers with a native half-duplex mode may override it.
    fn write_then_read(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), Error> {
        // Small register transactions only; callers needing more do it in chunks.
        const SCRATCH: usize = 72;
        let total = tx.len() + rx.len();
        if total > SCRATCH {
            return Err(Error::Overflow);
        }
        let mut buf = [0u8; SCRATCH];
        buf[..tx.len()].copy_from_slice(tx);
        self.transfer(&mut buf[..total])?;
        rx.copy_from_slice(&buf[tx.len()..total]);
        Ok(())
    }
}
