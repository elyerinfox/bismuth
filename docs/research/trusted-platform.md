# Bismuth Trusted Platform: TPM, Hardware Root of Trust, and TPM-Derived Encryption

> Status: research and design proposal, not yet implemented.
> Scope: whether and how Bismuth can support a Trusted Platform Module (TPM 2.0) or a
> secure element as a hardware root of trust, and what "memory encryption derived from the
> TPM" can honestly mean on the kernel's targets (Cortex-M3/M4/M33/M55 and RV32 MCUs: tens
> to hundreds of KB of on-chip SRAM, an MPU or PMP but no MMU, no DRAM controller). It
> answers the user's question — *"can we support TPM and memory encryption derived from
> it?"* — by designing a discrete-TPM/secure-element device driver, a trusted-platform
> service (measured boot, sealing, attestation), a TPM-rooted key hierarchy that reuses the
> existing keystore, and three forms of scoped software encryption that actually work on an
> MCU. It is explicit about the one thing that does **not** work (transparent always-on
> hardware RAM encryption).
>
> Read alongside [`docs/research/security.md`](./security.md) (domains, handles, rights,
> keystore, entropy, DICE/attestation, TrustZone-M) and
> [`docs/research/filesystems.md`](./filesystems.md) (the `BlockDevice` class the
> encrypted-storage layer builds on). This document reuses that vocabulary rather than
> repeating it.
>
> Current Bismuth baseline (read from the tree):
> - **Software root of trust only.** `security::keystore` holds key material behind
>   generation-checked `Handle`s with PSA-style usage rights (`K_ENCRYPT`, `K_DERIVE`, …),
>   does ChaCha20-Poly1305 / HMAC-SHA-256 / HKDF-SHA-256 / SHA-256 over vetted RustCrypto
>   crates, runs KATs before first use, and zeroizes on destroy. `security::entropy`
>   gathers health-tested TRNG samples into per-domain ChaCha20 fast-key-erasure DRBGs.
>   There is no hardware-anchored key, no measured boot, and no attestation.
> - **`security::container::ContainerDecl` already carries `version: u32` and
>   `image_hash: [u8; 32]`** ("Measurement of the workload image … for attestation"), and
>   `Health` carries `generation`/`violations`/`faults`. These fields are *stored only*
>   today — nothing extends them into a PCR or signs them. §4 makes them live.
> - **`DeviceClass::Spi` is reserved** in `driver/mod.rs` but unimplemented; `DeviceClass::I2c`
>   is implemented (`driver/i2c`, with a `SimI2c` + `I2cTarget` sim). A discrete TPM speaks
>   SPI or I2C, so it slots into the existing bus/driver/middleware model.
> - **The crate is `#![deny(unsafe_code)]` with a 5-module TCB**
>   (`arch/cortex_m.rs`, `arch/mmio.rs`, `kernel/cell.rs`, `kernel/stack.rs`,
>   `kernel/usermem.rs`). Only the SPI/I2C controller's register access may touch
>   `arch/mmio.rs`; every byte of TPM protocol and all crypto is ordinary safe Rust.
> - **Everything is statically sized** from `config.rs` (`BISMUTH_*` consts). No heap.
> - **The host simulator (`sim.rs`) resets and runs a whole system in a test.** A software
>   TPM model (§2.4) makes every seal/unseal/PCR/attestation/encrypted-storage path testable
>   with no hardware — this is a first-class requirement, not an afterthought.

---

## 0. TL;DR

- **Yes, as a device — no, as magic.** A discrete **TPM 2.0 over SPI/I2C** (Infineon OPTIGA
  SLB 9670 SPI or SLB 9673 I2C, ST ST33, Microchip ATTPM20P) or a **secure element**
  (Microchip ATECC608, Infineon OPTIGA Trust M) fits Bismuth's `Driver`/bus model cleanly
  and gives a real hardware root of trust. What it does **not** give — and cannot, on this
  class of part — is transparent, always-on encryption of all of RAM. There is no DRAM
  controller with inline AES (AMD SME/SEV, Intel TME/MKTME are server/DRAM features), no
  MMU to fault on access and decrypt a line, and software "encrypt all of SRAM" is a
  non-starter (no fault path, ruinous perf). So **"memory encryption derived from the TPM"
  on Bismuth means scoped software encryption of specific regions, keyed from the TPM**, not
  an omnipresent layer. §9 leads with this limitation.
- **Three forms of scoped encryption that do work**, all keyed from a TPM-sealed root KEK and
  all built on the *existing* keystore AEAD: **(a)** encrypted storage at rest (an encrypted
  `BlockDevice` wrapper whose key is released only by a measured-boot `TPM2_Unseal`), **(b)**
  encrypted retained SRAM across deep-sleep/hibernate (AEAD-seal a static region before
  power-down, re-derive the key and decrypt on resume — cold-boot resistance), **(c)**
  sealed-secret / "enclave-lite" protected-object buffers (secrets kept AEAD-encrypted in
  RAM, decrypted into a tiny scratch only while in use, then re-sealed).
- **Layering:** the **TPM transport** (TIS framing over SPI/I2C, locality, STS polling, the
  SPI wait state) is **L2 `driver`**, moves opaque bytes only, and holds no keys — so it
  never imports the security layer. The **trusted-platform service** (TPM 2.0 command codec,
  PCRs, seal/unseal, quote, KEK release into the keystore, session crypto) is **L3
  `security::trust`**, which may import both the L2 transport and its L3 keystore sibling.
  This keeps the downward-only import rule (`tests/structure.rs`) intact.
- **Pure-Rust, minimal command subset — no C TPM stack.** `tss-esapi` is a C-backed FFI
  wrapper, not `no_std`; linking `tpm2-tss` would break the safe-Rust rule. Instead implement
  ~13 TPM 2.0 commands as plain byte marshalling in safe Rust (a TPM command is a big-endian
  TLV blob; the codec is tractable and 100% safe). This is the only honest option under
  `#![deny(unsafe_code)]`.
- **TPM roots the keystore; the keystore does the hierarchy.** The TPM's job is to *gate
  release* of one 32-byte root KEK on the measured-boot PCR state (`TPM2_Unseal`). That KEK
  is `keystore::import`ed as a non-exportable HKDF IKM; per-domain / per-volume KEKs come
  from the **existing `keystore::derive` (HKDF-SHA-256)**. Keys never leave the keystore;
  the TPM never does bulk crypto. This division is fast, static, and reuses code already in
  the tree.
- **Crypto mismatch is contained.** Everything *we* do with derived keys stays on the
  in-tree RustCrypto primitives (ChaCha20-Poly1305, HKDF/HMAC/SHA-256, zeroize). The TPM
  *internally* uses SHA-256 PCR banks and, for **session parameter encryption**, AES-CFB —
  which we need **only** if the threat model includes a bus interposer that must not see the
  unsealed KEK. That one case needs an AES implementation (`aes` + `cfb-mode`), **flagged in
  §7 for a decision**; the rest of the system needs no new crypto crate.
- **Fully host-testable.** A safe in-memory **software TPM** (`SoftTpm`) implements the same
  command subset behind the same transport trait, so seal/unseal, PCR policy, quotes and the
  whole encrypted-storage path run deterministically in the simulator — including an
  interposer model for the session-crypto tests.
- **Measured vs secure boot.** Bismuth is not the bootloader (consistent with
  `security.md`): secure boot (verify-and-refuse) belongs to the first stage. Bismuth does
  *measured* boot — it extends the handoff measurements, the manifest hash, and each
  container's `image_hash`/`version` into TPM PCRs, then seals storage keys to that state and
  attests it. Sealing-to-PCR is what makes at-rest key release **power-fail-safe**: a device
  that boots into the wrong state simply never gets the key.

---

## 1. Problem statement, baseline, and threat model

### 1.1 What the user asked and what it decomposes into

"Can we support TPM and memory encryption derived from it?" is two questions:

1. **Can Bismuth use a hardware root of trust (a TPM or equivalent)?** Yes. A discrete TPM
   or secure element is just a device on an existing bus, and the protocol and crypto are
   safe Rust. §§2–5.
2. **Can we derive *memory encryption* from it?** Partly, and the honest answer matters.
   "Memory encryption" to most people means *transparent full-RAM encryption* (AMD SME,
   Intel TME). That is impossible on an MCU (§9.1). What is both possible and useful is
   **scoped software encryption of specific regions and of data at rest, with the key rooted
   in the TPM**. §6 designs the three forms that work.

### 1.2 Where Bismuth is today

| Capability | Today | Gap this document fills |
|---|---|---|
| Key storage | `keystore` RAM table, generation-checked handles, PSA usage rights | Keys are seeded from the per-domain DRBG only; **nothing anchors them to hardware**, so a cloned image yields cloneable keys |
| Randomness | Health-tested TRNG → per-domain ChaCha20 FKE DRBG | A TPM's `TPM2_GetRandom` is a NIST-assessed source we can credit and mix in (§5.4) |
| Boot trust | None in-kernel; `security.md` plans a DICE handoff | No PCRs, no sealing to boot state, no attestation |
| Workload identity | `ContainerDecl.version` / `image_hash` **stored only** | Extend them into PCRs; seal/attest against them (§4) |
| At-rest encryption | None (no block/FS layer existed; `filesystems.md` adds `BlockDevice`) | Encrypted `BlockDevice` wrapper keyed by unseal-at-boot (§6a) |
| Sleep/resume secrecy | Retained RAM (if any) is plaintext | AEAD-seal retained SRAM before power-down (§6b) |
| Secret hygiene in RAM | `zeroize` on destroy; secrets live in cleartext while held | Keep secrets sealed, open into scratch only while in use (§6c) |

### 1.3 Threat model (and the scoping that leads)

**In scope, and what each mitigation buys:**

| Adversary | Without a TPM | With this design |
|---|---|---|
| **Image cloning / counterfeit** (copy the firmware + flash to another board) | Clone has identical keys; indistinguishable | Root KEK is sealed to *this* TPM; a clone's TPM holds a different seed, so the KEK never unseals and encrypted storage is inert (§4, §6a) |
| **Offline flash readout** (desolder/read the SPI flash or SD card) | Plaintext data and keys | Data is AEAD ciphertext; the key is in the TPM, released only after a correct measured boot (§6a) |
| **Cold-boot / power-pull on retained SRAM** (read remanent SRAM after yanking power) | Remanent secrets recoverable ([Halderman et al.][coldboot]; TPM-protected systems are *not* immune — the attack targets RAM, not the TPM [[Whonix][whonix-cb]]) | Retained region is ciphertext at rest; the key exists only transiently on a legitimate resume, re-derived through the TPM (§6b) |
| **Firmware substitution / rollback** (boot a modified or older image) | Runs with full key access | PCRs reflect the exact image+manifest+containers; the sealed KEK does not release for a mismatched state; a quote exposes it remotely (§4) |
| **Boot into attacker state then ask for keys** | — | Seal-to-PCR is evaluated *inside* the TPM at unseal time; a wrong boot state fails closed |

**Explicitly out of scope on these targets (honest, in §9):**

- **Transparent always-on encryption of all of RAM.** Not possible on MCU-class silicon
  (§9.1). "Memory encryption" here is scoped, not omnipresent.
- **Resistance to an active bus interposer *from power-on*.** Detectable and partly
  defeatable with TPM sessions (§7), but a reset-and-replay attack on PCRs is a known TPM
  limitation ([kernel TPM security doc][ktpm-sec]); full defence needs spec-level secure
  channels not present on commodity parts.
- **Invasive silicon attacks on the TPM/SE die.** The part's own Common Criteria /
  FIPS certification is the only defence; out of Bismuth's scope.
- **DMA-capable peripherals reading the scratch regions.** Handled by the MPU/DMA rules
  already in `security.md` §5.4, not re-litigated here.

---

## 2. TPM-as-device: driver, transport, and the sim model

### 2.1 The two layers, and why the split matters for the safe-Rust rule

A discrete TPM is a device that exchanges **command blobs** for **response blobs**. The
work splits cleanly along Bismuth's layer boundary:

```text
  L3  security::trust      TPM 2.0 command codec, PCR state, seal/unseal, quote,
                           session HMAC + parameter encryption (crypto), KEK → keystore
                                   │  transceive(cmd_bytes, &mut rsp_bytes)
  L2  driver::tpm (TIS)    locality, TPM_STS polling, FIFO, SPI/I2C wait state   (no crypto!)
                                   │  Op::Transfer{ cs/addr, tx, rx }
  L2  driver::spi / i2c    bus controller                                        (mmio in TCB)
                                   │
  hardware                 SLB 9670 / ATTPM20P / ATECC608
```

The **transport moves opaque bytes and holds no keys**, so `driver::tpm` imports only
`driver` and `arch` — never `security`. All crypto (session HMAC, parameter encryption, the
KEK) lives in `security::trust` at L3, which is *allowed* to import the L2 transport (down)
and its keystore sibling (same layer). This is the whole reason session crypto is **not** in
the driver: putting it there would be an L2→L3 (`crate::security`) import, which
`tests/structure.rs::layers_only_depend_downwards` forbids. The split is both clean
architecture and a hard constraint.

### 2.2 The bus: implement `DeviceClass::Spi` like `DeviceClass::I2c`

`DeviceClass::Spi` is reserved but empty. Mirror `driver/i2c` exactly:

```rust
// src/driver/spi/mod.rs
//! Classification: L2 devices · spi class · safe · tpm
pub struct SpiBus(pub Device);
impl SpiBus {
    pub fn open(name: &str) -> Result<Self, Error> {
        Ok(SpiBus(expect(Device::find(name)?, DeviceClass::Spi)?))
    }
    /// One SPI transaction: assert chip-select `cs`, clock out `tx` while clocking in `rx`.
    pub fn transfer(&self, cs: u16, tx: &[u8], rx: &mut [u8]) -> Result<usize, Error> {
        self.0.transfer(cs, tx, rx)          // reuses Op::Transfer { addr: cs, tx, rx }
    }
}
```

`Op::Transfer { addr, tx, rx }` already models "write `tx` then read `rx` at `addr`"; for SPI
`addr` is the chip-select line (for I2C it is the device address — the TPM works over either).
A real controller (`SimSpi`'s hardware counterpart) is an ordinary `Driver` whose register
access goes through `arch::mmio` exactly as `entropy::Stm32Rng` does; the `BUS_SET_SPEED_HZ`
/ `BUS_GET_SPEED_HZ` ioctls (`0x04xx`, already defined) apply unchanged. For the sim, add a
`SpiTarget` trait and a `SimSpi` controller, byte-for-byte analogous to `I2cTarget`/`SimI2c`:

```rust
// src/driver/spi/sim.rs
//! Classification: L2 devices · driver: spi (simulated) · safe · tpm
pub trait SpiTarget: Sync {
    /// Full-duplex: for byte i, shift out `rx[i]` while taking in `tx[i]`.
    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), Error>;
}
pub struct SimSpi { targets: IrqCell<[Option<&'static dyn SpiTarget>; 4]>, speed: IrqCell<u32> }
```

### 2.3 The TIS transport (TCTI): TPM Interface Specification over the bus

The TPM Interface Specification (TIS), profiled by the TCG PC Client Platform TPM Profile
(PTP), defines a small register file (per *locality*) and a FIFO for command/response bytes.
The register offsets and status bits are stable across implementations
([QEMU `hw/acpi/tpm.h`][qemu-tpm]):

| Register | Offset | Use |
|---|---|---|
| `TPM_ACCESS` | `0x0000` | request/release locality, see `activeLocality` |
| `TPM_STS` | `0x0018` | status: `commandReady`(bit6), `tpmGo`(bit5), `dataAvail`(bit4), `Expect`(bit3), `stsValid`(bit7); burst count in `0x19..0x1b` |
| `TPM_DATA_FIFO` | `0x0024` | push command bytes / pop response bytes |
| `TPM_DID_VID` | `0x0f00` | vendor/device id (probe) |

The **SPI framing** wraps each register access in a 4-byte header (TCG PTP §7.4.6, as
reflected in the [u-boot][uboot-tis] and [coreboot][coreboot-tis] drivers): byte 0 =
`direction(bit7) | (len-1)` (clear bit7 = write; `len-1` caps a burst at 64 bytes), byte 1 =
`0xD4` (the TPM register-space prefix), bytes 2–3 = the 16-bit register offset, big-endian.
The TPM applies **flow control / a wait state**: it may stall by holding the bus line low on
the last header clock, after which the host clocks one byte at a time and proceeds only once
the received byte's bit 0 (`0x01`) is set; drivers cap the poll (u-boot: 100 iterations) and
return `Error::Timeout` otherwise. A command exchange is then: request locality → wait
`commandReady` → write the command to `DATA_FIFO` (respecting burst count and `Expect`) →
write `tpmGo` → poll `dataAvail` → read the response. I2C TPMs (SLB 9673) use the same
register semantics with an I2C transaction instead of the SPI header.

```rust
// src/driver/tpm/mod.rs
//! Classification: L2 devices · tpm transport · safe · tpm
/// A TCG "TCTI": exchange one TPM command blob for its response. Bytes only — no keys,
/// no crypto, so this stays below the security layer.
pub trait TpmTransport: Sync {
    /// Write `cmd` (full command: 10-byte header + body) and read the response into `rsp`;
    /// returns the response length. Drives locality, STS and the bus wait state.
    fn transceive(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error>;
}

// src/driver/tpm/tis.rs
//! Classification: L2 devices · tpm TIS/SPI framing · safe · tpm
pub struct TisSpi { bus: SpiBus, cs: u16, locality: u8 }
impl TpmTransport for TisSpi {
    fn transceive(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> { /* as above */ }
}
```

**Proposed layer / classification:** bus = `L2 devices · spi class · safe · tpm`; transport
= `L2 devices · tpm transport · safe · tpm`. Both are `safe` (no `unsafe`); only a *real*
SPI controller's mmio is TCB, and that already exists under `arch/mmio.rs`.

### 2.4 The software TPM (`SoftTpm`): host testing with no hardware

This is the linchpin of testability. `SoftTpm` is a **safe, in-memory model that implements
`TpmTransport`** by *interpreting* the TPM command bytes and returning well-formed response
bytes. Because it sits behind the same trait, the **real command codec and the entire
trust service run against it unchanged** — the only difference between host and hardware is
which `TpmTransport` is installed.

```rust
// src/security/trust/soft.rs
//! Classification: L3 services · security: software TPM model (sim) · safe · tpm
pub struct SoftTpm {
    sps:    [u8; 32],                         // storage primary seed (random per instance)
    eps:    [u8; 32],                         // endorsement primary seed (→ attestation key)
    pcr:    IrqCell<[[u8; 32]; TPM_PCRS]>,     // SHA-256 PCR bank
    objects: IrqCell<[Option<SoftObject>; TPM_MAX_OBJECTS]>, // loaded keys / sealed blobs
    nv:     IrqCell<[SoftNvIndex; TPM_NV_SLOTS]>,            // monotonic counters, small data
    rng:    IrqCell<Drbg>,                     // deterministic for reproducible tests
}
impl TpmTransport for SoftTpm {
    fn transceive(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> {
        match parse_cc(cmd)? {                 // dispatch on the command code
            cc::PCR_EXTEND   => { /* pcr[i] = SHA256(pcr[i] || digest) */ }
            cc::UNSEAL       => { /* release iff policy digest == current PCR policy */ }
            cc::QUOTE        => { /* sign (PCR digest || nonce) with the EPS-derived AK */ }
            // … the subset of §3 …
        }
    }
}
```

Key properties: **deterministic** (seeded `Drbg`), **self-contained** (no OS, no files),
and **adversarial variants** are trivial — a `TamperTransport` that wraps a `SoftTpm` and
flips bytes models a bus interposer for the §7 session tests, and a second `SoftTpm` with a
different `sps` models a *cloned* board (its sealed blobs must fail to unseal). The sim-SPI
path can also wrap a `SoftTpm` as a `SpiTarget` so the TIS framing itself is exercised end to
end on the host.

---

## 3. The minimal TPM 2.0 command subset

A TPM 2.0 command is a big-endian blob: `tag (u16) | commandSize (u32) | commandCode (u32) |
handles | authorization area | parameters`; responses mirror it with a `responseCode`. The
codec is pure marshalling of a fixed set of structures — no allocation, no `unsafe`. We
implement the **smallest subset that supports measured boot, sealing, and attestation**:

| Command | Why we need it | Minimal? |
|---|---|---|
| `TPM2_Startup` | bring the TPM up after power-on | required |
| `TPM2_GetCapability` | read PCR banks / fixed properties; probe | required |
| `TPM2_GetRandom` | NIST-assessed entropy source (§5.4) | required |
| `TPM2_PCR_Extend` | record a measurement into a PCR (measured boot, §4) | required |
| `TPM2_PCR_Read` | read current PCR state (diagnostics, pre-seal check) | required |
| `TPM2_StartAuthSession` | open a policy session (for seal/unseal) and/or an HMAC+salt session (bus protection, §7) | required |
| `TPM2_PolicyPCR` | bind a session to a PCR selection+digest | required |
| `TPM2_CreatePrimary` | derive the Storage Root Key (SRK) from the storage seed | required (once) |
| `TPM2_Create` | create a **keyedhash sealed object** holding the root KEK, bound to a PCR policy | required |
| `TPM2_Load` | load the sealed object / a child key under the SRK | required |
| `TPM2_Unseal` | release the sealed secret iff the policy (PCRs) is satisfied | required |
| `TPM2_Quote` | sign (PCR digest ‖ nonce) with the attestation key (remote attestation) | required for §4.3 |
| `TPM2_FlushContext` | free a transient handle (bounded handle slots) | required |
| `TPM2_NV_DefineSpace` / `_Increment` / `_Read` | monotonic counter for anti-rollback / sleep-nonce (§6b) | optional |

Everything else (RSA/ECC key import, duplication, policy-OR trees, auditing, PCR allocation
changes) is **deliberately excluded** — it adds codec surface and attack surface for no MCU
benefit, mirroring the "keep the syscall surface tiny" discipline of `security.md`. Note
that **there is no fixed storage root key in TPM 2.0**; the SRK is derived from the storage
primary seed by `TPM2_CreatePrimary` and must be recreated (deterministically, from the same
seed+template) or made persistent — a point real drivers call out
([kernel trusted-keys][gfiber-trusted]). Sealed data must be a `TPM_ALG_KEYEDHASH` object
created by `TPM2_Create` ([tpm2-tools][tpm2-unseal]).

**Codec shape (safe, no heap):**

```rust
// src/security/trust/cmd.rs
//! Classification: L3 services · security: tpm 2.0 command codec · safe · tpm
struct CmdBuf { bytes: [u8; TPM_CMD_BYTES], len: usize }  // bounded command builder
impl CmdBuf {
    fn begin(&mut self, tag: u16, cc: u32) -> &mut Self { /* write header, fix size at end */ }
    fn u16(&mut self, v: u16) -> &mut Self { /* push big-endian */ self }
    fn bytes(&mut self, b: &[u8]) -> &mut Self { /* TPM2B: u16 len prefix + data */ self }
    fn finish(&mut self) -> &[u8] { /* backpatch commandSize */ &self.bytes[..self.len] }
}
// Responses are parsed with a cursor that bounds-checks every read against `rsp.len()`;
// a short/truncated response is Error::Io, a non-zero responseCode maps to Error::Integrity
// (policy/auth failure) or Error::Io (transport/TPM error).
```

### 3.1 Secure-element alternative path

For the most constrained or cost-sensitive parts, a **secure element** is a lighter root of
trust than a full TPM. The trade-off:

| | Discrete TPM 2.0 (SLB 9670, ATTPM20P, ST33) | Secure element (ATECC608, OPTIGA Trust M) |
|---|---|---|
| Model | Standardized TCG command set, hierarchies, **arbitrary PCRs**, policy sessions, NV, broad algorithms | Fixed slot model: a handful of key slots + a small config/data zone |
| Measured boot | Native (`PCR_Extend`, seal-to-PCR, quote) | **No general PCRs**; must be *emulated* (SE releases a slot only after the host proves a measurement via a MAC/derived-key check) |
| Attestation | `TPM2_Quote`, standard EAT/PSA token path | ECDSA `Sign` of a host-supplied digest (ad-hoc) |
| Algorithms | SHA-256, RSA, ECC, HMAC, KDF, RNG | ECDH/ECDSA P-256, SHA-256, HMAC/KDF, AES, RNG; OPTIGA Trust M adds RSA + P-384 ([Adafruit][adafruit-trustm]). ATECC608 adds an AES accelerator and secure-boot support ([Microchip AN3983][mc-an3983]); Microchip ships a separate TPM (ATTPM20P) for full TPM needs |
| Interface | SPI (SLB 9670) or I2C (SLB 9673); FIPS 140-2 L2 / CC EAL4+ ([Infineon][infineon-slb9670]) | I2C (single-wire variants exist); CC-certified families |
| Pick it when | You need standards-based measured boot, remote attestation, NV monotonic counters, broad policy | You need cheap device identity/auth, TLS/LoRaWAN onboarding, ECDSA, and key storage on a tiny part, and can emulate "release on correct measurement" |

Crucially, **both sit behind one `RootOfTrust` trait** (§4.1), so the keystore integration,
the sealed-KEK flow, and the sim tests are identical regardless of backend; only the
`seal_to_pcr`/`unseal`/`quote` implementations differ. A secure element implements
"seal to measurement" by gating a stored secret's release on a host-presented MAC over the
measurement (e.g. the ATECC608 derived-key / CheckMAC primitives) rather than an internal PCR
policy.

---

## 4. The trusted-platform service (measured boot, sealing, attestation)

### 4.1 The `RootOfTrust` trait and the naming collision

`security::seal()` already exists and means **policy sealing** — freezing the capability
configuration so it can only tighten. TPM **object sealing** is a *different* operation
(binding a secret to a PCR policy). To avoid confusion, the trusted-platform service lives in
its own module `security::trust` and never reuses the bare word `seal`:

- policy sealing stays `security::seal()` / `security::is_sealed()`;
- TPM object sealing is `trust::seal_to_pcr()` / `trust::unseal()` (always PCR-qualified in
  the name), and attestation is `trust::quote()`.

A reader scanning `use` lines sees `security::seal` vs `security::trust::seal_to_pcr` and
cannot mistake one for the other.

```rust
// src/security/trust/mod.rs
//! Classification: L3 services · security: trusted platform · safe · tpm
/// A hardware (or simulated) root of trust. Implemented by `Tpm<T: TpmTransport>`,
/// by `SecureElement`, and directly by `SoftTpm` for the sim.
pub trait RootOfTrust: Sync {
    fn get_random(&self, out: &mut [u8]) -> Result<(), Error>;
    fn pcr_extend(&self, pcr: u8, digest: &[u8; 32]) -> Result<(), Error>;
    fn pcr_read(&self, pcr: u8) -> Result<[u8; 32], Error>;
    /// Create an opaque sealed blob binding `secret` to the given PCR selection's current
    /// digest. Safe to store in flash. (TPM2_Create, keyedhash + PolicyPCR.)
    fn seal_to_pcr(&self, secret: &[u8], sel: PcrSelect, out: &mut SealedBlob) -> Result<usize, Error>;
    /// Release a sealed secret iff the PCRs still satisfy the bound policy. (TPM2_Load +
    /// TPM2_Unseal.) A policy mismatch is Error::Integrity; an unready TPM is Error::NotReady.
    fn unseal(&self, blob: &SealedBlob, out: &mut [u8]) -> Result<usize, Error>;
    /// Sign (PCR digest ‖ nonce) with the attestation key. (TPM2_Quote.)
    fn quote(&self, sel: PcrSelect, nonce: &[u8], out: &mut Quote) -> Result<usize, Error>;
}

static ROOT: IrqCell<Option<&'static dyn RootOfTrust>> = IrqCell::new(None);
pub fn bind(r: &'static dyn RootOfTrust) -> Result<(), Error> { /* kernel-only, before seal() */ }
```

`SealedBlob` and `Quote` are fixed-size (`[u8; TPM_BLOB_BYTES]` + length), so no heap.

### 4.2 PCR allocation and measured boot (making the container fields live)

Measured boot is the discipline of **recording what ran** into append-only PCRs
(`pcr[i] = SHA256(pcr[i] ‖ measurement)`), as distinct from **secure boot** (verify a
signature and refuse to run a bad image). Bismuth does measured boot in-kernel; secure boot
belongs to the immutable first stage (MCUboot or a Rust stage), exactly as `security.md`
§8 scopes it. Proposed PCR map (small, MCU-appropriate):

| PCR | Extended with | Source |
|---|---|---|
| 0 | first-stage + Bismuth image measurement | the DICE/measured-boot handoff block (`security.md` §8) |
| 1 | board description + kernel config + **manifest hash** (the capability graph) | computed at boot from the static manifest |
| 2 | each container's `image_hash` (and `version`), in declaration order | **`ContainerDecl.image_hash` / `.version` — the fields that are stored-only today** |
| 3 | security lifecycle: debug-port state, `seal()` done | boot/lifecycle flags |
| 4.. | application-defined | apps |

This is the concrete answer to "the container measurement fields are shaped for this but
unused": at `container::install`/`start`, extend PCR 2 with `decl.image_hash` and a digest of
`decl.version`. From then on the TPM's PCR 2 *is* a cryptographic statement of which
workloads, at which versions, are running. Sealing a storage KEK to PCRs 0–2 makes the key
releasable only when the exact firmware + capability graph + container set booted; a quote
over PCRs 0–3 makes "this device runs these containers under this manifest" **remotely
verifiable** — something `security.md` already wants for the manifest hash and now gets for
free for workloads too.

```rust
// at boot, after devices are registered and the manifest is known:
trust::bind(&TPM)?;                                   // install the root of trust
trust::pcr_extend(1, &keystore::sha256(MANIFEST_BYTES))?;
for c in MANIFEST.containers {                         // container::install already iterates these
    trust::pcr_extend(2, &c.image_hash)?;
    trust::pcr_extend(2, &keystore::sha256(&c.version.to_le_bytes()))?;
}
```

### 4.3 Attestation (`quote`) and the existing token path

`trust::quote(sel, nonce, &mut q)` returns a `TPM2_Quote`: a signed structure over
`SHA256(selected PCRs)` and the verifier's `nonce` (freshness). `security.md` §8 already
specifies the outward format — a **COSE_Sign1 PSA attestation token (RFC 9783 profile)**
whose claims include the software-component measurements and the manifest hash. The TPM
quote is the hardware-anchored evidence that fills those measurement claims; the token is
assembled and signed in the keystore/attestation path. On a TrustZone part the quote can be
delegated to TF-M Initial Attestation instead. Health telemetry
(`container::Health { generation, violations, faults }`) can be carried as additional
claims, so a verifier sees not just *what* booted but its runtime integrity state.

**Reset-attack honesty:** an attacker who can reset the TPM and replay boot-time
`PCR_Extend`s is not caught by per-command HMAC alone; this is a documented TPM limitation
([kernel TPM security doc][ktpm-sec], [LSM interposer thread][lsm-interposer]). Seal-to-PCR
still protects *at-rest* keys (the data is useless without a correct live boot), and the
quote's freshness nonce defeats replay of the *attestation*, but we do not claim to defeat a
physical reset-and-replay of the measurement sequence.

---

## 5. TPM-rooted key hierarchy (reusing the keystore)

### 5.1 Division of labour: TPM gates, keystore derives

The TPM's role is deliberately narrow: **hold one 32-byte root KEK sealed to the measured
boot state, and release it exactly once per boot if (and only if) the PCRs are correct.**
Everything downstream is the *existing* keystore. This is faster (no per-key TPM round trip),
static, and reuses vetted in-tree code rather than widening the TPM codec.

```text
  TPM storage seed ──CreatePrimary──► SRK ──Load──► sealed KEK object
                                                   │ Unseal (iff PCR policy holds)
                                                   ▼
                       root KEK (32 B, in RAM only this boot)
                                                   │ keystore::import  (HkdfSha256 IKM,
                                                   ▼                     NOT exportable)
                       root KEK handle  ──keystore::derive (HKDF-SHA-256, existing)──┐
                                                   │                                  │
                              info="…/vol0"        │ info="…/dom:telemetry"           │ info="…/retained"
                                                   ▼                                  ▼
                       storage volume key (AEAD)   per-domain KEK (AEAD)   retained-RAM key (AEAD)
```

```rust
// boot, kernel domain, before security::seal():
let mut kek = [0u8; 32];
match trust::unseal(&ROOT_KEK_BLOB, &mut kek) {        // ROOT_KEK_BLOB lives in flash
    Ok(32) => {}
    Err(Error::Integrity) | Err(Error::NotReady) => return fail_closed(), // wrong boot state
    _ => return Err(Error::Io),
}
let root = keystore::import(KeyAttrs::kdf(), &kek)?;    // KeyType::HkdfSha256, usage K_DERIVE
kek.zeroize();
// Per-volume / per-domain KEKs via the EXISTING keystore HKDF — no new crypto path:
let vol0 = keystore::derive(root, b"bismuth/kek/v1/vol0",        KeyAttrs::aead())?;
let dkek = keystore::derive(root, b"bismuth/kek/v1/dom:telemetry", KeyAttrs::aead())?;
```

Everything here already exists: `keystore::import`, `keystore::derive`, `KeyAttrs::kdf()` /
`::aead()`, `Rights::K_DERIVE` / `K_ENCRYPT` / `K_DECRYPT`. The only new thing is *where the
IKM comes from* — the TPM instead of the DRBG. The derived keys are generation-checked,
rights-checked, zeroized-on-destroy handles, and **`K_EXPORT` is denied** so a TPM-rooted
key is no more extractable than any other keystore key.

### 5.2 First provisioning (one-time)

On a factory-fresh device: seed the entropy pool, `TPM2_CreatePrimary` the SRK,
generate the root KEK (`trust::get_random` or the keystore DRBG), `trust::seal_to_pcr(kek,
PCRs 0..=2, &mut blob)`, and persist `blob` to flash. The plaintext KEK is zeroized
immediately; thereafter it exists only transiently, post-unseal, each boot. Provisioning
runs once, gated by the lifecycle state (`security.md` §8 provisioning → deployed).

### 5.3 How this strengthens the per-domain contexts

`security.md` gives each domain its own DRBG; this gives each domain a **KEK anchored to the
hardware and the measured boot**. A domain's long-lived secrets (its storage, its sealed
objects) are now bound to *this physical device booted into this exact state* — a cloned
image on another board derives different keys (different TPM seed) and a tampered image
derives nothing (PCR mismatch → no unseal). The per-domain KEK slots into the manifest's
handle grants exactly like a key handle today (`{ object = "key:dom_kek", rights =
["K_DERIVE"] }`), so the compile-time capability checks (`manifest::validate`) apply
unchanged.

### 5.4 Bonus: the TPM as an entropy source

`TPM2_GetRandom` is a vendor-certified (SP 800-90B) RNG. Wrap it as an `EntropySource`
(the trait in `entropy::sources`) credited per the part's certification and mixed into the
existing pool next to `Stm32Rng`:

```rust
pub struct TpmRng<'a> { tpm: &'a dyn RootOfTrust, min_entropy_bits: u8 }
impl EntropySource for TpmRng<'_> {
    fn min_entropy_bits(&self) -> u8 { self.min_entropy_bits }
    fn read(&self, out: &mut [u8]) -> Result<usize, Error> { self.tpm.get_random(out).map(|_| out.len()) }
}
```

Over SPI this is slow, so use it for *seeding/mix-in*, not bulk draws — the per-domain DRBGs
remain the fast path. It is a defence-in-depth independent noise source, not a replacement.

---

## 6. TPM-derived encryption: the three forms that work on an MCU

All three key from the TPM-sealed root KEK via §5. The retained-RAM (§6b) and
protected-object (§6c) services live at L3 `security::trust` and call the keystore AEAD
directly (`keystore::aead_seal` / `aead_open`). The encrypted block wrapper (§6a) is an L2
`BlockDevice`; to keep the block data path off the keystore's handle table (both for the
layer rule and for speed on a per-block hot path), it does its AEAD with the
`chacha20poly1305` primitive **inline** on a raw data key injected at mount, rather than
calling the keystore per block. All use ChaCha20-Poly1305 and share one non-negotiable rule:
**never reuse a (key, nonce) pair** — reuse is catastrophic for both confidentiality and
authenticity. Each subsection specifies its nonce discipline explicitly.

### 6a. Encrypted storage at rest — an encrypted `BlockDevice` wrapper

**Dovetail with `filesystems.md` (confirmed with the FS design).** That document defines the
`BlockDevice` trait (`geometry` + `read(blk, off, buf)` / `prog(blk, off, data)` /
`erase(blk)` / `sync`, geometry `{read_size, prog_size, block_size, block_count,
block_cycles, kind}`) at L2 `driver::block`, and decides that the data-plane layers
(`BlockCache`, `Partition`, `ReadOnly`, `WearCounter`) are **`BlockDevice` wrappers composed
at build time**, *not* `Op`/`Request`/`Middleware` layers. The filesystem calls `BlockDevice`
**directly** and bypasses the `Op` chain entirely (as `net::transmit` bypasses it), so the
`Op`-middleware you already know (`Stats`, `Trace`, `Exclusive`, `AccessPolicy`) applies only
to the `/dev/<name>` control node for admin/ioctls, never to FS traffic. The encrypted layer
is therefore **the crypto sibling of `BlockCache`/`Partition`** — a wrapper that implements
`BlockDevice` around an inner `BlockDevice` — composed into the mount chain at build time:

```rust
static CHAIN: CryptBlock<Partition<Sd>> = /* … */;
mount("/sd", fs_over(&CHAIN));   // littlefs/FAT see an ordinary BlockDevice; encryption is invisible
```

The filesystem is **oblivious to encryption**, and per-block AEAD inside the wrapper is the
*only* integrity layer — littlefs's CRCs are torn-write detection, not tamper resistance, and
FAT has none, so this is the right and only place for authentication. The FS does **no**
Merkle/integrity of its own (confirmed with the FS owner).

```rust
// src/driver/block/crypt.rs
//! Classification: L2 devices · block: AEAD wrapper · safe · crypto
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
use zeroize::Zeroize;

/// A BlockDevice that encrypts each logical block with ChaCha20-Poly1305. It holds the raw
/// data-encryption key (DEK) injected at mount — NOT a keystore handle — so this L2 layer
/// does its own AEAD and never calls `security::keystore` on the per-block path.
pub struct CryptBlock<D: BlockDevice> {
    inner:  D,
    dek:    IrqCell<Option<[u8; 32]>>,  // injected at mount; None → fail closed; zeroized on unmount
    usable: u32,                        // logical blocks shown to the FS (inner minus the OOB band)
}
impl<D: BlockDevice> CryptBlock<D> {
    /// Called by trusted mount code (L3/L4) once the TPM unseal has recovered the volume
    /// DEK (§5.1). The DEK is a bulk data key, not a root/wrapping secret; the block data
    /// path needs it inline, so it legitimately leaves the keystore here.
    pub fn set_dek(&self, dek: [u8; 32]) { self.dek.lock(|k| *k = Some(dek)); }
    /// Drop the key on unmount/suspend so it does not linger in RAM.
    pub fn unmount(&self) { self.dek.lock(|k| if let Some(mut d) = k.take() { d.zeroize() }); }
}
impl<D: BlockDevice> BlockDevice for CryptBlock<D> {
    fn geometry(&self) -> BlockGeometry {
        let g = self.inner.geometry();   // present a *logical* geometry: whole-block AEAD, fewer blocks
        BlockGeometry { read_size: g.block_size, prog_size: g.block_size, block_count: self.usable, ..g }
    }
    fn prog(&self, blk: u32, _off: u32, data: &[u8]) -> Result<(), Error> {
        let dek = self.dek.lock(|k| *k).ok_or(Error::NotReady)?;    // never write plaintext
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&blk.to_le_bytes());             // LBA domain-separates the nonce space
        rng_fill(&mut nonce[4..])?;                                 // 8 FRESH random bytes per write (CSPRNG)
        let mut buf = [0u8; BLK];
        buf[..data.len()].copy_from_slice(data);
        let tag = ChaCha20Poly1305::new((&dek).into())
            .encrypt_in_place_detached(&nonce.into(), &blk.to_le_bytes(), &mut buf)  // AAD = blk (binds to LBA)
            .map_err(|_| Error::Invalid)?;
        self.inner.prog(blk, 0, &buf)?;                             // data first,
        self.write_oob(blk, &nonce[4..], &tag.into())?;             // then OOB {8 nonce bytes, 16 tag}
        self.inner.sync()                                           // synchronous to stable storage (no write-back)
    }
    fn read(&self, blk: u32, _off: u32, out: &mut [u8]) -> Result<(), Error> {
        let dek = self.dek.lock(|k| *k).ok_or(Error::NotReady)?;
        let (rand8, tag) = self.read_oob(blk)?;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&blk.to_le_bytes());
        nonce[4..].copy_from_slice(&rand8);
        let mut buf = [0u8; BLK];
        self.inner.read(blk, 0, &mut buf)?;
        ChaCha20Poly1305::new((&dek).into())
            .decrypt_in_place_detached(&nonce.into(), &blk.to_le_bytes(), &mut buf, (&tag).into())
            .map_err(|_| { buf.zeroize(); Error::Integrity })?;     // tamper / torn write → Integrity
        out.copy_from_slice(&buf[..out.len()]);
        Ok(())
    }
    fn erase(&self, blk: u32) -> Result<(), Error> {
        self.invalidate_oob(blk)?;        // clear this block's nonce+tag so stale ciphertext cannot be replayed
        self.inner.erase(blk)
    }
    fn sync(&self) -> Result<(), Error> { self.inner.sync() }
}
```

**Nonce / IV management (the hazard fs-research flagged, redesigned):** a durable
per-block *counter* is the wrong primitive here — it must survive the torn-write window and
never roll back across power loss, which is exactly the hard problem. Instead the 96-bit
nonce is `blk (u32 LE) ‖ 64 fresh random bits` drawn from the CSPRNG on **every** program,
and the 8 random bytes are stored next to the 16-byte tag in the OOB band. The LBA prefix
domain-separates the nonce space, so the 64 random bits only need to be unique *per block*:
the birthday bound is ~2³² rewrites of the *same* block before a meaningful collision
probability, far beyond any SD/eMMC/flash block's write endurance. **This removes the durable
monotonic-counter-across-power-loss requirement entirely.** Under a torn write, the data
block and its OOB entry either both survive old, both land new, or land inconsistent — and an
inconsistent pair simply fails authentication (`Error::Integrity`), which the FS treats like
a littlefs CRC failure; no nonce is ever reused, because each write draws fresh randomness
regardless of what survived. `XChaCha20-Poly1305` (192-bit nonce, same `chacha20poly1305`
crate) is the belt-and-suspenders option where an even larger margin is wanted; the keystore
KATs cover `ChaCha20-Poly1305`, so the block layer may use either. The AEAD **AAD = `blk`**
binds each ciphertext to its logical address, so a block relocated to another LBA fails
authentication. OOB per block = 8 (nonce) + 16 (tag) = 24 bytes held in a **separate reserved
metadata region** the wrapper addresses itself — **not stolen from each logical block**: the
logical `block_size` `CryptBlock` presents to the FS stays a **power of two** (512/1024/2048/
4096), as FAT hard-requires and littlefs wants, and only `block_count` drops (`usable =
block_count − ceil(block_count · 24 / block_size)`). A 4072-byte logical block would break
both filesystems, so the 24 bytes must come out of the block *count*, never the block *size*.
`erase(blk)` must invalidate that block's OOB so stale ciphertext cannot be replayed after a
logical erase.

**Scope — what per-block AEAD does and does not give (honest):** AAD = `blk` plus a fresh
random nonce gives **confidentiality, per-block integrity, LBA-relocation binding, and clean
torn-write detection**. It does **not** give **freshness / anti-rollback**: an offline
attacker who keeps an old *valid* `(ciphertext, nonce, tag)` triple for a given LBA can
restore it later and it will authenticate, because it was legitimately produced for that
block under that key. Defeating that needs an authenticated monotonic **version per block**,
anchored in a trusted root — i.e. a Merkle/version tree whose root lives in a **TPM NV
monotonic counter** (the §3 optional `NV_*` commands). That is exactly the durable counter we
dropped here, and it belongs in *this* (TPM) layer, not the FS — the FS stays oblivious and
does no Merkle integrity of its own. Anti-rollback is therefore **documented future work**
(§9.3), not something this design claims.

**Media fit (honest; primary story = `MediaKind::Disk`):** in-place per-block AEAD fits
`Disk`/`Ram` (SD/eMMC/RAM disk, overwrite-in-place) cleanly — make that the primary case
(FAT or littlefs-over-disk). Over raw `MediaKind::Flash` it is a poor fit: you cannot rewrite
a logical block (or its OOB) without erasing the physical erase-block, and littlefs already
owns erase-before-write, copy-on-write and wear-leveling underneath. If raw flash must be
encrypted, `CryptBlock` has to **faithfully preserve the flash geometry** (erase granularity,
`prog_size`, program-once-per-word, `erase_value`) and sit **below** littlefs, giving every
physical reprogram a fresh random nonce; alternatively encrypt **above** the flash FS. A
length-preserving tweakable mode (XTS-AES) stores no OOB but gives confidentiality *without*
authentication and needs an AES crate (§7 flag), so it is not recommended here.
**Power-safety constraint (from the FS design):** a power-safe FS needs the device's
`prog`/`erase` to be synchronous to stable storage, so **do not insert a write-back
`BlockCache` between the FS and `CryptBlock`** — hence the `sync()` after each `prog` above.

**Key hierarchy and rekey.** Do not use the TPM-unsealed KEK as the AEAD key directly. The
volume has a random **DEK** (generated at format) stored **wrapped** under a volume KEK
(`keystore::aead_seal`) in its header; the KEK is `keystore::derive`d from the TPM root KEK
(§5.1). Trusted mount code (L3/L4) unseals the root KEK, derives the volume KEK, `aead_open`s
the wrapped DEK, and injects the raw DEK via `CryptBlock::set_dek`. This is the LUKS
master-key pattern: **rekeying the KEK (re-seal to new PCRs) only re-wraps the DEK — it never
re-encrypts the data.** All keystore calls happen in trusted mount code; `CryptBlock` only
ever holds the raw DEK in an `IrqCell`, zeroized on unmount/suspend.

**Key release bound to unseal-at-boot (the power-fail-safe property):** `CryptBlock.dek` is
`None` until mount injects it after a successful unseal. If the TPM unseal fails (wrong PCRs
→ wrong boot state), the DEK is never injected, every `read`/`prog` returns
`Error::NotReady`, and the filesystem **cannot mount**. No code path reads or writes plaintext
without a live, measured-boot key release — storage is inert on any device or image that is
not the measured-good one.

**RNG touchpoint:** `rng_fill` is the one service `CryptBlock` needs beyond `chacha20poly1305`
and `zeroize`. It is the kernel CSPRNG (`security::entropy::fill`); because `driver` already
depends on `security` for the request `Caller`, this is permitted by
`structure.rs` (the L2 forbidden list is `net`/`compat`/`edge`, not `security`). For strict
zero-coupling it can instead be an injected `&'static dyn RngCore` handed in at mount beside
the DEK.

**Sim test:** register a sim/RAM `BlockDevice`, compose `CryptBlock` over it, bind a
`SoftTpm`, seal a volume KEK to a PCR state, boot-unseal it, inject the DEK, write blocks
through the FS, and assert: (1) round-trip read == write; (2) the underlying blocks are
ciphertext (never equal the plaintext); (3) a flipped ciphertext/tag/nonce byte yields
`Error::Integrity`; (4) a block relocated to another LBA fails the AAD check; (5) a second
`SoftTpm` with a different seed (a "clone") fails the unseal, so the DEK is never injected and
the FS fails closed; (6) two successive writes of the same block use different nonces
(inspect the OOB), proving no reuse; (7) after `unmount`, the DEK slot is zeroized.

### 6b. Encrypted retained RAM across deep-sleep / hibernate

Some MCUs keep a backup SRAM / RTC-domain region powered across STOP/STANDBY, or simply do
not zero a `.noinit` region on warm reset. That retained region is where you stash state to
resume quickly — and, on a cold-boot / power-pull attack, exactly what an adversary reads.
Mitigation: **AEAD-seal the retained region in place before power-down and decrypt it on
resume**, with the key rooted in the TPM so it is unavailable to an attacker who bypasses a
legitimate boot.

```rust
// src/security/trust/retained.rs   (L3: uses the keystore, so it lives at L3, not in arch)
//! Classification: L3 services · security: retained-RAM sealing · safe · tpm
#[unsafe(link_section = ".retained")]                 // placement only; see the TCB note below
static mut RETAINED: [u8; RETAINED_BYTES] = [0; RETAINED_BYTES];
static TRAILER: IrqCell<Trailer> = IrqCell::new(Trailer::ZERO); // nonce counter + tag, in backup regs

pub fn pre_sleep() -> Result<(), Error> {
    let key = retained_key()?;                         // keystore handle, derived from the root KEK
    let ctr = TRAILER.lock(|t| { t.ctr += 1; t.ctr }); // monotonic sleep counter (never reused)
    let nonce = nonce96(REGION_ID, ctr);
    let region = /* &mut [u8] view of RETAINED via a safe accessor */;
    let tag = keystore::aead_seal(key, &nonce, &aad(FW_VERSION), region)?;
    TRAILER.lock(|t| t.tag = tag);                     // tag + ctr survive in always-on backup registers
    Ok(())                                             // region is now ciphertext; drop into STANDBY
}
pub fn post_resume() -> Result<(), Error> {
    let key = retained_key()?;                         // re-derived through the TPM-rooted keystore
    let (ctr, tag) = TRAILER.lock(|t| (t.ctr, t.tag));
    let region = /* &mut [u8] view */;
    keystore::aead_open(key, &nonce96(REGION_ID, ctr), &aad(FW_VERSION), region, &tag)  // Integrity on tamper
}
```

**Key lifecycle:** the retained-RAM key is **never stored in the retained region** (that
would defeat the whole scheme). It is derived at resume from the TPM-rooted keystore, which
requires a correct measured boot — so an attacker who pulls power and reads SRAM sees only
ciphertext, and the key material exists only transiently on a legitimate resume. **Nonce:**
a monotonic sleep counter kept in always-on backup registers (or a TPM NV monotonic counter,
§3), concatenated with a region id — guaranteeing no nonce reuse across sleep cycles. **AAD**
= firmware version (a downgraded firmware cannot open a region sealed by a newer one).
**Bounded:** one fixed `RETAINED_BYTES` region and one small `Trailer`; nothing dynamic.

**Safe-rust note:** placing a static in a named linker section needs the `link_section`
attribute; the *accessor* that turns the static into a `&mut [u8]` is the only hazard and
belongs in `kernel/usermem.rs` / a tiny arch helper (the existing TCB), **not** in the trust
service. The trust service receives an already-safe `&mut [u8]` and does pure AEAD on it. No
new TCB module is required if an existing safe accessor (e.g. a `StackSource`-style region
provider) is reused.

**Sim test:** fill `RETAINED` with a known pattern, `pre_sleep()`, assert the bytes are now
ciphertext, scribble/forget the in-RAM key (model power-down), `post_resume()`, assert the
pattern is recovered; then flip a byte and assert `Error::Integrity`; then model a cold-boot
read (ciphertext only, no key) and assert nothing is recoverable.

### 6c. Sealed-secret / protected-object buffers ("enclave-lite")

The keystore's rule is *keys never leave the keystore*. For **application secrets** (a device
credential, an OTA token, a private payload) that must live in RAM but should spend as little
time as possible in cleartext, keep them **AEAD-encrypted in a static pool and decrypt into a
tiny scratch only inside a closure**, re-sealing (zeroizing the scratch) on exit:

```rust
// src/security/trust/sealed.rs
//! Classification: L3 services · security: protected objects · safe · tpm
pub struct Protected { nonce_ctr: u64, len: u16, tag: [u8; 16], ct: [u8; PROT_MAX] } // one slot
static POOL: IrqCell<[Option<Protected>; MAX_PROTECTED]> = IrqCell::new([None; MAX_PROTECTED]);

pub fn store(key: Handle, plaintext: &[u8]) -> Result<ProtId, Error> { /* aead_seal into a slot */ }
/// Decrypt into a bounded scratch, run `f`, then zeroize the scratch. The plaintext never
/// outlives the closure; `f` cannot stash it because it borrows a scratch slice.
pub fn with_unsealed<R>(id: ProtId, key: Handle, f: impl FnOnce(&[u8]) -> R) -> Result<R, Error> {
    let mut scratch = [0u8; PROT_MAX];                 // bounded, on the caller's kernel stack
    let p = /* copy ct+tag out of the slot */;
    keystore::aead_open(key, &nonce96(id, p.nonce_ctr), &aad(id), &mut scratch[..p.len as usize], &p.tag)?;
    let r = f(&scratch[..p.len as usize]);
    scratch.zeroize();                                 // cleartext window closed
    Ok(r)
}
pub fn reseal(id: ProtId, key: Handle, plaintext: &[u8]) -> Result<(), Error> { /* bump ctr, aead_seal */ }
```

**Nonce:** a per-object monotonic counter bumped on every `reseal` (so re-encrypting edited
content never reuses a nonce). **AAD** = the object id. **Key lifecycle:** the wrapping key
is a TPM-rooted keystore handle (`K_ENCRYPT`/`K_DECRYPT`), so the sealed objects inherit the
"only on this device, only after a good boot" property. **Bounded:** `MAX_PROTECTED` slots of
`PROT_MAX` bytes, one scratch per in-flight `with_unsealed`. This narrows the cold-boot and
fault-injection window for secrets from "the whole uptime" to "only while actively in use" —
the MCU-scale analogue of an enclave, built entirely from the existing AEAD.

**Sim test:** store a secret, assert the pool slot is ciphertext, `with_unsealed` and check
the plaintext is visible inside the closure, assert the scratch is zero after the closure
returns (reuse the keystore's `residual_material`-style inspection hook), and assert a
tampered slot fails with `Error::Integrity`.

---

## 7. Crypto notes: what the TPM does vs what we do, and the one flag

### 7.1 Two crypto worlds, kept apart

| | Inside the TPM (the chip does it) | In Bismuth with derived keys (we do it) |
|---|---|---|
| Hash / PCRs | SHA-256 PCR bank | SHA-256 (`sha2`, in tree) |
| Symmetric | AES (storage), **AES-CFB for session parameter encryption** | **ChaCha20-Poly1305** (`chacha20poly1305`, in tree) |
| MAC | HMAC-SHA-256 (sessions) | HMAC-SHA-256 (`hmac`, in tree) |
| KDF | KDFa (internal) | HKDF-SHA-256 (`hkdf`, in tree) |
| Asymmetric | RSA / ECC P-256 (SRK, AK, EK) | none — we never do asym on the MCU |

The important point: **for §§5–6, everything *we* compute stays on the in-tree RustCrypto
primitives.** The root KEK out of `TPM2_Unseal` is just 32 opaque bytes; we HKDF-expand it and
AEAD with ChaCha20-Poly1305. There is no algorithm mismatch to resolve on our side of the
bus — the TPM's internal use of AES/RSA/ECC is the chip's business.

### 7.2 Protecting the SPI/I2C bus — the only place AES enters

The mismatch bites in exactly one scenario: if the threat model includes a **bus
interposer** (a probe/chip soldered on the SPI lines), then the bytes crossing the bus need
protection, and TPM 2.0's mechanism for that is **sessions**: salted **HMAC-SHA-256**
sessions for integrity and **parameter encryption** (commonly **AES-128-CFB**) for
confidentiality of secret-bearing command parameters
([kernel TPM security doc][ktpm-sec], [LSM interposer thread][lsm-interposer]). What is
protected how:

- **PCR extends/reads and command flow:** HMAC integrity only — measurements are not secret,
  but a salted HMAC session makes a substituted value produce a detectable HMAC failure.
- **Secret-bearing commands (`Unseal`, `GetRandom`, key import):** need **parameter
  encryption** too, because the response *carries the secret* — and in our design the
  `TPM2_Unseal` response carries the **root KEK**. Without response encryption, an interposer
  reads the KEK off the bus and the whole scheme collapses.

So the decision reduces to the threat model, in tiers:

| Tier | Protection | New crypto crate | Use when |
|---|---|---|---|
| 0 | Plaintext sessions | none | TPM soldered next to the MCU, short traces, interposer out of scope (common for a single-board IoT device) |
| 1 | Salted **HMAC-SHA-256** sessions (integrity) | none (`hmac`/`sha2` in tree) | detect command/PCR tampering; cheap |
| 2 | + **AES-CFB** parameter encryption on `Unseal`/`GetRandom` | **`aes` + `cfb-mode`** — FLAG | the unsealed KEK must not be readable on the bus |
| 3 | + salted session via EK/null-primary ECDH | + an ECC primitive (`p256`) — FLAG | active interposer resistance from power-on |

**The flag (§9):** Tier 2+ requires an **AES implementation**, which Bismuth does **not**
have today. `aes` and `cfb-mode` (RustCrypto) are pure-Rust, `no_std`, and well-reviewed, so
adding them keeps the safe-Rust rule — but the research framing says *do not introduce new
crypto crates without flagging*, so this is explicitly **a decision for the user**. The
salted ECDH of Tier 3 (the kernel TPM subsystem uses a null-primary EC key to salt the
session [[kernel TPM security doc][ktpm-sec]]) needs an asymmetric primitive too, a bigger
addition.

**Recommendation:** default to **Tier 1** (free, detects tampering). Treat **Tier 2 as
*required* whenever the root KEK actually crosses the bus** — i.e. whenever §§6a–6c rely on an
unsealed KEK on a board where a bus interposer is in scope. If adding `aes` is unacceptable,
the fallback is to accept Tier 0/1 on boards where the TPM and MCU share a PCB and an
interposer means the device is already physically compromised (a defensible threat-model
stance taken by some kernel maintainers [[LSM interposer thread][lsm-interposer]]). Note also
that the Linux kernel disabled its TPM-bus HMAC by default in 2025 over init-failure and
performance regressions ([patch][google-hmac-patch]) — a reminder that session crypto is not
free and should be a deliberate, measured choice, not an always-on default.

### 7.3 Constant-time and multiply-timing caveats

The Cortex-M3 variable-time `UMULL` caveat from `security.md` §6.5 applies to any
software asymmetric/field arithmetic (Tier 3). ChaCha20-Poly1305 and SHA-256/HMAC are not
affected (no data-dependent multiplies on the hot path). All tag/MAC comparisons already go
through the keystore's constant-time AEAD verification.

---

## 8. Module layout, config, new surface, and staged plan

### 8.1 Proposed module layout

```text
src/driver/spi/
  mod.rs       //! L2 devices · spi class · safe · tpm            (SpiBus typed wrapper, DeviceClass::Spi)
  sim.rs       //! L2 devices · driver: spi (simulated) · safe · tpm   (SimSpi + SpiTarget, like SimI2c/I2cTarget)
src/driver/tpm/
  mod.rs       //! L2 devices · tpm transport · safe · tpm        (TpmTransport trait)
  tis.rs       //! L2 devices · tpm TIS/SPI framing · safe · tpm  (TisSpi; locality, STS, wait state)
src/driver/block/
  crypt.rs     //! L2 devices · block: AEAD wrapper · safe · crypto  (CryptBlock<D>: BlockDevice composition wrapper — §6a;
               //  holds a raw DEK injected at mount, not a keystore handle; sibling of filesystems.md's BlockCache/Partition)
src/security/trust/
  mod.rs       //! L3 services · security: trusted platform · safe · tpm   (RootOfTrust, bind, PCR map, seal_to_pcr/unseal/quote)
  cmd.rs       //! L3 services · security: tpm 2.0 command codec · safe · tpm
  session.rs   //! L3 services · security: tpm sessions (HMAC/param-enc) · safe · tpm   (Tiers 1–3; AES only if enabled)
  soft.rs      //! L3 services · security: software TPM model (sim) · safe · tpm        (SoftTpm)
  se.rs        //! L3 services · security: secure-element root of trust · safe · tpm     (ATECC608/OPTIGA, optional)
  retained.rs  //! L3 services · security: retained-RAM sealing · safe · tpm            (§6b)
  sealed.rs    //! L3 services · security: protected objects · safe · tpm               (§6c)
```

Downward-only imports hold: `driver::{spi,tpm,block}` (L2) import only `driver`/`arch`;
`security::trust` (L3) imports the L2 transport (down) and its L3 `keystore`/`entropy`
siblings. Nothing in L2 imports `crate::security` beyond the already-allowed shims.

### 8.2 `config.rs` additions (static sizing)

```rust
/// Bounded TPM command/response buffer (TCG small-command envelope). 1 KiB covers the subset.
pub const TPM_CMD_BYTES: usize   = parse_or(option_env!("BISMUTH_TPM_CMD_BYTES"), 1024);
/// SHA-256 PCRs modelled/used.
pub const TPM_PCRS: usize        = parse_or(option_env!("BISMUTH_TPM_PCRS"), 8);
/// Transient TPM handles (loaded objects + sessions) live at once.
pub const TPM_MAX_OBJECTS: usize = parse_or(option_env!("BISMUTH_TPM_MAX_OBJECTS"), 4);
/// Max sealed-blob size stored in flash (keyedhash object wrapper).
pub const TPM_BLOB_BYTES: usize  = parse_or(option_env!("BISMUTH_TPM_BLOB_BYTES"), 256);
/// Retained-RAM region sealed across sleep.
pub const RETAINED_BYTES: usize  = parse_or(option_env!("BISMUTH_RETAINED_BYTES"), 1024);
/// Protected-object pool (§6c): slots and max plaintext per slot.
pub const MAX_PROTECTED: usize   = parse_or(option_env!("BISMUTH_MAX_PROTECTED"), 4);
pub const PROT_MAX: usize        = parse_or(option_env!("BISMUTH_PROT_MAX"), 256);
```

Feature flags: `tpm = ["crypto"]` (the trust service + transport; requires the keystore);
`tpm-session-enc = ["tpm", "dep:aes", "dep:cfb-mode"]` (Tier 2, **flagged**);
`secure-element = ["crypto"]` (the SE backend). `CryptBlock` (§6a) needs only `crypto`
(`chacha20poly1305`) plus the FS doc's block feature and compiles without `tpm` — it is the
*mount site* that injects a TPM-derived DEK, so the TPM tie lives in the trusted mount code,
not in the L2 wrapper.

### 8.3 New rights / errors (kept minimal)

- **Rights:** reuse `K_ENCRYPT`/`K_DECRYPT`/`K_DERIVE` for all key operations; the
  TPM-derived KEK is an ordinary `Object::Key`. Add **one** right, `Rights::ATTEST`
  (`1 << 22`), for "may request a quote / read measurements", granted sparingly like the
  other `K_*` rights and checked by `trust::quote`. No new `Object` variant is needed (sealed
  blobs at rest are plain flash bytes; the root KEK is a keystore key).
- **Errors:** reuse the existing enum — `Error::Integrity` (EBADMSG) for a failed
  unseal-policy / HMAC / tag / quote-verify (the natural fit, already used by the keystore),
  `Error::NotReady` (ENODEV) for "TPM not present / key not yet released / fail-closed
  storage", `Error::Io` for transport/TPM-response errors, `Error::Timeout` for the bus wait
  state. **No new `Error` variant is required**, which keeps the POSIX `errno` mapping
  untouched.

### 8.4 Staged implementation order (each stage: host-sim tests, keeps `#![deny(unsafe_code)]`)

| Stage | Deliverable | Sim-test strategy | New `unsafe` |
|---|---|---|---|
| **0. SPI class** | `driver/spi` (`SpiBus`) + `SimSpi`/`SpiTarget`; `DeviceClass::Spi` wired like I2c | transfer round-trips against a sim target; speed ioctls | none |
| **1. TPM codec + SoftTpm** | `trust::cmd` codec for the §3 subset; `SoftTpm` implementing `TpmTransport`; `RootOfTrust` for `Tpm<T>` | `Startup`/`GetRandom`/`PCR_Extend`/`PCR_Read` against `SoftTpm`; codec golden vectors; truncated-response fuzzing | none |
| **2. TIS transport** | `driver/tpm/tis` framing over `SpiBus`; wrap `SoftTpm` behind the sim SPI bus so the *same* codec runs over the wire | TIS register sequence; wait-state polling and timeout; end-to-end `Tpm` over `SimSpi`→`SoftTpm` | none |
| **3. Seal/derive + keystore root** | `CreatePrimary`/SRK, `seal_to_pcr`/`unseal`; `keystore::import` the unsealed KEK; per-domain/volume `keystore::derive` | seal a KEK to a PCR state, unseal only when PCRs match, fail closed otherwise; a second `SoftTpm` (clone) fails; derived keys cross-checked | none |
| **4. Measured boot + attestation** | extend PCRs with manifest hash + `ContainerDecl.image_hash`/`version`; `quote`; PSA-token claim wiring (per `security.md` §8) | PCR values after extending a container set; quote verifies against the sim AK; wrong image → different PCRs → no unseal; `ATTEST` right enforced | none |
| **5. Encrypted storage** | `driver/block/crypt::CryptBlock<D>` (`BlockDevice` composition wrapper); random per-block nonce in OOB; mount `set_dek` from the TPM-unsealed, KEK-wrapped volume DEK; fail-closed mount; rekey = re-wrap DEK | over a sim/RAM `BlockDevice`: round-trip, ciphertext-at-rest, tamper/torn→`Integrity`, LBA-relocation→`Integrity`, clone/wrong-boot→unmountable, two writes use distinct nonces, DEK zeroized on unmount | none |
| **6. Retained RAM + protected objects** | `trust::retained` (§6b), `trust::sealed` (§6c) | pre-sleep→ciphertext, resume→recovered, tamper→`Integrity`, cold-boot (no key)→nothing; `with_unsealed` scratch zeroized after use | only a *safe* region accessor, reusing the existing TCB — **no new TCB module** |
| **7. Bus sessions (optional, flagged)** | `trust::session` Tier 1 (HMAC); Tier 2 (AES-CFB param-enc) behind `tpm-session-enc`; Tier 3 later | a `TamperTransport`/eavesdropper wrapping `SoftTpm`: assert HMAC detects tampering (Tier 1) and that `Unseal`'s KEK is not recoverable from the wire (Tier 2) | none (`aes`/`cfb-mode` are safe deps) |
| **8. Secure-element backend (optional)** | `trust::se` implementing `RootOfTrust` over ATECC608/OPTIGA Trust M (emulated seal-to-measurement) | the §§3–6 tests re-run against the SE backend behind the same trait | none |

Ordering rationale: stages 0–2 add the plumbing with zero security claims; stage 3 is where
the hardware-rooted key appears; stages 5–6 are the three encryption forms; session crypto
(stage 7) is deferred and optional because it is the only part that touches the crypto-crate
and threat-model decisions. Every stage is testable against `SoftTpm` with no hardware, and a
real SLB 9670 board port only swaps the `TpmTransport` at stage 2.

---

## 9. Open questions, risks, and documented-limitation candidates

### 9.1 Lead limitation: no transparent hardware RAM encryption on MCUs

**This is the honest core of the answer and belongs in the limitations section of any docs.**
"Memory encryption" in the datacenter sense — transparent, always-on encryption of all of
RAM by the memory controller (AMD SME/SEV, Intel TME/MKTME) — is **not possible on Bismuth's
targets**, for structural reasons:

- **No DRAM / no memory controller with inline AES.** SME/TME are features of a DRAM
  controller that encrypts cache-line traffic to external DRAM. MCUs use **on-chip SRAM**
  with no such controller; there is nothing to insert an AES stage into.
- **No MMU → no fault-driven decrypt.** Transparent encryption relies on the CPU faulting on
  access so a layer can decrypt a page. The MPU only *permits or faults* an access; it cannot
  transform it. There is no demand-paging hook to decrypt-on-touch.
- **Software "encrypt all of RAM" is a non-starter.** The CPU must execute instructions and
  do arithmetic on *plaintext* in registers and stack; you cannot keep the working set
  encrypted and still run. Per-access AEAD of the whole address space would be 100–1000× and
  has no coherent story for interrupts, DMA, or the stack.

Therefore, **on Bismuth, "memory encryption derived from the TPM" means the scoped software
encryption of §6 — storage at rest, retained RAM across sleep, and sealed object buffers —
not an omnipresent transparent layer.** This should be stated plainly to anyone who asks for
"TPM memory encryption" so expectations match reality.

**Future, explicitly out of scope now:** a Cortex-A class SoC with TrustZone-A, OP-TEE and a
firmware TPM (fTPM), and/or a memory controller with inline encryption (Arm CCA Realms, SoC
memory scramblers) could offer something closer to transparent protection. fTPM/OP-TEE are
**Cortex-A only** (they need a rich TEE and a secure-world OS), so they do not apply to the
current MCU targets; this is a separate, later platform story.

### 9.2 Risks and things that would tempt `unsafe`

- **A C TPM stack (tpm2-tss via FFI) would break the safe-Rust rule.** `tss-esapi` is a
  C-library wrapper, not `no_std` ([docs][tss-esapi]), and bindgen FFI pulls `unsafe` and a
  large external TCB into the crate. The design avoids this entirely by implementing the
  small pure-Rust command subset — flagged here as the explicit reason *not* to take the
  FFI shortcut.
- **Casting TPM/on-disk structures with `transmute`/`bytemuck`** is the classic temptation in
  a codec. The house rule (already followed by `net::csum` and endorsed by `filesystems.md`)
  is explicit `from_be_bytes`/`to_be_bytes` with bounds-checked cursors. No `unsafe`.
- **The retained-RAM region accessor** (`&mut [u8]` over a `link_section` static) is the one
  place touching raw memory; it must reuse the existing TCB (a safe region provider), not
  introduce a sixth TCB module.
- **Nonce-reuse bugs** are the highest-severity risk in §6, and the two forms use *different*
  disciplines that each need a dedicated sim test. Storage (§6a) draws a **fresh random
  nonce per block write** (LBA-prefixed), so the test asserts successive writes of one block
  use distinct nonces and never repeat. Retained RAM (§6b) uses a **monotonic sleep counter
  in always-on backup registers / TPM NV**, whose durability and non-rollback across power
  cycles is a correctness dependency worth a KAT. Mixing the two models up (e.g. a random
  nonce where a counter is assumed, or vice versa) is the bug class to guard against.
- **Flash media and authenticated encryption do not compose trivially** (§6a): the clean
  authenticated design is for Disk/Ram media; raw NOR/NAND needs encryption above the FS or a
  non-authenticated tweakable mode. This is a real design fork, resolved with the FS owner as
  "Disk/Ram primary, raw flash is encrypt-above-FS or geometry-preserving-below-littlefs".

### 9.3 Open questions

1. **Threat model per board: is a bus interposer in scope?** This single decision determines
   whether Tier 2 session encryption (and thus the `aes` crate) is required (§7). It should be
   a per-board manifest property, not a global default.
2. **TPM vs secure element as the default** for the reference boards — TPM for
   standards/attestation, SE for cost/size. The `RootOfTrust` trait makes it a build-time
   choice; which to ship first is a product question.
3. **Where does `ROOT_KEK_BLOB` live and how is anti-rollback enforced?** Flash is simplest;
   a TPM NV monotonic counter (optional §3 commands) gives rollback protection but widens the
   codec.
4. **Does the first-stage bootloader extend PCR 0 before handing off,** or does Bismuth do all
   extends? The DICE handoff block (`security.md` §8) is the natural carrier; the contract
   with MCUboot/first-stage needs pinning.
5. **Persist the SRK (`EvictControl`) or recreate it each boot** from the storage seed?
   Recreating avoids NV writes but costs a `CreatePrimary` per boot (noticeable over SPI).
6. **Alignment with `filesystems.md` on the exact encrypted-block placement** (metadata-band
   wrapper vs encrypt-above-FS for flash) — coordinated here as "FS-oblivious, per-block AEAD
   below"; the flash case stays open.

**Documented-limitation candidate — storage anti-rollback is future work.** The §6a
encrypted-block wrapper provides confidentiality, per-block integrity, and LBA-relocation
binding, but **not freshness**: an offline attacker can restore a prior *valid* ciphertext for
the same LBA and it authenticates (it was legitimately produced for that block). Defeating
rollback requires an authenticated per-block **version tree** (Merkle) whose root is anchored
in a **TPM NV monotonic counter** — the durable counter deliberately *not* used for storage
nonces. This lives in the TPM layer (not the FS, which stays oblivious), is bounded and
static like the rest, and is left as explicit future work rather than claimed now. It should
appear in the limitations section alongside §9.1 so "encrypted at rest" is not mistaken for
"rollback-proof".

---

## References

**TPM 2.0 specifications and transport**
- TCG TPM 2.0 Library Specification (Part 1 Architecture, Part 3 Commands). https://trustedcomputinggroup.org/resource/tpm-library-specification/
- TCG PC Client Platform TPM Profile (PTP) Specification (TIS register map, localities, SPI framing §7.4.6, flow-control wait state). https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/
- [qemu-tpm]: QEMU `include/hw/acpi/tpm.h` — TIS register offsets (STS 0x18, DATA_FIFO 0x24, DID_VID 0xf00) and STS bit flags. https://qemu.googlesource.com/qemu/+/refs/tags/v6.0.0-rc0/include/hw/acpi/tpm.h
- [uboot-tis]: U-Boot `drivers/tpm/tpm2_tis_spi.c` — SPI TPM wait-state polling (100-iteration cap). https://qemu.googlesource.com/u-boot/+/refs/heads/master/drivers/tpm/tpm2_tis_spi.c
- [coreboot-tis]: coreboot `src/drivers/spi/tpm/tpm.c` — SPI TPM header framing and ready-bit polling. https://git.ch1p.io/coreboot.git/tree/src/drivers/spi/tpm/tpm.c
- OpenTitan TPM-over-SPI device (command/address/read/write FIFOs, HW wait state). https://opensecura.googlesource.com/3p/lowrisc/opentitan/+/38bb72d0595ce6e7dd6e6226e6f03c22819d5b17%5E%21
- [tpm2-unseal]: tpm2-tools `tpm2_unseal` man page — sealed data is a `TPM_ALG_KEYEDHASH` object created by `tpm2_create`. https://www.mankier.com/1/tpm2_unseal
- [gfiber-trusted]: Linux trusted-keys TPM2 commit — "no fixed storage root key in TPM2; caller specifies the key handle". https://gfiber.googlesource.com/kernel/bruno/+/0fe5480303a1657b328a0a389f8d99249d9961f5

**TPM bus protection (sessions)**
- [ktpm-sec]: Linux kernel documentation, "TPM Security" — salted HMAC sessions, null-primary salt key, parameter encryption of secret-bearing commands, reset-attack limitation. https://www.kernel.org/doc/html/next/security/tpm/tpm-security.html
- [lsm-interposer]: LSM mailing-list thread, "Documenting the proposal for TPM 2.0 security in the face of bus interposer attacks" (what is HMAC-protected vs encrypted; threat-model dispute). https://kernsec.org/pipermail/linux-security-module-archive/2018-November/009835.html
- [google-hmac-patch]: 2025 kernel patch disabling `TCG_TPM2_HMAC` by default (init failures, performance regressions). https://patchew.org/linux/20250814162252.3504279-1-cfenn@google.com

**Discrete TPM and secure-element parts**
- [infineon-slb9670]: Infineon OPTIGA TPM SLB 9670 (TCG TPM 2.0, SPI, FIPS 140-2 L2, CC EAL4+, 110 µA standby). https://infineon.com/cms/de/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm/slb-9670vq2.0
- Infineon OPTIGA TPM SLB 9673 (I2C) and SLB 9672 (industrial temp range). https://community.element14.com/products/devtools/product-pages/w/documents/23053/infineon-tpm-v2-0-peripheral-module
- [mc-an3983]: Microchip ATECC608 — ECDH/ECDSA, AES accelerator, secure boot for small MCUs. https://www.microchip.com/en-us/application-notes/an3983
- [adafruit-trustm]: Infineon OPTIGA Trust M overview — ECC P-256/P-384, RSA 1024/2048, SHA-256, TRNG, user memory. https://learn.adafruit.com/products/4351/guides

**Pure-Rust TPM status**
- [tss-esapi]: `tss-esapi` crate docs — C-backed FFI wrapper over the TSS ESAPI; depends on `tss2-esys`/`tss2-tctildr`/`tss2-mu`; not `no_std`. https://docs.rs/tss-esapi/
- RustCrypto `aes` and `cfb-mode` crates (pure-Rust, `no_std`; needed only for Tier 2 session parameter encryption). https://github.com/RustCrypto/block-ciphers ; https://github.com/RustCrypto/block-modes

**Cold-boot / retained-RAM threat model**
- [coldboot]: J. A. Halderman et al., "Lest We Remember: Cold Boot Attacks on Encryption Keys," USENIX Security 2008. https://jhalderm.com/pub/papers/coldboot-sec08.pdf
- [whonix-cb]: Whonix, "Cold Boot Attack Defense" (RAM clears within minutes; TPM-protected and full-disk-encrypted systems are not immune to RAM-remanence attacks). https://whonix.org/wiki/Cold_Boot_Attack_Defense
- TRESOR / RamCrypt (keys in CPU registers; process-memory encryption trade-offs). https://lkml.iu.edu/hypermail/linux/kernel/2410.0/04628.html

**Reused from the security research (not re-derived here)**
- TCG DICE Layering Architecture. https://trustedcomputinggroup.org/resource/dice-layering-architecture/
- RFC 9783, Arm PSA Attestation Token. https://www.rfc-editor.org/rfc/rfc9783
- NIST SP 800-90B (entropy sources; crediting `TPM2_GetRandom`). https://csrc.nist.gov/pubs/sp/800/90/b/final
