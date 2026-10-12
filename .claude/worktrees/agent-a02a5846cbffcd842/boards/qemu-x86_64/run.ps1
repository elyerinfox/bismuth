# Build the Bismuth x86-64 kernel, wrap it into a bootable BIOS image, and boot it in QEMU.
#
#   powershell -ExecutionPolicy Bypass -File boards\qemu-x86_64\run.ps1
#   (or, from that folder:  .\run.ps1)
#
# The kernel builds on the stable toolchain; the `bootloader` image builder needs nightly
# (it compiles the BIOS/UEFI stages with -Z build-std), so that one step runs under nightly.
# QEMU must be installed; override its path with  $env:QEMU  if it isn't where scoop puts it.

$ErrorActionPreference = "Stop"

$Root  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Board = Join-Path $Root "boards\qemu-x86_64"
$Image = Join-Path $Root "boards\qemu-x86_64-image"
$Kelf  = Join-Path $Board "target\x86_64-unknown-none\debug\bismuth-x86"
$Img   = Join-Path $Image "bios.img"
$Qemu  = if ($env:QEMU) { $env:QEMU } else { Join-Path $env:USERPROFILE "scoop\apps\qemu\current\qemu-system-x86_64.exe" }

Write-Host ">> building kernel (stable, x86_64-unknown-none)"
Push-Location $Board
cargo build
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "kernel build failed" }
Pop-Location

Write-Host ">> building bootable BIOS image (nightly: bootloader stages)"
Push-Location $Image
$prev = $env:RUSTUP_TOOLCHAIN
$env:RUSTUP_TOOLCHAIN = "nightly"
cargo run --quiet -- $Kelf $Img | Out-Null
$code = $LASTEXITCODE
if ($prev) { $env:RUSTUP_TOOLCHAIN = $prev } else { Remove-Item Env:\RUSTUP_TOOLCHAIN -ErrorAction SilentlyContinue }
if ($code -ne 0) { Pop-Location; throw "image build failed" }
Pop-Location

if (-not (Test-Path $Qemu)) { throw "qemu-system-x86_64 not found at $Qemu (set `$env:QEMU)" }

# A scratch disk exposed as a virtio-blk-pci device for the virtio-pci driver to probe.
$Disk = Join-Path $Image "virtio-disk.img"
if (-not (Test-Path $Disk)) { $fs = [System.IO.File]::Create($Disk); $fs.SetLength(16MB); $fs.Close() }

Write-Host ">> booting in QEMU (serial on this console; the demo halts QEMU when done, or Ctrl-A X)"
& $Qemu -drive "format=raw,file=$Img" -serial stdio -display none -no-reboot `
    -drive "format=raw,file=$Disk,if=none,id=vd0" -device virtio-blk-pci,drive=vd0 `
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
