// Host-side builder: turn the Bismuth x86-64 kernel ELF into a bootable BIOS disk image.
fn main() {
    let kernel = std::env::args().nth(1).expect("usage: <kernel-elf> [out.img]");
    let out = std::env::args().nth(2).unwrap_or_else(|| "bios.img".to_string());
    let out = std::path::PathBuf::from(out);
    bootloader::DiskImageBuilder::new(std::path::PathBuf::from(kernel))
        .create_bios_image(&out)
        .expect("create bios image");
    println!("{}", out.display());
}
