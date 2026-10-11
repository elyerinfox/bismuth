use std::{env, fs, path::PathBuf};

fn main() {
    // Put memory.x where the linker (and cortex-m-rt's link.x) can find it.
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::copy("memory.x", out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
}
