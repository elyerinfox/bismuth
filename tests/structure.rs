//! Repository structure rules, enforced on every test run:
//!
//! 1. every source file carries a well-formed `Classification:` line;
//! 2. `unsafe` is opted into only by the trusted computing base, and those files (and
//!    only those) are classified as TCB;
//! 3. layers only depend downwards (a lower layer never imports a higher one).

use std::fs;
use std::path::{Path, PathBuf};

const TCB: &[&str] = &[
    "src/arch/cortex_m.rs",
    "src/arch/mmio.rs",
    "src/kernel/cell.rs",
    "src/kernel/heap.rs",
    "src/kernel/stack.rs",
    "src/kernel/usermem.rs",
    // The virtio-blk driver does DMA (shared rings + bounce buffer), so it is TCB like the
    // other ports' device glue, not a plain safe-over-Mmio driver.
    "src/driver/block/virtio_mmio.rs",
    // The legacy virtio-pci block driver (x86-64) likewise does DMA via shared rings + buffers.
    "src/driver/block/virtio_pci.rs",
    // Likewise the virtio-net driver: shared RX/TX virtqueues and frame buffers (DMA).
    "src/net/drivers/virtio_net.rs",
];

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn rel(p: &Path) -> String {
    p.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap().to_string_lossy().replace('\\', "/")
}

struct Info {
    path: String,
    text: String,
    layer: String,
    safety: String,
}

fn classified() -> Vec<Info> {
    let mut files = Vec::new();
    sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    files.sort();
    files
        .iter()
        .map(|p| {
            let text = fs::read_to_string(p).unwrap();
            let path = rel(p);
            let line = text
                .lines()
                .find(|l| l.starts_with("//! Classification:"))
                .unwrap_or_else(|| panic!("{path}: missing `//! Classification:` line"));
            let fields: Vec<&str> = line["//! Classification:".len()..].split('·').map(str::trim).collect();
            assert_eq!(fields.len(), 4, "{path}: classification needs `layer · category · safety · feature`");
            let (layer, safety) = (fields[0].to_string(), fields[2].to_string());
            Info { path, text, layer, safety }
        })
        .collect()
}

#[test]
fn every_file_is_classified() {
    let files = classified();
    assert!(files.len() > 50);
    let layers = ["L0 port", "L1 kernel", "L2 devices", "L3 services", "L4 personalities", "support"];
    for f in &files {
        assert!(layers.contains(&f.layer.as_str()), "{}: unknown layer `{}`", f.path, f.layer);
        assert!(["safe", "TCB (unsafe allowed)"].contains(&f.safety.as_str()), "{}: bad safety field", f.path);
    }
}

#[test]
fn unsafe_is_confined_to_the_trusted_computing_base() {
    for f in classified() {
        // The x86-64 and aarch64 ports each live in their own directory; every file there is TCB.
        let tcb = TCB.contains(&f.path.as_str())
            || f.path.starts_with("src/arch/x86_64/")
            || f.path.starts_with("src/arch/aarch64/")
            || f.path.starts_with("src/arch/cortex_a/");
        let opts_in = f.text.contains("#![allow(unsafe_code)]") || f.text.contains("#[allow(unsafe_code)]");
        assert_eq!(opts_in, tcb, "{}: unsafe opt-in must match the TCB allow-list", f.path);
        assert_eq!(f.safety == "TCB (unsafe allowed)", tcb, "{}: safety classification", f.path);
    }
    let root = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(root.contains("#![deny(unsafe_code)]"));
}

#[test]
fn layers_only_depend_downwards() {
    // Which top-level modules each layer may NOT import.
    let forbidden: &[(&str, &[&str])] = &[
        ("L0 port", &["crate::driver", "crate::net", "crate::compat", "crate::edge", "crate::security", "crate::fs", "crate::ext"]),
        ("L1 kernel", &["crate::driver", "crate::net", "crate::compat", "crate::edge", "crate::console", "crate::fs", "crate::ext"]),
        ("L2 devices", &["crate::net::", "crate::compat", "crate::edge", "crate::fs", "crate::ext"]),
        ("L3 services", &["crate::compat::posix", "crate::compat::freertos"]),
    ];
    // Known, documented exceptions:
    // * kernel → security hooks for domain checks (spawn/task-control policy);
    // * port trap/fault entry → the system-call gate and fault accounting (a trap
    //   necessarily calls upwards).
    let allowed = [
        "crate::security::current",
        "crate::security::check_",
        "crate::security::DomainId",
        "crate::security::Caller",
        "crate::security::syscall::dispatch",
        "crate::security::kill",
        "crate::security::record_fault",
    ];
    for f in classified() {
        let Some((_, banned)) = forbidden.iter().find(|(l, _)| *l == f.layer) else { continue };
        for (n, line) in f.text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for b in *banned {
                if code.contains(b) && !allowed.iter().any(|a| code.contains(a)) {
                    panic!("{}:{}: layer `{}` must not use `{}`", f.path, n + 1, f.layer, b);
                }
            }
        }
    }
}
