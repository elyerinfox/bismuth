//! The OCI-WASM image loader: parse an image manifest, locate the `application/wasm` layer by
//! digest, verify it (content addressing), and run it under WASI — "run a container image".

#![cfg(all(feature = "wasm", feature = "crypto"))]

use bismuth::wasm::oci;
use sha2::{Digest, Sha256};

// A wasm layer: (import proc_exit) (func (export "_start") i32.const 7 call 0) — exits with 7.
const LAYER: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x08, 0x02, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x00, 0x00,
    0x02, 0x24, 0x01, 0x16, b'w', b'a', b's', b'i', b'_', b's', b'n', b'a', b'p', b's', b'h', b'o', b't', b'_', b'p',
    b'r', b'e', b'v', b'i', b'e', b'w', b'1', 0x09, b'p', b'r', b'o', b'c', b'_', b'e', b'x', b'i', b't', 0x00, 0x00,
    0x03, 0x02, 0x01, 0x01,
    0x07, 0x0a, 0x01, 0x06, b'_', b's', b't', b'a', b'r', b't', 0x00, 0x01,
    0x0a, 0x08, 0x01, 0x06, 0x00, 0x41, 0x07, 0x10, 0x00, 0x0b,
];

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn loads_and_runs_a_wasm_image_from_its_manifest() {
    let digest = format!("sha256:{}", hex(&Sha256::digest(LAYER)));
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{{"mediaType":"application/vnd.wasm.config.v1+json","digest":"sha256:00","size":2}},
            "layers":[{{"mediaType":"application/wasm","digest":"{digest}","size":{}}}]}}"#,
        LAYER.len()
    );

    // The manifest names one wasm layer; the loader fetches it by digest, verifies, and runs it.
    let code = oci::run_image(&manifest, |d| if d == digest { Some(LAYER) } else { None }).unwrap();
    assert_eq!(code, 7);

    // A manifest whose layer digest does not match the blob is rejected (content addressing).
    let bad = manifest.replace(&digest, "sha256:deadbeef");
    assert!(oci::run_image(&bad, |_| Some(LAYER)).is_err());
}

#[test]
fn parses_the_layer_descriptors() {
    let m = oci::ImageManifest::parse(
        r#"{"layers":[{"mediaType":"application/wasm","digest":"sha256:abc","size":10}]}"#,
    )
    .unwrap();
    assert_eq!(m.layers.len(), 1);
    assert_eq!(m.wasm_digest(), Some("sha256:abc"));
}
