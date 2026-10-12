//! A minimal OCI image loader for the WASM container path (the `runwasi` / Docker+Wasm model):
//! parse an OCI image **manifest** (JSON), locate the `application/wasm` layer, and run it in the
//! interpreter under WASI. This is "run a container *image*" without a Linux userland — the layer
//! blob is a `wasm32` module, not an ELF rootfs.
//!
//! `pull` (fetching blobs from a registry over the network) is a separate transport; this is the
//! offline half — given a manifest and a way to fetch blobs by digest, it admits and runs the
//! image. With the `crypto` feature each blob's `sha256:` digest is verified (content addressing);
//! without it (e.g. the soft-float boards) the layer is located and run unverified.
//!
//! Classification: L4 personalities · OCI-WASM image loader · safe · wasm

use alloc::string::String;
use alloc::vec::Vec;

use super::Module;
use crate::Error;

/// One layer descriptor from an image manifest.
pub struct Layer {
    pub media_type: String,
    pub digest: String,
}

/// The parsed subset of an OCI image manifest we need: its layers.
pub struct ImageManifest {
    pub layers: Vec<Layer>,
}

/// Read the string value of `"key"` within the JSON object text `obj` (first occurrence).
fn string_field(obj: &str, key: &str) -> Option<String> {
    let b = obj.as_bytes();
    let pat = {
        let mut p = String::from("\"");
        p.push_str(key);
        p.push('"');
        p
    };
    let mut i = obj.find(&pat)? + pat.len();
    // Skip whitespace and the ':'.
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t' || b[i] == b'\n' || b[i] == b'\r' || b[i] == b':') {
        i += 1;
    }
    if i >= b.len() || b[i] != b'"' {
        return None;
    }
    i += 1;
    let start = i;
    while i < b.len() && b[i] != b'"' {
        i += 1;
    }
    Some(String::from(&obj[start..i]))
}

/// Split the text of a JSON array into its top-level `{ ... }` object slices.
fn array_objects(arr: &str) -> Vec<&str> {
    let b = arr.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    out.push(&arr[start..=i]);
                }
            }
            _ => {}
        }
    }
    out
}

impl ImageManifest {
    /// Parse the `layers` array of an OCI image manifest. Targeted — it extracts each layer's
    /// `mediaType` and `digest`, not a general JSON tree.
    pub fn parse(json: &str) -> Result<ImageManifest, Error> {
        let key = json.find("\"layers\"").ok_or(Error::Invalid)?;
        let open = json[key..].find('[').ok_or(Error::Invalid)? + key;
        // Find the matching ']' for this '['.
        let b = json.as_bytes();
        let (mut depth, mut end) = (0i32, open);
        for i in open..b.len() {
            match b[i] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let mut layers = Vec::new();
        for obj in array_objects(&json[open..=end]) {
            let media_type = string_field(obj, "mediaType").unwrap_or_default();
            let digest = string_field(obj, "digest").unwrap_or_default();
            layers.push(Layer { media_type, digest });
        }
        Ok(ImageManifest { layers })
    }

    /// The digest of the first `application/wasm` layer (the workload).
    pub fn wasm_digest(&self) -> Option<&str> {
        self.layers.iter().find(|l| l.media_type.contains("wasm")).map(|l| l.digest.as_str())
    }
}

/// Verify a blob against a `sha256:<hex>` digest (content addressing). With `crypto` enabled this
/// recomputes SHA-256; without it, it is a no-op (returns `Ok`).
#[cfg(feature = "crypto")]
pub fn verify_digest(digest: &str, blob: &[u8]) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    let hex = digest.strip_prefix("sha256:").ok_or(Error::Unsupported)?;
    let got: [u8; 32] = Sha256::digest(blob).into();
    // Compare against the lowercase hex.
    let mut want = [0u8; 32];
    if hex.len() != 64 {
        return Err(Error::Invalid);
    }
    for (i, w) in want.iter_mut().enumerate() {
        let hi = (hex.as_bytes()[2 * i] as char).to_digit(16).ok_or(Error::Invalid)?;
        let lo = (hex.as_bytes()[2 * i + 1] as char).to_digit(16).ok_or(Error::Invalid)?;
        *w = ((hi << 4) | lo) as u8;
    }
    if got == want { Ok(()) } else { Err(Error::Integrity) }
}

#[cfg(not(feature = "crypto"))]
pub fn verify_digest(_digest: &str, _blob: &[u8]) -> Result<(), Error> {
    Ok(())
}

/// Load an OCI-WASM image: parse the manifest, fetch the `application/wasm` layer by digest via
/// `blob`, verify it (content addressing), and run it under WASI. Returns the module's exit code.
pub fn run_image<'a>(manifest_json: &str, blob: impl Fn(&str) -> Option<&'a [u8]>) -> Result<i32, Error> {
    let m = ImageManifest::parse(manifest_json)?;
    let digest = m.wasm_digest().ok_or(Error::NotFound)?;
    let bytes = blob(digest).ok_or(Error::NotFound)?;
    verify_digest(digest, bytes)?;
    Module::parse(bytes)?.run_wasi()
}
