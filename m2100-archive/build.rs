//! Bakes in the identity of the decoder guest this add-on is built with (Ruling 1):
//! `M2100_GUEST_SHA256` is the sha256 of `addon/m2100-decoder.wasm` (copied there
//! by build.sh), or "" when the file is absent, which disables decoding.
//! `M2100_WASMTIME_VERSION` keys the compiled-module cache.

use sha2::{Digest, Sha256};
use std::fs;

const GUEST: &str = "addon/m2100-decoder.wasm";

fn main() {
    println!("cargo:rerun-if-changed={GUEST}");
    println!("cargo:rerun-if-changed=Cargo.lock");

    let sha = match fs::read(GUEST) {
        Ok(bytes) => hex(&Sha256::digest(&bytes)),
        Err(_) => String::new(),
    };
    println!("cargo:rustc-env=M2100_GUEST_SHA256={sha}");

    let lock = fs::read_to_string("Cargo.lock").expect("Cargo.lock");
    let mut lines = lock.lines();
    let mut version = None;
    while let Some(l) = lines.next() {
        if l == "name = \"wasmtime\"" {
            version = lines
                .next()
                .and_then(|v| v.strip_prefix("version = \""))
                .and_then(|v| v.strip_suffix('"'))
                .map(str::to_string);
            break;
        }
    }
    let version = version.expect("wasmtime in Cargo.lock");
    println!("cargo:rustc-env=M2100_WASMTIME_VERSION={version}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
