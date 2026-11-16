#!/usr/bin/env bash
# Build the decoder guest and the static aarch64 binary, and place both in addon/
# for the add-on image. The binary bakes in the guest's sha256 (build.rs) and
# refuses any other guest at run time, so both must come from the same run.
# Uses a musl cross image because rusqlite's bundled SQLite needs a C cross compiler.
set -euo pipefail
cd "$(dirname "$0")"

# The guest: wasm32-wasip1 needs the rustup toolchain (Arch's system Rust has no wasm std).
WASM_CARGO=${WASM_CARGO:-$HOME/.cargo/bin/cargo}
(cd ../m2100-decoder && "$WASM_CARGO" +1.98.0 build --release --locked --target wasm32-wasip1)
cp ../m2100-decoder/target/wasm32-wasip1/release/m2100-decoder.wasm addon/m2100-decoder.wasm
echo "guest: $(sha256sum addon/m2100-decoder.wasm)"

IMAGE=${IMAGE:-messense/rust-musl-cross:aarch64-musl}
TARGET=aarch64-unknown-linux-musl
mkdir -p target/docker-cargo

docker run --rm --user "$(id -u):$(id -g)" \
  -e HOME=/work/target/docker-cargo -e CARGO_HOME=/work/target/docker-cargo \
  -e CARGO_TARGET_DIR=/work/target/docker-target \
  -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-unknown-linux-musl-gcc \
  -v "$PWD":/work -w /work \
  "$IMAGE" cargo build --release --target "$TARGET" --locked

BIN=target/docker-target/$TARGET/release/m2100-archive
cp "$BIN" addon/m2100-archive

DESC=$(file -b addon/m2100-archive)
echo "$DESC"
case "$DESC" in *"ARM aarch64"*) ;; *) echo "FAIL: not ARM aarch64" >&2; exit 1;; esac
case "$DESC" in *"statically linked"*|*"static-pie linked"*) ;; *) echo "FAIL: not statically linked" >&2; exit 1;; esac
sha256sum addon/m2100-archive
