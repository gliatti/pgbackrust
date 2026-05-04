#!/usr/bin/env bash
# build-ffi.sh — invoked by the meson custom_target that produces libpgbr_ffi.a + pgbr_ffi.h.
# Runs `cargo build` to compile the static library, then `cbindgen` to emit the matching C header.
# All paths are absolute. The cargo target dir is colocated with the meson build to keep artefacts
# scoped per-build.
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <source_root> <build_root> <output_lib> <output_header>" >&2
    exit 64
fi

SOURCE_ROOT="$1"
BUILD_ROOT="$2"
OUTPUT_LIB="$3"
OUTPUT_HEADER="$4"

CARGO_TARGET_DIR="${BUILD_ROOT}/cargo-ffi"
export CARGO_TARGET_DIR

cargo build \
    --release \
    --manifest-path "${SOURCE_ROOT}/Cargo.toml" \
    --package pgbr-ffi

# Cargo writes target/release/libpgbr_ffi.a; copy it to the meson-expected output path.
install -m 0644 "${CARGO_TARGET_DIR}/release/libpgbr_ffi.a" "${OUTPUT_LIB}"

cbindgen \
    --quiet \
    --crate pgbr-ffi \
    --config "${SOURCE_ROOT}/cbindgen.toml" \
    --output "${OUTPUT_HEADER}" \
    "${SOURCE_ROOT}/crates/pgbr-ffi"
