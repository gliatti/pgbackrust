#!/usr/bin/env bash
# build-ffi.sh — invoked by the meson custom_target that produces libpgbr_ffi.a + pgbr_ffi.h.
# Runs `cargo build` to compile the static library, then `cbindgen` to emit the matching C header.
# All paths are absolute. The cargo target dir is colocated with the meson build to keep artefacts
# scoped per-build.
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
    echo "usage: $0 <source_root> <build_root> <output_lib> <output_header> [c_debug]" >&2
    exit 64
fi

SOURCE_ROOT="$1"
BUILD_ROOT="$2"
OUTPUT_LIB="$3"
OUTPUT_HEADER="$4"
# Optional 5th arg: "1" to enable the cargo c-debug feature (DEBUG layout). The src/meson.build
# `custom_target` passes this from `get_option('debug')` so the Rust mirror in
# `pgbr-core::mem_context` matches the C bitfield layout.
C_DEBUG_ARG="${5:-${PGBR_C_DEBUG:-0}}"

CARGO_TARGET_DIR="${BUILD_ROOT}/cargo-ffi"
export CARGO_TARGET_DIR

# When the C side defines `DEBUG`, the meson custom_target sets `PGBR_C_DEBUG=1` in the env so
# the Rust crate enables the layout-matching `c-debug` feature on `pgbr-ffi` (and transitively
# `pgbr-core`). Without this the struct mirrors in `pgbr-core::mem_context` use the wrong layout
# for DEBUG builds (or vice versa for release) and corrupt memory.
CARGO_FEATURES_ARGS=()
if [[ "${C_DEBUG_ARG}" == "1" ]]; then
    CARGO_FEATURES_ARGS=(--features c-debug)
fi
# Export PGBR_C_DEBUG so the build.rs scripts in pgbr-core / pgbr-ffi pick it up and emit the
# `cfg(c_debug)` in the compiled crate. The cargo `c-debug` feature is also passed for
# documentation; both paths set the same compile-time `cfg`.
export PGBR_C_DEBUG="${C_DEBUG_ARG}"
echo "[build-ffi.sh] c_debug=${C_DEBUG_ARG} -> features=${CARGO_FEATURES_ARGS[*]:-(none)}" >&2

# Use a feature-suffixed target dir so cargo never reuses an artefact built with the wrong
# feature set. Without this suffix, ninja's input-tracking would happily reuse a previous
# `libpgbr_ffi.a` whose `pgbr-core::mem_context::MemContext` struct has the wrong layout for
# the current `PGBR_C_DEBUG` value (cargo's incremental-build cache keys on the active feature
# set, but the resulting `target/release/libpgbr_ffi.a` path is the same regardless).
if [[ "${C_DEBUG_ARG}" == "1" ]]; then
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR}-cdbg"
fi
export CARGO_TARGET_DIR

cargo build \
    --release \
    --manifest-path "${SOURCE_ROOT}/Cargo.toml" \
    --package pgbr-ffi \
    "${CARGO_FEATURES_ARGS[@]}"

# Cargo writes target/release/libpgbr_ffi.a; copy it to the meson-expected output path.
install -m 0644 "${CARGO_TARGET_DIR}/release/libpgbr_ffi.a" "${OUTPUT_LIB}"

# Pass the same feature to cbindgen so the generated header matches the compiled archive.
CBINDGEN_FEATURES_ARGS=()
if [[ "${PGBR_C_DEBUG:-0}" == "1" ]]; then
    CBINDGEN_FEATURES_ARGS=(--config "${SOURCE_ROOT}/cbindgen.toml")
fi

cbindgen \
    --quiet \
    --crate pgbr-ffi \
    --config "${SOURCE_ROOT}/cbindgen.toml" \
    --output "${OUTPUT_HEADER}" \
    "${SOURCE_ROOT}/crates/pgbr-ffi"
