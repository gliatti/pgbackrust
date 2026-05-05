// Read the `PGBR_C_DEBUG` env var (set by the meson custom_target via build-ffi.sh) and emit a
// `cfg(c_debug)` so the `MemContext` mirror in `mem_context.rs` can switch its layout without
// requiring callers to enable a cargo feature. The cargo `c-debug` feature is harder to plumb
// because feature propagation across `--package pgbr-ffi --features c-debug` does not always
// reach `pgbr-core` in the test build (root cause unknown; the manual `cargo build` from the
// repository root with the same flags does propagate, but the test.pl flow does not).
fn main() {
    println!("cargo:rerun-if-env-changed=PGBR_C_DEBUG");
    println!("cargo::rustc-check-cfg=cfg(c_debug)");
    if std::env::var("PGBR_C_DEBUG").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=c_debug");
    }
}
