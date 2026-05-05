// See `crates/pgbr-core/build.rs`. The same `cfg(c_debug)` is emitted in this crate so the FFI
// shims (e.g. `pgbr_mem_context_field_name`) can branch on the C build's DEBUG mode without
// going through the cargo feature graph.
fn main() {
    println!("cargo:rerun-if-env-changed=PGBR_C_DEBUG");
    println!("cargo::rustc-check-cfg=cfg(c_debug)");
    if std::env::var("PGBR_C_DEBUG").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=c_debug");
    }
}
