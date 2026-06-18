//! The UniFFI bindings generator (canonical pattern from the UniFFI guide). Run e.g.:
//! `cargo run -p spark-ffi --bin uniffi-bindgen -- generate \
//!   --library target/debug/libspark_ffi.dylib --language swift --out-dir bindings`
fn main() {
    uniffi::uniffi_bindgen_main()
}
