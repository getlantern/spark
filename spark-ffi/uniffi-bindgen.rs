//! The UniFFI bindings generator (canonical pattern from the UniFFI guide). The `uniffi-bindgen`
//! feature (which this bin requires) pulls UniFFI's CLI; run e.g.:
//! `cargo run -p spark-ffi --features uniffi-bindgen --bin uniffi-bindgen -- generate \
//!   --library target/release/libspark_ffi.dylib --language swift --out-dir bindings`
fn main() {
    uniffi::uniffi_bindgen_main()
}
