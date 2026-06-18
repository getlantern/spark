//! The frb-exposed API. `flutter_rust_bridge_codegen` scans `crate::api` (see
//! `flutter_rust_bridge.yaml`) and generates the Dart bindings + the Rust glue in
//! `frb_generated.rs`.

pub mod control;
