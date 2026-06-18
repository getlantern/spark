//! `spark-bridge` — the desktop Flutter binding (a thin `flutter_rust_bridge` layer over
//! `spark-backend`). The public API lives in [`api`]; `frb_generated` is produced by
//! `flutter_rust_bridge_codegen generate` (do not edit by hand) and wires it to Dart.

pub mod api;
mod frb_generated;
