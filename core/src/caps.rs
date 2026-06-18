//! Compiled-in capability reporting — which optional transports/netstacks *this* `spark-core` build
//! supports. The control plane surfaces this (ADR 0004) so a UI offers only valid choices. Pure
//! `cfg!`, so it reflects exactly the features the running binary was built with (no config, no
//! runtime probing).

/// The optional features compiled into this build of `spark-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compiled {
    /// The AnyTLS-over-BoringSSL transport (`anytls` feature, ADR 0001).
    pub anytls: bool,
    /// The dynamic wasm transport (`wasm-transport` feature, ADR 0003).
    pub wasm_transport: bool,
    /// The kernel-TCP "system" netstack (`system-stack` feature, ADR 0002).
    pub system_stack: bool,
}

/// Report which optional features are compiled into this build.
pub fn compiled() -> Compiled {
    Compiled {
        anytls: cfg!(feature = "anytls"),
        wasm_transport: cfg!(feature = "wasm-transport"),
        system_stack: cfg!(feature = "system-stack"),
    }
}
