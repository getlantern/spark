//! Opening-move engines (ADR 0013 §4 / §7 step 1). An engine realizes a *verified, opaque* opening
//! plan onto an already-established, already-shaped byte stream and returns the post-handshake
//! stream. The core stays protocol-blind: it never parses [`OpeningPlan::params`]. Today the only
//! engine is [`tls`] (the boring/flint-tls Chrome realization); the registry `get` is the extension
//! point future engines (e.g. Bitcoin) plug into.

use std::io;

use async_trait::async_trait;

use crate::BoxedStream;

pub mod genome;
pub use genome::Genome;

#[cfg(feature = "anytls")]
pub mod tls;

/// Stable registry key for an engine.
pub type EngineId = &'static str;

/// The boring/flint-tls Chrome realization — the one engine this step ships.
pub const TLS: EngineId = "tls";

/// A verified opening plan handed across the core→engine boundary. `params` / `fallback` are opaque
/// postcard [`Genome`] blobs the core never parses; the engine selected by [`Self::engine`] decodes
/// their `engine_params`.
pub struct OpeningPlan {
    /// Engine registry key selecting which engine realizes this plan (set by the transport builder).
    pub engine: EngineId,
    /// Peer name (TLS SNI for the TLS engine).
    pub sni: String,
    /// Dynamic params to attempt (a postcard `Genome`); empty ⇒ use `fallback`.
    pub params: Vec<u8>,
    /// Always-realizable static-config params (a postcard `Genome`), used when `params` is empty or
    /// unrealizable — so connectivity never depends on a dynamic plan succeeding.
    pub fallback: Vec<u8>,
}

/// Realizes an [`OpeningPlan`] onto an established byte stream, returning the wrapped stream.
#[async_trait]
pub trait OpeningEngine: Send + Sync {
    fn id(&self) -> EngineId;
    async fn realize(&self, stream: BoxedStream, plan: &OpeningPlan) -> io::Result<BoxedStream>;
}

/// Look up a compiled-in engine by id, or `None` when its feature is off — so the call site fails
/// loud rather than silently degrading (ADR 0013 consequences).
pub fn get(id: EngineId) -> Option<&'static dyn OpeningEngine> {
    #[cfg(feature = "anytls")]
    if id == TLS {
        return Some(tls::ENGINE);
    }
    #[cfg(not(feature = "anytls"))]
    let _ = id; // no engines compiled in this build
    None
}
