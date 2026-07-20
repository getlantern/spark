//! The neutral opening-move genome (ADR 0013 §4). Protocol-blind: a generic header + a generic
//! wire-shaping plan + an opaque, engine-interpreted `engine_params` blob. The core builds,
//! (de)serializes, and routes on it but never parses `engine_params` — that is the engine's job.
//!
//! `wire` reuses [`flint_tls::gambit::Wire`], which is neutral Layer-C shaping that merely *lives* in
//! flint-tls today (serde + `to_wire_plan`); moving it to `flint-shaping` is out of scope. postcard is
//! positional (not self-describing), so the field order below *is* the wire schema: new fields must be
//! appended and `genome_version` bumped.

use flint_tls::gambit::Wire;
use serde::{Deserialize, Serialize};

use super::EngineId;

/// A protocol-neutral opening plan: generic header + wire + an opaque engine-params blob.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Genome {
    /// Schema version of this envelope (v1).
    pub genome_version: u32,
    /// Monotonic anti-rollback counter for a future signed-distribution channel. Carried but not yet
    /// enforced — this step wires no signing.
    pub version: u64,
    /// Identifier, for server-side fitness attribution.
    pub id: String,
    /// Engine registry key (`"tls"` today) — selects the engine that interprets `engine_params`.
    pub engine: String,
    /// Generic Layer-C wire-shaping plan. Carried; per-connection application stays deferred (the
    /// transport's static `WirePlan` drives shaping today).
    pub wire: Wire,
    /// Opaque, engine-interpreted params — the core never parses these. For the TLS engine, a
    /// postcard-encoded `flint_tls::gambit::Gambit`.
    pub engine_params: Vec<u8>,
}

impl Genome {
    /// Wrap an engine's opaque params in the neutral envelope (v1 schema; `version` initialized to 1,
    /// anti-rollback not yet enforced).
    pub fn new(
        id: impl Into<String>,
        engine: EngineId,
        wire: Wire,
        engine_params: Vec<u8>,
    ) -> Self {
        Self {
            genome_version: 1,
            version: 1,
            id: id.into(),
            engine: engine.to_owned(),
            wire,
            engine_params,
        }
    }

    /// postcard-encode (the canonical serialized form on the opening-plan channel).
    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }

    /// Decode a postcard-encoded genome.
    pub fn decode(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_postcard() {
        let g = Genome::new("x", super::super::TLS, Wire::default(), vec![1, 2, 3]);
        assert_eq!(Genome::decode(&g.encode().unwrap()).unwrap(), g);
    }
}
