//! Opening-move engines (ADR 0013 §4 / §7 step 1). An engine realizes a *verified, opaque* opening
//! plan onto an already-established, already-shaped byte stream and returns the post-handshake
//! stream. The core stays protocol-blind: it never parses [`OpeningPlan::params`]. Today the only
//! engine is [`tls`] (the boring/flint-tls Chrome realization); the registry `get` is the extension
//! point future engines (e.g. Bitcoin) plug into.
//!
//! Engines **compose** (§7 step 3): because `realize` takes a byte stream and returns one, an engine
//! can write a cleartext prelude and then [`upgrade_to`] a sub-engine on the same live stream — the
//! STARTTLS shape (a future RDP engine → the TLS engine). The sub-engine + its params come from the
//! composing engine's own `engine_params`.

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
    #[cfg(test)]
    if id == "echo" {
        return Some(ECHO_ENGINE);
    }
    #[cfg(all(not(feature = "anytls"), not(test)))]
    let _ = id; // no engines compiled in this build
    None
}

/// Hand an established byte stream to the engine named in `plan`, realizing its opening move and
/// returning the wrapped stream — the mid-stream **composition seam** (ADR 0013 §7 step 3). A
/// composing engine (e.g. a STARTTLS-shaped one) calls this from inside its own `realize`, after
/// writing a cleartext prelude, to upgrade the live connection to a sub-engine (typically the TLS
/// engine) named + parameterized by its own `engine_params`. Fails **loud** if that engine isn't
/// compiled in — never silently degrades. Also the canonical entry the transport layer uses.
pub async fn upgrade_to(stream: BoxedStream, plan: &OpeningPlan) -> io::Result<BoxedStream> {
    let engine = get(plan.engine)
        .ok_or_else(|| io::Error::other(format!("engine '{}' not compiled", plan.engine)))?;
    engine.realize(stream, plan).await
}

/// A trivial engine for the composition tests: writes a marker so a peer can observe it ran, and
/// returns the stream unchanged. Registered in [`get`] under `"echo"` in test builds only.
#[cfg(test)]
struct EchoEngine;

#[cfg(test)]
static ECHO_ENGINE: &EchoEngine = &EchoEngine;

#[cfg(test)]
#[async_trait]
impl OpeningEngine for EchoEngine {
    fn id(&self) -> EngineId {
        "echo"
    }
    async fn realize(
        &self,
        mut stream: BoxedStream,
        _plan: &OpeningPlan,
    ) -> io::Result<BoxedStream> {
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"ECHO").await?;
        stream.flush().await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn plan_for(engine: EngineId) -> OpeningPlan {
        OpeningPlan {
            engine,
            sni: "x".into(),
            params: Vec::new(),
            fallback: Vec::new(),
        }
    }

    #[tokio::test]
    async fn upgrade_to_resolves_and_realizes_via_the_registry() {
        let (client, mut peer) = tokio::io::duplex(64);
        let _stream = upgrade_to(Box::new(client), &plan_for("echo"))
            .await
            .expect("echo engine realizes");
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).await.expect("read echo marker");
        assert_eq!(&buf, b"ECHO");
    }

    #[tokio::test]
    async fn upgrade_to_fails_loud_on_an_unknown_engine() {
        let (client, _peer) = tokio::io::duplex(64);
        // map the Ok stream (not `Debug`) to `()` so `expect_err` can format it.
        let err = upgrade_to(Box::new(client), &plan_for("nonexistent"))
            .await
            .map(|_| ())
            .expect_err("unknown engine must fail loud");
        assert!(
            err.to_string().contains("nonexistent"),
            "the error names the missing engine"
        );
    }

    /// A STARTTLS-shaped composing engine: writes a cleartext prelude, then upgrades the live stream
    /// to a sub-engine via `upgrade_to` — the pattern the future RDP engine uses.
    struct PreludeEngine;

    #[async_trait]
    impl OpeningEngine for PreludeEngine {
        fn id(&self) -> EngineId {
            "prelude"
        }
        async fn realize(
            &self,
            mut stream: BoxedStream,
            _plan: &OpeningPlan,
        ) -> io::Result<BoxedStream> {
            use tokio::io::AsyncWriteExt;
            stream.write_all(b"PRELUDE").await?;
            stream.flush().await?;
            // Upgrade the live connection to the sub-engine (here the test `echo` engine).
            upgrade_to(stream, &plan_for("echo")).await
        }
    }

    #[tokio::test]
    async fn a_prelude_engine_composes_via_upgrade_to() {
        let (client, mut peer) = tokio::io::duplex(64);
        let _stream = PreludeEngine
            .realize(Box::new(client), &plan_for("prelude"))
            .await
            .expect("compose");
        let mut buf = [0u8; 11];
        peer.read_exact(&mut buf)
            .await
            .expect("read prelude + echo");
        assert_eq!(&buf, b"PRELUDEECHO");
    }
}
