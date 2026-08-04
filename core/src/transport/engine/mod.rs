//! Opening-move engines (ADR 0013 §4 / §7 step 1). An engine realizes a *verified, opaque* opening
//! plan onto an already-established, already-shaped byte stream and returns the post-handshake
//! stream. The core stays protocol-blind: it never parses [`OpeningPlan::params`].
//!
//! An engine is either **compiled in** (the boring/flint-tls realization, [`tls`]) or **delivered**
//! as a signed WASM module ([`module::ModuleEngine`]) registered at runtime. That is the point of
//! this seam: a genome names its engine by string, and whether that string resolves to native code
//! or to an artifact somebody shipped is invisible to everything above it. Until this step the two
//! were separate rails, for one mechanical reason — [`get`] was keyed by `&'static str` and returned
//! a `&'static dyn`, and no runtime-loaded module can satisfy either.
//!
//! Engines **compose** (§7 step 3): because `realize` takes a byte stream and returns one, an engine
//! can write a cleartext prelude and then [`upgrade_to`] a sub-engine on the same live stream — the
//! STARTTLS shape (a future RDP engine → the TLS engine). The sub-engine + its params come from the
//! composing engine's own `engine_params`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock, RwLock};

use async_trait::async_trait;

use crate::BoxedStream;

pub mod genome;
pub use genome::Genome;

#[cfg(feature = "anytls")]
pub mod tls;

#[cfg(feature = "wasm-transport")]
pub mod bundle;
#[cfg(feature = "wasm-transport")]
pub use bundle::{Bundle, BundleVerifier, VerifiedBundle};

#[cfg(feature = "wasm-transport")]
pub mod store;
#[cfg(feature = "wasm-transport")]
pub use store::BundleStore;

#[cfg(feature = "wasm-transport")]
pub mod module;
#[cfg(feature = "wasm-transport")]
pub use module::ModuleEngine;

/// Stable registry key for a **compiled-in** engine. Delivered engines are named by an owned
/// `String` instead, since their name arrives with an artifact rather than being written here.
pub type EngineId = &'static str;

/// The boring/flint-tls Chrome realization — the compiled-in engine.
pub const TLS: EngineId = "tls";

/// Canonical registry name for the BIP324 (Bitcoin v2 P2P) module engine. A constant so the genome
/// author, whoever registers the module, and the tests cannot drift on spelling — the engine itself
/// is delivered, not compiled in.
pub const BIP324: &str = "bip324";

/// A verified opening plan handed across the core→engine boundary. `params` / `fallback` are opaque
/// postcard [`Genome`] blobs the core never parses; the engine selected by [`Self::engine`] decodes
/// their `engine_params`.
pub struct OpeningPlan {
    /// Names the engine that realizes this plan (set by the transport builder). `Cow` so a
    /// compiled-in engine costs no allocation (`Cow::Borrowed(TLS)`) while a delivered one can still
    /// be named by an owned `String` read out of a genome.
    pub engine: Cow<'static, str>,
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
    /// This engine's registry name. Borrowed from `self` because a delivered engine owns its name.
    fn id(&self) -> &str;
    async fn realize(&self, stream: BoxedStream, plan: &OpeningPlan) -> io::Result<BoxedStream>;
}

/// The registry of **delivered** engines — those backed by an artifact rather than by compiled-in
/// code, registered at runtime by [`register`].
///
/// Process-wide rather than threaded through a parameter, because [`upgrade_to`] is the composition
/// seam: a composing engine calls it from inside its own `realize`, where there is no context to
/// thread. The lock is held only long enough to clone an `Arc` out or insert one — never across an
/// `.await`, so it cannot deadlock the runtime. A poisoned lock is recovered from rather than
/// panicked on: a registry entry is immutable once inserted, so a panic elsewhere leaves nothing
/// half-written to observe.
fn delivered() -> &'static RwLock<HashMap<String, Arc<dyn OpeningEngine>>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, Arc<dyn OpeningEngine>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// Register a delivered engine under its own [`OpeningEngine::id`], returning whatever it displaced.
///
/// This is how a signed WASM module becomes nameable by a genome: verify + compile the artifact,
/// wrap it in a [`module::ModuleEngine`], register it, and any genome carrying that `engine` string
/// now resolves to it. Replacing an existing registration is deliberate — that is how a newer
/// artifact supersedes an older one without a restart. Anti-rollback is the *verifier's* job (the
/// signed version floor), not this function's.
pub fn register(engine: Arc<dyn OpeningEngine>) -> Option<Arc<dyn OpeningEngine>> {
    let name = engine.id().to_owned();
    delivered()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(name, engine)
}

/// Remove a delivered engine, returning it if it was registered.
pub fn unregister(name: &str) -> Option<Arc<dyn OpeningEngine>> {
    delivered()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(name)
}

/// Resolve an engine by name: compiled-in engines first, then the delivered registry. `None` when
/// nothing answers to that name — including when a compiled-in engine's feature is off — so the call
/// site fails loud rather than silently degrading (ADR 0013 consequences).
///
/// Compiled-in engines are handed out as a cached `Arc` (allocated once, cloned thereafter) so the
/// owned return type costs nothing per dial.
pub fn get(id: &str) -> Option<Arc<dyn OpeningEngine>> {
    #[cfg(feature = "anytls")]
    if id == TLS {
        static TLS_ENGINE: OnceLock<Arc<dyn OpeningEngine>> = OnceLock::new();
        return Some(Arc::clone(
            TLS_ENGINE.get_or_init(|| Arc::new(tls::TlsEngine)),
        ));
    }
    #[cfg(test)]
    if id == "echo" {
        static ECHO: OnceLock<Arc<dyn OpeningEngine>> = OnceLock::new();
        return Some(Arc::clone(ECHO.get_or_init(|| Arc::new(EchoEngine))));
    }
    delivered()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned()
}

/// Hand an established byte stream to the engine named in `plan`, realizing its opening move and
/// returning the wrapped stream — the mid-stream **composition seam** (ADR 0013 §7 step 3). A
/// composing engine (e.g. a STARTTLS-shaped one) calls this from inside its own `realize`, after
/// writing a cleartext prelude, to upgrade the live connection to a sub-engine (typically the TLS
/// engine) named + parameterized by its own `engine_params`. Fails **loud** if that engine isn't
/// compiled in — never silently degrades. Also the canonical entry the transport layer uses.
pub async fn upgrade_to(stream: BoxedStream, plan: &OpeningPlan) -> io::Result<BoxedStream> {
    let engine = get(&plan.engine)
        .ok_or_else(|| io::Error::other(format!("engine '{}' not compiled", plan.engine)))?;
    engine.realize(stream, plan).await
}

/// A trivial engine for the composition tests: writes a marker so a peer can observe it ran, and
/// returns the stream unchanged. Registered in [`get`] under `"echo"` in test builds only.
#[cfg(test)]
struct EchoEngine;

#[cfg(test)]
#[async_trait]
impl OpeningEngine for EchoEngine {
    fn id(&self) -> &str {
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

    fn plan_for(engine: &'static str) -> OpeningPlan {
        OpeningPlan {
            engine: Cow::Borrowed(engine),
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
        fn id(&self) -> &str {
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
