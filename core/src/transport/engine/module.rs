//! A delivered engine: a signed WASM module behind the [`OpeningEngine`] seam (ADR 0013 §7 — the
//! step that joins the module rail to the genome rail).
//!
//! Before this, a WASM transport was reachable only through `[transport.wasm]`, as a whole pool
//! entry, with its `init` bytes hand-written as a hex string in config; and a genome could only ever
//! name compiled-in code. Both rails already described the same thing — "opaque parameters the core
//! must not parse, interpreted by whoever implements the protocol" — so this adapter is mostly a
//! matter of admitting that. `realize` does what the WASM dial path already did (instantiate, run the
//! interactive handshake if the module drives one, wrap in the steady-state transform), but reached
//! through the engine registry, which means a genome can now select it.
//!
//! Deliberately parallel to [`super::tls::TlsEngine`], down to the `resolve`/`warn` shape: both
//! decode the neutral [`Genome`], both refuse a genome addressed to another engine, and both fall
//! back rather than fail, because connectivity must never depend on a dynamic plan being usable.
//! The one asymmetry is what the params *become* — a boring `Profile` there, the module's `init`
//! blob here.

use std::io;

use async_trait::async_trait;
use flint_shaping::{SegmentShapingStream, WirePlan};

use super::{Genome, OpeningEngine, OpeningPlan};
use crate::transport::wasm::{TransformModule, TransformStream};
use crate::BoxedStream;

/// A verified, compiled WASM module acting as an opening engine under a registry name.
///
/// Cheap to clone-and-share via the `Arc` the registry holds: [`TransformModule`] is an `Arc`-backed
/// compiled module, and a fresh guest instance (its own linear memory and protocol state) is created
/// per connection inside [`OpeningEngine::realize`].
pub struct ModuleEngine {
    name: String,
    module: TransformModule,
}

impl ModuleEngine {
    /// Wrap a verified module as the engine named `name`.
    ///
    /// The name is what a genome's `engine` field must carry to select this module, so it is the
    /// caller's job to use the artifact's own name (see [`super::BIP324`]) rather than invent one.
    /// This type deliberately takes an already-verified [`TransformModule`]: signature and
    /// anti-rollback checking belongs to the verifier, and duplicating it here would invite the two
    /// copies to disagree.
    pub fn new(name: impl Into<String>, module: TransformModule) -> Self {
        Self {
            name: name.into(),
            module,
        }
    }

    /// The compiled module behind this engine.
    ///
    /// Exposed because not every realization is stream-shaped: the UDP dial path needs the
    /// [`Transform`](crate::transport::wasm::Transform) itself (it shares one instance between the
    /// two split halves behind a `Mutex`), so it cannot go through [`OpeningEngine::realize`], which
    /// consumes a stream and returns a stream. Both paths still derive their `init` bytes from
    /// [`Self::init_bytes`], so there is one notion of "this transport's protocol parameters" even
    /// though there are two shapes of realization.
    pub fn module(&self) -> &TransformModule {
        &self.module
    }

    /// Everything one connection needs from its opening plan: the module's `init` bytes and the
    /// Layer-C wire-shaping plan — taken from the dynamic genome if usable, else the static fallback.
    ///
    /// Both come from the **same** genome by construction. Deriving them independently would let a
    /// connection be shaped according to one plan while the module was configured by another, which
    /// is a combination nobody authored and nobody tested.
    ///
    /// Empty `init` bytes are a legitimate result rather than an error: a module with no `init` export
    /// takes no configuration at all, and `instantiate_with_config` is what enforces that pairing.
    pub fn plan(&self, params: &[u8], fallback: &[u8]) -> (Vec<u8>, WirePlan) {
        let genome = self
            .resolve(params, true)
            .or_else(|| self.resolve(fallback, false));
        match genome {
            Some(g) => (g.engine_params, g.wire.to_wire_plan()),
            None => (Vec::new(), WirePlan::default()),
        }
    }

    /// Just the `init` bytes — for the UDP dial path, which realizes the transform itself and has no
    /// stream to shape at the point it needs them.
    pub fn init_bytes(&self, params: &[u8], fallback: &[u8]) -> Vec<u8> {
        self.plan(params, fallback).0
    }

    /// Decode and vet opaque params as a neutral [`Genome`] addressed to this engine.
    ///
    /// `None` on empty / undecodable / wrong-schema / wrong-engine params, so the caller falls back.
    /// `warn` narrates the attempt: pass `true` for a dynamic plan (a decode failure there is news)
    /// and `false` for the static fallback, whose contents were already surfaced once at construction
    /// — otherwise a misconfigured fallback logs on every single connection.
    fn resolve(&self, params: &[u8], warn: bool) -> Option<Genome> {
        if params.is_empty() {
            return None;
        }
        let genome = match Genome::decode(params) {
            Ok(g) => g,
            Err(e) => {
                if warn {
                    tracing::warn!(error = %e, engine = %self.name, "genome undecodable; using fallback");
                }
                return None;
            }
        };
        if genome.genome_version != Genome::SCHEMA_VERSION {
            if warn {
                tracing::warn!(
                    version = genome.genome_version,
                    engine = %self.name,
                    "unsupported genome schema version; using fallback"
                );
            }
            return None;
        }
        // Refusing a genome addressed elsewhere is the load-bearing check: `engine_params` is an
        // opaque blob, so handing another engine's bytes to this module's `init` would be
        // indistinguishable from corruption — and a module aborts (traps) on a malformed config.
        if genome.engine != self.name {
            if warn {
                tracing::warn!(
                    genome_engine = %genome.engine,
                    engine = %self.name,
                    "genome is for a different engine; using fallback"
                );
            }
            return None;
        }
        Some(genome)
    }
}

#[async_trait]
impl OpeningEngine for ModuleEngine {
    fn id(&self) -> &str {
        &self.name
    }

    async fn realize(&self, stream: BoxedStream, plan: &OpeningPlan) -> io::Result<BoxedStream> {
        let (init, wire) = self.plan(&plan.params, &plan.fallback);
        let mut transform = self
            .module
            .instantiate_with_config(&init)
            .map_err(|e| io::Error::other(e.to_string()))?;
        // Shape the opening write per the genome's Layer-C plan — split it into separate flushed
        // segments, optionally spaced in time. Until this step the WASM path did no shaping at all,
        // which meant a non-TLS transport had no way to fragment its opening and the discovery GA's
        // protocol-neutral shaping operators were inert for it.
        //
        // `SegmentShapingStream` is transparent once the opening is out, so it stays in the path for
        // the connection's life (as it does on the TLS path); skip wrapping entirely for a no-op plan
        // rather than pay an indirection for nothing. `tcp_nodelay` is deliberately not handled here:
        // it needs the concrete socket, which this seam has already boxed away, so the dial path
        // applies it.
        let stream: BoxedStream = if wire.is_noop() {
            stream
        } else {
            Box::new(SegmentShapingStream::new(stream, wire))
        };
        let mut stream = stream;
        // An interactive opening (BIP324 and anything else that negotiates) runs on the raw stream
        // before any steady-state bytes; the keys it derives stay inside the guest for the transform
        // that follows. A transform-only module reports false and is passed straight through, which
        // is what keeps this wiring protocol-blind.
        if transform.drives_handshake() {
            transform.run_handshake(&mut stream).await?;
        }
        Ok(Box::new(TransformStream::new(stream, transform)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::engine::{self, BIP324};
    use std::borrow::Cow;
    use std::sync::Arc;

    /// A genome addressed to `engine`, carrying `params` as its opaque engine params.
    fn genome_for(engine: &str, params: Vec<u8>) -> Vec<u8> {
        let mut g = Genome::new("test", engine::TLS, Default::default(), params);
        g.engine = engine.to_owned();
        g.encode().expect("encode genome")
    }

    fn xor_engine(name: &str) -> ModuleEngine {
        ModuleEngine::new(name, crate::transport::wasm::testutil::xor_module())
    }

    #[test]
    fn resolve_extracts_engine_params_for_this_engine() {
        let e = xor_engine("obfs-xor");
        let g = genome_for("obfs-xor", vec![7, 8, 9]);
        assert_eq!(
            e.plan(&g, &[]).0,
            vec![7, 8, 9],
            "params for this engine are handed through verbatim"
        );
    }

    /// Step 3: the wire plan and the `init` bytes must come from the *same* genome. A dynamic genome
    /// that resolves supplies both; if it is refused, both come from the fallback — never one from
    /// each, which would shape a connection per a plan that did not configure it.
    #[test]
    fn the_wire_plan_and_init_bytes_come_from_one_genome() {
        use flint_shaping::SegmentSplit;

        let e = xor_engine("obfs-xor");
        let shaped = |engine: &str, params: Vec<u8>, split: &str| {
            let mut g = Genome::new(
                "g",
                engine,
                flint_tls::gambit::Wire {
                    segment_split: split.to_owned(),
                    ..Default::default()
                },
                params,
            );
            g.genome_version = Genome::SCHEMA_VERSION;
            g.encode().expect("encode")
        };

        // A usable dynamic genome supplies both halves.
        let dynamic = shaped("obfs-xor", vec![1], "700,1400");
        let fallback = shaped("obfs-xor", vec![2], "none");
        let (init, wire) = e.plan(&dynamic, &fallback);
        assert_eq!(init, vec![1], "init came from the dynamic genome");
        assert!(
            !wire.is_noop(),
            "so did the shaping — not the fallback's 'none'"
        );
        assert!(matches!(wire.segment_split, SegmentSplit::Explicit(ref o) if o == &[700, 1400]));

        // A refused dynamic genome means the fallback supplies both, not a mix of the two.
        let misaddressed = shaped("someone-else", vec![1], "700,1400");
        let (init, wire) = e.plan(&misaddressed, &fallback);
        assert_eq!(init, vec![2], "init came from the fallback");
        assert!(wire.is_noop(), "and so did the shaping");
    }

    #[test]
    fn resolve_declines_unusable_params() {
        let e = xor_engine("obfs-xor");
        assert!(e.resolve(&[], true).is_none(), "empty ⇒ use fallback");
        assert!(e.resolve(&[0xFF], true).is_none(), "undecodable genome");
        // A genome for another engine must decline rather than feed foreign bytes to `init`.
        assert!(
            e.resolve(&genome_for("bitcoin", vec![1, 2, 3]), true)
                .is_none(),
            "wrong engine"
        );
        let mut bad = Genome::new("x", engine::TLS, Default::default(), Vec::new());
        bad.engine = "obfs-xor".to_owned();
        bad.genome_version = 99;
        assert!(
            e.resolve(&bad.encode().expect("encode"), true).is_none(),
            "unknown schema version"
        );
    }

    /// Step 3, behaviourally: the genome's wire plan must actually reach the wire, not merely be
    /// decoded. Over real TCP with an inter-segment delay, a peer's first read sees only the first
    /// segment — which is exactly what a censor's reassembly has to contend with. Before this step the
    /// WASM path ignored the plan entirely and the whole opening left as one write.
    #[tokio::test]
    async fn the_genome_wire_plan_actually_segments_the_opening_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        const NAME: &str = "shaping-test";
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Report the size of the *first* read: with the segments spaced in time, that is the first
        // segment alone unless the plan was ignored.
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 64];
            s.read(&mut buf).await.expect("first read")
        });

        let conn = TcpStream::connect(addr).await.expect("connect");
        let genome = Genome::new(
            "g",
            NAME,
            flint_tls::gambit::Wire {
                segment_split: "3".to_owned(),
                delay_ms: Some(80),
                ..Default::default()
            },
            Vec::new(),
        )
        .encode()
        .expect("encode");
        let plan = OpeningPlan {
            engine: Cow::Borrowed(NAME),
            sni: String::new(),
            params: genome,
            fallback: Vec::new(),
        };
        let mut stream = xor_engine(NAME)
            .realize(Box::new(conn), &plan)
            .await
            .expect("realize");
        stream.write_all(b"0123456789").await.expect("write");
        stream.flush().await.expect("flush");

        assert_eq!(
            peer.await.expect("peer task"),
            3,
            "the opening left as its first 3-byte segment, not as one 10-byte write"
        );

        // Control, so the assertion above cannot pass vacuously: the identical harness with a
        // shaping-free genome must deliver the whole write at once. If both cases read 3 bytes the
        // test proves nothing about shaping.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 64];
            s.read(&mut buf).await.expect("first read")
        });
        let conn = TcpStream::connect(addr).await.expect("connect");
        let plan = OpeningPlan {
            engine: Cow::Borrowed(NAME),
            sni: String::new(),
            params: Genome::new("g", NAME, Default::default(), Vec::new())
                .encode()
                .expect("encode"),
            fallback: Vec::new(),
        };
        let mut stream = xor_engine(NAME)
            .realize(Box::new(conn), &plan)
            .await
            .expect("realize");
        stream.write_all(b"0123456789").await.expect("write");
        stream.flush().await.expect("flush");
        assert_eq!(
            peer.await.expect("peer task"),
            10,
            "with no shaping plan the whole opening arrives in one read"
        );
    }

    /// The unification, end to end at the seam: register a module under a name, then resolve that
    /// name through the *registry* — the same path a genome's `engine` string takes — and realize it
    /// onto a live stream. Proves a delivered engine is reachable exactly like a compiled-in one.
    #[tokio::test]
    async fn a_registered_module_realizes_through_the_registry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const NAME: &str = "obfs-xor-registry-test";
        engine::register(Arc::new(xor_engine(NAME)));

        let resolved = engine::get(NAME).expect("a registered module resolves by name");
        assert_eq!(resolved.id(), NAME);

        let (client, mut peer) = tokio::io::duplex(256);
        let plan = OpeningPlan {
            engine: Cow::Borrowed(NAME),
            sni: "x".into(),
            params: genome_for(NAME, Vec::new()),
            fallback: Vec::new(),
        };
        let mut wrapped = engine::upgrade_to(Box::new(client), &plan)
            .await
            .expect("realize the delivered engine");

        // obfs-xor is XOR 0x5A: what lands on the wire is the plaintext masked, which proves the
        // module's transform is actually in the path rather than the stream being passed through.
        wrapped.write_all(b"hello").await.expect("write");
        wrapped.flush().await.expect("flush");
        let mut got = [0u8; 5];
        peer.read_exact(&mut got).await.expect("read wire bytes");
        let want: Vec<u8> = b"hello".iter().map(|b| b ^ 0x5A).collect();
        assert_eq!(
            &got[..],
            &want[..],
            "wire bytes are XOR-masked by the module"
        );

        engine::unregister(NAME);
        assert!(
            engine::get(NAME).is_none(),
            "unregister removes the delivered engine"
        );
    }

    /// Step 1's actual thesis, end to end: a **real protocol** delivered as a signed artifact,
    /// selected by a genome's `engine` string through the registry, with its protocol parameters
    /// carried in that genome's opaque `engine_params` — completing an interactive handshake and
    /// tunnelling bytes. Nothing here is Bitcoin-aware except the fixture and the params blob.
    ///
    /// Note that one registered engine serves *both* ends: the role is a genome field, not a
    /// property of the engine. That is the property that makes a delivered engine configurable the
    /// same way a TLS gambit is.
    #[cfg(feature = "bip324")]
    #[tokio::test]
    async fn a_delivered_bip324_engine_handshakes_selected_by_genome() {
        use crate::transport::wasm::ModuleVerifier;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/bip324.spkw");
        let artifact = std::fs::read(&path).expect("read the committed bip324.spkw fixture");
        let module = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify + compile the signed bip324 module")
            .into_module();

        const NAME: &str = "bip324-engine-test";
        engine::register(Arc::new(ModuleEngine::new(NAME, module)));

        // [role][network_magic(4)][k_srv_len(2) = 0][garbage…] — mainnet, no side-door.
        const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
        let plan = |role: u8, garbage: &[u8]| {
            let mut init = vec![role];
            init.extend_from_slice(&MAGIC);
            init.extend_from_slice(&[0, 0]);
            init.extend_from_slice(garbage);
            OpeningPlan {
                engine: Cow::Borrowed(NAME),
                sni: "x".into(),
                params: genome_for(NAME, init),
                fallback: Vec::new(),
            }
        };

        // Both ends must run concurrently — `realize` drives the handshake to completion, so
        // awaiting one before starting the other would deadlock on the first read.
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (init_plan, resp_plan) = (plan(0, b"initiator garbage"), plan(1, b"responder garbage"));
        let (initiator, responder) = tokio::join!(
            engine::upgrade_to(Box::new(a), &init_plan),
            engine::upgrade_to(Box::new(b), &resp_plan),
        );
        let mut initiator = initiator.expect("initiator realizes through the registry");
        let mut responder = responder.expect("responder realizes through the registry");

        const MSG: &[u8] = b"through the tunnel";
        initiator.write_all(MSG).await.expect("write");
        initiator.flush().await.expect("flush");
        let mut got = vec![0u8; MSG.len()];
        responder.read_exact(&mut got).await.expect("read");
        assert_eq!(got, MSG, "bytes survive the delivered engine's transform");

        engine::unregister(NAME);
    }

    /// The name `BIP324` is a constant precisely so a genome and a registration cannot drift; if a
    /// genome carries a different spelling the engine must decline it rather than trap on foreign
    /// `init` bytes.
    #[test]
    fn the_bip324_name_is_what_a_genome_must_carry() {
        let e = xor_engine(BIP324);
        assert!(e.resolve(&genome_for(BIP324, vec![1]), true).is_some());
        assert!(e.resolve(&genome_for("bip-324", vec![1]), true).is_none());
    }
}
