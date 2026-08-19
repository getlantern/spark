//! The exit binary against a real client, over real TCP.
//!
//! `core` already tests `SplittingServer` and `WasmServer` directly. What is untested until here is
//! *this crate's wiring*: that a bundle installed the way an operator installs it resolves, that the
//! responder `init` bytes this crate builds are the ones the guest expects, and that the `k_srv` an
//! operator passes on the command line is the same secret the client's tag is checked against. Every
//! one of those is a place where the exit and the client can be individually correct and still not
//! speak to each other.

use std::net::SocketAddr;
use std::sync::Arc;

use spark_core::transport::engine::{BundleStore, Genome, ModuleEngine};
use spark_core::transport::wasm::{SplittingServer, TransformModule, UpstreamPool, WasmServer};
use spark_core::transport::Transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ENGINE: &str = "bip324";
const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
const K_SRV: &[u8] = b"per-server-side-door-secret";

/// An echo server standing in for the tunnel's destination.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Lift the raw guest module out of a signed `.spkw`, whose framing is
/// `MAGIC "SPKW" | version: u32 BE | name_len: u16 BE | name | wasm_len: u32 BE | wasm | sig(64)`
/// (see `core/src/transport/wasm/signing.rs`).
///
/// The obvious source — `modules/bip324/target/…/bip324.wasm` — is a **local build artifact**:
/// `modules/*/target` is gitignored and CI never builds the guest modules (they are a different
/// target and ABI, built on demand by `scripts/build-module.sh`). Reading it passes on a machine that
/// happens to have built one and fails everywhere else, which is exactly what it did. The committed
/// `.spkw` fixture is the only form of this module that is actually in the repository.
fn wasm_from_spkw(artifact: &[u8]) -> Vec<u8> {
    assert_eq!(&artifact[..4], b"SPKW", "not a signed module artifact");
    let name_len = u16::from_be_bytes([artifact[8], artifact[9]]) as usize;
    let wasm_len_at = 10 + name_len;
    let wasm_len = u32::from_be_bytes([
        artifact[wasm_len_at],
        artifact[wasm_len_at + 1],
        artifact[wasm_len_at + 2],
        artifact[wasm_len_at + 3],
    ]) as usize;
    let start = wasm_len_at + 4;
    artifact[start..start + wasm_len].to_vec()
}

/// The committed dev-signed bip324 module, wrapped in a bundle and installed exactly as
/// `spark-wasm-server install` would, so the test exercises the store rather than a raw `.wasm`.
fn install_bundle(dir: &std::path::Path) -> TransformModule {
    let artifact =
        std::fs::read("../core/tests/fixtures/wasm/bip324.spkw").expect("committed bip324 fixture");
    // Verify before trusting the framing: the parse below reads length fields out of these bytes.
    let signed = spark_core::transport::wasm::ModuleVerifier::pinned()
        .verify(&artifact, 0)
        .expect("the committed fixture verifies under the pinned dev key");
    let wasm = wasm_from_spkw(&artifact);
    assert_eq!(signed.name(), ENGINE);

    let genome = Genome::new("plan", ENGINE, Default::default(), Vec::new())
        .encode()
        .expect("encode genome");
    let bundle = spark_core::transport::engine::Bundle::new(ENGINE, vec![genome], Some(wasm));
    let art = spark_core::transport::engine::sign_bundle(
        &spark_core::transport::wasm::dev_keypair(),
        ENGINE,
        1,
        &bundle,
    )
    .expect("sign bundle");

    let verified = BundleStore::new(dir).install(&art).expect("install");
    TransformModule::load_scoped(
        verified.wasm.as_deref().expect("bundle carries the module"),
        verified.capabilities.clone(),
    )
    .expect("compile")
}

/// Responder init, built the way `serve_bitcoin` builds it:
/// `[role=1][magic:4][k_srv_len=0]`.
fn responder_init() -> Vec<u8> {
    let mut v = Vec::with_capacity(7);
    v.push(1u8);
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&0u16.to_be_bytes());
    v
}

/// Initiator init: the same shape with the side-door key present, which is what makes this client
/// classify as a tunnel rather than a passing Bitcoin peer.
fn initiator_init() -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + K_SRV.len());
    v.push(0u8);
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&(K_SRV.len() as u16).to_be_bytes());
    v.extend_from_slice(K_SRV);
    v
}

/// A UDP echo server standing in for a QUIC destination.
async fn spawn_udp_echo() -> SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if sock.send_to(&buf[..n], from).await.is_err() {
                return;
            }
        }
    });
    addr
}

/// Chrome prefers HTTP/3 where the edge offers it, so a tunnel that relays TCP and drops UDP does
/// not fail cleanly — it stalls, per site, while QUIC attempts collapse and Chrome backs down. The
/// exit spoke only TCP until now: it read the announced target and dialed it, with no case for the
/// UDP-associate sentinel, so every association broke (`send to upstream failed … Broken pipe`).
///
/// This drives the real client's `dial_udp` against the real exit — the two halves are separately
/// plausible and the interesting failures are between them: the sentinel dispatch, the *second*
/// address (connect-mode), and the `[u16 BE len][payload]` framing in both directions.
#[tokio::test]
async fn a_client_relays_datagrams_through_the_egress() {
    use spark_core::transport::UdpTransport;

    let dir = std::env::temp_dir().join(format!("spark-wasm-server-udp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let module = install_bundle(&dir);

    let udp_echo = spawn_udp_echo().await;
    let bitcoind = spawn_echo().await;

    let wasm = WasmServer::new(module.clone()).with_config(responder_init());
    let splitter = Arc::new(SplittingServer::new(
        wasm,
        K_SRV.to_vec(),
        UpstreamPool::single(bitcoind),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind egress");
    let egress = listener.local_addr().expect("egress addr");
    tokio::spawn(async move {
        while let Ok((conn, peer)) = listener.accept().await {
            let splitter = Arc::clone(&splitter);
            tokio::spawn(async move {
                let _ = splitter.handle(conn, peer.ip()).await;
            });
        }
    });

    let engine = Arc::new(ModuleEngine::new(ENGINE.to_string(), module));
    let transport = spark_core::transport::wasm::WasmTransport::with_engine(egress, engine)
        .with_config(initiator_init());
    let (mut sink, mut source) = transport
        .dial_udp(udp_echo)
        .await
        .expect("open a UDP association through the egress");

    // Several datagrams, so the test covers the steady state and not just the opening frame that
    // rides along with the header.
    for i in 0u8..4 {
        let payload = vec![i; 64 + i as usize];
        sink.send(&payload).await.expect("send a datagram");
        let mut out = vec![0u8; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), source.recv(&mut out))
            .await
            .expect("a reply arrives (no deadlock, no dropped association)")
            .expect("recv");
        assert_eq!(
            &out[..n],
            &payload[..],
            "datagram {i} must round-trip through the egress intact"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn a_tagged_client_tunnels_and_an_untagged_peer_reaches_bitcoin() {
    let dir = std::env::temp_dir().join(format!("spark-wasm-server-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let module = install_bundle(&dir);

    let echo = spawn_echo().await; // the tunnel's destination
    let bitcoind = spawn_echo().await; // stands in for the real node behind the egress

    // The egress, wired as `serve_bitcoin` wires it.
    let wasm = WasmServer::new(module.clone()).with_config(responder_init());
    let splitter = Arc::new(SplittingServer::new(
        wasm,
        K_SRV.to_vec(),
        UpstreamPool::single(bitcoind),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind egress");
    let egress = listener.local_addr().expect("egress addr");
    tokio::spawn(async move {
        while let Ok((conn, peer)) = listener.accept().await {
            let splitter = Arc::clone(&splitter);
            tokio::spawn(async move {
                let _ = splitter.handle(conn, peer.ip()).await;
            });
        }
    });

    // A Lantern client: same module, initiator role, same k_srv.
    let engine = Arc::new(ModuleEngine::new(ENGINE.to_string(), module));
    let transport = spark_core::transport::wasm::WasmTransport::with_engine(egress, engine)
        .with_config(initiator_init());
    let mut stream = transport.dial(echo).await.expect("dial through the egress");
    let msg = b"through the bitcoin-shaped egress";
    stream.write_all(msg).await.expect("write");
    let mut got = vec![0u8; msg.len()];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(&got[..], &msg[..], "the tunnel carried the payload");

    // A peer with no side-door tag must be proxied to the node, not tunnelled and not dropped —
    // that indistinguishability is the entire reason this mode exists.
    let mut peer = TcpStream::connect(egress).await.expect("connect as a peer");
    peer.write_all(b"i am an ordinary bitcoin peer")
        .await
        .expect("peer write");
    let mut echoed = vec![0u8; 29];
    peer.read_exact(&mut echoed).await.expect("peer read");
    assert_eq!(
        &echoed[..],
        b"i am an ordinary bitcoin peer",
        "an untagged peer is proxied to the upstream node untouched"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The deployed shape: the provisioning pipeline writes one JSON file and restarts the unit, and the
/// bundle rides *in that file*, hex-encoded — the same artifact and encoding the client is sent.
///
/// The success path already has coverage above (`serve_bitcoin` is what `run` dispatches to, and it
/// blocks forever once it starts listening), so these pin the checks that happen *before* anything
/// listens. That ordering is the point: a bad bundle or a bad config should stop the process at
/// deploy time, where someone is watching, not at the first client connection.
mod run_from_config {
    use super::*;

    fn write_config(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("launch.json");
        std::fs::write(&path, body).expect("write config");
        path
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A signed bundle, minted here so the test does not depend on a build artifact.
    fn bundle_hex() -> String {
        let artifact = std::fs::read("../core/tests/fixtures/wasm/bip324.spkw")
            .expect("committed bip324 fixture");
        let wasm = super::wasm_from_spkw(&artifact);
        let genome = Genome::new("plan", ENGINE, Default::default(), Vec::new())
            .encode()
            .expect("encode genome");
        let bundle = spark_core::transport::engine::Bundle::new(ENGINE, vec![genome], Some(wasm));
        hex(&spark_core::transport::engine::sign_bundle(
            &spark_core::transport::wasm::dev_keypair(),
            ENGINE,
            1,
            &bundle,
        )
        .expect("sign"))
    }

    #[tokio::test]
    async fn the_bundle_in_the_config_is_installed_before_anything_listens() {
        let dir = std::env::temp_dir().join(format!("wasm-server-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let store = dir.join("bundles");

        // Deliberately an unknown mode: `run` installs, *then* dispatches, so this returns instead of
        // blocking on a listener while still proving the install happened.
        let cfg = write_config(
            &dir,
            &format!(
                r#"{{"mode":"nonsense","engine":"{ENGINE}","listen":"127.0.0.1:0",
                     "bundle_dir":{store:?},"bundle":"{}"}}"#,
                bundle_hex()
            ),
        );
        let err = wasm_server::run(wasm_server::Run { config: cfg })
            .await
            .expect_err("an unknown mode must be refused");
        assert!(err.to_string().contains("unknown mode"), "got: {err}");
        assert!(
            BundleStore::new(&store).contains(ENGINE),
            "the config's bundle was installed before the mode was even looked at"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The store keys on the name inside the *signature*. A config naming a different engine would
    /// otherwise install under the signed name and then fail an unrelated-looking "not installed".
    #[tokio::test]
    async fn a_config_naming_the_wrong_engine_is_refused() {
        let dir = std::env::temp_dir().join(format!("wasm-server-cfg-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let cfg = write_config(
            &dir,
            &format!(
                r#"{{"mode":"bitcoin","engine":"not-what-it-is","listen":"127.0.0.1:0",
                     "bundle_dir":{:?},"bundle":"{}","upstream":"127.0.0.1:1","k_srv":"aa"}}"#,
                dir.join("bundles"),
                bundle_hex()
            ),
        );
        let err = wasm_server::run(wasm_server::Run { config: cfg })
            .await
            .expect_err("an engine/signature mismatch must be refused");
        assert!(
            err.to_string().contains("signed as `bip324`"),
            "the error must name the real reason, got: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `bitcoin` mode without an upstream would be an egress that refuses every non-tunnel peer —
    /// trivially distinguishable from a Bitcoin node, which is the one thing this mode must not be.
    #[tokio::test]
    async fn bitcoin_mode_requires_an_upstream() {
        let dir = std::env::temp_dir().join(format!("wasm-server-cfg-up-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let cfg = write_config(
            &dir,
            r#"{"mode":"bitcoin","engine":"bip324","listen":"127.0.0.1:0","k_srv":"aa"}"#,
        );
        let err = wasm_server::run(wasm_server::Run { config: cfg })
            .await
            .expect_err("bitcoin mode without an upstream must be refused");
        // Match the structure, not the prose: the property under test is "the config is rejected,
        // naming upstream", and pinning the exact sentence makes an unrelated reword look like a
        // regression — which is how this assertion broke when the field became a list.
        assert!(
            matches!(
                &err,
                wasm_server::ServerError::BadArgument { flag, reason }
                    if *flag == "--config" && reason.contains("upstream")
            ),
            "got: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A pool spelled as an array is accepted, and a bare string still is too.
    ///
    /// The single-address spelling is what an operator writes by hand and what every config written
    /// before the field became a list already contains, so dropping it would break those configs on
    /// upgrade with a parse error rather than a behaviour change.
    #[tokio::test]
    async fn upstream_accepts_both_one_address_and_a_list() {
        for (label, upstream) in [
            ("bare string", r#""127.0.0.1:8333""#),
            ("one-element array", r#"["127.0.0.1:8333"]"#),
            ("pool", r#"["127.0.0.1:8333","127.0.0.1:8334"]"#),
        ] {
            let dir = std::env::temp_dir().join(format!(
                "wasm-server-cfg-pool-{}-{}",
                std::process::id(),
                label.replace(' ', "-")
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let cfg = write_config(
                &dir,
                &format!(
                    r#"{{"mode":"bitcoin","engine":"bip324","listen":"127.0.0.1:0","k_srv":"aa","upstream":{upstream}}}"#
                ),
            );
            let err = wasm_server::run(wasm_server::Run { config: cfg })
                .await
                .expect_err("no bundle is installed, so startup still fails — but not on parsing");
            assert!(
                !matches!(
                    &err,
                    wasm_server::ServerError::BadArgument { reason, .. }
                        if reason.contains("upstream")
                ),
                "{label} must parse as an upstream pool, got: {err}"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }
}

/// The exit's logging asymmetry, asserted against the real `tracing` stream.
///
/// An untagged peer — a potential active prober — is recorded **with its address**, because it is
/// either a real Bitcoin peer or somebody probing us, and the second is what an operator needs to
/// see. A client that presented a valid side-door tag is one of *our users*, and an exit host is
/// precisely the machine an adversary would seize to learn who they are, so it is never written down.
///
/// Both halves matter: without the first there is no probe signal at all; without the second every
/// exit becomes a record of our own users.
///
/// This lives here rather than beside `SplittingServer` in `core` for a mundane but load-bearing
/// reason: `tracing` caches callsite interest process-wide, another `core` unit test installs a
/// *global* subscriber, and the two race — the test passed alone and failed in the full suite. An
/// integration test gets its own process, so the scoped subscriber is the only one there is.
mod logging_hygiene {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::Duration;

    type CapturedEvent = BTreeMap<String, String>;

    /// Collects every `tracing` event's structured fields.
    ///
    /// Fields rather than formatted text: an assertion on rendered output would pass or fail on field
    /// ordering and escaping, neither of which is the property under test.
    fn capture_layer(
        sink: Arc<Mutex<Vec<CapturedEvent>>>,
    ) -> impl tracing_subscriber::Layer<tracing_subscriber::registry::Registry> {
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::Context;
        use tracing_subscriber::Layer;

        #[derive(Default)]
        struct Fields(CapturedEvent);
        impl Visit for Fields {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }
        }

        struct Capture(Arc<Mutex<Vec<CapturedEvent>>>);
        impl Layer<tracing_subscriber::registry::Registry> for Capture {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: Context<'_, tracing_subscriber::registry::Registry>,
            ) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().expect("capture lock").push(fields.0);
            }
        }
        Capture(sink)
    }

    #[tokio::test]
    async fn an_untagged_peer_is_logged_by_address_and_a_tunnel_client_is_not() {
        use tracing_subscriber::layer::SubscriberExt;

        let events: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry::Registry::default()
            .with(capture_layer(Arc::clone(&events)));
        let _guard = tracing::subscriber::set_default(subscriber);

        let dir = std::env::temp_dir().join(format!("wasm-server-hygiene-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let module = install_bundle(&dir);

        let echo = spawn_echo().await;
        let bitcoind = spawn_echo().await;
        let wasm = WasmServer::new(module.clone()).with_config(responder_init());
        let splitter = Arc::new(SplittingServer::new(
            wasm,
            K_SRV.to_vec(),
            UpstreamPool::single(bitcoind),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind egress");
        let egress = listener.local_addr().expect("egress addr");
        tokio::spawn(async move {
            while let Ok((conn, peer)) = listener.accept().await {
                let splitter = Arc::clone(&splitter);
                tokio::spawn(async move {
                    let _ = splitter.handle(conn, peer.ip()).await;
                });
            }
        });

        // A tunnel client, which authenticates.
        let engine = Arc::new(ModuleEngine::new(ENGINE.to_string(), module));
        let transport = spark_core::transport::wasm::WasmTransport::with_engine(egress, engine)
            .with_config(initiator_init());
        let mut tunneled = transport.dial(echo).await.expect("tunnel dial");
        tunneled.write_all(b"user traffic").await.expect("write");
        let mut got = [0u8; 12];
        tunneled.read_exact(&mut got).await.expect("read");
        drop(tunneled);

        // An untagged peer, which does not. 96 bytes of non-tag opening.
        let mut peer = TcpStream::connect(egress).await.expect("peer connect");
        let opening: Vec<u8> = (0..96u32).map(|i| i as u8).collect();
        peer.write_all(&opening).await.expect("peer write");
        let mut echoed = vec![0u8; opening.len()];
        peer.read_exact(&mut echoed).await.expect("peer read");
        drop(peer);

        // The probe record rides a `Drop` on a spawned task, so wait for it rather than sleeping a
        // guessed interval — a fixed delay is a flake that only shows up on a busy machine.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = events
                .lock()
                .expect("capture lock")
                .iter()
                .any(|e| e.get("message").map(String::as_str) == Some("untagged peer"));
            if seen {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no untagged record appeared within the deadline"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let captured = events.lock().expect("capture lock").clone();
        let untagged: Vec<&CapturedEvent> = captured
            .iter()
            .filter(|e| e.get("message").map(String::as_str) == Some("untagged peer"))
            .collect();
        assert_eq!(untagged.len(), 1, "expected one probe record: {captured:?}");
        let record = untagged[0];
        assert!(
            record.contains_key("peer"),
            "the probe record must carry the peer's address: {record:?}"
        );
        // The fields that separate a prober from a real peer. Without them an operator sees only
        // *that* somebody connected, which every legitimate Bitcoin peer also does.
        for field in [
            "opening",
            "duration_ms",
            "bytes_to_upstream",
            "bytes_from_upstream",
        ] {
            assert!(
                record.contains_key(field),
                "probe triage needs `{field}`: {record:?}"
            );
        }

        // The other half: no event anywhere may carry an address for the client that authenticated.
        // `untagged peer` is the only event permitted a `peer` field at all.
        let leaked: Vec<&CapturedEvent> = captured
            .iter()
            .filter(|e| {
                e.contains_key("peer")
                    && e.get("message").map(String::as_str) != Some("untagged peer")
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "a tunnel client is one of our users and must never be written down; leaked: {leaked:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
