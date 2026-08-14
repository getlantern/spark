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
use spark_core::transport::wasm::{SplittingServer, TransformModule, WasmServer};
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

#[tokio::test]
async fn a_tagged_client_tunnels_and_an_untagged_peer_reaches_bitcoin() {
    let dir = std::env::temp_dir().join(format!("spark-wasm-server-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let module = install_bundle(&dir);

    let echo = spawn_echo().await; // the tunnel's destination
    let bitcoind = spawn_echo().await; // stands in for the real node behind the egress

    // The egress, wired as `serve_bitcoin` wires it.
    let wasm = WasmServer::new(module.clone()).with_config(responder_init());
    let splitter = Arc::new(SplittingServer::new(wasm, K_SRV.to_vec(), bitcoind));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind egress");
    let egress = listener.local_addr().expect("egress addr");
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            let splitter = Arc::clone(&splitter);
            tokio::spawn(async move {
                let _ = splitter.handle(conn).await;
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
        assert!(
            err.to_string().contains("requires `upstream`"),
            "got: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
