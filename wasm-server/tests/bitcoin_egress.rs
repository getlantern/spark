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

/// The committed dev-signed bip324 module, wrapped in a bundle and installed exactly as
/// `spark-wasm-server install` would, so the test exercises the store rather than a raw `.wasm`.
fn install_bundle(dir: &std::path::Path) -> TransformModule {
    let artifact =
        std::fs::read("../core/tests/fixtures/wasm/bip324.spkw").expect("committed bip324 fixture");
    // The fixture is a module (`.spkw`); rewrap it as the bundle the store speaks.
    let signed = spark_core::transport::wasm::ModuleVerifier::pinned()
        .verify(&artifact, 0)
        .expect("the committed fixture verifies under the pinned dev key");
    let wasm = std::fs::read("../modules/bip324/target/wasm32-unknown-unknown/release/bip324.wasm")
        .expect("built bip324 guest module");
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
