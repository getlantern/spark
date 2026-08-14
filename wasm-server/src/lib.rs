//! The exit side of spark's dynamic WASM transports (ADR 0013 §7).
//!
//! Every other spark transport has a server somewhere: `dns-tunnel-server` for the DNS tunnel,
//! lantern-box for the sing-box protocols. The dynamic transports had none — `WasmServer` and
//! `SplittingServer` existed in `core` with no binary wrapping them — so a module could be signed,
//! delivered, verified and loaded by a client with nothing at the other end to talk to. This is that
//! other end.
//!
//! **The server verifies its own bundle**, through the same [`BundleStore`] the client installs into.
//! It could have been handed a bare `.wasm`, which would have been simpler; it is not, deliberately.
//! Client and exit must agree on *which* module they are speaking, and the signed bundle is the only
//! artifact that names an engine, pins a version, and carries the capability grant. Verifying the
//! same artifact under the same pinned key means the two cannot drift, and an operator cannot quietly
//! run a module nobody signed.
//!
//! Two modes, because BIP324 needs more than a listener:
//!
//! - `serve` — accept, run the module as **responder**, read the announced target, relay. The general
//!   case, and what a transform-only module (obfs-xor) wants.
//! - `serve-bitcoin` — the **splitting egress**: peek each connection, and either run the BIP324
//!   tunnel (side-door tag matches) or proxy the bytes untouched to a real Bitcoin node. A
//!   non-participant, including an active prober, sees a well-formed Bitcoin peer — which is the
//!   collateral-freedom property the whole transport exists for, and it only holds if `--upstream`
//!   really is a Bitcoin node.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use spark_core::transport::engine::BundleStore;
use spark_core::transport::wasm::{SplittingServer, TransformModule, WasmServer};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

#[derive(Parser)]
#[command(about = "spark dynamic-transport exit server (ADR 0013 §7)")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Verify a signed bundle and install it into this host's store.
    ///
    /// The provisioning step: an exit is given a `.spkb` and has to put it somewhere `serve` can
    /// resolve it by engine name. Verification happens here, before anything is written, so a bad
    /// artifact is refused at deploy time rather than at the first connection.
    Install(Install),
    /// Relay tunnels for a delivered module. The general case.
    Serve(Serve),
    /// BIP324 splitting egress: tunnel for tagged clients, proxy everything else to a real Bitcoin
    /// node so the listener is indistinguishable from one.
    ServeBitcoin(ServeBitcoin),
}

#[derive(Parser)]
pub struct Install {
    /// Directory to install into. Created on first install.
    #[arg(long)]
    bundle_dir: PathBuf,
    /// The signed `.spkb` artifact to install.
    artifact: PathBuf,
}

#[derive(Parser)]
pub struct Serve {
    /// Directory holding installed bundles, as `BundleStore` lays it out.
    #[arg(long)]
    bundle_dir: PathBuf,
    /// Engine to serve — the name the bundle was **signed** as.
    #[arg(long)]
    engine: String,
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: SocketAddr,
    /// Hex `init` bytes for the module. Empty for a transform-only module.
    #[arg(long, default_value = "")]
    init_config: String,
}

#[derive(Parser)]
pub struct ServeBitcoin {
    #[arg(long)]
    bundle_dir: PathBuf,
    /// Engine to serve. Defaults to the canonical BIP324 engine name.
    #[arg(long, default_value = "bip324")]
    engine: String,
    /// Address to listen on. Defaults to the Bitcoin P2P port — a node on a different port is a
    /// weaker cover story than one on 8333.
    #[arg(long, default_value = "0.0.0.0:8333")]
    listen: SocketAddr,
    /// The real Bitcoin node to proxy non-tunnel connections to.
    ///
    /// Required, and there is no default, because getting it wrong silently destroys the property
    /// this mode exists for: an egress that drops or refuses unrecognized peers is trivially
    /// distinguishable from a Bitcoin node, which is exactly what a prober checks for.
    #[arg(long)]
    upstream: SocketAddr,
    /// Per-server side-door secret (`k_srv`), hex. Clients derive their opening tag from the same
    /// value, so this is what pairs a client to this egress — treat it as a secret and give it to
    /// clients through the signed config, never in the clear.
    #[arg(long)]
    k_srv: String,
    /// Network magic, hex (4 bytes). Defaults to Bitcoin **mainnet** — the cover is only cover if it
    /// looks like the network real peers are on.
    #[arg(long, default_value = "f9beb4d9")]
    magic: String,
}

/// Decode an even-length hex string. Over bytes, never `&str` slicing: a multi-byte character would
/// otherwise panic mid-codepoint rather than erroring, and these values come from an operator's
/// command line.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let bytes = s.trim().as_bytes();
    if bytes.len() % 2 != 0 {
        bail!(
            "expected an even number of hex characters, got {}",
            bytes.len()
        );
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0]);
            let lo = hex_nibble(pair[1]);
            match (hi, lo) {
                (Some(h), Some(l)) => Ok((h << 4) | l),
                _ => bail!("invalid hex digit"),
            }
        })
        .collect()
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Verify and install a bundle into this host's store.
///
/// `BundleStore::install` checks the signature against the key pinned in this binary and enforces
/// both persisted anti-rollback floors *before* writing anything, so a tampered or replayed artifact
/// is refused here — at deploy time, with an operator watching — rather than at the first connection.
pub fn install(args: Install) -> Result<()> {
    let artifact = std::fs::read(&args.artifact)
        .with_context(|| format!("reading {}", args.artifact.display()))?;
    let verified = BundleStore::new(&args.bundle_dir)
        .install(&artifact)
        .with_context(|| format!("installing {}", args.artifact.display()))?;
    info!(
        engine = %verified.engine,
        version = verified.version,
        genomes = verified.genomes.len(),
        dir = %args.bundle_dir.display(),
        "installed a verified bundle"
    );
    Ok(())
}

/// Load and **verify** the engine's bundle, returning its compiled module.
///
/// Goes through `BundleStore::load`, which re-checks the Ed25519 signature against the key pinned in
/// this binary and enforces both persisted anti-rollback floors — the identical check the client
/// runs. A release build refuses to compile without `SPARK_MODULE_PUBKEY_HEX`, so an exit cannot be
/// built that trusts the development key.
///
/// The module is scoped to whatever capabilities the bundle was *signed* with, so an operator cannot
/// widen a module's authority by editing anything on this host.
pub fn load_verified(bundle_dir: &PathBuf, engine: &str) -> Result<TransformModule> {
    let verified = BundleStore::new(bundle_dir)
        .load(engine)
        .with_context(|| format!("loading bundle for engine `{engine}`"))?;
    let wasm = verified
        .wasm
        .as_deref()
        .with_context(|| format!("bundle for engine `{engine}` carries plans but no module"))?;
    let module = TransformModule::load_scoped(wasm, verified.capabilities.clone())
        .map_err(|e| anyhow::anyhow!("compiling module for engine `{engine}`: {e}"))?;
    info!(
        engine = %verified.engine,
        version = verified.version,
        capabilities = ?verified.capabilities,
        "loaded a verified bundle"
    );
    Ok(module)
}

pub async fn serve(args: Serve) -> Result<()> {
    let module = load_verified(&args.bundle_dir, &args.engine)?;
    let init = decode_hex(&args.init_config).context("--init-config")?;
    let server = Arc::new(WasmServer::new(module).with_config(init));

    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, engine = %args.engine, "serving");
    loop {
        let (conn, peer) = listener.accept().await?;
        let server = Arc::clone(&server);
        // Per-connection failures are logged and dropped, never propagated: one client sending
        // garbage must not take the listener down for everyone else.
        tokio::spawn(async move {
            if let Err(e) = relay_one(&server, conn).await {
                warn!(%peer, error = %e, "connection failed");
            }
        });
    }
}

/// Deobfuscate one connection, dial the target it announced, and splice the two.
async fn relay_one(server: &WasmServer, conn: TcpStream) -> Result<()> {
    let (target, leftover, mut wrapped) = server.accept(conn).await.context("accept")?;
    let mut upstream = match &target {
        spark_core::transport::tcp_tunnel::header::Address::Ip(sa) => TcpStream::connect(*sa).await,
        spark_core::transport::tcp_tunnel::header::Address::Domain { host, port } => {
            TcpStream::connect((host.as_str(), *port)).await
        }
    }
    .with_context(|| format!("dialing announced target {target:?}"))?;

    // Bytes that arrived in the same read as the header have already left the client; dropping them
    // would silently truncate the very first request on every connection.
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    tokio::io::copy_bidirectional(&mut wrapped, &mut upstream).await?;
    Ok(())
}

pub async fn serve_bitcoin(args: ServeBitcoin) -> Result<()> {
    let module = load_verified(&args.bundle_dir, &args.engine)?;
    let k_srv = decode_hex(&args.k_srv).context("--k-srv")?;
    if k_srv.is_empty() {
        // An empty key makes the side-door tag publicly recomputable from the ellswift, so every
        // connection would classify as a tunnel client and the Bitcoin cover would be gone.
        bail!("--k-srv must not be empty: an empty side-door key is not a secret");
    }
    let magic = decode_hex(&args.magic).context("--magic")?;
    if magic.len() != 4 {
        bail!("--magic must be exactly 4 bytes, got {}", magic.len());
    }

    // Responder init: [role=1][magic:4][k_srv_len:u16 BE][k_srv][garbage]. The side door is a no-op
    // for a responder — the *splitter* is what checks the tag — so the key is declared empty here
    // rather than handed to the guest, keeping the secret in host memory only.
    let mut init = Vec::with_capacity(7);
    init.push(1u8);
    init.extend_from_slice(&magic);
    init.extend_from_slice(&0u16.to_be_bytes());

    let wasm = WasmServer::new(module).with_config(init);
    let splitter = Arc::new(SplittingServer::new(wasm, k_srv, args.upstream));

    let listener = TcpListener::bind(args.listen).await?;
    info!(
        listen = %args.listen,
        upstream = %args.upstream,
        engine = %args.engine,
        "serving BIP324 splitting egress"
    );
    loop {
        let (conn, peer) = listener.accept().await?;
        let splitter = Arc::clone(&splitter);
        tokio::spawn(async move {
            // `handle` covers both branches — tunnel and proxy-to-bitcoind — so a failure here says
            // nothing about which one the peer was, and must not be treated as a tunnel error.
            if let Err(e) = splitter.handle(conn).await {
                warn!(%peer, error = %e, "connection failed");
            }
        });
    }
}
