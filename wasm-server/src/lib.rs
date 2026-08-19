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

use clap::{Parser, Subcommand};
use spark_core::transport::engine::BundleStore;
use spark_core::transport::wasm::{
    relay_to_target, SplittingServer, TransformModule, UpstreamPool, WasmServer,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

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
    /// Run from a config file — the deployed shape.
    ///
    /// The provisioning pipeline delivers a proxy's settings by writing one file and restarting the
    /// unit, so this is the form that fits it. It also keeps `k_srv` out of the process's argv, where
    /// any local `ps` would read it.
    ///
    /// The config carries the bundle itself, hex-encoded, so the exit obtains its module by exactly
    /// the mechanism the *client* does. One delivery path, one encoding, and both sides verify the
    /// same artifact against the same pinned key before running it.
    Run(Run),
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
    pub bundle_dir: PathBuf,
    /// The signed `.spkb` artifact to install.
    pub artifact: PathBuf,
}

#[derive(Parser)]
pub struct Run {
    // `pub` so the integration test can construct a launch without going through clap.
    /// Path to the JSON launch config.
    #[arg(long)]
    pub config: PathBuf,
}

/// The launch config the provisioning pipeline writes.
///
/// JSON because that is what lantern-cloud's config-push produces; the field names mirror the
/// equivalent flags so an operator can move between the two without a translation table.
#[derive(Debug, serde::Deserialize)]
pub struct FileConfig {
    /// `"bitcoin"` for the splitting egress, `"relay"` for the general case.
    mode: String,
    /// Engine to serve — the name the bundle was **signed** as.
    pub engine: String,
    pub listen: SocketAddr,
    /// Where bundles are installed. Defaults to `bundles/` **under** the unit's `StateDirectory` —
    /// `StateDirectory=spark-wasm-server` creates `/var/lib/spark-wasm-server`, and the store gets
    /// its own subdirectory there so its artifacts and `floors.toml` do not sit loose in the state
    /// root alongside whatever else this service ever needs to keep.
    ///
    /// That root is the only path this service can write at all: it runs under `DynamicUser` with
    /// `ProtectSystem=strict`, so anywhere else is read-only by construction.
    #[serde(default = "default_bundle_dir")]
    pub bundle_dir: PathBuf,
    /// The signed `.spkb`, hex-encoded — the same artifact and the same encoding the client is sent.
    /// Installed on startup, before anything listens. Absent means "already installed".
    #[serde(default)]
    bundle: String,
    /// `bitcoin` mode only: the real Bitcoin nodes to proxy non-tunnel connections to.
    ///
    /// A list rather than one address: `bitcoind` scores misbehaviour per peer, and every peer we
    /// forward is *us* from the upstream's point of view, so one bad sender we proxy can get this
    /// egress banned from its only cover. Accepts a bare string as well as an array, matching how
    /// the client's own schema treats `url` — an operator with one node should not have to know it
    /// is a degenerate pool.
    #[serde(default, deserialize_with = "de_addr_or_vec")]
    upstream: Vec<SocketAddr>,
    /// `bitcoin` mode only: the per-server side-door secret, hex.
    ///
    /// **This file holds a secret.** It should be written `0600`, the way the pipeline already treats
    /// a TLS private key — carrying it here rather than in argv is half the reason this mode exists.
    #[serde(default)]
    pub k_srv: String,
    /// `bitcoin` mode only. Defaults to Bitcoin mainnet.
    #[serde(default = "default_magic")]
    pub magic: String,
    /// `relay` mode only: hex `init` bytes for the module.
    #[serde(default)]
    pub init_config: String,
}

/// Deserialize `upstream` from either a bare address or an array of them.
///
/// Mirrors `de_string_or_vec` in the client's config schema, and for the same reason: the single-node
/// spelling is the one an operator writes by hand, and it should not have to be an array of one.
fn de_addr_or_vec<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<SocketAddr>, D::Error> {
    use serde::Deserialize as _;

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(SocketAddr),
        Many(Vec<SocketAddr>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(a) => vec![a],
        OneOrMany::Many(v) => v,
    })
}

/// How often the egress logs its running totals.
const SUMMARY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Aborts a background task when the owner goes away.
///
/// CLAUDE.md forbids a detached `tokio::spawn` whose handle nobody can cancel; the summary loop is
/// infinite, so it needs an owner that ends it.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn default_bundle_dir() -> PathBuf {
    PathBuf::from("/var/lib/spark-wasm-server/bundles")
}

fn default_magic() -> String {
    "f9beb4d9".to_owned()
}

#[derive(Parser)]
pub struct Serve {
    /// Directory holding installed bundles, as `BundleStore` lays it out.
    #[arg(long)]
    pub bundle_dir: PathBuf,
    /// Engine to serve — the name the bundle was **signed** as.
    #[arg(long)]
    pub engine: String,
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:443")]
    pub listen: SocketAddr,
    /// Hex `init` bytes for the module. Empty for a transform-only module.
    #[arg(long, default_value = "")]
    pub init_config: String,
}

#[derive(Parser)]
pub struct ServeBitcoin {
    #[arg(long)]
    pub bundle_dir: PathBuf,
    /// Engine to serve. Defaults to the canonical BIP324 engine name.
    #[arg(long, default_value = "bip324")]
    pub engine: String,
    /// Address to listen on. Defaults to the Bitcoin P2P port — a node on a different port is a
    /// weaker cover story than one on 8333.
    #[arg(long, default_value = "0.0.0.0:8333")]
    pub listen: SocketAddr,
    /// A real Bitcoin node to proxy non-tunnel connections to. Repeat for a pool.
    ///
    /// Required, and there is no default, because getting it wrong silently destroys the property
    /// this mode exists for: an egress that drops or refuses unrecognized peers is trivially
    /// distinguishable from a Bitcoin node, which is exactly what a prober checks for.
    ///
    /// With several, each peer is mapped to one of them by its own address and always transits that
    /// same node — see [`UpstreamPool`]. A ban then costs 1/N of the cover rather than all of it.
    #[arg(long, required = true)]
    pub upstream: Vec<SocketAddr>,
    /// Per-server side-door secret (`k_srv`), hex. Clients derive their opening tag from the same
    /// value, so this is what pairs a client to this egress — treat it as a secret and give it to
    /// clients through the signed config, never in the clear.
    #[arg(long)]
    pub k_srv: String,
    /// Network magic, hex (4 bytes). Defaults to Bitcoin **mainnet** — the cover is only cover if it
    /// looks like the network real peers are on.
    #[arg(long, default_value = "f9beb4d9")]
    pub magic: String,
}

/// Why the exit failed to start or to serve a connection.
///
/// `thiserror` at this boundary rather than `anyhow` (CLAUDE.md): the binary is one caller, but the
/// integration tests are another, and a test asserting *which* refusal happened — a bad signature
/// versus a bad flag — should not have to match on a formatted string.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    /// The bundle would not verify, install, or load — a wrong key, a tampered artifact, or a
    /// rolled-back version. Refusing here is the point, so it is its own variant.
    #[error("bundle for engine `{engine}`: {source}")]
    Bundle {
        engine: String,
        #[source]
        source: spark_core::transport::engine::store::StoreError,
    },
    #[error("bundle for engine `{0}` carries plans but no module")]
    NoModule(String),
    #[error("compiling module for engine `{engine}`: {source}")]
    Compile {
        engine: String,
        #[source]
        source: spark_core::transport::wasm::WasmError,
    },
    #[error("{flag}: {reason}")]
    BadArgument { flag: &'static str, reason: String },
}

impl ServerError {
    fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> Self {
        let context = context.into();
        move |source| ServerError::Io { context, source }
    }
    fn bad(flag: &'static str, reason: impl Into<String>) -> Self {
        ServerError::BadArgument {
            flag,
            reason: reason.into(),
        }
    }
}

type Result<T> = std::result::Result<T, ServerError>;

/// Decode an even-length hex string. Over bytes, never `&str` slicing: a multi-byte character would
/// otherwise panic mid-codepoint rather than erroring, and these values come from an operator's
/// command line.
fn decode_hex(flag: &'static str, s: &str) -> Result<Vec<u8>> {
    let bytes = s.trim().as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(ServerError::bad(
            flag,
            format!(
                "expected an even number of hex characters, got {}",
                bytes.len()
            ),
        ));
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            (Some(h), Some(l)) => Ok((h << 4) | l),
            _ => Err(ServerError::bad(flag, "invalid hex digit")),
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
    let artifact = std::fs::read(&args.artifact).map_err(ServerError::io(format!(
        "reading {}",
        args.artifact.display()
    )))?;
    let verified = BundleStore::new(&args.bundle_dir)
        .install(&artifact)
        .map_err(|source| ServerError::Bundle {
            engine: args.artifact.display().to_string(),
            source,
        })?;
    info!(
        engine = %verified.engine,
        version = verified.version,
        genomes = verified.genomes.len(),
        dir = %args.bundle_dir.display(),
        "installed a verified bundle"
    );
    Ok(())
}

/// Run from a config file: install the bundle it carries, then serve.
///
/// Installing before listening is deliberate — a bundle that will not verify should stop the process
/// at startup, where the deploy notices, rather than at the first client connection.
pub async fn run(args: Run) -> Result<()> {
    let raw = std::fs::read_to_string(&args.config).map_err(ServerError::io(format!(
        "reading {}",
        args.config.display()
    )))?;
    let cfg: FileConfig = serde_json::from_str(&raw)
        .map_err(|e| ServerError::bad("--config", format!("{}: {e}", args.config.display())))?;

    if !cfg.bundle.is_empty() {
        let artifact = decode_hex("bundle", &cfg.bundle)?;
        let verified = BundleStore::new(&cfg.bundle_dir)
            .install(&artifact)
            .map_err(|source| ServerError::Bundle {
                engine: cfg.engine.clone(),
                source,
            })?;
        // The store keys on the name inside the *signature*, so a config naming one engine while
        // carrying another would install under the signed name and then fail an unrelated-looking
        // "not installed" lookup. Say the real thing.
        if verified.engine != cfg.engine {
            return Err(ServerError::bad(
                "--config",
                format!(
                    "names engine `{}` but the bundle is signed as `{}`",
                    cfg.engine, verified.engine
                ),
            ));
        }
        info!(engine = %verified.engine, version = verified.version, "installed the config's bundle");
    }

    match cfg.mode.as_str() {
        "bitcoin" => {
            serve_bitcoin(ServeBitcoin {
                bundle_dir: cfg.bundle_dir,
                engine: cfg.engine,
                listen: cfg.listen,
                upstream: {
                    if cfg.upstream.is_empty() {
                        return Err(ServerError::bad(
                            "--config",
                            "mode `bitcoin` requires at least one `upstream`",
                        ));
                    }
                    cfg.upstream
                },
                k_srv: cfg.k_srv,
                magic: cfg.magic,
            })
            .await
        }
        "relay" => {
            serve(Serve {
                bundle_dir: cfg.bundle_dir,
                engine: cfg.engine,
                listen: cfg.listen,
                init_config: cfg.init_config,
            })
            .await
        }
        other => Err(ServerError::bad(
            "--config",
            format!("unknown mode `{other}` — expected `bitcoin` or `relay`"),
        )),
    }
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
        .map_err(|source| ServerError::Bundle {
            engine: engine.to_owned(),
            source,
        })?;
    let wasm = verified
        .wasm
        .as_deref()
        .ok_or_else(|| ServerError::NoModule(engine.to_owned()))?;
    let module =
        TransformModule::load_scoped(wasm, verified.capabilities.clone()).map_err(|source| {
            ServerError::Compile {
                engine: engine.to_owned(),
                source,
            }
        })?;
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
    let init = decode_hex("--init-config", &args.init_config)?;
    let server = Arc::new(WasmServer::new(module).with_config(init));

    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(ServerError::io(format!("binding {}", args.listen)))?;
    info!(listen = %args.listen, engine = %args.engine, "serving");
    loop {
        let (conn, peer) = listener
            .accept()
            .await
            .map_err(ServerError::io("accepting"))?;
        let server = Arc::clone(&server);
        // Per-connection failures are logged and dropped, never propagated: one client sending
        // garbage must not take the listener down for everyone else.
        tokio::spawn(async move {
            if let Err(e) = relay_one(&server, conn).await {
                // The peer address is debug-only for the same reason the destination is: a
                // default-level log of who connected is a record of who used the service.
                debug!(%peer, "connection failed");
                warn!(error = %e, "connection failed");
            }
        });
    }
}

/// Deobfuscate one connection, dial the target it announced, and splice the two.
///
/// **Log hygiene** (docs/GOAL.md, non-negotiable): the announced destination never reaches an error
/// or a default-level log. That rule matters more here than anywhere in the client — an exit sees the
/// destination of every user's every flow, so a destination in a `warn!` would make the server's own
/// log the most sensitive artifact in the deployment. The error names what failed; the destination is
/// available at `debug` when someone is actually debugging.
async fn relay_one(server: &WasmServer, conn: TcpStream) -> Result<()> {
    let (target, leftover, wrapped) = server
        .accept(conn)
        .await
        .map_err(ServerError::io("reading the tunnel header"))?;

    // Shared with the splitting egress: a UDP association is dispatched on the sentinel there too,
    // and one implementation is what keeps a protocol addition from reaching one exit and not the
    // other. (It did not, once: the splitter kept dialing TCP for UDP associations.)
    relay_to_target(target, leftover, wrapped)
        .await
        .map_err(ServerError::io("relaying"))
}

pub async fn serve_bitcoin(args: ServeBitcoin) -> Result<()> {
    let module = load_verified(&args.bundle_dir, &args.engine)?;
    let k_srv = decode_hex("--k-srv", &args.k_srv)?;
    if k_srv.is_empty() {
        // An empty key makes the side-door tag publicly recomputable from the ellswift, so every
        // connection would classify as a tunnel client and the Bitcoin cover would be gone.
        return Err(ServerError::bad(
            "--k-srv",
            "must not be empty: an empty side-door key is not a secret",
        ));
    }
    let magic = decode_hex("--magic", &args.magic)?;
    if magic.len() != 4 {
        return Err(ServerError::bad(
            "--magic",
            format!("must be exactly 4 bytes, got {}", magic.len()),
        ));
    }

    // Responder init: [role=1][magic:4][k_srv_len:u16 BE][k_srv][garbage]. The side door is a no-op
    // for a responder — the *splitter* is what checks the tag — so the key is declared empty here
    // rather than handed to the guest, keeping the secret in host memory only.
    let mut init = Vec::with_capacity(7);
    init.push(1u8);
    init.extend_from_slice(&magic);
    init.extend_from_slice(&0u16.to_be_bytes());

    let wasm = WasmServer::new(module).with_config(init);
    let upstream = UpstreamPool::new(args.upstream.iter().copied())
        .map_err(|e| ServerError::bad("--upstream", e.to_string()))?;
    let pool_size = upstream.len();
    let splitter = Arc::new(SplittingServer::new(wasm, k_srv, upstream));

    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(ServerError::io(format!("binding {}", args.listen)))?;
    info!(
        listen = %args.listen,
        upstreams = pool_size,
        engine = %args.engine,
        "serving BIP324 splitting egress"
    );
    // At `info`, with the addresses. These are our own cover infrastructure, not user destinations —
    // docs/GOAL.md's log-hygiene rule protects where *users* go, and an operator cannot tell a
    // degraded exit from a healthy one without knowing which nodes it is actually using.
    for addr in args.upstream.iter() {
        info!(upstream = %addr, "upstream in pool");
    }

    // A periodic roll-up so the shape of the traffic is visible without aggregating per-connection
    // lines: how much of what we serve is tunnel versus cover, and whether untagged peers are being
    // served at all. Held in a JoinHandle rather than detached (CLAUDE.md) and aborted with the loop.
    let telemetry = splitter.telemetry();
    let summary = tokio::spawn(async move {
        let mut tick = tokio::time::interval(SUMMARY_INTERVAL);
        // The first tick fires immediately; skip it so startup does not emit an all-zero line.
        tick.tick().await;
        loop {
            tick.tick().await;
            telemetry.log_summary();
        }
    });
    let _summary = AbortOnDrop(summary);
    loop {
        let (conn, peer) = listener
            .accept()
            .await
            .map_err(ServerError::io("accepting"))?;
        let splitter = Arc::clone(&splitter);
        tokio::spawn(async move {
            // `handle` covers both branches — tunnel and proxy-to-bitcoind — so a failure here says
            // nothing about which one the peer was, and must not be treated as a tunnel error.
            if let Err(e) = splitter.handle(conn, peer.ip()).await {
                debug!(%peer, "connection failed");
                warn!(error = %e, "connection failed");
            }
        });
    }
}
