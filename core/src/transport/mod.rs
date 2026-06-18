//! Tunnel transports: how the proxy core reaches a target.
//!
//! Two surfaces, one per L4 protocol — matching the universal shape in sing-box, Leaf, and
//! the QUIC transports (see the `udp-transport-design-proposal` memory):
//!
//! - [`Transport`] (TCP): "give me a byte stream to this target."
//! - [`UdpTransport`] (UDP): "give me a connected datagram channel to this target," split
//!   into [`PacketSink`]/[`PacketSource`] halves so the send side can live in the netstack
//!   read loop while the recv side runs in a reply pump.
//!
//! The proxy forwarders depend only on the traits, so swapping a direct connection for a
//! tunneled one is a configuration choice, not a code change:
//!
//! - [`DirectTransport`] connects/sends straight to the target (the M2 behavior).
//! - [`tcp_tunnel::client::TunnelClient`] routes through a tunnel server (M3/M4 for TCP, M5
//!   for UDP-over-stream).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use socket2::SockRef;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::config::{AnytlsConfig, Config, WasmConfig};
use crate::net::SocketProtector;
use crate::BoxedStream;

pub mod anytls;
pub mod tcp_tunnel;
/// Path B dynamic transport (ADR 0003): a `wasmi`-hosted byte-transform module, behind the
/// `wasm-transport` feature so the base build carries no WASM runtime.
#[cfg(feature = "wasm-transport")]
pub mod wasm;

/// Connect a TCP stream to `addr`, optionally pinning the socket to a physical interface
/// (so the dial bypasses the tunnel route — see [`SocketProtector`]). Shared by
/// [`DirectTransport`] and the tunnel client (which dials its server).
pub(crate) async fn protected_tcp_connect(
    addr: SocketAddr,
    protector: Option<&SocketProtector>,
) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(p) = protector {
        p.protect(SockRef::from(&socket), addr.is_ipv4())?;
    }
    socket.connect(addr).await
}

/// Build a connected UDP socket to `target`, optionally pinned to a physical interface.
fn protected_udp_socket(
    target: SocketAddr,
    protector: Option<&SocketProtector>,
) -> io::Result<socket2::Socket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if let Some(p) = protector {
        p.protect(SockRef::from(&socket), target.is_ipv4())?;
    }
    let bind = if target.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Build the TCP + UDP transports from `config`: a tunnel client when `transport.server` is
/// set, otherwise direct; both pinned to `transport.protect_interface` when configured.
pub fn from_config(config: &Config) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(SocketProtector::for_interface(name)?),
        None => None,
    };
    // AnyTLS takes precedence over the plain `server` tunnel when configured.
    if let Some(anytls) = &config.transport.anytls {
        return anytls_transport(anytls, protector);
    }
    // The dynamic wasm transport is next in precedence (above the plain `server` tunnel).
    if let Some(wasm) = &config.transport.wasm {
        return wasm_transport(wasm, protector);
    }
    Ok(match config.transport.server {
        Some(server) => {
            let mut client = tcp_tunnel::client::TunnelClient::new(server);
            if let Some(p) = protector {
                client = client.with_socket_protection(p);
            }
            let client = Arc::new(client);
            (
                client.clone() as Arc<dyn Transport>,
                client as Arc<dyn UdpTransport>,
            )
        }
        None => {
            let direct = Arc::new(DirectTransport::new(protector));
            (
                direct.clone() as Arc<dyn Transport>,
                direct as Arc<dyn UdpTransport>,
            )
        }
    })
}

/// Build the AnyTLS transport (feature `anytls`) — TCP and UDP (sing UoT v2) over one session pool.
#[cfg(feature = "anytls")]
fn anytls_transport(
    cfg: &AnytlsConfig,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let sni = cfg
        .sni
        .clone()
        .unwrap_or_else(|| cfg.server.ip().to_string());
    // One transport serves both TCP and UDP (UoT v2), sharing the session pool.
    let t = Arc::new(anytls::AnytlsTransport::new(
        cfg.server,
        cfg.password.clone(),
        sni,
        protector,
    ));
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `anytls` feature, a configured AnyTLS transport is a hard error rather than a silent
/// fallback (the user asked for AnyTLS but the binary can't provide it).
#[cfg(not(feature = "anytls"))]
fn anytls_transport(
    _cfg: &AnytlsConfig,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.anytls is configured but spark was built without the `anytls` feature",
    ))
}

/// Build the dynamic wasm transport (feature `wasm-transport`): read the signed module artifact,
/// verify it against the pinned key and the (config + persisted) anti-rollback floor, then build a
/// [`wasm::WasmTransport`] (which serves both TCP and UDP) delivering any `init` config.
#[cfg(feature = "wasm-transport")]
fn wasm_transport(
    cfg: &WasmConfig,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let key: [u8; 32] = decode_hex(&cfg.public_key)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| io::Error::other("transport.wasm.public_key must be 32 bytes of hex"))?;
    let init_config = match &cfg.init_config {
        Some(hex) => decode_hex(hex)
            .ok_or_else(|| io::Error::other("transport.wasm.init_config invalid hex"))?,
        None => Vec::new(),
    };
    let artifact = std::fs::read(&cfg.module).map_err(|e| {
        io::Error::other(format!(
            "transport.wasm: reading module {}: {e}",
            cfg.module.display()
        ))
    })?;

    // Authenticate first (this also enforces the config floor); the name is trusted only afterwards.
    let signed = wasm::ModuleVerifier::new(key)
        .verify(&artifact, cfg.min_version)
        .map_err(|e| io::Error::other(format!("transport.wasm: {e}")))?;

    // Persisted per-name floor: a second anti-rollback gate that survives restarts.
    if let Some(path) = &cfg.floor_path {
        let floor = wasm_floor::get(path, signed.name())?;
        if signed.version() < floor {
            return Err(io::Error::other(format!(
                "transport.wasm: module `{}` v{} is below the persisted floor v{}",
                signed.name(),
                signed.version(),
                floor
            )));
        }
        wasm_floor::bump(path, signed.name(), signed.version())?;
    }

    let mut t = wasm::WasmTransport::new(cfg.server, signed.into_module()).with_config(init_config);
    if let Some(p) = protector {
        t = t.with_socket_protection(p);
    }
    let t = Arc::new(t);
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `wasm-transport` feature, a configured wasm transport is a hard error (mirroring
/// AnyTLS) rather than a silent fallback.
#[cfg(not(feature = "wasm-transport"))]
fn wasm_transport(
    _cfg: &WasmConfig,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.wasm is configured but spark was built without the `wasm-transport` feature",
    ))
}

/// Decode an even-length hex string into bytes (no `hex` crate dependency).
#[cfg(feature = "wasm-transport")]
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// A persisted per-module version floor (a TOML `name = version` map) for anti-rollback across
/// restarts. A missing file is an empty floor.
#[cfg(feature = "wasm-transport")]
mod wasm_floor {
    use std::collections::BTreeMap;
    use std::io;
    use std::path::Path;

    /// The recorded floor for `name`, or `0` if none.
    pub fn get(path: &Path, name: &str) -> io::Result<u32> {
        Ok(read(path)?.get(name).copied().unwrap_or(0))
    }

    /// Raise the recorded floor for `name` to `version` (never lowers it).
    pub fn bump(path: &Path, name: &str, version: u32) -> io::Result<()> {
        let mut map = read(path)?;
        let entry = map.entry(name.to_string()).or_insert(0);
        *entry = (*entry).max(version);
        let toml = toml::to_string(&map).map_err(io::Error::other)?;
        std::fs::write(path, toml)
    }

    fn read(path: &Path) -> io::Result<BTreeMap<String, u32>> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e),
        }
    }
}

/// A way to obtain a bidirectional byte stream to a target address.
///
/// The target is a [`SocketAddr`] because that is what the netstack surfaces (the original
/// destination an application dialed). A transport that addresses targets by name resolves
/// or forwards the name itself.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Open a stream to `target`. The returned stream relays application bytes
    /// transparently in both directions.
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream>;
}

/// The send half of a connected UDP association: datagrams to the negotiated target.
#[async_trait]
pub trait PacketSink: Send {
    /// Send one datagram to the association's target.
    async fn send(&mut self, payload: &[u8]) -> io::Result<()>;
}

/// The receive half of a connected UDP association: datagrams from the negotiated target.
#[async_trait]
pub trait PacketSource: Send {
    /// Receive one datagram into `buf`, returning its length. If `buf` is shorter than the
    /// datagram the excess is dropped (UDP truncation semantics), but the whole datagram is
    /// still consumed so a stream-backed source stays frame-aligned.
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// Boxed [`PacketSink`].
pub type BoxedPacketSink = Box<dyn PacketSink>;
/// Boxed [`PacketSource`].
pub type BoxedPacketSource = Box<dyn PacketSource>;

/// A way to obtain a connected UDP datagram channel to a target.
///
/// Returns the send/recv halves already split (rather than one `&self` object) because a
/// stream-backed implementation can't offer `&self` writes without holding a lock across an
/// `.await`. The split lets the netstack read loop own the sink (`&mut`) while a per-flow
/// reply pump owns the source.
#[async_trait]
pub trait UdpTransport: Send + Sync {
    /// Open a connected UDP association to `target`, returning its split halves.
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)>;
}

/// Connects/sends straight to the target with no tunnel — the direct behavior, expressed as
/// both a [`Transport`] (TCP) and a [`UdpTransport`] (UDP). An optional [`SocketProtector`]
/// pins its dials to a physical interface so they bypass the tunnel route.
#[derive(Default)]
pub struct DirectTransport {
    protector: Option<SocketProtector>,
}

impl DirectTransport {
    /// A direct transport, optionally pinning outbound sockets to a physical interface.
    pub fn new(protector: Option<SocketProtector>) -> Self {
        Self { protector }
    }
}

#[async_trait]
impl Transport for DirectTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let stream = protected_tcp_connect(target, self.protector.as_ref()).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl UdpTransport for DirectTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // Build an ephemeral socket (pinned to the protected interface if any), then
        // `connect` so send/recv talk only to `target`.
        let socket = protected_udp_socket(target, self.protector.as_ref())?;
        let socket = UdpSocket::from_std(socket.into())?;
        socket.connect(target).await?;
        let socket = Arc::new(socket);
        Ok((
            Box::new(DirectPacketSink(Arc::clone(&socket))),
            Box::new(DirectPacketSource(socket)),
        ))
    }
}

/// Send half over a connected [`UdpSocket`] (shared via `Arc`; tokio's UDP send/recv take
/// `&self`, so no lock is needed).
struct DirectPacketSink(Arc<UdpSocket>);

#[async_trait]
impl PacketSink for DirectPacketSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.0.send(payload).await.map(|_| ())
    }
}

/// Receive half over the same connected [`UdpSocket`].
struct DirectPacketSource(Arc<UdpSocket>);

#[async_trait]
impl PacketSource for DirectPacketSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }
}

#[cfg(all(test, feature = "wasm-transport"))]
mod wasm_config_tests {
    use super::*;
    use crate::config::{Config, TransportConfig, WasmConfig};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key")
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Sign the XOR fixture as `(name, version)` and return the artifact bytes.
    fn xor_artifact(kp: &Ed25519KeyPair, name: &str, version: u32) -> Vec<u8> {
        let wasm = wat::parse_str(wasm::testutil::XOR_WAT).expect("assemble fixture");
        let sig = kp.sign(&wasm::signing_payload(name, version, &wasm));
        let mut s = [0u8; 64];
        s.copy_from_slice(sig.as_ref());
        wasm::build_artifact(name, version, &wasm, &s)
    }

    /// A unique temp path (process id + a counter), so parallel tests don't collide.
    fn temp_path(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "spark-wasm-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn config_with(wasm: WasmConfig) -> Config {
        Config {
            transport: TransportConfig {
                wasm: Some(wasm),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn base_cfg(module: std::path::PathBuf, public_key: String, min_version: u32) -> WasmConfig {
        WasmConfig {
            server: "192.0.2.1:443".parse().unwrap(),
            module,
            public_key,
            min_version,
            init_config: None,
            floor_path: None,
        }
    }

    #[test]
    fn from_config_builds_a_verified_wasm_transport() {
        let kp = keypair();
        let path = temp_path("ok");
        std::fs::write(&path, xor_artifact(&kp, "obfs", 5)).expect("write artifact");
        let cfg = config_with(base_cfg(path.clone(), to_hex(kp.public_key().as_ref()), 0));
        // Builds a transport (which serves both TCP and UDP) from the verified module.
        from_config(&cfg).expect("from_config should build the wasm transport");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_rejects_a_rollback() {
        let kp = keypair();
        let path = temp_path("rollback");
        std::fs::write(&path, xor_artifact(&kp, "obfs", 3)).expect("write artifact");
        // Config floor 5 is above the artifact's version 3.
        let cfg = config_with(base_cfg(path.clone(), to_hex(kp.public_key().as_ref()), 5));
        assert!(from_config(&cfg).is_err(), "a rollback must be rejected");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_rejects_a_wrong_pinned_key() {
        let signer = keypair();
        let attacker = keypair();
        let path = temp_path("wrongkey");
        std::fs::write(&path, xor_artifact(&signer, "obfs", 1)).expect("write artifact");
        let cfg = config_with(base_cfg(
            path.clone(),
            to_hex(attacker.public_key().as_ref()),
            0,
        ));
        assert!(
            from_config(&cfg).is_err(),
            "a wrong pinned key must be rejected"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn persisted_floor_is_enforced_and_bumped() {
        let kp = keypair();
        let pubkey = to_hex(kp.public_key().as_ref());
        let floor_path = temp_path("floor");

        // Installing v5 succeeds and bumps the persisted floor to 5.
        let p5 = temp_path("art5");
        std::fs::write(&p5, xor_artifact(&kp, "obfs", 5)).expect("write");
        let mut cfg5 = base_cfg(p5.clone(), pubkey.clone(), 0);
        cfg5.floor_path = Some(floor_path.clone());
        from_config(&config_with(cfg5)).expect("v5 installs");

        // A v4 artifact now clears the config floor (0) but not the persisted floor (5).
        let p4 = temp_path("art4");
        std::fs::write(&p4, xor_artifact(&kp, "obfs", 4)).expect("write");
        let mut cfg4 = base_cfg(p4.clone(), pubkey, 0);
        cfg4.floor_path = Some(floor_path.clone());
        assert!(
            from_config(&config_with(cfg4)).is_err(),
            "the persisted floor must reject the older version"
        );

        std::fs::remove_file(&p5).ok();
        std::fs::remove_file(&p4).ok();
        std::fs::remove_file(&floor_path).ok();
    }
}
