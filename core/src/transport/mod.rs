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

use crate::config::{AnytlsConfig, Config, SamizdatConfig, WasmConfig};
use crate::net::SocketProtector;
use crate::BoxedStream;
use flint_shaping::{DelaySpec, SegmentSplit, WirePlan};

/// Build a [`WirePlan`] from the static `[transport.shaping]` config. flint's `WirePlan` is
/// config-agnostic, so this adapter (the public replacement for the former `WirePlan::from_config`)
/// lives spark-side. Maps Layer C only; Layer B `record_fragment` defaults off.
pub fn wire_plan_from_config(c: &crate::config::ShapingConfig) -> WirePlan {
    let segment_split = match c.segment_split.trim() {
        "" | "none" => SegmentSplit::None,
        "sni_boundary" => SegmentSplit::SniBoundary,
        list => SegmentSplit::Explicit(
            list.split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect(),
        ),
    };
    WirePlan {
        segment_split,
        inter_segment_delay: c.delay_ms.map_or(DelaySpec::None, |ms| {
            DelaySpec::Fixed(std::time::Duration::from_millis(ms))
        }),
        tcp_nodelay: c.tcp_nodelay,
        ..Default::default()
    }
}

/// Back-compat shim: the wire-shaping primitives now live in the `flint-shaping` crate. This keeps
/// the `crate::transport::shaping::{WirePlan, SegmentSplit, DelaySpec, SegmentShapingStream, …}`
/// paths working; the former `WirePlan::from_config` is now [`wire_plan_from_config`].
pub use flint_shaping as shaping;

/// Back-compat shim: the gambit ClientHello genome and JA4 fingerprinting now live in the `flint-tls`
/// crate. Keeps the `crate::transport::{gambit, ja4}::…` import paths working.
pub use flint_tls::{gambit, ja4};

pub mod anytls;
/// The discovery harness inner loop (ADR 0006 P5, design §5.2): GA mutation/crossover over the
/// genome + a boring-realized JA4 fidelity score vs the anchor. The full loop is server-side.
pub mod discovery;
pub mod probe;
/// Samizdat transport (ADR 0007): REALITY-style auth in the TLS `legacy_session_id` + H2 CONNECT
/// mux, wire-interoperable with deployed lantern-box `"samizdat"` servers. Behind the `samizdat`
/// feature so the base build pulls neither the boring TLS backend nor the `h2` dependency.
#[cfg(feature = "samizdat")]
pub mod samizdat;
/// Latency-selecting transport over a multi-server pool (design: docs/multi-server-selection-design.md).
/// Gated behind `multi-server` so the base build pulls no `flint-dial` dependency.
#[cfg(feature = "multi-server")]
pub mod select;
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

/// Build one server entry's transport pair from its [`ServerSpec`]. The single seam for transport
/// kinds — adding a kind is a new `ServerSpec` variant + a match arm here. `protector` is cloned per
/// entry (it is `Clone`); `wire` is the shared opening-shaping plan. Only the multi-server pool path
/// (`build_selecting`) uses this, so it's gated to keep the base build free of dead code.
#[cfg(feature = "multi-server")]
pub(crate) fn build_one(
    spec: &crate::config::ServerSpec,
    protector: Option<&SocketProtector>,
    wire: &WirePlan,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    use crate::config::ServerSpec;
    match spec {
        ServerSpec::Anytls(cfg) => anytls_transport(cfg, protector.cloned(), wire.clone()),
        ServerSpec::Samizdat(cfg) => samizdat_transport(cfg, protector.cloned(), wire.clone()),
        ServerSpec::Wasm(cfg) => wasm_transport(cfg, protector.cloned()),
        ServerSpec::Tunnel(cfg) => {
            let server = cfg.server.socket_addr()?;
            let mut client = tcp_tunnel::client::TunnelClient::new(server);
            if let Some(p) = protector.cloned() {
                client = client.with_socket_protection(p);
            }
            let client = Arc::new(client);
            Ok((
                client.clone() as Arc<dyn Transport>,
                client as Arc<dyn UdpTransport>,
            ))
        }
    }
}

/// Build a `SelectingTransport` over `config.transport.servers`. Each entry's callback URL is its
/// per-entry override or the global `transport.callback_url`; the pool needs at least one callback.
#[cfg(feature = "multi-server")]
fn build_selecting(
    config: &Config,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    use crate::transport::probe::CallbackUrl;
    use crate::transport::select::{Member, SelectingTransport, ServerMeta};
    let wire = wire_plan_from_config(&config.transport.shaping);
    let mut members = Vec::with_capacity(config.transport.servers.len());
    for entry in &config.transport.servers {
        let raw = entry
            .callback_url
            .as_deref()
            .or(config.transport.callback_url.as_deref())
            .ok_or_else(|| {
                io::Error::other("transport.servers requires a callback_url (global or per-entry)")
            })?;
        let callback = CallbackUrl::parse(raw)?;
        if callback.tls && !cfg!(feature = "anytls") {
            return Err(io::Error::other(format!(
                "https callback `{raw}` requires the `anytls` feature (TLS backend); use an http:// callback or build with anytls"
            )));
        }
        let (transport, udp) = build_one(&entry.spec, protector.as_ref(), &wire)?;
        let meta = ServerMeta {
            name: entry.name.clone(),
            country: entry.country.clone(),
            country_code: entry.country_code.clone(),
            city: entry.city.clone(),
        };
        members.push(Member::new(transport, udp, callback, meta));
    }
    // Fail-open fallback (issue #11): when the whole pool is unhealthy the selecting transport dials
    // directly instead of blackholing. Built with the same protector as the members, so the direct
    // dial bypasses the tunnel route just like a pool member would.
    let direct = Arc::new(DirectTransport::new(protector));
    let st = Arc::new(SelectingTransport::new(
        members,
        std::time::Duration::from_secs(config.transport.probe_interval_secs),
        config.transport.probe_window,
        direct.clone() as Arc<dyn Transport>,
        direct as Arc<dyn UdpTransport>,
    ));
    Ok((
        st.clone() as Arc<dyn Transport>,
        st as Arc<dyn UdpTransport>,
    ))
}

#[cfg(not(feature = "multi-server"))]
fn build_selecting(
    _config: &Config,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.servers is configured but spark was built without the `multi-server` feature",
    ))
}

/// Build the TCP + UDP transports from `config`: a tunnel client when `transport.server` is
/// set, otherwise direct; both pinned to `transport.protect_interface` when configured.
pub fn from_config(config: &Config) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(SocketProtector::for_interface(name)?),
        None => None,
    };
    // A configured server pool supersedes the single-transport fields: build a latency-selecting
    // transport over it.
    if !config.transport.servers.is_empty() {
        return build_selecting(config, protector);
    }
    // AnyTLS takes precedence over the plain `server` tunnel when configured.
    if let Some(anytls) = &config.transport.anytls {
        let wire = wire_plan_from_config(&config.transport.shaping);
        return anytls_transport(anytls, protector, wire);
    }
    // Samizdat (ADR 0007) — like AnyTLS, takes precedence over the plain `server` tunnel. It reuses
    // the shared `[transport.shaping]` plan to fragment the ClientHello (Geneva-style, on by default
    // in the Go client).
    if let Some(samizdat) = &config.transport.samizdat {
        let wire = wire_plan_from_config(&config.transport.shaping);
        return samizdat_transport(samizdat, protector, wire);
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
    wire: WirePlan,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let server = cfg.server.socket_addr()?;
    let sni = cfg.sni.clone().unwrap_or_else(|| server.ip().to_string());
    // Resolve the inline gambit genome (Layers A/B) onto the boring executor (ADR 0006 P2). Knobs
    // boring2 can't realize are surfaced once here, never silently dropped. This is also the fallback
    // profile when a dynamic gambit module (P3, below) faults or over-reaches.
    let resolved = flint_tls::Profile::resolve(&cfg.clienthello, &cfg.records);
    for note in &resolved.unrealizable {
        tracing::warn!(knob = note, "anytls gambit knob not realizable on boring");
    }
    let profile = resolved.profile;

    // P3: an optional signed Path-B module that computes a fresh gambit per connection.
    #[cfg(feature = "wasm-transport")]
    if let Some(gcfg) = &cfg.gambit {
        let gambit = load_gambit_module(gcfg)?;
        let t = Arc::new(anytls::AnytlsTransport::with_dynamic_gambit(
            server,
            cfg.password.clone(),
            sni,
            protector,
            wire,
            profile,
            gambit,
        ));
        return Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>));
    }
    #[cfg(not(feature = "wasm-transport"))]
    if cfg.gambit.is_some() {
        return Err(io::Error::other(
            "transport.anytls.gambit is configured but spark was built without the `wasm-transport` feature",
        ));
    }

    // One transport serves both TCP and UDP (UoT v2), sharing the session pool.
    let t = Arc::new(anytls::AnytlsTransport::new(
        server,
        cfg.password.clone(),
        sni,
        protector,
        wire,
        profile,
    ));
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Read, verify (pinned key + config & persisted anti-rollback floors, exactly like
/// [`wasm_transport`]), and instantiate a Path-B gambit-compute module (ADR 0006 P3). The module is
/// the trust root; its computed gambits are gated per-connection by `Profile::for_boring`.
#[cfg(all(feature = "anytls", feature = "wasm-transport"))]
fn load_gambit_module(cfg: &crate::config::GambitModuleConfig) -> io::Result<wasm::Transform> {
    let artifact = std::fs::read(&cfg.module).map_err(|e| {
        io::Error::other(format!(
            "transport.anytls.gambit: reading module {}: {e}",
            cfg.module.display()
        ))
    })?;
    let signed = wasm::ModuleVerifier::pinned()
        .verify(&artifact, cfg.min_version)
        .map_err(|e| io::Error::other(format!("transport.anytls.gambit: {e}")))?;
    // Persisted per-name floor: a second anti-rollback gate that survives restarts.
    if let Some(path) = &cfg.floor_path {
        let floor = wasm_floor::get(path, signed.name())?;
        if signed.version() < floor {
            return Err(io::Error::other(format!(
                "transport.anytls.gambit: module `{}` v{} is below the persisted floor v{}",
                signed.name(),
                signed.version(),
                floor
            )));
        }
        wasm_floor::bump(path, signed.name(), signed.version())?;
    }
    signed
        .into_module()
        .instantiate()
        .map_err(|e| io::Error::other(format!("transport.anytls.gambit: instantiate: {e}")))
}

/// Without the `anytls` feature, a configured AnyTLS transport is a hard error rather than a silent
/// fallback (the user asked for AnyTLS but the binary can't provide it).
#[cfg(not(feature = "anytls"))]
fn anytls_transport(
    _cfg: &AnytlsConfig,
    _protector: Option<SocketProtector>,
    _wire: WirePlan,
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

    // Verify against the key pinned in the binary (not config), authenticating before the module
    // name is trusted; this also enforces the config anti-rollback floor.
    let signed = wasm::ModuleVerifier::pinned()
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

/// Build the Samizdat transport (feature `samizdat`): decode the pinned server public key + short
/// ID, then a [`samizdat::SamizdatTransport`] (TCP only; its `UdpTransport` reports unsupported).
#[cfg(feature = "samizdat")]
fn samizdat_transport(
    cfg: &SamizdatConfig,
    protector: Option<SocketProtector>,
    wire: WirePlan,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let server_pubkey = decode_hex_n::<32>(&cfg.server_pubkey)
        .ok_or_else(|| io::Error::other("transport.samizdat.server_pubkey must be 32-byte hex"))?;
    let short_id = decode_hex_n::<8>(&cfg.short_id)
        .ok_or_else(|| io::Error::other("transport.samizdat.short_id must be 8-byte hex"))?;
    let server = cfg.server.socket_addr()?;
    let sni = cfg.sni.clone().unwrap_or_else(|| server.ip().to_string());
    let t = Arc::new(samizdat::SamizdatTransport::new(
        server,
        server_pubkey,
        short_id,
        sni,
        wire,
        protector,
    ));
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `samizdat` feature, a configured Samizdat transport is a hard error (mirroring
/// AnyTLS/wasm) rather than a silent fallback.
#[cfg(not(feature = "samizdat"))]
fn samizdat_transport(
    _cfg: &SamizdatConfig,
    _protector: Option<SocketProtector>,
    _wire: WirePlan,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.samizdat is configured but spark was built without the `samizdat` feature",
    ))
}

/// Decode an even-length hex string into exactly `N` bytes (`None` on wrong length or non-hex).
#[cfg(feature = "samizdat")]
fn decode_hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
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
    use ring::signature::Ed25519KeyPair;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wasm::testutil::dev_keypair;

    fn random_keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key")
    }

    /// Sign the XOR fixture as `(name, version)` with `kp` and return the artifact bytes.
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

    fn base_cfg(module: std::path::PathBuf, min_version: u32) -> WasmConfig {
        WasmConfig {
            server: "192.0.2.1:443".parse().unwrap(),
            module,
            min_version,
            init_config: None,
            floor_path: None,
        }
    }

    #[test]
    fn from_config_builds_a_verified_wasm_transport() {
        // Signed by the dev key the binary pins (ModuleVerifier::pinned), so it verifies.
        let path = temp_path("ok");
        std::fs::write(&path, xor_artifact(&dev_keypair(), "obfs", 5)).expect("write artifact");
        let cfg = config_with(base_cfg(path.clone(), 0));
        from_config(&cfg).expect("from_config should build the wasm transport");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_rejects_a_rollback() {
        let path = temp_path("rollback");
        std::fs::write(&path, xor_artifact(&dev_keypair(), "obfs", 3)).expect("write artifact");
        // Config floor 5 is above the artifact's version 3.
        let cfg = config_with(base_cfg(path.clone(), 5));
        assert!(from_config(&cfg).is_err(), "a rollback must be rejected");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_rejects_a_module_not_signed_by_the_pinned_key() {
        // Signed by a random key, not the pinned one, so verification fails.
        let path = temp_path("wrongkey");
        std::fs::write(&path, xor_artifact(&random_keypair(), "obfs", 1)).expect("write artifact");
        let cfg = config_with(base_cfg(path.clone(), 0));
        assert!(
            from_config(&cfg).is_err(),
            "a module not signed by the pinned key must be rejected"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn persisted_floor_is_enforced_and_bumped() {
        let floor_path = temp_path("floor");

        // Installing v5 succeeds and bumps the persisted floor to 5.
        let p5 = temp_path("art5");
        std::fs::write(&p5, xor_artifact(&dev_keypair(), "obfs", 5)).expect("write");
        let mut cfg5 = base_cfg(p5.clone(), 0);
        cfg5.floor_path = Some(floor_path.clone());
        from_config(&config_with(cfg5)).expect("v5 installs");

        // A v4 artifact now clears the config floor (0) but not the persisted floor (5).
        let p4 = temp_path("art4");
        std::fs::write(&p4, xor_artifact(&dev_keypair(), "obfs", 4)).expect("write");
        let mut cfg4 = base_cfg(p4.clone(), 0);
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

/// Samizdat config wiring (ADR 0007): `from_config` builds the transport and validates the
/// hex-encoded server public key + short ID.
#[cfg(all(test, feature = "samizdat"))]
mod samizdat_config_tests {
    use super::*;
    use crate::config::{Config, SamizdatConfig, TransportConfig};

    fn config_with(server_pubkey: &str, short_id: &str) -> Config {
        Config {
            transport: TransportConfig {
                samizdat: Some(SamizdatConfig {
                    server: "192.0.2.1:443".parse().unwrap(),
                    server_pubkey: server_pubkey.to_owned(),
                    short_id: short_id.to_owned(),
                    sni: Some("cover.example".to_owned()),
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn builds_a_samizdat_transport() {
        // 32-byte pubkey + 8-byte short id, valid hex.
        from_config(&config_with(&"a0".repeat(32), &"10".repeat(8)))
            .expect("from_config should build the samizdat transport");
    }

    #[test]
    fn rejects_a_wrong_length_server_pubkey() {
        assert!(from_config(&config_with(&"a0".repeat(31), &"10".repeat(8))).is_err());
    }

    #[test]
    fn rejects_a_wrong_length_short_id() {
        assert!(from_config(&config_with(&"a0".repeat(32), &"10".repeat(4))).is_err());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(from_config(&config_with(&"zz".repeat(32), &"10".repeat(8))).is_err());
    }
}

#[cfg(all(test, feature = "multi-server"))]
mod pool_config_tests {
    use super::*;
    use crate::config::{Config, ServerEntry, ServerSpec, TransportConfig, TunnelConfig};

    #[tokio::test]
    async fn from_config_builds_a_selecting_transport_for_a_pool() {
        let cfg = Config {
            transport: TransportConfig {
                servers: vec![ServerEntry {
                    spec: ServerSpec::Tunnel(TunnelConfig {
                        server: "1.2.3.4:443".parse().unwrap(),
                        sni: None,
                    }),
                    callback_url: None,
                    name: None,
                    country: None,
                    country_code: None,
                    city: None,
                }],
                callback_url: Some("http://127.0.0.1:80/ok".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        from_config(&cfg).expect("from_config should build the selecting transport");
    }

    #[cfg(not(feature = "anytls"))]
    #[tokio::test]
    async fn https_callback_without_anytls_is_a_clear_error() {
        let cfg = Config {
            transport: TransportConfig {
                servers: vec![ServerEntry {
                    spec: ServerSpec::Tunnel(TunnelConfig {
                        server: "1.2.3.4:443".parse().unwrap(),
                        sni: None,
                    }),
                    callback_url: None,
                    name: None,
                    country: None,
                    country_code: None,
                    city: None,
                }],
                callback_url: Some("https://canary.example/x".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = from_config(&cfg)
            .err()
            .expect("https callback without anytls must error");
        assert!(err.to_string().contains("anytls"), "error was: {err}");
    }

    #[tokio::test]
    async fn pool_without_callback_url_is_an_error() {
        let cfg = Config {
            transport: TransportConfig {
                servers: vec![ServerEntry {
                    spec: ServerSpec::Tunnel(TunnelConfig {
                        server: "1.2.3.4:443".parse().unwrap(),
                        sni: None,
                    }),
                    callback_url: None,
                    name: None,
                    country: None,
                    country_code: None,
                    city: None,
                }],
                callback_url: None,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(from_config(&cfg).is_err());
    }
}

/// AnyTLS + dynamic-gambit config wiring (ADR 0006 P3): a signed Path-B gambit module loaded via
/// `[transport.anytls.gambit]` and attached to the AnyTLS transport.
#[cfg(all(test, feature = "anytls", feature = "wasm-transport"))]
mod anytls_gambit_config_tests {
    use super::*;
    use crate::config::{AnytlsConfig, Config, GambitModuleConfig, TransportConfig};
    use flint_tls::gambit::Gambit;
    use ring::signature::Ed25519KeyPair;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wasm::testutil::dev_keypair;

    /// A signed gambit-compute module: `memory` + `alloc` + a `compute_gambit` that returns the
    /// postcard encoding of a minimal constrained gambit held in a data segment.
    fn gambit_artifact(kp: &Ed25519KeyPair, name: &str, version: u32) -> Vec<u8> {
        let g = Gambit {
            genome_version: 1,
            version: 1,
            id: "g".into(),
            anchor: Default::default(),
            clienthello: Default::default(),
            records: Default::default(),
            wire: Default::default(),
            requires: vec![],
        };
        let bytes = postcard::to_stdvec(&g).expect("encode gambit");
        let escaped: String = bytes.iter().map(|b| format!("\\{b:02x}")).collect();
        let wat = format!(
            r#"(module
  (memory (export "memory") 2)
  (data (i32.const 2048) "{escaped}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "compute_gambit") (param i32 i32) (result i64)
    (i64.or (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
            (i64.extend_i32_u (i32.const {len})))))"#,
            len = bytes.len()
        );
        let wasm = wat::parse_str(&wat).expect("assemble");
        let sig = kp.sign(&wasm::signing_payload(name, version, &wasm));
        let mut s = [0u8; 64];
        s.copy_from_slice(sig.as_ref());
        wasm::build_artifact(name, version, &wasm, &s)
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "spark-gambit-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn cfg_with(gambit: GambitModuleConfig) -> Config {
        Config {
            transport: TransportConfig {
                anytls: Some(AnytlsConfig {
                    server: "192.0.2.1:443".parse().unwrap(),
                    password: "pw".into(),
                    sni: None,
                    clienthello: Default::default(),
                    records: Default::default(),
                    gambit: Some(gambit),
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn from_config_attaches_a_verified_dynamic_gambit() {
        let path = temp_path("ok");
        std::fs::write(&path, gambit_artifact(&dev_keypair(), "opening", 2)).expect("write");
        let cfg = cfg_with(GambitModuleConfig {
            module: path.clone(),
            min_version: 0,
            floor_path: None,
        });
        // Builds within a runtime (the transport spawns its idle sweep).
        from_config(&cfg).expect("from_config should attach the dynamic gambit");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn from_config_rejects_a_gambit_module_rollback() {
        let path = temp_path("rollback");
        std::fs::write(&path, gambit_artifact(&dev_keypair(), "opening", 2)).expect("write");
        // Config floor 5 is above the artifact's version 2 → verification must fail.
        let cfg = cfg_with(GambitModuleConfig {
            module: path.clone(),
            min_version: 5,
            floor_path: None,
        });
        assert!(
            from_config(&cfg).is_err(),
            "a gambit-module rollback must be rejected"
        );
        std::fs::remove_file(&path).ok();
    }
}
