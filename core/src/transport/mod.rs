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

use crate::config::{
    AnytlsConfig, Config, DnsTunnelConfig, FrontedMeekConfig, Hysteria2Config, SamizdatConfig,
    ShadowsocksConfig, WasmConfig,
};
// Only the cipher-mapping helper (feature-gated) needs this; keep it out of the base build.
#[cfg(feature = "dns-tunnel")]
use crate::config::DnsTunnelCipher;
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
/// DNS-tunnel transport (ADR 0011): a clean-slate DNS-tunnelling protocol that aggregates over many
/// recursive resolvers. Behind the `dns-tunnel` feature so the base build pulls neither
/// `dns-tunnel-core` nor its `lz4_flex`.
#[cfg(feature = "dns-tunnel")]
pub mod dns_tunnel;
/// Domain-fronted meek polling transport (Shir-o-Khorshid CDN-fronting, no MITM).
/// Behind the `fronted-meek` feature so the base build pulls neither flint-fronted
/// nor its boring dial path. See docs/fronted-meek-design.md.
#[cfg(feature = "fronted-meek")]
pub mod fronted_meek;
/// Hysteria 2 transport (ADR 0010): a QUIC client (quinn/rustls-ring) interoperable with deployed
/// apernet/hysteria servers, with Salamander+Gecko obfuscation. Behind the `hysteria2` feature so the
/// base build pulls no QUIC stack.
#[cfg(feature = "hysteria2")]
pub mod hysteria2;
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
/// Shadowsocks 2022 transport (ADR 0009): a pre-shared-key AEAD tunnel interoperable with deployed
/// shadowsocks-rust servers. Behind the `shadowsocks` feature so the base build pulls neither
/// `blake3` nor `aes`.
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
pub mod tcp_tunnel;

/// A dial target that may be an unresolved domain: the fake-IP proxy path recovers a domain from a
/// flow's fake IP and dials it by name so the exit resolves (no client DNS). Re-exported from the
/// tunnel header, which already encodes it on the wire.
pub use tcp_tunnel::header::Address;
/// UDP-over-TCP v2 (sing-box UoT) framing, shared by the stream transports that tunnel UDP over a
/// reliable stream (AnyTLS, Samizdat). Gated on those transports so the base build pulls no UoT code.
#[cfg(any(feature = "anytls", feature = "samizdat"))]
pub(crate) mod uot;
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

/// Build a bound, nonblocking UDP socket, optionally pinned to a physical interface (so its traffic
/// bypasses the tunnel route). `target` only selects the address family for the bind; the caller
/// `connect`s it to the destination afterward.
pub(crate) fn protected_udp_socket(
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
        ServerSpec::Shadowsocks(cfg) => shadowsocks_transport(cfg, protector.cloned()),
        ServerSpec::Hysteria2(cfg) => hysteria2_transport(cfg, protector.cloned()),
        ServerSpec::DnsTunnel(cfg) => dns_tunnel_transport(cfg, protector.cloned()),
        ServerSpec::FrontedMeek(cfg) => fronted_meek_transport(cfg),
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

/// Build one pool [`Member`] (callback + transport) from a [`ServerEntry`], or an error describing why
/// it can't be built: a missing callback, an https callback without the `anytls` TLS backend, or a
/// transport whose feature isn't compiled in. `build_selecting` skips members that error so one
/// un-buildable entry doesn't sink the whole pool.
#[cfg(feature = "multi-server")]
fn build_member(
    entry: &crate::config::ServerEntry,
    config: &Config,
    protector: Option<&SocketProtector>,
    wire: &WirePlan,
) -> io::Result<crate::transport::select::Member> {
    use crate::transport::probe::CallbackUrl;
    use crate::transport::select::Member;
    let raw = entry
        .callback_url
        .as_deref()
        .or(config.transport.callback_url.as_deref())
        .ok_or_else(|| io::Error::other("requires a callback_url (global or per-entry)"))?;
    let callback = CallbackUrl::parse(raw)?;
    if callback.tls && !cfg!(feature = "anytls") {
        return Err(io::Error::other(format!(
            "https callback `{raw}` requires the `anytls` feature (TLS backend); use an http:// callback or build with anytls"
        )));
    }
    let (transport, udp) = build_one(&entry.spec, protector, wire)?;
    let meta = ServerMeta {
        name: entry.name.clone(),
        country: entry.country.clone(),
        country_code: entry.country_code.clone(),
        city: entry.city.clone(),
    };
    Ok(Member::new(transport, udp, callback, meta)
        .with_label(spec_label(&entry.spec))
        .with_protocol(spec_kind(&entry.spec).to_string()))
}

/// The bare protocol kind for a spec, e.g. `"hysteria2"` — surfaced to the UI as a per-member
/// subtitle. (`spec_label` is the same kind plus the server address, for diagnostic logs.)
#[cfg(feature = "multi-server")]
fn spec_kind(spec: &crate::config::ServerSpec) -> &'static str {
    use crate::config::ServerSpec;
    match spec {
        ServerSpec::Anytls(_) => "anytls",
        ServerSpec::Samizdat(_) => "samizdat",
        ServerSpec::Shadowsocks(_) => "shadowsocks",
        ServerSpec::Hysteria2(_) => "hysteria2",
        ServerSpec::FrontedMeek(_) => "meek",
        ServerSpec::Wasm(_) => "wasm",
        ServerSpec::Tunnel(_) => "tunnel",
        ServerSpec::DnsTunnel(_) => "dns-tunnel",
    }
}

/// A diagnostic label for a pool member: `"{protocol} {server-addr}"` (e.g.
/// `samizdat 161.33.223.26:31464`), so probe/selection logs name the protocol *and* the exact server.
#[cfg(feature = "multi-server")]
fn spec_label(spec: &crate::config::ServerSpec) -> String {
    use crate::config::ServerSpec;
    match spec {
        ServerSpec::Anytls(c) => format!("anytls {}", c.server),
        ServerSpec::Samizdat(c) => format!("samizdat {}", c.server),
        ServerSpec::Shadowsocks(c) => format!("shadowsocks {}", c.server),
        ServerSpec::Hysteria2(c) => format!("hysteria2 {}", c.server),
        ServerSpec::FrontedMeek(c) => format!(
            "meek {}",
            // Match FrontedMeekTransport::new, which treats whitespace-only as unset.
            if c.meek_host.trim().is_empty() {
                crate::config::DEFAULT_FRONTED_MEEK_HOST
            } else {
                c.meek_host.trim()
            }
        ),
        ServerSpec::Wasm(c) => format!("wasm {}", c.server),
        ServerSpec::Tunnel(c) => format!("tunnel {}", c.server),
        // Log hygiene: never surface the tunnel zone/resolvers — just the resolver count.
        ServerSpec::DnsTunnel(c) => {
            format!("dns-tunnel ({} configured resolvers)", c.resolvers.len())
        }
    }
}

/// Build a `SelectingTransport` over `config.transport.servers`. Each entry's callback URL is its
/// per-entry override or the global `transport.callback_url`. Members that can't be built (notably a
/// transport whose feature isn't compiled in) are **skipped** — a partial pool still connects, and a
/// future protocol in a fetched config can't brick the tunnel; the pool must end up non-empty.
#[cfg(feature = "multi-server")]
#[allow(clippy::type_complexity)]
fn build_selecting(
    config: &Config,
    protector: Option<SocketProtector>,
) -> io::Result<(
    Arc<dyn Transport>,
    Arc<dyn UdpTransport>,
    Option<Arc<dyn PoolControl>>,
)> {
    use crate::transport::select::SelectingTransport;
    let wire = wire_plan_from_config(&config.transport.shaping);
    let mut members = Vec::with_capacity(config.transport.servers.len());
    let mut skipped: Vec<String> = Vec::new();
    for entry in &config.transport.servers {
        // Skip (don't propagate) a member we can't build, mirroring the config_raw adapter skipping
        // outbounds it can't represent. The reason is logged and aggregated into the empty-pool error.
        match build_member(entry, config, protector.as_ref(), &wire) {
            Ok(m) => members.push(m),
            Err(e) => {
                let who = entry.name.as_deref().unwrap_or("<unnamed>");
                tracing::warn!(server = who, error = %e, "transport.servers: skipping un-buildable pool member");
                skipped.push(format!("{who}: {e}"));
            }
        }
    }
    if members.is_empty() {
        return Err(io::Error::other(format!(
            "transport.servers: no buildable pool members ({} skipped — {})",
            skipped.len(),
            skipped.join("; ")
        )));
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
        st.clone() as Arc<dyn UdpTransport>,
        Some(st as Arc<dyn PoolControl>),
    ))
}

#[cfg(not(feature = "multi-server"))]
#[allow(clippy::type_complexity)]
fn build_selecting(
    _config: &Config,
    _protector: Option<SocketProtector>,
) -> io::Result<(
    Arc<dyn Transport>,
    Arc<dyn UdpTransport>,
    Option<Arc<dyn PoolControl>>,
)> {
    Err(io::Error::other(
        "transport.servers is configured but spark was built without the `multi-server` feature",
    ))
}

/// Build the TCP + UDP transports from `config`: a tunnel client when `transport.server` is
/// set, otherwise direct; both pinned to `transport.protect_interface` when configured. A thin
/// wrapper over [`from_config_with_control`] that discards the (pool-only) control handle, for the
/// callers that don't drive the server-selection UI.
pub fn from_config(config: &Config) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    from_config_with_control(config).map(|(tcp, udp, _control)| (tcp, udp))
}

/// Like [`from_config`], but also returns the runtime [`PoolControl`] handle when the config builds a
/// multi-server pool (`Some` only for a `[[transport.servers]]` pool; `None` for direct/tunnel/AnyTLS/
/// Samizdat/wasm). The fd-path tunnel registers this handle so the platform FFI can drive the
/// server-selection UI (`fd_tunnel::servers_json`/`select_server`).
#[allow(clippy::type_complexity)]
pub fn from_config_with_control(
    config: &Config,
) -> io::Result<(
    Arc<dyn Transport>,
    Arc<dyn UdpTransport>,
    Option<Arc<dyn PoolControl>>,
)> {
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(SocketProtector::for_interface(name)?),
        None => None,
    };
    // A configured server pool supersedes the single-transport fields: build a latency-selecting
    // transport over it (the only path with a control handle).
    if !config.transport.servers.is_empty() {
        return build_selecting(config, protector);
    }
    // AnyTLS takes precedence over the plain `server` tunnel when configured.
    if let Some(anytls) = &config.transport.anytls {
        let wire = wire_plan_from_config(&config.transport.shaping);
        let (tcp, udp) = anytls_transport(anytls, protector, wire)?;
        return Ok((tcp, udp, None));
    }
    // Samizdat (ADR 0007) — like AnyTLS, takes precedence over the plain `server` tunnel. It reuses
    // the shared `[transport.shaping]` plan to fragment the ClientHello (Geneva-style, on by default
    // in the Go client).
    if let Some(samizdat) = &config.transport.samizdat {
        let wire = wire_plan_from_config(&config.transport.shaping);
        let (tcp, udp) = samizdat_transport(samizdat, protector, wire)?;
        return Ok((tcp, udp, None));
    }
    // Shadowsocks 2022 (ADR 0009) — like AnyTLS/Samizdat, takes precedence over the plain `server`
    // tunnel. Not TLS, so it takes no shaping plan. Not a pool, so no control handle.
    if let Some(ss) = &config.transport.shadowsocks {
        let (tcp, udp) = shadowsocks_transport(ss, protector)?;
        return Ok((tcp, udp, None));
    }
    // Hysteria 2 (ADR 0010) — QUIC transport; like the others, takes precedence over the plain
    // `server` tunnel. Not TLS, so no shaping plan. Not a pool, so no control handle.
    if let Some(hy2) = &config.transport.hysteria2 {
        let (tcp, udp) = hysteria2_transport(hy2, protector)?;
        return Ok((tcp, udp, None));
    }
    // DNS-tunnel (ADR 0011) — the shutdown escalation tier. Like the others, takes precedence over the
    // plain `server` tunnel. Not TLS (no shaping plan); not a pool (no control handle).
    if let Some(dt) = &config.transport.dns_tunnel {
        let (tcp, udp) = dns_tunnel_transport(dt, protector)?;
        return Ok((tcp, udp, None));
    }
    // The dynamic wasm transport is next in precedence (above the plain `server` tunnel).
    if let Some(wasm) = &config.transport.wasm {
        let (tcp, udp) = wasm_transport(wasm, protector)?;
        return Ok((tcp, udp, None));
    }
    // Domain-fronted meek polling (Shir-o-Khorshid CDN-fronting): self-bootstrapping
    // (scans CDN edges from the user's own network), above the plain `server` tunnel.
    if let Some(fm) = &config.transport.fronted_meek {
        let (tcp, udp) = fronted_meek_transport(fm)?;
        return Ok((tcp, udp, None));
    }
    let (tcp, udp) = match config.transport.server {
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
    };
    Ok((tcp, udp, None))
}

/// Merge a gambit's Layer-B record-split offsets into the dialer's wire plan. [`wire_plan_from_config`]
/// maps Layer C only (`record_fragment` defaults to `None`), so the gambit's `records.split_offsets`
/// is the sole source of `record_fragment`. An empty offsets list leaves the wire plan untouched.
#[cfg(feature = "anytls")]
fn with_record_split(mut wire: WirePlan, records: &flint_tls::gambit::Records) -> WirePlan {
    if !records.split_offsets.is_empty() {
        wire.record_fragment =
            flint_shaping::RecordFragment::Offsets(records.split_offsets.clone());
    }
    wire
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
    // Fold the static-config gambit's Layer-B record-split into the (static, per-transport) wire plan
    // so both the static and dynamic-gambit construction paths below inherit it. Note: a *dynamic*
    // gambit re-resolves only the Layer-A/B-clienthello Profile per connection; its
    // `records.split_offsets` won't reach this static WirePlan (a per-connection WirePlan refactor is
    // deferred), so dynamic per-connection record-split is a known limitation.
    let wire = with_record_split(wire, &cfg.records);
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

/// Build the Shadowsocks transport (feature `shadowsocks`): decode + length-check the base64 PSK,
/// then a [`shadowsocks::ShadowsocksTransport`] serving both TCP and UDP (UDP errors for the chacha
/// method). SS is not TLS, so it takes no shaping plan.
#[cfg(feature = "shadowsocks")]
fn shadowsocks_transport(
    cfg: &ShadowsocksConfig,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let server = cfg.server.socket_addr()?;
    let psk = shadowsocks::decode_psk(cfg.method, &cfg.password)
        .map_err(|e| io::Error::other(format!("transport.shadowsocks: {e}")))?;
    let t = Arc::new(shadowsocks::ShadowsocksTransport::new(
        server, cfg.method, psk, protector,
    ));
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `shadowsocks` feature, a configured SS transport is a hard error (mirrors anytls/wasm).
#[cfg(not(feature = "shadowsocks"))]
fn shadowsocks_transport(
    _cfg: &ShadowsocksConfig,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.shadowsocks is configured but spark was built without the `shadowsocks` feature",
    ))
}

/// Build the Hysteria 2 transport (feature `hysteria2`): a QUIC client serving both TCP and UDP.
///
/// `protector`, when set, pins the QUIC data-plane UDP socket to the physical interface so the
/// transport's own packets bypass the tunnel route.
#[cfg(feature = "hysteria2")]
fn hysteria2_transport(
    cfg: &Hysteria2Config,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let server = cfg.server.socket_addr()?;
    let t = Arc::new(hysteria2::Hysteria2Transport::new(
        cfg.clone(),
        server,
        protector,
    ));
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `hysteria2` feature, a configured Hysteria 2 transport is a hard error (mirrors
/// anytls/shadowsocks/wasm).
#[cfg(not(feature = "hysteria2"))]
fn hysteria2_transport(
    _cfg: &Hysteria2Config,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.hysteria2 is configured but spark was built without the `hysteria2` feature",
    ))
}

/// Build the DNS-tunnel transport (feature `dns-tunnel`, ADR 0011): decode the server's base64 Ed25519
/// public key (which authenticates the forward-secret handshake), map the config cipher, and build a
/// resolver list (the configured `resolvers`, or the `authoritative`
/// address when none are given — authoritative mode). TCP only; `UdpTransport` reports unsupported.
#[cfg(feature = "dns-tunnel")]
fn dns_tunnel_transport(
    cfg: &DnsTunnelConfig,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let server_pub = dns_tunnel_core::crypto::decode_server_pub(&cfg.server_pubkey)
        .map_err(|e| io::Error::other(format!("transport.dns-tunnel: {e}")))?;
    let mut resolvers = cfg.resolvers.clone();
    // Auto-include the OS-configured resolver(s) (default on) — during a shutdown the mandated local
    // resolver is often the only one that still forwards DNS. Recursive mode only (authoritative mode
    // dials the server directly). Log hygiene: never log the discovered IPs.
    if cfg.authoritative.is_none() && cfg.use_system_resolvers.unwrap_or(true) {
        resolvers.extend(dns_tunnel::balancer::system_resolvers());
    }
    if resolvers.is_empty() {
        if let Some(auth) = &cfg.authoritative {
            resolvers.push(auth.socket_addr()?.to_string());
        }
    }
    if resolvers.is_empty() {
        return Err(io::Error::other(
            "transport.dns-tunnel: set `resolvers`, `authoritative`, or enable system resolvers",
        ));
    }
    let cipher = match cfg.cipher {
        DnsTunnelCipher::ChaCha20Poly1305 => dns_tunnel_core::crypto::Cipher::ChaCha20Poly1305,
        DnsTunnelCipher::Aes256Gcm => dns_tunnel_core::crypto::Cipher::Aes256Gcm,
    };
    let session = dns_tunnel_core::session::Config {
        cipher,
        ..Default::default()
    };
    let pool_cfg = dns_tunnel::balancer::PoolConfig {
        // ≥1; higher = delivery probability + fast working-subset discovery under a shutdown.
        duplication: cfg.duplication.unwrap_or(1).max(1),
        ..Default::default()
    };
    let t = Arc::new(dns_tunnel::DnsTunnelTransport::new(
        cfg.zone.clone(),
        server_pub,
        resolvers,
        pool_cfg,
        session,
        protector,
    ));
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `dns-tunnel` feature, a configured DNS-tunnel transport is a hard error (mirrors
/// anytls/shadowsocks/hysteria2/wasm).
#[cfg(not(feature = "dns-tunnel"))]
fn dns_tunnel_transport(
    _cfg: &DnsTunnelConfig,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.dns-tunnel is configured but spark was built without the `dns-tunnel` feature",
    ))
}

#[cfg(all(test, feature = "dns-tunnel"))]
mod dns_tunnel_wiring_tests {
    use super::*;
    use crate::config::{DnsTunnelCipher, DnsTunnelCompression, DnsTunnelConfig};

    // 32 bytes, base64 — the shape of an Ed25519 public key (validity isn't checked until a handshake).
    const PUBKEY_B64: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";

    #[test]
    fn builder_accepts_a_valid_config() {
        let cfg = DnsTunnelConfig {
            zone: "t.example.com".into(),
            server_pubkey: PUBKEY_B64.into(),
            resolvers: vec!["1.1.1.1".into(), "8.8.8.8:53".into()],
            authoritative: None,
            cipher: DnsTunnelCipher::Aes256Gcm,
            compression: DnsTunnelCompression::Off,
            duplication: Some(3),
            use_system_resolvers: Some(false),
        };
        assert!(dns_tunnel_transport(&cfg, None).is_ok());
    }

    #[test]
    fn builder_rejects_no_resolvers_and_no_authoritative() {
        let cfg = DnsTunnelConfig {
            zone: "t.example.com".into(),
            server_pubkey: PUBKEY_B64.into(),
            resolvers: vec![],
            authoritative: None,
            cipher: DnsTunnelCipher::default(),
            compression: DnsTunnelCompression::default(),
            duplication: None,
            // Deterministic: don't pull in this machine's /etc/resolv.conf, so the empty-pool error
            // path is what's exercised.
            use_system_resolvers: Some(false),
        };
        assert!(dns_tunnel_transport(&cfg, None).is_err());
    }
}

/// Build the domain-fronted meek polling transport (feature `fronted-meek`).
/// Self-bootstrapping — it scans CDN edges from the user's own network — so it
/// takes no per-server address. No protector/wire: the front TLS dial happens
/// inside `flint` (see the `fronted_meek` module note).
#[cfg(feature = "fronted-meek")]
fn fronted_meek_transport(
    cfg: &FrontedMeekConfig,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let t = Arc::new(fronted_meek::FrontedMeekTransport::new(cfg)?);
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `fronted-meek` feature, a configured fronted-meek transport is a
/// hard error (mirrors anytls/samizdat/wasm).
#[cfg(not(feature = "fronted-meek"))]
fn fronted_meek_transport(
    _cfg: &FrontedMeekConfig,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.fronted_meek is configured but spark was built without the `fronted-meek` feature",
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

/// Display metadata for a pool member, surfaced to the server-selection UI via [`PoolControl::snapshot`].
/// All optional — sourced from the per-entry `[[transport.servers]]` location fields (Phase 2; the
/// full `config_raw.json` shape is Phase 3). Does not affect transport behavior. Lives here (not in
/// the feature-gated `select` module) so [`PoolControl`] has a uniform signature in every build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerMeta {
    /// Short tag/identifier, e.g. `"sfo3"`.
    pub name: Option<String>,
    /// Display country, e.g. `"United States"`.
    pub country: Option<String>,
    /// ISO 3166-1 alpha-2 code, e.g. `"US"` (the UI renders a flag from it).
    pub country_code: Option<String>,
    /// Display city, e.g. `"San Francisco"`.
    pub city: Option<String>,
}

/// A point-in-time view of one pool member for the server-selection UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberStatus {
    /// Index into the pool (the stable handle the UI passes back to [`PoolControl::set_pin`]).
    pub index: usize,
    /// Display metadata (country/city/flag/name).
    pub meta: ServerMeta,
    /// Transport protocol kind, e.g. `"hysteria2"` — shown beneath the location in the UI.
    pub protocol: String,
    /// Last measured probe latency in whole milliseconds; `None` if never measured or unhealthy.
    pub latency_ms: Option<u64>,
    /// Whether the last probe found this member healthy.
    pub healthy: bool,
    /// Whether new flows currently dial this member first (the pinned member, or — on auto — the
    /// latency-ranked best).
    pub is_current: bool,
}

/// Runtime control surface for a configured server pool, exposed to the platform FFI so the UI can
/// read per-member status and pin a choice. Only the multi-server [`select::SelectingTransport`]
/// implements it; non-pool transports have no control handle (`from_config_with_control` returns
/// `None`).
pub trait PoolControl: Send + Sync {
    /// Per-member status snapshot, ordered by pool index.
    fn snapshot(&self) -> Vec<MemberStatus>;
    /// Pin which member new flows dial first: `Some(index)` overrides the latency ranking, `None`
    /// returns to auto. New flows only; in-flight unaffected. Returns `true` if applied, `false` if
    /// an out-of-range index was ignored (so callers can report a real failure instead of a no-op).
    fn set_pin(&self, index: Option<usize>) -> bool;
}

/// JSON-escape a string for [`snapshot_to_json`] (only the characters JSON requires: quote,
/// backslash, and C0 control chars). Hand-rolled so core needs no JSON dependency.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A JSON string literal for an optional value (`"..."` escaped, or `null`).
fn json_opt_str(v: &Option<String>) -> String {
    match v {
        Some(s) => format!("\"{}\"", json_escape(s)),
        None => "null".to_string(),
    }
}

/// Serialize a member snapshot to the JSON array the UI consumes (camelCase keys), e.g.
/// `[{"index":0,"name":"sfo3","country":"United States","countryCode":"US","city":"San Francisco",
/// "latencyMs":19,"healthy":true,"isCurrent":true}]`. Hand-rolled to keep core JSON-dependency-free;
/// the shape is small and fixed. Used by `fd_tunnel::servers_json` across the FFI.
pub fn snapshot_to_json(members: &[MemberStatus]) -> String {
    let objs: Vec<String> = members
        .iter()
        .map(|m| {
            format!(
                "{{\"index\":{},\"name\":{},\"country\":{},\"countryCode\":{},\"city\":{},\"protocol\":\"{}\",\"latencyMs\":{},\"healthy\":{},\"isCurrent\":{}}}",
                m.index,
                json_opt_str(&m.meta.name),
                json_opt_str(&m.meta.country),
                json_opt_str(&m.meta.country_code),
                json_opt_str(&m.meta.city),
                json_escape(&m.protocol),
                m.latency_ms
                    .map(|l| l.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                m.healthy,
                m.is_current,
            )
        })
        .collect();
    format!("[{}]", objs.join(","))
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

    /// Open a stream to a target that may be an unresolved **domain** — the fake-IP proxy path,
    /// where a flow's real destination is a name recovered from its fake IP (smart-routing/M4).
    ///
    /// The default handles only [`Address::Ip`] (delegating to [`dial`](Self::dial)) and rejects a
    /// domain. Transports whose wire protocol carries a domain to the exit (so the exit resolves —
    /// no client DNS) override this: the plain tunnel, shadowsocks, and hysteria2 (and the selecting
    /// pool, which delegates to whichever members it holds). For transports that can't, the forwarder
    /// falls back to client-side resolution + dial-by-IP.
    async fn dial_addr(&self, target: Address) -> io::Result<BoxedStream> {
        match target {
            Address::Ip(sa) => self.dial(sa).await,
            // `Unsupported` (not a generic error) so callers like `SelectingTransport::dial_addr` can
            // tell "this transport can't carry a domain" from a real dial failure and not demote an
            // otherwise-healthy member.
            Address::Domain { host, port } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("transport does not support domain targets ({host}:{port})"),
            )),
        }
    }
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

#[cfg(test)]
mod dial_addr_tests {
    use super::*;
    use tokio::net::TcpListener;

    /// The default [`Transport::dial_addr`] delegates an `Ip` target to `dial`, and rejects a
    /// `Domain` (a transport whose wire protocol can't carry a name — the forwarder resolves those
    /// client-side and retries by IP). Transports that *can* carry a domain override the default.
    #[tokio::test]
    async fn default_dial_addr_delegates_ip_and_rejects_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let direct = DirectTransport::new(None);
        assert!(
            direct.dial_addr(Address::Ip(addr)).await.is_ok(),
            "Ip target delegates to dial()"
        );
        assert!(
            direct
                .dial_addr(Address::domain("example.com", 80).expect("domain"))
                .await
                .is_err(),
            "the default impl can't carry a domain target"
        );
    }
}

#[cfg(test)]
mod snapshot_json_tests {
    use super::*;

    #[test]
    fn snapshot_to_json_shapes_members_camelcase_with_nulls() {
        let members = vec![
            MemberStatus {
                index: 0,
                meta: ServerMeta {
                    name: Some("sfo3".into()),
                    country: Some("United States".into()),
                    country_code: Some("US".into()),
                    city: Some("San Francisco".into()),
                },
                protocol: "hysteria2".into(),
                latency_ms: Some(19),
                healthy: true,
                is_current: true,
            },
            MemberStatus {
                index: 1,
                meta: ServerMeta::default(),
                protocol: "samizdat".into(),
                latency_ms: None,
                healthy: false,
                is_current: false,
            },
        ];
        assert_eq!(
            snapshot_to_json(&members),
            "[{\"index\":0,\"name\":\"sfo3\",\"country\":\"United States\",\"countryCode\":\"US\",\"city\":\"San Francisco\",\"protocol\":\"hysteria2\",\"latencyMs\":19,\"healthy\":true,\"isCurrent\":true},\
             {\"index\":1,\"name\":null,\"country\":null,\"countryCode\":null,\"city\":null,\"protocol\":\"samizdat\",\"latencyMs\":null,\"healthy\":false,\"isCurrent\":false}]"
        );
    }

    #[test]
    fn snapshot_to_json_escapes_quotes_and_backslashes() {
        let members = vec![MemberStatus {
            index: 0,
            meta: ServerMeta {
                city: Some("a\"b\\c".into()),
                ..Default::default()
            },
            protocol: "samizdat".into(),
            latency_ms: None,
            healthy: false,
            is_current: false,
        }];
        let json = snapshot_to_json(&members);
        assert!(json.contains(r#""city":"a\"b\\c""#), "got: {json}");
    }

    #[test]
    fn empty_snapshot_is_empty_json_array() {
        assert_eq!(snapshot_to_json(&[]), "[]");
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
                    latitude: None,
                    longitude: None,
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
                    latitude: None,
                    longitude: None,
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

    #[cfg(not(feature = "anytls"))]
    #[tokio::test]
    async fn pool_skips_unbuildable_member_and_keeps_the_buildable_one() {
        // Member A has an https callback (un-buildable without anytls — stands in for any member whose
        // transport feature isn't compiled in); member B uses the global http callback (buildable).
        // The pool must drop A and build with B rather than failing entirely (the old behavior).
        let mk = |name: &str, cb: Option<&str>| ServerEntry {
            spec: ServerSpec::Tunnel(TunnelConfig {
                server: "1.2.3.4:443".parse().unwrap(),
                sni: None,
            }),
            callback_url: cb.map(str::to_owned),
            name: Some(name.to_owned()),
            country: None,
            country_code: None,
            city: None,
            latitude: None,
            longitude: None,
        };
        let cfg = Config {
            transport: TransportConfig {
                servers: vec![
                    mk("A-https", Some("https://bad.example/x")),
                    mk("B-http", None),
                ],
                callback_url: Some("http://127.0.0.1:80/ok".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        from_config(&cfg).expect(
            "pool should build from the buildable member after skipping the un-buildable one",
        );
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
                    latitude: None,
                    longitude: None,
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

#[cfg(all(test, feature = "shadowsocks"))]
mod shadowsocks_config_tests {
    use super::*;

    #[test]
    fn from_config_builds_a_shadowsocks_transport() {
        let toml = r#"
[transport.shadowsocks]
server = "1.2.3.4:8388"
method = "2022-blake3-aes-256-gcm"
password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
"#;
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        let _ = from_config(&cfg).expect("shadowsocks transport builds");
    }

    #[test]
    fn from_config_rejects_a_bad_length_psk() {
        let toml = r#"
[transport.shadowsocks]
server = "1.2.3.4:8388"
method = "2022-blake3-aes-256-gcm"
password = "c2hvcnQ="
"#;
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        assert!(from_config(&cfg).is_err());
    }
}

#[cfg(all(test, feature = "hysteria2"))]
mod hysteria2_config_tests {
    use super::*;

    #[test]
    fn from_config_builds_a_hysteria2_transport() {
        // IP:port literal so no DNS resolution is needed; `Hysteria2Transport::new` is lazy.
        let toml = r#"
[transport.hysteria2]
server = "1.2.3.4:443"
auth = "s3cr3t"
"#;
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        let _ = from_config(&cfg).expect("hysteria2 transport builds");
    }

    #[test]
    fn from_config_parses_a_hysteria2_pool_entry() {
        let toml = r#"
[[transport.servers]]
kind = "hysteria2"
server = "1.2.3.4:443"
auth = "s3cr3t"
"#;
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        let entry = &cfg.transport.servers[0];
        assert!(
            matches!(entry.spec, crate::config::ServerSpec::Hysteria2(_)),
            "expected a Hysteria2 pool entry, got: {:?}",
            entry.spec
        );
    }
}

#[cfg(test)]
mod fronted_meek_config_tests {
    // Only the transport-build test needs `super` items (`from_config`); the serde tests use
    // fully-qualified `crate::config::*` paths, so the glob import is unused in the base build.
    #[cfg(feature = "fronted-meek")]
    use super::*;

    // Building the transport needs the feature compiled in; the serde tests below don't (the
    // FrontedMeek variant + `fronted-meek` alias are unconditional), so they run in every build.
    #[cfg(feature = "fronted-meek")]
    #[test]
    fn from_config_builds_a_fronted_meek_transport() {
        // Empty table → self-bootstrapping defaults; new() is lazy (no dial/scan).
        let toml = "[transport.fronted_meek]\n";
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        let _ = from_config(&cfg).expect("fronted-meek transport builds");
    }

    #[test]
    fn from_config_parses_a_meek_pool_entry() {
        // `kind = "meek"` must deserialize to FrontedMeek — guards the serde rename (the wire/pool
        // identifier is `meek`, matching the server-side protocol; the Rust variant stays FrontedMeek).
        let toml = r#"
[[transport.servers]]
kind = "meek"
meek_host = "meek.example.org"
"#;
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        let entry = &cfg.transport.servers[0];
        assert!(
            matches!(entry.spec, crate::config::ServerSpec::FrontedMeek(_)),
            "expected a FrontedMeek pool entry, got: {:?}",
            entry.spec
        );
    }

    #[test]
    fn from_config_accepts_legacy_fronted_meek_pool_kind() {
        // The pre-rename pool tag `kind = "fronted-meek"` must still deserialize (serde alias), so a
        // native-TOML pool written by an older build keeps working after the rename to `meek`.
        let toml = r#"
[[transport.servers]]
kind = "fronted-meek"
meek_host = "meek.example.org"
"#;
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        assert!(matches!(
            cfg.transport.servers[0].spec,
            crate::config::ServerSpec::FrontedMeek(_)
        ));
    }
}

/// P4a gambit realization: the Layer-B record-split wiring (`with_record_split`) and confirmation
/// that the static-config explicit-order + session-id-inject knobs flow through to boring
/// automatically via the bumped flint connector.
#[cfg(all(test, feature = "anytls"))]
mod anytls_gambit_realization_tests {
    use super::*;
    use flint_tls::gambit::{Capability, Gambit, Records};

    #[test]
    fn record_split_offsets_become_record_fragment_offsets() {
        let recs = Records {
            split_offsets: vec![6, 12],
            ..Default::default()
        };
        let wire = with_record_split(WirePlan::default(), &recs);
        assert!(
            matches!(wire.record_fragment, flint_shaping::RecordFragment::Offsets(ref o) if *o == [6, 12]),
            "split_offsets must map to RecordFragment::Offsets"
        );

        // Empty offsets ⇒ wire untouched (record_fragment stays the default None).
        let empty = Records {
            split_offsets: vec![],
            ..Default::default()
        };
        assert!(
            matches!(
                with_record_split(WirePlan::default(), &empty).record_fragment,
                flint_shaping::RecordFragment::None
            ),
            "empty split_offsets must leave record_fragment at its None default"
        );
    }

    #[test]
    fn session_id_inject_gambit_is_accepted_by_boring_now() {
        // A gambit requiring SessionIdInject must pass for_boring: the bumped flint advertises the
        // capability (BORING_CAPABILITIES), so for_boring no longer declines it.
        let g = Gambit {
            genome_version: 1,
            version: 1,
            id: "g".into(),
            anchor: Default::default(),
            clienthello: Default::default(),
            records: Default::default(),
            wire: Default::default(),
            requires: vec![Capability::SessionIdInject],
        };
        assert!(
            flint_tls::Profile::for_boring(&g).is_ok(),
            "a session_id_inject gambit must be accepted by boring"
        );
    }
}

/// Manual **out-of-NE** diagnostic (ignored by default): dial each server from a real fetched
/// `config_raw.json` **directly, with no tunnel**, optionally pinned to a physical interface — to
/// isolate transport interop from the macOS NE's UDP egress. It runs the real health probe (dial →
/// callback GET → read) against each pool member, so it answers whether spark reaches the *real*
/// servers when there's no tunnel at all. Run with the **VPN off**:
///   SPARK_REAL_CONFIG=$HOME/config_raw.json SPARK_PIN_IFACE=en1 \
///     cargo test -p spark-core \
///       --features config-fetch,samizdat,shadowsocks,hysteria2,bootstrap-dns \
///       -- --ignored --nocapture dial_real_servers
///
/// `HEALTHY` ⇒ the transport dialed and the origin replied (protocol + servers + network are fine).
/// `UNHEALTHY` ⇒ the dial/handshake failed or timed out for that member. It reads a local file with
/// live secrets — never commit that file; this test logs none of them.
#[cfg(all(test, feature = "multi-server"))]
mod real_server_probe {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "manual: needs SPARK_REAL_CONFIG (a real config_raw.json) and the VPN off"]
    async fn dial_real_servers() {
        let Some(path) = std::env::var_os("SPARK_REAL_CONFIG") else {
            eprintln!("SPARK_REAL_CONFIG unset — skipping (point it at a config_raw.json)");
            return;
        };
        // Surface spark's own tracing (e.g. hysteria2's "QUIC connected" / "/auth ok" stages) to
        // stderr via the log bridge, so a hang shows WHERE: QUIC handshake vs /auth.
        extern "C" fn trace_to_stderr(level: u8, msg: *const std::os::raw::c_char) {
            // SAFETY: the bridge passes a valid NUL-terminated string for the call's duration.
            let s = unsafe { std::ffi::CStr::from_ptr(msg) }.to_string_lossy();
            eprintln!("[L{level}] {s}");
        }
        crate::log_bridge::install(trace_to_stderr);

        let raw = std::fs::read_to_string(&path).expect("read SPARK_REAL_CONFIG");
        let cfg = crate::config::Config::from_config_str(&raw).expect("adapt config_raw.json");
        // Pin like the lantern-api path (SPARK_PIN_IFACE=en1), so this matches on-device routing
        // minus the tunnel itself.
        let protector = std::env::var("SPARK_PIN_IFACE")
            .ok()
            .and_then(|i| crate::net::SocketProtector::for_interface(&i).ok());
        eprintln!(
            "dialing {} pool members directly (pin={:?})",
            cfg.transport.servers.len(),
            protector.as_ref().map(|p| p.interface())
        );
        let wire = wire_plan_from_config(&cfg.transport.shaping);
        let global_cb = cfg.transport.callback_url.clone();
        for entry in &cfg.transport.servers {
            let label = spec_label(&entry.spec);
            let (transport, _udp) = match build_one(&entry.spec, protector.as_ref(), &wire) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{label}: build failed: {e}");
                    continue;
                }
            };
            // Run the real health probe (dial -> callback GET -> read) so the lazy TCPResponse path is
            // exercised end-to-end, exactly like on device — not just whether dial returns.
            let Some(cb_raw) = entry.callback_url.as_deref().or(global_cb.as_deref()) else {
                eprintln!("{label}: no callback_url; skipping");
                continue;
            };
            let callback = match crate::transport::probe::CallbackUrl::parse(cb_raw) {
                Ok(c) => c,
                Err(e) => {
                    // Both the URL and the parse error embed the token (errors like
                    // "missing scheme: <full url>"), so strip everything from the first `?` —
                    // the bandit callback's token lives in `?token=...`.
                    let cb_safe = cb_raw.split_once('?').map_or(cb_raw, |(p, _)| p);
                    let err = e.to_string();
                    let err_safe = err.split_once('?').map_or(err.as_str(), |(p, _)| p);
                    eprintln!("{label}: bad callback {cb_safe}: {err_safe}");
                    continue;
                }
            };
            let outcome = crate::transport::probe::probe(
                &transport,
                &callback,
                Duration::from_secs(10),
                &label,
            )
            .await;
            if outcome.healthy {
                eprintln!("{label}: HEALTHY (probe ok, latency {:?})", outcome.latency);
            } else {
                eprintln!("{label}: UNHEALTHY (probe failed/timed out)");
            }
        }
    }
}
