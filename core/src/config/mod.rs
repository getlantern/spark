//! TOML configuration schema.
//!
//! [`Config`] is the production-shaped settings the CLI (and, later, the privileged service)
//! load from a TOML file. It mirrors the CLI flags but is the single source of truth once
//! loaded. Every field has a default, so a partial or empty file is valid; unknown keys are
//! rejected so typos surface instead of being silently ignored.
//!
//! ```
//! # use spark_core::config::Config;
//! let cfg = Config::from_toml_str(r#"
//!     [tun]
//!     addr = "10.0.0.1"
//!     prefix = 24
//!
//!     [transport]
//!     server = "192.0.2.1:8388"
//! "#).unwrap();
//! assert_eq!(cfg.tun.prefix, 24);
//! assert!(cfg.transport.server.is_some());
//! ```

use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use flint_tls::gambit::{ClientHello, Records};

/// Adapter from the Lantern API's `config_raw.json` payload (a sing-box-style config) into
/// [`Config`] (Phase 3). See [`lantern::from_config_raw_json`].
pub mod lantern;

/// Fetch config from the Lantern `config-new` API and feed it into [`lantern`] (Phase 3 fetch half).
#[cfg(feature = "config-fetch")]
pub mod fetch;

/// A proxy server address: a literal `IP:port` ([`Endpoint::Ip`], the unchanged path with no startup
/// DNS) or a `host:port` to resolve before dialing ([`Endpoint::Host`], requires the `bootstrap-dns`
/// feature). Deserializes from a single TOML string. See `docs/bootstrap-resolver-design.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// An already-resolved socket address — dialed directly.
    Ip(SocketAddr),
    /// A hostname + port resolved at startup by the bootstrap resolver.
    Host {
        /// The hostname to resolve.
        host: String,
        /// The port to pair with the resolved address.
        port: u16,
    },
}

impl Endpoint {
    /// The resolved [`SocketAddr`], or an error if this is still an unresolved [`Endpoint::Host`].
    /// The bootstrap phase resolves every `Host` to an `Ip` before the transport is built, so a `Host`
    /// reaching here means resolution didn't run (e.g. built without the `bootstrap-dns` feature).
    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Endpoint::Ip(addr) => Ok(*addr),
            Endpoint::Host { host, port } => Err(io::Error::other(format!(
                "endpoint {host}:{port} is an unresolved hostname — the bootstrap phase \
                 (resolve_bootstrap) must run before the transport is built, and the binary must be \
                 built with the `bootstrap-dns` feature to resolve hostnames"
            ))),
        }
    }

    /// `(host, port)` when this needs resolution; `None` when it is already an [`Endpoint::Ip`].
    pub fn unresolved(&self) -> Option<(&str, u16)> {
        match self {
            Endpoint::Host { host, port } => Some((host.as_str(), *port)),
            Endpoint::Ip(_) => None,
        }
    }
}

impl std::str::FromStr for Endpoint {
    type Err = EndpointParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Endpoint::Ip(addr));
        }
        let (host, port) = s.rsplit_once(':').ok_or(EndpointParseError)?;
        let port: u16 = port.parse().map_err(|_| EndpointParseError)?;
        // Reject an empty host, any leftover `:`, or embedded whitespace. A bracketed IPv6 literal
        // already parsed via the `SocketAddr` branch above, so a `:` here means an unbracketed IPv6
        // (`2001:db8::1:443`) or a double-port typo (`host:443:80`); whitespace (`" host:443"`,
        // `"host :443"`) is an invalid hostname. Fail fast at parse time rather than letting any of
        // these masquerade as a hostname and blow up confusingly during resolution.
        if host.is_empty() || host.contains(':') || host.chars().any(char::is_whitespace) {
            return Err(EndpointParseError);
        }
        Ok(Endpoint::Host {
            host: host.to_owned(),
            port,
        })
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Ip(addr) => write!(f, "{addr}"),
            Endpoint::Host { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// A `[transport.*].server` string was neither `IP:port` nor `host:port`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("endpoint must be `IP:port` or `host:port`")]
pub struct EndpointParseError;

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Serialize for Endpoint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// Top-level configuration. Each section has defaults, so missing sections and fields fall
/// back rather than erroring.
// No `Eq`: `ServerEntry` carries `f64` lat/long (Phase 3), and `f64: !Eq`. `PartialEq` is kept
// (used by tests / equality checks); nothing requires full `Eq` on the config types.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// TUN device settings.
    pub tun: TunConfig,
    /// How upstream traffic is reached.
    pub transport: TransportConfig,
    /// UDP forwarding settings.
    pub udp: UdpConfig,
    /// Whether spark manages the routing table (full-tunnel) itself.
    pub routing: RoutingConfig,
    /// Kill-switch behavior when the tunnel drops.
    pub kill_switch: KillSwitchConfig,
    /// Logging settings.
    pub log: LogConfig,
    /// Rule-based smart-routing + ad-block, parsed from `config_raw.json`'s
    /// `smart_routing` / `ad_block` / `options.route.rules` sections. Empty for native TOML
    /// configs, so the base full-tunnel behavior is unchanged.
    pub smart_routing: SmartRoutingConfig,
    /// Per-action DoH resolver endpoints from `config_raw.json`'s `options.dns` (`dns_local` /
    /// `dns_remote`). Empty for native TOML configs. With the `bootstrap-dns` feature the
    /// smart-routing resolvers then fall back to the built-in un-poisoned DoH pool; without it they
    /// return `None` and flows degrade (Direct→Proxy, Proxy→dial-by-name).
    pub dns: DnsConfig,
}

/// The config's `options.dns` endpoints spark uses for per-action resolution: `dns_local` (direct DoH
/// — the Direct action's local resolver) and `dns_remote` (the Proxy client-side-resolution fallback).
/// Only IP-addressed `type: "https"` servers are captured (flint dials a fixed IP); hostname or
/// non-`https` servers are ignored. Data only; the `dns` engine builds resolvers from it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// `dns_local` — direct DoH; used to resolve a Direct flow's real (best-local) IP.
    pub local: Option<DohEndpoint>,
    /// `dns_remote` — used (alongside the resilient pool) for the Proxy client-side fallback.
    pub remote: Option<DohEndpoint>,
}

/// A DoH resolver endpoint: an IP-addressed HTTPS server (RFC 8484).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DohEndpoint {
    /// The resolver IP literal (flint dials this fixed address).
    pub server: String,
    /// The DoH port (443 unless overridden).
    #[serde(default = "default_doh_port")]
    pub port: u16,
    /// The DoH path (usually `/dns-query`).
    #[serde(default = "default_doh_path")]
    pub path: String,
}

/// The default DoH port when a [`DohEndpoint`] omits it.
fn default_doh_port() -> u16 {
    443
}

/// The default DoH path when a [`DohEndpoint`] omits it (also reused by the resolver builder to
/// normalize an explicitly-empty path — hence `pub(crate)`).
pub(crate) fn default_doh_path() -> String {
    "/dns-query".to_string()
}

/// Rule-based smart-routing + ad-block config. **Data only** — the (feature-gated) `rules` engine
/// loads the referenced `.srs` rule-sets and applies precedence; this just captures the refs and
/// inline IP rules the Lantern config declared. Distinct from [`RoutingConfig`] (OS route table).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmartRoutingConfig {
    /// Rule-sets to fetch/load and the action their matches produce (`ad_block` → Reject;
    /// `smart_routing` categories → their outbound's action). Precedence is applied by the engine.
    pub rule_sets: Vec<RuleSetRef>,
    /// Inline IP/CIDR rules from `options.route.rules` (e.g. Quad9 `9.9.9.9/32` → Direct).
    pub inline_ip_rules: Vec<InlineIpRule>,
}

/// A reference to a sing-box `.srs` rule-set and the action its matches produce.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RuleSetRef {
    /// The action a match yields.
    pub action: RouteAction,
    /// The rule-set tag (identifier from the config).
    pub tag: String,
    /// The `.srs` URL to fetch.
    pub url: String,
}

/// An inline IP/CIDR rule (raw CIDR text, parsed by the engine).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InlineIpRule {
    /// CIDR in `a.b.c.d/len` (or IPv6) text form.
    pub cidr: String,
    /// The action a match yields.
    pub action: RouteAction,
}

/// The routing action a rule yields — the config layer's always-compiled vocabulary; the
/// (feature-gated) engine maps it to its own action enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteAction {
    /// Through the proxy pool (the config's `route.final`) — the default.
    #[default]
    Proxy,
    /// Direct, bypassing the proxy.
    Direct,
    /// Drop the flow.
    Reject,
}

/// Whether spark takes over the routing table to capture all traffic (full-tunnel). Off by
/// default, leaving routing to the operator; when on, the service installs the split-default
/// covers on connect and restores/blackholes them on teardown (see [`crate::routing`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    /// When `true`, spark installs and tears down full-tunnel routes itself. Default `false`.
    pub manage: bool,
}

/// What happens to traffic if the tunnel drops unexpectedly. The product default is **fail
/// open** (restore direct routing, loudly) — see process-architecture-and-ipc.md §5.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KillSwitchConfig {
    /// When `true`, block traffic instead of falling back to direct routing (the per-profile
    /// fail-closed override). Default `false` = fail open.
    pub fail_closed: bool,
}

/// Which netstack terminates TCP from the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StackKind {
    /// Userspace smoltcp stack — cross-platform, the default.
    #[default]
    Userspace,
    /// Kernel-TCP "system" stack: a NAT redirect gateway to a local kernel listener (sing-box's
    /// `system`). Desktop-only (Linux/macOS) and requires the `system-stack` build feature; the
    /// build errors at startup if it's selected without the feature. See
    /// `docs/system-stack-design.md`.
    System,
}

/// TUN device settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunConfig {
    /// Requested device name (the OS may assign a different one). `None` = let the OS pick.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// IPv4 address assigned to the interface.
    pub addr: Ipv4Addr,
    /// IPv4 prefix length for the interface address.
    pub prefix: u8,
    /// MTU override; `None` uses the device default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Which netstack terminates TCP (`userspace` default, or `system`).
    pub stack: StackKind,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            addr: Ipv4Addr::new(10, 0, 0, 1),
            prefix: 24,
            mtu: None,
            stack: StackKind::default(),
        }
    }
}

/// How upstream traffic is reached.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)] // no Eq: contains ServerEntry (f64 lat/long)
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    /// Tunnel server address. When set, flows are tunneled through it; when `None`, flows
    /// are dialed directly to their original destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<SocketAddr>,
    /// Physical interface to pin upstream sockets to (e.g. `"en0"`), so the proxy's own
    /// dials bypass the tunnel route. Required on macOS to forward without a routing loop;
    /// `None` leaves sockets on the default route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_interface: Option<String>,
    /// AnyTLS transport (ADR 0001): when set, flows tunnel through this AnyTLS server over TLS,
    /// authenticated by the password. Takes precedence over the plain `server` tunnel. Requires
    /// the `anytls` build feature to take effect (else `from_config` errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anytls: Option<AnytlsConfig>,
    /// Dynamic wasm transport (ADR 0003): when set, flows tunnel through this spark server,
    /// obfuscated by a signed WebAssembly module. Takes precedence over the plain `server` tunnel
    /// (but `anytls`, if also set, wins). Requires the `wasm-transport` build feature to take effect
    /// (else `from_config` errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm: Option<WasmConfig>,
    /// Samizdat transport (ADR 0007): when set, flows tunnel through this Samizdat server as HTTP/2
    /// CONNECT streams over one Chrome-fingerprinted TLS session, authenticated by a REALITY-style
    /// SessionID in the TLS `legacy_session_id`. Takes precedence over the plain `server` tunnel.
    /// Requires the `samizdat` build feature (else `from_config` errors). TCP only (v1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub samizdat: Option<SamizdatConfig>,
    /// Shadowsocks 2022 transport (ADR 0009): when set, flows tunnel through this SS-2022 server.
    /// Takes precedence over the plain `server` tunnel. Requires the `shadowsocks` build feature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadowsocks: Option<ShadowsocksConfig>,
    /// Hysteria 2 transport (ADR 0010): when set, flows tunnel through this Hysteria 2 server over
    /// QUIC, optionally obfuscated with Salamander+Gecko. Requires the `hysteria2` build feature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hysteria2: Option<Hysteria2Config>,
    /// DNS-tunnel transport (ADR 0011): when set, flows tunnel over DNS, aggregating over recursive
    /// resolvers. Requires the `dns-tunnel` build feature (else `from_config` errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_tunnel: Option<DnsTunnelConfig>,
    /// Domain-fronted meek polling transport: tunnels through a CDN edge
    /// (Akamai/CloudFront/Aliyun) to Lantern's meek-server via the Shir-o-Khorshid
    /// CDN-fronting model (no MITM). Self-bootstrapping — discovers working edges
    /// from the user's own network, so all fields are optional and it can run with
    /// no other config. Requires the `fronted-meek` build feature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fronted_meek: Option<FrontedMeekConfig>,
    /// Opening-handshake shaping (ADR 0006 Phase 1): fragment the TLS ClientHello across TCP
    /// segments (e.g. at the SNI boundary) with optional inter-segment delay. Applies to the AnyTLS
    /// and Samizdat handshakes (both build their `WirePlan` from this). Default: no shaping.
    pub shaping: ShapingConfig,
    /// A pool of servers to probe and select among by latency (see
    /// `docs/multi-server-selection-design.md`). When non-empty, supersedes the single-transport
    /// fields above; spark builds a latency-selecting transport over the pool. Empty = the legacy
    /// single-transport path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<ServerEntry>,
    /// Default health-check URL fetched *through* each server to confirm it works end-to-end
    /// (per-entry `callback_url` overrides). Required when `servers` is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    /// Seconds between full pool re-probes.
    pub probe_interval_secs: u64,
    /// Max probes in flight at once (bounded concurrency for large pools).
    pub probe_window: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            server: None,
            protect_interface: None,
            anytls: None,
            wasm: None,
            samizdat: None,
            shadowsocks: None,
            hysteria2: None,
            dns_tunnel: None,
            fronted_meek: None,
            shaping: ShapingConfig::default(),
            servers: Vec::new(),
            callback_url: None,
            probe_interval_secs: 300,
            probe_window: 8,
        }
    }
}

/// Opening-handshake framing/timing (ADR 0006 Phase 1, genome Layer C). Shapes only the opening
/// write (the ClientHello); a default value does nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShapingConfig {
    /// `"none"`, `"sni_boundary"`, or comma-separated byte offsets (e.g. `"700,1400"`) into the
    /// opening write at which to split it into separate, flushed TCP segments.
    pub segment_split: String,
    /// Fixed delay between segments, in milliseconds (omit for none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
    /// Set `TCP_NODELAY` so each flushed segment leaves as its own packet.
    pub tcp_nodelay: bool,
}

impl Default for ShapingConfig {
    fn default() -> Self {
        Self {
            segment_split: "none".to_owned(),
            delay_ms: None,
            tcp_nodelay: true,
        }
    }
}

/// Dynamic wasm transport configuration (ADR 0003). The Ed25519 key that artifacts are verified
/// against is **pinned in the binary** at build time (not configured here), so a tampered config
/// can't swap in an attacker's signing key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmConfig {
    /// The spark server address to tunnel through.
    pub server: SocketAddr,
    /// Path to the signed module artifact (delivered out of band; see `wasm::ModuleVerifier`).
    pub module: PathBuf,
    /// Anti-rollback floor — reject a module whose version is below this. Default `0`.
    #[serde(default)]
    pub min_version: u32,
    /// Optional hex-encoded configuration bytes delivered to the module's `init` export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_config: Option<String>,
    /// Optional path to a persisted per-name version floor (a TOML `name = version` map). When set,
    /// the loaded version must also clear the persisted floor, and a successful load bumps it —
    /// anti-rollback that survives restarts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor_path: Option<PathBuf>,
}

/// The built-in meek endpoint used when `transport.fronted_meek.meek_host` is
/// unset. This is the inner host Akamai fronts route to. Single source of truth,
/// referenced by the transport and diagnostics.
pub const DEFAULT_FRONTED_MEEK_HOST: &str = "meek.dsa.akamai.getiantem.org";

/// Built-in inner hosts the CloudFront / Aliyun edges front to, used when the
/// corresponding config field is unset. Each CDN routes by a *different* inner
/// host (an Akamai host won't route through a CloudFront/Aliyun distribution), so
/// they can't share one value.
pub const DEFAULT_CLOUDFRONT_MEEK_HOST: &str = "d1hludsvicirbc.cloudfront.net";
pub const DEFAULT_ALIYUN_MEEK_HOST: &str = "meek-aliyun.getiantem.org";

/// Domain-fronted meek polling transport configuration. Every field is optional:
/// with an empty `[transport.fronted_meek]` table the transport self-bootstraps
/// (scans Akamai/CloudFront/Aliyun edges from the user's own network) and fronts
/// to the default Lantern meek endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontedMeekConfig {
    /// Inner host the Akamai edges route to. Empty → the built-in default
    /// (`meek.dsa.akamai.getiantem.org`).
    #[serde(default)]
    pub meek_host: String,
    /// Inner host the CloudFront edges route to. Empty → the built-in default
    /// (`d1hludsvicirbc.cloudfront.net`).
    #[serde(default)]
    pub cloudfront_host: String,
    /// Inner host the Aliyun edges route to. Empty → the built-in default
    /// (`meek-aliyun.getiantem.org`).
    #[serde(default)]
    pub aliyun_host: String,
    /// HTTP version over the fronted TLS connection. Unset → auto-select from the
    /// ALPN the edge negotiates (recommended). `"h1"` or `"h2"` force it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
}

/// AnyTLS transport configuration (ADR 0001).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnytlsConfig {
    /// The AnyTLS server address — `IP:port` or `host:port` (resolved at startup, see
    /// `docs/bootstrap-resolver-design.md`).
    pub server: Endpoint,
    /// The shared password — the auth secret (sent `sha256`'d on the wire).
    pub password: String,
    /// TLS SNI to present. When omitted: for a `host:port` server the bootstrap phase fills it with
    /// the hostname (before resolving it away); for an `IP:port` server the transport builder defaults
    /// it to the IP literal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Inline Layer-A ClientHello knobs (ADR 0006 P2 gambit genome). Default = the Chrome-137
    /// anchor (byte-identical to the prior hardcoded handshake). This is an operator-set *local*
    /// profile; signed, discovery-deployed gambits use the same vocabulary over a verified channel.
    #[serde(default)]
    pub clienthello: ClientHello,
    /// Inline Layer-B record-framing knobs (`size_limit`, `split_offsets`). Default = the anchor.
    #[serde(default)]
    pub records: Records,
    /// Optional Path-B module that **computes** a gambit per connection (ADR 0006 P3). When set, the
    /// inline `clienthello`/`records` knobs above become the *fallback* profile (used when the module
    /// faults or yields a gambit boring can't realize). Requires the `wasm-transport` feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gambit: Option<GambitModuleConfig>,
}

/// Samizdat transport configuration (ADR 0007). REALITY-style auth in the TLS `legacy_session_id`
/// plus an HTTP/2 CONNECT mux over one Chrome-fingerprinted TLS session; wire-interoperable with
/// deployed `lantern-box` `"samizdat"` servers. TCP only (v1) — see `docs/samizdat-transport-design.md`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamizdatConfig {
    /// The Samizdat server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// The server's X25519 public key, hex-encoded (32 bytes) — the HKDF IKM for the auth PSK.
    pub server_pubkey: String,
    /// The pre-shared short ID, hex-encoded (8 bytes).
    pub short_id: String,
    /// TLS SNI (cover-site name) to present. When omitted: for a `host:port` server the bootstrap
    /// phase fills it with the hostname (before resolving it away); for an `IP:port` server the
    /// transport builder defaults it to the IP literal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

/// The Shadowsocks 2022 (SIP022) methods spark implements. The `rename` values are the canonical
/// method names used by shadowsocks-rust / sing-box config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum SsMethod {
    /// `2022-blake3-aes-128-gcm` — 16-byte key/salt. TCP + UDP.
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm,
    /// `2022-blake3-aes-256-gcm` — 32-byte key/salt. TCP + UDP.
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm,
    /// `2022-blake3-chacha20-poly1305` — 32-byte key/salt. TCP only in v1 (UDP needs XChaCha20).
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Chacha20Poly1305,
}

impl SsMethod {
    /// PSK / session-subkey length in bytes (SIP022 §2.1).
    pub fn key_len(self) -> usize {
        match self {
            SsMethod::Aes128Gcm => 16,
            SsMethod::Aes256Gcm | SsMethod::Chacha20Poly1305 => 32,
        }
    }
    /// Per-stream random salt length — equal to the key length (SIP022 §2.2).
    pub fn salt_len(self) -> usize {
        self.key_len()
    }
    /// Whether this is an AES-GCM method (the UDP-capable family in v1).
    pub fn is_aes(self) -> bool {
        matches!(self, SsMethod::Aes128Gcm | SsMethod::Aes256Gcm)
    }
}

/// Shadowsocks 2022 (SIP022) transport configuration (ADR 0009). A pre-shared-key AEAD tunnel,
/// wire-interoperable with deployed shadowsocks-rust / sing-box SS-2022 servers. See
/// `docs/shadowsocks-design.md`. Requires the `shadowsocks` build feature (else `from_config` errors).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    /// The SS server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// The SS-2022 method (cipher); sets key/salt size and the AEAD construction.
    pub method: SsMethod,
    /// The pre-shared key, base64-encoded. Decoded length MUST equal `method.key_len()`.
    pub password: String,
}

/// DNS-tunnel transport configuration (ADR 0011). A clean-slate DNS-tunnelling protocol that
/// aggregates over many recursive resolvers for shutdown resilience. Requires the `dns-tunnel` build
/// feature (else `from_config` errors). See `docs/dns-tunnel-design.md`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsTunnelConfig {
    /// The delegated tunnel zone, e.g. `"t.example.com"`.
    pub zone: String,
    /// The server's static Ed25519 **public** key, base64 (from the server's `keygen`). Safe to
    /// distribute — it is not a secret; the forward-secret handshake authenticates the server with it
    /// and derives per-session keys from ephemeral↔ephemeral DH (so a leaked config can't decrypt
    /// traffic).
    pub server_pubkey: String,
    /// Recursive resolvers to spray queries across: `IP`, `IP:port`, `CIDR`, `CIDR:port`, `[v6]:port`
    /// (CIDRs expand to host IPs). Used in recursive mode.
    #[serde(default)]
    pub resolvers: Vec<String>,
    /// Optional: dial the authoritative server directly (authoritative mode / testing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoritative: Option<Endpoint>,
    /// AEAD cipher.
    #[serde(default)]
    pub cipher: DnsTunnelCipher,
    /// Payload compression. NB: parsed but **not yet applied by the client** — `dns-tunnel-core`
    /// supports LZ4 frame compression (`FLAG_COMPRESSED`), but the client transport does not yet drive
    /// it from this setting, so `lz4` is currently inert (a documented follow-up). Kept on the config
    /// surface so enabling it later is a client-only change.
    #[serde(default)]
    pub compression: DnsTunnelCompression,
    /// How many resolvers each query is sent to (default 1). Higher trades proportional bandwidth for
    /// delivery probability on lossy paths **and fast discovery of the working subset when most
    /// resolvers are blocked** — e.g. a national shutdown. Measured against a mostly-dead pool,
    /// time-to-first-byte was 27 s at 1 vs 0.3 s at 5 (serial failover → parallel probing). Set ~3–5
    /// for shutdown / last-resort profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplication: Option<usize>,
    /// Auto-include the OS-configured resolver(s) (`/etc/resolv.conf` on Unix) in the recursive pool.
    /// Default **true**: during a national shutdown the mandated local/ISP resolver is often the only
    /// one that still forwards DNS, so it's the lifeline. Ignored in authoritative mode. Set false to
    /// use only the configured `resolvers` (e.g. to avoid routing tunnel queries through the ISP's
    /// resolver when public resolvers are reachable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_system_resolvers: Option<bool>,
}

/// The AEAD cipher for the DNS-tunnel transport (ADR 0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum DnsTunnelCipher {
    /// ChaCha20-Poly1305 (default; constant-time in software, no AES-NI dependency).
    #[default]
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    /// AES-256-GCM.
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

/// Payload compression for the DNS-tunnel transport (ADR 0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum DnsTunnelCompression {
    /// No compression (default).
    #[default]
    #[serde(rename = "off")]
    Off,
    /// LZ4 via the pure-Rust `lz4_flex`.
    #[serde(rename = "lz4")]
    Lz4,
}

/// Hysteria 2 transport configuration (ADR 0010). A QUIC client interoperable with apernet/hysteria.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Config {
    /// Server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// `Hysteria-Auth` credential.
    pub auth: String,
    /// TLS SNI. When omitted: bootstrap fills it with the hostname; for an IP it defaults to the IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Client receive-rate hint sent as `Hysteria-CC-RX` (Mbps; 0 = unknown → server uses BBR).
    #[serde(default)]
    pub down_mbps: u32,
    /// TLS verification mode.
    #[serde(default)]
    pub tls: Hysteria2Tls,
    /// Optional Salamander/Gecko obfuscation. Omit for plain QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Tls {
    #[serde(default)]
    pub mode: Hysteria2TlsMode,
    /// Hex SHA-256 of the server cert; required when `mode = "pin-sha256"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hysteria2TlsMode {
    #[default]
    SystemRoots,
    PinSha256,
    Insecure,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Obfs {
    /// Obfuscation type. Only `salamander` is supported (Gecko is the `gecko` flag below, layered on
    /// Salamander); an unknown value is rejected at config-parse time.
    #[serde(rename = "type")]
    pub kind: Hysteria2ObfsType,
    /// Obfuscation pre-shared key.
    pub password: String,
    /// Wrap Salamander with Gecko handshake-fragmentation.
    #[serde(default)]
    pub gecko: bool,
}

/// The Hysteria 2 obfuscation type. Only Salamander exists in v1 (Gecko wraps it via the
/// [`Hysteria2Obfs::gecko`] flag, not a separate type). A strongly-typed enum so a misconfigured
/// `type` fails at parse time instead of silently behaving as Salamander.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hysteria2ObfsType {
    /// Salamander XOR obfuscation (Hysteria 2 spec §Salamander).
    Salamander,
}

/// The plain `tcp_tunnel` client kind for a pool entry — a tunnel server addressed by `server`,
/// with no extra mimicry (mirrors the legacy top-level `transport.server`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// The tunnel server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// TLS SNI is not applicable to the plain tunnel; present for symmetry, currently unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

/// One transport kind in a server pool, internally tagged by `kind` with the kind's fields flat
/// alongside it (e.g. `kind = "anytls"`, `server = ...`, `password = ...`). Wraps the existing
/// per-kind config structs so a pool entry is configured exactly like a single transport.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ServerSpec {
    /// AnyTLS-over-boring (ADR 0001).
    Anytls(AnytlsConfig),
    /// Samizdat (ADR 0007).
    Samizdat(SamizdatConfig),
    /// Dynamic wasm transport (ADR 0003).
    Wasm(WasmConfig),
    /// Plain `tcp_tunnel` client.
    Tunnel(TunnelConfig),
    /// Shadowsocks 2022 (ADR 0009).
    Shadowsocks(ShadowsocksConfig),
    /// Hysteria 2 (ADR 0010).
    Hysteria2(Hysteria2Config),
    /// Domain-fronted meek polling (Shir-o-Khorshid CDN-fronting). Renamed to `"meek"` so the pool
    /// `kind` matches the server-side protocol/outbound type and `spec_kind()` (the Rust variant stays
    /// `FrontedMeek` — the transport-impl name; only the wire/protocol identifier is `meek`). The
    /// `fronted-meek` alias keeps any native-TOML pools written under the pre-rename tag deserializable.
    #[serde(rename = "meek", alias = "fronted-meek")]
    FrontedMeek(FrontedMeekConfig),
    /// DNS-tunnel (ADR 0011).
    #[serde(rename = "dns-tunnel")]
    DnsTunnel(DnsTunnelConfig),
}

/// One server in the pool: a transport spec plus an optional per-entry callback override (falls back
/// to `transport.callback_url`). `#[serde(flatten)]` puts the spec's `kind` + fields and the
/// `callback_url` at the same TOML level. (`deny_unknown_fields` is incompatible with `flatten`.)
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)] // no Eq: f64 lat/long
pub struct ServerEntry {
    /// The transport kind + its config.
    #[serde(flatten)]
    pub spec: ServerSpec,
    /// Per-entry health-check URL; overrides `transport.callback_url` when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    /// Display metadata for the server-selection UI, surfaced via the selecting transport's
    /// `snapshot()`. All optional — absent fields fall back to the server address / "Tunnel" in the
    /// UI. This is the minimal Phase 2 subset; the full `config_raw.json` location shape (lat/long,
    /// outbound grouping) lands in Phase 3. Does not affect transport behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// Geographic coordinates (Phase 3, from `config_raw.json`'s `outbound_locations`) for the
    /// selection UI's map / distance hints. Optional; absent → the textual location is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
}

/// A signed Path-B module that computes a gambit per connection (ADR 0006 P3). Verified by the same
/// pinned module-signing key + anti-rollback floor as the byte-transform [`WasmConfig`] modules.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GambitModuleConfig {
    /// Path to the signed module artifact.
    pub module: PathBuf,
    /// Config anti-rollback floor — the artifact's version must be ≥ this.
    #[serde(default)]
    pub min_version: u32,
    /// Optional persisted per-module version floor (a `name = version` TOML map) for anti-rollback
    /// across restarts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor_path: Option<PathBuf>,
}

/// UDP forwarding settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpConfig {
    /// Seconds of inactivity before a UDP NAT association is reclaimed.
    pub idle_timeout_secs: u64,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 60,
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Log source/destination addresses (disables redaction). Off by default for hygiene.
    pub debug: bool,
}

/// Errors loading a [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("failed to read config file {path}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The TOML failed to parse or violated the schema.
    #[error("failed to parse TOML config")]
    Parse(#[from] toml::de::Error),
    /// A `config_raw.json` (Lantern API) payload failed to parse or adapt.
    #[error("failed to adapt config_raw.json: {0}")]
    ConfigRaw(#[from] lantern::ConfigRawError),
}

impl Config {
    /// Parse a [`Config`] from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    /// Parse a [`Config`] from either spark's native TOML or a Lantern `config_raw.json` payload,
    /// auto-detected: a JSON object carrying an `options.outbounds` array goes through the
    /// [`lantern`](crate::config::lantern) adapter; anything else through the TOML parser. The single
    /// entry point for an externally-supplied config string — [`from_path`](Self::from_path) (file),
    /// the `SPARK_CONFIG` env, and the Apple NE control channel all route through it, so every caller
    /// accepts both formats.
    pub fn from_config_str(s: &str) -> Result<Self, ConfigError> {
        if lantern::looks_like_config_raw(s) {
            Ok(lantern::from_config_raw_json(s)?)
        } else {
            Self::from_toml_str(s)
        }
    }

    /// Load a [`Config`] from a file — native TOML or a Lantern `config_raw.json`, auto-detected via
    /// [`from_config_str`](Self::from_config_str).
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        // Accept either native TOML or a Lantern config_raw.json file (auto-detected).
        Self::from_config_str(&contents)
    }

    /// Render this config back to TOML (used for round-trip tests and `--print-config`).
    pub fn to_toml_string(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// The first proxy `server` configured as a hostname needing resolution (`"host:port"`), or
    /// `None` if every configured server is an IP literal. Used to fail fast when a hostname is
    /// configured but the resolver wasn't built in (no `bootstrap-dns` feature). Scans both the
    /// single-transport fields and the multi-server pool.
    pub fn first_unresolved_host(&self) -> Option<String> {
        let singles = [
            self.transport.anytls.as_ref().map(|c| &c.server),
            self.transport.samizdat.as_ref().map(|c| &c.server),
            self.transport.shadowsocks.as_ref().map(|c| &c.server),
            self.transport.hysteria2.as_ref().map(|c| &c.server),
            // DNS-tunnel: the resolvers are IP literals (parsed by the balancer); only the optional
            // `authoritative` endpoint can be a hostname needing resolution.
            self.transport
                .dns_tunnel
                .as_ref()
                .and_then(|c| c.authoritative.as_ref()),
        ];
        let pool = self.transport.servers.iter().filter_map(|e| match &e.spec {
            ServerSpec::Anytls(c) => Some(&c.server),
            ServerSpec::Samizdat(c) => Some(&c.server),
            ServerSpec::Tunnel(c) => Some(&c.server),
            ServerSpec::Shadowsocks(c) => Some(&c.server),
            ServerSpec::Hysteria2(c) => Some(&c.server),
            ServerSpec::Wasm(_) => None, // wasm.server is a SocketAddr, never a hostname
            ServerSpec::FrontedMeek(_) => None, // self-bootstrapping; no server host to resolve
            ServerSpec::DnsTunnel(c) => c.authoritative.as_ref(), // resolvers are IP literals
        });
        singles
            .into_iter()
            .flatten()
            .chain(pool)
            .find_map(|ep| ep.unresolved().map(|(h, p)| format!("{h}:{p}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_toml_yields_defaults() {
        assert_eq!(Config::from_toml_str("").unwrap(), Config::default());
    }

    #[test]
    fn defaults_are_the_documented_values() {
        let c = Config::default();
        assert_eq!(c.tun.addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(c.tun.prefix, 24);
        assert_eq!(c.tun.name, None);
        assert_eq!(c.tun.mtu, None);
        assert_eq!(c.transport.server, None);
        assert_eq!(c.udp.idle_timeout_secs, 60);
        assert!(!c.log.debug);
    }

    #[test]
    fn parses_a_full_config() {
        let c = Config::from_toml_str(
            r#"
            [tun]
            name = "tun0"
            addr = "10.9.8.1"
            prefix = 30
            mtu = 1400

            [transport]
            server = "192.0.2.1:8388"

            [udp]
            idle_timeout_secs = 120

            [log]
            debug = true
        "#,
        )
        .unwrap();
        assert_eq!(c.tun.name.as_deref(), Some("tun0"));
        assert_eq!(c.tun.addr, Ipv4Addr::new(10, 9, 8, 1));
        assert_eq!(c.tun.prefix, 30);
        assert_eq!(c.tun.mtu, Some(1400));
        assert_eq!(c.transport.server, Some("192.0.2.1:8388".parse().unwrap()));
        assert_eq!(c.udp.idle_timeout_secs, 120);
        assert!(c.log.debug);
    }

    #[test]
    fn round_trips_through_toml() {
        for cfg in [
            Config::default(),
            Config {
                tun: TunConfig {
                    name: Some("utun7".into()),
                    addr: Ipv4Addr::new(172, 16, 0, 1),
                    prefix: 16,
                    mtu: Some(1280),
                    stack: StackKind::System,
                },
                transport: TransportConfig {
                    server: Some("[2001:db8::1]:443".parse().unwrap()),
                    protect_interface: Some("en0".into()),
                    anytls: None,
                    samizdat: None,
                    shadowsocks: None,
                    hysteria2: None,
                    dns_tunnel: None,
                    fronted_meek: None,
                    wasm: Some(WasmConfig {
                        server: "192.0.2.9:443".parse().unwrap(),
                        module: PathBuf::from("/etc/spark/obfs.spkw"),
                        min_version: 7,
                        init_config: Some("deadbeef".into()),
                        floor_path: Some(PathBuf::from("/var/lib/spark/floors.toml")),
                    }),
                    shaping: ShapingConfig {
                        segment_split: "sni_boundary".into(),
                        delay_ms: Some(12),
                        tcp_nodelay: true,
                    },
                    servers: Vec::new(),
                    callback_url: None,
                    probe_interval_secs: 300,
                    probe_window: 8,
                },
                udp: UdpConfig {
                    idle_timeout_secs: 30,
                },
                routing: RoutingConfig { manage: true },
                kill_switch: KillSwitchConfig { fail_closed: true },
                log: LogConfig { debug: true },
                smart_routing: SmartRoutingConfig {
                    rule_sets: vec![RuleSetRef {
                        action: RouteAction::Reject,
                        tag: "ads".into(),
                        url: "https://x/ads.srs".into(),
                    }],
                    inline_ip_rules: vec![InlineIpRule {
                        cidr: "9.9.9.9/32".into(),
                        action: RouteAction::Direct,
                    }],
                },
                dns: DnsConfig {
                    local: Some(DohEndpoint {
                        server: "9.9.9.9".into(),
                        port: 443,
                        path: "/dns-query".into(),
                    }),
                    remote: None,
                },
            },
        ] {
            let rendered = cfg.to_toml_string().unwrap();
            let parsed = Config::from_toml_str(&rendered).unwrap();
            assert_eq!(parsed, cfg, "round-trip changed the config:\n{rendered}");
        }
    }

    #[test]
    fn parses_a_wasm_transport_config() {
        let c = Config::from_toml_str(
            r#"
            [transport.wasm]
            server = "192.0.2.1:443"
            module = "/etc/spark/obfs.spkw"
            min_version = 9
        "#,
        )
        .unwrap();
        let wasm = c.transport.wasm.expect("wasm config");
        assert_eq!(wasm.server, "192.0.2.1:443".parse().unwrap());
        assert_eq!(wasm.module, PathBuf::from("/etc/spark/obfs.spkw"));
        assert_eq!(wasm.min_version, 9);
        assert_eq!(wasm.init_config, None);
        assert_eq!(wasm.floor_path, None);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::from_toml_str("[tun]\nbogus = 1\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn parses_samizdat_config() {
        let c = Config::from_toml_str(
            r#"
            [transport.samizdat]
            server = "192.0.2.1:443"
            server_pubkey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            short_id = "1011121314151617"
            sni = "ok.example"
        "#,
        )
        .unwrap();
        let s = c.transport.samizdat.expect("samizdat config");
        assert_eq!(s.server, "192.0.2.1:443".parse().unwrap());
        assert_eq!(s.server_pubkey.len(), 64); // 32 bytes, hex
        assert_eq!(s.short_id, "1011121314151617");
        assert_eq!(s.sni.as_deref(), Some("ok.example"));
    }

    #[test]
    fn parses_inline_anytls_gambit_knobs() {
        use flint_tls::gambit::EchMode;
        let c = Config::from_toml_str(
            r#"
            [transport.anytls]
            server = "192.0.2.1:443"
            password = "hunter2"
            sni = "www.example.com"

            [transport.anytls.clienthello]
            ech = "off"
            pq_kem = false

            [transport.anytls.records]
            size_limit = 1300
        "#,
        )
        .unwrap();
        let anytls = c.transport.anytls.expect("anytls config");
        assert_eq!(anytls.clienthello.ech, Some(EchMode::Off));
        assert_eq!(anytls.clienthello.pq_kem, Some(false));
        assert_eq!(anytls.records.size_limit, Some(1300));
        // An omitted gambit section defaults to the Chrome-137 anchor (all-None).
        assert_eq!(anytls.clienthello.alps, None);
        // No dynamic gambit module unless explicitly configured.
        assert!(anytls.gambit.is_none());
    }

    #[test]
    fn parses_anytls_dynamic_gambit_module() {
        let c = Config::from_toml_str(
            r#"
            [transport.anytls]
            server = "192.0.2.1:443"
            password = "pw"

            [transport.anytls.gambit]
            module = "/etc/spark/opening.spkw"
            min_version = 4
        "#,
        )
        .unwrap();
        let g = c
            .transport
            .anytls
            .expect("anytls")
            .gambit
            .expect("gambit module");
        assert_eq!(g.module, PathBuf::from("/etc/spark/opening.spkw"));
        assert_eq!(g.min_version, 4);
        assert_eq!(g.floor_path, None);
    }

    #[test]
    fn endpoint_parses_ip_and_host() {
        assert_eq!(
            "1.2.3.4:443".parse::<Endpoint>().unwrap(),
            Endpoint::Ip("1.2.3.4:443".parse().unwrap())
        );
        assert_eq!(
            "[2001:db8::1]:443".parse::<Endpoint>().unwrap(),
            Endpoint::Ip("[2001:db8::1]:443".parse().unwrap())
        );
        assert_eq!(
            "proxy.example.com:443".parse::<Endpoint>().unwrap(),
            Endpoint::Host {
                host: "proxy.example.com".into(),
                port: 443
            }
        );
        // junk: no port, empty host, or non-numeric port.
        assert!("notanaddress".parse::<Endpoint>().is_err());
        assert!(":443".parse::<Endpoint>().is_err());
        assert!("host:notaport".parse::<Endpoint>().is_err());
        // a stray `:` in the host (unbracketed IPv6 or a double-port typo) is rejected at parse time.
        assert!("2001:db8::1:443".parse::<Endpoint>().is_err());
        assert!("host:443:80".parse::<Endpoint>().is_err());
        // whitespace in the host is an invalid hostname, rejected at parse time.
        assert!(" proxy.example.com:443".parse::<Endpoint>().is_err());
        assert!("proxy.example.com :443".parse::<Endpoint>().is_err());
    }

    #[test]
    fn endpoint_socket_addr_and_unresolved() {
        let ip: Endpoint = "1.2.3.4:443".parse().unwrap();
        assert_eq!(ip.socket_addr().unwrap(), "1.2.3.4:443".parse().unwrap());
        assert_eq!(ip.unresolved(), None);

        let host: Endpoint = "h.example:80".parse().unwrap();
        assert!(host.socket_addr().is_err());
        assert_eq!(host.unresolved(), Some(("h.example", 80)));
    }

    #[test]
    fn endpoint_serde_round_trips() {
        // Endpoint serializes/deserializes as a single string, for both variants. Tested directly
        // and via the anytls.server field (now an Endpoint).
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            e: Endpoint,
        }
        for s in ["1.2.3.4:443", "proxy.example.com:8443"] {
            let w = W {
                e: s.parse().unwrap(),
            };
            let toml = toml::to_string(&w).unwrap();
            let back: W = toml::from_str(&toml).unwrap();
            assert_eq!(w, back, "round-trip changed:\n{toml}");
        }
    }

    #[test]
    fn doh_endpoint_defaults_port_and_path() {
        // Only `server` given: port and path fall back to their defaults.
        let bare: DohEndpoint = toml::from_str("server = \"9.9.9.9\"").unwrap();
        assert_eq!(
            bare,
            DohEndpoint {
                server: "9.9.9.9".into(),
                port: 443,
                path: "/dns-query".into(),
            }
        );
        // Explicit values override the defaults.
        let full: DohEndpoint =
            toml::from_str("server = \"1.1.1.1\"\nport = 8443\npath = \"/resolve\"").unwrap();
        assert_eq!(full.port, 8443);
        assert_eq!(full.path, "/resolve");
        // Unknown fields are rejected (consistent with the other config structs).
        assert!(toml::from_str::<DohEndpoint>("server = \"9.9.9.9\"\nbogus = true").is_err());
    }

    #[test]
    fn first_unresolved_host_finds_a_hostname() {
        let c = Config::from_toml_str(
            "[transport.anytls]\nserver = \"proxy.example.com:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(
            c.first_unresolved_host().as_deref(),
            Some("proxy.example.com:443")
        );

        let c2 = Config::from_toml_str(
            "[transport.anytls]\nserver = \"1.2.3.4:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(c2.first_unresolved_host(), None);
    }

    #[test]
    fn shadowsocks_method_sizes() {
        assert_eq!(SsMethod::Aes128Gcm.key_len(), 16);
        assert_eq!(SsMethod::Aes128Gcm.salt_len(), 16);
        assert_eq!(SsMethod::Aes256Gcm.key_len(), 32);
        assert!(SsMethod::Aes256Gcm.is_aes());
        assert_eq!(SsMethod::Chacha20Poly1305.key_len(), 32);
        assert!(!SsMethod::Chacha20Poly1305.is_aes());
    }

    #[test]
    fn hysteria2_config_round_trips_through_toml() {
        let toml = r#"
[transport.hysteria2]
server = "proxy.example.com:443"
auth = "secret"

[transport.hysteria2.obfs]
type = "salamander"
password = "obfskey"
gecko = true
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let h = cfg.transport.hysteria2.clone().unwrap();
        assert_eq!(h.server, "proxy.example.com:443".parse().unwrap());
        assert_eq!(h.auth, "secret");
        let obfs = h.obfs.unwrap();
        assert_eq!(obfs.kind, Hysteria2ObfsType::Salamander);
        assert_eq!(obfs.password, "obfskey");
        assert!(obfs.gecko);
        assert!(matches!(h.tls.mode, Hysteria2TlsMode::SystemRoots)); // default
    }

    #[test]
    fn hysteria2_rejects_unknown_obfs_type() {
        // An unknown obfs `type` must fail at parse time, not silently behave as Salamander.
        let toml = "[transport.hysteria2]\nserver = \"1.2.3.4:443\"\nauth = \"x\"\n\n\
                    [transport.hysteria2.obfs]\ntype = \"bogus\"\npassword = \"k\"\n";
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    fn shadowsocks_config_round_trips_through_toml() {
        let toml = r#"
[transport.shadowsocks]
server = "1.2.3.4:8388"
method = "2022-blake3-aes-256-gcm"
password = "c29tZS1iYXNlNjQtcHNr"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let ss = cfg.transport.shadowsocks.clone().unwrap();
        assert_eq!(ss.server, "1.2.3.4:8388".parse().unwrap());
        assert_eq!(ss.method, SsMethod::Aes256Gcm);
        assert_eq!(ss.password, "c29tZS1iYXNlNjQtcHNr");
        let out = cfg.to_toml_string().unwrap();
        assert!(out.contains("2022-blake3-aes-256-gcm"));
    }

    #[test]
    fn dns_tunnel_config_round_trips_through_toml() {
        let toml = r#"
[transport.dns_tunnel]
zone = "t.example.com"
server_pubkey = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
resolvers = ["1.1.1.1", "8.8.8.8:53", "9.9.9.0/30"]
cipher = "aes-256-gcm"
compression = "lz4"
duplication = 3
use_system_resolvers = false
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let dt = cfg.transport.dns_tunnel.clone().unwrap();
        assert_eq!(dt.zone, "t.example.com");
        assert_eq!(dt.resolvers.len(), 3);
        assert_eq!(dt.cipher, DnsTunnelCipher::Aes256Gcm);
        assert_eq!(dt.compression, DnsTunnelCompression::Lz4);
        assert_eq!(dt.duplication, Some(3));
        assert_eq!(dt.use_system_resolvers, Some(false));
        assert!(dt.authoritative.is_none());
        let out = cfg.to_toml_string().unwrap();
        assert!(out.contains("aes-256-gcm"));
    }

    #[test]
    fn dns_tunnel_config_defaults_cipher_and_compression() {
        let toml = r#"
[transport.dns_tunnel]
zone = "t.example.com"
server_pubkey = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
authoritative = "127.0.0.1:5300"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let dt = cfg.transport.dns_tunnel.clone().unwrap();
        assert_eq!(
            dt.cipher,
            DnsTunnelCipher::ChaCha20Poly1305,
            "default cipher"
        );
        assert_eq!(
            dt.compression,
            DnsTunnelCompression::Off,
            "default: no compression"
        );
        assert!(dt.resolvers.is_empty());
        assert!(dt.authoritative.is_some());
    }

    #[test]
    fn parses_a_shadowsocks_pool_entry() {
        let c = Config::from_toml_str(
            "[transport]\ncallback_url = \"http://127.0.0.1/ok\"\n\n[[transport.servers]]\nkind = \"shadowsocks\"\nserver = \"1.2.3.4:8388\"\nmethod = \"2022-blake3-aes-128-gcm\"\npassword = \"MTIzNDU2Nzg5MDEyMzQ1Ng==\"\n",
        )
        .unwrap();
        match &c.transport.servers[0].spec {
            ServerSpec::Shadowsocks(ss) => {
                assert_eq!(ss.method, SsMethod::Aes128Gcm);
                assert_eq!(ss.server, "1.2.3.4:8388".parse().unwrap());
            }
            other => panic!("expected a shadowsocks pool entry, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_dns_tunnel_pool_entry() {
        let c = Config::from_toml_str(
            "[[transport.servers]]\nkind = \"dns-tunnel\"\nzone = \"t.example.com\"\nserver_pubkey = \"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=\"\nresolvers = [\"1.1.1.1\", \"8.8.8.8\"]\n",
        )
        .unwrap();
        match &c.transport.servers[0].spec {
            ServerSpec::DnsTunnel(dt) => {
                assert_eq!(dt.zone, "t.example.com");
                assert_eq!(dt.resolvers.len(), 2);
            }
            other => panic!("expected a dns-tunnel pool entry, got {other:?}"),
        }
    }

    #[test]
    fn first_unresolved_host_scans_the_pool() {
        let c = Config::from_toml_str(
            "[transport]\ncallback_url = \"http://127.0.0.1/ok\"\n\n[[transport.servers]]\nkind = \"tunnel\"\nserver = \"pool-host.example:443\"\n",
        )
        .unwrap();
        assert_eq!(
            c.first_unresolved_host().as_deref(),
            Some("pool-host.example:443")
        );
        // an all-IP pool has nothing unresolved.
        let c2 = Config::from_toml_str(
            "[transport]\ncallback_url = \"http://127.0.0.1/ok\"\n\n[[transport.servers]]\nkind = \"tunnel\"\nserver = \"1.2.3.4:443\"\n",
        )
        .unwrap();
        assert_eq!(c2.first_unresolved_host(), None);
    }

    #[test]
    fn parses_a_server_pool_with_callbacks_and_knobs() {
        let c = Config::from_toml_str(
            r#"
            [transport]
            callback_url = "https://canary.example/generate_204"
            probe_interval_secs = 120
            probe_window = 4

            [[transport.servers]]
            kind = "anytls"
            server = "proxy-a.example.com:443"
            password = "pw"

            [[transport.servers]]
            kind = "samizdat"
            server = "203.0.113.7:443"
            server_pubkey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            short_id = "1011121314151617"
            callback_url = "https://other.example/ok"
            "#,
        )
        .unwrap();
        assert_eq!(
            c.transport.callback_url.as_deref(),
            Some("https://canary.example/generate_204")
        );
        assert_eq!(c.transport.probe_interval_secs, 120);
        assert_eq!(c.transport.probe_window, 4);
        let servers = &c.transport.servers;
        assert_eq!(servers.len(), 2);
        assert!(matches!(servers[0].spec, ServerSpec::Anytls(_)));
        assert_eq!(servers[0].callback_url, None); // falls back to the global default
        assert_eq!(
            servers[1].callback_url.as_deref(),
            Some("https://other.example/ok")
        );
    }

    #[test]
    fn pool_defaults_when_absent() {
        let c = Config::default();
        assert!(c.transport.servers.is_empty());
        assert_eq!(c.transport.probe_interval_secs, 300);
        assert_eq!(c.transport.probe_window, 8);
        assert_eq!(c.transport.callback_url, None);
    }

    #[test]
    fn server_spec_parses_each_kind() {
        // internally-tagged by `kind`, flat fields.
        let anytls: ServerSpec =
            toml::from_str("kind = \"anytls\"\nserver = \"1.2.3.4:443\"\npassword = \"pw\"\n")
                .unwrap();
        assert!(matches!(anytls, ServerSpec::Anytls(_)));
        let tunnel: ServerSpec =
            toml::from_str("kind = \"tunnel\"\nserver = \"5.6.7.8:443\"\n").unwrap();
        assert!(matches!(tunnel, ServerSpec::Tunnel(_)));
        // unknown kind is rejected.
        assert!(toml::from_str::<ServerSpec>("kind = \"bogus\"\n").is_err());
    }

    #[test]
    fn anytls_host_server_round_trips_through_toml() {
        for s in ["1.2.3.4:443", "proxy.example.com:8443"] {
            let toml = format!("[transport.anytls]\nserver = \"{s}\"\npassword = \"pw\"\n");
            let c = Config::from_toml_str(&toml).unwrap();
            let rendered = c.to_toml_string().unwrap();
            let back = Config::from_toml_str(&rendered).unwrap();
            assert_eq!(c, back, "round-trip changed:\n{rendered}");
        }
        // And the hostname actually lands as Endpoint::Host.
        let c = Config::from_toml_str(
            "[transport.anytls]\nserver = \"proxy.example.com:8443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(
            c.transport.anytls.unwrap().server,
            Endpoint::Host {
                host: "proxy.example.com".into(),
                port: 8443
            }
        );
    }

    #[test]
    fn parses_server_location_metadata() {
        // The per-entry location fields (Phase 2) sit alongside the flattened spec. This also guards
        // that TunnelConfig's deny_unknown_fields doesn't reject them (they're consumed by
        // ServerEntry, not the flattened spec).
        let toml = "\
[transport]
callback_url = \"http://127.0.0.1/ok\"

[[transport.servers]]
kind = \"tunnel\"
server = \"144.126.208.126:9000\"
callback_url = \"http://144.126.208.126:8080/\"
name = \"sfo3\"
country = \"United States\"
country_code = \"US\"
city = \"San Francisco\"
";
        let c = Config::from_toml_str(toml).unwrap();
        let s = &c.transport.servers[0];
        assert!(matches!(s.spec, ServerSpec::Tunnel(_)));
        assert_eq!(s.name.as_deref(), Some("sfo3"));
        assert_eq!(s.country.as_deref(), Some("United States"));
        assert_eq!(s.country_code.as_deref(), Some("US"));
        assert_eq!(s.city.as_deref(), Some("San Francisco"));
        // The optional fields round-trip through serialization.
        let back = Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
        assert_eq!(c, back);
    }
}
