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
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
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
    /// Opening-handshake shaping (ADR 0006 Phase 1): fragment the TLS ClientHello across TCP
    /// segments (e.g. at the SNI boundary) with optional inter-segment delay. Applies to the AnyTLS
    /// handshake. Default: no shaping.
    pub shaping: ShapingConfig,
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
}

impl Config {
    /// Parse a [`Config`] from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    /// Load a [`Config`] from a TOML file.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&contents)
    }

    /// Render this config back to TOML (used for round-trip tests and `--print-config`).
    pub fn to_toml_string(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// The first proxy `server` configured as a hostname needing resolution (`"host:port"`), or
    /// `None` if every configured server is an IP literal. Used to fail fast when a hostname is
    /// configured but the resolver wasn't built in (no `bootstrap-dns` feature).
    pub fn first_unresolved_host(&self) -> Option<String> {
        let servers = [
            self.transport.anytls.as_ref().map(|c| &c.server),
            self.transport.samizdat.as_ref().map(|c| &c.server),
        ];
        servers
            .into_iter()
            .flatten()
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
                },
                udp: UdpConfig {
                    idle_timeout_secs: 30,
                },
                routing: RoutingConfig { manage: true },
                kill_switch: KillSwitchConfig { fail_closed: true },
                log: LogConfig { debug: true },
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
    fn server_spec_parses_each_kind() {
        // internally-tagged by `kind`, flat fields.
        let anytls: ServerSpec = toml::from_str("kind = \"anytls\"\nserver = \"1.2.3.4:443\"\npassword = \"pw\"\n").unwrap();
        assert!(matches!(anytls, ServerSpec::Anytls(_)));
        let tunnel: ServerSpec = toml::from_str("kind = \"tunnel\"\nserver = \"5.6.7.8:443\"\n").unwrap();
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
}
