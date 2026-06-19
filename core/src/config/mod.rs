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
    /// The AnyTLS server address.
    pub server: SocketAddr,
    /// The shared password — the auth secret (sent `sha256`'d on the wire).
    pub password: String,
    /// TLS SNI to present; defaults to the server's IP literal when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
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
}
