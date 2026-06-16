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
use std::path::Path;

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
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            addr: Ipv4Addr::new(10, 0, 0, 1),
            prefix: 24,
            mtu: None,
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
                },
                transport: TransportConfig {
                    server: Some("[2001:db8::1]:443".parse().unwrap()),
                    protect_interface: Some("en0".into()),
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
    fn unknown_keys_are_rejected() {
        let err = Config::from_toml_str("[tun]\nbogus = 1\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }
}
