//! Data-path config resolution, mirroring the Flutter NEBackend precedence
//! (newest wins): a runtime `config.toml` in the app-support dir → the baked
//! `SPARK_CONFIG` (base64 TOML) → `SPARK_PROXY` (host:port) → None (direct).
//!
//! The resolved string is handed to the system extension via
//! `providerConfiguration["config"]`; the extension's C ABI (`spark_tunnel_run`)
//! decodes it (TOML, base64-TOML, or a bare host:port) exactly as it does for
//! the Flutter app, so this layer stays a passthrough.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One server for the selection UI. Serializes to the camelCase shape the TS `ServerInfo` expects,
/// and deserializes the live pool JSON from the NE channel (`spark_servers_json`) — so the same type
/// carries both the static (config-derived) list and the live overlay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    #[serde(default)]
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(
        rename = "countryCode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(rename = "latencyMs", default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub healthy: bool,
    #[serde(rename = "isCurrent", default)]
    pub is_current: bool,
}

/// The pool's servers parsed from the resolved `config.toml` — the static list (metadata only, no
/// latency), available without a running tunnel. Empty when the config is absent, a bare `host:port`,
/// base64 (the NE decodes that form, not us), or has no `[[transport.servers]]`. Order matches the
/// core's pool index, so a live snapshot overlays by `index`.
pub fn servers_from_config() -> Vec<ServerInfo> {
    let Some(text) = resolve() else {
        return Vec::new();
    };
    #[derive(Deserialize)]
    struct Root {
        transport: Option<Transport>,
    }
    #[derive(Deserialize)]
    struct Transport {
        #[serde(default)]
        servers: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        name: Option<String>,
        country: Option<String>,
        country_code: Option<String>,
        city: Option<String>,
    }
    let root: Root = match toml::from_str(&text) {
        Ok(r) => r,
        Err(_) => return Vec::new(), // host:port / base64 / invalid → no static list
    };
    root.transport
        .map(|t| t.servers)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, e)| ServerInfo {
            index: i,
            name: e.name,
            country: e.country,
            country_code: e.country_code,
            city: e.city,
            latency_ms: None,
            healthy: false,
            is_current: false,
        })
        .collect()
}

/// macOS app-support config path: `~/Library/Application Support/org.getlantern.spark/config.toml`.
pub fn config_file_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Application Support/org.getlantern.spark/config.toml"))
}

/// Resolve the data-path config string, or None for a direct (untunneled) run.
pub fn resolve() -> Option<String> {
    resolve_with(
        config_file_path().and_then(|p| std::fs::read_to_string(p).ok()),
        std::env::var("SPARK_CONFIG").ok(),
        std::env::var("SPARK_PROXY").ok(),
    )
}

/// Pure precedence logic, split out so it's unit-testable without touching the
/// filesystem or environment. First non-empty wins, in NEBackend order.
fn resolve_with(
    file: Option<String>,
    baked: Option<String>,
    proxy: Option<String>,
) -> Option<String> {
    [file, baked, proxy]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::resolve_with;

    #[test]
    fn file_wins_over_everything() {
        let r = resolve_with(
            Some("  toml-from-file  ".into()),
            Some("baked".into()),
            Some("1.2.3.4:443".into()),
        );
        assert_eq!(r.as_deref(), Some("toml-from-file"));
    }

    #[test]
    fn baked_wins_when_no_file() {
        let r = resolve_with(None, Some("baked".into()), Some("1.2.3.4:443".into()));
        assert_eq!(r.as_deref(), Some("baked"));
    }

    #[test]
    fn proxy_is_last_resort() {
        let r = resolve_with(None, None, Some("1.2.3.4:443".into()));
        assert_eq!(r.as_deref(), Some("1.2.3.4:443"));
    }

    #[test]
    fn empty_and_whitespace_are_skipped() {
        // an empty/whitespace file falls through to the baked config
        let r = resolve_with(Some("   ".into()), Some("baked".into()), None);
        assert_eq!(r.as_deref(), Some("baked"));
    }

    #[test]
    fn none_means_direct() {
        assert_eq!(resolve_with(None, None, None), None);
        assert_eq!(resolve_with(Some(String::new()), None, None), None);
    }
}
