//! Data-path config resolution for the controlling app.
//!
//! **The daemon (the NE system extension) owns config acquisition.** When the app supplies no
//! explicit config, the extension self-fetches its server pool from the Lantern config-new API
//! (`spark_tunnel_run`'s default on the `config-fetch` slice) — the fetch must bypass the tunnel and
//! only the extension can guarantee that, so the decision lives there, not here. This resolver is
//! therefore a thin passthrough that carries only **deliberate dev overrides**: the baked
//! `SPARK_CONFIG` (base64 TOML) → `SPARK_PROXY` (host:port) → `None`. `None` is the normal path: it
//! hands the extension no `providerConfiguration["config"]`, which it reads as "fetch it yourself".
//!
//! Note there is intentionally no persistent on-disk config file here anymore: a stale local file
//! would shadow the fetch (every connect must pull the current pool), so the only on-disk config is
//! the extension's own last-good fetch cache, used solely as an offline fallback.

use serde::{Deserialize, Serialize};

/// One server for the selection UI. Serializes to the camelCase shape the TS `ServerInfo` expects,
/// and deserializes the live pool JSON from the NE channel (`spark_servers_json`) — so the same type
/// carries both the static (config-derived) list and the live overlay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    // Required (no `serde(default)`): `index` is the handle the live overlay matches on and that the
    // UI passes back to `spark_select_server`, so a reply missing it must fail `from_str` (handled as
    // non-fatal by the caller) rather than silently deserialize to 0 and overlay/pin the wrong member.
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

/// The static pool list parsed from an explicit TOML dev override (`resolve()`), metadata only (no
/// latency), available without a running tunnel. Empty in the normal (daemon-fetch) path — the pool
/// is only known after the extension fetches it, so the live snapshot fills the UI on connect — and
/// also empty for a bare `host:port`, base64 `SPARK_CONFIG` (the NE decodes that form, not us), or a
/// config with no `[[transport.servers]]`. Order matches the core's pool index for the overlay.
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

/// Resolve a deliberate dev override config string, or `None` for the normal **daemon-fetch** path.
/// `None` is handed to the extension as no `providerConfiguration["config"]`, which it reads as
/// "self-fetch the pool" (see the module docs). Only explicit env overrides bypass the fetch.
pub fn resolve() -> Option<String> {
    resolve_with(
        std::env::var("SPARK_CONFIG").ok(),
        std::env::var("SPARK_PROXY").ok(),
    )
}

/// Pure precedence logic, split out so it's unit-testable without touching the environment. First
/// non-empty wins (`SPARK_CONFIG` over `SPARK_PROXY`); all-empty → `None` (daemon self-fetches).
fn resolve_with(baked: Option<String>, proxy: Option<String>) -> Option<String> {
    [baked, proxy]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::resolve_with;

    #[test]
    fn baked_wins_over_proxy() {
        let r = resolve_with(Some("baked".into()), Some("1.2.3.4:443".into()));
        assert_eq!(r.as_deref(), Some("baked"));
    }

    #[test]
    fn proxy_is_last_resort() {
        let r = resolve_with(None, Some("1.2.3.4:443".into()));
        assert_eq!(r.as_deref(), Some("1.2.3.4:443"));
    }

    #[test]
    fn empty_and_whitespace_are_skipped() {
        // an empty/whitespace baked override falls through to the proxy
        let r = resolve_with(Some("   ".into()), Some("1.2.3.4:443".into()));
        assert_eq!(r.as_deref(), Some("1.2.3.4:443"));
    }

    #[test]
    fn none_means_daemon_fetch() {
        // No explicit override → None → the extension self-fetches its config.
        assert_eq!(resolve_with(None, None), None);
        assert_eq!(resolve_with(Some(String::new()), None), None);
    }
}
