//! Pure parser: a fetched `config_raw.json` body (Lantern shape) → the static location list.
//! Used by the **app-side** cache reads that resolve the cache dir directly: macOS `AppleControl`
//! today, and (Phase 2c) the iOS app, which both read their app-group container. Android is the
//! exception — its main process can't reliably resolve the `:vpn` process's `filesDir`, and it
//! shouldn't load the native lib, so Android parses the cache **core-side in the `:vpn` process**
//! (via a JNI entry) and returns it over the existing `servers` IPC; see the Phase 2b plan. No I/O,
//! no platform deps — trivially unit-tested on every target.

use crate::models::ServerInfo;

/// Parse `config_raw.json`'s top-level `servers[]` geo entries into `ServerInfo`, indexed by
/// position (matching the live-pool ordering). Invalid/empty JSON → an empty list. No live fields are
/// invented: `protocol`/`latency_ms` are `None`, `healthy`/`is_current` are `false` — those come from
/// the NE/core snapshot only when connected.
pub(crate) fn servers_from_cache_json(raw: &str) -> Vec<ServerInfo> {
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Root {
        #[serde(default)]
        servers: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        country: Option<String>,
        // Accept both spellings: the config-new payload uses snake_case, but the camelCase
        // `countryCode` is used on the control-channel ServerInfo, so alias it to avoid silently
        // dropping the code if a backend emits camelCase here too.
        #[serde(alias = "countryCode")]
        country_code: Option<String>,
        city: Option<String>,
    }
    let root: Root = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    root.servers
        .into_iter()
        .enumerate()
        .map(|(i, e)| ServerInfo {
            index: i,
            name: None,
            country: e.country,
            country_code: e.country_code,
            city: e.city,
            protocol: None,
            latency_ms: None,
            healthy: false,
            is_current: false,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::servers_from_cache_json;

    #[test]
    fn parses_top_level_servers_geo_into_serverinfo() {
        let raw = r#"{
            "servers": [
                {"country": "U.S.A.", "country_code": "US", "city": "Ashburn", "latitude": 1.0, "longitude": 2.0},
                {"country": "Germany", "country_code": "DE", "city": "Frankfurt"}
            ],
            "options": {}
        }"#;
        let list = servers_from_cache_json(raw);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].index, 0);
        assert_eq!(list[0].country.as_deref(), Some("U.S.A."));
        assert_eq!(list[0].country_code.as_deref(), Some("US"));
        assert_eq!(list[0].city.as_deref(), Some("Ashburn"));
        assert_eq!(list[1].index, 1);
        assert_eq!(list[1].city.as_deref(), Some("Frankfurt"));
        assert!(!list[0].healthy);
        assert!(list[0].latency_ms.is_none());
        assert!(!list[0].is_current);
    }

    #[test]
    fn empty_or_invalid_json_yields_empty_list() {
        assert!(servers_from_cache_json("").is_empty());
        assert!(servers_from_cache_json("not json").is_empty());
        assert!(servers_from_cache_json(r#"{"options":{}}"#).is_empty());
    }

    #[test]
    fn accepts_camelcase_country_code_alias() {
        let raw = r#"{"servers": [{"country": "Japan", "countryCode": "JP", "city": "Tokyo"}]}"#;
        let list = servers_from_cache_json(raw);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].country_code.as_deref(), Some("JP"));
    }
}
