//! Adapter from the Lantern API's `config_raw.json` payload into spark's [`Config`] (Phase 3).
//!
//! `config_raw.json` is a sing-box-style config: `options.{dns,outbounds,route}` plus Lantern
//! sidecars (`outbound_locations`, `bandit_url_overrides`, `smart_routing`, `ad_block`, …). Spark
//! does full-tunnel, so this adapter consumes only the slice it can act on — the proxy
//! **outbounds**, joined by their `tag` to per-outbound geo (`outbound_locations`) and the bandit
//! callback URL (`bandit_url_overrides`) — and maps each into a [`ServerEntry`] pool member. The DNS
//! / `route` / `smart_routing` / `ad_block` sections are intentionally ignored for now (deferred; the
//! raw structs below can grow to cover them without touching callers).
//!
//! Outbounds spark can't represent are skipped (logged), not fatal: an unsupported transport
//! `type` (e.g. `unbounded`) or an unsupported parameter (e.g. a legacy, non-SS-2022 Shadowsocks
//! `method`). The remaining outbounds form the pool.

use std::collections::HashMap;

use serde::Deserialize;

use super::{
    Config, Endpoint, Hysteria2Config, Hysteria2Tls, Hysteria2TlsMode, SamizdatConfig, ServerEntry,
    ServerSpec, ShadowsocksConfig, SsMethod,
};

/// Error parsing/adapting a `config_raw.json` payload.
#[derive(Debug, thiserror::Error)]
pub enum ConfigRawError {
    /// The string was not valid JSON / not the expected `config_raw` shape.
    #[error("config_raw JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// Parsed fine, but none of the `found` outbounds is a transport spark can use — so there is no
    /// pool to build. Surfaced (rather than returning an empty pool) so the caller fails loudly
    /// instead of silently falling back to direct, untunneled forwarding.
    #[error("config_raw.json has no outbound spark can use (found {found}, none supported)")]
    NoSupportedOutbounds {
        /// How many outbounds were present (all unsupported).
        found: usize,
    },
}

/// True if `s` parses as a JSON object with an `options.outbounds` array — the `config_raw.json`
/// shape — vs spark's native TOML, so the loader can route the string to [`from_config_raw_json`].
/// A structural check (not a substring scan): unrelated JSON — including one that merely mentions
/// `options`/`outbounds` in string values — isn't mis-routed. `from_config_raw_json` re-parses and
/// is the real validation; the extra parse here is fine since config load is infrequent.
pub fn looks_like_config_raw(s: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(s)
        .ok()
        .and_then(|v| {
            v.get("options")
                .and_then(|o| o.get("outbounds"))
                .map(serde_json::Value::is_array)
        })
        .unwrap_or(false)
}

/// Parse a Lantern `config_raw.json` string and map its proxy outbounds into a spark [`Config`]'s
/// server pool. Each `options.outbounds[*]` becomes a [`ServerEntry`], joined by its `tag` to geo
/// (`outbound_locations`) and the bandit callback URL (`bandit_url_overrides`). Outbounds spark
/// can't represent — an unsupported transport `type` (e.g. `unbounded`) or a non-SS-2022
/// Shadowsocks `method` — are skipped with a warning. The `dns` / `route` / `smart_routing` /
/// `ad_block` sections are ignored for now (deferred).
pub fn from_config_raw_json(s: &str) -> Result<Config, ConfigRawError> {
    let raw: RawRoot = serde_json::from_str(s)?;
    let mut cfg = Config::default();
    // poll_interval_seconds → pool re-probe cadence (0 / absent ⇒ keep the default).
    if raw.poll_interval_seconds > 0 {
        cfg.transport.probe_interval_secs = raw.poll_interval_seconds;
    }
    for ob in &raw.options.outbounds {
        let Some(spec) = map_outbound(ob) else {
            tracing::warn!(
                tag = %ob.tag,
                kind = %ob.kind,
                "config_raw: skipping outbound spark can't represent"
            );
            continue;
        };
        let loc = raw.outbound_locations.get(&ob.tag);
        cfg.transport.servers.push(ServerEntry {
            spec,
            callback_url: raw.bandit_url_overrides.get(&ob.tag).cloned(),
            name: None,
            country: loc.and_then(|l| l.country.clone()),
            country_code: loc.and_then(|l| l.country_code.clone()),
            city: loc.and_then(|l| l.city.clone()),
            latitude: loc.and_then(|l| l.latitude),
            longitude: loc.and_then(|l| l.longitude),
        });
    }
    // An empty pool would make `from_config` fall back to direct (untunneled) forwarding, silently
    // running unprotected despite a config_raw.json being supplied — fail loudly instead.
    if cfg.transport.servers.is_empty() {
        return Err(ConfigRawError::NoSupportedOutbounds {
            found: raw.options.outbounds.len(),
        });
    }
    Ok(cfg)
}

/// Map one raw sing-box outbound into a spark [`ServerSpec`], or `None` if spark can't represent it
/// (unsupported `type`, a missing required field, or a non-SS-2022 Shadowsocks method).
fn map_outbound(ob: &RawOutbound) -> Option<ServerSpec> {
    let endpoint = || {
        format!("{}:{}", ob.server, ob.server_port)
            .parse::<Endpoint>()
            .ok()
    };
    match ob.kind.as_str() {
        "samizdat" => Some(ServerSpec::Samizdat(SamizdatConfig {
            server: endpoint()?,
            server_pubkey: ob.public_key.clone()?,
            short_id: ob.short_id.clone()?,
            sni: ob.server_name.clone(),
        })),
        "hysteria2" => {
            let insecure = ob.tls.as_ref().is_some_and(|t| t.insecure);
            Some(ServerSpec::Hysteria2(Hysteria2Config {
                server: endpoint()?,
                auth: ob.password.clone()?,
                sni: ob.tls.as_ref().and_then(|t| t.server_name.clone()),
                down_mbps: 0,
                tls: Hysteria2Tls {
                    mode: if insecure {
                        Hysteria2TlsMode::Insecure
                    } else {
                        Hysteria2TlsMode::SystemRoots
                    },
                    pin_sha256: None,
                },
                obfs: None,
            }))
        }
        "shadowsocks" => Some(ServerSpec::Shadowsocks(ShadowsocksConfig {
            server: endpoint()?,
            method: ss_method(ob.method.as_deref()?)?,
            password: ob.password.clone()?,
        })),
        _ => None, // unbounded, etc. — no spark transport
    }
}

/// Map a sing-box Shadowsocks `method` string to spark's SS-2022 [`SsMethod`], or `None` for a
/// non-SS-2022 (legacy) method spark doesn't implement.
fn ss_method(method: &str) -> Option<SsMethod> {
    match method {
        "2022-blake3-aes-128-gcm" => Some(SsMethod::Aes128Gcm),
        "2022-blake3-aes-256-gcm" => Some(SsMethod::Aes256Gcm),
        "2022-blake3-chacha20-poly1305" => Some(SsMethod::Chacha20Poly1305),
        _ => None,
    }
}

// ---- The `config_raw.json` slice spark consumes. Lenient: serde ignores unknown fields, so the
// many sections spark doesn't use (dns/route/features/otel/…) and per-outbound extras pass through.

#[derive(Deserialize)]
struct RawRoot {
    #[serde(default)]
    poll_interval_seconds: u64,
    #[serde(default)]
    options: RawOptions,
    #[serde(default)]
    outbound_locations: HashMap<String, RawLocation>,
    #[serde(default)]
    bandit_url_overrides: HashMap<String, String>,
}

#[derive(Deserialize, Default)]
struct RawOptions {
    #[serde(default)]
    outbounds: Vec<RawOutbound>,
}

#[derive(Deserialize)]
struct RawOutbound {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    server_port: u16,
    // samizdat
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    short_id: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
    // hysteria2 / shadowsocks
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    tls: Option<RawTls>,
    #[serde(default)]
    method: Option<String>,
}

#[derive(Deserialize)]
struct RawTls {
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    insecure: bool,
}

#[derive(Deserialize)]
struct RawLocation {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small, structurally-faithful sample with FAKE credentials/IPs/tokens (never the real
    // config_raw.json, which carries live secrets). Covers: samizdat (maps), hysteria2 w/
    // tls.insecure (maps), legacy-method shadowsocks (skipped), SS-2022 shadowsocks (maps),
    // unbounded (skipped) — plus geo + callbacks keyed by `tag`, and poll_interval_seconds.
    const SAMPLE: &str = r#"{
      "country": "US",
      "ip": "203.0.113.7",
      "poll_interval_seconds": 45,
      "options": {
        "dns": { "servers": [] },
        "route": { "rules": [] },
        "outbounds": [
          { "type": "samizdat", "tag": "sz-1", "server": "198.51.100.10", "server_port": 8443,
            "public_key": "aa11bb22", "short_id": "00ff00ff", "server_name": "cover.example.com" },
          { "type": "hysteria2", "tag": "hy-1", "server": "198.51.100.20", "server_port": 45000,
            "password": "fakeauthtoken", "tls": { "enabled": true, "server_name": "www.example.org", "insecure": true } },
          { "type": "shadowsocks", "tag": "ss-legacy", "server": "198.51.100.30", "server_port": 8388,
            "method": "chacha20-ietf-poly1305", "password": "bGVnYWN5a2V5" },
          { "type": "shadowsocks", "tag": "ss-2022", "server": "198.51.100.40", "server_port": 9000,
            "method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng==" },
          { "type": "unbounded", "tag": "ub-1", "server": "", "server_port": 0, "egress_addr": "wss://x.example" }
        ]
      },
      "outbound_locations": {
        "sz-1": { "country": "Germany", "city": "Berlin", "country_code": "DE", "latitude": 52.52, "longitude": 13.405 },
        "hy-1": { "country": "Japan", "city": "Tokyo", "country_code": "JP", "latitude": 35.69, "longitude": 139.69 },
        "ss-2022": { "country": "Brazil", "city": "São Paulo", "country_code": "BR", "latitude": -23.55, "longitude": -46.63 }
      },
      "bandit_url_overrides": {
        "sz-1": "https://api.example/cb?token=aaa",
        "hy-1": "https://api.example/cb?token=bbb",
        "ss-2022": "https://api.example/cb?token=ddd"
      }
    }"#;

    fn parse() -> Config {
        from_config_raw_json(SAMPLE).expect("config_raw adapts")
    }

    #[test]
    fn maps_samizdat_outbound_with_geo_and_callback() {
        let cfg = parse();
        let e = cfg
            .transport
            .servers
            .iter()
            .find(|e| matches!(&e.spec, ServerSpec::Samizdat(_)))
            .expect("a samizdat pool entry");
        let ServerSpec::Samizdat(s) = &e.spec else {
            unreachable!()
        };
        assert_eq!(s.server.to_string(), "198.51.100.10:8443");
        assert_eq!(s.server_pubkey, "aa11bb22");
        assert_eq!(s.short_id, "00ff00ff");
        assert_eq!(s.sni.as_deref(), Some("cover.example.com"));
        assert_eq!(e.country.as_deref(), Some("Germany"));
        assert_eq!(e.city.as_deref(), Some("Berlin"));
        assert_eq!(e.country_code.as_deref(), Some("DE"));
        assert_eq!(e.latitude, Some(52.52));
        assert_eq!(e.longitude, Some(13.405));
        assert_eq!(
            e.callback_url.as_deref(),
            Some("https://api.example/cb?token=aaa")
        );
    }

    #[test]
    fn maps_hysteria2_outbound_with_insecure_tls() {
        let cfg = parse();
        let e = cfg
            .transport
            .servers
            .iter()
            .find(|e| matches!(&e.spec, ServerSpec::Hysteria2(_)))
            .expect("a hysteria2 pool entry");
        let ServerSpec::Hysteria2(h) = &e.spec else {
            unreachable!()
        };
        assert_eq!(h.server.to_string(), "198.51.100.20:45000");
        assert_eq!(h.auth, "fakeauthtoken");
        assert_eq!(h.sni.as_deref(), Some("www.example.org"));
        assert_eq!(h.tls.mode, Hysteria2TlsMode::Insecure);
        assert_eq!(e.country_code.as_deref(), Some("JP"));
    }

    #[test]
    fn maps_ss2022_but_skips_legacy_shadowsocks_method() {
        let cfg = parse();
        let ss: Vec<_> = cfg
            .transport
            .servers
            .iter()
            .filter_map(|e| match &e.spec {
                ServerSpec::Shadowsocks(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(
            ss.len(),
            1,
            "only the SS-2022 entry maps; legacy method is skipped"
        );
        assert_eq!(ss[0].method, SsMethod::Aes128Gcm);
        assert_eq!(ss[0].server.to_string(), "198.51.100.40:9000");
    }

    #[test]
    fn skips_unsupported_transport_types() {
        let cfg = parse();
        // unbounded has no ServerSpec variant; the pool is exactly the 3 supported entries
        // (samizdat + hysteria2 + ss-2022). unbounded + legacy-ss are dropped.
        assert_eq!(cfg.transport.servers.len(), 3);
    }

    #[test]
    fn maps_poll_interval_to_probe_interval() {
        assert_eq!(parse().transport.probe_interval_secs, 45);
    }

    #[test]
    fn looks_like_config_raw_detects_json_with_outbounds() {
        assert!(looks_like_config_raw(SAMPLE));
        assert!(!looks_like_config_raw(
            "[transport]\nserver = \"1.2.3.4:443\"\n"
        ));
        assert!(!looks_like_config_raw("{}"));
        // A bare `outbounds` key without `options` is not config_raw — don't mis-route it.
        assert!(!looks_like_config_raw(r#"{ "outbounds": [1, 2] }"#));
        // `options`/`outbounds` appearing only as string *values* (not keys) must not match.
        assert!(!looks_like_config_raw(
            r#"{ "note": "mentions options and outbounds" }"#
        ));
        // `options.outbounds` present but not an array is not the expected shape.
        assert!(!looks_like_config_raw(
            r#"{ "options": { "outbounds": 5 } }"#
        ));
    }

    #[test]
    fn from_config_str_routes_json_to_adapter_and_toml_to_parser() {
        // A config_raw.json payload is routed through the adapter (pool built).
        let cfg = Config::from_config_str(SAMPLE).expect("config_raw adapts");
        assert_eq!(cfg.transport.servers.len(), 3);
        // Native TOML still parses via the TOML path.
        let cfg2 = Config::from_config_str("[transport]\nserver = \"1.2.3.4:443\"\n")
            .expect("toml parses");
        assert!(cfg2.transport.server.is_some());
        assert!(cfg2.transport.servers.is_empty());
    }

    #[test]
    fn errors_when_no_supported_outbounds() {
        // A config_raw with only outbounds spark can't represent must error rather than yield an
        // empty pool — an empty pool falls back to direct (untunneled) forwarding, which would
        // silently run unprotected despite a config being supplied.
        let raw = r#"{ "options": { "outbounds": [
            { "type": "unbounded", "tag": "ub", "server": "", "server_port": 0 }
        ]}}"#;
        from_config_raw_json(raw).expect_err("all-unsupported config_raw must error");
        assert!(Config::from_config_str(raw).is_err());
    }
}
