//! Adapter from the Lantern API's `config_raw.json` payload into spark's [`Config`] (Phase 3).
//!
//! `config_raw.json` is a sing-box-style config: `options.{dns,outbounds,route}` plus Lantern
//! sidecars (`outbound_locations`, `bandit_url_overrides`, `smart_routing`, `ad_block`, …). Spark
//! does full-tunnel, so this adapter consumes only the slice it can act on — the proxy
//! **outbounds**, joined by their `tag` to per-outbound geo (`outbound_locations`) and the bandit
//! callback URL (`bandit_url_overrides`) — and maps each into a [`ServerEntry`] pool member. The
//! `smart_routing` / `ad_block` / `options.route.rules` sections feed the smart-routing engine, and
//! `options.dns`'s `dns_local` / `dns_remote` feed the per-action resolvers.
//!
//! Outbounds spark can't represent are skipped (logged), not fatal: an unsupported transport
//! `type` (e.g. `unbounded`) or an unsupported parameter (e.g. a legacy, non-SS-2022 Shadowsocks
//! `method`). The remaining outbounds form the pool.

use std::collections::HashMap;

use serde::Deserialize;

use super::{
    Config, DnsConfig, DohEndpoint, Endpoint, Hysteria2Config, Hysteria2Tls, Hysteria2TlsMode,
    InlineIpRule, RouteAction, RuleSetRef, SamizdatConfig, ServerEntry, ServerSpec,
    ShadowsocksConfig, SmartRoutingConfig, SsMethod,
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

/// The Unbounded (volunteer-proxy) settings spark surfaces to the plugin, distilled from the Lantern
/// config's `features.unbounded` gate and its top-level `unbounded` block. `core` doesn't depend on
/// `spark-sharing`, so this carries only the raw fields; the plugin (which does depend on it) builds
/// the `SharingConfig` + Freddie signaler from these.
///
/// Field mapping to the wire (lantern-cloud must keep these names in sync):
/// - `enabled`         ← `features.unbounded` (the master gate; absent ⇒ `false`)
/// - `egress_url`      ← `unbounded.egress_addr`     (the sharing egress WebSocket URL, `wss://…`)
/// - `signaling_url`   ← `unbounded.discovery_srv`   (the Freddie signaling endpoint, `https://…`)
/// - `concurrent_sessions` ← `unbounded.ctable_size` (how many peer sessions to advertise at once)
///
/// `enabled` alone doesn't imply the block is usable: the plugin also requires a non-empty
/// `egress_url` + `signaling_url` before it will start (see [`UnboundedConfig::is_available`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnboundedConfig {
    /// The `features.unbounded` master gate. Absent/false ⇒ the feature is off for this client.
    pub enabled: bool,
    /// Sharing egress WebSocket URL (`unbounded.egress_addr`, e.g. `wss://…`). Empty when absent.
    pub egress_url: String,
    /// Freddie signaling endpoint (`unbounded.discovery_srv`, an `https://…` URL). Empty when absent.
    pub signaling_url: String,
    /// Number of concurrent censored-user sessions to advertise (`unbounded.ctable_size`). `0` when
    /// absent — the plugin clamps to a sensible floor.
    pub concurrent_sessions: usize,
}

impl UnboundedConfig {
    /// True when the feature is gated on AND the block carries the two endpoints the plugin needs to
    /// actually start sharing. `enabled` without endpoints is treated as unavailable, since starting
    /// would only fail at dial time.
    pub fn is_available(&self) -> bool {
        self.enabled && !self.egress_url.is_empty() && !self.signaling_url.is_empty()
    }
}

/// Parse a Lantern `config_raw.json` string into its [`UnboundedConfig`] (the `features.unbounded`
/// gate joined with the top-level `unbounded` block). Absent sections default to `enabled = false`.
/// Same lenient parse as [`from_config_raw_json`]: unknown fields are ignored.
pub fn unbounded_from_config_raw_json(s: &str) -> Result<UnboundedConfig, ConfigRawError> {
    let raw: RawRoot = serde_json::from_str(s)?;
    Ok(raw.unbounded_config())
}

/// OTel reporting parameters from the config response, distilled from the top-level `otel` block
/// (getlantern/common `OTEL`) joined with the `features["otel.*"]` flags — mirrors radiance's
/// client-side contract (see the diagnostics design spec §2/§C4). The diag uploader consumes this;
/// `core` just carries the raw fields.
///
/// Field mapping to the wire (lantern-cloud must keep these names in sync):
/// - `endpoint`       ← `otel.endpoint`      (e.g. `ingest.us.signoz.cloud:443`)
/// - `headers`        ← `otel.headers`       (the server-set ingestion key etc.)
/// - `sample_rate`    ← `otel.sample_rate`   (absent ⇒ `1.0`; clamped to `[0.0, 1.0]`)
/// - `logs_enabled`   ← `features["otel.logs"]`   (absent ⇒ `false`)
/// - `traces_enabled` ← `features["otel.traces"]` (absent ⇒ `false`)
///
/// `otel.metrics_interval` is deliberately NOT parsed: Phase A emits no metrics signal (spec §9),
/// so carrying the knob would only invite dead wiring.
///
/// Header VALUES are opaque secrets (the SigNoz ingestion key lives there) — never log them.
#[derive(Debug, Clone, PartialEq)]
pub struct OtelConfig {
    /// The OTLP ingest endpoint (`otel.endpoint`, e.g. `ingest.us.signoz.cloud:443`). Never empty:
    /// an empty/absent endpoint yields `None` from [`otel_from_config_raw_json`] instead.
    pub endpoint: String,
    /// HTTP headers to attach verbatim to every upload (`otel.headers` — the ingestion key etc.).
    /// Sorted by key for determinism. Values are opaque secrets: never log them.
    pub headers: Vec<(String, String)>,
    /// Trace/diag sampling rate (`otel.sample_rate`). Absent ⇒ `1.0`; clamped to `[0.0, 1.0]`.
    pub sample_rate: f64,
    /// The `features["otel.logs"]` gate for the diag logs signal. Absent ⇒ `false`.
    pub logs_enabled: bool,
    /// The `features["otel.traces"]` gate for the traces signal. Absent ⇒ `false`.
    pub traces_enabled: bool,
}

/// Parse a Lantern `config_raw.json` string into its [`OtelConfig`] (the top-level `otel` block
/// joined with the `features["otel.logs"]` / `features["otel.traces"]` gates). Returns `None` when
/// the `otel` block is absent or its `endpoint` is empty/missing — radiance's
/// `Endpoint == "" ⇒ skip` rule: no endpoint means telemetry is off entirely. Same lenient parse
/// as [`from_config_raw_json`]: unknown fields are ignored.
pub fn otel_from_config_raw_json(s: &str) -> Result<Option<OtelConfig>, ConfigRawError> {
    let raw: RawRoot = serde_json::from_str(s)?;
    Ok(raw.otel_config())
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
/// Shadowsocks `method` — are skipped with a warning. The `smart_routing` / `ad_block` /
/// `options.route.rules` sections populate [`SmartRoutingConfig`], and `options.dns` populates
/// [`DnsConfig`].
pub fn from_config_raw_json(s: &str) -> Result<Config, ConfigRawError> {
    let raw: RawRoot = serde_json::from_str(s)?;
    let mut cfg = Config::default();
    // poll_interval_seconds → pool re-probe cadence (0 / absent ⇒ keep the default).
    if raw.poll_interval_seconds > 0 {
        cfg.transport.probe_interval_secs = raw.poll_interval_seconds;
    }
    // Stall-detection knobs: absent ⇒ TransportConfig defaults hold; present ⇒ override.
    if let Some(v) = raw.stall_window_seconds {
        cfg.transport.stall_window_secs = v;
    }
    if let Some(v) = raw.stall_demote_count {
        cfg.transport.stall_demote_count = v;
    }
    if let Some(v) = raw.stall_demote_window_seconds {
        cfg.transport.stall_demote_window_secs = v;
    }
    if let Some(v) = raw.stall_quarantine_seconds {
        cfg.transport.stall_quarantine_secs = v;
    }
    if let Some(v) = raw.stall_quarantine_max_seconds {
        cfg.transport.stall_quarantine_max_secs = v;
    }
    if let Some(v) = raw.stall_trial_flows {
        cfg.transport.stall_trial_flows = v;
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
    cfg.smart_routing = parse_smart_routing(&raw);
    cfg.dns = parse_dns(&raw);
    Ok(cfg)
}

/// Map `options.dns` into the spark [`DnsConfig`]: the IP-addressed `type: "https"` servers tagged
/// `dns_local` and `dns_remote`. Non-`https` servers (e.g. `fakeip`) and hostname servers are skipped
/// — flint's DoH dialer needs a fixed IP.
fn parse_dns(raw: &RawRoot) -> DnsConfig {
    let mut dns = DnsConfig::default();
    for s in &raw.options.dns.servers {
        if s.kind != "https" || s.server.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let endpoint = DohEndpoint {
            server: s.server.clone(),
            // Reuse the shared DohEndpoint defaults so config_raw-derived and TOML-derived endpoints
            // can't drift.
            port: if s.server_port == 0 {
                super::default_doh_port()
            } else {
                s.server_port
            },
            path: if s.path.is_empty() {
                super::default_doh_path()
            } else {
                s.path.clone()
            },
        };
        match s.tag.as_str() {
            "dns_local" => dns.local = Some(endpoint),
            "dns_remote" => dns.remote = Some(endpoint),
            _ => {}
        }
    }
    dns
}

/// Map the `smart_routing` / `ad_block` / `options.route.rules` sidecars into the spark
/// [`SmartRoutingConfig`]: rule-set refs (with their action) + inline IP rules. Precedence is
/// applied later by the engine; here we just capture what the config declared.
fn parse_smart_routing(raw: &RawRoot) -> SmartRoutingConfig {
    let mut sr = SmartRoutingConfig::default();
    // ad_block: every list drops (Reject). Marked `ad_block: true` so the Settings toggle gates
    // exactly these — never a smart_routing reject category (below).
    for rs in &raw.ad_block {
        sr.rule_sets.push(RuleSetRef {
            action: RouteAction::Reject,
            tag: rs.tag.clone(),
            url: rs.url.clone(),
            ad_block: true,
        });
    }
    // smart_routing categories: the category's outbound decides the action (e.g. `direct`, or
    // `reject`/`block`). These are NOT ad-block (`ad_block: false`) even when their action is
    // Reject — a reject category must stay permanently in force, not become toggleable.
    for cat in &raw.smart_routing {
        let action = route_action(&cat.category, cat.outbounds.first().map(String::as_str));
        for rs in &cat.rule_sets {
            sr.rule_sets.push(RuleSetRef {
                action,
                tag: rs.tag.clone(),
                url: rs.url.clone(),
                ad_block: false,
            });
        }
    }
    // options.route.rules: inline IP/CIDR rules (e.g. Quad9 9.9.9.9/32 → direct).
    for rule in &raw.options.route.rules {
        let Some(outbound) = rule.outbound.as_deref() else {
            continue;
        };
        let action = route_action(outbound, Some(outbound));
        if let Some(cidrs) = rule.ip_cidr.as_ref() {
            for cidr in cidrs.clone().into_vec() {
                sr.inline_ip_rules.push(InlineIpRule { cidr, action });
            }
        }
    }
    sr
}

/// Resolve a sing-box outbound/category name to a spark [`RouteAction`]. `direct` bypasses the
/// proxy; `reject`/`block` drops; anything else (a proxy outbound / `auto`) is proxied.
fn route_action(category: &str, outbound: Option<&str>) -> RouteAction {
    match outbound.unwrap_or(category) {
        "direct" => RouteAction::Direct,
        "reject" | "block" => RouteAction::Reject,
        _ => RouteAction::Proxy,
    }
}

/// Extract the bare host from a meek-server `url` (e.g. `"https://meek.example/"` → `"meek.example"`).
/// The meek wire carries a full URL; spark's scanner wants just the inner Host. Returns `None` for an
/// empty/hostless or malformed value (→ the client self-bootstraps to its built-in default endpoint).
fn host_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let after_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    // Authority ends at the first path/query/fragment delimiter.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop optional `userinfo@`, then a trailing `:port` — but only when the suffix is numeric.
    // A non-numeric suffix means a leftover colon (e.g. a `scheme:host` written without `//`, which
    // would otherwise yield the scheme as the "host"); treat that as malformed → None. Meek hosts are
    // DNS names, so a colon never legitimately survives here (no IPv6-literal/bracket handling needed).
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    let host = match host_port.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        Some(_) => return None,
        None => host_port,
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// Map one raw sing-box outbound into a spark [`ServerSpec`], or `None` if spark can't represent it
/// (unsupported `type`, a missing required field, or a non-SS-2022 Shadowsocks method).
fn map_outbound(ob: &RawOutbound) -> Option<ServerSpec> {
    // Build the endpoint from the separate host + port directly. Formatting `"{server}:{port}"` and
    // re-parsing would mangle an IPv6 literal (`"2001:db8::1"` + 443 → an unbracketed, unparseable
    // string) and silently drop the outbound.
    let endpoint = || -> Option<Endpoint> {
        // No host, or a missing/zero port (`server_port` defaults to 0): not a dialable endpoint.
        if ob.server.is_empty() || ob.server_port == 0 {
            return None;
        }
        match ob.server.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(Endpoint::Ip(std::net::SocketAddr::new(ip, ob.server_port))),
            // Not an IP literal → a hostname, resolved at startup by the bootstrap phase.
            Err(_) => Some(Endpoint::Host {
                host: ob.server.clone(),
                port: ob.server_port,
            }),
        }
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
        // Self-bootstrapping: no `server` endpoint needed (the client scans edges). The wire carries
        // the meek-server `url`; derive the bare inner host. Empty/absent → the client uses its
        // built-in default endpoint. http_version isn't on the wire, so it auto-selects from ALPN.
        // A build without the `fronted-meek` feature still maps this; building the transport then
        // fails via fronted_meek_transport()'s #[cfg(not)] stub — surfaced at connect in
        // single-transport mode, or skipped-with-warning as one member by build_selecting() in a
        // multi-server pool (only an all-meek pool fails). Mirrors samizdat/hysteria2.
        // Only the Akamai meek_host comes off the wire (from `url`); the CloudFront
        // and Aliyun inner hosts are left empty so the client uses its built-in
        // per-CDN defaults.
        "meek" => Some(ServerSpec::FrontedMeek(super::FrontedMeekConfig {
            meek_host: ob
                .url
                .as_deref()
                .and_then(host_from_url)
                .unwrap_or_default(),
            ..Default::default()
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
// many sections spark doesn't use and per-outbound extras pass through untouched.

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
    /// Smart-routing categories (rule-sets → an outbound, e.g. common domains → `direct`).
    #[serde(default)]
    smart_routing: Vec<RawSmartCategory>,
    /// Ad/malware/phishing rule-sets to drop.
    #[serde(default)]
    ad_block: Vec<RawRuleSetRef>,
    // Stall-detection knobs — absent today; present fields override TransportConfig defaults.
    #[serde(default)]
    stall_window_seconds: Option<u64>,
    #[serde(default)]
    stall_demote_count: Option<u32>,
    #[serde(default)]
    stall_demote_window_seconds: Option<u64>,
    #[serde(default)]
    stall_quarantine_seconds: Option<u64>,
    #[serde(default)]
    stall_quarantine_max_seconds: Option<u64>,
    #[serde(default)]
    stall_trial_flows: Option<u32>,
    /// The `features` map (feature flags). Only `unbounded` and the dotted `otel.logs` /
    /// `otel.traces` keys are consumed here; other keys — including `otel.metrics` — pass through
    /// untouched.
    #[serde(default)]
    features: RawFeatures,
    /// The top-level `unbounded` (volunteer-proxy) block. Absent ⇒ default (empty endpoints).
    #[serde(default)]
    unbounded: RawUnbounded,
    /// The top-level `otel` block (getlantern/common `OTEL`). Absent ⇒ default (empty endpoint,
    /// which [`RawRoot::otel_config`] maps to `None`).
    #[serde(default)]
    otel: RawOtel,
}

impl RawRoot {
    /// Distil the `features.unbounded` gate + the `unbounded` block into a [`UnboundedConfig`].
    fn unbounded_config(&self) -> UnboundedConfig {
        UnboundedConfig {
            enabled: self.features.unbounded,
            egress_url: self.unbounded.egress_addr.clone(),
            signaling_url: self.unbounded.discovery_srv.clone(),
            concurrent_sessions: self.unbounded.ctable_size,
        }
    }

    /// Distil the `otel` block + the `features["otel.*"]` gates into an [`OtelConfig`]. `None` when
    /// the block is absent or its endpoint is empty — radiance's `Endpoint == "" ⇒ skip` rule: no
    /// endpoint means telemetry is off entirely, regardless of the feature flags.
    fn otel_config(&self) -> Option<OtelConfig> {
        if self.otel.endpoint.is_empty() {
            return None;
        }
        let mut headers: Vec<(String, String)> = self
            .otel
            .headers
            .iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::String(s) if !k.is_empty() && !s.is_empty() => {
                    Some((k.clone(), s.clone()))
                }
                // Malformed entry (non-string/empty key or value): skip it, keep the rest. Header
                // values are opaque secrets (the ingestion key) — log the KEY only, never the value.
                _ => {
                    tracing::debug!(key = %k, "config_raw: skipping malformed otel header entry");
                    None
                }
            })
            .collect();
        // Sorted by key for determinism — the wire map has no order.
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        Some(OtelConfig {
            endpoint: self.otel.endpoint.clone(),
            headers,
            // Absent ⇒ 1.0 (always). Clamped: a server typo like `100` must not be interpreted as
            // anything but 'always', and a negative rate as anything but 'never'.
            sample_rate: self.otel.sample_rate.unwrap_or(1.0).clamp(0.0, 1.0),
            logs_enabled: self.features.otel_logs,
            traces_enabled: self.features.otel_traces,
        })
    }
}

/// The `features` flag map. Only `unbounded` and the dotted `otel.logs` / `otel.traces` keys are
/// consumed; other keys (`otel.metrics`, `private.gcp`, …) and anything else are ignored by serde's
/// unknown-field leniency.
#[derive(Deserialize, Default)]
struct RawFeatures {
    #[serde(default)]
    unbounded: bool,
    /// `features["otel.logs"]` → [`OtelConfig::logs_enabled`] (the diag logs-signal gate).
    #[serde(rename = "otel.logs", default)]
    otel_logs: bool,
    /// `features["otel.traces"]` → [`OtelConfig::traces_enabled`] (the traces-signal gate).
    #[serde(rename = "otel.traces", default)]
    otel_traces: bool,
}

/// The top-level `unbounded` block. spark consumes the egress WS URL, the Freddie signaling endpoint,
/// and the session-count hint; the other fields (`discovery_endpoint`, `egress_endpoint`,
/// `ptable_size`) are lantern-box wiring spark doesn't act on and are ignored.
#[derive(Deserialize, Default)]
struct RawUnbounded {
    /// Sharing egress WebSocket URL (`wss://…`) → [`UnboundedConfig::egress_url`].
    #[serde(default)]
    egress_addr: String,
    /// Freddie signaling endpoint (`https://…`) → [`UnboundedConfig::signaling_url`].
    #[serde(default)]
    discovery_srv: String,
    /// Concurrent-session hint → [`UnboundedConfig::concurrent_sessions`].
    #[serde(default)]
    ctable_size: usize,
}

/// The top-level `otel` block (getlantern/common `OTEL`). spark consumes the endpoint, headers, and
/// sample rate; `metrics_interval` is deliberately ignored — Phase A emits no metrics signal
/// (diagnostics design spec §9), so there is nothing for the knob to drive.
#[derive(Deserialize, Default)]
struct RawOtel {
    /// OTLP ingest endpoint → [`OtelConfig::endpoint`]. Empty/absent ⇒ telemetry off (`None`).
    #[serde(default)]
    endpoint: String,
    /// Upload headers (ingestion key etc.) → [`OtelConfig::headers`]. Values are kept as raw JSON
    /// so one malformed (non-string) entry skips that entry instead of failing the whole config
    /// parse. The values are opaque secrets — never log them.
    #[serde(default)]
    headers: HashMap<String, serde_json::Value>,
    /// Sampling rate → [`OtelConfig::sample_rate`]. Absent ⇒ 1.0 there.
    #[serde(default)]
    sample_rate: Option<f64>,
}

#[derive(Deserialize, Default)]
struct RawOptions {
    #[serde(default)]
    outbounds: Vec<RawOutbound>,
    /// sing-box `route` block; we consume only `rules` (inline IP rules like Quad9 → direct).
    #[serde(default)]
    route: RawRoute,
    /// sing-box `dns` block; we consume the IP-addressed `type: "https"` servers tagged `dns_local` /
    /// `dns_remote` (the per-action DoH resolvers).
    #[serde(default)]
    dns: RawDns,
}

/// The `options.dns` block (only its `servers` are consumed).
#[derive(Deserialize, Default)]
struct RawDns {
    #[serde(default)]
    servers: Vec<RawDnsServer>,
}

/// One `options.dns.servers[*]` (sing-box DNS server). Only `type: "https"` with an IP `server` is
/// usable as a spark DoH resolver; other kinds (`fakeip`, hostname servers, …) are ignored.
#[derive(Deserialize, Default)]
struct RawDnsServer {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    server_port: u16,
    #[serde(default)]
    path: String,
}

/// One `smart_routing` category: rule-sets routed to `outbounds` (e.g. `["direct"]`).
#[derive(Deserialize, Default)]
struct RawSmartCategory {
    #[serde(default)]
    category: String,
    #[serde(default)]
    rule_sets: Vec<RawRuleSetRef>,
    #[serde(default)]
    outbounds: Vec<String>,
}

/// A `.srs` rule-set reference (`smart_routing[*].rule_sets[*]` and `ad_block[*]`).
#[derive(Deserialize)]
struct RawRuleSetRef {
    tag: String,
    url: String,
}

/// The `options.route` block (only `rules` is consumed).
#[derive(Deserialize, Default)]
struct RawRoute {
    #[serde(default)]
    rules: Vec<RawRouteRule>,
}

/// One `options.route.rules[*]`; spark consumes only inline `ip_cidr` → `outbound` (domain and
/// rule_set matchers are ignored here — domains arrive via the `.srs` rule-sets).
#[derive(Deserialize, Default)]
struct RawRouteRule {
    #[serde(default)]
    ip_cidr: Option<StrOrVec>,
    #[serde(default)]
    outbound: Option<String>,
}

/// sing-box fields that accept either a single string or an array of strings (e.g. `ip_cidr`).
#[derive(Deserialize, Clone)]
#[serde(untagged)]
enum StrOrVec {
    One(String),
    Many(Vec<String>),
}

impl StrOrVec {
    fn into_vec(self) -> Vec<String> {
        match self {
            StrOrVec::One(s) => vec![s],
            StrOrVec::Many(v) => v,
        }
    }
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
    // meek (self-bootstrapping domain-fronted; `server`/`server_port` are unused — the client scans
    // edges itself). The lantern-box meek outbound carries the meek-server `url`; spark derives the
    // bare inner host from it.
    #[serde(default)]
    url: Option<String>,
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

    #[test]
    fn parses_smart_routing_ad_block_and_inline_ip_rules() {
        let raw = r#"{
          "options": {
            "route": { "rules": [ { "ip_cidr": "9.9.9.9/32", "outbound": "direct" } ] },
            "outbounds": [
              { "type": "samizdat", "tag": "sz-1", "server": "198.51.100.10", "server_port": 8443,
                "public_key": "aa11bb22", "short_id": "00ff00ff", "server_name": "cover.example.com" }
            ]
          },
          "smart_routing": [
            { "category": "direct", "outbounds": ["direct"],
              "rule_sets": [ { "tag": "common", "url": "https://x/common.srs" } ] }
          ],
          "ad_block": [ { "tag": "banad", "url": "https://x/banad.srs" } ]
        }"#;
        let sr = from_config_raw_json(raw).expect("adapts").smart_routing;
        // ad_block → Reject (with its URL), smart_routing direct category → Direct.
        assert!(sr.rule_sets.iter().any(|r| r.tag == "banad"
            && r.action == RouteAction::Reject
            && r.url == "https://x/banad.srs"));
        assert!(sr
            .rule_sets
            .iter()
            .any(|r| r.tag == "common" && r.action == RouteAction::Direct));
        // options.route.rules inline ip_cidr → Direct.
        assert_eq!(sr.inline_ip_rules.len(), 1);
        assert_eq!(sr.inline_ip_rules[0].cidr, "9.9.9.9/32");
        assert_eq!(sr.inline_ip_rules[0].action, RouteAction::Direct);
    }

    #[test]
    fn absent_smart_routing_sections_yield_empty() {
        // SAMPLE has an empty route.rules and no smart_routing/ad_block sidecars.
        let cfg = from_config_raw_json(SAMPLE).expect("adapts");
        assert!(
            cfg.smart_routing.rule_sets.is_empty() && cfg.smart_routing.inline_ip_rules.is_empty()
        );
        // SAMPLE's dns.servers is empty → no endpoints captured.
        assert_eq!(cfg.dns, crate::config::DnsConfig::default());
    }

    #[test]
    fn parses_dns_local_and_remote_https_servers() {
        let raw = r#"{
          "options": {
            "dns": { "servers": [
              { "type": "https", "tag": "dns_remote", "detour": "auto", "server": "9.9.9.9", "server_port": 443, "path": "/dns-query" },
              { "type": "https", "tag": "dns_local", "server": "9.9.9.9", "path": "/dns-query" },
              { "type": "fakeip", "tag": "dns_fakeip", "inet4_range": "28.0.0.0/15" },
              { "type": "https", "tag": "dns_hostname", "server": "dns.quad9.net" }
            ] },
            "outbounds": [
              { "type": "samizdat", "tag": "sz-1", "server": "198.51.100.10", "server_port": 8443,
                "public_key": "aa11bb22", "short_id": "00ff00ff", "server_name": "cover.example.com" }
            ]
          }
        }"#;
        let dns = from_config_raw_json(raw).expect("adapts").dns;
        // dns_local: IP https server, port defaulted to 443.
        let local = dns.local.expect("dns_local");
        assert_eq!(
            (local.server.as_str(), local.port, local.path.as_str()),
            ("9.9.9.9", 443, "/dns-query")
        );
        // dns_remote: explicit port.
        assert_eq!(dns.remote.expect("dns_remote").port, 443);
        // fakeip + hostname-server entries are ignored (not usable as a fixed-IP DoH resolver).
    }

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
    fn maps_meek_outbound_deriving_host_from_url() {
        // No `server` endpoint required (the client scans edges); the meek-server `url` is carried on
        // the wire and the bare inner host is derived from it.
        let raw = r#"{ "options": { "outbounds": [
            { "type": "meek", "tag": "meek-1", "url": "https://meek.dsa.akamai.getiantem.org/" }
        ]}}"#;
        let cfg = from_config_raw_json(raw).expect("config_raw adapts");
        assert_eq!(cfg.transport.servers.len(), 1);
        let ServerSpec::FrontedMeek(fm) = &cfg.transport.servers[0].spec else {
            panic!("expected a meek pool entry");
        };
        assert_eq!(fm.meek_host, "meek.dsa.akamai.getiantem.org");
        assert!(fm.http_version.is_none()); // not on the wire — client auto-selects from ALPN
    }

    #[test]
    fn maps_bare_meek_to_self_bootstrap_defaults() {
        // A meek outbound with no url maps to the self-bootstrapping defaults: empty meek_host → the
        // client's built-in endpoint, no forced HTTP version.
        let raw = r#"{ "options": { "outbounds": [ { "type": "meek", "tag": "meek-2" } ]}}"#;
        let cfg = from_config_raw_json(raw).expect("config_raw adapts");
        let ServerSpec::FrontedMeek(fm) = &cfg.transport.servers[0].spec else {
            panic!("expected meek");
        };
        assert!(fm.meek_host.is_empty());
        assert!(fm.http_version.is_none());
    }

    #[test]
    fn host_from_url_extracts_bare_host() {
        assert_eq!(
            host_from_url("https://meek.example/"),
            Some("meek.example".to_string())
        );
        assert_eq!(
            host_from_url("https://meek.example:8443/path"),
            Some("meek.example".to_string())
        );
        assert_eq!(
            host_from_url("meek.example"),
            Some("meek.example".to_string())
        );
        // No path, but a query or fragment: authority still ends at `?`/`#`.
        assert_eq!(
            host_from_url("https://meek.example?x=1"),
            Some("meek.example".to_string())
        );
        assert_eq!(
            host_from_url("https://meek.example#frag"),
            Some("meek.example".to_string())
        );
        // Surrounding whitespace and optional userinfo are stripped.
        assert_eq!(
            host_from_url("  https://meek.example/  "),
            Some("meek.example".to_string())
        );
        assert_eq!(
            host_from_url("https://user:pass@meek.example:443/"),
            Some("meek.example".to_string())
        );
        // A bare `host:port` (no scheme) still works — the suffix is a numeric port.
        assert_eq!(
            host_from_url("meek.example:8443"),
            Some("meek.example".to_string())
        );
        // Malformed `scheme:host` without `//`, or any leftover non-numeric `:suffix`, is treated as
        // hostless → None, so the client falls back to its built-in default rather than dialing a
        // bogus host (e.g. the scheme).
        assert_eq!(host_from_url("https:meek.example"), None);
        assert_eq!(host_from_url("ftp:something"), None);
        assert_eq!(host_from_url("meek.example:"), None);
        assert_eq!(host_from_url(""), None);
        assert_eq!(host_from_url("   "), None);
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

    #[test]
    fn maps_ipv6_server() {
        // sing-box gives `server` + `server_port` separately; an IPv6 literal must become a bracketed
        // socket addr, not a `"2001:db8::1:443"` mash-up that fails to parse (and gets dropped).
        let raw = r#"{ "options": { "outbounds": [
            { "type": "samizdat", "tag": "v6", "server": "2001:db8::1", "server_port": 443,
              "public_key": "ab", "short_id": "cd", "server_name": "x" }
        ]}}"#;
        let cfg = from_config_raw_json(raw).expect("ipv6 samizdat adapts");
        assert_eq!(cfg.transport.servers.len(), 1);
        let ServerSpec::Samizdat(s) = &cfg.transport.servers[0].spec else {
            panic!("expected samizdat")
        };
        assert_eq!(s.server.to_string(), "[2001:db8::1]:443");
    }

    #[test]
    fn skips_outbound_with_zero_or_missing_port() {
        // A missing/zero server_port is not a dialable endpoint — skip it rather than build a pool
        // entry that would dial port 0 at runtime. (Here it's the only outbound, so the pool errors.)
        let raw = r#"{ "options": { "outbounds": [
            { "type": "hysteria2", "tag": "noport", "server": "198.51.100.9", "password": "x" }
        ]}}"#;
        from_config_raw_json(raw).expect_err("zero-port outbound must not form a pool entry");
    }

    #[test]
    fn stall_defaults_preserved_when_absent() {
        // SAMPLE has no stall_* fields; Config::default() values must survive unchanged.
        // Stall detection ships OFF by default (window 0) pending the signal redesign.
        let c = parse();
        assert_eq!(c.transport.stall_window_secs, 0);
        assert_eq!(c.transport.stall_demote_count, 3);
        assert_eq!(c.transport.stall_demote_window_secs, 30);
        assert_eq!(c.transport.stall_quarantine_secs, 60);
        assert_eq!(c.transport.stall_quarantine_max_secs, 600);
        assert_eq!(c.transport.stall_trial_flows, 2);
    }

    #[test]
    fn parses_unbounded_block_with_features_gate() {
        // A hand-written fixture (never the real config_raw.json): features.unbounded=true plus an
        // unbounded block with egress (wss), signaling (https), and a session-count hint.
        let raw = r#"{
          "features": { "unbounded": true, "otel.metrics": true },
          "unbounded": {
            "discovery_srv": "https://freddie.example/signal",
            "discovery_endpoint": "peers",
            "egress_addr": "wss://egress.example/ws",
            "egress_endpoint": "eg",
            "ctable_size": 5,
            "ptable_size": 5
          },
          "options": { "outbounds": [] }
        }"#;
        let u = unbounded_from_config_raw_json(raw).expect("unbounded parses");
        assert!(u.enabled);
        assert_eq!(u.egress_url, "wss://egress.example/ws");
        assert_eq!(u.signaling_url, "https://freddie.example/signal");
        assert_eq!(u.concurrent_sessions, 5);
        assert!(u.is_available());
    }

    #[test]
    fn unbounded_defaults_disabled_when_block_absent() {
        // No features/unbounded sections at all → default (disabled, empty endpoints, not available).
        let raw = r#"{ "options": { "outbounds": [] } }"#;
        let u = unbounded_from_config_raw_json(raw).expect("unbounded parses");
        assert!(!u.enabled);
        assert!(u.egress_url.is_empty());
        assert!(u.signaling_url.is_empty());
        assert_eq!(u.concurrent_sessions, 0);
        assert!(!u.is_available());
    }

    #[test]
    fn unbounded_enabled_but_no_endpoints_is_not_available() {
        // The gate is on but the block carries no endpoints — treat as unavailable (starting would
        // only fail at dial time).
        let raw = r#"{ "features": { "unbounded": true }, "options": { "outbounds": [] } }"#;
        let u = unbounded_from_config_raw_json(raw).expect("unbounded parses");
        assert!(u.enabled);
        assert!(!u.is_available());
    }

    #[test]
    fn unbounded_endpoints_present_but_gate_off_is_not_available() {
        // Endpoints present but features.unbounded is false/absent → gated off, not available.
        let raw = r#"{
          "unbounded": { "discovery_srv": "https://x/s", "egress_addr": "wss://x/ws" },
          "options": { "outbounds": [] }
        }"#;
        let u = unbounded_from_config_raw_json(raw).expect("unbounded parses");
        assert!(!u.enabled);
        assert!(!u.is_available());
    }

    #[test]
    fn parses_otel_block_and_flags() {
        // A hand-written fixture (never the real config_raw.json — its ingestion key is live):
        // a full `otel` block plus both `features["otel.*"]` gates on.
        let raw = r#"{
          "features": { "otel.logs": true, "otel.traces": true, "otel.metrics": true },
          "otel": {
            "endpoint": "ingest.us.signoz.cloud:443",
            "headers": { "signoz-ingestion-key": "k1" },
            "sample_rate": 0.5,
            "metrics_interval": 30
          },
          "options": { "outbounds": [] }
        }"#;
        let o = otel_from_config_raw_json(raw)
            .expect("otel parses")
            .expect("otel block present");
        assert_eq!(o.endpoint, "ingest.us.signoz.cloud:443");
        assert_eq!(
            o.headers,
            vec![("signoz-ingestion-key".to_string(), "k1".to_string())]
        );
        assert_eq!(o.sample_rate, 0.5);
        assert!(o.logs_enabled);
        assert!(o.traces_enabled);
    }

    #[test]
    fn otel_absent_is_none() {
        // No `otel` block at all → telemetry off entirely (radiance: `Endpoint == "" ⇒ skip`).
        let raw = r#"{ "options": { "outbounds": [] } }"#;
        assert_eq!(otel_from_config_raw_json(raw).expect("parses"), None);
    }

    #[test]
    fn otel_empty_endpoint_is_none() {
        // A present block whose endpoint is empty is equally off — no endpoint, no upload path —
        // even when the feature flags are on.
        let raw = r#"{
          "features": { "otel.logs": true, "otel.traces": true },
          "otel": { "endpoint": "", "headers": { "signoz-ingestion-key": "k1" } },
          "options": { "outbounds": [] }
        }"#;
        assert_eq!(otel_from_config_raw_json(raw).expect("parses"), None);
        // An endpoint missing entirely (not just empty) behaves the same.
        let raw2 = r#"{ "otel": { "headers": { "k": "v" } }, "options": { "outbounds": [] } }"#;
        assert_eq!(otel_from_config_raw_json(raw2).expect("parses"), None);
    }

    #[test]
    fn otel_defaults() {
        // Endpoint only: sample_rate defaults to 1.0 (always), both flags default off when the
        // `features` map is absent, headers empty.
        let raw = r#"{
          "otel": { "endpoint": "ingest.us.signoz.cloud:443" },
          "options": { "outbounds": [] }
        }"#;
        let o = otel_from_config_raw_json(raw)
            .expect("parses")
            .expect("present");
        assert_eq!(o.sample_rate, 1.0);
        assert!(!o.logs_enabled);
        assert!(!o.traces_enabled);
        assert!(o.headers.is_empty());
    }

    #[test]
    fn otel_sample_rate_is_clamped() {
        // A server typo like 100 must be read as 'always' (1.0), never anything else; a negative
        // rate clamps to 0.0 (never).
        let raw = |rate: &str| {
            format!(
                r#"{{ "otel": {{ "endpoint": "e:443", "sample_rate": {rate} }},
                      "options": {{ "outbounds": [] }} }}"#
            )
        };
        let hi = otel_from_config_raw_json(&raw("100"))
            .expect("parses")
            .expect("present");
        assert_eq!(hi.sample_rate, 1.0);
        let lo = otel_from_config_raw_json(&raw("-3"))
            .expect("parses")
            .expect("present");
        assert_eq!(lo.sample_rate, 0.0);
    }

    #[test]
    fn otel_malformed_header_entries_are_skipped() {
        // A non-string (or empty) header entry must not poison the whole parse — skip just that
        // entry, keep the valid ones, sorted by key for determinism.
        let raw = r#"{
          "otel": {
            "endpoint": "e:443",
            "headers": { "zzz": "v2", "bad-number": 7, "empty-val": "", "signoz-ingestion-key": "k1" }
          },
          "options": { "outbounds": [] }
        }"#;
        let o = otel_from_config_raw_json(raw)
            .expect("parses")
            .expect("present");
        assert_eq!(
            o.headers,
            vec![
                ("signoz-ingestion-key".to_string(), "k1".to_string()),
                ("zzz".to_string(), "v2".to_string())
            ]
        );
    }

    #[test]
    fn stall_override_maps_from_wire() {
        // A config_raw payload that carries stall_* fields must override the defaults.
        let raw = r#"{
          "stall_window_seconds": 42,
          "stall_demote_count": 7,
          "stall_demote_window_seconds": 90,
          "stall_quarantine_seconds": 120,
          "stall_quarantine_max_seconds": 1200,
          "stall_trial_flows": 5,
          "options": { "outbounds": [
            { "type": "samizdat", "tag": "sz-1", "server": "198.51.100.10", "server_port": 8443,
              "public_key": "aa11bb22", "short_id": "00ff00ff", "server_name": "cover.example.com" }
          ]}
        }"#;
        let cfg = from_config_raw_json(raw).expect("stall-override config_raw adapts");
        assert_eq!(cfg.transport.stall_window_secs, 42);
        assert_eq!(cfg.transport.stall_demote_count, 7);
        assert_eq!(cfg.transport.stall_demote_window_secs, 90);
        assert_eq!(cfg.transport.stall_quarantine_secs, 120);
        assert_eq!(cfg.transport.stall_quarantine_max_secs, 1200);
        assert_eq!(cfg.transport.stall_trial_flows, 5);
    }
}
