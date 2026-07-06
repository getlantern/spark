//! The user's split-tunnel "bypass the VPN" list — a per-device preference the UI edits and
//! injects into the tunnel. Parsed here (shared by every platform); applied by the router
//! (`crate::rules::router`). Bypass entries route Direct; see the design doc.

use serde::{Deserialize, Serialize};

/// The user's bypass list. `enabled` is the master toggle; when false the list is preserved but
/// ignored. `domains` match the host and its subdomains; `ips` are single IPs or CIDRs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SplitTunnel {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

/// The result of adding raw user text: what was kept (split into domains/ips) and what was rejected.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AddOutcome {
    pub added_domains: Vec<String>,
    pub added_ips: Vec<String>,
    pub rejected: Vec<String>,
}

/// A parse failure at the FFI boundary.
#[derive(Debug, thiserror::Error)]
pub enum SplitTunnelError {
    #[error("invalid split-tunnel json: {0}")]
    Json(String),
}

impl SplitTunnel {
    /// No entries (regardless of `enabled`).
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty()
    }

    /// Add comma-separated raw user text: each token is normalized, classified as an IP/CIDR or a
    /// plausible hostname, and appended if not already present. Returns what was added vs rejected so
    /// the UI can flag bad entries. Invalid tokens are neither added nor silently dropped.
    ///
    /// Note on `AddOutcome` field semantics: `rejected` contains the trimmed *original* token (what
    /// the user typed), while `added_domains`/`added_ips` contain the *normalized* host. This
    /// intentional asymmetry lets the UI show the user exactly what they entered when flagging an
    /// invalid entry.
    pub fn add_entries(&mut self, raw: &str) -> AddOutcome {
        let mut out = AddOutcome::default();
        for token in raw.split(',') {
            let host = normalize_one(token);
            if host.is_empty() {
                continue; // an empty field (trailing comma / whitespace) is not a rejection
            }
            if is_ip_or_cidr(&host) {
                if !self.ips.iter().any(|e| e == &host) {
                    self.ips.push(host.clone());
                    out.added_ips.push(host);
                }
            } else if is_plausible_hostname(&host) {
                if !self.domains.iter().any(|e| e == &host) {
                    self.domains.push(host.clone());
                    out.added_domains.push(host);
                }
            } else {
                out.rejected.push(token.trim().to_string());
            }
        }
        out
    }
}

/// Parse the JSON payload the platforms serialize (`{enabled, domains, ips}`).
pub fn parse(json: &str) -> Result<SplitTunnel, SplitTunnelError> {
    serde_json::from_str(json).map_err(|e| SplitTunnelError::Json(e.to_string()))
}

/// Normalize one raw entry to a bare host: trim, lowercase, strip a URL scheme, drop any
/// path/query/fragment (`https://Mail.Example.com/inbox` -> `mail.example.com`,
/// `example.com/path` -> `example.com`). A bare CIDR's slash is preserved (`10.0.0.0/8`,
/// `fd00::/8` stay intact) by only stripping a `/…` path when the part before it isn't a bare IP.
/// Also strips a trailing `:port` suffix when there is exactly one colon (e.g. `example.com:443`
/// -> `example.com`). IPv6 literals have two or more colons and are left intact so that
/// `is_ip_or_cidr` can parse them correctly.
fn normalize_one(entry: &str) -> String {
    let mut e = entry.trim().to_ascii_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = e.strip_prefix(scheme) {
            e = rest.to_string();
            break;
        }
    }
    // Strip query/fragment always.
    if let Some(idx) = e.find(['?', '#']) {
        e.truncate(idx);
    }
    // Strip a path `/…` too — UNLESS the part before the slash is a bare IP, i.e. this is CIDR
    // notation (`10.0.0.0/8`, `fd00::/8`), which must be preserved for `is_ip_or_cidr`.
    if let Some(slash) = e.find('/') {
        if e[..slash].parse::<std::net::IpAddr>().is_err() {
            e.truncate(slash);
        }
    }
    // Strip a trailing :port on a hostname or IPv4 (exactly one colon). IPv6 literals have >=2
    // colons, so they're left intact for is_ip_or_cidr to parse. Split tunneling matches by
    // host/IP, not port, so `example.com:443` bypasses `example.com`.
    if e.matches(':').count() == 1 {
        if let Some((host, port)) = e.rsplit_once(':') {
            if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                e = host.to_string();
            }
        }
    }
    e.trim().to_string()
}

/// A minimal hostname sanity check (not full RFC): at least one dot, only letters/digits/`-`/`.`,
/// no leading/trailing/adjacent dots. Keeps obvious junk ("not a domain") out of the list.
fn is_plausible_hostname(h: &str) -> bool {
    !h.starts_with('.')
        && !h.ends_with('.')
        && !h.contains("..")
        && h.contains('.')
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// Whether `s` is a bare IP or a CIDR (`a.b.c.d/len`). Validated with `std::net` locally so this
/// always-compiled module does NOT depend on the `smart-routing`-gated rules engine (which has its
/// own `parse_ip_or_cidr` for building the matcher). Classification only — the router re-parses.
fn is_ip_or_cidr(s: &str) -> bool {
    use std::net::IpAddr;
    match s.split_once('/') {
        Some((addr, prefix)) => match addr.trim().parse::<IpAddr>() {
            Ok(ip) => prefix
                .trim()
                .parse::<u8>()
                .is_ok_and(|p| p <= if ip.is_ipv4() { 32 } else { 128 }),
            Err(_) => false,
        },
        None => s.parse::<IpAddr>().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips() {
        let st = SplitTunnel {
            enabled: true,
            domains: vec!["google.com".into()],
            ips: vec!["1.2.3.4".into()],
        };
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(parse(&json).unwrap(), st);
    }

    #[test]
    fn parse_defaults_missing_fields() {
        assert_eq!(parse("{}").unwrap(), SplitTunnel::default());
    }

    #[test]
    fn is_empty_ignores_enabled() {
        assert!(SplitTunnel {
            enabled: true,
            ..Default::default()
        }
        .is_empty());
        assert!(!SplitTunnel {
            enabled: false,
            domains: vec!["x.com".into()],
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn add_entries_splits_domains_ips_and_rejects_junk() {
        let mut st = SplitTunnel::default();
        let out = st.add_entries(
            "google.com, https://Mail.Example.com/inbox , 1.2.3.4, 10.0.0.0/8, not a domain, ",
        );
        assert_eq!(
            out.added_domains,
            vec!["google.com".to_string(), "mail.example.com".to_string()]
        );
        assert_eq!(
            out.added_ips,
            vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()]
        );
        assert_eq!(out.rejected, vec!["not a domain".to_string()]);
        assert_eq!(
            st.domains,
            vec!["google.com".to_string(), "mail.example.com".to_string()]
        );
        assert_eq!(
            st.ips,
            vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn add_entries_strips_port_and_accepts_ipv6() {
        let mut st = SplitTunnel::default();
        let out = st.add_entries("example.com:443, https://api.example.com:8443/v1, ::1, fd00::/8");
        assert_eq!(
            out.added_domains,
            vec!["example.com".to_string(), "api.example.com".to_string()]
        );
        assert_eq!(
            out.added_ips,
            vec!["::1".to_string(), "fd00::/8".to_string()]
        );
        assert!(out.rejected.is_empty());
    }

    #[test]
    fn add_entries_strips_bare_host_path_but_keeps_cidr() {
        let mut st = SplitTunnel::default();
        // A scheme-less host with a path is normalized to the bare host; a bare CIDR keeps its slash.
        let out = st.add_entries("example.com/path, foo.com/a/b?q=1, 10.0.0.0/8");
        assert_eq!(
            out.added_domains,
            vec!["example.com".to_string(), "foo.com".to_string()]
        );
        assert_eq!(out.added_ips, vec!["10.0.0.0/8".to_string()]);
        assert!(out.rejected.is_empty());
    }

    #[test]
    fn add_entries_dedupes_against_existing() {
        let mut st = SplitTunnel {
            enabled: true,
            domains: vec!["google.com".into()],
            ips: vec![],
        };
        let out = st.add_entries("google.com, GOOGLE.com, x.com");
        assert_eq!(out.added_domains, vec!["x.com".to_string()]); // google.com already present
        assert_eq!(
            st.domains,
            vec!["google.com".to_string(), "x.com".to_string()]
        );
    }
}
