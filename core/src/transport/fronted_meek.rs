//! Domain-fronted meek **polling** transport — the Shir-o-Khorshid CDN-fronting
//! model (NO MITM, no local cert). Flows tunnel to Lantern's meek-server through
//! a CDN edge the censor can't block (Akamai/CloudFront/Aliyun): the client TLS-
//! connects to an edge IP with a benign/empty SNI and carries the real host in
//! the encrypted `Host` header; the CDN routes by Host to the meek origin, which
//! relays to a SOCKS5 upstream and out.
//!
//! **Self-bootstrapping:** with no server-delivered front list, it discovers
//! working edges *from the user's own network* — Akamai edge hostnames resolved
//! through the system resolver (geo-local, truthful), plus CloudFront/Aliyun IPs
//! sampled from embedded prefix lists (see `flint_fronted::scanner`). The
//! candidates are raced (the race doubles as the probe); the winning edge is
//! cached so later flows skip the scan.
//!
//! TCP only — `UdpTransport` reports unsupported (meek is a polling HTTP tunnel).
//!
//! Limitation: the front TLS dial happens inside `flint`, which doesn't take a
//! [`SocketProtector`], so meek's own dials aren't yet pinned to the physical
//! interface. Acceptable while validating; production on macOS needs a
//! socket-protection hook threaded into `flint_dial`.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use tokio::sync::OnceCell;

use flint_fronted::{
    dial_fronts_alpn, open_meek_poll, open_meek_poll_auto, scanner, socks5, DialOptions,
    MaterializedFront, MeekHttpVersion, MeekPollConfig, MeekPollConn, SystemResolver,
};

use super::{BoxedPacketSink, BoxedPacketSource, Transport, UdpTransport};
use crate::config::{
    FrontedMeekConfig, DEFAULT_ALIYUN_MEEK_HOST, DEFAULT_CLOUDFRONT_MEEK_HOST,
    DEFAULT_FRONTED_MEEK_HOST,
};
use crate::BoxedStream;

pub struct FrontedMeekTransport {
    /// Inner host each CDN's fronts route to. The inner `Host` is CDN-specific, so
    /// these can't share one value; the winning front's host is used per connection
    /// (see `open_tunnel`). `meek_host` is Akamai (primary); cloudfront/aliyun feed
    /// the scanner's per-CDN candidate generation.
    meek_host: String,
    cloudfront_host: String,
    aliyun_host: String,
    /// `None` = auto-select per connection from the negotiated ALPN; `Some` =
    /// forced by config.
    http_version: Option<MeekHttpVersion>,
    seed: u64,
    /// Scanned-once candidate fronts (Akamai/CloudFront/Aliyun), built lazily.
    fronts: OnceCell<Vec<MaterializedFront>>,
    /// Last front that worked — tried first to skip the race on the next flow.
    cached: Mutex<Option<MaterializedFront>>,
}

impl FrontedMeekTransport {
    pub fn new(cfg: &FrontedMeekConfig) -> io::Result<Self> {
        // Unset → auto-select per connection from the ALPN the edge negotiates
        // (the boring Chrome dial offers h2,http/1.1). The deployed Akamai endpoint
        // negotiates h1; a CDN that re-originates h2 gets h2 — automatically.
        // "h1"/"h2" force it; empty/whitespace is treated as unset (like meek_host).
        let http_version = match cfg.http_version.as_deref().map(str::trim) {
            None | Some("") => None,
            Some("h1") => Some(MeekHttpVersion::H1),
            Some("h2") => Some(MeekHttpVersion::H2),
            Some(other) => {
                return Err(io::Error::other(format!(
                    "transport.fronted_meek.http_version {other:?} invalid (want \"h1\" or \"h2\")"
                )))
            }
        };
        Ok(Self {
            meek_host: bare_host(&cfg.meek_host, DEFAULT_FRONTED_MEEK_HOST, "meek_host")?,
            cloudfront_host: bare_host(
                &cfg.cloudfront_host,
                DEFAULT_CLOUDFRONT_MEEK_HOST,
                "cloudfront_host",
            )?,
            aliyun_host: bare_host(&cfg.aliyun_host, DEFAULT_ALIYUN_MEEK_HOST, "aliyun_host")?,
            http_version,
            seed: seed_now(),
            fronts: OnceCell::new(),
            cached: Mutex::new(None),
        })
    }

    /// Lazily scan once: Akamai local-DNS + CloudFront/Aliyun prefix sampling →
    /// materialized candidate fronts. No server config required.
    async fn candidate_fronts(&self) -> &[MaterializedFront] {
        self.fronts
            .get_or_init(|| async {
                // Each CDN routes to its own inner host. All three are always set
                // (new() fills empty/whitespace with the built-in default via
                // bare_host), so enable all three CDNs' candidates.
                let targets = scanner::ScanTargets::for_host(self.meek_host.clone())
                    .with_cloudfront_host(self.cloudfront_host.clone())
                    .with_aliyun_host(self.aliyun_host.clone());
                let cands =
                    scanner::all_candidates(&SystemResolver::new(), &targets, self.seed).await;
                cands
                    .iter()
                    .map(|c| MaterializedFront {
                        front: c.to_front(),
                        addrs: vec![c.addr],
                    })
                    .collect()
            })
            .await
    }

    async fn open_tunnel(&self) -> io::Result<MeekPollConn> {
        // Get a fronted connection: the last-known-good front first (single dial,
        // no race), else race the full candidate pool and cache the winner.
        let cached = self
            .cached
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // The meek POSTs must address the host the *winning* front routes to (the
        // inner Host is CDN-specific), so carry it out of the dial with the conn.
        let (conn, inner_host) = 'conn: {
            if let Some(front) = cached {
                if let Ok(c) = dial_fronts_alpn(
                    &self.meek_host,
                    std::slice::from_ref(&front),
                    DialOptions::default(),
                )
                .await
                {
                    let inner = c.fronted_host().to_owned();
                    break 'conn (c, inner);
                }
                // The cached front failed — evict it so every subsequent flow
                // doesn't pay its full dial timeout before falling back to the race.
                *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }
            let fronts = self.candidate_fronts().await;
            let c = dial_fronts_alpn(&self.meek_host, fronts, DialOptions::default())
                .await
                .map_err(io::Error::other)?;
            // Cache and address the *winning* front from the connection itself — its
            // own inner host plus the exact addr that won. Don't index back into
            // `fronts` by candidate_index: that indexes the flattened front×addr dial
            // list, not the `fronts` slice, so it can cache the wrong front if a front
            // ever carries >1 addr.
            let inner = c.fronted_host().to_owned();
            *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = Some(MaterializedFront {
                front: c.front.clone(),
                addrs: vec![c.addr],
            });
            (c, inner)
        };
        // Open meek to the winning front's inner host, picking the HTTP version:
        // forced by config, or auto-detected from the ALPN the winning edge negotiated.
        let m = MeekPollConfig::new(inner_host);
        match self.http_version {
            Some(v) => {
                let mut m = m;
                m.http_version = v;
                open_meek_poll(conn, m)
            }
            None => open_meek_poll_auto(conn, m),
        }
    }
}

#[async_trait]
impl Transport for FrontedMeekTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let mut conn = self.open_tunnel().await?;
        // The meek-server relays each session to a SOCKS5 upstream (microsocks);
        // CONNECT to the application's target over the tunnel.
        socks5::connect(&mut conn, &socks5::Target::Ip(target)).await?;
        Ok(Box::new(conn))
    }
}

#[async_trait]
impl UdpTransport for FrontedMeekTransport {
    async fn dial_udp(
        &self,
        _target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        Err(io::Error::other(
            "fronted-meek: UDP is not supported (meek is a TCP polling tunnel)",
        ))
    }
}

/// Validate a configured meek inner host as a bare DNS authority, defaulting to
/// `default` when empty. meek always fronts on TLS/443, so the host is the DNS
/// name + HTTP Host / verify identity — reject embedded whitespace/control,
/// authority-breaking chars (`/?#@\`), and a port `:`; fail fast here, not at dial.
fn bare_host(value: &str, default: &str, field: &str) -> io::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(default.to_owned());
    }
    if trimmed
        .bytes()
        .any(|b| b <= 0x20 || b >= 0x7f || matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b':'))
    {
        return Err(io::Error::other(format!(
            "transport.fronted_meek.{field} {trimmed:?} is not a bare host \
             (no whitespace/control, `/?#@\\`, or port `:`)"
        )));
    }
    Ok(trimmed.to_owned())
}

fn seed_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(http_version: Option<&str>) -> FrontedMeekConfig {
        FrontedMeekConfig {
            http_version: http_version.map(str::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn empty_host_defaults_and_unset_version_is_auto() {
        let t = FrontedMeekTransport::new(&cfg(None)).expect("new");
        // Each CDN defaults to its own inner host (they can't share one).
        assert_eq!(t.meek_host, DEFAULT_FRONTED_MEEK_HOST);
        assert_eq!(t.cloudfront_host, DEFAULT_CLOUDFRONT_MEEK_HOST);
        assert_eq!(t.aliyun_host, DEFAULT_ALIYUN_MEEK_HOST);
        assert_eq!(t.http_version, None); // auto-select from ALPN
    }

    #[test]
    fn per_cdn_hosts_are_validated_as_bare_hosts() {
        let bad = FrontedMeekConfig {
            cloudfront_host: "https://evil.example/path".into(),
            ..Default::default()
        };
        assert!(FrontedMeekTransport::new(&bad).is_err());
        let ok = FrontedMeekConfig {
            cloudfront_host: "d123.cloudfront.net".into(),
            aliyun_host: "meek.aliyun.example".into(),
            ..Default::default()
        };
        let t = FrontedMeekTransport::new(&ok).expect("new");
        assert_eq!(t.cloudfront_host, "d123.cloudfront.net");
        assert_eq!(t.aliyun_host, "meek.aliyun.example");
    }

    #[test]
    fn http_version_is_parsed_or_rejected() {
        assert_eq!(
            FrontedMeekTransport::new(&cfg(Some("h1")))
                .unwrap()
                .http_version,
            Some(MeekHttpVersion::H1)
        );
        assert_eq!(
            FrontedMeekTransport::new(&cfg(Some("h2")))
                .unwrap()
                .http_version,
            Some(MeekHttpVersion::H2)
        );
        assert!(FrontedMeekTransport::new(&cfg(Some("h3"))).is_err());
    }

    #[test]
    fn explicit_host_is_kept() {
        let t = FrontedMeekTransport::new(&FrontedMeekConfig {
            meek_host: "meek.example.org".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(t.meek_host, "meek.example.org");
    }

    #[tokio::test]
    async fn udp_is_unsupported() {
        let t = FrontedMeekTransport::new(&cfg(None)).unwrap();
        // The Ok variant (BoxedPacketSink, BoxedPacketSource) isn't Debug, so match
        // rather than expect_err.
        match t.dial_udp("1.2.3.4:53".parse().unwrap()).await {
            Ok(_) => panic!("UDP must be unsupported"),
            Err(e) => assert!(e.to_string().contains("UDP")),
        }
    }
}
