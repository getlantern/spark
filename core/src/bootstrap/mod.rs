//! Un-poisoned control-plane name resolution for spark startup (design:
//! `docs/bootstrap-resolver-design.md`).
//!
//! Resolution races at two levels: an *outer* race across strategies ([`RacingResolver`] over
//! [`DohResolver`] / [`ProxyResolver`]) and an *inner* race within DoH across the resolver pool
//! (`flint_dns::resolve`). Neither a blocked strategy nor a blocked individual resolver holds up the
//! first **validated** answer.

// Import the full set the module uses by the end of Phase C. `Arc`/`Duration`/`Config`/`Endpoint`/
// `UdpTransport` are used by Tasks C2–C4; they produce harmless unused-import warnings until then
// (this task's gate is `cargo test`, where warnings don't fail; the `-D warnings` clippy gate runs at
// the end of Phase C, by which point all are used).
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::{Config, Endpoint};
use crate::transport::UdpTransport;

/// Resolves a control-plane hostname to its first **validated** address. One impl per resolution
/// strategy; [`RacingResolver`] composes several. A trait so the wiring is unit-testable with a fake.
#[async_trait]
pub trait NameResolver: Send + Sync {
    /// Resolve `host` to a `SocketAddr` on `port`, returning the first validated address.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr>;
}

/// The outer happy-eyeballs race: holds an ordered set of strategy resolvers and returns the first
/// that yields a validated answer; errors only if every strategy fails.
pub struct RacingResolver {
    strategies: Vec<Box<dyn NameResolver>>,
}

impl RacingResolver {
    /// Race the given strategies (order is informational; all start together — the field is small).
    pub fn new(strategies: Vec<Box<dyn NameResolver>>) -> Self {
        Self { strategies }
    }
}

#[async_trait]
impl NameResolver for RacingResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        match flint_dial::race_with(self.strategies.len(), |i| {
            self.strategies[i].resolve(host, port)
        })
        .await
        {
            Ok((_winner, addr)) => Ok(addr),
            Err(errors) => Err(io::Error::other(format!(
                "all {} resolver strategies failed for {host}: {errors:?}",
                self.strategies.len()
            ))),
        }
    }
}

/// The always-available strategy: resolve over `flint_dns`'s un-poisoned DoH pool (the inner race).
/// Takes the first validated A record. The per-network winner cache is intentionally **not** used
/// here (design §3.1) — bootstrap is infrequent and a stale cached winner could eat a timeout.
pub struct DohResolver {
    pool: Vec<flint_dns::Resolver>,
}

impl Default for DohResolver {
    fn default() -> Self {
        Self {
            pool: flint_dns::default_pool(),
        }
    }
}

#[async_trait]
impl NameResolver for DohResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        let ips = flint_dns::resolve(host, flint_dns::TYPE_A, &self.pool)
            .await
            .map_err(io::Error::other)?;
        let ip = ips
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("DoH returned no A records"))?;
        Ok(SocketAddr::new(ip, port))
    }
}

/// Resolve a name by tunnelling a plain DNS/UDP query **through a proxy** addressed by IP: the exit
/// resolves upstream un-poisoned. Reuses `flint_dns`'s codec + answer validation. Independent of the
/// data-plane tunnel — it only needs the transport's UDP client. Chicken-and-egg (design §3.1): a
/// proxy named by *hostname* can't resolve itself through a proxy, so this only adds racers for
/// already-IP-addressed proxies.
pub struct ProxyResolver {
    udp: Arc<dyn UdpTransport>,
    upstreams: Vec<SocketAddr>,
    deadline: Duration,
}

impl ProxyResolver {
    /// A `ProxyResolver` that races `upstreams` (public recursive resolvers, e.g. `8.8.8.8:53`) over
    /// `udp`. Each attempt is bounded by a 5s deadline so an all-fail returns promptly.
    pub fn new(udp: Arc<dyn UdpTransport>, upstreams: Vec<SocketAddr>) -> Self {
        Self {
            udp,
            upstreams,
            deadline: Duration::from_secs(5),
        }
    }

    async fn query_one(
        &self,
        upstream: SocketAddr,
        host: &str,
        port: u16,
    ) -> io::Result<SocketAddr> {
        let (mut sink, mut source) = self.udp.dial_udp(upstream).await?;
        let query =
            flint_dns::codec::build_query(host, flint_dns::TYPE_A).map_err(io::Error::other)?;
        sink.send(&query).await?;
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(self.deadline, source.recv(&mut buf))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS-through-proxy timed out")
            })??;
        let answers = flint_dns::codec::parse_response(&buf[..n]).map_err(io::Error::other)?;
        let validated = flint_dns::validate::validate_answers(answers).map_err(io::Error::other)?;
        let ip = validated
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("no validated A records"))?;
        Ok(SocketAddr::new(ip, port))
    }
}

#[async_trait]
impl NameResolver for ProxyResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        match flint_dial::race_with(self.upstreams.len(), |i| {
            self.query_one(self.upstreams[i], host, port)
        })
        .await
        {
            Ok((_winner, addr)) => Ok(addr),
            Err(errors) => Err(io::Error::other(format!(
                "all {} proxy upstreams failed for {host}: {errors:?}",
                self.upstreams.len()
            ))),
        }
    }
}

/// Resolve every `Endpoint::Host` proxy `server` in `config` to an `Endpoint::Ip` via `resolver`
/// (design §3.3). An already-resolved `Ip` is left untouched. Errors with a clear message if any host
/// fails to resolve — **no silent fallthrough** to a poisoned/system lookup.
pub async fn resolve_endpoints(config: &mut Config, resolver: &dyn NameResolver) -> io::Result<()> {
    let mut servers: Vec<&mut Endpoint> = Vec::new();
    if let Some(anytls) = config.transport.anytls.as_mut() {
        servers.push(&mut anytls.server);
    }
    if let Some(samizdat) = config.transport.samizdat.as_mut() {
        servers.push(&mut samizdat.server);
    }
    for ep in servers {
        if let Some((host, port)) = ep.unresolved() {
            let host = host.to_owned();
            let addr = resolver
                .resolve(&host, port)
                .await
                .map_err(|e| io::Error::other(format!("couldn't resolve {host}:{port}: {e}")))?;
            *ep = Endpoint::Ip(addr);
        }
    }
    Ok(())
}

/// Build the default startup resolver. v1: DoH only — it is the always-available, un-poisoned path.
/// `ProxyResolver` needs an IP-addressed proxy to tunnel a query through, but with spark's current
/// single-proxy config a proxy named by *hostname* is exactly the case being resolved, so there is no
/// IP proxy to add here (chicken-and-egg, design §3.1). `ProxyResolver` is built + tested for the
/// future multi-proxy / API config-fetch consumer, which will construct it directly.
pub fn default_resolver(_config: &Config) -> RacingResolver {
    RacingResolver::new(vec![Box::new(DohResolver::default())])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AnytlsConfig, TransportConfig};
    use crate::transport::{BoxedPacketSink, BoxedPacketSource, PacketSink, PacketSource};

    /// A canned A-record response for `name` → `ip`, matching `flint_dns::codec::parse_response`
    /// (header, one question, one answer with a 0xC00C name pointer).
    fn dns_response_a(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0x00, 0x00]); // ID
        m.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, rcode=0
        m.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        m.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
        m.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        m.extend_from_slice(&[0xc0, 0x0c]); // answer NAME → pointer to the question
        m.extend_from_slice(&[0x00, 0x01]); // TYPE A
        m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300
        m.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        m.extend_from_slice(&ip);
        m
    }

    struct FakeUdp {
        response: Vec<u8>,
    }
    #[async_trait]
    impl UdpTransport for FakeUdp {
        async fn dial_udp(
            &self,
            _target: SocketAddr,
        ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
            Ok((
                Box::new(FakeSink),
                Box::new(FakeSource {
                    response: self.response.clone(),
                }),
            ))
        }
    }
    struct FakeSink;
    #[async_trait]
    impl PacketSink for FakeSink {
        async fn send(&mut self, _payload: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }
    struct FakeSource {
        response: Vec<u8>,
    }
    #[async_trait]
    impl PacketSource for FakeSource {
        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.response.len().min(buf.len());
            buf[..n].copy_from_slice(&self.response[..n]);
            Ok(n)
        }
    }

    #[tokio::test]
    async fn proxy_resolver_parses_and_validates() {
        let udp: Arc<dyn UdpTransport> = Arc::new(FakeUdp {
            response: dns_response_a("example.com", [93, 184, 216, 34]),
        });
        let r = ProxyResolver::new(udp, vec!["8.8.8.8:53".parse().unwrap()]);
        assert_eq!(
            r.resolve("example.com", 443).await.unwrap(),
            "93.184.216.34:443".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn proxy_resolver_rejects_a_bogon() {
        let udp: Arc<dyn UdpTransport> = Arc::new(FakeUdp {
            response: dns_response_a("example.com", [0, 0, 0, 0]), // 0.0.0.0 is a bogon
        });
        let r = ProxyResolver::new(udp, vec!["8.8.8.8:53".parse().unwrap()]);
        assert!(r.resolve("example.com", 443).await.is_err());
    }

    struct Fixed(io::Result<SocketAddr>);
    #[async_trait]
    impl NameResolver for Fixed {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<SocketAddr> {
            match &self.0 {
                Ok(a) => Ok(*a),
                Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    fn ok(s: &str) -> Box<dyn NameResolver> {
        Box::new(Fixed(Ok(s.parse().unwrap())))
    }
    fn fail() -> Box<dyn NameResolver> {
        Box::new(Fixed(Err(io::Error::other("decline"))))
    }

    #[tokio::test]
    async fn first_validated_wins() {
        let r = RacingResolver::new(vec![fail(), ok("1.2.3.4:443")]);
        assert_eq!(
            r.resolve("h", 443).await.unwrap(),
            "1.2.3.4:443".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn all_fail_is_an_error() {
        let r = RacingResolver::new(vec![fail(), fail()]);
        assert!(r.resolve("h", 443).await.is_err());
    }

    fn anytls_cfg(server: &str) -> Config {
        Config {
            transport: TransportConfig {
                anytls: Some(AnytlsConfig {
                    server: server.parse().unwrap(),
                    password: "pw".into(),
                    sni: None,
                    clienthello: Default::default(),
                    records: Default::default(),
                    gambit: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn resolve_endpoints_rewrites_host_to_ip() {
        let mut cfg = anytls_cfg("proxy.example.com:443");
        let resolver = RacingResolver::new(vec![ok("5.6.7.8:443")]);
        resolve_endpoints(&mut cfg, &resolver).await.unwrap();
        assert_eq!(
            cfg.transport.anytls.unwrap().server,
            Endpoint::Ip("5.6.7.8:443".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn resolve_endpoints_leaves_ip_untouched() {
        let mut cfg = anytls_cfg("1.2.3.4:443");
        // A resolver that would fail if called — proves an Ip endpoint never hits it.
        let resolver = RacingResolver::new(vec![fail()]);
        resolve_endpoints(&mut cfg, &resolver).await.unwrap();
        assert_eq!(
            cfg.transport.anytls.unwrap().server,
            Endpoint::Ip("1.2.3.4:443".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn resolve_endpoints_all_fail_is_an_error() {
        let mut cfg = anytls_cfg("proxy.example.com:443");
        let resolver = RacingResolver::new(vec![fail()]);
        assert!(resolve_endpoints(&mut cfg, &resolver).await.is_err());
    }

    /// Live end-to-end: `DohResolver` resolves a real hostname to a public (non-bogon) address.
    /// Requires network egress + boring; `#[ignore]`d in CI, mirroring flint-dns's own live test.
    /// Run with: `cargo test -p spark-core --features bootstrap-dns -- --ignored doh_resolves_live`
    #[tokio::test]
    #[ignore = "live: requires network egress to public DoH resolvers"]
    async fn doh_resolves_live() {
        let r = DohResolver::default();
        let addr = r
            .resolve("one.one.one.one", 443)
            .await
            .expect("resolve via DoH");
        assert_eq!(addr.port(), 443);
        assert!(!flint_dns::validate::is_bogon(addr.ip()));
    }
}
