//! Health probe for multi-server selection (design: `docs/multi-server-selection-design.md`):
//! time a transport's establish + verify it works end-to-end by fetching a callback URL *through*
//! it (2xx = healthy). The HTTP client is hand-rolled (no `hyper`/`reqwest`); HTTPS reuses the
//! `boring` backend linked by `anytls` (the callback TLS rides inside the tunnel, so no mimicry).

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::transport::Transport;

/// A minimally-parsed callback URL: `{scheme}://{host}[:{port}]{path}`. Hand-parsed (no `url` crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackUrl {
    /// `true` for `https://` (TLS), `false` for `http://`.
    pub tls: bool,
    /// Host to dial through the transport.
    pub host: String,
    /// Port (defaults: 443 for https, 80 for http).
    pub port: u16,
    /// Request path (includes leading `/`; `/` if none).
    pub path: String,
}

impl CallbackUrl {
    /// Parse `http(s)://host[:port]/path`. Errors on any other scheme or a malformed authority.
    pub fn parse(s: &str) -> io::Result<Self> {
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| io::Error::other(format!("callback url missing scheme: {s}")))?;
        let (tls, default_port) = match scheme {
            "https" => (true, 443),
            "http" => (false, 80),
            other => {
                return Err(io::Error::other(format!(
                    "unsupported callback scheme `{other}`"
                )))
            }
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(io::Error::other(format!("callback url missing host: {s}")));
        }
        let (host, port) = parse_authority(authority, default_port)?;
        Ok(CallbackUrl {
            tls,
            host,
            port,
            path: path.to_owned(),
        })
    }
}

/// Split an authority into `(host, port)`. Handles bracketed IPv6 (`[2001:db8::1]` / `[2001:db8::1]:443`,
/// brackets stripped from the stored host), `host:port`, and bare `host` (default port). Rejects an
/// **unbracketed** IPv6 literal (ambiguous with the port separator) — use `[addr]` instead.
fn parse_authority(authority: &str, default_port: u16) -> io::Result<(String, u16)> {
    if let Some(after_open) = authority.strip_prefix('[') {
        // Bracketed IPv6: "[addr]" or "[addr]:port".
        let (addr, rest) = after_open.split_once(']').ok_or_else(|| {
            io::Error::other(format!(
                "callback url: unterminated IPv6 bracket: {authority}"
            ))
        })?;
        if addr.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(io::Error::other(format!(
                "callback url: invalid IPv6 literal `{addr}`"
            )));
        }
        let port = match rest {
            "" => default_port,
            r => r
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| {
                    io::Error::other(format!("callback url: bad port after IPv6 `{authority}`"))
                })?,
        };
        Ok((addr.to_owned(), port))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return Err(io::Error::other(format!(
                "callback url: unbracketed IPv6 host `{authority}` — write it as `[addr]` or `[addr]:port`"
            )));
        }
        if h.is_empty() {
            return Err(io::Error::other(format!(
                "callback url missing host: {authority}"
            )));
        }
        let port = p
            .parse::<u16>()
            .map_err(|_| io::Error::other(format!("bad callback port: {authority}")))?;
        Ok((h.to_owned(), port))
    } else {
        Ok((authority.to_owned(), default_port))
    }
}

/// Send `GET {path}` over `stream`, read the status line, and return the HTTP status code. Errs if
/// the server sends no parseable status line (no response came back through the transport).
/// `Connection: close` so the server ends the body; we only parse the status line.
///
/// The status code is *returned, not judged*: the caller treats any complete response as a healthy
/// transport, matching lantern-box's `runProbe`. Notably the bandit callback returns 404 once its
/// probe token expires, but the transport that delivered the request still works.
pub(crate) async fn read_http_status<S>(mut stream: S, url: &CallbackUrl) -> io::Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Bracket an IPv6 host for the `Host:` header (e.g. `[2001:db8::1]` / `[2001:db8::1]:8080`).
    let host_for_header = if url.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    let host_header = if (url.tls && url.port == 443) || (!url.tls && url.port == 80) {
        host_for_header
    } else {
        format!("{host_for_header}:{}", url.port)
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: spark-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path, host_header
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    // Read up to the end of the status line (first CRLF). Bounded so a hostile server can't make us
    // read forever; the caller also wraps the whole probe in a deadline.
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while buf.len() < 256 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
    }
    // Status line: "HTTP/1.1 204 ...". Parse the 3-digit code.
    let line = String::from_utf8_lossy(&buf);
    let code = parse_status_code(&line)?;
    // Log the path without its query string: a bandit callback URL carries the probe token in
    // `?token=...`, which must not reach logs (this rides the os_log bridge on device).
    let path = url
        .path
        .split_once('?')
        .map_or(url.path.as_str(), |(p, _)| p);
    tracing::debug!(code, host = %url.host, tls = url.tls, %path, "probe: callback HTTP response");
    Ok(code)
}

/// Parse the HTTP status code from a status line like `HTTP/1.1 204 No Content`.
pub(crate) fn parse_status_code(status_line: &str) -> io::Result<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("malformed HTTP status line: {status_line:?}")))
}

/// Result of probing one server through its transport.
#[derive(Debug, Clone, Copy)]
pub struct ProbeOutcome {
    /// Time to establish the connection and complete the callback GET.
    /// Only meaningful when `healthy` is `true`; set to `Duration::MAX` on failure.
    pub latency: Duration,
    /// `true` iff the transport delivered the probe request and the origin returned any complete
    /// HTTP response within the deadline. The status code is not inspected (see [`read_http_status`]).
    pub healthy: bool,
}

impl ProbeOutcome {
    fn unhealthy() -> Self {
        ProbeOutcome {
            latency: Duration::MAX,
            healthy: false,
        }
    }
}

/// Probe one transport: dial the callback host through it (timing establish + callback),
/// run the HTTP GET, and report health + latency. The whole attempt is bounded by `deadline`.
/// Never panics; any error results in an unhealthy outcome (disqualified from ranking).
pub async fn probe(
    transport: &Arc<dyn Transport>,
    url: &CallbackUrl,
    deadline: Duration,
    label: &str,
) -> ProbeOutcome {
    let started = Instant::now();
    match tokio::time::timeout(deadline, probe_inner(transport, url, label)).await {
        // Any complete HTTP response means the transport carried the request and the origin replied
        // — that is the health signal. The code is logged (a 404 = expired bandit token on a working
        // transport) but not used to gate health.
        Ok(Ok(code)) => {
            let latency = started.elapsed();
            tracing::debug!(server = label, code, ?latency, "probe: healthy");
            ProbeOutcome {
                latency,
                healthy: true,
            }
        }
        // Log *why* a member is unhealthy — otherwise the reason (a protocol handshake failure, no
        // response, a timeout) is invisible and only the `healthy=N` count survives. `label`
        // identifies the pool member so a mixed-protocol pool's failures are attributable.
        Ok(Err(e)) => {
            tracing::debug!(server = label, error = %e, "probe: dial/handshake/no-response (unhealthy)");
            ProbeOutcome::unhealthy()
        }
        Err(_) => {
            tracing::debug!(server = label, ?deadline, "probe: timed out (unhealthy)");
            ProbeOutcome::unhealthy()
        }
    }
}

async fn probe_inner(
    transport: &Arc<dyn Transport>,
    url: &CallbackUrl,
    label: &str,
) -> io::Result<u16> {
    let target = resolve_callback_addr(&url.host, url.port).await?;
    let dialing = Instant::now();
    let stream = transport.dial(target).await?;
    // This line is the diagnostic seam: if a probe times out and we saw "transport dialed" for that
    // server, the handshake completed and the callback GET stalled; if we did NOT, the dial itself
    // (the protocol handshake) hung — i.e. spark couldn't establish to that server. `dial_ms` times
    // just the establish.
    tracing::debug!(
        server = label,
        dial_ms = dialing.elapsed().as_millis() as u64,
        "probe: transport dialed; running callback"
    );
    if url.tls {
        let tls = tls_wrap(stream, &url.host).await?;
        read_http_status(tls, url).await
    } else {
        read_http_status(stream, url).await
    }
}

/// Resolve a callback host to a dial address: an IP literal is used directly; a hostname is resolved
/// via the local resolver. The dial then rides the tunnel to that address, and the original hostname
/// is kept for the TLS SNI + `Host:` header. Probes re-resolve each round (DNS changes are picked up).
/// Local resolution of a public canary is fine for a health check — a poisoned/missing record just
/// marks the server unhealthy this round; no real traffic is routed on the result.
async fn resolve_callback_addr(host: &str, port: u16) -> io::Result<std::net::SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("callback host `{host}` resolved to no addresses")))
}

/// Wrap `stream` in **verifying** client TLS for `host`, using the boring backend linked by `anytls`.
/// No Chrome mimicry (a plain connector) — the callback check rides inside the tunnel, and the
/// config-fetch path that also uses this dials public hosts whose trust is plain public-CA TLS.
///
/// BoringSSL ships **no** built-in trust store, and its default verify paths only resolve the OS CA
/// store on desktop (macOS/Linux/Windows); on Android/iOS they don't, so a direct fetch to a public
/// host fails `CERTIFICATE_VERIFY_FAILED` (verified on the Android emulator). So we load the Mozilla
/// root set (`webpki-root-certs`) into the connector's X509 store — verification then works
/// identically on every platform (the desktop default paths remain in effect on top).
#[cfg(feature = "anytls")]
pub(crate) async fn tls_wrap<S>(
    stream: S,
    host: &str,
) -> io::Result<impl AsyncRead + AsyncWrite + Unpin>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = fetch_connector()?
        .configure()
        .map_err(|e| io::Error::other(format!("probe tls: {e}")))?;
    tokio_boring2::connect(config, host, stream)
        .await
        .map_err(|e| io::Error::other(format!("probe tls handshake: {e}")))
}

/// The shared client connector, **built exactly once and reused** — its `.configure()` mints a fresh
/// per-connection config, so a single connector serves every call. The **entire** build (including
/// DER-parsing the ~150-cert Mozilla root set into the X509 store) runs inside the `OnceLock`
/// initializer, so concurrent first-callers can't each parse the roots — important because `tls_wrap`
/// runs in the multi-server probe loop. See [`tls_wrap`] for why the roots are loaded (BoringSSL has
/// no built-in store; Android/iOS don't resolve it via the default verify paths). A cert that fails to
/// parse is skipped. The cached value is `None` only if the connector itself can't be allocated (an
/// The Mozilla root set as PEM, for a flint search `Space`'s trust anchors.
///
/// The same root set [`fetch_connector`] loads, in the other shape flint wants: `webpki-root-certs`
/// ships DER, `flint_proxyless::Space::roots` wants PEM. Kept beside it deliberately — root handling
/// belongs in one place, and this file already explains why BoringSSL needs it at all.
///
/// Leaving `Space::roots` empty is not a neutral default: flint falls back to BoringSSL's
/// `set_default_paths()`, which finds nothing on macOS (certificates live in the Keychain) and on
/// mobile. Every candidate then fails certificate verification instantly, and a strategy search that
/// reports "all N candidates failed" in about a second is indistinguishable from a censored network —
/// a bad thing for a censorship tool to be unable to tell apart.
///
/// Built once: parsing ~150 certificates per dial would be absurd, and the search dials often.
///
/// Gated on `proxyless` alone, not `any(proxyless, config-fetch)`: every caller is a proxyless
/// search space, so the `config-fetch` arm only made the function dead code in a `config-fetch`-only
/// build — which fails `-D warnings`. Widen this the day a non-proxyless caller exists, not before.
#[cfg(all(feature = "anytls", feature = "proxyless"))]
pub(crate) fn webpki_roots_pem() -> std::sync::Arc<[String]> {
    use std::sync::OnceLock;
    static ROOTS: OnceLock<std::sync::Arc<[String]>> = OnceLock::new();
    std::sync::Arc::clone(ROOTS.get_or_init(|| {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|der| boring2::x509::X509::from_der(der.as_ref()).ok())
            .filter_map(|cert| cert.to_pem().ok())
            .filter_map(|pem| String::from_utf8(pem).ok())
            .collect::<Vec<_>>()
            .into()
    }))
}

/// OOM-class failure); then every call errors, which is correct — nothing can dial without it.
#[cfg(feature = "anytls")]
fn fetch_connector() -> io::Result<&'static boring2::ssl::SslConnector> {
    use boring2::ssl::{SslConnector, SslMethod};
    use boring2::x509::X509;
    use std::sync::OnceLock;

    static CONNECTOR: OnceLock<Option<SslConnector>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let mut builder = SslConnector::builder(SslMethod::tls_client()).ok()?;
            {
                let store = builder.cert_store_mut();
                for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                    if let Ok(cert) = X509::from_der(der.as_ref()) {
                        let _ = store.add_cert(cert);
                    }
                }
            }
            Some(builder.build())
        })
        .as_ref()
        .ok_or_else(|| io::Error::other("probe tls: failed to build the TLS connector"))
}

#[cfg(not(feature = "anytls"))]
pub(crate) async fn tls_wrap<S>(_stream: S, _host: &str) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Err(io::Error::other(
        "https callback URL requires a TLS backend; build with the `anytls` feature (or use an http:// callback)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Transport;
    use crate::BoxedStream;
    use async_trait::async_trait;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct FakeTransport {
        status: &'static [u8],
    }

    #[async_trait]
    impl Transport for FakeTransport {
        async fn dial(&self, _t: SocketAddr) -> io::Result<BoxedStream> {
            let (client, mut server) = tokio::io::duplex(4096);
            let status = self.status;
            tokio::spawn(async move {
                let mut b = vec![0u8; 1024];
                let _ = server.read(&mut b).await;
                let _ = server.write_all(status).await;
            });
            Ok(Box::new(client))
        }

        /// Address-agnostic double: a domain dials exactly as an IP does.
        async fn dial_addr(&self, target: crate::transport::Address) -> io::Result<BoxedStream> {
            match target {
                crate::transport::Address::Ip(sa) => self.dial(sa).await,
                crate::transport::Address::Domain { port, .. } => {
                    self.dial(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
                        .await
                }
            }
        }
    }

    #[tokio::test]
    async fn probe_healthy_on_2xx_with_latency() {
        let t: Arc<dyn Transport> = Arc::new(FakeTransport {
            status: b"HTTP/1.1 204 No Content\r\n\r\n",
        });
        let url = CallbackUrl {
            tls: false,
            host: "127.0.0.1".into(),
            port: 80,
            path: "/".into(),
        };
        let out = probe(&t, &url, Duration::from_secs(5), "test").await;
        assert!(out.healthy);
    }

    // Any complete HTTP response means the transport carried the request and the origin replied —
    // that is the health signal, matching lantern-box's `runProbe` (which never inspects the status
    // code). The bandit callback returns 404 once its probe token expires (probe TTL =
    // poll_interval + 30s), so a working transport on a slightly-stale cached config returns 404;
    // gating health on 2xx would wrongly disqualify every server. 4xx/5xx are all healthy.
    #[tokio::test]
    async fn probe_healthy_on_404_expired_token() {
        let t: Arc<dyn Transport> = Arc::new(FakeTransport {
            status: b"HTTP/1.1 404 Not Found\r\n\r\n",
        });
        let url = CallbackUrl {
            tls: false,
            host: "127.0.0.1".into(),
            port: 80,
            path: "/v1/bandit/callback".into(),
        };
        assert!(
            probe(&t, &url, Duration::from_secs(5), "test")
                .await
                .healthy
        );
    }

    #[tokio::test]
    async fn probe_healthy_on_5xx_response() {
        let t: Arc<dyn Transport> = Arc::new(FakeTransport {
            status: b"HTTP/1.1 500 Err\r\n\r\n",
        });
        let url = CallbackUrl {
            tls: false,
            host: "127.0.0.1".into(),
            port: 80,
            path: "/".into(),
        };
        assert!(
            probe(&t, &url, Duration::from_secs(5), "test")
                .await
                .healthy
        );
    }

    // Unhealthy now means the transport never delivered a response: the dial succeeds but the server
    // closes without sending a status line, so no HTTP response comes back.
    #[tokio::test]
    async fn probe_unhealthy_on_no_response() {
        let t: Arc<dyn Transport> = Arc::new(FakeTransport { status: b"" });
        let url = CallbackUrl {
            tls: false,
            host: "127.0.0.1".into(),
            port: 80,
            path: "/".into(),
        };
        assert!(
            !probe(&t, &url, Duration::from_secs(5), "test")
                .await
                .healthy
        );
    }

    #[tokio::test]
    async fn read_http_status_reads_code_and_sends_request() {
        let (client, mut server) = tokio::io::duplex(4096);
        let url = CallbackUrl {
            tls: false,
            host: "h.example".into(),
            port: 80,
            path: "/ok".into(),
        };
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            req
        });
        let code = read_http_status(client, &url).await.unwrap();
        assert_eq!(code, 204);
        let req = server_task.await.unwrap();
        assert!(req.starts_with("GET /ok HTTP/1.1\r\n"), "req was: {req}");
        assert!(req.contains("Host: h.example\r\n"));
    }

    // A 4xx is still a complete response, so it parses to its code; the caller treats it as healthy.
    #[tokio::test]
    async fn read_http_status_returns_4xx_code() {
        let (client, mut server) = tokio::io::duplex(4096);
        let url = CallbackUrl {
            tls: false,
            host: "h.example".into(),
            port: 80,
            path: "/".into(),
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        assert_eq!(read_http_status(client, &url).await.unwrap(), 403);
    }

    #[test]
    fn parses_callback_urls() {
        let u = CallbackUrl::parse("https://canary.example/generate_204").unwrap();
        assert_eq!(
            u,
            CallbackUrl {
                tls: true,
                host: "canary.example".into(),
                port: 443,
                path: "/generate_204".into()
            }
        );
        let u = CallbackUrl::parse("http://1.2.3.4:8080/ok").unwrap();
        assert_eq!(
            u,
            CallbackUrl {
                tls: false,
                host: "1.2.3.4".into(),
                port: 8080,
                path: "/ok".into()
            }
        );
        let u = CallbackUrl::parse("https://h.example").unwrap();
        assert_eq!(u.path, "/");
        assert!(CallbackUrl::parse("ftp://h/x").is_err());
        assert!(CallbackUrl::parse("notaurl").is_err());
        assert!(CallbackUrl::parse("https://:443/x").is_err());
    }

    #[test]
    fn parses_bracketed_ipv6_and_rejects_unbracketed() {
        // bracketed IPv6, brackets stripped from the stored host; default + explicit port.
        let u = CallbackUrl::parse("https://[2001:db8::1]/p").unwrap();
        assert_eq!(
            u,
            CallbackUrl {
                tls: true,
                host: "2001:db8::1".into(),
                port: 443,
                path: "/p".into()
            }
        );
        let u = CallbackUrl::parse("http://[2001:db8::1]:8080/").unwrap();
        assert_eq!(
            u,
            CallbackUrl {
                tls: false,
                host: "2001:db8::1".into(),
                port: 8080,
                path: "/".into()
            }
        );
        // the stored host parses back as an IpAddr (so resolve_callback_addr uses the IP fast path).
        assert!(CallbackUrl::parse("https://[2001:db8::1]/p")
            .unwrap()
            .host
            .parse::<std::net::IpAddr>()
            .is_ok());
        // unbracketed IPv6 is ambiguous with the port separator → rejected.
        assert!(CallbackUrl::parse("http://2001:db8::1/x").is_err());
        // malformed brackets / bad literal.
        assert!(CallbackUrl::parse("http://[2001:db8::1/x").is_err());
        assert!(CallbackUrl::parse("http://[notv6]/x").is_err());
    }

    #[tokio::test]
    async fn resolve_callback_addr_handles_ip_and_localhost() {
        assert_eq!(
            resolve_callback_addr("1.2.3.4", 443).await.unwrap(),
            "1.2.3.4:443".parse().unwrap()
        );
        let a = resolve_callback_addr("localhost", 80).await.unwrap();
        assert!(a.ip().is_loopback());
        assert_eq!(a.port(), 80);
    }

    #[tokio::test]
    async fn http_get_includes_nondefault_port_in_host() {
        let (client, mut server) = tokio::io::duplex(4096);
        let url = CallbackUrl {
            tls: false,
            host: "h.example".into(),
            port: 8080,
            path: "/".into(),
        };
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let _ = read_http_status(client, &url).await.unwrap();
        let req = server_task.await.unwrap();
        assert!(req.contains("Host: h.example:8080\r\n"), "req was: {req}");
    }

    /// Live e2e: probe a real callback through a direct (no-proxy) transport. Set
    /// `SPARK_LIVE_CALLBACK` to any reachable `http(s)://` URL — hostname or IP (the probe resolves
    /// hostnames), e.g. `SPARK_LIVE_CALLBACK=https://www.gstatic.com/generate_204`. https needs `anytls`.
    /// Run: `SPARK_LIVE_CALLBACK=... cargo test -p spark-core --features anytls -- --ignored live_probe`
    #[tokio::test]
    #[ignore = "live: needs network + SPARK_LIVE_CALLBACK"]
    async fn live_probe() {
        let Ok(raw) = std::env::var("SPARK_LIVE_CALLBACK") else {
            return;
        };
        let url = CallbackUrl::parse(&raw).expect("valid SPARK_LIVE_CALLBACK");
        let direct: std::sync::Arc<dyn crate::transport::Transport> =
            std::sync::Arc::new(crate::transport::DirectTransport::new(None));
        let out = probe(&direct, &url, std::time::Duration::from_secs(8), "live").await;
        assert!(out.healthy, "live callback {raw} should be healthy");
    }
}
