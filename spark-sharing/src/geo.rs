//! Best-effort resolution of a peer IP to an approximate geographic location.
//!
//! [`GeoResolver`] queries the Lantern geo service over HTTPS and memoizes results
//! in a per-process cache. Every failure — network, HTTP status, or malformed body —
//! collapses to `None`: a missing location is never fatal to sharing.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const GEO_HOST: &str = "geo.getiantem.org";
const GEO_PORT: u16 = 443;
const MAX_GEO_RESPONSE_BYTES: usize = 64 * 1024;
/// Whole-lookup deadline (connect + TLS + request + read). Geo is decorative — a slow host must
/// never hold up the sharing event loop that awaits this.
const GEO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Upper bound on remembered lookups (successes and failures). See [`GeoResolver`].
const MAX_CACHE_ENTRIES: usize = 512;

/// An approximate geographic location for a peer, as returned by the geo service.
#[derive(Debug, Clone, PartialEq)]
pub struct Geo {
    pub country_code: String,
    pub lat: f64,
    pub lon: f64,
}

/// Why a single geo lookup could not produce a [`Geo`].
#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    /// The outbound request failed before a usable body was received.
    #[error("geo fetch failed: {0}")]
    Fetch(String),
    /// The response body was not the expected geo-service JSON shape.
    #[error("geo parse failed: {0}")]
    Parse(String),
}

type Fetcher = Box<
    dyn Fn(IpAddr) -> Pin<Box<dyn Future<Output = Result<String, GeoError>> + Send>> + Send + Sync,
>;

/// Resolves peer IPs to approximate locations, memoizing successes AND failures.
///
/// The cache is bounded ([`MAX_CACHE_ENTRIES`]): besides capping memory in a process that can run
/// for weeks, it bounds how long the volunteer's RAM holds the addresses of the censored users it
/// served. Caching failures matters as much as caching hits — without it, a geo service that is down
/// costs a full DNS+TCP+TLS round trip on *every* peer join rather than one per address.
pub struct GeoResolver {
    cache: Mutex<HashMap<IpAddr, Option<Geo>>>,
    fetch: Fetcher,
}

impl GeoResolver {
    /// Creates a resolver backed by the Lantern geo service over HTTPS.
    pub fn new() -> Self {
        Self::with_fetcher(|ip| Box::pin(get_geo_json(ip)))
    }

    /// Creates a resolver backed by a caller-supplied fetcher, for tests.
    pub fn with_fetcher<F>(fetch: F) -> Self
    where
        F: Fn(IpAddr) -> Pin<Box<dyn Future<Output = Result<String, GeoError>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            cache: Mutex::new(HashMap::new()),
            fetch: Box::new(fetch),
        }
    }

    /// Resolves `ip` to a [`Geo`], returning `None` on any cache miss that cannot be filled.
    ///
    /// The cache lock is released before the network fetch and re-acquired only to insert,
    /// so no guard is ever held across an `.await`. The fetch is bounded by [`GEO_TIMEOUT`]:
    /// callers drive this from the sharing event loop, so an unbounded wait here would stall peer
    /// accounting, the tray label, and the UI for as long as the geo host stays unresponsive.
    pub async fn resolve(&self, ip: IpAddr) -> Option<Geo> {
        // A non-global address can only ever come back empty — don't spend a round trip on it.
        if !is_geo_lookupable(ip) {
            return None;
        }
        // Recover from a poisoned cache lock (via `into_inner`) instead of skipping the cache — a
        // poison must not silently turn every lookup into a fresh network request. The guard is
        // scoped so it is released before the `.await` below (never held across it). A cached `None`
        // is a remembered failure and short-circuits just like a hit.
        {
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some(entry) = cache.get(&ip) {
                return entry.clone();
            }
        }

        let geo = match tokio::time::timeout(GEO_TIMEOUT, (self.fetch)(ip)).await {
            Ok(Ok(body)) => parse_geo(&body).ok(),
            // Fetch error, or the timeout elapsed: remember the failure either way.
            Ok(Err(_)) | Err(_) => None,
        };

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // Crude bound: clear wholesale at the cap rather than pull in an LRU dependency. The cap is
        // far above the plausible live-peer count, so a reset costs at most one re-lookup per peer.
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(ip, geo.clone());
        geo
    }
}

impl Default for GeoResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Look up a key case-insensitively. The geo service emits PascalCase (`Country`, `IsoCode`,
/// `Location`, `Latitude`), but be lenient so a future casing change on the service — or a
/// hand-written fixture — doesn't silently turn every lookup into `None` again.
fn get_ci<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    value.get(key).or_else(|| {
        value
            .as_object()?
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    })
}

fn parse_geo(body: &str) -> Result<Geo, GeoError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| GeoError::Parse(error.to_string()))?;
    let country_code = get_ci(&value, "Country")
        .and_then(|country| get_ci(country, "IsoCode"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| GeoError::Parse("missing Country.IsoCode".into()))?
        .to_owned();
    // The service answers 200 with an all-empty record for an address it can't place (verified
    // against a private IP), so an empty ISO code means "unresolved", not "resolved to nowhere".
    if country_code.is_empty() {
        return Err(GeoError::Parse("empty Country.IsoCode".into()));
    }
    let location =
        get_ci(&value, "Location").ok_or_else(|| GeoError::Parse("missing Location".into()))?;
    let lat = get_ci(location, "Latitude")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| GeoError::Parse("missing Location.Latitude".into()))?;
    let lon = get_ci(location, "Longitude")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| GeoError::Parse("missing Location.Longitude".into()))?;
    // Same sentinel on the coordinates: the empty record carries 0/0, which as a real position is
    // open ocean in the Gulf of Guinea. Treat it as unresolved rather than pinning a phantom arc.
    if lat == 0.0 && lon == 0.0 {
        return Err(GeoError::Parse("null island (0,0) coordinates".into()));
    }
    Ok(Geo {
        country_code,
        lat,
        lon,
    })
}

/// Whether `ip` is worth sending to the geo service. A peer's selected ICE candidate is legitimately
/// a LAN host candidate when peer and volunteer share a network (or a CGNAT address), which the
/// service can only answer "unknown" for — so skip it rather than spend a round trip on the join
/// path and disclose the local addressing.
fn is_geo_lookupable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || o[0] == 100 && (o[1] & 0xc0) == 64 // 100.64.0.0/10 CGNAT
                || o[0] == 0)
        }
        IpAddr::V6(v6) => {
            let first = v6.octets()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe) == 0xfc // fc00::/7 unique-local
                || (first == 0xfe && (v6.octets()[1] & 0xc0) == 0x80))
            // fe80::/10 link-local
        }
    }
}

/// A process-wide TLS connector for geo lookups, built once from the webpki roots and reused.
///
/// Building the `RootCertStore` + `ClientConfig` is comparatively expensive; without caching it
/// would be repeated on every cache-miss lookup (once per unique peer IP on the join path).
/// `TlsConnector` is `Arc`-backed, so cloning the cached one is cheap.
fn geo_connector() -> Result<TlsConnector, GeoError> {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    if let Some(connector) = CONNECTOR.get() {
        return Ok(connector.clone());
    }
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| GeoError::Fetch(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    // A concurrent builder may win the race; either way we return a usable connector, and the
    // first to `set` wins the cache slot for all subsequent lookups.
    let _ = CONNECTOR.set(connector.clone());
    Ok(connector)
}

/// Fetches the raw geo-service JSON body for `ip` over HTTPS.
///
/// This mirrors the raw rustls + tokio HTTP/1.1 path in [`crate::freddie`] rather than
/// pulling in a heavyweight HTTP client. It is deliberately best-effort: any failure
/// surfaces as [`GeoError::Fetch`], which [`GeoResolver::resolve`] maps to `None`.
async fn get_geo_json(ip: IpAddr) -> Result<String, GeoError> {
    let connector = geo_connector()?;
    let server_name =
        ServerName::try_from(GEO_HOST).map_err(|error| GeoError::Fetch(error.to_string()))?;

    let stream = TcpStream::connect((GEO_HOST, GEO_PORT))
        .await
        .map_err(|error| GeoError::Fetch(error.to_string()))?;
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| GeoError::Fetch(error.to_string()))?;

    let request = format!(
        "GET /lookup/{ip} HTTP/1.1\r\nHost: {GEO_HOST}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| GeoError::Fetch(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| GeoError::Fetch(error.to_string()))?;

    let mut received = Vec::with_capacity(4096);
    loop {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| GeoError::Fetch(error.to_string()))?;
        if read == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..read]);
        // Check the cap right after appending, so a single read can't push `received` an
        // unbounded amount past the limit before the next iteration.
        if received.len() > MAX_GEO_RESPONSE_BYTES {
            return Err(GeoError::Fetch("geo response exceeds limit".into()));
        }
    }

    http_2xx_body(&received)
}

/// Extract the body of a raw HTTP/1.1 response, requiring a 2xx status.
///
/// Best-effort by design: a non-2xx status is rejected here, and any other framing quirk (e.g. a
/// `Transfer-Encoding: chunked` body, which this deliberately does not decode) either fails here or
/// later at JSON parse — both surface as `None` at [`GeoResolver::resolve`]. The geo service returns
/// a small `Content-Length`-framed JSON, read to EOF via `Connection: close`.
fn http_2xx_body(received: &[u8]) -> Result<String, GeoError> {
    let status_line_end = received
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| GeoError::Fetch("geo response missing status line".into()))?;
    let status_line = String::from_utf8_lossy(&received[..status_line_end]);
    let is_2xx = status_line
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code.starts_with('2'));
    if !is_2xx {
        return Err(GeoError::Fetch(format!(
            "geo response status: {status_line}"
        )));
    }
    let header_end = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| GeoError::Fetch("geo response missing header terminator".into()))?;
    std::str::from_utf8(&received[header_end + 4..])
        .map(str::to_owned)
        .map_err(|error| GeoError::Fetch(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// A REAL geo-service response (captured from `GET /lookup/` for an Iranian address, trimmed to
    /// the fields we read plus the `RepresentedCountry` decoy). The wire format is PascalCase — a
    /// hand-written lowercase fixture is what previously let a key-casing bug ship green, silently
    /// resolving every peer to `None`.
    const REAL_GEO_BODY: &str = r#"{"Country":{"Names":{"en":"Iran"},"IsoCode":"IR","GeoNameID":130758,"IsInEuropeanUnion":false},"Location":{"TimeZone":"Asia/Tehran","Latitude":35.698,"Longitude":51.4115,"MetroCode":0,"AccuracyRadius":1000},"RepresentedCountry":{"Names":null,"IsoCode":"","Type":"","GeoNameID":0,"IsInEuropeanUnion":false}}"#;

    /// The service's "couldn't place this address" answer: HTTP 200 with an empty record.
    const UNKNOWN_GEO_BODY: &str = r#"{"Country":{"Names":null,"IsoCode":"","GeoNameID":0},"Location":{"Latitude":0,"Longitude":0}}"#;

    /// A routable address, so `is_geo_lookupable` doesn't short-circuit before the fetcher.
    fn global_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
    }

    #[tokio::test]
    async fn caches_and_parses_real_service_body() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let resolver = GeoResolver::with_fetcher(move |_ip| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok::<_, GeoError>(REAL_GEO_BODY.to_string()) })
        });
        let g = resolver.resolve(global_ip()).await;
        assert_eq!(
            g,
            Some(Geo {
                country_code: "IR".into(),
                lat: 35.698,
                lon: 51.4115
            }),
            "must parse the real PascalCase wire format, and must not pick up RepresentedCountry"
        );
        let _ = resolver.resolve(global_ip()).await; // second call hits cache
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn parse_geo_rejects_the_unknown_address_record() {
        // 200-with-empty-record must be an error (→ `None`), not a phantom pin at (0,0).
        assert!(parse_geo(UNKNOWN_GEO_BODY).is_err());
    }

    #[tokio::test]
    async fn resolve_none_on_fetch_error_and_caches_the_failure() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let resolver = GeoResolver::with_fetcher(move |_ip| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Err(GeoError::Fetch("boom".into())) })
        });
        assert_eq!(resolver.resolve(global_ip()).await, None);
        assert_eq!(resolver.resolve(global_ip()).await, None);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a failed lookup must be remembered, not retried on every peer join"
        );
    }

    #[tokio::test]
    async fn non_global_ips_never_reach_the_network() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let resolver = GeoResolver::with_fetcher(move |_ip| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok::<_, GeoError>(REAL_GEO_BODY.to_string()) })
        });
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), // CGNAT
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            "fe80::1".parse().expect("link-local literal"),
            "fd00::1".parse().expect("unique-local literal"),
        ] {
            assert_eq!(resolver.resolve(ip).await, None, "{ip} must be skipped");
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        // A routable address still resolves.
        assert!(resolver.resolve(global_ip()).await.is_some());
    }

    #[tokio::test]
    async fn resolve_gives_up_when_the_fetch_hangs() {
        // A fetcher that never completes must not park the caller (the sharing event loop).
        let resolver = GeoResolver::with_fetcher(|_ip| {
            Box::pin(async {
                std::future::pending::<()>().await;
                unreachable!()
            })
        });
        tokio::time::pause();
        let task = tokio::spawn(async move { resolver.resolve(global_ip()).await });
        tokio::time::advance(GEO_TIMEOUT + std::time::Duration::from_secs(1)).await;
        assert_eq!(task.await.expect("resolve task"), None);
    }

    #[test]
    fn http_2xx_body_extracts_on_200() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        assert_eq!(http_2xx_body(resp).unwrap(), "{\"ok\":true}");
    }

    #[test]
    fn http_2xx_body_rejects_non_2xx() {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert!(http_2xx_body(resp).is_err());
    }

    #[test]
    fn http_2xx_body_rejects_missing_terminator() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json";
        assert!(http_2xx_body(resp).is_err());
    }
}
