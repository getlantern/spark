//! Best-effort resolution of a peer IP to an approximate geographic location.
//!
//! [`GeoResolver`] queries the Lantern geo service over HTTPS and memoizes results
//! in a per-process cache. Every failure — network, HTTP status, or malformed body —
//! collapses to `None`: a missing location is never fatal to sharing.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const GEO_HOST: &str = "geo.getiantem.org";
const GEO_PORT: u16 = 443;
const MAX_GEO_RESPONSE_BYTES: usize = 64 * 1024;

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

/// Resolves peer IPs to approximate locations, caching each result for the process lifetime.
pub struct GeoResolver {
    cache: Mutex<HashMap<IpAddr, Geo>>,
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
    /// so no guard is ever held across an `.await`.
    pub async fn resolve(&self, ip: IpAddr) -> Option<Geo> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(geo) = cache.get(&ip) {
                return Some(geo.clone());
            }
        }

        let body = (self.fetch)(ip).await.ok()?;
        let geo = parse_geo(&body).ok()?;

        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(ip, geo.clone());
        }
        Some(geo)
    }
}

impl Default for GeoResolver {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_geo(body: &str) -> Result<Geo, GeoError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| GeoError::Parse(error.to_string()))?;
    let country_code = value
        .get("country")
        .and_then(|country| country.get("iso_code"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| GeoError::Parse("missing country.iso_code".into()))?
        .to_owned();
    let location = value
        .get("location")
        .ok_or_else(|| GeoError::Parse("missing location".into()))?;
    let lat = location
        .get("latitude")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| GeoError::Parse("missing location.latitude".into()))?;
    let lon = location
        .get("longitude")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| GeoError::Parse("missing location.longitude".into()))?;
    Ok(Geo {
        country_code,
        lat,
        lon,
    })
}

/// Fetches the raw geo-service JSON body for `ip` over HTTPS.
///
/// This mirrors the raw rustls + tokio HTTP/1.1 path in [`crate::freddie`] rather than
/// pulling in a heavyweight HTTP client. It is deliberately best-effort: any failure
/// surfaces as [`GeoError::Fetch`], which [`GeoResolver::resolve`] maps to `None`.
async fn get_geo_json(ip: IpAddr) -> Result<String, GeoError> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| GeoError::Fetch(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
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
        if received.len() > MAX_GEO_RESPONSE_BYTES {
            return Err(GeoError::Fetch("geo response exceeds limit".into()));
        }
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| GeoError::Fetch(error.to_string()))?;
        if read == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..read]);
    }

    let separator = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| GeoError::Fetch("geo response missing header terminator".into()))?;
    let body = &received[separator + 4..];
    String::from_utf8(body.to_vec()).map_err(|error| GeoError::Fetch(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn caches_and_parses() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        // fetch_fn returns the raw geo-service JSON body for an IP
        let resolver = GeoResolver::with_fetcher(move |_ip| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Ok::<_, GeoError>(r#"{"country":{"iso_code":"IR"},"location":{"latitude":35.7,"longitude":51.4}}"#.to_string())
            })
        });
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let g = resolver.resolve(ip).await;
        assert_eq!(
            g,
            Some(Geo {
                country_code: "IR".into(),
                lat: 35.7,
                lon: 51.4
            })
        );
        let _ = resolver.resolve(ip).await; // second call hits cache
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolve_none_on_fetch_error() {
        let resolver = GeoResolver::with_fetcher(|_ip| {
            Box::pin(async { Err(GeoError::Fetch("boom".into())) })
        });
        assert_eq!(
            resolver.resolve(IpAddr::V4(Ipv4Addr::LOCALHOST)).await,
            None
        );
    }
}
