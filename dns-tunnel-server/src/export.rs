//! Periodic OTLP/HTTP export of [`Metrics`] to a collector.
//!
//! One task, one connection per export, no retry queue. That is a deliberate consequence of the
//! metrics being **cumulative**: a failed export is not a lost count, only a lost sample, because the
//! next successful export carries the running total that includes everything the failed one would
//! have reported. Spooling to disk (what the client's `diag` path does for logs, where each record is
//! unique and unrecoverable) would buy nothing here and would add a disk-growth failure mode to a
//! server whose job is to stay up.
//!
//! Export is **off unless an endpoint is configured**. A server with no `--otel-endpoint` opens no
//! outbound connections at all, which keeps the default deployment as quiet on the network as it was
//! before this module existed.

use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::metrics::Metrics;
use crate::otlp::{encode_metrics, ResourceAttrs};

/// Where and how often to export.
pub struct ExportConfig {
    /// Collector host, e.g. `ingest.us.signoz.cloud`.
    pub host: String,
    pub port: u16,
    /// Ingestion key, sent as `signoz-ingestion-key`. Absent is allowed — a self-hosted collector on
    /// a private network may not want one.
    pub key: Option<String>,
    /// Opaque operator-chosen label distinguishing this server on a dashboard. Never derived from the
    /// zone or the host's address.
    pub instance: String,
    pub interval: Duration,
}

/// How long one export attempt may take end to end.
///
/// Bounded well under a typical interval so a black-holed collector cannot pile up tasks. The export
/// task is independent of the UDP loop, so this timeout protects only telemetry — a hung collector
/// can never slow the tunnel.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// Spawn the exporter. Returns the handle so the caller owns cancellation.
pub fn spawn(metrics: Arc<Metrics>, cfg: ExportConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let res = ResourceAttrs {
            service_name: "spark-dns-tunnel-server".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            instance: cfg.instance.clone(),
        };
        let start_nanos = unix_nanos();
        let mut ticker = tokio::time::interval(cfg.interval);
        // The first tick fires immediately; skipping a missed tick keeps a slow export from
        // producing a burst of catch-up exports afterwards.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            let body = encode_metrics(&res, &metrics.snapshot(), start_nanos, unix_nanos());
            match tokio::time::timeout(EXPORT_TIMEOUT, post(&cfg, &body)).await {
                Ok(Ok(status)) if (200..300).contains(&status) => {
                    tracing::debug!(status, "metrics exported");
                }
                // The collector's host is operator-configured, not user-supplied, so naming it in a
                // log breaks no hygiene rule — but the status alone is what actually diagnoses this.
                Ok(Ok(status)) => tracing::warn!(status, "metrics export rejected"),
                Ok(Err(e)) => tracing::warn!(error = %e, "metrics export failed"),
                Err(_) => tracing::warn!("metrics export timed out"),
            }
        }
    })
}

/// One export: connect, TLS, POST, read the status line.
async fn post(cfg: &ExportConfig, body: &[u8]) -> io::Result<u16> {
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port)).await?;
    let mut tls = tls_connect(tcp, &cfg.host).await?;

    let mut head = String::with_capacity(256);
    head.push_str("POST /v1/metrics HTTP/1.1\r\n");
    head.push_str(&format!("Host: {}\r\n", cfg.host));
    head.push_str("Content-Type: application/json\r\n");
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    if let Some(key) = &cfg.key {
        head.push_str(&format!("signoz-ingestion-key: {key}\r\n"));
    }
    // One connection per export; asking the collector to keep it open would idle a socket for the
    // whole interval to save a handshake once a minute.
    head.push_str("Connection: close\r\n\r\n");

    tls.write_all(head.as_bytes()).await?;
    tls.write_all(body).await?;
    tls.flush().await?;

    let mut buf = [0u8; 128];
    let n = tls.read(&mut buf).await?;
    parse_status(&buf[..n])
}

/// TLS with an explicit Mozilla root store.
///
/// BoringSSL ships no built-in root store, so an empty one would fail every handshake instantly —
/// the same reason `core/src/transport/probe.rs` loads the roots for the client. Built once: parsing
/// ~150 certificates per export would be absurd for a task that runs on a timer forever.
async fn tls_connect(
    stream: TcpStream,
    host: &str,
) -> io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    use boring2::ssl::{SslConnector, SslMethod};
    use boring2::x509::X509;
    use std::sync::OnceLock;

    static CONNECTOR: OnceLock<Option<SslConnector>> = OnceLock::new();
    let connector = CONNECTOR
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
        .ok_or_else(|| io::Error::other("otlp tls: failed to build the TLS connector"))?;

    let config = connector
        .configure()
        .map_err(|e| io::Error::other(format!("otlp tls: {e}")))?;
    tokio_boring2::connect(config, host, stream)
        .await
        .map_err(|e| io::Error::other(format!("otlp tls handshake: {e}")))
}

/// Pull the status code out of an HTTP/1.1 status line.
fn parse_status(head: &[u8]) -> io::Result<u16> {
    let text = String::from_utf8_lossy(head);
    let line = text.lines().next().unwrap_or_default();
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other("otlp: malformed HTTP status line"))
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_codes() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n").ok(), Some(200));
        assert_eq!(
            parse_status(b"HTTP/1.1 401 Unauthorized\r\n").ok(),
            Some(401)
        );
        assert_eq!(parse_status(b"HTTP/1.1 503 \r\n").ok(), Some(503));
    }

    #[test]
    fn malformed_status_is_an_error() {
        assert!(parse_status(b"").is_err());
        assert!(parse_status(b"garbage\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1 notanumber OK\r\n").is_err());
    }
}
