//! BoringSSL TLS connector for the AnyTLS transport (feature `anytls`, ADR 0001).
//!
//! Produces a raw TLS byte stream the [`super::session`] layer runs over. Certificate verification
//! is **skipped**: AnyTLS authenticates with the password (`sha256`), and TLS is the camouflage
//! carrier — the reference client does the same. A Chrome-fingerprint profile (cipher/curve order,
//! GREASE, ALPS, …) is the next refinement; this is vanilla boring for now (functional, but its
//! ClientHello is identifiable as boring, not Chrome).

use std::io;

use boring2::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio::net::TcpStream;
use tokio_boring2::SslStream;

/// TLS-connect over an established `TcpStream`, using `sni` for SNI.
pub async fn connect(stream: TcpStream, sni: &str) -> io::Result<SslStream<TcpStream>> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| io::Error::other(format!("boring ssl builder: {e}")))?;
    // The cert is neither trusted nor pinned — AnyTLS's auth is the password (see module docs).
    builder.set_verify(SslVerifyMode::NONE);
    let config = builder
        .build()
        .configure()
        .map_err(|e| io::Error::other(format!("boring ssl configure: {e}")))?;
    tokio_boring2::connect(config, sni, stream)
        .await
        .map_err(|e| io::Error::other(format!("anytls tls handshake: {e:?}")))
}
