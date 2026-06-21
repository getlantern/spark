//! Local Samizdat interop check — pairs with the `/tmp/sz-interop` Go harness (a real
//! `samizdat.Server` + an origin HTTP server on loopback).
//!
//! Reads `SZ_SERVER` / `SZ_PUBKEY` / `SZ_SHORTID` / `SZ_TARGET` from the environment, builds the
//! Samizdat transport via [`from_config`], dials the origin **through** the Samizdat server, sends an
//! HTTP/1.1 GET, and asserts an HTTP 200 with the origin body. Run with `--features samizdat`.
//!
//! This exercises the whole client stack end-to-end against the canonical Go server: the
//! Chrome ClientHello + kID SessionID auth, TLS-handshake completion, and HTTP/2 CONNECT muxing.

use spark_core::config::{Config, SamizdatConfig, ShapingConfig, TransportConfig};
use spark_core::transport::from_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let server = std::env::var("SZ_SERVER").expect("SZ_SERVER");
    let server_pubkey = std::env::var("SZ_PUBKEY").expect("SZ_PUBKEY");
    let short_id = std::env::var("SZ_SHORTID").expect("SZ_SHORTID");
    let target: std::net::SocketAddr = std::env::var("SZ_TARGET")
        .expect("SZ_TARGET")
        .parse()
        .expect("SZ_TARGET must be an addr");

    // Optional ClientHello fragmentation, e.g. SZ_SHAPING=sni_boundary (default: none).
    let shaping = match std::env::var("SZ_SHAPING") {
        Ok(split) if !split.is_empty() => ShapingConfig {
            segment_split: split,
            ..Default::default()
        },
        _ => ShapingConfig::default(),
    };
    println!("shaping: segment_split={}", shaping.segment_split);

    let cfg = Config {
        transport: TransportConfig {
            samizdat: Some(SamizdatConfig {
                server: server.parse().expect("SZ_SERVER must be an addr"),
                server_pubkey,
                short_id,
                sni: Some("cover.example".to_owned()),
            }),
            shaping,
            ..Default::default()
        },
        ..Default::default()
    };

    let (tcp, _udp) = from_config(&cfg).expect("from_config should build the samizdat transport");
    let mut stream = tcp.dial(target).await.expect("dial through samizdat");

    let request = format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write GET");
    // Half-close the send side (H2 END_STREAM) so the server's upload copy hits EOF, returns, and
    // sends END_STREAM back — otherwise `read_to_end` below blocks forever.
    stream.shutdown().await.expect("half-close the write side");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let resp = String::from_utf8_lossy(&buf);
    println!("--- response through samizdat ---\n{resp}---");
    assert!(resp.contains(" 200 "), "expected an HTTP 200 status line");
    assert!(
        resp.contains("hello from origin"),
        "expected the origin body"
    );
    println!("INTEROP OK");
}
