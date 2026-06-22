//! Live interop gate for the Shadowsocks 2022 (SIP022) transport — the authoritative check that
//! spark's SS-2022 client wire format is accepted by a real `shadowsocks-rust` server.
//!
//! Unlike the unit tests (which exercise spark's encoder against spark's own decoder, and so could
//! share a bug), this drives [`from_config`] → [`Transport::dial`] / [`UdpTransport::dial_udp`]
//! against an external `ssserver`. It is **env-gated**: with no `SPARK_SS_SERVER` / `SPARK_SS_PSK`
//! set it prints a skip line and returns, so it's a no-op in CI without a server.
//!
//! To run live, start a server and set the env:
//! ```text
//! PSK=$(openssl rand -base64 32)
//! ssserver -s 127.0.0.1:8388 -m 2022-blake3-aes-256-gcm -k "$PSK" -U &
//! SPARK_SS_SERVER=127.0.0.1:8388 \
//!   SPARK_SS_METHOD=2022-blake3-aes-256-gcm \
//!   SPARK_SS_PSK="$PSK" \
//!   cargo test -p spark-core --features shadowsocks --test shadowsocks_interop -- --nocapture
//! ```
//! The TCP test reaches `example.com:80` and the UDP test reaches `8.8.8.8:53`, so a live run needs
//! outbound internet from the host running the server.
#![cfg(feature = "shadowsocks")]

use std::sync::Arc;
use std::time::Duration;

use spark_core::config::Config;
use spark_core::transport::{from_config, Transport, UdpTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_METHOD: &str = "2022-blake3-aes-256-gcm";

/// Build a `[transport.shadowsocks]` config from the environment, or `None` to skip the test.
///
/// Reads `SPARK_SS_SERVER` (required, `IP:port`), `SPARK_SS_METHOD` (optional, defaults to
/// `2022-blake3-aes-256-gcm`) and `SPARK_SS_PSK` (required, base64). When either required var is
/// unset it prints a skip line and returns `None`.
fn config_from_env() -> Option<Config> {
    let server = std::env::var("SPARK_SS_SERVER").ok();
    let psk = std::env::var("SPARK_SS_PSK").ok();
    let (server, psk) = match (server, psk) {
        (Some(s), Some(p)) if !s.is_empty() && !p.is_empty() => (s, p),
        _ => {
            println!(
                "SKIP: set SPARK_SS_SERVER and SPARK_SS_PSK (and optionally SPARK_SS_METHOD) to run \
                 the live shadowsocks-rust interop gate"
            );
            return None;
        }
    };
    let method = std::env::var("SPARK_SS_METHOD").unwrap_or_else(|_| DEFAULT_METHOD.to_owned());

    let toml = format!(
        "[transport.shadowsocks]\nserver = \"{server}\"\nmethod = \"{method}\"\npassword = \"{psk}\"\n"
    );
    match Config::from_toml_str(&toml) {
        Ok(cfg) => Some(cfg),
        Err(e) => panic!("SPARK_SS_* env produced an invalid config: {e}"),
    }
}

/// Build the transport pair from the env config, panicking on a builder error (a real bug given a
/// well-formed config).
fn build() -> Option<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let cfg = config_from_env()?;
    Some(from_config(&cfg).expect("from_config should build the shadowsocks transport"))
}

/// TCP: dial `example.com:80` **through** the live SS server and confirm an HTTP response head.
///
/// A failure here with a connection reset / decrypt / EOF before any bytes is an SS-protocol bug in
/// spark's TCP codec; a failure to resolve/route to example.com is an environment limitation.
#[tokio::test]
async fn tcp_http_get_through_live_server() {
    let Some((tcp, _udp)) = build() else { return };

    // Resolve example.com at runtime rather than hardcoding an IP that may rotate.
    let target = timeout(TIMEOUT, tokio::net::lookup_host("example.com:80"))
        .await
        .expect("DNS lookup timed out")
        .expect("resolve example.com:80")
        .next()
        .expect("example.com:80 resolved to no addresses");
    println!("dialing example.com:80 ({target}) through the SS server");

    let mut stream = timeout(TIMEOUT, tcp.dial(target))
        .await
        .expect("dial timed out")
        .expect("dial example.com:80 through the SS server");

    let request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    timeout(TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .expect("write timed out")
        .expect("write GET through the SS tunnel");

    let mut buf = [0u8; 1024];
    let n = timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response through the SS tunnel");
    assert!(n > 0, "server closed without sending any response bytes");

    let head = String::from_utf8_lossy(&buf[..n]);
    println!("--- response head through SS ---\n{head}\n---");
    assert!(
        head.starts_with("HTTP/1.1 "),
        "expected an HTTP/1.1 status line, got: {head:?}"
    );
}

/// UDP: send a DNS A-query for example.com to `8.8.8.8:53` **through** the live SS server and
/// confirm the reply echoes the transaction id and is longer than the query (i.e. carries answers).
///
/// A decrypt/parse failure here is an SS-protocol bug in spark's UDP codec; an inability to reach
/// 8.8.8.8 is an environment limitation.
#[tokio::test]
async fn udp_dns_through_live_server() {
    let Some((_tcp, udp)) = build() else { return };

    let target = "8.8.8.8:53".parse().expect("8.8.8.8:53 parses");
    let (mut sink, mut source) = timeout(TIMEOUT, udp.dial_udp(target))
        .await
        .expect("dial_udp timed out")
        .expect("dial_udp 8.8.8.8:53 through the SS server");

    // A minimal DNS query: txid 0x1234, RD=1, 1 question, A/IN for example.com.
    let query = dns_a_query(0x1234, "example.com");
    timeout(TIMEOUT, sink.send(&query))
        .await
        .expect("UDP send timed out")
        .expect("send DNS query through the SS tunnel");

    let mut buf = [0u8; 1500];
    let n = timeout(TIMEOUT, source.recv(&mut buf))
        .await
        .expect("UDP recv timed out")
        .expect("recv DNS reply through the SS tunnel");
    let reply = &buf[..n];
    println!("DNS reply: {n} bytes (query was {} bytes)", query.len());

    assert!(
        reply.len() >= 2 && reply[0] == query[0] && reply[1] == query[1],
        "DNS reply did not echo the transaction id (got {:02x?})",
        &reply[..reply.len().min(2)]
    );
    assert!(
        reply.len() > query.len(),
        "DNS reply ({} bytes) was not longer than the query ({} bytes) — expected answers",
        reply.len(),
        query.len()
    );
}

/// Build a minimal DNS query packet: header (txid, RD=1, QDCOUNT=1) + one A/IN question for `name`.
fn dns_a_query(txid: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&txid.to_be_bytes()); // transaction id
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    q
}
