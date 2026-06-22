//! Live interop gate for the Hysteria 2 transport — the authoritative check that spark's
//! hand-rolled QUIC/HTTP3-auth/UDP-datagram wire format (and the Salamander+Gecko obfuscation) is
//! accepted by a real `apernet/hysteria` server.
//!
//! Unlike the unit tests (which exercise spark's encoder against spark's own decoder, and so could
//! share a bug), this drives [`from_config`] → [`Transport::dial`] / [`UdpTransport::dial_udp`]
//! against an external `hysteria server`. It is **env-gated**: with no `SPARK_HY2_SERVER` /
//! `SPARK_HY2_AUTH` set it prints a skip line and returns, so it's a no-op in CI without a server.
//!
//! To run live, start a server with a self-signed cert and set the env:
//! ```text
//! # self-signed cert for CN=hysteria
//! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
//!   -keyout /tmp/hy2-key.pem -out /tmp/hy2-cert.pem -days 3650 -subj "/CN=hysteria"
//! # config.yaml: listen :8443, tls {cert,key}, auth {type: password, password: <pw>}
//! hysteria server -c /tmp/hy2-config.yaml &
//! SPARK_HY2_SERVER=127.0.0.1:8443 SPARK_HY2_AUTH=<pw> \
//!   cargo test -p spark-core --features hysteria2 --test hysteria2_interop -- --nocapture
//! # then again with the server's obfs enabled and:
//! #   SPARK_HY2_OBFS=<obfspw>            (Salamander)
//! #   SPARK_HY2_OBFS=<obfspw> SPARK_HY2_GECKO=1   (Salamander + Gecko)
//! ```
//! The TCP test reaches `example.com:80` and the UDP test reaches `8.8.8.8:53`, so a live run needs
//! outbound internet from the host running the server. The self-signed cert means the client uses
//! `tls.mode = "insecure"`.
#![cfg(feature = "hysteria2")]

use std::sync::Arc;
use std::time::Duration;

use spark_core::config::Config;
use spark_core::transport::{from_config, Transport, UdpTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SNI: &str = "hysteria";

/// Build a `[transport.hysteria2]` config from the environment, or `None` to skip the test.
///
/// Reads `SPARK_HY2_SERVER` (required, `IP:port`) and `SPARK_HY2_AUTH` (required, the auth
/// credential). Optional: `SPARK_HY2_SNI` (defaults to `hysteria`), `SPARK_HY2_OBFS` (the
/// Salamander password — when set, obfuscation is enabled), `SPARK_HY2_GECKO` (`1` wraps Salamander
/// with Gecko). TLS verification is `insecure` (the live server uses a self-signed cert). When
/// either required var is unset it prints a skip line and returns `None`.
fn config_from_env() -> Option<Config> {
    let server = std::env::var("SPARK_HY2_SERVER").ok();
    let auth = std::env::var("SPARK_HY2_AUTH").ok();
    let (server, auth) = match (server, auth) {
        (Some(s), Some(a)) if !s.is_empty() && !a.is_empty() => (s, a),
        _ => {
            println!(
                "SKIP: set SPARK_HY2_SERVER and SPARK_HY2_AUTH (optionally SPARK_HY2_SNI, \
                 SPARK_HY2_OBFS, SPARK_HY2_GECKO) to run the live apernet/hysteria interop gate"
            );
            return None;
        }
    };
    let sni = std::env::var("SPARK_HY2_SNI").unwrap_or_else(|_| DEFAULT_SNI.to_owned());

    let mut toml = format!(
        "[transport.hysteria2]\nserver = \"{server}\"\nauth = \"{auth}\"\nsni = \"{sni}\"\n\n\
         [transport.hysteria2.tls]\nmode = \"insecure\"\n"
    );
    if let Ok(obfs_pw) = std::env::var("SPARK_HY2_OBFS") {
        if !obfs_pw.is_empty() {
            let gecko = std::env::var("SPARK_HY2_GECKO")
                .map(|v| v == "1")
                .unwrap_or(false);
            toml.push_str(&format!(
                "\n[transport.hysteria2.obfs]\ntype = \"salamander\"\npassword = \"{obfs_pw}\"\ngecko = {gecko}\n"
            ));
        }
    }

    println!("--- hysteria2 interop config ---\n{toml}---");
    match Config::from_toml_str(&toml) {
        Ok(cfg) => Some(cfg),
        Err(e) => panic!("SPARK_HY2_* env produced an invalid config: {e}"),
    }
}

/// Build the transport pair from the env config, panicking on a builder error (a real bug given a
/// well-formed config).
fn build() -> Option<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let cfg = config_from_env()?;
    Some(from_config(&cfg).expect("from_config should build the hysteria2 transport"))
}

/// TCP: dial `example.com:80` **through** the live Hysteria 2 server and confirm an HTTP response
/// head.
///
/// A failure here (QUIC handshake error, `/auth` rejection, TCPResponse parse failure, or an EOF
/// before any bytes) is a protocol bug in spark's quinn/auth/TCP-codec path — or, with obfs set, in
/// Salamander/Gecko. A failure to resolve/route to example.com is an environment limitation.
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
    println!("dialing example.com:80 ({target}) through the hysteria2 server");

    let mut stream = timeout(TIMEOUT, tcp.dial(target))
        .await
        .expect("dial timed out")
        .expect("dial example.com:80 through the hysteria2 server");

    let request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    timeout(TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .expect("write timed out")
        .expect("write GET through the hysteria2 tunnel");

    let mut buf = [0u8; 1024];
    let n = timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response through the hysteria2 tunnel");
    assert!(n > 0, "server closed without sending any response bytes");

    let head = String::from_utf8_lossy(&buf[..n]);
    println!("--- response head through hysteria2 ---\n{head}\n---");
    assert!(
        head.starts_with("HTTP/1.1 "),
        "expected an HTTP/1.1 status line, got: {head:?}"
    );
}

/// UDP: send a DNS A-query for example.com to `8.8.8.8:53` **through** the live Hysteria 2 server
/// and confirm the reply echoes the transaction id and is longer than the query (i.e. carries
/// answers).
///
/// A failure here is a bug in spark's UDPMessage datagram codec / fragmentation / receive pump (or
/// in the obfs layer when set), unless 8.8.8.8 is simply unreachable from the host (environment).
#[tokio::test]
async fn udp_dns_through_live_server() {
    let Some((_tcp, udp)) = build() else { return };

    let target = "8.8.8.8:53".parse().expect("8.8.8.8:53 parses");
    let (mut sink, mut source) = timeout(TIMEOUT, udp.dial_udp(target))
        .await
        .expect("dial_udp timed out")
        .expect("dial_udp 8.8.8.8:53 through the hysteria2 server");

    // A minimal DNS query: txid 0x1234, RD=1, 1 question, A/IN for example.com.
    let query = dns_a_query(0x1234, "example.com");
    timeout(TIMEOUT, sink.send(&query))
        .await
        .expect("UDP send timed out")
        .expect("send DNS query through the hysteria2 tunnel");

    let mut buf = [0u8; 1500];
    let n = timeout(TIMEOUT, source.recv(&mut buf))
        .await
        .expect("UDP recv timed out")
        .expect("recv DNS reply through the hysteria2 tunnel");
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
