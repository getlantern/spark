//! Full-stack e2e: a client (a `ClientSession` driven over real UDP) tunnels through `serve()` to a
//! **real TCP echo target** — proving the server's actual TCP egress, not an in-test echo shortcut.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dns_tunnel_core::addr::{self, Target};
use dns_tunnel_core::arq;
use dns_tunnel_core::crypto::{server_public_from_pkcs8, ServerStatic};
use dns_tunnel_core::session::{ClientSession, Config};
use dns_tunnel_server::{metrics::Metrics, serve, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// A real TCP echo server.
async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = vec![0u8; 16 * 1024];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&b[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn test_cfg() -> Config {
    Config {
        arq: arq::Config {
            initial_rto_ms: 60,
            min_rto_ms: 15,
            ..arq::Config::default()
        },
        query_timeout_ms: 200,
        max_query_inflight: 16,
        ..Config::default()
    }
}

/// A real TCP echo target reached by IP.
#[tokio::test]
async fn full_stack_real_tcp_egress_round_trip() {
    let echo = tcp_echo().await;
    round_trip_to(Target::Ip(echo)).await;
}

/// The same full stack, but the client names the target by **domain** and the *server* resolves it.
///
/// This is the capability the tunnel needs for bootstrap: the client never asks a resolver, so a
/// network that poisons DNS cannot reach the destination lookup. `localhost` keeps the test hermetic
/// while still exercising a genuine server-side resolution — the port is the echo server's real one,
/// so nothing passes unless the name actually resolved and connected.
#[tokio::test]
async fn full_stack_domain_target_is_resolved_by_the_server() {
    let echo = tcp_echo().await;
    round_trip_to(Target::Domain("localhost".into(), echo.port())).await;
}

/// Drive a payload through the tunnel to `target` and assert it comes back intact.
async fn round_trip_to(target: Target) {
    let pkcs8 = ServerStatic::generate().unwrap();
    let pubkey = server_public_from_pkcs8(&pkcs8).unwrap();
    let zone = "t.example.com";

    // The server (authoritative UDP endpoint) doing real TCP egress to the client's target.
    let server_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let metrics = std::sync::Arc::new(Metrics::new());
    tokio::spawn(serve(
        server_udp,
        ServerConfig {
            zone: zone.into(),
            privkey: pkcs8.clone(),
            session: test_cfg(),
            idle_timeout_ms: 60_000,
        },
        std::sync::Arc::clone(&metrics),
    ));

    // Minimal client: drive a ClientSession over a connected UDP socket (authoritative mode).
    let encoded = addr::encode(&target).expect("target encodes");
    let mut client = ClientSession::new(&pubkey, zone, &encoded, test_cfg()).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(server_addr).await.unwrap();

    let payload: Vec<u8> = (0..4096u32).map(|i| (i as u8).wrapping_mul(29)).collect();
    client.write(&payload);

    let start = Instant::now();
    let mut rbuf = vec![0u8; 2048];
    let mut got = Vec::new();
    while start.elapsed() < Duration::from_secs(20) {
        let now = start.elapsed().as_millis() as u64;
        while let Some(q) = client.poll_query(now) {
            udp.send(&q).await.unwrap();
        }
        got.extend_from_slice(&client.read());
        if got.len() >= payload.len() {
            break;
        }
        tokio::select! {
            r = udp.recv(&mut rbuf) => {
                if let Ok(n) = r {
                    client.on_answer(&rbuf[..n], now);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert_eq!(
        got, payload,
        "payload round-trips to {target} through the DNS tunnel and the server's real TCP egress"
    );

    // The counters must move on the live path, not merely compile. Instrumentation that is wired to
    // the wrong branch — or to no branch — looks identical to working instrumentation from the unit
    // tests, which only ever exercise `Metrics` directly.
    let snap = metrics.snapshot();
    assert!(snap.queries > 0, "queries counted");
    assert!(snap.answers > 0, "answers counted");
    assert_eq!(
        snap.streams_opened, 1,
        "one stream opened for this transfer"
    );
    assert!(
        snap.bytes_uplink >= payload.len() as u64,
        "uplink bytes counted: {} < {}",
        snap.bytes_uplink,
        payload.len()
    );
    assert!(
        snap.bytes_downlink >= payload.len() as u64,
        "downlink bytes counted: {} < {}",
        snap.bytes_downlink,
        payload.len()
    );
    // A clean transfer must not look like a failure anywhere.
    assert_eq!(snap.undecodable_targets, 0);
    assert_eq!(snap.backlog_drops, 0);
    assert_eq!(snap.connect_timeouts, 0);
    assert!(snap.connect_failures.is_empty());
}
