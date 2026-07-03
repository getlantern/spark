//! Full-stack e2e: a client (a `ClientSession` driven over real UDP) tunnels through `serve()` to a
//! **real TCP echo target** — proving the server's actual TCP egress, not an in-test echo shortcut.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dns_tunnel_core::arq;
use dns_tunnel_core::crypto::{server_public_from_pkcs8, ServerStatic};
use dns_tunnel_core::session::{ClientSession, Config};
use dns_tunnel_server::{serve, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// SOCKS5 address bytes (`ATYP ‖ addr ‖ port`) — matches the client transport's encoding.
fn encode_target(a: &SocketAddr) -> Vec<u8> {
    let mut v = Vec::new();
    match a {
        SocketAddr::V4(x) => {
            v.push(1);
            v.extend_from_slice(&x.ip().octets());
        }
        SocketAddr::V6(x) => {
            v.push(4);
            v.extend_from_slice(&x.ip().octets());
        }
    }
    v.extend_from_slice(&a.port().to_be_bytes());
    v
}

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

#[tokio::test]
async fn full_stack_real_tcp_egress_round_trip() {
    let pkcs8 = ServerStatic::generate().unwrap();
    let pubkey = server_public_from_pkcs8(&pkcs8).unwrap();
    let zone = "t.example.com";

    let echo = tcp_echo().await;

    // The server (authoritative UDP endpoint) doing real TCP egress to the client's target.
    let server_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    tokio::spawn(serve(
        server_udp,
        ServerConfig {
            zone: zone.into(),
            privkey: pkcs8.clone(),
            session: test_cfg(),
            idle_timeout_ms: 60_000,
        },
    ));

    // Minimal client: drive a ClientSession over a connected UDP socket (authoritative mode).
    let mut client = ClientSession::new(&pubkey, zone, &encode_target(&echo), test_cfg()).unwrap();
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
        "payload round-trips through the DNS tunnel and the server's real TCP egress"
    );
}
