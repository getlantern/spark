//! M3b integration test: drive a [`TunnelClient`] through a self-contained in-test relay
//! (PLAN Appendix B option 1) to a loopback echo target, and confirm a payload round-trips
//! in both directions. No TUN, no external process.

use std::net::SocketAddr;

use spark_core::transport::tcp_tunnel::client::TunnelClient;
use spark_core::transport::tcp_tunnel::header::Address;
use spark_core::transport::tcp_tunnel::stream::read_header;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Spawn a loopback TCP echo server; return its address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Spawn the minimal tunnel relay: read the SOCKS5-style header, dial the named target,
/// forward any bytes already read past the header, then splice the two connections.
async fn spawn_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (target, leftover) = read_header(&mut client).await.unwrap();
                // Resolve to candidate addresses and connect to the first that accepts.
                // (`localhost` resolves to both ::1 and 127.0.0.1; the echo server is
                // IPv4-only, so trying each candidate avoids an order-dependent failure.)
                let candidates: Vec<SocketAddr> = match target {
                    Address::Ip(sa) => vec![sa],
                    Address::Domain { host, port } => {
                        tokio::net::lookup_host((host.as_str(), port))
                            .await
                            .unwrap()
                            .collect()
                    }
                };
                let mut upstream = None;
                for cand in candidates {
                    if let Ok(s) = TcpStream::connect(cand).await {
                        upstream = Some(s);
                        break;
                    }
                }
                let mut upstream = upstream.expect("connect to a resolved target address");
                if !leftover.is_empty() {
                    upstream.write_all(&leftover).await.unwrap();
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn tunnels_through_relay_and_echoes_both_directions() {
    let echo_addr = spawn_echo().await;
    let relay_addr = spawn_relay().await;

    let client = TunnelClient::new(relay_addr);
    let mut stream = client.dial(Address::Ip(echo_addr)).await.unwrap();

    // First exchange.
    stream.write_all(b"hello tunnel").await.unwrap();
    let mut got = [0u8; 12];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello tunnel");

    // Second exchange on the same stream, to prove the relay keeps splicing after the
    // header is consumed (i.e. it isn't a one-shot).
    stream.write_all(b"again!").await.unwrap();
    let mut got2 = [0u8; 6];
    stream.read_exact(&mut got2).await.unwrap();
    assert_eq!(&got2, b"again!");
}

#[tokio::test]
async fn domain_target_resolves_through_relay() {
    let echo_addr = spawn_echo().await;
    let relay_addr = spawn_relay().await;

    // Name the target as a domain (localhost) + the echo port, exercising the ATYP=3 path
    // end to end through the relay's `read_header` + resolution.
    let client = TunnelClient::new(relay_addr);
    let target = Address::domain("localhost", echo_addr.port()).unwrap();
    let mut stream = client.dial(target).await.unwrap();

    stream.write_all(b"via domain").await.unwrap();
    let mut got = [0u8; 10];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"via domain");
}
