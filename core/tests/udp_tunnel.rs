//! M5 integration test: drive `TunnelClient::dial_udp` through a self-contained relay that
//! speaks spark's own UDP-associate protocol (magic sentinel + target header, then
//! `[u16 len][payload]` datagrams), confirming a datagram round-trips both directions and
//! the handshake announces the sentinel + the dialed target. No TUN, no UDP sockets needed —
//! the relay just echoes framed datagrams.

use bytes::{BufMut, BytesMut};
use spark_core::transport::tcp_tunnel::client::TunnelClient;
use spark_core::transport::tcp_tunnel::header::{Address, HeaderError};
use spark_core::transport::tcp_tunnel::udp::UDP_ASSOCIATE_SENTINEL;
use spark_core::transport::UdpTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Parse one SOCKS5-style address from `buf`, refilling from `reader` on a truncated prefix.
async fn read_address(reader: &mut OwnedReadHalf, buf: &mut BytesMut) -> Address {
    loop {
        match Address::parse(buf) {
            Ok((addr, consumed)) => {
                let _ = buf.split_to(consumed);
                return addr;
            }
            Err(HeaderError::Incomplete) => {
                let mut tmp = [0u8; 256];
                let n = reader.read(&mut tmp).await.unwrap();
                assert!(n > 0, "EOF while reading an address header");
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => panic!("malformed address header: {e:?}"),
        }
    }
}

/// Read one `[u16 len][payload]` datagram frame, refilling from `reader` as needed. `None`
/// on clean EOF.
async fn read_datagram(reader: &mut OwnedReadHalf, buf: &mut BytesMut) -> Option<Vec<u8>> {
    loop {
        if buf.len() >= 2 {
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() >= 2 + len {
                let _ = buf.split_to(2);
                return Some(buf.split_to(len).to_vec());
            }
        }
        let mut tmp = [0u8; 2048];
        let n = reader.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[tokio::test]
async fn tunnels_udp_datagrams_through_the_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();

    // The relay reads the UDP-associate handshake, reports what it saw, then echoes framed
    // datagrams back to the client.
    let (hdr_tx, hdr_rx) = oneshot::channel::<(Address, Address)>();
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = conn.into_split();
        let mut buf = BytesMut::new();

        let sentinel = read_address(&mut read, &mut buf).await;
        let target = read_address(&mut read, &mut buf).await;
        hdr_tx.send((sentinel, target)).unwrap();

        while let Some(payload) = read_datagram(&mut read, &mut buf).await {
            let mut frame = BytesMut::with_capacity(2 + payload.len());
            frame.put_u16(payload.len() as u16);
            frame.put_slice(&payload);
            if write.write_all(&frame).await.is_err() {
                break;
            }
        }
    });

    let target: std::net::SocketAddr = "93.184.216.34:53".parse().unwrap();
    let client = TunnelClient::new(relay_addr);
    let (mut sink, mut source) = client.dial_udp(target).await.unwrap();

    // Handshake announced the sentinel and the dialed target.
    let (sentinel, announced) = hdr_rx.await.unwrap();
    assert!(matches!(sentinel, Address::Domain { host, .. } if host == UDP_ASSOCIATE_SENTINEL));
    assert_eq!(announced, Address::Ip(target));

    // Datagram round-trips both directions.
    sink.send(b"dns-query").await.unwrap();
    let mut buf = [0u8; 64];
    let n = source.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"dns-query");

    // A second datagram on the same association still flows.
    sink.send(b"again").await.unwrap();
    let n = source.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"again");
}
