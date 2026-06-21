//! `spark-relay` — a minimal tunnel relay server for end-to-end testing.
//!
//! It speaks the plain `tcp_tunnel` wire protocol (see `core/src/transport/tcp_tunnel`),
//! reusing the core codec so it stays byte-compatible with the client:
//!
//! - **TCP**: read the `[Address]` header, dial the named target, forward any bytes already
//!   read past the header, then splice the two connections.
//! - **UDP**: the first header is the UDP-associate sentinel; the real target follows as a
//!   second `[Address]`. Thereafter the stream carries connect-mode `[u16 BE len][payload]`
//!   datagrams in both directions (client→target and target→client).
//!
//! This is a test/bring-up tool, not a production server: no auth, no TLS (the plain relay
//! is the base transport). Run it on a host reachable from the client and point
//! `[transport].server` at it.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context};
use bytes::BytesMut;
use clap::Parser;
use spark_core::transport::tcp_tunnel::header::{Address, HeaderError};
use spark_core::transport::tcp_tunnel::stream::read_header;
use spark_core::transport::tcp_tunnel::udp::udp_associate_sentinel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Parser)]
#[command(about = "Minimal spark tunnel relay (plain tcp_tunnel protocol) for e2e testing")]
struct Args {
    /// Address to listen on. Defaults to localhost; this is an unauthenticated
    /// relay, so pass `--listen 0.0.0.0:9000` explicitly to expose it externally
    /// (and only on a host firewalled to trusted clients).
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    eprintln!("[relay] listening on {}", args.listen);
    loop {
        let (conn, peer) = listener.accept().await.context("accept")?;
        tokio::spawn(async move {
            if let Err(e) = handle(conn, peer).await {
                eprintln!("[relay] {peer}: {e:#}");
            }
        });
    }
}

/// Dispatch a connection: the first header is either a TCP target or the UDP sentinel.
async fn handle(mut conn: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    let (first, leftover) = read_header(&mut conn).await.context("reading header")?;
    if first == udp_associate_sentinel() {
        handle_udp(conn, leftover, peer).await
    } else {
        handle_tcp(conn, first, leftover, peer).await
    }
}

/// TCP relay: dial the target, forward the post-header leftover, then splice.
async fn handle_tcp(
    mut conn: TcpStream,
    target: Address,
    leftover: BytesMut,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let addr = resolve(&target).await?;
    eprintln!("[relay] TCP {peer} -> {addr}");
    let mut upstream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    tokio::io::copy_bidirectional(&mut conn, &mut upstream)
        .await
        .context("splice")?;
    Ok(())
}

/// UDP relay (connect-mode): read the target (announced once after the sentinel), open a
/// connected UDP socket, then shuttle `[u16 len][payload]` frames each way.
async fn handle_udp(
    mut conn: TcpStream,
    mut buf: BytesMut,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let target = read_address(&mut conn, &mut buf).await?;
    let addr = resolve(&target).await?;
    eprintln!("[relay] UDP {peer} -> {addr}");
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid bind addr")
    } else {
        "[::]:0".parse().expect("valid bind addr")
    };
    let udp = UdpSocket::bind(bind).await?;
    udp.connect(addr)
        .await
        .with_context(|| format!("udp connect {addr}"))?;
    let udp = Arc::new(udp);
    let (mut rd, mut wr) = conn.into_split();

    // client -> target: parse `[u16 len][payload]` frames (starting from any leftover) and
    // forward the payload as a datagram.
    let send = Arc::clone(&udp);
    let mut pending = buf;
    let c2t = async move {
        loop {
            while pending.len() < 2 {
                if !read_more(&mut rd, &mut pending).await? {
                    return Ok::<(), anyhow::Error>(());
                }
            }
            let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
            while pending.len() < 2 + len {
                if !read_more(&mut rd, &mut pending).await? {
                    return Ok(());
                }
            }
            let frame = pending.split_to(2 + len);
            send.send(&frame[2..]).await?;
        }
    };

    // target -> client: each datagram becomes a `[u16 len][payload]` frame.
    let recv = Arc::clone(&udp);
    let t2c = async move {
        let mut dbuf = vec![0u8; u16::MAX as usize];
        loop {
            let n = recv.recv(&mut dbuf).await?;
            let mut out = BytesMut::with_capacity(2 + n);
            out.extend_from_slice(&(n as u16).to_be_bytes());
            out.extend_from_slice(&dbuf[..n]);
            wr.write_all(&out).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    // Either direction ending tears down the association.
    tokio::select! {
        r = c2t => r?,
        r = t2c => r.map(|_: ()| ())?,
    }
    Ok(())
}

/// Read one `[Address]` from `buf`, refilling from `conn` until it parses.
async fn read_address(conn: &mut TcpStream, buf: &mut BytesMut) -> anyhow::Result<Address> {
    loop {
        match Address::parse(buf) {
            Ok((addr, consumed)) => {
                let _ = buf.split_to(consumed);
                return Ok(addr);
            }
            Err(HeaderError::Incomplete) => {
                if !read_more(conn, buf).await? {
                    bail!("eof while reading address header");
                }
            }
            Err(e) => bail!("malformed address header: {e}"),
        }
    }
}

/// Append one read into `buf`; returns `false` on EOF.
async fn read_more<R: AsyncReadExt + Unpin>(
    rd: &mut R,
    buf: &mut BytesMut,
) -> anyhow::Result<bool> {
    let mut chunk = [0u8; 2048];
    let n = rd.read(&mut chunk).await?;
    if n == 0 {
        return Ok(false);
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(true)
}

/// Resolve a target [`Address`] to a concrete [`SocketAddr`] (first candidate for domains).
async fn resolve(target: &Address) -> anyhow::Result<SocketAddr> {
    match target {
        Address::Ip(sa) => Ok(*sa),
        Address::Domain { host, port } => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .with_context(|| format!("resolving {host}:{port}"))?
            .next()
            .with_context(|| format!("no address for {host}:{port}")),
    }
}
