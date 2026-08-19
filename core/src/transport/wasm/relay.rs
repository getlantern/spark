//! Relaying an accepted tunnel connection to the target it announced.
//!
//! Shared by both exits — the plain `serve` relay and the bitcoin splitting egress. They had a copy
//! each, identical except that only one of them existed when UDP was added; the splitter's copy went
//! on dialing TCP for a UDP association, so every association broke and QUIC-preferring sites stalled
//! behind the exit. One implementation is what keeps a protocol addition from reaching one exit and
//! not the other.

use std::io;
use std::net::SocketAddr;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::transport::tcp_tunnel::header::{Address, HeaderError};
use crate::transport::tcp_tunnel::udp::udp_associate_sentinel;

/// Read buffer for one relayed datagram. 64 KiB is the largest a UDP payload can be, so nothing
/// legitimate is truncated. Allocated per *association*, and only for associations that relay.
const UDP_DATAGRAM_MAX: usize = 64 * 1024;

/// Whether an announced target is the UDP-associate sentinel rather than a real destination.
///
/// Compared against the sentinel's own value so both ends stay tied to one constant; a literal here
/// would be a second definition, free to drift from the client's.
pub fn is_udp_associate(target: &Address) -> bool {
    *target == udp_associate_sentinel()
}

/// Relay an accepted tunnel connection: TCP to the announced target, or a UDP association when the
/// client sent the sentinel.
///
/// `leftover` is whatever arrived in the same read as the header — forwarded before anything else,
/// since dropping it truncates the connection's opening bytes (for QUIC, the Initial packet, so the
/// flow never starts at all).
///
/// **Log hygiene** (docs/GOAL.md): the announced destination never reaches a default-level log. An
/// exit sees the destination of every user's every flow, so a destination in a `warn!` would make
/// the exit's own log the most sensitive artifact in the deployment.
pub async fn relay_to_target<S>(target: Address, leftover: BytesMut, wrapped: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if is_udp_associate(&target) {
        return relay_udp(leftover, wrapped).await;
    }
    relay_tcp(target, leftover, wrapped).await
}

async fn relay_tcp<S>(target: Address, leftover: BytesMut, mut wrapped: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut up = match &target {
        Address::Ip(sa) => TcpStream::connect(*sa).await,
        Address::Domain { host, port } => TcpStream::connect((host.as_str(), *port)).await,
    }
    .inspect_err(|_| tracing::debug!(?target, "dialing the announced target failed"))?;
    if !leftover.is_empty() {
        up.write_all(&leftover).await?;
    }
    tokio::io::copy_bidirectional(&mut wrapped, &mut up).await?;
    Ok(())
}

/// Relay one UDP association: read the announced target, then pump `[u16 BE len][payload]` frames
/// between the client and a socket bound for this association.
///
/// **Connect-mode.** The target is announced once and every datagram goes to it, so frames carry no
/// per-datagram address — matching what the client sends (`WasmTransport::dial_udp_addr`). That is
/// what makes a QUIC flow cheap: one address per association rather than per packet.
///
/// The socket is bound per association and dropped with it, so nothing outlives the connection.
async fn relay_udp<S>(mut buf: BytesMut, wrapped: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut read, mut write) = tokio::io::split(wrapped);

    // The real target follows the sentinel and may not have arrived yet: `accept` returns whatever
    // shared the header's read, which need not include it.
    let mut chunk = [0u8; 2048];
    let target = loop {
        match Address::parse(&buf) {
            Ok((target, n)) => {
                buf.advance(n);
                break target;
            }
            Err(HeaderError::Incomplete) => {}
            Err(e) => return Err(io::Error::other(e)),
        }
        let n = read.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before the UDP target arrived",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let sock = connect_udp(&target).await?;

    // Both directions run as concurrent futures on this task rather than spawned ones. Spawning
    // would demand `S: Send + 'static`, which the splitting egress's stream is not — and the whole
    // point of sharing this function is that both exits reach it.
    //
    // Client → target. Frames already buffered are drained first: they arrived with the header, and
    // dropping them loses the association's opening datagram.
    let up = async {
        let mut chunk = [0u8; 2048];
        loop {
            while buf.len() >= 2 {
                let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if buf.len() < 2 + len {
                    break;
                }
                buf.advance(2);
                if sock.send(&buf[..len]).await.is_err() {
                    return;
                }
                buf.advance(len);
            }
            match read.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };

    // Target → client, same framing in reverse.
    let down = async {
        let mut datagram = vec![0u8; UDP_DATAGRAM_MAX];
        loop {
            let n = match sock.recv(&mut datagram).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let mut frame = BytesMut::with_capacity(2 + n);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
            frame.extend_from_slice(&datagram[..n]);
            if write.write_all(&frame).await.is_err() {
                return;
            }
        }
    };

    // Either direction ending ends the association: a closed client stream means nothing more will
    // be sent or wanted, and a dead socket means there is nothing left to relay.
    tokio::pin!(up, down);
    tokio::select! {
        _ = &mut up => {}
        _ = &mut down => {}
    }
    Ok(())
}

/// Bind a socket for one association and connect it to `target`.
///
/// The bind family follows the target's, so a v6 destination is not dialed from a v4 socket. A
/// domain is resolved here, as the TCP path resolves it — the exit is the side with a resolver that
/// sees the real network.
async fn connect_udp(target: &Address) -> io::Result<UdpSocket> {
    let peer: SocketAddr = match target {
        Address::Ip(sa) => *sa,
        Address::Domain { host, port } => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .inspect_err(|_| tracing::debug!(?target, "resolving the announced UDP target failed"))?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses"))?,
    };
    let bind: SocketAddr = if peer.is_ipv6() {
        "[::]:0".parse().expect("v6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("v4 wildcard")
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(peer).await?;
    Ok(sock)
}
