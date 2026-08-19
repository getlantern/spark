//! Relaying an accepted tunnel connection to the target it announced.
//!
//! Shared by both exits — the plain `serve` relay and the bitcoin splitting egress. They had a copy
//! each, identical except that only one of them existed when UDP was added; the splitter's copy went
//! on dialing TCP for a UDP association, so every association broke and QUIC-preferring sites stalled
//! behind the exit. One implementation is what keeps a protocol addition from reaching one exit and
//! not the other.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::transport::tcp_tunnel::header::{Address, HeaderError};
use crate::transport::tcp_tunnel::udp::udp_associate_sentinel;

/// Read buffer for one relayed datagram, sized to what the wire can express.
///
/// The frame's length field is a `u16`, so `u16::MAX` is the ceiling — not 64 KiB. Reading one byte
/// more than the field can hold would make `n as u16` wrap and describe a 0-byte datagram, framing
/// a payload the peer would never reassemble. A UDP payload cannot exceed this anyway (65535 less
/// the 8-byte header), so nothing legitimate is truncated.
///
/// Allocated per *association*, and only for associations that relay.
const UDP_DATAGRAM_MAX: usize = u16::MAX as usize;

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
///
/// ```no_run
/// # use spark_core::transport::wasm::{relay_to_target, WasmServer};
/// # async fn example(server: &WasmServer, conn: tokio::net::TcpStream) -> std::io::Result<()> {
/// // `accept` deobfuscates the connection and reads the tunnel header. Whatever it returns is
/// // handed straight over: the target decides TCP or UDP, and `leftover` is the bytes that shared
/// // the header's read — relaying them is not optional, it is the connection's first payload.
/// let (target, leftover, wrapped) = server.accept(conn).await?;
/// relay_to_target(target, leftover, wrapped).await
/// # }
/// ```
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
    // `tokio::io::split`, not `into_split` (CLAUDE.md prefers the owned halves). `into_split` is
    // inherent to `TcpStream`, and this function is generic over the stream precisely so both exits
    // reach it — the splitting egress hands in a `PrefixedStream`, not a `TcpStream`. The reason the
    // rule exists does not apply either: the halves stay on this task as two concurrent futures, so
    // the internal lock is never contended, and nothing here needs `Send + 'static`.
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
                sock.send(&buf[..len]).await?;
                buf.advance(len);
            }
            let n = read.read(&mut chunk).await?;
            // A closed client stream is how an association ends, not a failure.
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    };

    // Target → client, same framing in reverse.
    let down = async {
        let mut datagram = vec![0u8; UDP_DATAGRAM_MAX];
        loop {
            let n = sock.recv(&mut datagram).await?;
            let mut frame = BytesMut::with_capacity(2 + n);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
            frame.extend_from_slice(&datagram[..n]);
            write.write_all(&frame).await?;
        }
    };

    // Either direction ending ends the association: a closed client stream means nothing more will
    // be sent or wanted, and a dead socket means there is nothing left to relay. The surviving
    // direction's error is returned rather than dropped — the caller logs it, and a relay that
    // failed is not a relay that finished.
    tokio::pin!(up, down);
    tokio::select! {
        r = &mut up => r,
        r = &mut down => r,
    }
}

/// Bind a socket for one association and connect it to `target`.
///
/// The bind family follows each candidate's, so a v6 destination is not dialed from a v4 socket. A
/// domain is resolved here, as the TCP path resolves it — the exit is the side with a resolver that
/// sees the real network.
///
/// **Every** resolved address is tried, not just the first. `lookup_host` can return a v6 address
/// first on a host with no v6 route, and taking only `.next()` would fail the association outright
/// on a target that is perfectly reachable over v4 — the same address-family fallback every
/// ordinary client performs.
async fn connect_udp(target: &Address) -> io::Result<UdpSocket> {
    let candidates: Vec<SocketAddr> = match target {
        Address::Ip(sa) => vec![*sa],
        Address::Domain { host, port } => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .inspect_err(|_| tracing::debug!(?target, "resolving the announced UDP target failed"))?
            .collect(),
    };
    let mut last: Option<io::Error> = None;
    for peer in candidates {
        match bind_and_connect(peer).await {
            Ok(sock) => return Ok(sock),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "target resolved to no addresses")
    }))
}

/// Bind a wildcard socket of `peer`'s family and connect it, so sends need no address.
async fn bind_and_connect(peer: SocketAddr) -> io::Result<UdpSocket> {
    // Constructed rather than parsed: a wildcard address cannot fail to build, and an `expect` on
    // a parse in a per-association path is a panic waiting for the one input that surprises it.
    let bind = SocketAddr::new(
        if peer.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        },
        0,
    );
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(peer).await?;
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read buffer and the wire's length field have to agree. They are two constants in
    /// different places — `UDP_DATAGRAM_MAX` here, the `u16` in the frame header — and nothing makes
    /// them agree except this. A buffer larger than the field can express does not fail loudly: the
    /// `n as u16` truncates, so a maximal datagram is framed with a wrong (possibly zero) length and
    /// the peer reassembles garbage or stalls.
    #[test]
    fn the_read_buffer_cannot_outgrow_the_length_field() {
        assert!(
            UDP_DATAGRAM_MAX <= u16::MAX as usize,
            "a datagram of {UDP_DATAGRAM_MAX} bytes cannot be described by the frame's u16 length"
        );
        // And the cast at the framing site is lossless for every length the buffer can produce.
        assert_eq!(UDP_DATAGRAM_MAX as u16 as usize, UDP_DATAGRAM_MAX);
    }

    /// The sentinel is how a UDP association is told apart from a TCP target, and it is compared
    /// against a value defined in `tcp_tunnel::udp` — the same one the client encodes. A literal
    /// here would be a second definition free to drift, and the drift would not be a compile error:
    /// associations would simply be dialed as TCP again, which is the bug this fixes.
    #[test]
    fn the_sentinel_is_recognized_and_nothing_else_is() {
        assert!(is_udp_associate(&udp_associate_sentinel()));

        assert!(!is_udp_associate(&Address::Ip(
            "1.2.3.4:443".parse().unwrap()
        )));
        assert!(!is_udp_associate(&Address::Domain {
            host: "example.com".to_owned(),
            port: 443,
        }));
        // Same host, different port: the sentinel is the whole address, not the name.
        assert!(!is_udp_associate(&Address::Domain {
            host: crate::transport::tcp_tunnel::udp::UDP_ASSOCIATE_SENTINEL.to_owned(),
            port: 443,
        }));
    }
}
