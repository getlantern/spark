//! UDP over AnyTLS via sing-box **UDP-over-TCP v2** (feature `anytls`).
//!
//! Handshake on a fresh AnyTLS stream: write the UoT magic address (`sp.v2.udp-over-tcp.arpa`) as
//! the SOCKS5 target (this is how the server learns the stream is a UDP association), then the UoT
//! request `IsConnect(1 byte) | Destination(SOCKS5 addr)`. With `IsConnect = 1` (connected mode,
//! matching spark's connected `dial_udp(target)`) the destination is fixed, so each datagram is
//! just `[u16 BE len][payload]` — identical framing to the plain TCP tunnel's connect-mode UDP.
//!
//! Mirrors `sing/common/uot` (protocol.go / conn.go), so it interops with anytls-go's
//! `proxyOutboundUoT`.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::transport::tcp_tunnel::header::Address;
use crate::transport::{BoxedPacketSink, BoxedPacketSource, PacketSink, PacketSource};

use super::Stream;

/// The sing-box UoT v2 magic address — sent as the stream's SOCKS5 target to signal a UDP
/// association (RFC-style reserved `.arpa` name, so it can't collide with a real destination).
pub const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

/// Establish a UoT v2 **connected** association to `target` over an AnyTLS `stream`: write the magic
/// address + the connect request, then split the stream into framed datagram halves.
pub async fn associate(
    mut stream: Stream,
    target: SocketAddr,
) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
    let mut hdr = BytesMut::new();
    // SOCKS5 magic address (the stream's target ⇒ "this is UoT v2").
    Address::Domain {
        host: UOT_MAGIC.to_owned(),
        port: 0,
    }
    .encode(&mut hdr);
    // UoT request: IsConnect = 1 (connected), then the real destination.
    hdr.put_u8(1);
    Address::Ip(target).encode(&mut hdr);
    stream.write_all(&hdr).await?;
    stream.flush().await?;

    let (rd, wr) = tokio::io::split(stream);
    Ok((Box::new(UotSink(wr)), Box::new(UotSource(rd))))
}

/// Connected-mode send half: each datagram is `[u16 BE len][payload]` (destination is fixed).
struct UotSink(WriteHalf<Stream>);

#[async_trait]
impl PacketSink for UotSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP payload exceeds the 2-byte length field",
            ));
        }
        let mut frame = BytesMut::with_capacity(2 + payload.len());
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        self.0.write_all(&frame).await
    }
}

/// Connected-mode receive half: read `[u16 BE len]` then `len` payload bytes.
struct UotSource(ReadHalf<Stream>);

#[async_trait]
impl PacketSource for UotSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.0.read_u16().await? as usize;
        // Always consume the full datagram to stay frame-aligned, even if `buf` is shorter
        // (UDP truncation semantics).
        let mut datagram = vec![0u8; len];
        self.0.read_exact(&mut datagram).await?;
        let n = len.min(buf.len());
        buf[..n].copy_from_slice(&datagram[..n]);
        Ok(n)
    }
}
