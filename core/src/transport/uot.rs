//! UDP-over-TCP **v2** (sing-box UoT) framing, shared by the stream transports that tunnel UDP over a
//! reliable stream: AnyTLS (pooled mux streams) and Samizdat (HTTP/2 CONNECT streams).
//!
//! Verified against `sagernet/sing` `common/uot` (protocol.go / conn.go): the magic destination is
//! `sp.v2.udp-over-tcp.arpa`, the request is `IsConnect(1 byte) | Destination(socksaddr)`, and in
//! **connected** mode (`IsConnect = 1`, which matches spark's connected `dial_udp(target)`) the
//! destination is fixed so each datagram is just `[u16 BE len][payload]` — no per-datagram address.
//!
//! Conveying the magic *destination* is the caller's job, because it's the stream's destination, not
//! part of this framing: AnyTLS writes it as the stream's in-band SOCKS5 target; Samizdat sends it as
//! the H2 CONNECT `:authority`. Once the stream is routed to the magic, [`associate`] writes the
//! request and frames datagrams identically for both — so both interoperate with a sing-box UoT
//! inbound (which enters UoT mode from the magic destination, generically across inbound types).

use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::transport::tcp_tunnel::header::Address;
use crate::transport::{BoxedPacketSink, BoxedPacketSource, PacketSink, PacketSource};

/// The sing-box UoT v2 magic address (`uot.MagicAddress`). The stream's *destination* is set to this
/// so the server switches the stream into a UDP association (RFC-style reserved `.arpa` name, so it
/// can't collide with a real destination).
pub const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

/// Establish a UoT v2 **connected** association to `target` over `stream`, which the caller must have
/// already routed to [`UOT_MAGIC`] (AnyTLS: in-band SOCKS5 target; Samizdat: H2 CONNECT authority).
/// Writes the connect request (`IsConnect = 1 | Destination`), then splits the stream into framed
/// datagram halves (`[u16 BE len][payload]`). `target` may be a **domain** (ATYP=3): sing-box's UoT
/// server resolves it at the exit, so a fake-IP UDP flow reaches its real destination with no client
/// DNS.
pub async fn associate<S>(
    mut stream: S,
    target: Address,
) -> io::Result<(BoxedPacketSink, BoxedPacketSource)>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut hdr = BytesMut::new();
    // UoT Request: IsConnect = 1 (connected mode — destination is fixed), then the real destination
    // as a SOCKS5 addr (sing-box `EncodeRequest`: a bool byte + `WriteAddrPort`).
    hdr.put_u8(1);
    target.encode(&mut hdr);
    stream.write_all(&hdr).await?;
    stream.flush().await?;

    let (rd, wr) = tokio::io::split(stream);
    Ok((Box::new(UotSink(wr)), Box::new(UotSource(rd))))
}

/// Connected-mode send half: each datagram is `[u16 BE len][payload]` (sing-box uot `Conn.WriteTo`
/// in connected mode — the destination is fixed by the request, so it isn't repeated).
struct UotSink<S>(WriteHalf<S>);

#[async_trait]
impl<S: AsyncWrite + Send + Unpin + 'static> PacketSink for UotSink<S> {
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

/// Connected-mode receive half: read `[u16 BE len]` then `len` payload bytes (sing-box uot `ReadFrom`
/// with `isConnect`: skip the per-datagram address, read the length, then the datagram).
struct UotSource<S>(ReadHalf<S>);

#[async_trait]
impl<S: AsyncRead + Send + Unpin + 'static> PacketSource for UotSource<S> {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.0.read_u16().await? as usize;
        // Always consume the full datagram to stay frame-aligned, even if `buf` is shorter (UDP
        // truncation semantics).
        let mut datagram = vec![0u8; len];
        self.0.read_exact(&mut datagram).await?;
        let n = len.min(buf.len());
        buf[..n].copy_from_slice(&datagram[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The exact bytes a sing-box UoT v2 inbound expects after the stream is routed to the magic:
    // the request (IsConnect=1 + IPv4 socksaddr) then connected datagrams ([u16 len][payload]).
    #[tokio::test]
    async fn writes_singbox_uot_request_then_framed_datagrams() {
        let (client, mut server) = tokio::io::duplex(4096);
        let target = Address::Ip("1.2.3.4:53".parse().unwrap());
        let (mut sink, _src) = associate(client, target).await.unwrap();

        // Request: IsConnect(1) + SOCKS5 addr (ATYP 0x01 = IPv4) + 1.2.3.4 + port 53 (u16 BE).
        // ATYP 1/3/4 is the standard SOCKS5 serializer sing-box uses for the UoT request destination.
        let mut got = [0u8; 8];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [1, 0x01, 1, 2, 3, 4, 0x00, 53]);

        // A datagram: [u16 BE len][payload].
        sink.send(b"ping").await.unwrap();
        let mut frame = [0u8; 6];
        server.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame, [0x00, 0x04, b'p', b'i', b'n', b'g']);
    }

    #[tokio::test]
    async fn a_domain_target_encodes_as_socks5_atyp3() {
        // A recovered domain rides the UoT request as ATYP=3 so the exit resolves it — no client DNS.
        let (client, mut server) = tokio::io::duplex(4096);
        let target = Address::domain("dns.google", 53).unwrap();
        let (_sink, _src) = associate(client, target).await.unwrap();
        // IsConnect(1) + ATYP 0x03 + len(10) + "dns.google" + port 53 (u16 BE).
        let mut got = [0u8; 15];
        server.read_exact(&mut got).await.unwrap();
        let mut want = vec![1u8, 0x03, 10];
        want.extend_from_slice(b"dns.google");
        want.extend_from_slice(&[0x00, 53]);
        assert_eq!(got.as_slice(), want.as_slice());
    }

    #[tokio::test]
    async fn reads_a_framed_datagram() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (_sink, mut src) = associate(client, Address::Ip("1.2.3.4:53".parse().unwrap()))
            .await
            .unwrap();
        // Drain the request `associate` wrote, so the duplex doesn't back up.
        let mut req = [0u8; 8];
        server.read_exact(&mut req).await.unwrap();
        // Server sends one framed datagram: [u16 len=3]["pog"].
        server
            .write_all(&[0x00, 0x03, b'p', b'o', b'g'])
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pog");
    }
}
