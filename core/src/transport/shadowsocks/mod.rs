//! Shadowsocks 2022 (SIP022) transport (ADR 0009): a pre-shared-key AEAD tunnel, wire-interoperable
//! with deployed shadowsocks-rust / sing-box SS-2022 servers. TCP (three `2022-blake3-*` ciphers) +
//! UDP (the two AES methods). See `docs/shadowsocks-design.md`.

mod crypto;
mod tcp;
mod udp;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;

use crate::config::SsMethod;
use crate::net::SocketProtector;
use crate::transport::{
    protected_tcp_connect, protected_udp_socket, BoxedPacketSink, BoxedPacketSource, BoxedStream,
    Transport, UdpTransport,
};
use tcp::{encode_request, ShadowsocksStream};
use udp::{ShadowsocksUdpSink, ShadowsocksUdpSource};

/// An SS-2022 transport: dials the SS server per flow (TCP 1:1) and per UDP association.
pub struct ShadowsocksTransport {
    server: SocketAddr,
    method: SsMethod,
    psk: Vec<u8>,
    protector: Option<SocketProtector>,
}

impl ShadowsocksTransport {
    /// Build from a validated `(server, method, psk)`. `psk` is the already-decoded key
    /// (`method.key_len()` bytes); the builder in `transport/mod.rs` decodes + length-checks it.
    pub fn new(
        server: SocketAddr,
        method: SsMethod,
        psk: Vec<u8>,
        protector: Option<SocketProtector>,
    ) -> Self {
        ShadowsocksTransport {
            server,
            method,
            psk,
            protector,
        }
    }
}

#[async_trait]
impl Transport for ShadowsocksTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let conn = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        let req = encode_request(self.method, &self.psk, &target).map_err(io::Error::other)?;
        let stream = ShadowsocksStream::new(conn, self.method, self.psk.clone(), req);
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl UdpTransport for ShadowsocksTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        if !self.method.is_aes() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Shadowsocks UDP is supported only for the AES methods in this build (chacha UDP needs XChaCha20)",
            ));
        }
        let socket = protected_udp_socket(self.server, self.protector.as_ref())?;
        let socket = UdpSocket::from_std(socket.into())?;
        socket.connect(self.server).await?;
        let socket = Arc::new(socket);

        let mut session_id = [0u8; 8];
        SystemRandom::new()
            .fill(&mut session_id)
            .map_err(|_| io::Error::other("rng"))?;

        let sink = ShadowsocksUdpSink::new(
            Arc::clone(&socket),
            self.method,
            self.psk.clone(),
            target,
            session_id,
        );
        let source = ShadowsocksUdpSource::new(socket, self.method, self.psk.clone(), session_id);
        Ok((Box::new(sink), Box::new(source)))
    }
}

/// Append `addr` in SOCKS5 address format: ATYP(1) ‖ address ‖ port(u16be). spark only ever sends an
/// IP target, so only ATYP 1 (IPv4) and 4 (IPv6) are produced (SIP022 §3.1.3 / RFC 1928 §5).
pub(super) fn write_socks_addr(addr: &SocketAddr, out: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Parse a SOCKS5 address from the front of `buf`, returning the address and bytes consumed.
/// Returns `None` if truncated or the ATYP is a domain (`0x03`) — the server echoes the IP we sent,
/// so we never expect a domain on the response path.
pub(super) fn read_socks_addr(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let atyp = *buf.first()?;
    match atyp {
        0x01 => {
            let bytes: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
            let port = u16::from_be_bytes(buf.get(5..7)?.try_into().ok()?);
            Some((SocketAddr::new(Ipv4Addr::from(bytes).into(), port), 7))
        }
        0x04 => {
            let bytes: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            let port = u16::from_be_bytes(buf.get(17..19)?.try_into().ok()?);
            Some((SocketAddr::new(Ipv6Addr::from(bytes).into(), port), 19))
        }
        _ => None,
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::config::SsMethod;
    use crate::transport::UdpTransport;

    #[tokio::test]
    async fn dial_udp_rejects_chacha_method() {
        let t = ShadowsocksTransport::new(
            "127.0.0.1:1".parse().unwrap(),
            SsMethod::Chacha20Poly1305,
            vec![0u8; 32],
            None,
        );
        let target = "1.2.3.4:53".parse().unwrap();
        let err = t
            .dial_udp(target)
            .await
            .err()
            .expect("chacha udp must error");
        assert!(err.to_string().contains("UDP"));
    }
}

#[cfg(test)]
mod addr_tests {
    use super::*;

    #[test]
    fn socks_addr_v4_round_trips() {
        let addr: SocketAddr = "1.2.3.4:8388".parse().unwrap();
        let mut buf = Vec::new();
        write_socks_addr(&addr, &mut buf);
        assert_eq!(buf[0], 0x01); // ATYP IPv4
        assert_eq!(buf.len(), 1 + 4 + 2);
        let (got, consumed) = read_socks_addr(&buf).unwrap();
        assert_eq!(got, addr);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn socks_addr_v6_round_trips() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut buf = Vec::new();
        write_socks_addr(&addr, &mut buf);
        assert_eq!(buf[0], 0x04); // ATYP IPv6
        let (got, consumed) = read_socks_addr(&buf).unwrap();
        assert_eq!(got, addr);
        assert_eq!(consumed, 1 + 16 + 2);
    }

    #[test]
    fn read_socks_addr_rejects_truncated() {
        assert!(read_socks_addr(&[0x01, 1, 2]).is_none()); // ATYP + partial addr
        assert!(read_socks_addr(&[]).is_none()); // empty
        assert!(read_socks_addr(&[0x01, 1, 2, 3, 4, 99]).is_none()); // v4 addr ok, 1 port byte
        assert!(read_socks_addr(&[0x03, b'x']).is_none()); // domain ATYP rejected
        let mut v6_short = vec![0x04];
        v6_short.extend_from_slice(&[0u8; 16]); // full addr, no port
        assert!(read_socks_addr(&v6_short).is_none());
    }
}
