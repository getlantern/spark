//! Shadowsocks 2022 (SIP022) transport (ADR 0009): a pre-shared-key AEAD tunnel, wire-interoperable
//! with deployed shadowsocks-rust / sing-box SS-2022 servers. TCP and UDP, all three
//! `2022-blake3-*` ciphers. See `docs/shadowsocks-design.md`.
//!
//! UDP has two envelopes, not one parameterised by cipher: the AES methods encrypt a separate
//! header with a PSK-keyed block cipher and seal the body under a per-session subkey, while
//! `2022-blake3-chacha20-poly1305` puts a cleartext 24-byte nonce in front and seals everything
//! after it — session id included — with XChaCha20-Poly1305 under the PSK. See `udp::SinkSeal`.

mod crypto;
mod tcp;
/// Native SIP022 UDP datagram codec. Off by default — see `shadowsocks-native-udp` in Cargo.toml and
/// [`ShadowsocksTransport::dial_udp_addr`], which tunnels UDP over the TCP stream instead.
#[cfg(feature = "shadowsocks-native-udp")]
mod udp;

pub(crate) use crypto::decode_psk;

use std::io;
use std::net::SocketAddr;
#[cfg(any(test, feature = "shadowsocks-native-udp"))]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::config::SsMethod;
use crate::net::SocketProtector;
#[cfg(not(feature = "shadowsocks-native-udp"))]
use crate::transport::uot::{self, UOT_MAGIC};
use crate::transport::{
    protected_tcp_connect, Address, BoxedPacketSink, BoxedPacketSource, BoxedStream, Transport,
    UdpTransport,
};
use tcp::{encode_request, ShadowsocksStream};

/// Current Unix time in seconds (SIP022 timestamps). Shared by the TCP and UDP codecs.
pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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

#[cfg(feature = "shadowsocks-native-udp")]
impl ShadowsocksTransport {
    /// Native SIP022 UDP: a real UDP socket to the server, datagrams in the on-wire envelope.
    ///
    /// Correct per the spec and covered by `udp.rs`'s frame tests, but not what the deployed fleet
    /// accepts — see [`UdpTransport::dial_udp_addr`].
    async fn dial_udp_native(
        &self,
        target: Address,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        use ring::rand::{SecureRandom, SystemRandom};
        use std::sync::Arc;
        use udp::{ShadowsocksUdpSink, ShadowsocksUdpSource};

        let socket = crate::transport::protected_udp_socket(self.server, self.protector.as_ref())?;
        let socket = tokio::net::UdpSocket::from_std(socket.into())?;
        socket.connect(self.server).await?;
        let socket = Arc::new(socket);

        let mut session_id = [0u8; 8];
        SystemRandom::new()
            .fill(&mut session_id)
            .map_err(|_| io::Error::other("rng"))?;

        let sink = ShadowsocksUdpSink::new(
            Arc::clone(&socket),
            self.method,
            &self.psk,
            target,
            session_id,
        )
        .map_err(io::Error::other)?;
        let source = ShadowsocksUdpSource::new(socket, self.method, self.psk.clone(), session_id)
            .map_err(io::Error::other)?;
        Ok((Box::new(sink), Box::new(source)))
    }
}

impl ShadowsocksTransport {
    /// Connect and send the SS-2022 request carrying `target` (an IP or, on the fake-IP proxy path, a
    /// domain the **server** resolves at the exit — no client DNS). Shared by [`dial`]/[`dial_addr`].
    async fn dial_target(&self, target: &Address) -> io::Result<BoxedStream> {
        let conn = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        let req = encode_request(self.method, &self.psk, target).map_err(io::Error::other)?;
        let mut stream = ShadowsocksStream::new(conn, self.method, self.psk.clone(), req);
        // SS-2022 is request-first: the server can't send its response head until it has the request
        // prefix (which carries the target address). Flush it now so a read-first / server-first upper
        // layer doesn't deadlock waiting on a response the server is itself waiting to be unblocked for.
        stream.flush().await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Transport for ShadowsocksTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        self.dial_target(&Address::Ip(target)).await
    }

    async fn dial_addr(&self, target: Address) -> io::Result<BoxedStream> {
        self.dial_target(&target).await
    }
}

#[async_trait]
impl UdpTransport for ShadowsocksTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        self.dial_udp_addr(Address::Ip(target)).await
    }

    /// UDP rides **over the TCP tunnel** (sing-box UoT v2), not over SS-2022's native UDP.
    ///
    /// Native SIP022 UDP needs the server to listen on UDP and the path to it to pass UDP. Neither
    /// holds for the deployed fleet: every native association was answered with `Connection refused`
    /// (an ICMP port-unreachable, not an authentication failure), so the datagrams never reached a
    /// decryptor. UoT needs no UDP anywhere — it is an ordinary SS-2022 TCP stream addressed to
    /// [`UOT_MAGIC`], which a sing-box shadowsocks inbound turns into a UDP association on its side.
    ///
    /// **No server-side change is required.** Every shadowsocks inbound builds a `uot.NewRouter`
    /// unconditionally (`protocol/shadowsocks/inbound{,_multi,_relay}.go`); `udp_over_tcp` is an
    /// *outbound* option, i.e. a statement about what a client does, not something a server enables.
    /// Note this works only because the inbound handles it — global UoT at the router was removed in
    /// sing-box v1.7.0, which rejects the magic address outright.
    ///
    /// `target` may be a domain: it rides in the UoT request, so the **exit** resolves it and a
    /// proxied UDP flow still costs no client DNS — the same property the native path had.
    async fn dial_udp_addr(
        &self,
        target: Address,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // Port 0: the magic host is a signal, not a destination — nothing dials it. Matches what
        // samizdat and AnyTLS send.
        #[cfg(not(feature = "shadowsocks-native-udp"))]
        {
            let magic = Address::domain(UOT_MAGIC, 0).map_err(io::Error::other)?;
            let stream = self.dial_target(&magic).await?;
            uot::associate(stream, target).await
        }
        // `shadowsocks-native-udp` selects the on-wire SIP022 datagram path instead. Opt-in at build
        // time rather than a runtime fallback: which one works is a property of the deployment, not
        // of the flow, so discovering it per association would spend a failed round trip on every
        // one. Flip it for a fleet whose servers do listen on UDP.
        #[cfg(feature = "shadowsocks-native-udp")]
        {
            self.dial_udp_native(target).await
        }
    }
}

/// Append a dial target in SOCKS5 address format, carrying a **domain** (ATYP 3) as well as an IP
/// (ATYP 1/4). The fake-IP proxy path hands a recovered domain here so the shadowsocks **server**
/// resolves it at the exit (no client-side DNS). The domain length fits a `u8` — [`Address::domain`]
/// guarantees 1..=255 bytes.
pub(super) fn write_socks_target(addr: &Address, out: &mut Vec<u8>) {
    match addr {
        Address::Ip(sa) => write_socks_addr(sa, out),
        Address::Domain { host, port } => {
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// Append `addr` in SOCKS5 address format: ATYP(1) ‖ address ‖ port(u16be). Only ATYP 1 (IPv4) and 4
/// (IPv6) are produced here (SIP022 §3.1.3 / RFC 1928 §5); domains go through [`write_socks_target`].
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

#[cfg(any(test, feature = "shadowsocks-native-udp"))]
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
    use crate::transport::{Transport, UdpTransport};

    #[tokio::test]
    async fn dial_sends_request_prefix_without_a_prior_read_or_write() {
        // Guards the server-first deadlock: dial() must flush the SS request prefix on its own, before
        // the caller reads or writes anything. A fake server accepts and reads salt + the fixed header
        // chunk; if dial() didn't flush, this read would hang and the test would time out.
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 32 + 11 + 16]; // salt(32) + encrypted fixed header chunk
            sock.read_exact(&mut buf).await.unwrap();
            buf.len()
        });
        let t = ShadowsocksTransport::new(addr, SsMethod::Aes256Gcm, vec![5u8; 32], None);
        let _stream = t.dial("1.2.3.4:443".parse().unwrap()).await.unwrap();
        // The server received the prefix purely from dial()'s eager flush — no caller read/write.
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server must receive the prefix from dial() alone")
            .unwrap();
        assert_eq!(got, 32 + 11 + 16);
    }

    /// Chacha UDP now dials rather than refusing — the gate this replaces returned `Unsupported`
    /// for every `2022-blake3-chacha20-poly1305` datagram.
    ///
    /// Asserts only that it gets past the method check: the dial targets a closed port, so what
    /// comes back is a connect/socket outcome, never the old "supported only for the AES methods".
    /// The wire format itself is covered by the frame tests in `udp.rs`, which decrypt the packet
    /// the way the server does.
    #[tokio::test]
    async fn dial_udp_no_longer_refuses_the_chacha_method() {
        let t = ShadowsocksTransport::new(
            "127.0.0.1:1".parse().unwrap(),
            SsMethod::Chacha20Poly1305,
            vec![0u8; 32],
            None,
        );
        let target = "1.2.3.4:53".parse().unwrap();
        if let Err(e) = t.dial_udp(target).await {
            assert!(
                !e.to_string().contains("only for the AES methods"),
                "the method gate must be gone, got: {e}"
            );
            assert_ne!(e.kind(), std::io::ErrorKind::Unsupported);
        }
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
