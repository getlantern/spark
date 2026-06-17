//! The redirect gateway's per-packet logic: classify a TUN packet and rewrite its TCP 4-tuple so
//! the host kernel routes the connection to/from the local listener (see
//! `docs/system-stack-design.md`). This is the pure decision+rewrite core; the async TUN read/write
//! loop that drives it is the netstack task (chunk 3).
//!
//! Per address family the gateway holds two addresses on the tun subnet — `server` (the tun's own
//! address, where the kernel listener binds) and `gateway` = `server + 1` (the synthetic source for
//! redirected packets) — plus the listener's bound port and the [`TcpNat`] table. Classification is
//! purely by source: a packet *from* `server:listener_port` is a listener→app reply; anything else
//! to a routable target is an app→target packet to redirect.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::nat::TcpNat;
use super::rewrite::{rewrite_tcp, tcp_endpoints};

/// What the caller (the TUN loop) should do with a packet after [`Gateway::process_tcp`].
#[derive(Debug, PartialEq, Eq)]
pub enum PumpAction {
    /// Rewritten in place — write it back to the TUN.
    WriteBack,
    /// Not ours to redirect (non-TCP, family we don't serve, or a non-routable destination) — the
    /// caller handles it on another path or passes it through untouched.
    Passthrough,
    /// Drop silently: a stale/unknown NAT mapping, or the synthetic port space is exhausted.
    Drop,
}

/// Per-family redirect state.
struct FamilyGateway {
    /// The tun's own address; the kernel TCP listener binds here on `listener_port`.
    server: IpAddr,
    /// `server + 1`: the synthetic source address redirected packets appear to come from.
    gateway: IpAddr,
    /// The listener's bound port.
    listener_port: u16,
    /// source⇄natPort table for this family.
    nat: TcpNat,
}

impl FamilyGateway {
    fn new(server: IpAddr, listener_port: u16) -> Self {
        Self {
            server,
            gateway: next_addr(server),
            listener_port,
            nat: TcpNat::new(),
        }
    }
}

/// The redirect gateway across both address families. Owned by the pump task; the accept loop
/// resolves sessions through [`Gateway::resolve_accept`] (chunk 3 shares it behind a `Mutex`).
pub struct Gateway {
    v4: Option<FamilyGateway>,
    v6: Option<FamilyGateway>,
}

impl Gateway {
    /// Build a gateway for whichever families the tun serves. Each entry is the tun's
    /// `(server address, bound listener port)`; `gateway` (= server + 1) is derived.
    pub fn new(v4: Option<(Ipv4Addr, u16)>, v6: Option<(Ipv6Addr, u16)>) -> Self {
        Self {
            v4: v4.map(|(ip, port)| FamilyGateway::new(IpAddr::V4(ip), port)),
            v6: v6.map(|(ip, port)| FamilyGateway::new(IpAddr::V6(ip), port)),
        }
    }

    fn family_mut(&mut self, v6: bool) -> Option<&mut FamilyGateway> {
        if v6 {
            self.v6.as_mut()
        } else {
            self.v4.as_mut()
        }
    }

    /// Classify and rewrite one inbound TUN packet in place.
    ///
    /// - **listener → app** (`src == server:listener_port`): the destination port is the `natPort`;
    ///   recover the original `(client, target)` and rewrite to `src = target`, `dst = client` so
    ///   the app sees a reply from the address it dialed.
    /// - **app → target** (anything else, to a routable destination): allocate/recover a `natPort`
    ///   and rewrite to `src = gateway:natPort`, `dst = server:listener_port` so the kernel routes
    ///   it to the local listener (whose `accept()` peer port is the `natPort`).
    pub fn process_tcp(&mut self, pkt: &mut [u8], now: Instant) -> PumpAction {
        let Ok((src, dst)) = tcp_endpoints(pkt) else {
            return PumpAction::Passthrough; // not TCP / unparseable
        };
        let Some(fg) = self.family_mut(src.is_ipv6()) else {
            return PumpAction::Passthrough; // family we don't serve
        };

        if src.ip() == fg.server && src.port() == fg.listener_port {
            // listener → app: dst is gateway:natPort.
            match fg.nat.lookup_back(dst.port(), now) {
                Some((client, target)) => {
                    let _ = rewrite_tcp(pkt, target, client);
                    PumpAction::WriteBack
                }
                None => PumpAction::Drop, // stale/unknown mapping
            }
        } else {
            // app → target: only redirect routable destinations that aren't our own addresses.
            if !is_routable_target(dst.ip()) || dst.ip() == fg.server || dst.ip() == fg.gateway {
                return PumpAction::Passthrough;
            }
            match fg.nat.lookup(src, dst, now) {
                Some(nat_port) => {
                    let new_src = SocketAddr::new(fg.gateway, nat_port);
                    let new_dst = SocketAddr::new(fg.server, fg.listener_port);
                    let _ = rewrite_tcp(pkt, new_src, new_dst);
                    PumpAction::WriteBack
                }
                None => PumpAction::Drop, // port space exhausted
            }
        }
    }

    /// Resolve an accepted connection's peer address to its original `(client, target)`. The accept
    /// loop calls this with the kernel `TcpStream`'s peer (`gateway:natPort`) to learn the upstream
    /// to dial and the client to attribute the flow to.
    pub fn resolve_accept(
        &mut self,
        peer: SocketAddr,
        now: Instant,
    ) -> Option<(SocketAddr, SocketAddr)> {
        self.family_mut(peer.is_ipv6())?
            .nat
            .lookup_back(peer.port(), now)
    }

    /// Evict idle NAT mappings across both families; returns the number removed.
    pub fn evict_idle(&mut self, now: Instant, timeout: Duration) -> usize {
        let mut n = 0;
        if let Some(fg) = self.v4.as_mut() {
            n += fg.nat.evict_idle(now, timeout);
        }
        if let Some(fg) = self.v6.as_mut() {
            n += fg.nat.evict_idle(now, timeout);
        }
        n
    }
}

/// The next address (`ip + 1`), wrapping within the family. The gateway address is `server + 1`.
fn next_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a).wrapping_add(1))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a).wrapping_add(1))),
    }
}

/// Whether `ip` is a destination we should redirect: a routable unicast target. Excludes loopback,
/// multicast, broadcast, unspecified, and link-local (private ranges like 10/8 are fine — a user
/// may tunnel to them). Mirrors Go's `IsGlobalUnicast` closely enough for classification.
fn is_routable_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_loopback()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_unspecified()
                || a.is_link_local())
        }
        IpAddr::V6(a) => {
            !(a.is_loopback()
                || a.is_multicast()
                || a.is_unspecified()
                || (a.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTO_TCP: u8 = 6;

    /// Build a minimal valid IPv4 TCP packet `src -> dst`.
    fn ipv4_tcp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (sip, dip) = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
            _ => panic!("v4 only"),
        };
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&sip.octets());
        p[16..20].copy_from_slice(&dip.octets());
        p[20..22].copy_from_slice(&src.port().to_be_bytes());
        p[22..24].copy_from_slice(&dst.port().to_be_bytes());
        p[32] = 0x50;
        p[33] = 0x02; // SYN
        p[40..].copy_from_slice(payload);
        // Valid checksums via a no-op rewrite to the same tuple.
        rewrite_tcp(&mut p, src, dst).unwrap();
        p
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn gw() -> Gateway {
        // tun server 10.0.0.1, listener on port 9000; gateway derives to 10.0.0.2.
        Gateway::new(Some((Ipv4Addr::new(10, 0, 0, 1), 9000)), None)
    }

    #[test]
    fn outbound_redirects_to_listener_and_records_nat() {
        let mut g = gw();
        let now = Instant::now();
        let client = sa("10.0.0.1:50000"); // app source = tun addr (kernel-picked)
        let target = sa("93.184.216.34:443");
        let mut pkt = ipv4_tcp(client, target, b"");

        assert_eq!(g.process_tcp(&mut pkt, now), PumpAction::WriteBack);
        let (new_src, new_dst) = tcp_endpoints(&pkt).unwrap();
        // src -> gateway:natPort ; dst -> server:listener_port
        assert_eq!(new_src.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(new_dst, sa("10.0.0.1:9000"));
        let nat_port = new_src.port();

        // The accept loop resolving the listener peer recovers the original (client, target).
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), nat_port);
        assert_eq!(g.resolve_accept(peer, now), Some((client, target)));
    }

    #[test]
    fn inbound_reply_is_rewritten_back_to_the_app() {
        let mut g = gw();
        let now = Instant::now();
        let client = sa("10.0.0.1:50000");
        let target = sa("93.184.216.34:443");

        // First the outbound SYN to populate the NAT.
        let mut syn = ipv4_tcp(client, target, b"");
        g.process_tcp(&mut syn, now);
        let nat_port = tcp_endpoints(&syn).unwrap().0.port();

        // The listener's reply: server:listener_port -> gateway:natPort.
        let mut reply = ipv4_tcp(
            sa("10.0.0.1:9000"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), nat_port),
            b"",
        );
        assert_eq!(g.process_tcp(&mut reply, now), PumpAction::WriteBack);
        let (s, d) = tcp_endpoints(&reply).unwrap();
        assert_eq!(s, target, "reply appears to come from the dialed target");
        assert_eq!(d, client, "reply is delivered to the original app source");
    }

    #[test]
    fn full_handshake_round_trip_through_the_gateway() {
        let mut g = gw();
        let now = Instant::now();
        let client = sa("10.0.0.1:51000");
        let target = sa("1.2.3.4:80");

        let mut out = ipv4_tcp(client, target, b"GET /");
        assert_eq!(g.process_tcp(&mut out, now), PumpAction::WriteBack);
        let nat_port = tcp_endpoints(&out).unwrap().0.port();

        let mut back = ipv4_tcp(
            sa("10.0.0.1:9000"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), nat_port),
            b"200 OK",
        );
        g.process_tcp(&mut back, now);
        assert_eq!(tcp_endpoints(&back).unwrap(), (target, client));
    }

    #[test]
    fn unknown_natport_reply_is_dropped() {
        let mut g = gw();
        let mut reply = ipv4_tcp(
            sa("10.0.0.1:9000"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 12345),
            b"",
        );
        assert_eq!(g.process_tcp(&mut reply, Instant::now()), PumpAction::Drop);
    }

    #[test]
    fn non_tcp_and_local_destinations_pass_through() {
        let mut g = gw();
        let now = Instant::now();

        let mut udp = ipv4_tcp(sa("10.0.0.1:1"), sa("8.8.8.8:53"), b"");
        udp[9] = 17; // UDP
        assert_eq!(g.process_tcp(&mut udp, now), PumpAction::Passthrough);

        // Destination is the gateway address itself — not a proxy target.
        let mut local = ipv4_tcp(sa("10.0.0.1:2"), sa("10.0.0.2:80"), b"");
        assert_eq!(g.process_tcp(&mut local, now), PumpAction::Passthrough);

        // Multicast destination.
        let mut mcast = ipv4_tcp(sa("10.0.0.1:3"), sa("224.0.0.1:80"), b"");
        assert_eq!(g.process_tcp(&mut mcast, now), PumpAction::Passthrough);
    }

    #[test]
    fn gateway_address_is_server_plus_one() {
        assert_eq!(
            next_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(
            next_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255))),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0))
        );
    }
}
