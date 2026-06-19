---
name: udp-transport-design-proposal
description: DECIDED UDP-through-tunnel architecture for spark M5 (split PacketSink/Source + own framing); being implemented
metadata: 
  node_type: memory
  type: project
  originSessionId: b2538e8f-ad8a-4bf8-9b44-09f600c6d2c8
---

Architecture for tunneling UDP in spark (the from-scratch Rust VPN at
`~/go/src/github.com/getlantern/spark`), completing **M5 session 2**. Researched from prior art
and **DECIDED with Adam on 2026-06-11; implementing.** The "Decided path" section at the bottom
is authoritative and refines the original trait sketch (split halves, not `&self`).

**Core idea — one packet-conn abstraction, many carriers.** Every mature implementation
separates UDP from TCP into a datagram surface (read → `(payload, from_addr)`, write →
`(payload, to_addr)`) and lets each transport carry it however it likes. Write the
netstack→NAT→reply-pump orchestration ONCE against the abstraction; "Shadowsocks-TCP vs
Samizdat vs Hysteria" becomes an impl detail of the conn, not a fork in the core.

**Prior art (all converge):**
- **sing-box UoT** (`common/uot`, in module `github.com/sagernet/sing@v0.8.9`): stream-carried
  UDP. Client dials a *magic address* (`sp.v2.udp-over-tcp.arpa`) over ANY byte-stream
  transport, writes a one-time `Request{isConnect: bool, destination}`, then frames each
  datagram `[dest addr (omitted if isConnect)][u16 BE len][payload]`. Transport-agnostic →
  this is the path for Shadowsocks-TCP / Samizdat. **Our session-1 framing
  (`core/src/transport/tcp_tunnel/udp.rs`, `[Address][u16 len][payload]`) is structurally
  identical** — but uses SOCKS5 ATYP bytes (1/3/4), NOT UoT's serializer (0x00/0x01/0x02), so
  shape-compatible, not wire-compatible with sing-box servers.
- **sing-box `N.PacketConn`** = the abstraction: `ReadPacket(buf)->dest` / `WritePacket(buf,dest)`.
- **sing-quic** (getlantern/sing-quic, hysteria/hysteria2/tuic): datagram-carried. One QUIC
  conn multiplexes many UDP sessions via `udpSessionID`; frame
  `[sessionID u32][host len u16][host][port u16][packetID u16][fragID u8][fragTotal u8][len u16][payload]`
  — explicit fragmentation for the QUIC datagram MTU. Same PacketConn on top.
- **Leaf** (Rust, eycorsican/leaf, not on disk): `OutboundDatagramHandler` separate from
  `OutboundStreamHandler`; `OutboundDatagram::split()` → recv/send halves
  (`recv_from()->(bytes,addr)`, `send_to(bytes,addr)`); a `transport_type()` reliability marker
  says stream-based vs datagram-based carrier. `AnyStream = Box<dyn ProxyStream>` == our `BoxedStream`.

**Proposed spark traits (sibling to the existing stream `Transport`, do NOT overload `dial`):**
```rust
#[async_trait] pub trait PacketConn: Send {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn send_to(&mut self, buf: &[u8], dst: SocketAddr) -> io::Result<usize>;
}
#[async_trait] pub trait UdpTransport: Send + Sync {
    async fn dial_udp(&self, target: SocketAddr) -> io::Result<Box<dyn PacketConn>>;
}
```
- `TunnelClient::dial_udp` = UoT-style (open stream to server via magic target, send request,
  frame with the existing `tcp_tunnel::udp` codec). Future hysteria impls `PacketConn` via QUIC
  session multiplexing. NAT table (`proxy/udp.rs`, already built) holds per `(client_src,
  original_dst)` the `Box<dyn PacketConn>` + reply-pump JoinHandle; `evict_expired` drops both.
  Netstack `ReadHalf` drives `send_to`; pump reads `recv_from` and writes
  `(reply, original_dst, client_src)` to the netstack `WriteHalf`.

**Why (separate surface):** UDP has no connection for the netstack to "accept"; one demux stream
+ a NAT table is mandatory. Conflating it with the TCP stream `Transport` fights the grain of
every prior-art design and would force a rewrite per carrier.

## Decided path (2026-06-11, authoritative)

1. **Separate traits** (not folded into `Transport`).
2. **Own framing** in the `tcp_tunnel` transport (NOT UoT-byte-compat). Framing is per-transport
   (lives inside each `dial_udp`), so a future Shadowsocks/sing-box transport can speak UoT v2
   byte-for-byte without touching the core — decision 2 is reversible/localized.
3. **Connect-mode** (UoT `isConnect` *concept*, not its bytes): each netstack flow is keyed to one
   `original_dst`, so announce the target once at association open, then bare `[u16 BE len][payload]`
   datagrams. The session-1 per-frame `Address` codec (`tcp_tunnel::udp`) is retained as the
   full-cone fallback.
4. **Split halves, NOT `&self`** (revises the sketch above). Reason: a stream-backed conn can't do
   `&self` writes without holding a lock across `.await` (forbidden by CLAUDE.md). So `dial_udp`
   returns `(BoxedPacketSink, BoxedPacketSource)` (Leaf-style split): the sink lives in the netstack
   read loop (stored in the NAT entry, `&mut`), the source goes to a per-flow reply-pump task.
   - `PacketSink::send(&mut self, payload)` ; `PacketSource::recv(&mut self, buf) -> usize`.
     Connected to the negotiated target (no per-call address).
5. **UDP-associate dispatch = magic sentinel address** (UoT-style, but our own string), so the
   TCP header (M3a/M3b `[Address]`) is UNCHANGED. `tcp_tunnel` UDP wire = `Address::encode(MAGIC)`
   then `Address::encode(target)` then `[len][payload]*`. MAGIC = a reserved-`.invalid` FQDN
   sentinel the server recognizes.
6. **Netstack reply path = mpsc drain task** (avoids sharing the smoltcp `WriteHalf` Sink across
   reply pumps / locking across await): one task owns the netstack UDP `WriteHalf` and drains an
   `mpsc::Receiver`; reply pumps clone the `Sender`. Orientation (verified, vendored
   `src/udp.rs`): netstack `UdpMsg = (payload, local=client_src, remote=original_dst)` (inverted
   like TCP); a reply is sent to the stack as `(payload, original_dst, client_src)`.

**How to apply / status:** Implementing now. Reuses session-1 `NatTable` (NAT value =
`{sink, reply-pump JoinHandle}`; `evict_expired` drops both). `DirectTransport` also impls
`UdpTransport` (bind+connect a `tokio::net::UdpSocket`). `SmoltcpNetstack` flips to
`enable_udp(true)` + surfaces the halves. Hermetic tests: orchestration via fake netstack-UDP +
`DirectTransport` + UDP echo; `TunnelClient::dial_udp` via an in-test UDP tunnel relay + echo.
Live DNS gate still needs root. Build state + exact next chunk live in the repo at `docs/STATE.md`.
