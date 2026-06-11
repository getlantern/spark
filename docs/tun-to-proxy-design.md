# Design: TUN → Proxy Tunnel Pipeline

## The Problem

`tun-rs` produces raw IP packets. A proxy tunnel transport expects:
- A target `(host, port)` to relay to
- A stream of application bytes to forward

These don't compose directly. We need a **userspace TCP/IP stack** to terminate connections locally and surface them as streams.

## Netstack Decision: `netstack-smoltcp` (RESOLVED)

We use **`netstack-smoltcp`** rather than hand-rolling the smoltcp bridge. It is a
purpose-built netstack that turns TUN packets into TCP streams + UDP datagrams,
with smoltcp as the backend. Rationale:

- Pure Rust, no C dependency — preserves the small-binary / clean-cross-compile thesis.
- Runtime-configurable buffer sizes (`stack_buffer_size`, `tcp_buffer_size`,
  `udp_buffer_size`) — the lever for staying under the iOS Packet Tunnel Provider
  memory cap.
- It does the SYN-tracking / flow-surfacing that was the trickiest hand-rolled part
  of an earlier draft of this doc.
- Decoupled from the specific TUN crate: it consumes/produces a `Stream`/`Sink` of
  IP packet frames, so it bridges to `tun-rs`, `tun2`, or an Apple `NEPacketFlow`
  (over FFI) identically.

Rejected alternatives: `ipstack` (async-native but explicitly unstable — would mean
co-maintaining a netstack while also writing the transports and platform shims); `lwIP`
bindings (proven/fast but reintroduce a C dependency and cross-compilation friction
that undercut the whole thesis).

### Verified API surface (spike, against the crate source + a compiling spike)

- `StackBuilder::default().enable_tcp(bool).enable_udp(bool).enable_icmp(bool)
  .stack_buffer_size(n).tcp_buffer_size(n).udp_buffer_size(n).build()`
  returns `io::Result<(Stack, Option<Runner>, Option<UdpSocket>, Option<TcpListener>)>`.
- `Stack` implements `futures::Stream<Item = AnyIpPktFrame>` **and**
  `futures::Sink<AnyIpPktFrame>` → `stack.split()` gives the two ends you bridge to TUN.
- `Runner`, when present, **must be spawned** (`tokio::spawn(runner)`); it drives the
  smoltcp poll loop. ICMP is serviced by the TCP runner, so `enable_icmp(true)`
  requires `enable_tcp(true)` (the builder returns an error otherwise).
- `TcpListener` implements `Stream<Item = (TcpStream, SocketAddr, SocketAddr)>` =
  `(stream, local_addr, remote_addr)`. Pull connections with `.next().await`.
- **`TcpStream` implements tokio `AsyncRead + AsyncWrite`** → `copy_bidirectional`
  to an upstream works directly. This was the load-bearing assumption; it is confirmed.
- `local_addr` on the accepted connection is the **original destination** the app
  dialed — i.e. the address you pass to the tunnel transport as its target.
- `UdpSocket` splits into read/write halves implementing the futures `Stream`/`Sink`
  traits.

### Version / toolchain findings (IMPORTANT — affects the system prompt)

- Current `netstack-smoltcp` (0.2.x) pins **`smoltcp 0.12`, which requires rustc ≥ 1.80**.
- Current `tun-rs` (2.8.x) pulls a transitive dep requiring **edition 2024 → rustc ≥ 1.85**.
- Therefore the **MSRV must be ≥ 1.85**, not 1.75 as originally drafted. Pin it in
  `rust-toolchain.toml` and verify the iOS/Android cross-targets ship a recent enough
  toolchain.
- API note: the builder's `.mtu(n)` method exists in 0.2.x but not 0.1.x — pin the
  exact `netstack-smoltcp` version and don't assume builder methods across minor versions.

### The bridge (verified to compile)

`netstack-smoltcp` is TUN-crate-agnostic. The glue is the same on every platform —
forward TUN→`Stack` (Sink) and `Stack`→TUN (Stream):

```rust
let (mut stack_sink, mut stack_stream) = stack.split();
// stack -> TUN
tokio::spawn(async move {
    while let Some(Ok(pkt)) = stack_stream.next().await {
        tun_tx.send(pkt).await.ok();
    }
});
// TUN -> stack
tokio::spawn(async move {
    while let Some(pkt) = tun_rx.recv().await {
        stack_sink.send(pkt).await.ok();
    }
});
```

A compiling spike of this (plus the accept loop and `copy_bidirectional`) is in
`netstack-spike/`. It builds and runs against the real crate. Everything below about
hand-rolling the smoltcp `Device` trait is retained only as background — **you do not
need to implement it**; `netstack-smoltcp` does it for you.

## High-Level Data Flow

```
┌─────────┐  IP packets   ┌──────────┐  TCP/UDP    ┌─────────────┐  framed bytes ┌──────────┐
│   App   │ ◄──────────►  │  TUN     │ ◄────────► │   smoltcp   │ ◄────────►   │  tunnel  │
│         │               │  device  │             │  netstack   │               │  client  │
└─────────┘               └──────────┘             └─────────────┘               └────┬─────┘
                                                          │                            │
                                                  surfaces accepted                    │ relayed TCP
                                                  TcpSocket with                       │
                                                  original dest                        ▼
                                                                                  ┌──────────┐
                                                                                  │ tunnel   │
                                                                                  │ server   │
                                                                                  └────┬─────┘
                                                                                       │
                                                                                       ▼
                                                                                  real destination
```

The OS is configured to route some destination prefix through the TUN. The app's `connect(1.2.3.4:443)` produces a TCP SYN that comes out of the TUN. We hand that to smoltcp, which speaks TCP back to the app (synthesizing SYN-ACK packets) and gives us a `TcpSocket` whose payload we can read. We relay that payload through the tunnel transport with the original destination `(1.2.3.4, 443)` as the target address.

## Module Layout

```
src/
├── tun/          (done — wraps tun-rs, async read/write of IP packets)
├── packet/       (done — minimal IP parser)
├── netstack/     (NEW — smoltcp wrapper)
│   ├── device.rs   (smoltcp Device impl bridging to TUN)
│   ├── stack.rs    (poll loop, connection lifecycle)
│   └── stream.rs   (AsyncRead/AsyncWrite over smoltcp TcpSocket)
├── transport/
│   └── tcp_tunnel/  (NEW — first transport)
│       ├── header.rs   (SOCKS5-style address encoding)
│       ├── stream.rs   (relay stream wrapper)
│       └── client.rs   (dial logic)
├── proxy/        (NEW — orchestrator)
│   └── tcp.rs      (accepted stream → tunnel client, bidirectional copy)
└── main.rs
```

## The Sync/Async Bridge

smoltcp is **synchronous and poll-based**. tokio is async. You bridge them with this pattern:

```rust
// One async task reads from TUN and pushes packets into a channel:
async fn tun_rx_task(tun: TunReader, tx: mpsc::Sender<Bytes>) -> Result<()> {
    loop {
        let pkt = tun.read_packet().await?;
        tx.send(pkt).await?;
    }
}

// One async task pulls packets from a channel and writes them to TUN:
async fn tun_tx_task(mut tun: TunWriter, mut rx: mpsc::Receiver<Bytes>) -> Result<()> {
    while let Some(pkt) = rx.recv().await {
        tun.write_packet(&pkt).await?;
    }
}

// The smoltcp poll loop runs in its own task. It owns the Interface and Sockets.
// It uses try_recv on incoming and try_send on outgoing to stay non-blocking.
// It also receives "open new connection" requests and "send bytes on socket N"
// requests over a control channel from the proxy orchestrator.
async fn netstack_poll_loop(
    mut iface: Interface,
    mut sockets: SocketSet<'_>,
    mut device: TunDevice,
    mut control: mpsc::Receiver<NetstackCmd>,
    accepted_tx: mpsc::Sender<AcceptedConn>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_millis(10));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                iface.poll(Instant::now(), &mut device, &mut sockets);
                // Drain any newly-readable sockets, push bytes to their owners.
                // Detect newly-accepted connections, send via accepted_tx.
            }
            cmd = control.recv() => {
                if let Some(cmd) = cmd { handle_cmd(cmd, &mut sockets); }
            }
        }
    }
}
```

The smoltcp `Device` impl is the trickiest part. It holds the **sync** ends of the channels and implements `receive()` and `transmit()` via `try_recv` / `try_send`:

```rust
pub struct TunDevice {
    rx: mpsc::Receiver<Bytes>,        // packets from TUN
    tx: mpsc::Sender<Bytes>,          // packets to TUN
    mtu: usize,
}

impl smoltcp::phy::Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.rx.try_recv().ok()?;
        Some((TunRxToken(buf), TunTxToken { tx: &self.tx }))
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken { tx: &self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
```

**Note**: verify the exact smoltcp `Device` trait signature against current docs.rs — the GAT lifetime form changed between versions. The above is the smoltcp 0.11+ shape.

## How Connections Get Accepted

With `netstack-smoltcp` you do **not** hand-manage smoltcp sockets or 5-tuples. The
`TcpListener` surfaces each accepted flow as a stream item. The accept loop is:

```rust
while let Some((stream, local_addr, _remote_addr)) = tcp_listener.next().await {
    // local_addr == original destination the app dialed == tunnel target
    tokio::spawn(handle_conn(stream, local_addr));
}
```

The original destination comes for free as `local_addr`; no SYN re-injection, no
socket lifecycle bookkeeping. (The manual approaches below are retained only as
background for understanding what the crate does internally.)

## The Proxy Orchestrator

Once smoltcp surfaces an accepted connection, you get something like:

```rust
pub struct AcceptedConn {
    pub original_dst: SocketAddr,
    pub stream: NetstackStream,  // AsyncRead + AsyncWrite over smoltcp socket
}
```

The orchestrator's job for each `AcceptedConn`:

```rust
async fn handle_conn(conn: AcceptedConn, transport: Arc<TunnelClient>) -> Result<()> {
    let mut remote = transport.dial(conn.original_dst).await?;
    let (mut lr, mut lw) = tokio::io::split(conn.stream);
    let (mut rr, mut rw) = tokio::io::split(remote);

    let c1 = tokio::io::copy(&mut lr, &mut rw);
    let c2 = tokio::io::copy(&mut rr, &mut lw);

    tokio::try_join!(c1, c2)?;
    Ok(())
}
```

Use `tokio::io::copy_bidirectional` instead if you want fewer moving parts:

```rust
tokio::io::copy_bidirectional(&mut conn.stream, &mut remote).await?;
```

## TCP Tunnel Transport Sketch (first transport)

For the first transport, implement a **plain TCP tunnel** — a minimal relay to a tunnel
server. The client opens a TCP connection to the server, sends the target address, then
relays application bytes in both directions. No bespoke crypto: if you want the relay
encrypted, wrap it in TLS via `rustls` (already in the locked stack), which keeps the
transport itself simple and the crypto delegated to a vetted library.

Wire format for TCP (illustrative, keep it minimal):

```
Request (client → server):
[addr (SOCKS5-style ATYP|ADDR|PORT)] [payload bytes...]

After the header, the connection is a transparent byte relay in both directions.
```

Address encoding (SOCKS5-style):
```
ATYP(1) | ADDR | PORT(2)
ATYP=1 → IPv4(4)
ATYP=3 → DOMAIN: len(1) + name
ATYP=4 → IPv6(16)
```

The `TunnelClient::dial(target)` method:
1. Open a TCP connection to the tunnel server using `tokio::net::TcpStream`
   (optionally wrapped in a `rustls` client session).
2. Encode and send the target address header (SOCKS5-style).
3. Return a stream that relays bytes transparently on both directions.

The returned stream implements `AsyncRead + AsyncWrite`. Keep round-trip tests against a
simple relay/echo server (Appendix B in PLAN.md) before integrating with the netstack —
framing/buffering bugs are easiest to isolate there.

## Suggested Build Order

1. **Plain forwarder first.** Dial `tokio::net::TcpStream::connect(original_dst)`
   directly (no tunnel server). This verifies the netstack pipeline end-to-end without
   any transport complexity. You should be able to `curl 1.1.1.1` through your TUN and
   have it work.

2. **TCP tunnel transport in isolation.** Write it with unit tests and integration tests
   against a simple relay server running locally. Don't touch the TUN yet.

3. **Wire them together.** Replace the plain forwarder with the tunnel client. The same
   `curl` test should now flow through your tunnel server.

Each step is independently verifiable. Don't skip step 1 — it will save you days of
debugging because transport bugs and netstack bugs look identical from the outside (both
produce "connection hangs").

## UDP Note

UDP is a separate path:
- smoltcp's `UdpSocket` surfaces datagrams with `(src_endpoint, dst_endpoint, payload)`.
- The tunnel transport carries each datagram with a small per-packet framing (length +
  target address).
- You also need an association table mapping `(client_src, original_dst)` to a long-lived
  UDP socket to the tunnel server, with idle timeout.

Defer UDP until TCP works end-to-end.

## Things to Verify Against docs.rs Before Coding

- `smoltcp::phy::Device` trait shape (GAT lifetimes changed across 0.9 → 0.10 → 0.11)
- `smoltcp::iface::Interface::poll` signature
- `tun-rs` async read/write APIs (the crate has both sync and async surfaces)
- `rustls` client config / `tokio-rustls` `TlsConnector` API (if wrapping the relay in TLS)

## Open Questions to Resolve

1. **Routing setup**: how does the OS route traffic through the TUN? You'll need a `ip route add` step or to set the TUN as the default gateway with policy routing to avoid loops. Document this in the README before the design is "done."
2. **DNS**: where do DNS queries go? They'll hit the TUN as UDP/53 by default. Decide: (a) proxy them through the tunnel like everything else, (b) intercept and resolve via a configured resolver, (c) bypass entirely.
3. **MTU**: the TUN MTU and the tunnel server's path MTU interact. Default to 1500 - overhead, document the math.
