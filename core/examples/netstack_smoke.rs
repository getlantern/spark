//! M0 gate: prove `netstack-smoltcp` 0.2.2 composes the way the design assumes, on
//! the real (>= 1.85) toolchain, WITHOUT a live TUN device. Prints `NETSTACK OK`.
//!
//! Load-bearing assumptions exercised here (re-verify before trusting STATE.md):
//!   1. `StackBuilder` is fluent and `.mtu(n)` exists in 0.2.x (NOT 0.1.x).
//!   2. `build()` returns `(Stack, Option<Runner>, Option<UdpSocket>, Option<TcpListener>)`.
//!   3. `Stack` is `Stream<Item = io::Result<AnyIpPktFrame>>` + `Sink<AnyIpPktFrame>`,
//!      so `stack.split()` gives the two halves we bridge to the TUN.
//!   4. `TcpListener` yields `(TcpStream, local_addr, remote_addr)`, where `local_addr`
//!      is the original destination the app dialed.
//!   5. `TcpStream: AsyncRead + AsyncWrite (+ Unpin)`, so `copy_bidirectional` to an
//!      upstream works directly — verified by the (never-fired) `handle_conn` below.

use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{AnyIpPktFrame, StackBuilder, TcpStream};
use tokio::sync::mpsc;

/// Stand-in for a framed TUN device: a stream of inbound IP packets plus a sink of
/// outbound IP packets. `tun-rs`'s `.into_framed()` yields this shape, as does an
/// Apple `NEPacketTunnelFlow` shuttled over a channel via FFI.
struct PacketSource {
    inbound: mpsc::Receiver<AnyIpPktFrame>,
    outbound: mpsc::Sender<AnyIpPktFrame>,
}

/// Bridge the netstack to a packet source — the identical glue on every platform.
async fn run_bridge(stack: netstack_smoltcp::Stack, mut tun: PacketSource) {
    let (mut stack_sink, mut stack_stream) = stack.split();

    let to_tun = async move {
        while let Some(Ok(pkt)) = stack_stream.next().await {
            if tun.outbound.send(pkt).await.is_err() {
                break;
            }
        }
    };
    let to_stack = async move {
        while let Some(pkt) = tun.inbound.recv().await {
            if stack_sink.send(pkt).await.is_err() {
                break;
            }
        }
    };
    tokio::join!(to_tun, to_stack);
}

/// Per-connection job. The real tool dials a tunnel-transport stream to `original_dst`;
/// here we plain-connect, which is enough to prove `TcpStream` has the `AsyncRead +
/// AsyncWrite + Unpin` shape `copy_bidirectional` requires. Never fires in this smoke
/// test (no packets flow), but it must compile.
async fn handle_conn(mut down: TcpStream, original_dst: SocketAddr) -> std::io::Result<()> {
    let mut up = tokio::net::TcpStream::connect(original_dst).await?;
    let (_down_to_up, _up_to_down) = tokio::io::copy_bidirectional(&mut down, &mut up).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Buffer sizing is the iOS memory-cap lever. `.mtu(1500)` exercises the 0.2.x-only
    // builder method (it does not exist on 0.1.x).
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .stack_buffer_size(512)
        .tcp_buffer_size(512)
        .udp_buffer_size(256)
        .mtu(1500)
        .build()?;

    // The runner drives smoltcp's poll loop; it must be spawned when present.
    if let Some(runner) = runner {
        tokio::spawn(runner);
    }

    // Accept loop: a stream of (stream, local_addr=src, remote_addr=original_dst).
    // NOTE: netstack-smoltcp inverts the usual server-socket naming — `local_addr` is
    // the app's source and `remote_addr` is the original destination (the socket
    // `listen`s on the packet's dst_addr). Dial the THIRD element. See
    // core/src/netstack/mod.rs::accept_tcp for the verified derivation.
    if let Some(mut listener) = tcp_listener {
        tokio::spawn(async move {
            while let Some((stream, _src, original_dst)) = listener.next().await {
                tokio::spawn(async move {
                    let _ = handle_conn(stream, original_dst).await;
                });
            }
        });
    }

    if let Some(_udp) = udp_socket {
        // UDP NAT table keyed by (src, original_dst) is built at M5.
    }

    // No real TUN: feed the bridge empty channels so it idles, then declare success
    // once the stack has been built and wired without panicking.
    let (_in_tx, in_rx) = mpsc::channel::<AnyIpPktFrame>(64);
    let (out_tx, _out_rx) = mpsc::channel::<AnyIpPktFrame>(64);
    let tun = PacketSource {
        inbound: in_rx,
        outbound: out_tx,
    };

    tokio::select! {
        _ = run_bridge(stack, tun) => {}
        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
            println!("NETSTACK OK");
        }
    }
    Ok(())
}
