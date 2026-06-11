//! Spike: verify that `netstack-smoltcp` 0.2.2 composes the way the design doc
//! assumes, WITHOUT a live TUN device. Goal: a clean `cargo build` exercising
//! every load-bearing type assumption.

use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{AnyIpPktFrame, StackBuilder, TcpStream};
use tokio::sync::mpsc;

/// Stand-in for a framed TUN device: a Stream of inbound IP packets + a Sink of
/// outbound IP packets. tun-rs/tun2 `.into_framed()` yields this shape, as does
/// an Apple NEPacketFlow shuttled over a channel via FFI.
struct PacketSource {
    inbound: mpsc::Receiver<AnyIpPktFrame>,
    outbound: mpsc::Sender<AnyIpPktFrame>,
}

/// Bridge the netstack to a packet source — identical glue on every platform.
async fn run_bridge(stack: netstack_smoltcp::Stack, mut tun: PacketSource) {
    let (mut stack_sink, mut stack_stream) = stack.split();

    let to_tun = async move {
        while let Some(pkt) = stack_stream.next().await {
            if let Ok(pkt) = pkt {
                if tun.outbound.send(pkt).await.is_err() { break; }
            }
        }
    };
    let to_stack = async move {
        while let Some(pkt) = tun.inbound.recv().await {
            if stack_sink.send(pkt).await.is_err() { break; }
        }
    };
    tokio::join!(to_tun, to_stack);
}

/// Per-connection job. Real tool: dial a Shadowsocks-2022 stream to original_dst.
/// Here: plain TCP connect (design doc milestone 1, same AsyncRead+AsyncWrite shape).
async fn handle_conn(mut down: TcpStream, original_dst: SocketAddr) -> std::io::Result<()> {
    let mut up = tokio::net::TcpStream::connect(original_dst).await?;
    // The whole verification: TcpStream must be AsyncRead+AsyncWrite here.
    let (_d2u, _u2d) = tokio::io::copy_bidirectional(&mut down, &mut up).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // (1) Runtime buffer sizing — the iOS memory-cap lever.
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .stack_buffer_size(512)
        .tcp_buffer_size(512)
        .udp_buffer_size(256)
        .build()?;

    // (3) Runner must be driven.
    if let Some(runner) = runner { tokio::spawn(runner); }

    // (4)+(5)+(6) Accept loop: Stream of (stream, local_addr, remote_addr).
    if let Some(mut listener) = tcp_listener {
        tokio::spawn(async move {
            while let Some((stream, local_addr, _remote_addr)) = listener.next().await {
                tokio::spawn(async move { let _ = handle_conn(stream, local_addr).await; });
            }
        });
    }

    if let Some(_udp) = udp_socket { /* NAT table keyed by (src, original_dst) */ }

    let (_in_tx, in_rx) = mpsc::channel::<AnyIpPktFrame>(64);
    let (out_tx, _out_rx) = mpsc::channel::<AnyIpPktFrame>(64);
    let tun = PacketSource { inbound: in_rx, outbound: out_tx };

    tokio::select! {
        _ = run_bridge(stack, tun) => {}
        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
            println!("SPIKE OK: all netstack-smoltcp type assumptions hold.");
        }
    }
    Ok(())
}
