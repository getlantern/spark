//! The netstack surface the proxy core depends on, plus the `netstack-smoltcp` impl.
//!
//! A TUN device hands us raw L3 IP packets; the proxy core wants L4 streams. The
//! netstack is what bridges the two: it runs a userspace TCP/IP stack (smoltcp, here)
//! that terminates the application's TCP connections and surfaces each as an accepted
//! byte stream tagged with the address the application originally dialed.
//!
//! The core depends only on the [`Netstack`] trait and [`TcpFlow`], never on
//! `netstack-smoltcp` directly, so the implementation can later be swapped for
//! `ipstack`, a hand-rolled smoltcp bridge, or a newer netstack without touching the
//! proxy. [`SmoltcpNetstack`] is the one M2 implementation.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::tun::Tun;
use crate::BoxedStream;

// The system (kernel-TCP) netstack — a second `Netstack` impl behind the `system-stack` feature
// (off by default; desktop-only). See `docs/system-stack-design.md`.
#[cfg(feature = "system-stack")]
pub mod system;

/// Channel depth for the netstack UDP surface (inbound datagrams and pending replies).
const UDP_CHANNEL_DEPTH: usize = 1024;

/// Depth of the netstack's IP-packet channels between the smoltcp stack and the TUN bridge (each
/// direction). The vendored default (1024) is too shallow for the egress burst of a multi-flow
/// download: the channel saturates and throughput nearly stalls. Deeper channels are a **partial
/// mitigation** — they raise the concurrent-download floor ~14× (measured 0.03 → 0.42 Gb/s at 4
/// streams, `bench/`) but do NOT cure the underlying collapse, which is a single-dispatch-task
/// pathology in netstack-smoltcp (see `docs/system-stack-design.md` §9). The tokio mpsc bound does
/// not preallocate, so this is a worst-case cap, not resident cost — but tune it down for the iOS
/// Packet-Tunnel memory cap (frames are MTU-sized).
const STACK_BUFFER_SIZE: usize = 16384;
/// Depth of the per-direction TCP IP-packet channel inside the stack.
const TCP_BUFFER_SIZE: usize = 8192;

/// Whether the netstack should terminate a flow to `dst`. IPv4: always. IPv6: only our fake-IP
/// range — a fake v6 recovers to a domain the exit dials by name, so it is deliverable.
///
/// A **real** IPv6 destination (e.g. resolved by a browser's own DoH, which bypasses the fake-IP
/// DNS) cannot currently egress — the exits are v4-only — and smoltcp completes the TCP handshake
/// locally *before* the upstream dial, which poisons the client's Happy-Eyeballs fallback: the
/// app sees an established connection that then stalls for ~10 s+ instead of instantly falling
/// back to v4 (observed as broken Google images / flaky YouTube, whose hosts are aggressively
/// dual-stacked). Dropping the packets here means the v6 SYN gets no answer, the app's racing v4
/// candidate wins in milliseconds, and nothing leaks around the tunnel — the platform still
/// claims `::/0`, so the packets die inside the TUN rather than egressing the physical NIC.
/// Revisit if the exits gain IPv6 egress.
fn allow_flow_dst(dst: &std::net::IpAddr) -> bool {
    match dst {
        std::net::IpAddr::V4(_) => true,
        #[cfg(feature = "smart-routing")]
        std::net::IpAddr::V6(a) => crate::dns::fakeip::is_fake_v6(a),
        // Without the fake-IP DNS there are no deliverable v6 destinations at all.
        #[cfg(not(feature = "smart-routing"))]
        std::net::IpAddr::V6(_) => false,
    }
}

/// A surfaced L4 TCP flow, independent of the netstack implementation.
pub struct TcpFlow {
    /// The address the application originally dialed — i.e. the upstream to connect to.
    pub original_dst: SocketAddr,
    /// The application's source address inside the tunnel. Not needed to forward a plain
    /// TCP flow, but kept for debug logging now and UDP NAT keying later.
    pub src: SocketAddr,
    /// The flow's byte stream: reading yields app→upstream bytes, writing delivers
    /// upstream→app bytes.
    pub stream: BoxedStream,
    /// Abort the connection with an RST (REJECT semantics) — fired for `Decision::Reject` so the
    /// client fails fast with ECONNRESET instead of hanging until its own timeout. Dropping the
    /// smoltcp stream alone does not reliably deliver any close to the client (observed: the
    /// client socket stays ESTABLISHED and ad-blocked hosts hang browsers for 15+ s). `None`
    /// where the impl has no RST surface (the flow is then just dropped, as before).
    pub abort: Option<Box<dyn FnOnce() + Send>>,
}

/// A UDP datagram crossing the netstack boundary, tagged with its flow identity.
///
/// For an inbound datagram (from the TUN) `payload` is what the app sent. For a reply the
/// proxy hands back, `payload` is the upstream's response; the netstack writes it to the TUN
/// as an IP packet `src = original_dst`, `dst = client_src` so the app sees a reply from the
/// address it dialed.
pub struct UdpDatagram {
    /// The application's source address inside the tunnel.
    pub client_src: SocketAddr,
    /// The address the application originally dialed.
    pub original_dst: SocketAddr,
    /// The datagram payload.
    pub payload: Vec<u8>,
}

/// The netstack's UDP surface: a receiver of inbound datagrams and a sender for replies.
/// Obtained once from [`SmoltcpNetstack::take_udp`] and consumed by the UDP proxy loop.
pub type UdpSurface = (mpsc::Receiver<UdpDatagram>, mpsc::Sender<UdpDatagram>);

/// The netstack surface our proxy depends on. `netstack-smoltcp` is one impl; the kernel-TCP
/// `system` stack is another, selected by config (see [`build`]).
#[async_trait]
pub trait Netstack: Send {
    /// Yield the next accepted TCP flow, or `None` once the netstack has shut down.
    async fn accept_tcp(&mut self) -> Option<TcpFlow>;
    // UDP surface added when the UDP path is built (M5).
}

/// Lets a boxed netstack be passed to the generic [`proxy`](crate::proxy) forwarders, so the impl
/// can be chosen at runtime ([`build`]) while the core stays statically typed.
#[async_trait]
impl Netstack for Box<dyn Netstack> {
    async fn accept_tcp(&mut self) -> Option<TcpFlow> {
        (**self).accept_tcp().await
    }
}

/// Build the configured netstack over `tun`: the userspace smoltcp stack (default) or the kernel
/// `system` stack. Returns the TCP netstack plus the UDP surface that drives the UDP proxy (both
/// stacks supply one — the system stack's is the "mixed" datagram path).
pub fn build(
    tun: Arc<Tun>,
    config: &crate::config::Config,
) -> io::Result<(Box<dyn Netstack>, Option<UdpSurface>)> {
    match resolve_stack(config.tun.stack) {
        Resolved::Userspace => {
            let mut ns = SmoltcpNetstack::new(tun)?;
            let udp = ns.take_udp();
            Ok((Box::new(ns), udp))
        }
        Resolved::System => build_system(tun, config),
    }
}

/// What [`StackKind::Auto`](crate::config::StackKind::Auto) resolves to, once the platform staging
/// has been applied. Only ever `Userspace` or `System` — `Auto` is a request, not an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    Userspace,
    System,
}

/// Apply the per-platform staging for `auto`, leaving an explicit choice untouched.
///
/// The kernel stack is meant to become the default — it removes the concurrent-download collapse
/// (userspace craters to 0.13 Gb/s at two parallel downloads while system holds ~1.09), and sing-box
/// already defaults to kernel TCP on every platform it supports. It is staged rather than flipped at
/// once because **every platform still has a distinct open gate**, and shipping a data path that has
/// never executed somewhere does not degrade the product there, it breaks it.
///
/// What is gating each platform, so flipping one is a one-line change here plus a test:
///
/// - **Linux** — the only platform with a live gate (netns A/B), but that gate ran with
///   `rp_filter=0`. The redirect re-injects packets on the TUN destined to a *local* address, which
///   strict reverse-path filtering drops, and most distributions ship `rp_filter` enabled. Flipping
///   needs spark to either relax it for the redirected path or detect that it is already relaxed —
///   auto-selecting today would break the tunnel on a default install.
/// - **macOS** — **runs correctly** (verified 2026-08-02: TCP and UDP, smoke and sustained
///   multi-flow, against a WAN peer). Still userspace by default for a different reason than the
///   others: the link was ~90 Mb/s and the collapse takes userspace to ~130 Mb/s, so the wire was
///   slower than the pathology. Both stacks therefore looked equally healthy, and the kernel stack's
///   *advantage* is unmeasured on macOS rather than disproven. A second run over a ~250 Mb/s LAN peer
///   still did not reproduce it: userspace held 0.268 Gb/s at 4 streams, twice the droplet's 0.13
///   floor. The collapse is CPU-bound (one dispatch task for every flow), so a fast desktop may never
///   reach the regime — which makes throughput the wrong argument for flipping *any* desktop default,
///   and makes Android the higher-value target. See `docs/system-stack-design.md`.
/// - **Android** — **executed 2026-08-03, and it does not work**: the stack initializes cleanly (arm
///   confirmed in logcat, zero smoltcp lines, no panic, `tun0` up) and then forwards nothing — 100%
///   packet loss, while userspace on the same device and peer carried 58–62 Mb/s minutes earlier.
///   `rp_filter` is already `0` on every interface there, so the documented Linux precondition is
///   **not** the cause, and an unprivileged app cannot change it regardless. This is a real bug in
///   the redirect mechanism on Android, not a gate awaiting a measurement. See
///   `docs/android-system-stack-gate.md` §0a.
/// - **Windows** — not merely unverified: sing-tun keeps a *separate* `stack_system_windows.go`
///   because bind/socket semantics differ, so this likely needs its own code path rather than a
///   flag flip (`docs/system-stack-design.md` §7).
/// - **iOS** — permanent. `NEPacketTunnelFlow` is not a kernel tun, so redirect-to-a-local-listener
///   has nothing to redirect to. sing-box runs gVisor there for the same reason.
///
/// Without the `system-stack` feature compiled in, `auto` resolves to userspace. That is not the
/// silent fallback the codebase forbids: nobody asked for the kernel stack, so there is no request
/// to fail. Asking for it *explicitly* without the feature remains a hard startup error.
pub fn resolve_stack(kind: crate::config::StackKind) -> Resolved {
    use crate::config::StackKind;
    match kind {
        StackKind::Userspace => Resolved::Userspace,
        StackKind::System => Resolved::System,
        // Every platform is still gated; see the list above. Flip one by returning `System` here
        // under its `cfg`, once its gate has actually passed.
        StackKind::Auto => Resolved::Userspace,
    }
}

/// Build the system (kernel-TCP) stack when the `system-stack` feature is present.
#[cfg(feature = "system-stack")]
fn build_system(
    tun: Arc<Tun>,
    config: &crate::config::Config,
) -> io::Result<(Box<dyn Netstack>, Option<UdpSurface>)> {
    // IPv4 only for now; the tun's configured address is the listener/server address.
    let mut ns = system::SystemNetstack::new(tun, Some(config.tun.addr), None)?;
    let udp = ns.take_udp(); // the "mixed" stack: kernel TCP + the proxy's UDP datagram path
    Ok((Box::new(ns), udp))
}

/// Without the feature, selecting `stack = system` is a hard error rather than a silent fallback.
#[cfg(not(feature = "system-stack"))]
fn build_system(
    _tun: Arc<Tun>,
    _config: &crate::config::Config,
) -> io::Result<(Box<dyn Netstack>, Option<UdpSurface>)> {
    Err(io::Error::other(
        "tun.stack = system but spark was built without the `system-stack` feature",
    ))
}

/// A [`Netstack`] backed by the vendored `netstack-smoltcp` crate.
///
/// Owns the accept side of the stack (the TCP listener) plus the background tasks that
/// keep it alive — smoltcp's poll runner and the bidirectional TUN↔stack packet bridge.
/// All three are aborted when the handle is dropped.
pub struct SmoltcpNetstack {
    listener: TcpListener,
    /// The UDP surface (inbound receiver + reply sender), taken once via [`Self::take_udp`].
    udp: Option<UdpSurface>,
    /// Runner + the TUN↔stack bridge + the UDP drain tasks. Held so they can be aborted on
    /// drop rather than leaked (CLAUDE.md: store every spawned `JoinHandle` that isn't
    /// fire-and-forget).
    tasks: Vec<JoinHandle<()>>,
}

impl SmoltcpNetstack {
    /// Build the stack sized to the device MTU, spawn the poll runner and the
    /// bidirectional TUN↔stack bridge, and return a handle whose
    /// [`Netstack::accept_tcp`] yields surfaced TCP flows.
    ///
    /// `tun` is shared (`Arc`) because the two bridge directions read and write the same
    /// device concurrently from separate tasks; both `Tun::recv`/`Tun::send` take `&self`.
    pub fn new(tun: Arc<Tun>) -> io::Result<Self> {
        let mtu = tun.mtu();

        // ICMP rides the TCP interface (smoltcp answers echo), preserving the M1 `ping <tun>`
        // sanity check at no extra cost.
        let (stack, runner, udp_socket, listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .stack_buffer_size(STACK_BUFFER_SIZE)
            .tcp_buffer_size(TCP_BUFFER_SIZE)
            .mtu(mtu)
            .add_ip_filter_fn(|_src, dst| allow_flow_dst(dst))
            .build()?;

        let listener =
            listener.ok_or_else(|| io::Error::other("netstack built without a TCP listener"))?;
        let udp_socket =
            udp_socket.ok_or_else(|| io::Error::other("netstack built without a UDP socket"))?;

        let mut tasks = Vec::with_capacity(5);

        // The runner drives smoltcp's poll loop; it must run for the stack to make
        // progress. Its `io::Result<()>` output is normalized to `()` so all tasks share
        // one `JoinHandle` type.
        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                if let Err(e) = runner.await {
                    warn!(error = %e, "netstack runner exited with error");
                }
            }));
        }

        let (mut sink, mut stream) = stack.split();

        // stack → TUN: write each outbound IP packet the netstack produces to the device.
        let tun_tx = Arc::clone(&tun);
        tasks.push(tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                match item {
                    Ok(pkt) => {
                        if let Err(e) = tun_tx.send(&pkt).await {
                            warn!(error = %e, "TUN send failed; stopping stack→TUN bridge");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "netstack emitted an error frame; stopping stack→TUN bridge");
                        break;
                    }
                }
            }
            debug!("stack→TUN bridge ended");
        }));

        // TUN → stack: feed each inbound IP packet to the netstack. The stack's sink
        // takes an owned `AnyIpPktFrame` (= `Vec<u8>`), so we read directly into a
        // fresh MTU-sized `Vec` and hand it over — one allocation, no copy. (The owned
        // `Vec` is the vendored crate's API; a reusable buffer would force a `.to_vec()`.)
        let tun_rx = Arc::clone(&tun);
        tasks.push(tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; mtu];
                match tun_rx.recv(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => {
                        buf.truncate(n);
                        if let Err(e) = sink.send(buf).await {
                            warn!(error = %e, "netstack sink closed; stopping TUN→stack bridge");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "TUN recv failed; stopping TUN→stack bridge");
                        break;
                    }
                }
            }
            debug!("TUN→stack bridge ended");
        }));

        // UDP surface. The netstack `UdpSocket` splits into a Stream of inbound datagrams
        // and a Sink for replies. Rather than expose those (un-nameable) halves, move each
        // into a drain task bridging it to an mpsc channel the proxy can hold.
        let (mut udp_read, mut udp_write) = udp_socket.split();
        let (in_tx, in_rx) = mpsc::channel::<UdpDatagram>(UDP_CHANNEL_DEPTH);
        let (reply_tx, mut reply_rx) = mpsc::channel::<UdpDatagram>(UDP_CHANNEL_DEPTH);

        // stack → proxy: each inbound `UdpMsg = (payload, local, remote)` is, like the TCP
        // listener, inverted — `local` is the client source, `remote` the original dest.
        tasks.push(tokio::spawn(async move {
            while let Some((payload, client_src, original_dst)) = udp_read.next().await {
                let datagram = UdpDatagram {
                    client_src,
                    original_dst,
                    payload,
                };
                if in_tx.send(datagram).await.is_err() {
                    break; // proxy dropped the receiver
                }
            }
            debug!("UDP stack→proxy drain ended");
        }));

        // proxy → stack: a reply is written to the TUN as `src = original_dst`,
        // `dst = client_src` so the app sees it coming from the address it dialed.
        tasks.push(tokio::spawn(async move {
            while let Some(reply) = reply_rx.recv().await {
                if udp_write
                    .send((reply.payload, reply.original_dst, reply.client_src))
                    .await
                    .is_err()
                {
                    warn!("netstack UDP sink closed; stopping proxy→stack UDP drain");
                    break;
                }
            }
            debug!("UDP proxy→stack drain ended");
        }));

        Ok(Self {
            listener,
            udp: Some((in_rx, reply_tx)),
            tasks,
        })
    }

    /// Take the UDP surface (inbound datagram receiver + reply sender). Returns `Some` only
    /// the first time; subsequent calls return `None`.
    pub fn take_udp(&mut self) -> Option<UdpSurface> {
        self.udp.take()
    }
}

#[async_trait]
impl Netstack for SmoltcpNetstack {
    async fn accept_tcp(&mut self) -> Option<TcpFlow> {
        // The listener yields `(stream, local_addr, remote_addr)`. In netstack-smoltcp
        // these accessors are inverted from the usual server-socket sense: `local_addr`
        // is the application's source (built from `packet.src_addr`) and `remote_addr`
        // is the original destination (`packet.dst_addr`) — the upstream the app dialed.
        // Verified against the vendored source (vendor/netstack-smoltcp/src/tcp.rs:118,
        // 132-133,165, where the socket `listen`s on `dst_addr`). Dial `remote_addr`.
        let (stream, src, original_dst) = self.listener.next().await?;
        let abort = stream.abort_handle();
        Some(TcpFlow {
            original_dst,
            src,
            stream: Box::new(stream),
            abort: Some(Box::new(move || abort.abort())),
        })
    }
}

impl Drop for SmoltcpNetstack {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::allow_flow_dst;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_destinations_are_always_allowed() {
        assert!(allow_flow_dst(&ip("142.250.65.161"))); // real
        assert!(allow_flow_dst(&ip("28.0.0.23"))); // fake-IP v4
        assert!(allow_flow_dst(&ip("8.8.8.8"))); // the tunnel DNS address
    }

    #[test]
    fn real_v6_destinations_are_dropped() {
        // A real global address (Google), a neighbouring ULA, and link-local: none can currently
        // egress, and locally accepting them poisons the client's Happy-Eyeballs v4 fallback.
        assert!(!allow_flow_dst(&ip("2607:f8b0:400f:807::2001")));
        assert!(!allow_flow_dst(&ip("fd00:2019::1")));
        assert!(!allow_flow_dst(&ip("fe80::1")));
    }

    #[cfg(feature = "smart-routing")]
    #[test]
    fn fake_v6_destinations_are_allowed() {
        // Inside the fake pool (3000:2018:: slice used by the allocator) — recoverable to a
        // domain, so deliverable by name.
        assert!(allow_flow_dst(&ip("3000:2018::17")));
        assert!(allow_flow_dst(&IpAddr::V6(crate::dns::fakeip::V6_BASE)));
    }

    #[test]
    fn an_explicit_choice_is_never_overridden_by_staging() {
        use super::{resolve_stack, Resolved};
        // Choosing a stack by hand is how you test ahead of a gate, so `resolve_stack` must pass it
        // through untouched no matter what the staging says for this platform.
        use crate::config::StackKind;
        assert_eq!(resolve_stack(StackKind::System), Resolved::System);
        assert_eq!(resolve_stack(StackKind::Userspace), Resolved::Userspace);
    }

    #[test]
    fn auto_is_conservative_until_this_platform_has_a_passing_gate() {
        use super::{resolve_stack, Resolved};
        // Deliberately asserts the *current* staging rather than a general property: this test is the
        // tripwire that makes flipping a platform a conscious edit. When a gate passes and
        // `resolve_stack` starts returning `System` here, this assertion is supposed to fail and be
        // updated in the same commit — with the gate result cited in the message.
        use crate::config::StackKind;
        assert_eq!(
            resolve_stack(StackKind::Auto),
            Resolved::Userspace,
            "auto still resolves conservatively on this platform; see resolve_stack's gate list"
        );
    }

    #[test]
    fn auto_is_the_default_so_an_omitted_stack_key_is_staged() {
        // The whole mechanism only bites if configs that say nothing about `stack` get `Auto`.
        assert_eq!(
            crate::config::StackKind::default(),
            crate::config::StackKind::Auto
        );
    }
}
