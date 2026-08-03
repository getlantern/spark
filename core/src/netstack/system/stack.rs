//! [`SystemNetstack`] — the kernel-TCP [`Netstack`] implementation, wiring [`Gateway`] to the live
//! TUN + a kernel TCP listener.
//!
//! Three tasks share the [`Gateway`] (behind a fast, never-held-across-`.await` `std::sync::Mutex`):
//! - **pump** — reads each IP packet from the TUN and, by protocol: TCP → [`Gateway::process_tcp`]
//!   rewrite + write back; UDP → extract a `UdpDatagram` to the proxy's UDP loop and inject its
//!   replies (the "mixed" stack, so DNS works). ICMP/other are dropped.
//! - **accept loop** (one per bound listener) — `accept()`s a kernel `TcpStream`, resolves its peer
//!   (`gateway:natPort`) back to the original `(client, target)` via [`Gateway::resolve_accept`],
//!   and surfaces it as a [`TcpFlow`] for the proxy. The stream *is* a real kernel socket.
//! - **reaper** — periodically evicts idle NAT mappings.
//!
//! NAT lifecycle: the pump removes a mapping on RST and marks both-FIN connections "closing" so the
//! reaper reclaims them on a short timeout (with a long idle timeout as the safety net). Caveat
//! confirmed at the live gate: redirected packets re-enter the host on the TUN destined to a local
//! address, so Linux reverse-path filtering (`rp_filter`) must be relaxed on that path.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::pump::{Gateway, PumpAction};
use super::rewrite;
use crate::netstack::{Netstack, TcpFlow, UdpDatagram, UdpSurface};
use crate::tun::Tun;

/// Accepted flows buffered for the proxy before the accept loop backpressures.
const ACCEPT_CHANNEL_DEPTH: usize = 256;
/// Depth of the UDP datagram channels (inbound to the proxy, and replies back). UDP is lossy, so a
/// full inbound channel drops rather than blocking the pump.
const UDP_CHANNEL_DEPTH: usize = 1024;
/// How often the idle-NAT reaper runs.
const REAPER_INTERVAL: Duration = Duration::from_secs(300);
/// Evict an *active* NAT mapping after this much silence. Generous: evicting a live (but quiet)
/// connection's mapping breaks it. RST removes immediately and a both-FIN close uses the shorter
/// timeout below, so this is just the safety net for connections that vanish without a clean close.
const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(7200);
/// Evict a gracefully-closing (both-FIN) mapping after this much silence — short, to reclaim the
/// synthetic port promptly while still covering any final ACK/retransmit.
const NAT_CLOSING_TIMEOUT: Duration = Duration::from_secs(60);

/// A [`Netstack`] in which the host kernel owns TCP; see the module docs.
pub struct SystemNetstack {
    accept_rx: mpsc::Receiver<TcpFlow>,
    /// The UDP surface for the proxy's UDP loop, taken once via [`Self::take_udp`].
    udp: Option<UdpSurface>,
    /// pump + accept loop(s) + reaper. Aborted on drop.
    tasks: Vec<JoinHandle<()>>,
}

impl SystemNetstack {
    /// Build the system stack over `tun`. `server_v4`/`server_v6` are the tun's own addresses (the
    /// kernel listener binds to each present family; the synthetic `gateway` address is derived as
    /// `server + 1`). Must be called within a tokio runtime; at least one family is required.
    pub fn new(
        tun: Arc<Tun>,
        server_v4: Option<Ipv4Addr>,
        server_v6: Option<Ipv6Addr>,
    ) -> io::Result<Self> {
        let mtu = tun.mtu();
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_CHANNEL_DEPTH);

        let mut listeners = Vec::new();
        let v4 = match server_v4 {
            Some(ip) => {
                let (l, port) = bind_listener(IpAddr::V4(ip))?;
                listeners.push(l);
                Some((ip, port))
            }
            None => None,
        };
        let v6 = match server_v6 {
            Some(ip) => {
                let (l, port) = bind_listener(IpAddr::V6(ip))?;
                listeners.push(l);
                Some((ip, port))
            }
            None => None,
        };
        if v4.is_none() && v6.is_none() {
            return Err(io::Error::other(
                "system netstack: no IPv4/IPv6 server address",
            ));
        }

        // Log the redirect's coordinates at startup. Without this a failure is indistinguishable
        // from "the stack never ran" — which is exactly how the Android gate presented.
        if let Some((ip, port)) = v4 {
            debug!(server = %ip, gateway = %crate::netstack::system::pump::next_addr(IpAddr::V4(ip)), listener_port = port, "system stack: v4 redirect ready");
        }
        if let Some((ip, port)) = v6 {
            debug!(server = %ip, listener_port = port, "system stack: v6 redirect ready");
        }
        let gateway = Arc::new(Mutex::new(Gateway::new(v4, v6)));
        // UDP surface: the pump extracts inbound datagrams into `udp_in_tx` (proxy reads
        // `udp_in_rx`); the proxy's replies arrive on `udp_reply_rx` for the pump to inject.
        let (udp_in_tx, udp_in_rx) = mpsc::channel::<UdpDatagram>(UDP_CHANNEL_DEPTH);
        let (udp_reply_tx, udp_reply_rx) = mpsc::channel::<UdpDatagram>(UDP_CHANNEL_DEPTH);

        let mut tasks = Vec::with_capacity(listeners.len() + 2);
        tasks.push(tokio::spawn(pump_loop(
            Arc::clone(&tun),
            Arc::clone(&gateway),
            mtu,
            udp_in_tx,
            udp_reply_rx,
        )));
        for listener in listeners {
            tasks.push(tokio::spawn(accept_loop(
                listener,
                Arc::clone(&gateway),
                accept_tx.clone(),
            )));
        }
        tasks.push(tokio::spawn(reaper_loop(Arc::clone(&gateway))));

        Ok(Self {
            accept_rx,
            udp: Some((udp_in_rx, udp_reply_tx)),
            tasks,
        })
    }

    /// Take the UDP surface (inbound datagram receiver + reply sender) for the proxy's UDP loop.
    /// Returns `Some` only the first time, mirroring [`SmoltcpNetstack::take_udp`].
    ///
    /// [`SmoltcpNetstack::take_udp`]: crate::netstack::SmoltcpNetstack::take_udp
    pub fn take_udp(&mut self) -> Option<UdpSurface> {
        self.udp.take()
    }
}

impl Drop for SystemNetstack {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[async_trait]
impl Netstack for SystemNetstack {
    async fn accept_tcp(&mut self) -> Option<TcpFlow> {
        self.accept_rx.recv().await
    }
}

/// Bind a non-blocking kernel TCP listener to `ip` on an ephemeral port; return it + the port.
fn bind_listener(ip: IpAddr) -> io::Result<(TcpListener, u16)> {
    let std = std::net::TcpListener::bind(SocketAddr::new(ip, 0))?;
    std.set_nonblocking(true)?;
    let port = std.local_addr()?.port();
    Ok((TcpListener::from_std(std)?, port))
}

/// Lock the gateway, tolerating a poisoned mutex (a panicked holder leaves the NAT consistent
/// enough — the lock is only ever held for one synchronous `process`/`resolve`/`evict`).
fn lock(gateway: &Mutex<Gateway>) -> std::sync::MutexGuard<'_, Gateway> {
    gateway.lock().unwrap_or_else(|e| e.into_inner())
}

/// The TUN ↔ kernel pump. Reads each IP packet and, by protocol: TCP → rewrite via the gateway and
/// write back; UDP → extract a [`UdpDatagram`] to the proxy (the "mixed" stack). Concurrently
/// injects UDP replies from the proxy as fresh UDP packets onto the TUN. The gateway lock is taken
/// only for the synchronous classify/rewrite, never across a TUN `.await`.
async fn pump_loop(
    tun: Arc<Tun>,
    gateway: Arc<Mutex<Gateway>>,
    mtu: usize,
    udp_in: mpsc::Sender<UdpDatagram>,
    mut udp_reply_rx: mpsc::Receiver<UdpDatagram>,
) {
    let mut buf = vec![0u8; mtu.max(1500)];
    let mut reply_buf = Vec::with_capacity(mtu.max(1500));
    // Trace the opening packets only: enough to locate a blackhole, bounded so a working tunnel does
    // not spam. Counts every branch, so "no TCP seen" and "TCP seen but never written" look different.
    let mut traced = 0u32;
    const TRACE_FIRST: u32 = 20;
    loop {
        tokio::select! {
            r = tun.recv(&mut buf) => {
                let n = match r {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        warn!(error = %e, "system stack: TUN recv failed; stopping pump");
                        break;
                    }
                };
                let proto = rewrite::ip_protocol(&buf[..n]);
                if traced < TRACE_FIRST {
                    traced += 1;
                    debug!(n = traced, len = n, proto = ?proto, "system stack: rx packet");
                }
                match proto {
                    Some(6) => {
                        let action = lock(&gateway).process_tcp(&mut buf[..n], Instant::now());
                        if traced <= TRACE_FIRST {
                            debug!(action = ?action, "system stack: tcp rewrite decision");
                        }
                        if action == PumpAction::WriteBack {
                            if let Err(e) = tun.send(&buf[..n]).await {
                                warn!(error = %e, "system stack: TUN send failed; stopping pump");
                                break;
                            }
                            if traced <= TRACE_FIRST {
                                debug!("system stack: wrote rewritten packet back to TUN");
                            }
                        }
                    }
                    Some(17) => extract_udp(&buf[..n], &gateway, &udp_in),
                    _ => {} // ICMP/other: not handled by the system stack — dropped.
                }
            }
            reply = udp_reply_rx.recv() => {
                let Some(reply) = reply else { break }; // proxy gone
                // Inject as src = the dialed target, dst = the app — the reply the app expects.
                if rewrite::build_udp(reply.original_dst, reply.client_src, &reply.payload, &mut reply_buf).is_ok() {
                    if let Err(e) = tun.send(&reply_buf).await {
                        warn!(error = %e, "system stack: TUN send (udp reply) failed; stopping pump");
                        break;
                    }
                }
            }
        }
    }
    debug!("system stack: pump ended");
}

/// Parse an inbound UDP packet and, if it targets a routable destination, hand it to the proxy's UDP
/// loop. Lossy by design: a full inbound channel drops the datagram rather than blocking the pump.
fn extract_udp(pkt: &[u8], gateway: &Mutex<Gateway>, udp_in: &mpsc::Sender<UdpDatagram>) {
    let Ok((src, dst, payload_off)) = rewrite::udp_endpoints(pkt) else {
        return;
    };
    if !lock(gateway).intercept_udp(src, dst) {
        return; // not a routable proxy target — drop
    }
    let datagram = UdpDatagram {
        client_src: src,
        original_dst: dst,
        payload: pkt[payload_off..].to_vec(),
    };
    let _ = udp_in.try_send(datagram); // drop if full/closed (UDP is lossy)
}

/// Accept kernel connections and surface each as a [`TcpFlow`], resolving the original endpoints
/// from the NAT.
async fn accept_loop(
    listener: TcpListener,
    gateway: Arc<Mutex<Gateway>>,
    accept_tx: mpsc::Sender<TcpFlow>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "system stack: accept failed; stopping accept loop");
                break;
            }
        };
        debug!(%peer, "system stack: kernel listener accepted a redirected connection");
        let resolved = lock(&gateway).resolve_accept(peer, Instant::now());
        match resolved {
            Some((client, target)) => {
                let flow = TcpFlow {
                    original_dst: target,
                    src: client,
                    stream: Box::new(stream),
                    abort: None,
                };
                if accept_tx.send(flow).await.is_err() {
                    break; // the proxy dropped the receiver
                }
            }
            None => debug!(%peer, "system stack: accepted connection has no NAT mapping; dropping"),
        }
    }
    debug!("system stack: accept loop ended");
}

/// Periodically evict idle NAT mappings.
async fn reaper_loop(gateway: Arc<Mutex<Gateway>>) {
    let mut tick = tokio::time::interval(REAPER_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let removed =
            lock(&gateway).evict_idle(Instant::now(), NAT_IDLE_TIMEOUT, NAT_CLOSING_TIMEOUT);
        if removed > 0 {
            debug!(removed, "system stack: evicted idle NAT mappings");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_a_listener_on_an_ephemeral_port() {
        let (listener, port) = bind_listener(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert!(port > 0);
        assert_eq!(listener.local_addr().unwrap().port(), port);
    }
}
