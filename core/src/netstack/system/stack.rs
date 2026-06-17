//! [`SystemNetstack`] — the kernel-TCP [`Netstack`] implementation, wiring [`Gateway`] to the live
//! TUN + a kernel TCP listener.
//!
//! Three tasks share the [`Gateway`] (behind a fast, never-held-across-`.await` `std::sync::Mutex`):
//! - **pump** — reads each IP packet from the TUN, runs [`Gateway::process_tcp`], writes the
//!   rewritten packet back. Non-TCP packets are dropped for now (TCP-only; UDP/ICMP — i.e. the
//!   "mixed" stack — is a later chunk, so DNS over this stack won't resolve yet).
//! - **accept loop** (one per bound listener) — `accept()`s a kernel `TcpStream`, resolves its peer
//!   (`gateway:natPort`) back to the original `(client, target)` via [`Gateway::resolve_accept`],
//!   and surfaces it as a [`TcpFlow`] for the proxy. The stream *is* a real kernel socket.
//! - **reaper** — periodically evicts idle NAT mappings.
//!
//! Caveat for the live gate: redirected packets re-enter the host on the TUN destined to a local
//! address; Linux reverse-path filtering (`rp_filter`) may drop them, and FIN/RST-driven NAT
//! removal isn't implemented yet (idle eviction only). Both are addressed when this is gated.

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
use crate::netstack::{Netstack, TcpFlow};
use crate::tun::Tun;

/// Accepted flows buffered for the proxy before the accept loop backpressures.
const ACCEPT_CHANNEL_DEPTH: usize = 256;
/// How often the idle-NAT reaper runs.
const REAPER_INTERVAL: Duration = Duration::from_secs(300);
/// Evict a NAT mapping after this much silence. Generous: evicting a live (but quiet) connection's
/// mapping breaks it, and FIN/RST-driven removal isn't implemented yet.
const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(7200);

/// A [`Netstack`] in which the host kernel owns TCP; see the module docs.
pub struct SystemNetstack {
    accept_rx: mpsc::Receiver<TcpFlow>,
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

        let gateway = Arc::new(Mutex::new(Gateway::new(v4, v6)));
        let mut tasks = Vec::with_capacity(listeners.len() + 2);
        tasks.push(tokio::spawn(pump_loop(
            Arc::clone(&tun),
            Arc::clone(&gateway),
            mtu,
        )));
        for listener in listeners {
            tasks.push(tokio::spawn(accept_loop(
                listener,
                Arc::clone(&gateway),
                accept_tx.clone(),
            )));
        }
        tasks.push(tokio::spawn(reaper_loop(Arc::clone(&gateway))));

        Ok(Self { accept_rx, tasks })
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

/// Read → rewrite → write back. The lock is taken only for the synchronous `process_tcp`, never
/// across the TUN `.await`s.
async fn pump_loop(tun: Arc<Tun>, gateway: Arc<Mutex<Gateway>>, mtu: usize) {
    let mut buf = vec![0u8; mtu.max(1500)];
    loop {
        let n = match tun.recv(&mut buf).await {
            Ok(0) => continue,
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "system stack: TUN recv failed; stopping pump");
                break;
            }
        };
        let action = lock(&gateway).process_tcp(&mut buf[..n], Instant::now());
        if action == PumpAction::WriteBack {
            if let Err(e) = tun.send(&buf[..n]).await {
                warn!(error = %e, "system stack: TUN send failed; stopping pump");
                break;
            }
        }
        // Passthrough/Drop: dropped. UDP/ICMP over the system stack is a later chunk.
    }
    debug!("system stack: pump ended");
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
        let resolved = lock(&gateway).resolve_accept(peer, Instant::now());
        match resolved {
            Some((client, target)) => {
                let flow = TcpFlow {
                    original_dst: target,
                    src: client,
                    stream: Box::new(stream),
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
        let removed = lock(&gateway).evict_idle(Instant::now(), NAT_IDLE_TIMEOUT);
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
