//! UDP forwarding (M5).
//!
//! UDP has no connection for the netstack to "accept", so the netstack surfaces every
//! datagram on a single stream (`UdpSocket::split() → (ReadHalf, WriteHalf)`, each item a
//! `(payload, client_src, original_dst)` — note the same source/destination naming
//! inversion as the TCP listener). To route replies back to the right client we keep a
//! [`NatTable`] of associations keyed by `(client_src, original_dst)`, each holding the
//! per-flow state needed to reach the target and reclaimed after [`idle_timeout`] of
//! silence (UDP has no FIN).
//!
//! [`run_udp`] is the orchestration: it drains the netstack's inbound datagrams, and for
//! each `(client_src, original_dst)` flow gets-or-creates an association — a
//! [`UdpTransport::dial_udp`] connection to the target plus a reply-pump task that writes
//! the upstream's responses back through the netstack. Idle associations are reclaimed on a
//! periodic sweep.
//!
//! The live DNS/echo gate needs root (a TUN); the orchestration itself is exercised
//! hermetically against `DirectTransport` + a loopback echo (see tests).
//!
//! [`idle_timeout`]: NatTable::new

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::netstack::UdpDatagram;
use crate::transport::{BoxedPacketSink, BoxedPacketSource, UdpTransport};

/// Default idle timeout before a UDP association is reclaimed. DNS is request/response and
/// short-lived; 60s comfortably covers a slow resolver round-trip without stranding state.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How often expired associations are swept. Must be well under [`DEFAULT_IDLE_TIMEOUT`].
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// Receive-buffer size for the reply pump — the largest a UDP payload can be.
const MAX_DATAGRAM: usize = u16::MAX as usize;

/// Identifies a UDP flow: the client's source address and the destination it addressed.
/// Datagrams sharing a key reuse one association; the reply path is keyed on it too.
pub type FlowKey = (SocketAddr, SocketAddr);

/// A NAT association table mapping a UDP [`FlowKey`] to per-flow state `V`, reclaiming
/// associations idle longer than the configured timeout.
///
/// Time is passed in (`now: Instant`) rather than read internally, so eviction is
/// deterministically testable. The orchestration loop supplies `Instant::now()`.
pub struct NatTable<V> {
    idle_timeout: Duration,
    entries: HashMap<FlowKey, Entry<V>>,
}

struct Entry<V> {
    value: V,
    last_seen: Instant,
}

impl<V> NatTable<V> {
    /// Create an empty table whose associations expire after `idle_timeout` of silence.
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            entries: HashMap::new(),
        }
    }

    /// Number of live associations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no live associations.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the association for `key`, refreshing its activity timestamp to `now`.
    /// Returns `None` if there is no such association.
    pub fn get(&mut self, key: &FlowKey, now: Instant) -> Option<&V> {
        let entry = self.entries.get_mut(key)?;
        entry.last_seen = now;
        Some(&entry.value)
    }

    /// Get the association for `key`, creating it with `make` if absent. Either way its
    /// activity timestamp is refreshed to `now`.
    pub fn get_or_insert_with<F>(&mut self, key: FlowKey, now: Instant, make: F) -> &mut V
    where
        F: FnOnce() -> V,
    {
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            value: make(),
            last_seen: now,
        });
        entry.last_seen = now;
        &mut entry.value
    }

    /// Mutably look up the association for `key`, refreshing its activity timestamp to
    /// `now`. Returns `None` if there is no such association.
    pub fn get_mut(&mut self, key: &FlowKey, now: Instant) -> Option<&mut V> {
        let entry = self.entries.get_mut(key)?;
        entry.last_seen = now;
        Some(&mut entry.value)
    }

    /// Insert (or replace) the association for `key`, stamping its activity time as `now`.
    pub fn insert(&mut self, key: FlowKey, value: V, now: Instant) {
        self.entries.insert(
            key,
            Entry {
                value,
                last_seen: now,
            },
        );
    }

    /// Remove and return the association for `key`, if any.
    pub fn remove(&mut self, key: &FlowKey) -> Option<V> {
        self.entries.remove(key).map(|e| e.value)
    }

    /// Remove every association idle for longer than the idle timeout as of `now`,
    /// returning the reclaimed values so the caller can release their resources (e.g.
    /// close the per-flow socket to the tunnel server).
    pub fn evict_expired(&mut self, now: Instant) -> Vec<V> {
        let timeout = self.idle_timeout;
        // Collect keys first (the borrow ends before we mutate), then take the values out.
        // `FlowKey` is `Copy`, so this is cheap.
        let expired: Vec<FlowKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_seen) > timeout)
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key).map(|entry| entry.value))
            .collect()
    }
}

/// Per-flow UDP association: the send half toward the target (driven by the read loop) and
/// the reply-pump task handle (aborted when the association is reclaimed).
struct Association {
    sink: BoxedPacketSink,
    pump: JoinHandle<()>,
}

/// Forward UDP datagrams between the netstack and upstreams reached via `transport`.
///
/// Runs until `inbound` closes. Inbound datagrams open or reuse a per-flow association and
/// are sent to the target; each association's reply pump feeds responses back through
/// `reply_tx`. A periodic sweep reclaims associations idle past `idle_timeout`.
pub async fn run_udp(
    mut inbound: mpsc::Receiver<UdpDatagram>,
    reply_tx: mpsc::Sender<UdpDatagram>,
    transport: Arc<dyn UdpTransport>,
    idle_timeout: Duration,
) {
    let mut nat: NatTable<Association> = NatTable::new(idle_timeout);
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        tokio::select! {
            maybe = inbound.recv() => {
                let Some(dgram) = maybe else {
                    debug!("UDP inbound closed; ending udp proxy loop");
                    break;
                };
                handle_inbound(&mut nat, &transport, &reply_tx, dgram).await;
            }
            _ = sweep.tick() => {
                for assoc in nat.evict_expired(Instant::now()) {
                    assoc.pump.abort();
                }
            }
        }
    }
    // Abort any pumps still alive so they don't outlive the loop.
    for (_, assoc) in std::mem::take(&mut nat.entries) {
        assoc.value.pump.abort();
    }
}

/// Send one inbound datagram toward its target, opening the association (and its reply pump)
/// on first sight of the flow.
async fn handle_inbound(
    nat: &mut NatTable<Association>,
    transport: &Arc<dyn UdpTransport>,
    reply_tx: &mpsc::Sender<UdpDatagram>,
    dgram: UdpDatagram,
) {
    let key = (dgram.client_src, dgram.original_dst);
    let now = Instant::now();

    if nat.get_mut(&key, now).is_none() {
        let (sink, source) = match transport.dial_udp(dgram.original_dst).await {
            Ok(halves) => halves,
            Err(e) => {
                warn!(error = %e, "udp: opening association to upstream failed");
                return;
            }
        };
        let pump = spawn_reply_pump(
            source,
            reply_tx.clone(),
            dgram.client_src,
            dgram.original_dst,
        );
        nat.insert(key, Association { sink, pump }, now);
    }

    // Take the send result out before re-borrowing `nat` to handle a failure.
    let send_result = match nat.get_mut(&key, now) {
        Some(assoc) => assoc.sink.send(&dgram.payload).await,
        None => return,
    };
    if let Err(e) = send_result {
        warn!(error = %e, "udp: send to upstream failed; dropping association");
        if let Some(assoc) = nat.remove(&key) {
            assoc.pump.abort();
        }
    }
}

/// Spawn the task that reads upstream replies for one association and forwards them back to
/// the netstack tagged with the flow's identity.
fn spawn_reply_pump(
    mut source: BoxedPacketSource,
    reply_tx: mpsc::Sender<UdpDatagram>,
    client_src: SocketAddr,
    original_dst: SocketAddr,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        // `recv` errors (association closed) end the pump.
        while let Ok(n) = source.recv(&mut buf).await {
            let reply = UdpDatagram {
                client_src,
                original_dst,
                payload: buf[..n].to_vec(),
            };
            if reply_tx.send(reply).await.is_err() {
                break; // netstack/proxy gone
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout() -> Duration {
        Duration::from_secs(30)
    }

    #[test]
    fn get_or_insert_with_creates_then_reuses() {
        let mut table: NatTable<u32> = NatTable::new(timeout());
        let t0 = Instant::now();
        let key: FlowKey = (
            "10.0.0.2:1111".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
        );

        let mut calls = 0;
        *table.get_or_insert_with(key, t0, || {
            calls += 1;
            7
        }) += 1;
        // Second call to the same key must reuse, not re-create.
        let v = table.get_or_insert_with(key, t0, || {
            calls += 1;
            99
        });
        assert_eq!(*v, 8);
        assert_eq!(calls, 1);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn evicts_only_idle_entries_and_returns_them() {
        let mut table: NatTable<&'static str> = NatTable::new(timeout());
        let t0 = Instant::now();
        let a: FlowKey = ("10.0.0.2:1".parse().unwrap(), "1.1.1.1:53".parse().unwrap());
        let b: FlowKey = ("10.0.0.2:2".parse().unwrap(), "8.8.8.8:53".parse().unwrap());

        table.get_or_insert_with(a, t0, || "a");
        table.get_or_insert_with(b, t0, || "b");

        // Refresh only `b`, well after `a` would expire.
        let later = t0 + timeout() + Duration::from_secs(1);
        assert_eq!(table.get(&b, later), Some(&"b"));

        let evicted = table.evict_expired(later);
        assert_eq!(evicted, vec!["a"]);
        assert_eq!(table.len(), 1);
        assert!(table.get(&a, later).is_none());
        assert!(table.get(&b, later).is_some());
    }

    #[test]
    fn nothing_evicted_before_timeout() {
        let mut table: NatTable<u8> = NatTable::new(timeout());
        let t0 = Instant::now();
        let key: FlowKey = ("10.0.0.2:1".parse().unwrap(), "1.1.1.1:53".parse().unwrap());
        table.get_or_insert_with(key, t0, || 1);

        let within = t0 + timeout(); // exactly at the boundary is not "longer than"
        assert!(table.evict_expired(within).is_empty());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn remove_takes_the_value() {
        let mut table: NatTable<u8> = NatTable::new(timeout());
        let t0 = Instant::now();
        let key: FlowKey = ("10.0.0.2:1".parse().unwrap(), "1.1.1.1:53".parse().unwrap());
        table.get_or_insert_with(key, t0, || 42);
        assert_eq!(table.remove(&key), Some(42));
        assert!(table.is_empty());
    }

    /// Full orchestration without a TUN: an inbound datagram opens an association via
    /// `DirectTransport`, reaches a loopback echo, and the reply pump routes the echo back
    /// out `reply_tx` tagged with the original flow identity (the reply-orientation check).
    #[tokio::test]
    async fn run_udp_round_trips_via_direct_transport() {
        use crate::transport::DirectTransport;
        use tokio::net::UdpSocket;

        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                if echo.send_to(&b[..n], from).await.is_err() {
                    break;
                }
            }
        });

        let (in_tx, in_rx) = mpsc::channel(16);
        let (reply_tx, mut reply_rx) = mpsc::channel(16);
        tokio::spawn(run_udp(
            in_rx,
            reply_tx,
            Arc::new(DirectTransport),
            Duration::from_secs(30),
        ));

        let client_src: SocketAddr = "10.0.0.2:5555".parse().unwrap();
        in_tx
            .send(UdpDatagram {
                client_src,
                original_dst: echo_addr,
                payload: b"ping".to_vec(),
            })
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(2), reply_rx.recv())
            .await
            .expect("reply within 2s")
            .expect("a reply datagram");
        assert_eq!(reply.payload, b"ping");
        assert_eq!(reply.client_src, client_src);
        assert_eq!(reply.original_dst, echo_addr);
    }
}
