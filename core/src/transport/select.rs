//! Latency-selecting transport over a server pool (design: `docs/multi-server-selection-design.md`).
//! Implements `Transport`/`UdpTransport`; new flows use the current-best member; a background prober
//! (E3) re-ranks and swaps with failover + hysteresis. The current selection is read under a short
//! `std::sync::Mutex` (never held across `.await`).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::transport::probe::{CallbackUrl, ProbeOutcome};
use crate::transport::{BoxedPacketSink, BoxedPacketSource, Transport, UdpTransport};
use crate::BoxedStream;

/// A built pool member: its transport pair + the callback URL used to probe it.
pub(crate) struct Member {
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) udp: Arc<dyn UdpTransport>,
    pub(crate) callback: CallbackUrl,
}

impl Member {
    pub(crate) fn new(
        transport: Arc<dyn Transport>,
        udp: Arc<dyn UdpTransport>,
        callback: CallbackUrl,
    ) -> Self {
        Member {
            transport,
            udp,
            callback,
        }
    }
}

/// Ranked selection: indices into the pool, best-first; empty = nothing healthy.
#[derive(Default)]
struct Selection {
    ranked: Arc<[usize]>,
}

/// A latency-selecting transport over a pool of [`Member`]s.
pub struct SelectingTransport {
    members: Arc<Vec<Member>>,
    selection: Arc<Mutex<Selection>>,
    reprobe: Arc<tokio::sync::Notify>,
    prober: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SelectingTransport {
    /// Build a selecting transport over `members`, spawning a background prober. Must be called inside
    /// a tokio runtime (as `from_config`'s callers are). The prober runs an initial round immediately,
    /// then re-probes every `interval`; `window` bounds probe concurrency.
    pub(crate) fn new(members: Vec<Member>, interval: std::time::Duration, window: usize) -> Self {
        let members = Arc::new(members);
        // Seed with config order so flows can dial (with failover) before the first probe round; an
        // empty ranking would make startup dials fail with "no healthy server".
        let seeded: Arc<[usize]> = (0..members.len()).collect();
        let selection = Arc::new(Mutex::new(Selection { ranked: seeded }));
        let reprobe = Arc::new(tokio::sync::Notify::new());
        // Clamp to ≥1s so a misconfigured `probe_interval_secs = 0` can't spin the prober.
        let interval = interval.max(std::time::Duration::from_secs(1));
        let task = tokio::spawn(prober_loop(
            Arc::clone(&members),
            Arc::clone(&selection),
            Arc::clone(&reprobe),
            interval,
            window.max(1),
        ));
        SelectingTransport {
            members,
            selection,
            reprobe,
            prober: Mutex::new(Some(task)),
        }
    }

    /// Current best-first order (snapshot; lock not held across `.await`). Returns a cheap
    /// `Arc` clone — a refcount bump, no heap allocation on the hot path.
    fn order(&self) -> Arc<[usize]> {
        self.selection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ranked
            .clone()
    }

    /// Move a failed member to the back of the ranking (so new flows stop trying it first) and wake
    /// the prober for an immediate off-cycle re-probe. A transient reorder; the next probe round
    /// re-ranks properly (a truly-dead server fails its health check and drops out). Allocates a
    /// new `Arc<[usize]>` — demote is the cold error path, so this is acceptable.
    fn demote(&self, member: usize) {
        {
            let mut sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
            let mut v = sel.ranked.to_vec();
            if let Some(pos) = v.iter().position(|&i| i == member) {
                v.remove(pos);
                v.push(member);
                sel.ranked = v.into();
            }
        }
        self.reprobe.notify_one();
    }
}

#[async_trait]
impl Transport for SelectingTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let order = self.order();
        if order.is_empty() {
            return Err(io::Error::other("no healthy server in the pool"));
        }
        let mut last_err = None;
        for &i in order.iter() {
            match self.members[i].transport.dial(target).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    self.demote(i);
                    last_err = Some(e); // failover to next-best
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no healthy server in the pool")))
    }
}

#[async_trait]
impl UdpTransport for SelectingTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let order = self.order();
        if order.is_empty() {
            return Err(io::Error::other("no healthy server in the pool"));
        }
        let mut last_err = None;
        for &i in order.iter() {
            match self.members[i].udp.dial_udp(target).await {
                Ok(p) => return Ok(p),
                Err(e) => {
                    self.demote(i);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no healthy server in the pool")))
    }
}

impl Drop for SelectingTransport {
    fn drop(&mut self) {
        if let Some(h) = self.prober.lock().unwrap_or_else(|e| e.into_inner()).take() {
            h.abort();
        }
    }
}

/// Background prober: probe the pool (windowed), update the ranked selection (with hysteresis), then
/// wait `interval` (or until a demotion wakes it early) and repeat. Per-probe deadline = `interval`
/// capped at 10s so a slow server can't stall a whole round on a short interval.
async fn prober_loop(
    members: Arc<Vec<Member>>,
    selection: Arc<Mutex<Selection>>,
    reprobe: Arc<tokio::sync::Notify>,
    interval: std::time::Duration,
    window: usize,
) {
    use crate::transport::probe::probe;
    let per_probe = interval.min(std::time::Duration::from_secs(10));
    let mut measured = false;
    loop {
        let outcomes = flint_dial::probe_windowed(members.len(), window, |i| {
            // Clone the (cheap) Arc + CallbackUrl into the future so it borrows nothing from `members`.
            let transport = Arc::clone(&members[i].transport);
            let callback = members[i].callback.clone();
            async move { probe(&transport, &callback, per_probe).await }
        })
        .await;
        {
            let mut sel = selection.lock().unwrap_or_else(|e| e.into_inner());
            sel.ranked = if measured {
                next_order(&sel.ranked, &outcomes).into()
            } else {
                rank(&outcomes).into()
            };
        }
        measured = true;
        tracing::debug!(
            healthy = outcomes.iter().filter(|(_, o)| o.healthy).count(),
            pool = members.len(),
            "pool re-probed"
        );
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = reprobe.notified() => {}
        }
    }
}

/// How much lower a challenger's latency must be to displace the incumbent best (hysteresis).
const SWITCH_MARGIN: f64 = 0.20;

/// Healthy members, best (lowest latency) first; unhealthy dropped.
fn rank(outcomes: &[(usize, ProbeOutcome)]) -> Vec<usize> {
    let mut healthy: Vec<&(usize, ProbeOutcome)> =
        outcomes.iter().filter(|(_, o)| o.healthy).collect();
    healthy.sort_by_key(|(_, o)| o.latency);
    healthy.iter().map(|(i, _)| *i).collect()
}

/// New best-first order given the `current` order and a fresh probe round. The fresh ranking wins,
/// EXCEPT the incumbent best is kept in front unless a challenger is ≥ `SWITCH_MARGIN` lower latency
/// or the incumbent is no longer healthy — hysteresis against flapping between near-equal servers.
fn next_order(current: &[usize], fresh: &[(usize, ProbeOutcome)]) -> Vec<usize> {
    let ranked = rank(fresh);
    let incumbent = match current.first() {
        Some(i) => *i,
        None => return ranked, // nothing to keep
    };
    let incumbent_latency = fresh
        .iter()
        .find(|(i, _)| *i == incumbent)
        .filter(|(_, o)| o.healthy)
        .map(|(_, o)| o.latency);
    let challenger = ranked.first().copied();
    match (incumbent_latency, challenger) {
        (Some(inc), Some(ch)) if ch != incumbent => {
            let ch_latency = fresh
                .iter()
                .find(|(i, _)| *i == ch)
                .map(|(_, o)| o.latency)
                .unwrap_or(Duration::MAX);
            if ch_latency.as_secs_f64() <= inc.as_secs_f64() * (1.0 - SWITCH_MARGIN) {
                ranked // challenger is meaningfully better → adopt fresh order
            } else {
                // keep incumbent first, then the rest of the fresh order (minus the incumbent).
                let mut order = vec![incumbent];
                order.extend(ranked.into_iter().filter(|i| *i != incumbent));
                order
            }
        }
        (Some(_), _) => ranked, // incumbent is also the challenger (still best) → fresh order is fine
        (None, _) => ranked,    // incumbent unhealthy → adopt fresh order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Serve204;
    #[async_trait]
    impl Transport for Serve204 {
        async fn dial(&self, _t: SocketAddr) -> io::Result<BoxedStream> {
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut b = vec![0u8; 1024];
                let _ = server.read(&mut b).await;
                let _ = server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            });
            Ok(Box::new(client))
        }
    }
    fn member_serving_204() -> Member {
        Member {
            transport: Arc::new(Serve204),
            udp: Arc::new(NoUdp),
            // An IP literal keeps the test offline (no DNS lookup in `resolve_callback_addr`); the
            // probe does resolve hostnames, but the fake transport ignores the target regardless.
            callback: CallbackUrl {
                tls: false,
                host: "127.0.0.1".into(),
                port: 80,
                path: "/".into(),
            },
        }
    }

    #[tokio::test]
    async fn new_seeds_config_order_before_probing() {
        let st = SelectingTransport::new(
            vec![member(true), member(true)],
            std::time::Duration::from_secs(300),
            8,
        );
        assert_eq!(&*st.order(), &[0usize, 1][..]); // seeded synchronously; prober hasn't run yet
    }

    #[tokio::test]
    async fn new_probes_and_drops_unhealthy() {
        // 0 serves 204 (healthy), 1's dial fails (unhealthy). After the first probe round the prober
        // re-ranks to [0] (1 dropped).
        let members = vec![member_serving_204(), member(false)];
        let st = SelectingTransport::new(members, std::time::Duration::from_secs(300), 8);
        for _ in 0..100 {
            if st.order().as_ref() == [0usize].as_slice() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            &*st.order(),
            &[0usize][..],
            "prober should drop the unhealthy server"
        );
    }

    // A fake transport: dial always errors, or always yields a dummy stream.
    struct FakeT {
        ok: bool,
    }
    #[async_trait]
    impl Transport for FakeT {
        async fn dial(&self, _t: SocketAddr) -> io::Result<BoxedStream> {
            if self.ok {
                Ok(Box::new(tokio::io::duplex(16).0))
            } else {
                Err(io::Error::other("down"))
            }
        }
    }
    struct NoUdp;
    #[async_trait]
    impl UdpTransport for NoUdp {
        async fn dial_udp(
            &self,
            _t: SocketAddr,
        ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
            Err(io::Error::other("no udp"))
        }
    }
    fn member(ok: bool) -> Member {
        Member {
            transport: Arc::new(FakeT { ok }),
            udp: Arc::new(NoUdp),
            callback: CallbackUrl {
                tls: false,
                host: "h".into(),
                port: 80,
                path: "/".into(),
            },
        }
    }
    fn selecting(members: Vec<Member>, ranked: Vec<usize>) -> SelectingTransport {
        SelectingTransport {
            members: Arc::new(members),
            selection: Arc::new(Mutex::new(Selection {
                ranked: ranked.into(),
            })),
            reprobe: Arc::new(tokio::sync::Notify::new()),
            prober: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn dial_uses_best_then_fails_over() {
        let t = selecting(vec![member(false), member(true)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn dial_errors_when_no_healthy() {
        let t = selecting(vec![member(true)], vec![]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn dial_errors_when_all_down() {
        let t = selecting(vec![member(false), member(false)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn dial_demotes_a_failed_best() {
        // best (0) is down, 1 is up. After a dial, 0 should be demoted behind 1.
        let t = selecting(vec![member(false), member(true)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_ok()); // fails over 0→1
                                                                      // 0 was demoted to the back; the live order now leads with 1.
        assert_eq!(&*t.order(), &[1usize, 0][..]);
    }

    #[test]
    fn rank_orders_healthy_by_latency_and_drops_unhealthy() {
        use crate::transport::probe::ProbeOutcome;
        use std::time::Duration;
        let outs = vec![
            (
                0,
                ProbeOutcome {
                    latency: Duration::from_millis(80),
                    healthy: true,
                },
            ),
            (
                1,
                ProbeOutcome {
                    latency: Duration::MAX,
                    healthy: false,
                },
            ),
            (
                2,
                ProbeOutcome {
                    latency: Duration::from_millis(20),
                    healthy: true,
                },
            ),
        ];
        assert_eq!(rank(&outs), vec![2, 0]); // 20ms before 80ms; index 1 dropped
    }

    #[test]
    fn next_order_keeps_current_unless_challenger_is_20pct_better() {
        use crate::transport::probe::ProbeOutcome;
        use std::time::Duration;
        let current = vec![0];
        // index 0 = 100ms (current), index 2 = 90ms challenger: only 10% better → keep 0 first.
        let fresh = vec![
            (
                0,
                ProbeOutcome {
                    latency: Duration::from_millis(100),
                    healthy: true,
                },
            ),
            (
                2,
                ProbeOutcome {
                    latency: Duration::from_millis(90),
                    healthy: true,
                },
            ),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 0);
        // index 2 = 70ms: 30% better → it leads.
        let fresh = vec![
            (
                0,
                ProbeOutcome {
                    latency: Duration::from_millis(100),
                    healthy: true,
                },
            ),
            (
                2,
                ProbeOutcome {
                    latency: Duration::from_millis(70),
                    healthy: true,
                },
            ),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 2);
        // current became unhealthy → challenger leads regardless of margin.
        let fresh = vec![
            (
                0,
                ProbeOutcome {
                    latency: Duration::MAX,
                    healthy: false,
                },
            ),
            (
                2,
                ProbeOutcome {
                    latency: Duration::from_millis(99),
                    healthy: true,
                },
            ),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 2);
    }
}
