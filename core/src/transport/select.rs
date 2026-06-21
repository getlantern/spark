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

/// Ranked selection: indices into the pool, best-first; empty = nothing healthy.
#[derive(Default)]
struct Selection {
    ranked: Vec<usize>,
}

/// A latency-selecting transport over a pool of [`Member`]s.
pub struct SelectingTransport {
    members: Arc<Vec<Member>>,
    selection: Arc<Mutex<Selection>>,
    prober: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SelectingTransport {
    /// Current best-first order (snapshot; lock not held across `.await`).
    fn order(&self) -> Vec<usize> {
        self.selection.lock().expect("selection mutex").ranked.clone()
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
        for i in order {
            match self.members[i].transport.dial(target).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e), // failover to next-best
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no healthy server in the pool")))
    }
}

#[async_trait]
impl UdpTransport for SelectingTransport {
    async fn dial_udp(&self, target: SocketAddr) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let order = self.order();
        if order.is_empty() {
            return Err(io::Error::other("no healthy server in the pool"));
        }
        let mut last_err = None;
        for i in order {
            match self.members[i].udp.dial_udp(target).await {
                Ok(p) => return Ok(p),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no healthy server in the pool")))
    }
}

impl Drop for SelectingTransport {
    fn drop(&mut self) {
        if let Some(h) = self.prober.lock().expect("prober mutex").take() {
            h.abort();
        }
    }
}

/// How much lower a challenger's latency must be to displace the incumbent best (hysteresis).
const SWITCH_MARGIN: f64 = 0.20;

/// Healthy members, best (lowest latency) first; unhealthy dropped.
fn rank(outcomes: &[(usize, ProbeOutcome)]) -> Vec<usize> {
    let mut healthy: Vec<&(usize, ProbeOutcome)> = outcomes.iter().filter(|(_, o)| o.healthy).collect();
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

    // A fake transport: dial always errors, or always yields a dummy stream.
    struct FakeT { ok: bool }
    #[async_trait]
    impl Transport for FakeT {
        async fn dial(&self, _t: SocketAddr) -> io::Result<BoxedStream> {
            if self.ok { Ok(Box::new(tokio::io::duplex(16).0)) } else { Err(io::Error::other("down")) }
        }
    }
    struct NoUdp;
    #[async_trait]
    impl UdpTransport for NoUdp {
        async fn dial_udp(&self, _t: SocketAddr) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
            Err(io::Error::other("no udp"))
        }
    }
    fn member(ok: bool) -> Member {
        Member {
            transport: Arc::new(FakeT { ok }),
            udp: Arc::new(NoUdp),
            callback: CallbackUrl { tls: false, host: "h".into(), port: 80, path: "/".into() },
        }
    }
    fn selecting(members: Vec<Member>, ranked: Vec<usize>) -> SelectingTransport {
        SelectingTransport {
            members: Arc::new(members),
            selection: Arc::new(Mutex::new(Selection { ranked })),
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

    #[test]
    fn rank_orders_healthy_by_latency_and_drops_unhealthy() {
        use crate::transport::probe::ProbeOutcome;
        use std::time::Duration;
        let outs = vec![
            (0, ProbeOutcome { latency: Duration::from_millis(80), healthy: true }),
            (1, ProbeOutcome { latency: Duration::MAX, healthy: false }),
            (2, ProbeOutcome { latency: Duration::from_millis(20), healthy: true }),
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
            (0, ProbeOutcome { latency: Duration::from_millis(100), healthy: true }),
            (2, ProbeOutcome { latency: Duration::from_millis(90), healthy: true }),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 0);
        // index 2 = 70ms: 30% better → it leads.
        let fresh = vec![
            (0, ProbeOutcome { latency: Duration::from_millis(100), healthy: true }),
            (2, ProbeOutcome { latency: Duration::from_millis(70), healthy: true }),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 2);
        // current became unhealthy → challenger leads regardless of margin.
        let fresh = vec![
            (0, ProbeOutcome { latency: Duration::MAX, healthy: false }),
            (2, ProbeOutcome { latency: Duration::from_millis(99), healthy: true }),
        ];
        assert_eq!(next_order(&current, &fresh)[0], 2);
    }
}
