//! Latency-selecting transport over a server pool (design: `docs/multi-server-selection-design.md`).
//! Implements `Transport`/`UdpTransport`; new flows use the current-best member; a background prober
//! (E3) re-ranks and swaps with failover + hysteresis. The current selection is read under a short
//! `std::sync::Mutex` (never held across `.await`).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::transport::probe::CallbackUrl;
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
}
