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
use crate::transport::{
    Address, BoxedPacketSink, BoxedPacketSource, MemberStatus, PoolControl, ServerMeta, Transport,
    UdpTransport,
};
use crate::BoxedStream;

/// A built pool member: its transport pair, the callback URL used to probe it, and UI metadata.
/// `Clone` is cheap — the transports are `Arc`s — and lets [`SelectingTransport::reload`] carry a
/// proven member across a live config swap.
#[derive(Clone)]
pub(crate) struct Member {
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) udp: Arc<dyn UdpTransport>,
    pub(crate) callback: CallbackUrl,
    pub(crate) meta: ServerMeta,
    /// Human label for probe/diagnostic logs: `"{protocol} {server-addr}"` (e.g.
    /// `samizdat 161.33.223.26:31464`). Set by the builder; empty for the bare `new` used in tests.
    pub(crate) label: String,
    /// Transport protocol kind for the UI (e.g. `"hysteria2"`). Set by the builder; empty for the
    /// bare `new` used in tests.
    pub(crate) protocol: String,
}

impl Member {
    pub(crate) fn new(
        transport: Arc<dyn Transport>,
        udp: Arc<dyn UdpTransport>,
        callback: CallbackUrl,
        meta: ServerMeta,
    ) -> Self {
        Member {
            transport,
            udp,
            callback,
            meta,
            label: String::new(),
            protocol: String::new(),
        }
    }

    /// Set the diagnostic label (builder-style), used by `build_member`.
    pub(crate) fn with_label(mut self, label: String) -> Self {
        self.label = label;
        self
    }

    /// Set the UI protocol kind (builder-style), used by `build_member`.
    pub(crate) fn with_protocol(mut self, protocol: String) -> Self {
        self.protocol = protocol;
        self
    }
}

/// Ranked selection plus the state `snapshot()`/`set_pin()` read, all under one mutex.
#[derive(Default)]
struct Selection {
    /// Indices into the pool, best (lowest latency) first; empty = nothing healthy.
    ranked: Arc<[usize]>,
    /// Latest probe outcome per member index (len == pool size once the first round runs); `None`
    /// before a member has been measured. Drives the latency/health columns in `snapshot()`.
    latest: Vec<Option<ProbeOutcome>>,
    /// Manual pin: when `Some(i)`, new flows dial member `i` first regardless of latency ranking
    /// (the user chose it); `None` = auto (follow `ranked`). See [`SelectingTransport::set_pin`].
    pinned: Option<usize>,
}

/// A latency-selecting transport over a pool of [`Member`]s.
///
/// When no member can serve a flow (the pool is all-unhealthy, or every dial in the current order
/// fails), the transport **fails open to direct** rather than erroring — see [`Self::dial`].
pub struct SelectingTransport {
    /// The live member list. Wrapped in a mutex-guarded `Arc` so [`Self::reload`] can atomically
    /// swap in a refreshed set (new flows/probes pick it up) without disturbing in-flight dials —
    /// mirrors the `selection` mutex discipline (short lock, never held across `.await`). Readers
    /// take a cheap `Arc` clone via [`Self::members`].
    members: Arc<Mutex<Arc<Vec<Member>>>>,
    selection: Arc<Mutex<Selection>>,
    reprobe: Arc<tokio::sync::Notify>,
    prober: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Fail-open fallback (issue #11; the product fail-open default, `docs/process-architecture-and-ipc.md`
    /// §5): when no pool member can serve a flow, dial through these directly so traffic degrades to
    /// a direct connection instead of blackholing. Built from the same `protect_interface` as the
    /// pool, so the direct dial still bypasses the tunnel route.
    direct_tcp: Arc<dyn Transport>,
    direct_udp: Arc<dyn UdpTransport>,
}

impl SelectingTransport {
    /// Build a selecting transport over `members`, spawning a background prober. Must be called inside
    /// a tokio runtime (as `from_config`'s callers are). The prober runs an initial round immediately,
    /// then re-probes every `interval`; `window` bounds probe concurrency. `direct_tcp`/`direct_udp`
    /// are the fail-open fallback dialed when no member can serve a flow (see the struct doc).
    pub(crate) fn new(
        members: Vec<Member>,
        interval: std::time::Duration,
        window: usize,
        direct_tcp: Arc<dyn Transport>,
        direct_udp: Arc<dyn UdpTransport>,
    ) -> Self {
        let len = members.len();
        let members = Arc::new(Mutex::new(Arc::new(members)));
        // Seed with config order so flows can dial (with failover) before the first probe round;
        // without it, startup flows would fail open to direct (below) before the pool ever got a
        // chance to prove itself.
        let seeded: Arc<[usize]> = (0..len).collect();
        let selection = Arc::new(Mutex::new(Selection {
            ranked: seeded,
            latest: vec![None; len],
            pinned: None,
        }));
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
            direct_tcp,
            direct_udp,
        }
    }

    /// A cheap snapshot of the current member list (short lock, never held across `.await`). Callers
    /// index it with `.get(i)` because a concurrent [`Self::reload`] may have shrunk the pool since
    /// the `selection` indices were computed.
    fn members(&self) -> Arc<Vec<Member>> {
        self.members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The order in which `dial` tries members for a new flow: the pinned member first (if any),
    /// then the latency-ranked rest. On auto (no pin) this is just the ranked order. Snapshot; the
    /// lock is never held across `.await`. The common (unpinned) path returns a cheap `Arc` clone.
    fn order(&self) -> Arc<[usize]> {
        let len = self.members().len();
        let sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        match sel.pinned {
            // Pin first, then the ranked rest (minus the pin). Even an unhealthy pin (not in
            // `ranked`) is tried first — the user chose it — then we fail over to healthy members.
            Some(p) if p < len => {
                let mut v = Vec::with_capacity(len);
                v.push(p);
                v.extend(sel.ranked.iter().copied().filter(|&i| i != p));
                v.into()
            }
            _ => sel.ranked.clone(),
        }
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

    /// A point-in-time view of every pool member — metadata, last-probe latency/health, and which
    /// one new flows currently dial first — for the server-selection UI. Reads the live state under
    /// the short selection lock (never across `.await`); ordered by pool index (the UI groups/sorts).
    pub fn snapshot(&self) -> Vec<MemberStatus> {
        let members = self.members();
        let sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        // The member new flows dial first: the pin if valid, else the latency-ranked best.
        let current = match sel.pinned {
            Some(p) if p < members.len() => Some(p),
            _ => sel.ranked.first().copied(),
        };
        (0..members.len())
            .map(|i| {
                let outcome = sel.latest.get(i).copied().flatten();
                MemberStatus {
                    index: i,
                    meta: members[i].meta.clone(),
                    protocol: members[i].protocol.clone(),
                    // Latency is only meaningful for a healthy probe (`latency` is `Duration::MAX`
                    // on failure), so report `None` unless healthy.
                    latency_ms: outcome
                        .filter(|o| o.healthy)
                        .map(|o| o.latency.as_millis() as u64),
                    healthy: outcome.map(|o| o.healthy).unwrap_or(false),
                    is_current: Some(i) == current,
                }
            })
            .collect()
    }

    /// Manually pin which member new flows dial first: `Some(index)` overrides the latency ranking
    /// (the user's explicit choice), `None` returns to auto (latency-ranked). Out-of-range indices
    /// are ignored (logged) so a stale UI handle can't silently flip the pool to auto. Takes effect
    /// for **new** flows; in-flight connections are unaffected.
    ///
    /// Returns `true` when the pin was applied (auto, or a valid index) and `false` when an
    /// out-of-range index was ignored — so the FFI/UI layer can distinguish a real pin from a no-op
    /// instead of always reporting success.
    pub fn set_pin(&self, index: Option<usize>) -> bool {
        if let Some(i) = index {
            let len = self.members().len();
            if i >= len {
                tracing::warn!(index = i, pool = len, "set_pin ignored: index out of range");
                return false;
            }
        }
        let mut sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        sel.pinned = index;
        tracing::debug!(?index, "server selection pin updated");
        true
    }

    /// Live-replace the pool's members with `new_members` (built from a refreshed config), so new
    /// servers are probed and surfaced without a reconnect. Retains the **best prior working proxy**
    /// so traffic never gaps while the new set is measured: the current best *healthy* member (the
    /// pin if valid, else the latency-ranked best) is identified by its `label` (a stable
    /// `"{protocol} {addr}"` server identity); if the refreshed config dropped it, its `Member` is
    /// carried over as a fallback. That member is seeded first in the ranking with its last-good
    /// outcome so it stays "current" until the immediate re-probe re-ranks (hysteresis lets a clearly
    /// better new server take over; an unhealthy carried member drops out on the next round). A
    /// manual pin is preserved by identity only if that exact server survives the refresh.
    pub(crate) fn reload(&self, mut new_members: Vec<Member>) {
        let old = self.members();
        // Prior best working proxy + the manual pin's identity, read together under the selection lock.
        let (prior, pinned_label) = {
            let sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
            let idx = sel
                .pinned
                .filter(|&p| p < old.len())
                .or_else(|| sel.ranked.first().copied());
            let prior = idx.and_then(|i| {
                let oc = sel.latest.get(i).copied().flatten();
                match oc {
                    Some(o) if o.healthy && !old[i].label.is_empty() => Some((old[i].clone(), o)),
                    _ => None,
                }
            });
            let pinned_label = sel
                .pinned
                .and_then(|p| old.get(p))
                .map(|m| m.label.clone())
                .filter(|l| !l.is_empty());
            (prior, pinned_label)
        };
        // Carry the proven server over if the refreshed config no longer lists it.
        let mut carried: Option<(usize, ProbeOutcome)> = None;
        if let Some((m, oc)) = prior {
            match new_members
                .iter()
                .position(|nm| !nm.label.is_empty() && nm.label == m.label)
            {
                Some(pos) => carried = Some((pos, oc)),
                None => {
                    new_members.push(m);
                    carried = Some((new_members.len() - 1, oc));
                }
            }
        }
        let new_arc = Arc::new(new_members);
        let n = new_arc.len();
        {
            // selection → members lock order (the only site holding both), matching all readers.
            let mut sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
            *self.members.lock().unwrap_or_else(|e| e.into_inner()) = Arc::clone(&new_arc);
            // Carried-best leads (continuity), then the rest in config order.
            let mut ranked = Vec::with_capacity(n);
            if let Some((ci, _)) = carried {
                ranked.push(ci);
            }
            ranked.extend((0..n).filter(|&i| carried.map(|(ci, _)| ci) != Some(i)));
            sel.ranked = ranked.into();
            sel.latest = vec![None; n];
            if let Some((ci, oc)) = carried {
                sel.latest[ci] = Some(oc);
            }
            // Keep the manual pin only if that exact server survived the refresh.
            sel.pinned = pinned_label.and_then(|lbl| new_arc.iter().position(|m| m.label == lbl));
        }
        tracing::info!(members = n, "pool reloaded from refreshed config");
        self.reprobe.notify_one();
    }
}

/// The dyn-dispatched control surface the fd-path tunnel registers for the platform FFI. Delegates
/// to the inherent methods (disambiguated by the explicit `SelectingTransport::` path so the trait
/// method doesn't recurse into itself).
impl PoolControl for SelectingTransport {
    fn snapshot(&self) -> Vec<MemberStatus> {
        SelectingTransport::snapshot(self)
    }
    fn set_pin(&self, index: Option<usize>) -> bool {
        SelectingTransport::set_pin(self, index)
    }
}

#[async_trait]
impl Transport for SelectingTransport {
    /// Dial through the best-ranked pool member, failing over to the next on error. If no member
    /// can serve the flow — the pool is all-unhealthy (empty order) or every dial fails — **fail
    /// open to a direct dial** (loudly logged) so traffic degrades to a direct connection rather
    /// than blackholing (issue #11; arch doc §5 fail-open default).
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let members = self.members();
        let order = self.order();
        for &i in order.iter() {
            // Bounds-guard: a concurrent `reload` may have shrunk the pool since `order` was read.
            let Some(m) = members.get(i) else { continue };
            match m.transport.dial(target).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    self.demote(i);
                    tracing::debug!(member = i, error = %e, "pool member dial failed; failing over");
                }
            }
        }
        tracing::warn!(
            %target,
            pool = members.len(),
            "no pool member could serve the flow; failing open to a direct dial"
        );
        self.direct_tcp.dial(target).await
    }

    async fn dial_addr(&self, target: Address) -> io::Result<BoxedStream> {
        let members = self.members();
        let order = self.order();
        let mut last_err = None;
        for &i in order.iter() {
            let Some(m) = members.get(i) else { continue };
            match m.transport.dial_addr(target.clone()).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    // Don't demote a member that merely can't carry a domain target (`Unsupported`) —
                    // it's healthy for the IP-based retry path. Demote only on a real dial failure.
                    if e.kind() != io::ErrorKind::Unsupported {
                        self.demote(i);
                    }
                    tracing::debug!(member = i, error = %e, "pool member dial_addr failed; failing over");
                    last_err = Some(e);
                }
            }
        }
        // Fail open to a direct dial only for an IP target. A domain can't be direct-dialed here
        // (the recovered name has no address yet), so surface the error — the forwarder then resolves
        // it client-side and retries by IP.
        match target {
            Address::Ip(sa) => {
                tracing::warn!(
                    %sa,
                    pool = members.len(),
                    "no pool member could serve the flow; failing open to a direct dial"
                );
                self.direct_tcp.dial(sa).await
            }
            Address::Domain { host, port } => Err(last_err.unwrap_or_else(|| {
                io::Error::other(format!("no pool member could serve {host}:{port}"))
            })),
        }
    }
}

#[async_trait]
impl UdpTransport for SelectingTransport {
    /// UDP counterpart of [`SelectingTransport::dial`], with the same fail-open-to-direct floor.
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let members = self.members();
        let order = self.order();
        for &i in order.iter() {
            let Some(m) = members.get(i) else { continue };
            match m.udp.dial_udp(target).await {
                Ok(p) => return Ok(p),
                Err(e) => {
                    self.demote(i);
                    tracing::debug!(member = i, error = %e, "pool member udp dial failed; failing over");
                }
            }
        }
        tracing::warn!(
            %target,
            pool = members.len(),
            "no pool member could serve the udp flow; failing open to a direct dial"
        );
        self.direct_udp.dial_udp(target).await
    }

    /// UDP dial-by-name counterpart. A member that can't carry a UDP domain (`Unsupported`) is
    /// skipped without demotion (mirrors [`dial_addr`]); a real failure demotes + fails over. If no
    /// member can carry the name, fall through to direct — which returns `Unsupported` for a domain,
    /// letting the UDP forwarder resolve client-side.
    async fn dial_udp_addr(
        &self,
        target: Address,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let members = self.members();
        let order = self.order();
        for &i in order.iter() {
            let Some(m) = members.get(i) else { continue };
            match m.udp.dial_udp_addr(target.clone()).await {
                Ok(p) => return Ok(p),
                Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                    tracing::debug!(
                        member = i,
                        "pool member can't carry a UDP domain; trying next"
                    );
                }
                Err(e) => {
                    self.demote(i);
                    tracing::debug!(member = i, error = %e, "pool member udp dial_udp_addr failed; failing over");
                }
            }
        }
        self.direct_udp.dial_udp_addr(target).await
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
    members: Arc<Mutex<Arc<Vec<Member>>>>,
    selection: Arc<Mutex<Selection>>,
    reprobe: Arc<tokio::sync::Notify>,
    interval: std::time::Duration,
    window: usize,
) {
    use crate::transport::probe::probe;
    let per_probe = interval.min(std::time::Duration::from_secs(10));
    let mut measured = false;
    loop {
        // Snapshot the live member set for this round. A `reload` mid-round is picked up on the next
        // round (and wakes us early via `reprobe`), so a refreshed pool is probed promptly.
        let members = members.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let outcomes = flint_dial::probe_windowed(members.len(), window, |i| {
            // Clone the (cheap) Arc + CallbackUrl into the future so it borrows nothing from `members`.
            let transport = Arc::clone(&members[i].transport);
            let callback = members[i].callback.clone();
            // Identify the member in probe logs by protocol + server addr (e.g.
            // `samizdat 161.33.223.26:31464`), falling back to the index, so a mixed-protocol pool's
            // failures are attributable to a specific server.
            let label = if members[i].label.is_empty() {
                format!("#{i}")
            } else {
                members[i].label.clone()
            };
            async move { probe(&transport, &callback, per_probe, &label).await }
        })
        .await;
        {
            let mut sel = selection.lock().unwrap_or_else(|e| e.into_inner());
            // Record the latest per-member outcome for `snapshot()` before re-ranking.
            if sel.latest.len() != members.len() {
                sel.latest = vec![None; members.len()];
            }
            for (i, o) in &outcomes {
                if let Some(slot) = sel.latest.get_mut(*i) {
                    *slot = Some(*o);
                }
            }
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
    use crate::transport::{PacketSink, PacketSource};

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
            meta: ServerMeta::default(),
            label: String::new(),
            protocol: String::new(),
        }
    }

    #[tokio::test]
    async fn new_seeds_config_order_before_probing() {
        let st = SelectingTransport::new(
            vec![member(true), member(true)],
            std::time::Duration::from_secs(300),
            8,
            Arc::new(FakeT { ok: true }),
            Arc::new(NoUdp),
        );
        assert_eq!(&*st.order(), &[0usize, 1][..]); // seeded synchronously; prober hasn't run yet
    }

    #[tokio::test]
    async fn new_probes_and_drops_unhealthy() {
        // 0 serves 204 (healthy), 1's dial fails (unhealthy). After the first probe round the prober
        // re-ranks to [0] (1 dropped).
        let members = vec![member_serving_204(), member(false)];
        // Short interval so the per-probe deadline (min(interval, 10s)) is small, and poll against a
        // generous 10s wall-clock deadline — comfortably longer than a probe round even on a slow,
        // loaded CI runner (the probes are in-memory and finish in ms; the budget just can't be
        // tighter than the round, which the old 1s budget was — that flaked on windows-latest).
        let st = SelectingTransport::new(
            members,
            std::time::Duration::from_secs(1),
            8,
            Arc::new(FakeT { ok: true }),
            Arc::new(NoUdp),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while st.order().as_ref() != [0usize].as_slice() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            &*st.order(),
            &[0usize][..],
            "prober should drop the unhealthy server within 10s"
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
    // A UDP transport whose dial always succeeds with no-op sink/source halves — used as the
    // fail-open direct fallback in the UDP tests.
    struct OkUdp;
    #[async_trait]
    impl UdpTransport for OkUdp {
        async fn dial_udp(
            &self,
            _t: SocketAddr,
        ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
            Ok((Box::new(NopSink), Box::new(NopSource)))
        }
    }
    struct NopSink;
    #[async_trait]
    impl PacketSink for NopSink {
        async fn send(&mut self, _payload: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }
    struct NopSource;
    #[async_trait]
    impl PacketSource for NopSource {
        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    fn member(ok: bool) -> Member {
        member_with_meta(ok, ServerMeta::default())
    }
    fn member_with_meta(ok: bool, meta: ServerMeta) -> Member {
        Member {
            transport: Arc::new(FakeT { ok }),
            udp: Arc::new(NoUdp),
            callback: CallbackUrl {
                tls: false,
                host: "h".into(),
                port: 80,
                path: "/".into(),
            },
            meta,
            label: String::new(),
            protocol: String::new(),
        }
    }
    fn meta(name: &str, cc: &str) -> ServerMeta {
        ServerMeta {
            name: Some(name.into()),
            country_code: Some(cc.into()),
            ..Default::default()
        }
    }
    // A member with a stable `label` server-identity (what `reload` matches on to retain/dedup).
    fn member_labeled(ok: bool, meta: ServerMeta, label: &str) -> Member {
        member_with_meta(ok, meta).with_label(label.to_string())
    }
    // A selecting transport with a healthy direct fallback (TCP + UDP both succeed), so the tests
    // that exercise fail-open observe a successful direct dial.
    fn selecting(members: Vec<Member>, ranked: Vec<usize>) -> SelectingTransport {
        selecting_with_direct(
            members,
            ranked,
            Arc::new(FakeT { ok: true }),
            Arc::new(OkUdp),
        )
    }
    fn selecting_with_direct(
        members: Vec<Member>,
        ranked: Vec<usize>,
        direct_tcp: Arc<dyn Transport>,
        direct_udp: Arc<dyn UdpTransport>,
    ) -> SelectingTransport {
        let n = members.len();
        SelectingTransport {
            members: Arc::new(Mutex::new(Arc::new(members))),
            selection: Arc::new(Mutex::new(Selection {
                ranked: ranked.into(),
                latest: vec![None; n],
                pinned: None,
            })),
            reprobe: Arc::new(tokio::sync::Notify::new()),
            prober: Mutex::new(None),
            direct_tcp,
            direct_udp,
        }
    }

    #[tokio::test]
    async fn dial_uses_best_then_fails_over() {
        let t = selecting(vec![member(false), member(true)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn dial_falls_open_to_direct_when_no_healthy() {
        // Empty ranking (no healthy pool member) → fail open to the direct fallback rather than
        // erroring (issue #11).
        let t = selecting(vec![member(true)], vec![]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn dial_falls_open_to_direct_when_all_down() {
        // Every pool member's dial fails → fail open to the direct fallback.
        let t = selecting(vec![member(false), member(false)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn dial_errors_when_pool_and_direct_both_fail() {
        // Pool all-down AND the direct fallback also fails → the error surfaces. Fail-open must not
        // manufacture a false success when even a direct dial can't connect.
        let t = selecting_with_direct(
            vec![member(false)],
            vec![0],
            Arc::new(FakeT { ok: false }),
            Arc::new(NoUdp),
        );
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn dial_udp_falls_open_to_direct_when_all_down() {
        // member's UDP (NoUdp) errors → fail open to the direct UDP fallback (OkUdp).
        let t = selecting(vec![member(false)], vec![0]);
        assert!(t.dial_udp("1.2.3.4:80".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn dial_demotes_a_failed_best() {
        // best (0) is down, 1 is up. After a dial, 0 should be demoted behind 1.
        let t = selecting(vec![member(false), member(true)], vec![0, 1]);
        assert!(t.dial("1.2.3.4:80".parse().unwrap()).await.is_ok()); // fails over 0→1
                                                                      // 0 was demoted to the back; the live order now leads with 1.
        assert_eq!(&*t.order(), &[1usize, 0][..]);
    }

    #[tokio::test]
    async fn set_pin_overrides_then_releases_dial_order() {
        // Auto order leads with the ranked best (1). Pinning 0 puts it first; unpinning restores auto.
        let t = selecting(vec![member(true), member(true)], vec![1, 0]);
        assert_eq!(&*t.order(), &[1usize, 0][..], "auto follows the ranking");
        assert!(t.set_pin(Some(0)), "valid pin reports applied");
        assert_eq!(
            &*t.order(),
            &[0usize, 1][..],
            "pin leads, ranked rest follows"
        );
        assert!(t.set_pin(None), "unpin (auto) reports applied");
        assert_eq!(&*t.order(), &[1usize, 0][..], "unpin returns to auto");
    }

    #[tokio::test]
    async fn set_pin_ignores_out_of_range() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        assert!(
            !t.set_pin(Some(99)), // no such member → ignored, reports not-applied
            "out-of-range pin reports failure, not a silent success"
        );
        assert_eq!(&*t.order(), &[0usize, 1][..]);
        assert!(t.snapshot()[0].is_current, "still on the ranked best");
    }

    #[tokio::test]
    async fn snapshot_reports_metadata_latency_health_and_current() {
        let t = selecting(
            vec![
                member_with_meta(true, meta("sfo3", "US")),
                member_with_meta(true, meta("lon1", "GB")),
            ],
            vec![0, 1],
        );
        // Seed the latest probe outcomes the prober would normally record.
        {
            let mut sel = t.selection.lock().unwrap();
            sel.latest = vec![
                Some(ProbeOutcome {
                    latency: Duration::from_millis(20),
                    healthy: true,
                }),
                Some(ProbeOutcome {
                    latency: Duration::MAX,
                    healthy: false,
                }),
            ];
        }
        let snap = t.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].meta.name.as_deref(), Some("sfo3"));
        assert_eq!(snap[0].meta.country_code.as_deref(), Some("US"));
        assert_eq!(snap[0].latency_ms, Some(20));
        assert!(snap[0].healthy);
        assert!(snap[0].is_current, "ranked best is current on auto");
        // Unhealthy member: latency is suppressed (Duration::MAX is not a real measurement).
        assert_eq!(snap[1].latency_ms, None);
        assert!(!snap[1].healthy);
        assert!(!snap[1].is_current);
    }

    #[tokio::test]
    async fn snapshot_is_current_follows_pin() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        t.set_pin(Some(1));
        let snap = t.snapshot();
        assert!(!snap[0].is_current);
        assert!(snap[1].is_current, "the pinned member is current");
    }

    #[tokio::test]
    async fn reload_replaces_members() {
        let t = selecting(vec![member_with_meta(true, meta("old", "US"))], vec![0]);
        t.reload(vec![
            member_with_meta(true, meta("newA", "GB")),
            member_with_meta(true, meta("newB", "DE")),
        ]);
        let snap = t.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].meta.name.as_deref(), Some("newA"));
        assert_eq!(snap[1].meta.name.as_deref(), Some("newB"));
    }

    #[tokio::test]
    async fn reload_keeps_best_prior_working_proxy() {
        // A healthy, labeled incumbent that the refreshed config omits must be carried over.
        let t = selecting(
            vec![member_labeled(
                true,
                meta("keep", "US"),
                "samizdat 1.1.1.1:443",
            )],
            vec![0],
        );
        {
            let mut sel = t.selection.lock().unwrap();
            sel.latest = vec![Some(ProbeOutcome {
                latency: Duration::from_millis(30),
                healthy: true,
            })];
        }
        t.reload(vec![member_labeled(
            true,
            meta("fresh", "GB"),
            "hysteria2 2.2.2.2:443",
        )]);
        let snap = t.snapshot();
        let kept = snap
            .iter()
            .find(|s| s.meta.name.as_deref() == Some("keep"))
            .expect("proven server carried over");
        assert!(
            kept.is_current,
            "carried best leads new flows until re-probe"
        );
        assert!(kept.healthy, "carried best keeps its last-good health");
        assert_eq!(kept.latency_ms, Some(30), "and its last-good latency");
    }

    #[tokio::test]
    async fn reload_dedups_retained_best_when_present() {
        // When the refreshed config still lists the prior best, don't duplicate it.
        let t = selecting(
            vec![member_labeled(
                true,
                meta("keep", "US"),
                "samizdat 1.1.1.1:443",
            )],
            vec![0],
        );
        {
            let mut sel = t.selection.lock().unwrap();
            sel.latest = vec![Some(ProbeOutcome {
                latency: Duration::from_millis(30),
                healthy: true,
            })];
        }
        t.reload(vec![
            member_labeled(true, meta("keep", "US"), "samizdat 1.1.1.1:443"),
            member_labeled(true, meta("fresh", "GB"), "hysteria2 2.2.2.2:443"),
        ]);
        let snap = t.snapshot();
        assert_eq!(snap.len(), 2, "no duplicate of the retained server");
        assert_eq!(snap[0].meta.name.as_deref(), Some("keep"));
        assert!(snap[0].is_current, "retained best still leads");
    }

    #[tokio::test]
    async fn reload_drops_pin_when_server_gone() {
        // A manual pin is preserved by identity only if that exact server survives the refresh.
        let t = selecting(
            vec![
                member_labeled(true, meta("a", "US"), "samizdat 1.1.1.1:443"),
                member_labeled(true, meta("b", "GB"), "hysteria2 2.2.2.2:443"),
            ],
            vec![0, 1],
        );
        t.set_pin(Some(1)); // pin "b"
                            // Refresh drops "b"; only "c" remains. The pin must not carry to a different server.
        t.reload(vec![member_labeled(
            true,
            meta("c", "DE"),
            "shadowsocks 3.3.3.3:443",
        )]);
        let sel = t.selection.lock().unwrap();
        assert_eq!(sel.pinned, None, "pin dropped: the pinned server is gone");
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
