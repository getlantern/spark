//! Latency-selecting transport over a server pool (design: `docs/multi-server-selection-design.md`).
//! Implements `Transport`/`UdpTransport`; new flows use the current-best member; a background prober
//! (E3) re-ranks and swaps with failover + hysteresis. The current selection is read under a short
//! `std::sync::Mutex` (never held across `.await`).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::transport::probe::{CallbackUrl, ProbeOutcome};
use crate::transport::stall::{
    PacketSinkGuard, PacketSourceGuard, StallSink, StallTracker, StreamStallGuard,
};
use crate::transport::{
    Address, BoxedPacketSink, BoxedPacketSource, MemberStatus, PoolControl, ServerMeta, Transport,
    UdpTransport,
};
use crate::BoxedStream;

/// Liveness tunables captured from `TransportConfig` at pool build. Carries BOTH demotion signals:
/// the stall detector (`window`/`demote_*`, off by default) and the dial-failure breaker
/// (`dial_failure_*`, on by default). The quarantine cooldown/backoff/re-admission fields are shared
/// — they describe what happens after a demotion, independent of which signal caused it.
#[derive(Clone, Copy)]
pub(crate) struct StallConfig {
    pub(crate) window: std::time::Duration,
    pub(crate) demote_count: u32,
    pub(crate) demote_window: std::time::Duration,
    pub(crate) quarantine: std::time::Duration,
    pub(crate) quarantine_max: std::time::Duration,
    pub(crate) trial_flows: u32,
    pub(crate) dial_failure_count: u32,
    pub(crate) dial_failure_window: std::time::Duration,
}

impl StallConfig {
    pub(crate) fn enabled(&self) -> bool {
        !self.window.is_zero()
    }

    /// Whether the dial-failure breaker is armed. Independent of [`Self::enabled`]: the stall signal
    /// ships off (it infers trouble from quiet and false-positives), while an errored dial is a
    /// direct observation and needs no such caution.
    pub(crate) fn breaker_enabled(&self) -> bool {
        self.dial_failure_count > 0 && !self.dial_failure_window.is_zero()
    }
}

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

/// Per-member liveness state driven by stall reports (separate from the latency `Selection`).
#[derive(Clone)]
pub(crate) enum MemberState {
    Healthy,
    /// Quarantined until this instant; `strikes` counts consecutive quarantines (backoff).
    Quarantined {
        until: tokio::time::Instant,
        strikes: u32,
    },
    /// On trial: re-admitted, needs `clean_needed` clean flows to fully recover; `strikes` retained
    /// so a failed trial backs off further.
    OnTrial {
        clean_needed: u32,
        strikes: u32,
    },
}

struct MemberHealth {
    state: MemberState,
    /// Millis-since-pool-start of recent stalls (for the K-in-window count).
    recent_stalls: std::collections::VecDeque<u64>,
    /// Millis-since-pool-start of recent failed dials (for the breaker's K-in-window count). Also
    /// drives dial ordering: a member with any entry here is dialed after the clean ones.
    recent_dial_failures: std::collections::VecDeque<u64>,
}

impl MemberHealth {
    fn new() -> Self {
        Self {
            state: MemberState::Healthy,
            recent_stalls: std::collections::VecDeque::new(),
            recent_dial_failures: std::collections::VecDeque::new(),
        }
    }
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
    /// Bumped by [`Self::reload`] each time the member set is swapped. The prober captures it with
    /// its member snapshot and re-checks after probing: if it changed, a reload landed mid-round, so
    /// the prober discards its now-stale outcomes rather than writing them over the freshly-reset
    /// selection (which would leave latency/ranking pointing at the wrong generation of servers).
    epoch: Arc<AtomicU64>,
    reprobe: Arc<tokio::sync::Notify>,
    prober: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Fail-open fallback (issue #11; the product fail-open default, `docs/process-architecture-and-ipc.md`
    /// §5): when no pool member can serve a flow, dial through these directly so traffic degrades to
    /// a direct connection instead of blackholing. Built from the same `protect_interface` as the
    /// pool, so the direct dial still bypasses the tunnel route.
    direct_tcp: Arc<dyn Transport>,
    direct_udp: Arc<dyn UdpTransport>,
    /// Stall-detection tunables (zero window = disabled).
    stall: StallConfig,
    /// Per-member health state (stall accounting). LOCK ORDER: `health` is NEVER held at the same
    /// time as `selection` — `record_stall` locks only `health`; the dial path locks only
    /// `selection`. Keeping them separate avoids deadlock.
    /// `Arc` because the prober reads it too: the probe cannot observe establishment health on a
    /// connection-caching transport (its `dial` reuses the cached connection — hysteria2 probes come
    /// back at `dial_ms=0`), so real flow outcomes are the only evidence that a member can still serve
    /// a NEW flow, and the ranking/health verdict has to see them.
    health: Arc<Mutex<Vec<MemberHealth>>>,
    /// Epoch base for computing millis-since-pool-start in stall timestamps.
    health_base: tokio::time::Instant,
    /// Weak self-reference so the guard helpers can obtain an `Arc<Self>` for the `StallSink` impl
    /// without a reference cycle. Set by `build_selecting` immediately after `Arc::new`.
    pub(crate) me: std::sync::OnceLock<std::sync::Weak<Self>>,
}

impl SelectingTransport {
    /// Build a selecting transport over `members`, spawning a background prober. Must be called inside
    /// a tokio runtime (as `from_config`'s callers are). The prober runs an initial round immediately,
    /// then re-probes every `interval`; `window` bounds probe concurrency. `direct_tcp`/`direct_udp`
    /// are the fail-open fallback dialed when no member can serve a flow (see the struct doc).
    /// `stall` controls per-flow stall detection (zero window = disabled).
    pub(crate) fn new(
        members: Vec<Member>,
        interval: std::time::Duration,
        window: usize,
        direct_tcp: Arc<dyn Transport>,
        direct_udp: Arc<dyn UdpTransport>,
        stall: StallConfig,
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
        let epoch = Arc::new(AtomicU64::new(0));
        let health = Arc::new(Mutex::new((0..len).map(|_| MemberHealth::new()).collect()));
        let health_base = tokio::time::Instant::now();
        // Clamp to ≥1s so a misconfigured `probe_interval_secs = 0` can't spin the prober.
        let interval = interval.max(std::time::Duration::from_secs(1));
        let task = tokio::spawn(prober_loop(
            Arc::clone(&members),
            Arc::clone(&selection),
            Arc::clone(&epoch),
            Arc::clone(&reprobe),
            interval,
            window.max(1),
            Arc::clone(&health),
            health_base,
            stall,
        ));
        SelectingTransport {
            members,
            selection,
            epoch,
            reprobe,
            prober: Mutex::new(Some(task)),
            direct_tcp,
            direct_udp,
            stall,
            health,
            health_base,
            me: std::sync::OnceLock::new(),
        }
    }

    /// Obtain an `Arc<Self>` from the weak self-reference set by `build_selecting`. Returns `None`
    /// before `me` is initialised (only during `new`, before the `Arc` is constructed).
    fn arc(&self) -> Option<Arc<Self>> {
        self.me.get().and_then(|w| w.upgrade())
    }

    /// Wrap a member's TCP stream in a stall guard (no-op when disabled).
    fn guard_stream(self: &Arc<Self>, member: usize, s: BoxedStream) -> BoxedStream {
        if !self.stall.enabled() {
            return s;
        }
        let sink: Arc<dyn StallSink> = self.clone();
        let tracker = StallTracker::new(sink, member, self.stall.window);
        Box::new(StreamStallGuard::new(s, tracker, self.stall.window))
    }

    /// Wrap a member's datagram halves in stall guards (no-op when disabled).
    fn guard_udp(
        self: &Arc<Self>,
        member: usize,
        sink_half: BoxedPacketSink,
        source_half: BoxedPacketSource,
    ) -> (BoxedPacketSink, BoxedPacketSource) {
        if !self.stall.enabled() {
            return (sink_half, source_half);
        }
        let sink: Arc<dyn StallSink> = self.clone();
        let tracker = StallTracker::new(sink, member, self.stall.window);
        (
            Box::new(PacketSinkGuard::new(sink_half, tracker.clone())),
            Box::new(PacketSourceGuard::new(
                source_half,
                tracker,
                self.stall.window,
            )),
        )
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

    /// Indices currently excluded from new flows: quarantined members whose cooldown hasn't elapsed.
    /// Locks ONLY `health` — never call while the `selection` guard is alive.
    fn excluded(&self) -> std::collections::HashSet<usize> {
        let now = tokio::time::Instant::now();
        let health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        health
            .iter()
            .enumerate()
            .filter_map(|(i, h)| match h.state {
                MemberState::Quarantined { until, .. } if until > now => Some(i),
                _ => None,
            })
            .collect()
    }

    /// A **consistent** `(members, dial-order)` pair, read under a single `selection`-lock hold
    /// (selection → members order) so a racing [`Self::reload`] — which swaps both under the same
    /// lock — can't pair a new order with old members (or vice-versa) for one flow. The order is the
    /// pinned member first (if any), then the latency-ranked rest; on auto it's just the ranking.
    /// Quarantined members whose cooldown has elapsed are lazily promoted to `OnTrial` here.
    /// Quarantined members are filtered out AFTER the selection lock is released, then `health` is
    /// locked — the two locks are never held simultaneously. Neither lock is held across `.await`.
    /// Members that recently failed a dial are sunk behind the clean ones, then an `OnTrial` member
    /// (not excluded) is moved to the front so the next flow proves it first.
    /// `health` is locked in up to four short scopes (promotion, excluded, recently-failed,
    /// trial-position); the `selection` lock occupies one scope — NONE of these five scopes overlap.
    fn members_and_order(&self) -> (Arc<Vec<Member>>, Arc<[usize]>) {
        // 1. Promotion: lazily advance any elapsed quarantine to OnTrial (health lock only).
        {
            let now = tokio::time::Instant::now();
            let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
            for h in health.iter_mut() {
                if let MemberState::Quarantined { until, strikes } = h.state {
                    if until <= now {
                        h.state = MemberState::OnTrial {
                            clean_needed: self.stall.trial_flows,
                            strikes,
                        };
                    }
                }
            }
        } // health guard dropped here, before the selection block below.

        // 2. Scope the selection lock so it drops before we call excluded() (which locks health).
        let (members, order) = {
            let sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
            let members = self.members();
            let order: Arc<[usize]> = match sel.pinned {
                // Pin first, then the ranked rest (minus the pin). Even an unhealthy pin (not in
                // `ranked`) is tried first — the user chose it — then we fail over to healthy members.
                Some(p) if p < members.len() => {
                    let mut v = Vec::with_capacity(members.len());
                    v.push(p);
                    v.extend(sel.ranked.iter().copied().filter(|&i| i != p));
                    v.into()
                }
                _ => sel.ranked.clone(),
            };
            (members, order)
            // `sel` (selection guard) is dropped here — before excluded() below.
        };

        // 3. Lock only `health` now (selection guard already dropped above).
        let excluded = self.excluded();
        let order: Arc<[usize]> = if excluded.is_empty() {
            order
        } else {
            order
                .iter()
                .copied()
                .filter(|i| !excluded.contains(i))
                .collect()
        };

        // 4. Recent-success ordering: sink members that failed a dial inside the breaker's window
        //    behind the clean ones, preserving relative order within each group. This must live here
        //    rather than in the prober's `rank`: `demote` reorders `ranked` and then *wakes the
        //    prober*, which re-sorts on probe latency alone and puts the failing member straight back
        //    in front — a member whose probe callback succeeds while real dials time out would
        //    otherwise stay first choice indefinitely, with every new flow paying its dial timeout.
        //    Applied per-dial after `ranked` is read, so no re-probe can clobber it.
        // Intersect with `order` first: `recently_failed` spans every member, while `order` has already
        // had the quarantined ones filtered out, so comparing raw lengths could read "everything is
        // penalised" when a quarantined member made up the difference — leaving a penalised member
        // ahead of a clean one.
        let failed: std::collections::HashSet<usize> = self
            .recently_failed()
            .into_iter()
            .filter(|i| order.contains(i))
            .collect();
        let order: Arc<[usize]> = if failed.is_empty() || failed.len() == order.len() {
            order // nothing to sink, or everything is penalised → the existing order stands
        } else {
            let mut v = Vec::with_capacity(order.len());
            v.extend(order.iter().copied().filter(|i| !failed.contains(i)));
            v.extend(order.iter().copied().filter(|i| failed.contains(i)));
            v.into()
        };

        // 5. Trial routing: if any member is OnTrial (not excluded → present in order), lead the
        //    order with it so the next flow is handed to it for re-admission proof (health lock only;
        //    selection guard already dropped in step 2). Deliberately after step 4 — a trial exists
        //    precisely to re-test a member that failed, so it outranks the recent-failure penalty.
        let trial = {
            let health = self.health.lock().unwrap_or_else(|e| e.into_inner());
            health
                .iter()
                .position(|h| matches!(h.state, MemberState::OnTrial { .. }))
        };
        let order: Arc<[usize]> = match trial {
            Some(tm) if order.contains(&tm) => {
                let mut v = Vec::with_capacity(order.len());
                v.push(tm);
                v.extend(order.iter().copied().filter(|&i| i != tm));
                v.into()
            }
            _ => order,
        };

        (members, order)
    }

    /// Just the dial-order (see [`Self::members_and_order`]); test-only, since production dials take
    /// the paired `(members, order)` snapshot for consistency.
    #[cfg(test)]
    fn order(&self) -> Arc<[usize]> {
        self.members_and_order().1
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
    /// Quarantined members, and members whose recent real dials failed, are reported as unhealthy.
    /// `excluded()` / `recently_failed()` / `members_and_order()` are all called before the `selection`
    /// lock is taken so that `health` and `selection` are never held simultaneously.
    pub fn snapshot(&self) -> Vec<MemberStatus> {
        // All three lock only `health` (or take and release both), and run BEFORE the selection lock.
        let excluded = self.excluded();
        let failing = self.recently_failed();
        // `current` must be the member a flow would ACTUALLY dial first, which since the recent-failure
        // sink is no longer `ranked.first()` — reporting the ranking's head would name a member that
        // flows are now skipping.
        //
        // NOTE this is not a pure read: `members_and_order` lazily promotes an elapsed quarantine to
        // `OnTrial`. Harmless (the cooldown has genuinely elapsed, and the next dial would do it
        // anyway) but it means a UI poll can advance that transition a little sooner than flow traffic
        // would. Reimplementing the order here to avoid it would just risk the two drifting apart.
        //
        // The epoch is captured alongside it: `dial_first` indexes the generation live at this moment,
        // while `members` below is read under the selection lock and may be a NEWER one if a `reload`
        // lands in between. Comparing epochs detects exactly that, and we fall back to the ranking head
        // — which IS generation-consistent with `members`, being read under the same lock.
        let gen_before = self.epoch.load(Ordering::Relaxed);
        let dial_first = self.members_and_order().1.first().copied();
        // Read members under the selection lock (selection → members order) so a racing `reload`
        // can't pair one generation's members with another's ranking/latency.
        let sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        let members = self.members();
        // The member new flows dial first: the pin if valid, else the head of the real dial order —
        // falling back to the ranking head if a reload raced us, and range-checked either way so a
        // stale index can't silently leave every member `is_current: false`.
        let head = if self.epoch.load(Ordering::Relaxed) == gen_before {
            dial_first
        } else {
            sel.ranked.first().copied()
        };
        let current = match sel.pinned {
            Some(p) if p < members.len() => Some(p),
            _ => head.filter(|&i| i < members.len()),
        };
        (0..members.len())
            .map(|i| {
                let outcome = sel.latest.get(i).copied().flatten();
                let probe_healthy = outcome.map(|o| o.healthy).unwrap_or(false);
                MemberStatus {
                    index: i,
                    meta: members[i].meta.clone(),
                    protocol: members[i].protocol.clone(),
                    // Latency is only meaningful for a healthy probe (`latency` is `Duration::MAX`
                    // on failure), so report `None` unless healthy.
                    latency_ms: outcome
                        .filter(|o| o.healthy)
                        .map(|o| o.latency.as_millis() as u64),
                    // A quarantined member, or one whose recent real dials failed, is reported
                    // unhealthy even when the probe said otherwise — on a caching transport the probe
                    // reuses its connection and cannot see that establishment is broken, so believing
                    // it here is what made `healthy=5 pool=5` true while nothing could connect.
                    healthy: probe_healthy && !excluded.contains(&i) && !failing.contains(&i),
                    is_current: Some(i) == current,
                    // Reported separately from `is_current` on purpose: those coincide while a pin is
                    // set, but the UI needs to know WHY a member is current — "Selected Location" vs
                    // "Smart Location" — and it must learn that from here rather than from an index it
                    // remembered, which a config refresh silently repoints at another server.
                    is_pinned: sel.pinned == Some(i),
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
        // Take `selection` first, then read `members.len()` while holding it — uniform selection →
        // members lock order with reload/members_and_order/snapshot. (`self.members()` already
        // releases the members lock before returning, so there was no actual inversion, but keeping
        // the order uniform removes any doubt.)
        let mut sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = index {
            let len = self.members().len();
            if i >= len {
                tracing::warn!(index = i, pool = len, "set_pin ignored: index out of range");
                return false;
            }
        }
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
    ///
    /// Gated on `multi-server` — the only place members are rebuilt from config
    /// ([`crate::transport::build_members`]) is that feature.
    #[cfg(feature = "multi-server")]
    pub(crate) fn reload(&self, mut new_members: Vec<Member>) {
        // Hold `selection` for the WHOLE reload (selection → members order), so:
        //  - a concurrent set_pin/dial/snapshot sees either the pre- or post-reload state, never a
        //    torn mix, and the pin identity we preserve can't be clobbered by a set_pin racing
        //    between its capture and its re-apply;
        //  - the member swap + epoch bump happen together under the `members` lock, so the prober
        //    (which reads members + epoch under that same lock) can't pair one generation's members
        //    with another's epoch.
        // `old` is snapshotted under the lock and indexed with `.get()` for defence in depth.
        let mut sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        let old = self.members();
        // Prior best working proxy: the pin (if valid) else the ranked best; must be healthy. Keyed
        // by `label` (stable `"{protocol} {addr}"` server identity).
        let idx = sel
            .pinned
            .filter(|&p| p < old.len())
            .or_else(|| sel.ranked.first().copied());
        let prior = idx.and_then(|i| {
            let m = old.get(i)?;
            let oc = sel.latest.get(i).copied().flatten();
            match oc {
                Some(o) if o.healthy && !m.label.is_empty() => Some((m.clone(), o)),
                _ => None,
            }
        });
        // The current manual pin, captured by identity (`label`) so it can be re-applied afterwards —
        // pool indices are reshuffled by every refresh (a carried member is appended, and `ranked` is
        // rebuilt below), so an index is only meaningful within one generation.
        let pinned_member = sel
            .pinned
            .and_then(|p| old.get(p))
            .filter(|m| !m.label.is_empty())
            .cloned();
        let pinned_label = pinned_member.as_ref().map(|m| m.label.clone());
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
        // Keep the manual pin alive across the refresh **unconditionally** — including when the pinned
        // member is unhealthy, and when the refreshed config no longer lists it at all. The `prior`
        // carry above is for auto-mode continuity and so requires health; a pin is a user decision, and
        // dropping it reverts to auto with nothing saying so. That is the bug this fixes: the UI kept
        // showing a manual selection the core had already discarded.
        //
        // Pinning a member the config dropped is bounded, not open-ended: the dial-failure breaker
        // quarantines it after `dial_failure_count` failures and flows fail over, so a dead pin costs a
        // few timeouts rather than the connection.
        if let Some(m) = pinned_member {
            if !new_members.iter().any(|nm| nm.label == m.label) {
                new_members.push(m);
            }
        }
        let new_arc = Arc::new(new_members);
        let n = new_arc.len();
        // Swap members + bump the epoch atomically under the members lock, so the prober reads a
        // consistent (members, epoch) pair and a round that straddles this reload is discarded.
        {
            let mut m = self.members.lock().unwrap_or_else(|e| e.into_inner());
            *m = Arc::clone(&new_arc);
            self.epoch.fetch_add(1, Ordering::Relaxed);
        }
        // Reset the selection for the new pool: carried-best leads (continuity), then config order.
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
        // Re-resolve the pin to its INDEX in the new pool, by identity. The block above guarantees the
        // member is present, so this only ever yields `None` when there was no pin to begin with.
        sel.pinned = pinned_label.and_then(|lbl| new_arc.iter().position(|m| m.label == lbl));
        drop(sel);
        // Reset health to all-Healthy OUTSIDE the selection-locked region (sel already dropped
        // above) so health and selection are never held at the same time.
        *self.health.lock().unwrap_or_else(|e| e.into_inner()) =
            (0..n).map(|_| MemberHealth::new()).collect();
        tracing::info!(members = n, "pool reloaded from refreshed config");
        self.reprobe.notify_one();
    }

    /// Note a failed dial through `member`, tripping the breaker once it accumulates
    /// `dial_failure_count` failures inside `dial_failure_window`.
    ///
    /// Reuses the stall path's quarantine cooldown, exponential backoff and `OnTrial` re-admission —
    /// only what counts as a strike differs. It ships armed where the stall signal does not, because
    /// an errored dial is observed rather than inferred (see [`StallConfig::breaker_enabled`]).
    ///
    /// **Pool floor:** never quarantines the last non-quarantined member. An empty pool makes
    /// [`SelectingTransport::dial`] fail open to a *direct* dial, leaking the user's real IP — worse
    /// than a slow proxy. This is the guard whose absence took the stall signal out of service.
    fn record_dial_failure(&self, member: usize) {
        if !self.stall.breaker_enabled() {
            return;
        }
        let now = tokio::time::Instant::now();
        let now_ms = now.duration_since(self.health_base).as_millis() as u64;
        let window_ms = self.stall.dial_failure_window.as_millis() as u64;
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        // Count dialable members BEFORE the mutable borrow, for the pool-floor check below. Matches
        // `excluded()`'s definition exactly — a quarantined member whose cooldown has already elapsed
        // is still offered to flows (it is promoted to `OnTrial` lazily), so it counts as dialable.
        // Counting it as absent would hold the breaker off while the pool could in fact spare a member.
        let live = health
            .iter()
            .filter(|h| !matches!(h.state, MemberState::Quarantined { until, .. } if until > now))
            .count();
        let Some(h) = health.get_mut(member) else {
            return;
        };
        h.recent_dial_failures.push_back(now_ms);
        while let Some(&front) = h.recent_dial_failures.front() {
            if now_ms.saturating_sub(front) > window_ms {
                h.recent_dial_failures.pop_front();
            } else {
                break;
            }
        }
        if (h.recent_dial_failures.len() as u32) < self.stall.dial_failure_count {
            return;
        }
        if live <= 1 {
            // Hold the failing member in rotation — a bad proxy beats a real-IP leak. The history is
            // kept, so it trips as soon as some other member is dialable.
            //
            // Log only on the crossing, not on every later failure: because the history is retained,
            // an outage on a one-member pool would otherwise emit a warn per failed dial, burying the
            // signal it exists to give (window pruning can re-cross, so this is ~once per window).
            if h.recent_dial_failures.len() as u32 == self.stall.dial_failure_count {
                tracing::warn!(
                    member,
                    "dial-failure breaker held off: quarantining would empty the pool (fail-open to direct)"
                );
            }
            return;
        }
        let strikes = match h.state {
            MemberState::Quarantined { strikes, .. } | MemberState::OnTrial { strikes, .. } => {
                strikes
            }
            MemberState::Healthy => 0,
        };
        let n = strikes.saturating_add(1);
        let shift = (n - 1).min(16);
        let backoff = self
            .stall
            .quarantine
            .saturating_mul(1u32 << shift)
            .min(self.stall.quarantine_max);
        h.state = MemberState::Quarantined {
            until: now + backoff,
            strikes: n,
        };
        h.recent_dial_failures.clear();
        h.recent_stalls.clear();
        tracing::info!(
            member,
            strikes = n,
            backoff_secs = backoff.as_secs(),
            "pool member quarantined (dial failures)"
        );
    }

    /// Note a successful dial through `member`, clearing its dial-failure history so transient blips
    /// age out and stop penalising its dial order. Mirrors how a clean flow ages out stalls in
    /// [`StallSink::record_flow_ok`].
    fn record_dial_ok(&self, member: usize) {
        if !self.stall.breaker_enabled() {
            return;
        }
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = health.get_mut(member) {
            h.recent_dial_failures.clear();
        }
    }

    /// Members with a failed dial inside `dial_failure_window` — dialed only after the clean ones
    /// (see [`Self::members_and_order`]). Prunes nothing; stale entries are dropped on the next
    /// [`Self::record_dial_failure`], and a success clears them outright.
    ///
    /// Returns a `HashSet` (like [`Self::excluded`]) because the caller membership-tests it once per
    /// entry in the dial order, on every dial.
    fn recently_failed(&self) -> std::collections::HashSet<usize> {
        if !self.stall.breaker_enabled() {
            return std::collections::HashSet::new();
        }
        let health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        recently_failed_in(&health, self.health_base, self.stall.dial_failure_window)
    }

    /// Test-only: returns `true` if member `i` is currently quarantined.
    #[cfg(test)]
    pub(crate) fn is_quarantined(&self, i: usize) -> bool {
        matches!(
            self.health.lock().unwrap_or_else(|e| e.into_inner())[i].state,
            MemberState::Quarantined { .. }
        )
    }

    #[cfg(test)]
    pub(crate) fn member_state(&self, i: usize) -> MemberState {
        self.health.lock().unwrap_or_else(|e| e.into_inner())[i]
            .state
            .clone()
    }
}

impl StallSink for SelectingTransport {
    fn record_stall(&self, member: usize) {
        let now_ms = tokio::time::Instant::now()
            .duration_since(self.health_base)
            .as_millis() as u64;
        let window_ms = self.stall.demote_window.as_millis() as u64;
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        let Some(h) = health.get_mut(member) else {
            return;
        };
        h.recent_stalls.push_back(now_ms);
        while let Some(&front) = h.recent_stalls.front() {
            if now_ms.saturating_sub(front) > window_ms {
                h.recent_stalls.pop_front();
            } else {
                break;
            }
        }
        let strikes = match h.state {
            MemberState::Quarantined { strikes, .. } | MemberState::OnTrial { strikes, .. } => {
                strikes
            }
            MemberState::Healthy => 0,
        };
        let trial_stall = matches!(h.state, MemberState::OnTrial { .. });
        if trial_stall || h.recent_stalls.len() as u32 >= self.stall.demote_count {
            let n = strikes.saturating_add(1);
            let shift = (n - 1).min(16);
            let backoff = self
                .stall
                .quarantine
                .saturating_mul(1u32 << shift)
                .min(self.stall.quarantine_max);
            h.state = MemberState::Quarantined {
                until: tokio::time::Instant::now() + backoff,
                strikes: n,
            };
            h.recent_stalls.clear();
            tracing::info!(member, strikes = n, "pool member quarantined (stalls)");
        }
    }
    fn record_flow_ok(&self, member: usize) {
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        let Some(h) = health.get_mut(member) else {
            return;
        };
        match &mut h.state {
            MemberState::OnTrial { clean_needed, .. } => {
                *clean_needed = clean_needed.saturating_sub(1);
                if *clean_needed == 0 {
                    h.state = MemberState::Healthy;
                    h.recent_stalls.clear();
                    tracing::info!(member, "pool member restored after clean trial flows");
                }
            }
            // Outside trial, a clean flow ages out transient stalls.
            MemberState::Healthy => h.recent_stalls.clear(),
            MemberState::Quarantined { .. } => {}
        }
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

    /// Rebuild the pool from a refreshed config and hand the new members to [`Self::reload`] (which
    /// retains the best prior working proxy). Uses the same socket protector the initial pool used —
    /// derived from `config.transport.protect_interface`, which the fd-path re-applies to a fetched
    /// config before calling. Keeps the current pool (returns `Err`) if the refreshed set builds
    /// nothing. `multi-server`-only; without it the trait's no-op default applies.
    #[cfg(feature = "multi-server")]
    fn reload_from_config(&self, config: &crate::config::Config) -> std::io::Result<()> {
        let protector = match config.transport.protect_interface.as_deref() {
            Some(name) => Some(crate::transport::SocketProtector::for_interface(name)?),
            None => None,
        };
        let (members, skipped) = crate::transport::build_members(config, protector.as_ref());
        if members.is_empty() {
            return Err(std::io::Error::other(format!(
                "reload: no buildable pool members ({} skipped)",
                skipped.len()
            )));
        }
        self.reload(members);
        Ok(())
    }
}

#[async_trait]
impl Transport for SelectingTransport {
    /// Dial through the best-ranked pool member, failing over to the next on error. If no member
    /// can serve the flow — the pool is all-unhealthy (empty order) or every dial fails — **fail
    /// open to a direct dial** (loudly logged) so traffic degrades to a direct connection rather
    /// than blackholing (issue #11; arch doc §5 fail-open default).
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let (members, order) = self.members_and_order();
        for &i in order.iter() {
            // Consistent (members, order) pair from `members_and_order`; `.get` stays as a cheap
            // belt-and-suspenders guard.
            let Some(m) = members.get(i) else { continue };
            match m.transport.dial(target).await {
                Ok(s) => {
                    self.record_dial_ok(i);
                    return Ok(match self.arc() {
                        Some(me) => me.guard_stream(i, s),
                        None => s,
                    });
                }
                Err(e) => {
                    self.record_dial_failure(i);
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
        let (members, order) = self.members_and_order();
        let mut last_err = None;
        for &i in order.iter() {
            let Some(m) = members.get(i) else { continue };
            match m.transport.dial_addr(target.clone()).await {
                Ok(s) => {
                    self.record_dial_ok(i);
                    return Ok(match self.arc() {
                        Some(me) => me.guard_stream(i, s),
                        None => s,
                    });
                }
                Err(e) => {
                    // Don't demote a member that merely can't carry a domain target (`Unsupported`) —
                    // it's healthy for the IP-based retry path. Demote only on a real dial failure.
                    if e.kind() != io::ErrorKind::Unsupported {
                        self.record_dial_failure(i);
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
        let (members, order) = self.members_and_order();
        for &i in order.iter() {
            let Some(m) = members.get(i) else { continue };
            match m.udp.dial_udp(target).await {
                Ok(p) => {
                    self.record_dial_ok(i);
                    return Ok(match self.arc() {
                        Some(me) => me.guard_udp(i, p.0, p.1),
                        None => p,
                    });
                }
                Err(e) => {
                    self.record_dial_failure(i);
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
        let (members, order) = self.members_and_order();
        for &i in order.iter() {
            let Some(m) = members.get(i) else { continue };
            match m.udp.dial_udp_addr(target.clone()).await {
                Ok(p) => {
                    self.record_dial_ok(i);
                    return Ok(match self.arc() {
                        Some(me) => me.guard_udp(i, p.0, p.1),
                        None => p,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                    tracing::debug!(
                        member = i,
                        "pool member can't carry a UDP domain; trying next"
                    );
                }
                Err(e) => {
                    self.record_dial_failure(i);
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
#[allow(clippy::too_many_arguments)] // plumbing, not logic: every arg is a shared handle or a tunable
async fn prober_loop(
    members: Arc<Mutex<Arc<Vec<Member>>>>,
    selection: Arc<Mutex<Selection>>,
    epoch: Arc<AtomicU64>,
    reprobe: Arc<tokio::sync::Notify>,
    interval: std::time::Duration,
    window: usize,
    health: Arc<Mutex<Vec<MemberHealth>>>,
    health_base: tokio::time::Instant,
    stall: StallConfig,
) {
    use crate::transport::probe::probe;
    let per_probe = interval.min(std::time::Duration::from_secs(10));
    let mut measured = false;
    loop {
        // Snapshot the live member set + its generation for this round, both read under the members
        // lock so they're a consistent pair (reload swaps members + bumps the epoch under that same
        // lock). A `reload` mid-round is caught by the post-probe epoch re-check and re-probed
        // promptly (reload wakes us via `reprobe`).
        let (members, gen) = {
            let guard = members.lock().unwrap_or_else(|e| e.into_inner());
            (guard.clone(), epoch.load(Ordering::Relaxed))
        };
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
        // Real flow outcomes, read BEFORE the selection lock (the two are never held together). The
        // probe cannot see this for itself: on a connection-caching transport its `dial` reuses the
        // cached connection, so it reports healthy for a member that currently cannot establish a new
        // one — observed as `dial_ms=0` on every hysteria2 probe while that member's flows timed out.
        let failing = if stall.breaker_enabled() {
            let h = health.lock().unwrap_or_else(|e| e.into_inner());
            recently_failed_in(&h, health_base, stall.dial_failure_window)
        } else {
            std::collections::HashSet::new()
        };
        let mut applied = false;
        {
            let mut sel = selection.lock().unwrap_or_else(|e| e.into_inner());
            // Discard outcomes if a `reload` swapped the pool while we were probing — writing them
            // would clobber the reset selection with the wrong generation's latency/ranking. reload
            // queued a `reprobe`, so the wait below returns immediately and re-probes the new set.
            if epoch.load(Ordering::Relaxed) == gen {
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
                    next_order(&sel.ranked, &outcomes, &failing).into()
                } else {
                    rank(&outcomes, &failing).into()
                };
                measured = true;
                applied = true;
            } else {
                tracing::debug!("pool reloaded mid-probe; discarding stale-generation outcomes");
            }
        }
        // Only report on outcomes we actually applied. After a mid-round `reload` the indices in
        // `outcomes` belong to the previous pool generation, so logging them would name the wrong
        // members — and the contradiction below is a WARN, which is a bad place to be wrong.
        if !applied {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = reprobe.notified() => {}
            }
            continue;
        }
        let probe_healthy = outcomes.iter().filter(|(_, o)| o.healthy).count();
        // Members the probe called healthy while their real flows are failing. This contradiction is
        // the signature of a caching transport whose cached connection still works but whose
        // establishment path does not — and it is exactly what a `healthy=N pool=N` line hides.
        let contradicting: Vec<usize> = outcomes
            .iter()
            .filter(|(i, o)| o.healthy && failing.contains(i))
            .map(|(i, _)| *i)
            .collect();
        if !contradicting.is_empty() {
            tracing::warn!(
                members = ?contradicting,
                "probe reports healthy but recent dials failed — trusting flow outcomes and ranking these last"
            );
        }
        tracing::debug!(
            healthy = probe_healthy,
            failing = failing.len(),
            pool = members.len(),
            "pool re-probed"
        );
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = reprobe.notified() => {}
        }
    }
}

/// Members with a failed dial inside `window`. Shared by [`SelectingTransport::recently_failed`] (the
/// dial path) and the prober (ranking + the honest health count), so both read "recently failing" the
/// same way.
fn recently_failed_in(
    health: &[MemberHealth],
    base: tokio::time::Instant,
    window: Duration,
) -> std::collections::HashSet<usize> {
    let now_ms = tokio::time::Instant::now().duration_since(base).as_millis() as u64;
    let window_ms = window.as_millis() as u64;
    health
        .iter()
        .enumerate()
        .filter(|(_, h)| {
            h.recent_dial_failures
                .iter()
                .any(|&t| now_ms.saturating_sub(t) <= window_ms)
        })
        .map(|(i, _)| i)
        .collect()
}

/// How much lower a challenger's latency must be to displace the incumbent best (hysteresis).
const SWITCH_MARGIN: f64 = 0.20;

/// Healthy members, best (lowest latency) first; unhealthy dropped. Members in `failing` (a recent
/// real dial failure) sort **behind** every clean member regardless of probe latency — on a
/// connection-caching transport the probe reuses its cached connection and so reports a fast, healthy
/// result for a member that cannot currently establish a new one. Probe latency alone would keep
/// promoting it.
fn rank(
    outcomes: &[(usize, ProbeOutcome)],
    failing: &std::collections::HashSet<usize>,
) -> Vec<usize> {
    let mut healthy: Vec<&(usize, ProbeOutcome)> =
        outcomes.iter().filter(|(_, o)| o.healthy).collect();
    healthy.sort_by_key(|(i, o)| (failing.contains(i), o.latency));
    healthy.iter().map(|(i, _)| *i).collect()
}

/// New best-first order given the `current` order and a fresh probe round. The fresh ranking wins,
/// EXCEPT the incumbent best is kept in front unless a challenger is ≥ `SWITCH_MARGIN` lower latency
/// or the incumbent is no longer healthy — hysteresis against flapping between near-equal servers.
///
/// An incumbent in `failing` forfeits the hysteresis outright: keeping a member whose real dials are
/// failing in front — on the strength of a probe that reused its cached connection — is what let one
/// bad server stay first choice for 140 of 152 seconds.
fn next_order(
    current: &[usize],
    fresh: &[(usize, ProbeOutcome)],
    failing: &std::collections::HashSet<usize>,
) -> Vec<usize> {
    let ranked = rank(fresh, failing);
    let incumbent = match current.first() {
        Some(i) => *i,
        None => return ranked, // nothing to keep
    };
    if failing.contains(&incumbent) {
        return ranked; // no hysteresis for a member whose flows are failing
    }
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

    fn test_stall_cfg() -> StallConfig {
        StallConfig {
            window: std::time::Duration::from_secs(15),
            demote_count: 3,
            demote_window: std::time::Duration::from_secs(30),
            quarantine: std::time::Duration::from_secs(60),
            quarantine_max: std::time::Duration::from_secs(600),
            trial_flows: 2,
            dial_failure_count: 3,
            dial_failure_window: std::time::Duration::from_secs(30),
        }
    }

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
            test_stall_cfg(),
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
            test_stall_cfg(),
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
    #[cfg(feature = "multi-server")]
    fn member_labeled(ok: bool, meta: ServerMeta, label: &str) -> Member {
        member_with_meta(ok, meta).with_label(label.to_string())
    }
    // No member has a recent dial failure — the baseline for the pure ranking tests.
    fn no_failures() -> std::collections::HashSet<usize> {
        std::collections::HashSet::new()
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
    /// As [`selecting`], with an explicit liveness config (for exercising the breaker's own knobs).
    fn selecting_with_stall(
        members: Vec<Member>,
        ranked: Vec<usize>,
        stall: StallConfig,
    ) -> SelectingTransport {
        let mut t = selecting(members, ranked);
        t.stall = stall;
        t
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
            epoch: Arc::new(AtomicU64::new(0)),
            reprobe: Arc::new(tokio::sync::Notify::new()),
            prober: Mutex::new(None),
            direct_tcp,
            direct_udp,
            stall: test_stall_cfg(),
            health: Arc::new(Mutex::new((0..n).map(|_| MemberHealth::new()).collect())),
            health_base: tokio::time::Instant::now(),
            me: std::sync::OnceLock::new(),
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

    #[cfg(feature = "multi-server")]
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

    #[cfg(feature = "multi-server")]
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

    #[cfg(feature = "multi-server")]
    #[tokio::test]
    async fn reload_keeps_a_manual_pin_the_new_config_dropped() {
        // The reported bug: pick a server, a fresh config arrives without it, and the pin is silently
        // discarded — the pool reverts to auto while the UI still shows the old selection. Deliberately
        // give the pinned member NO probe outcome, so it is unhealthy and the `prior` continuity carry
        // (which requires health) cannot be what saves it.
        let t = selecting(
            vec![
                member_labeled(true, meta("picked", "SE"), "hysteria2 5.5.5.5:443"),
                member_labeled(true, meta("other", "US"), "samizdat 6.6.6.6:443"),
            ],
            vec![0, 1],
        );
        assert!(t.set_pin(Some(0)), "pin the first member");

        t.reload(vec![member_labeled(
            true,
            meta("brand-new", "JP"),
            "hysteria2 7.7.7.7:443",
        )]);

        let snap = t.snapshot();
        let pinned: Vec<_> = snap.iter().filter(|s| s.is_pinned).collect();
        assert_eq!(pinned.len(), 1, "exactly one member stays pinned");
        assert_eq!(
            pinned[0].meta.name.as_deref(),
            Some("picked"),
            "and it is the server the user chose, not whatever now sits at its old index"
        );
        assert!(
            pinned[0].is_current,
            "a pin is dialed first, so it is also current"
        );
        assert!(
            !snap
                .iter()
                .any(|s| s.meta.name.as_deref() == Some("brand-new") && s.is_pinned),
            "the new config's server must not inherit the pin"
        );
    }

    #[cfg(feature = "multi-server")]
    #[tokio::test]
    async fn reload_repoints_a_surviving_pin_at_its_new_index() {
        // The other half: indices are reshuffled by a refresh, so the pin must follow the SERVER, not
        // the slot. Here the picked server survives but moves from index 1 to index 0 — a UI that
        // cached "1" would name the wrong row, which is what made "Selected Location" wrong.
        let t = selecting(
            vec![
                member_labeled(true, meta("decoy", "US"), "samizdat 8.8.8.8:443"),
                member_labeled(true, meta("picked", "SE"), "hysteria2 5.5.5.5:443"),
            ],
            vec![0, 1],
        );
        assert!(t.set_pin(Some(1)));

        t.reload(vec![
            member_labeled(true, meta("picked", "SE"), "hysteria2 5.5.5.5:443"),
            member_labeled(true, meta("decoy", "US"), "samizdat 8.8.8.8:443"),
        ]);

        let snap = t.snapshot();
        let pinned: Vec<_> = snap.iter().filter(|s| s.is_pinned).collect();
        assert_eq!(pinned.len(), 1, "still exactly one pin");
        assert_eq!(
            pinned[0].meta.name.as_deref(),
            Some("picked"),
            "the pin followed the server across the index change"
        );
        assert_eq!(pinned[0].index, 0, "which now lives at index 0");
    }

    #[tokio::test]
    async fn no_member_is_pinned_on_auto() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        assert!(
            !t.snapshot().iter().any(|s| s.is_pinned),
            "auto means no manual pin, so the UI shows Smart Location"
        );
        assert!(t.set_pin(Some(1)));
        assert!(t.snapshot()[1].is_pinned, "pinning reports on that member");
        assert!(t.set_pin(None), "back to auto");
        assert!(
            !t.snapshot().iter().any(|s| s.is_pinned),
            "clearing the pin clears the flag"
        );
    }

    #[cfg(feature = "multi-server")]
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

    #[cfg(feature = "multi-server")]
    #[cfg(feature = "multi-server")]
    #[tokio::test]
    async fn reload_carries_pin_to_its_own_server_never_to_another() {
        // DELIBERATE CONTRACT CHANGE. This previously asserted the pin was DROPPED when the refreshed
        // config omitted the pinned server. Dropping it reverts the pool to auto with nothing saying so,
        // and the UI went on showing the old selection — the reported "Selected Location is wrong" bug.
        // The pin is now carried across the refresh instead.
        //
        // What has NOT changed, and is the real invariant here: the pin follows the SERVER, never the
        // slot. It must never land on a different server just because that server now occupies the old
        // index.
        let t = selecting(
            vec![
                member_labeled(true, meta("a", "US"), "samizdat 1.1.1.1:443"),
                member_labeled(true, meta("b", "GB"), "hysteria2 2.2.2.2:443"),
            ],
            vec![0, 1],
        );
        t.set_pin(Some(1)); // pin "b"
                            // Refresh drops "b" and offers only "c".
        t.reload(vec![member_labeled(
            true,
            meta("c", "DE"),
            "shadowsocks 3.3.3.3:443",
        )]);
        let snap = t.snapshot();
        let pinned: Vec<_> = snap.iter().filter(|s| s.is_pinned).collect();
        assert_eq!(pinned.len(), 1, "the pin survives the refresh");
        assert_eq!(
            pinned[0].meta.name.as_deref(),
            Some("b"),
            "carried to the server the user picked"
        );
        assert!(
            !snap
                .iter()
                .any(|s| s.meta.name.as_deref() == Some("c") && s.is_pinned),
            "and NEVER to the unrelated server that replaced it"
        );
    }

    #[cfg(feature = "multi-server")]
    #[tokio::test]
    async fn reload_from_config_rejects_empty_server_set() {
        // A refreshed config that builds no members must NOT wipe the live pool — keep the current
        // one and surface the error so the caller logs it (fd_tunnel keeps serving).
        let t = selecting(vec![member_with_meta(true, meta("live", "US"))], vec![0]);
        let cfg = crate::config::Config::default(); // no transport.servers
        assert!(
            PoolControl::reload_from_config(&t, &cfg).is_err(),
            "empty refreshed server set is rejected"
        );
        assert_eq!(t.snapshot().len(), 1, "current pool is preserved");
    }

    #[tokio::test(start_paused = true)]
    async fn member_quarantines_after_k_stalls() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        // Below threshold: 2 stalls (default K=3) → still healthy.
        StallSink::record_stall(&t, 0);
        StallSink::record_stall(&t, 0);
        assert!(!t.is_quarantined(0));
        StallSink::record_stall(&t, 0); // 3rd within window → quarantined
        assert!(t.is_quarantined(0));
        assert!(!t.is_quarantined(1), "other member unaffected");
    }

    #[tokio::test(start_paused = true)]
    async fn quarantined_member_excluded_from_order() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        assert!(t.is_quarantined(0));
        let (_members, order) = t.members_and_order();
        assert!(
            !order.contains(&0),
            "quarantined member is not offered to new flows"
        );
        assert!(order.contains(&1));
    }

    #[cfg(feature = "multi-server")]
    #[tokio::test(start_paused = true)]
    async fn reload_clears_quarantine() {
        let t = selecting(vec![member_with_meta(true, meta("a", "US"))], vec![0]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        assert!(t.is_quarantined(0));
        t.reload(vec![member_with_meta(true, meta("a2", "US"))]);
        assert!(!t.is_quarantined(0), "reload resets member health");
    }

    #[tokio::test(start_paused = true)]
    async fn quarantine_elapses_to_trial_and_offers_flows() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        // Before cooldown: excluded.
        assert!(!t.members_and_order().1.contains(&0));
        // After the 60s base cooldown: member 0 goes on trial and is offered the next flow first.
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let (_m, order) = t.members_and_order();
        assert_eq!(
            order.first().copied(),
            Some(0),
            "trial member gets the next flow"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn trial_restores_after_clean_flows() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order(); // promotes to OnTrial (clean_needed = 2)
        StallSink::record_flow_ok(&t, 0);
        StallSink::record_flow_ok(&t, 0); // 2 clean trial flows → restored
        assert!(matches!(t.member_state(0), MemberState::Healthy));
    }

    #[tokio::test(start_paused = true)]
    async fn trial_stall_requarantines_with_backoff() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order(); // OnTrial, strikes = 1
        StallSink::record_stall(&t, 0); // a trial-flow stall → re-quarantine (strikes = 2)
        assert!(t.is_quarantined(0));
        // Backoff doubled: still quarantined after the first 60s cooldown, cleared only after ~120s.
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order();
        assert!(
            t.is_quarantined(0),
            "second-strike cooldown is ~120s, not 60s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn breaker_quarantines_after_k_dial_failures() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        t.record_dial_failure(0);
        t.record_dial_failure(0);
        assert!(!t.is_quarantined(0), "below the K=3 threshold");
        t.record_dial_failure(0);
        assert!(t.is_quarantined(0), "3rd failure inside the window trips");
        assert!(!t.is_quarantined(1), "other member unaffected");
    }

    #[tokio::test(start_paused = true)]
    async fn breaker_ages_failures_out_of_the_window() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        t.record_dial_failure(0);
        t.record_dial_failure(0);
        // Past the 30s window, the first two no longer count toward the threshold.
        tokio::time::advance(std::time::Duration::from_secs(31)).await;
        t.record_dial_failure(0);
        assert!(!t.is_quarantined(0), "stale failures must not accumulate");
    }

    #[tokio::test(start_paused = true)]
    async fn breaker_pool_floor_never_empties_the_pool() {
        // A one-member pool: quarantining it would leave `dial` no member and fail open to a DIRECT
        // dial, leaking the user's real IP. A failing proxy is the lesser evil, so the breaker holds.
        let t = selecting(vec![member(true)], vec![0]);
        for _ in 0..10 {
            t.record_dial_failure(0);
        }
        assert!(
            !t.is_quarantined(0),
            "last dialable member must stay in rotation"
        );
        assert!(
            t.members_and_order().1.contains(&0),
            "and must still be offered to flows"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn breaker_trips_once_a_second_member_is_available() {
        // The floor is about the pool's state, not a permanent exemption: the retained history trips
        // as soon as quarantining no longer empties the pool.
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 1); // park member 1 so only member 0 is dialable
        }
        assert!(t.is_quarantined(1));
        for _ in 0..3 {
            t.record_dial_failure(0);
        }
        assert!(!t.is_quarantined(0), "held off while it is the last member");
        // Member 1's cooldown elapses → it becomes dialable again, so member 0 may now be parked.
        // The 61s wait also ages the failures above out of the 30s window (as it should), so the
        // breaker is re-armed by fresh failures rather than stale ones.
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order(); // lazily promotes member 1 to OnTrial
        for _ in 0..3 {
            t.record_dial_failure(0);
        }
        assert!(t.is_quarantined(0), "trips once the pool can spare it");
    }

    #[tokio::test(start_paused = true)]
    async fn successful_dial_clears_failure_history() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        t.record_dial_failure(0);
        t.record_dial_failure(0);
        t.record_dial_ok(0); // a good dial ages out the transient failures
        t.record_dial_failure(0);
        t.record_dial_failure(0);
        assert!(
            !t.is_quarantined(0),
            "a success resets the count, so 2 more must not trip"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn recently_failed_member_is_dialed_last() {
        // The regression this exists for: a member whose probe callback succeeds while real dials
        // time out used to stay first choice, because `demote` woke the prober and the prober
        // re-sorted on probe latency alone. The order must reflect real dial outcomes.
        let t = selecting(
            vec![member(true), member(true), member(true)],
            vec![0, 1, 2],
        );
        t.record_dial_failure(0); // one failure: below the breaker threshold, still penalised
        assert!(!t.is_quarantined(0));
        let order = t.members_and_order().1;
        assert_eq!(
            order.to_vec(),
            vec![1, 2, 0],
            "penalised member sinks to the back, clean members keep their relative order"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn all_members_penalised_keeps_the_existing_order() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        t.record_dial_failure(0);
        t.record_dial_failure(1);
        assert_eq!(
            t.members_and_order().1.to_vec(),
            vec![0, 1],
            "nothing to gain from reordering when every member is penalised"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn trial_member_outranks_the_recent_failure_penalty() {
        // A trial exists precisely to re-test a member that failed, so it must lead the order even
        // though it carries a recent failure (ordering step 5 runs after step 4).
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order(); // promotes member 0 to OnTrial
        t.record_dial_failure(0);
        assert_eq!(
            t.members_and_order().1.first().copied(),
            Some(0),
            "trial routing wins over the penalty"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pool_floor_counts_elapsed_quarantine_as_dialable() {
        // A quarantined member whose cooldown has elapsed is still offered to flows, so the pool can
        // spare the failing one — the floor must not treat it as absent and hold the breaker off.
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 1);
        }
        assert!(t.is_quarantined(1));
        tokio::time::advance(std::time::Duration::from_secs(61)).await; // cooldown elapses
        for _ in 0..3 {
            t.record_dial_failure(0);
        }
        assert!(
            t.is_quarantined(0),
            "member 1 is dialable again (pending lazy promotion), so member 0 may be parked"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn penalty_ignores_quarantined_members_when_counting() {
        // `recently_failed` spans all members but `order` excludes quarantined ones. A penalised
        // member plus a quarantined one must not read as "everything is penalised" and skip the sink.
        let t = selecting(
            vec![member(true), member(true), member(true)],
            vec![0, 1, 2],
        );
        for _ in 0..3 {
            t.record_dial_failure(2); // member 2 → quarantined, and carries failure history
        }
        assert!(t.is_quarantined(2));
        t.record_dial_failure(0); // member 0 → penalised but healthy
        assert_eq!(
            t.members_and_order().1.to_vec(),
            vec![1, 0],
            "member 2 is excluded; member 0 still sinks behind the clean member 1"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn breaker_off_when_count_is_zero() {
        let mut cfg = test_stall_cfg();
        cfg.dial_failure_count = 0;
        let t = selecting_with_stall(vec![member(true), member(true)], vec![0, 1], cfg);
        for _ in 0..10 {
            t.record_dial_failure(0);
        }
        assert!(!t.is_quarantined(0), "breaker disabled by config");
        assert_eq!(
            t.members_and_order().1.to_vec(),
            vec![0, 1],
            "and no ordering penalty is applied"
        );
    }

    #[test]
    fn rank_sinks_a_failing_member_despite_the_best_probe_latency() {
        // The regression in one assertion: member 0 has the FASTEST probe (because a caching transport
        // reuses its connection, so the probe measures nothing about establishment) while its real
        // dials are failing. Latency alone would rank it first.
        let outs = vec![
            (
                0,
                ProbeOutcome {
                    latency: Duration::from_millis(5),
                    healthy: true,
                },
            ),
            (
                1,
                ProbeOutcome {
                    latency: Duration::from_millis(200),
                    healthy: true,
                },
            ),
        ];
        let failing: std::collections::HashSet<usize> = [0].into_iter().collect();
        assert_eq!(
            rank(&outs, &failing),
            vec![1, 0],
            "flow outcomes outweigh probe latency"
        );
        assert_eq!(
            rank(&outs, &no_failures()),
            vec![0, 1],
            "and without failures, latency decides"
        );
    }

    #[test]
    fn failing_incumbent_forfeits_hysteresis() {
        // Hysteresis normally keeps the incumbent in front unless a challenger is 20% faster. A
        // failing incumbent must lose it outright, or a 5ms-probe member that cannot connect stays
        // first choice forever.
        let current = vec![0, 1];
        let fresh = vec![
            (
                0,
                ProbeOutcome {
                    latency: Duration::from_millis(100),
                    healthy: true,
                },
            ),
            (
                1,
                ProbeOutcome {
                    latency: Duration::from_millis(95),
                    healthy: true,
                },
            ),
        ];
        assert_eq!(
            next_order(&current, &fresh, &no_failures())[0],
            0,
            "95ms is not 20% better, so the incumbent keeps the lead"
        );
        let failing: std::collections::HashSet<usize> = [0].into_iter().collect();
        assert_eq!(
            next_order(&current, &fresh, &failing)[0],
            1,
            "but a failing incumbent yields immediately"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_reports_a_failing_member_unhealthy_and_names_the_real_current() {
        // `healthy=5 pool=5` while nothing could connect was true only because health came from the
        // probe alone. A member with recent dial failures must read unhealthy, and `is_current` must
        // name the member flows actually dial first — not the head of the latency ranking.
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        {
            let mut sel = t.selection.lock().unwrap();
            sel.latest = vec![
                Some(ProbeOutcome {
                    latency: Duration::from_millis(5),
                    healthy: true,
                }),
                Some(ProbeOutcome {
                    latency: Duration::from_millis(200),
                    healthy: true,
                }),
            ];
        }
        assert!(
            t.snapshot()[0].healthy,
            "clean member 0 starts healthy and current"
        );
        assert!(t.snapshot()[0].is_current);

        t.record_dial_failure(0); // one failure: penalised, still below the breaker threshold
        let snap = t.snapshot();
        assert!(
            !snap[0].healthy,
            "probe said healthy; the failed dial overrides it"
        );
        assert!(snap[1].healthy);
        assert!(!snap[0].is_current, "flows no longer dial member 0 first");
        assert!(snap[1].is_current, "so the snapshot must name member 1");
    }

    #[tokio::test(start_paused = true)]
    async fn breaker_off_when_window_is_zero() {
        // A zero window disables the breaker just as a zero count does — `breaker_enabled` requires
        // both, and the config docs promise it.
        let mut cfg = test_stall_cfg();
        cfg.dial_failure_window = std::time::Duration::ZERO;
        let t = selecting_with_stall(vec![member(true), member(true)], vec![0, 1], cfg);
        for _ in 0..10 {
            t.record_dial_failure(0);
        }
        assert!(!t.is_quarantined(0), "zero window disables the breaker");
        assert_eq!(t.members_and_order().1.to_vec(), vec![0, 1]);
    }

    #[cfg(feature = "multi-server")]
    #[tokio::test]
    async fn members_and_order_pair_is_consistent_after_reload() {
        // The dial-path invariant: the (members, order) pair is from one generation, so every order
        // index is valid for the paired members snapshot (no stale new-order-vs-old-members panic).
        let t = selecting(
            vec![
                member_with_meta(true, meta("a", "US")),
                member_with_meta(true, meta("b", "GB")),
            ],
            vec![0, 1],
        );
        t.reload(vec![member_with_meta(true, meta("c", "DE"))]);
        let (members, order) = t.members_and_order();
        assert_eq!(members.len(), 1, "members reflect the reloaded set");
        assert!(
            order.iter().all(|&i| i < members.len()),
            "every dial-order index is in range for the paired members"
        );
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
        assert_eq!(rank(&outs, &no_failures()), vec![2, 0]); // 20ms before 80ms; index 1 dropped
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
        assert_eq!(next_order(&current, &fresh, &no_failures())[0], 0);
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
        assert_eq!(next_order(&current, &fresh, &no_failures())[0], 2);
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
        assert_eq!(next_order(&current, &fresh, &no_failures())[0], 2);
    }
}
