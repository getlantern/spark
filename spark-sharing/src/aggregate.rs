use std::collections::{BTreeMap, BTreeSet};

use lantern_unbounded::supervisor::{PoolEvent, SupervisorEvent};

use crate::geo::Geo;

#[derive(Debug, Clone, PartialEq)]
pub struct PeerView {
    pub session_id: String,
    pub geo: Option<Geo>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SharingStatus {
    pub helping_now: usize,
    pub peers: Vec<PeerView>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SharingDelta {
    Joined(PeerView),
    Left(String),
}

/// Folds the per-slot supervisor event stream into a live per-session view.
#[derive(Default)]
pub struct Aggregator {
    /// Live relays keyed by `(slot, session_id)`.
    ///
    /// Keying on `session_id` alone is wrong: it is the *consumer's* stable id, shared across all of
    /// its concurrent paths (upstream `concurrent_sessions` defaults to 5), so one consumer can hold
    /// several of this volunteer's slots at once. Keyed by session alone, the second slot's connect
    /// was swallowed as a duplicate and then the *first* slot's disconnect dropped the peer entirely
    /// while other slots were still relaying — under-reporting `helping_now`, clearing the globe arc
    /// early, and double-counting the consumer when it reconnected. [`Aggregator::status`] groups back
    /// to one entry per session, so a consumer on three slots is still displayed once.
    live: BTreeMap<(usize, String), Option<Geo>>,
    /// Every session id seen this run, so `sessions_this_run` counts a consumer once no matter how
    /// many slots it occupies or how often it reconnects.
    seen: BTreeSet<String>,
    sessions_this_run: u64,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one pool event; returns a delta the caller should act on (bump the
    /// persisted counter on `Joined`, re-emit the snapshot on either), or `None`.
    pub fn apply(&mut self, ev: PoolEvent) -> Option<SharingDelta> {
        let slot = ev.slot;
        match ev.event {
            SupervisorEvent::PeerConnected { session_id, .. } => {
                self.connect(slot, session_id, None)
            }
            SupervisorEvent::PeerDisconnected { session_id } => self.disconnect(slot, session_id),
            _ => None,
        }
    }

    /// Record a relay on `slot` for `session_id`. Emits `Joined` only when this is the session's
    /// FIRST live slot — a consumer spreading over several slots is one peer to the UI.
    fn connect(
        &mut self,
        slot: usize,
        session_id: String,
        geo: Option<Geo>,
    ) -> Option<SharingDelta> {
        let key = (slot, session_id.clone());
        if self.live.contains_key(&key) {
            return None; // same slot re-announced
        }
        let first_live_slot = !self.session_is_live(&session_id);
        self.live.insert(key, geo.clone());
        // Count a consumer once per run, however many slots it uses or times it reconnects.
        if self.seen.insert(session_id.clone()) {
            self.sessions_this_run += 1;
        }
        if first_live_slot {
            Some(SharingDelta::Joined(PeerView { session_id, geo }))
        } else {
            None
        }
    }

    /// Release `slot`'s relay for `session_id`. Emits `Left` only once the session's LAST slot is
    /// gone, so one path dropping doesn't clear a consumer that other slots still serve.
    fn disconnect(&mut self, slot: usize, session_id: String) -> Option<SharingDelta> {
        // `?`: unknown (slot, session) — nothing to release.
        self.live.remove(&(slot, session_id.clone()))?;
        if self.session_is_live(&session_id) {
            return None; // still relaying on another slot
        }
        Some(SharingDelta::Left(session_id))
    }

    /// Whether any slot currently holds a relay for `session_id` (slot count is tiny — upstream
    /// `concurrent_sessions` — so the scan is cheaper than a second index).
    fn session_is_live(&self, session_id: &str) -> bool {
        self.live.keys().any(|(_, id)| id == session_id)
    }

    /// Like [`Aggregator::apply`], but resolves peer geolocation before emitting a
    /// `Joined` delta. Used by the plugin's aggregation loop; the sync [`Aggregator::apply`]
    /// stays for pure unit tests.
    pub async fn apply_with_geo(
        &mut self,
        ev: PoolEvent,
        resolver: &crate::geo::GeoResolver,
    ) -> Option<SharingDelta> {
        let slot = ev.slot;
        match ev.event {
            SupervisorEvent::PeerConnected { session_id, remote } => {
                // Skip the lookup entirely when this slot is already recorded, so a re-announce
                // can't spend a network round trip on the event loop's critical path.
                if self.live.contains_key(&(slot, session_id.clone())) {
                    return None;
                }
                let geo = match remote {
                    Some(addr) => resolver.resolve(addr.ip()).await,
                    None => None,
                };
                self.connect(slot, session_id, geo)
            }
            SupervisorEvent::PeerDisconnected { session_id } => self.disconnect(slot, session_id),
            _ => None,
        }
    }

    pub fn status(&self) -> SharingStatus {
        // Group the per-slot entries back to one per consumer, in a deterministic (session-id) order.
        // Order matters: the globe colours arcs by list position, so a `HashMap`'s per-call ordering
        // made existing arcs change colour on every poll.
        let mut by_session: BTreeMap<&str, Option<Geo>> = BTreeMap::new();
        for ((_, id), geo) in &self.live {
            let entry = by_session.entry(id.as_str()).or_insert_with(|| geo.clone());
            // Prefer a resolved location: slots serve the same consumer, but a later slot's lookup
            // may have failed where an earlier one succeeded.
            if entry.is_none() {
                *entry = geo.clone();
            }
        }
        let peers: Vec<PeerView> = by_session
            .into_iter()
            .map(|(id, geo)| PeerView {
                session_id: id.to_string(),
                geo,
            })
            .collect();
        SharingStatus {
            helping_now: peers.len(),
            peers,
        }
    }

    pub fn sessions_this_run(&self) -> u64 {
        self.sessions_this_run
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_unbounded::supervisor::{PoolEvent, SupervisorEvent};

    fn joined(id: &str) -> PoolEvent {
        PoolEvent {
            slot: 0,
            event: SupervisorEvent::PeerConnected {
                session_id: id.into(),
                remote: None,
            },
        }
    }
    fn left(id: &str) -> PoolEvent {
        PoolEvent {
            slot: 0,
            event: SupervisorEvent::PeerDisconnected {
                session_id: id.into(),
            },
        }
    }

    #[test]
    fn helping_now_refcounts_by_session_and_dedups() {
        let mut agg = Aggregator::new();
        assert_eq!(
            agg.apply(joined("a")),
            Some(SharingDelta::Joined(PeerView {
                session_id: "a".into(),
                geo: None
            }))
        );
        // duplicate connect for the same session is ignored (no delta, no double count)
        assert_eq!(agg.apply(joined("a")), None);
        assert!(agg.apply(joined("b")).is_some());
        assert_eq!(agg.status().helping_now, 2);
        assert_eq!(agg.apply(left("a")), Some(SharingDelta::Left("a".into())));
        assert_eq!(agg.status().helping_now, 1);
        // total distinct sessions seen this run
        assert_eq!(agg.sessions_this_run(), 2);
    }

    #[test]
    fn ignores_unrelated_events_and_unknown_leaves() {
        let mut agg = Aggregator::new();
        assert_eq!(
            agg.apply(PoolEvent {
                slot: 0,
                event: SupervisorEvent::AttemptStarted { attempt: 1 }
            }),
            None
        );
        assert_eq!(agg.apply(left("nope")), None); // leave for a session we never saw
        assert_eq!(agg.status().helping_now, 0);
    }

    fn joined_on(slot: usize, id: &str) -> PoolEvent {
        PoolEvent {
            slot,
            event: SupervisorEvent::PeerConnected {
                session_id: id.into(),
                remote: None,
            },
        }
    }
    fn left_on(slot: usize, id: &str) -> PoolEvent {
        PoolEvent {
            slot,
            event: SupervisorEvent::PeerDisconnected {
                session_id: id.into(),
            },
        }
    }

    /// One consumer can occupy several of this volunteer's slots (its session id is stable across its
    /// concurrent paths). It must show as ONE peer, count ONCE, and survive a single slot dropping.
    #[test]
    fn one_consumer_across_slots_is_one_peer_and_outlives_a_single_slot() {
        let mut agg = Aggregator::new();
        assert!(matches!(
            agg.apply(joined_on(0, "c")),
            Some(SharingDelta::Joined(_))
        ));
        // Second path of the SAME consumer: no duplicate Joined, still one displayed peer.
        assert_eq!(agg.apply(joined_on(1, "c")), None);
        assert_eq!(agg.status().helping_now, 1);
        assert_eq!(agg.status().peers.len(), 1);
        assert_eq!(agg.sessions_this_run(), 1, "one consumer counts once");

        // First slot drops — the consumer is still being served on slot 1, so it must NOT disappear.
        assert_eq!(
            agg.apply(left_on(0, "c")),
            None,
            "a single path dropping must not clear a consumer other slots still serve"
        );
        assert_eq!(agg.status().helping_now, 1);

        // Last slot drops — now the consumer is gone.
        assert_eq!(
            agg.apply(left_on(1, "c")),
            Some(SharingDelta::Left("c".into()))
        );
        assert_eq!(agg.status().helping_now, 0);

        // A reconnect is the same consumer: it must not inflate the run total again.
        assert!(matches!(
            agg.apply(joined_on(0, "c")),
            Some(SharingDelta::Joined(_))
        ));
        assert_eq!(agg.sessions_this_run(), 1);
    }

    /// The UI colours arcs by list position, so ordering must not vary between calls.
    #[test]
    fn peers_are_ordered_by_session_id_not_slot() {
        let mut agg = Aggregator::new();
        let _ = agg.apply(joined_on(2, "c"));
        let _ = agg.apply(joined_on(0, "a"));
        let _ = agg.apply(joined_on(1, "b"));
        let ids: Vec<String> = agg
            .status()
            .peers
            .into_iter()
            .map(|p| p.session_id)
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
        assert_eq!(agg.status(), agg.status(), "status must be stable per call");
    }

    #[tokio::test]
    async fn joined_carries_resolved_geo() {
        // Real geo-service key casing (`Country.IsoCode` / `Location.Latitude`) — a hand-written
        // snake_case body is what let the casing bug ship green. See geo::tests::REAL_GEO_BODY.
        let resolver = crate::geo::GeoResolver::with_fetcher(|_| {
            Box::pin(async {
                Ok::<_, crate::geo::GeoError>(
                    r#"{"Country":{"IsoCode":"IR"},"Location":{"Latitude":1.0,"Longitude":2.0}}"#
                        .to_string(),
                )
            })
        });
        let mut agg = Aggregator::new();
        let ev = PoolEvent {
            slot: 0,
            event: SupervisorEvent::PeerConnected {
                session_id: "a".into(),
                remote: "203.0.113.5:443".parse().ok(),
            },
        };
        let delta = agg.apply_with_geo(ev, &resolver).await;
        assert_eq!(
            delta,
            Some(SharingDelta::Joined(PeerView {
                session_id: "a".into(),
                geo: Some(crate::geo::Geo {
                    country_code: "IR".into(),
                    lat: 1.0,
                    lon: 2.0
                })
            }))
        );
    }
}
