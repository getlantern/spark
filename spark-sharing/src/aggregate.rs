use std::collections::HashMap;

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
    live: HashMap<String, Option<Geo>>,
    sessions_this_run: u64,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one pool event; returns a delta the caller should act on (bump the
    /// persisted counter on `Joined`, re-emit the snapshot on either), or `None`.
    pub fn apply(&mut self, ev: PoolEvent) -> Option<SharingDelta> {
        match ev.event {
            SupervisorEvent::PeerConnected { session_id, .. } => {
                if self.live.contains_key(&session_id) {
                    return None;
                }
                self.live.insert(session_id.clone(), None);
                self.sessions_this_run += 1;
                Some(SharingDelta::Joined(PeerView {
                    session_id,
                    geo: None,
                }))
            }
            SupervisorEvent::PeerDisconnected { session_id } => {
                if self.live.remove(&session_id).is_some() {
                    Some(SharingDelta::Left(session_id))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Like [`Aggregator::apply`], but resolves peer geolocation before emitting a
    /// `Joined` delta. Used by the plugin's aggregation loop; the sync [`Aggregator::apply`]
    /// stays for pure unit tests.
    pub async fn apply_with_geo(
        &mut self,
        ev: PoolEvent,
        resolver: &crate::geo::GeoResolver,
    ) -> Option<SharingDelta> {
        match ev.event {
            SupervisorEvent::PeerConnected { session_id, remote } => {
                if self.live.contains_key(&session_id) {
                    return None;
                }
                let geo = match remote {
                    Some(addr) => resolver.resolve(addr.ip()).await,
                    None => None,
                };
                self.live.insert(session_id.clone(), geo.clone());
                self.sessions_this_run += 1;
                Some(SharingDelta::Joined(PeerView { session_id, geo }))
            }
            SupervisorEvent::PeerDisconnected { session_id } => {
                if self.live.remove(&session_id).is_some() {
                    Some(SharingDelta::Left(session_id))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn status(&self) -> SharingStatus {
        let peers = self
            .live
            .iter()
            .map(|(id, geo)| PeerView {
                session_id: id.clone(),
                geo: geo.clone(),
            })
            .collect();
        SharingStatus {
            helping_now: self.live.len(),
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

    #[tokio::test]
    async fn joined_carries_resolved_geo() {
        let resolver = crate::geo::GeoResolver::with_fetcher(|_| {
            Box::pin(async {
                Ok::<_, crate::geo::GeoError>(
                    r#"{"country":{"iso_code":"IR"},"location":{"latitude":1.0,"longitude":2.0}}"#
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
