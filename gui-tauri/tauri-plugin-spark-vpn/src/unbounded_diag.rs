//! §C6 diagnostic timeline + §C3a session traces for the Unbounded sharing pool.
//!
//! A **pure mapper** ([`diag_for_event`]) folds the `spark-sharing` pool-event stream
//! into typed diagnostic actions — [`DiagEvent`]s for the timeline and
//! [`SessionTrace`] spans for the SigNoz waterfall — which the aggregation loop in
//! `unbounded.rs` applies via [`apply_actions`]. Keeping the mapping pure (no I/O, no
//! globals) makes the whole timeline unit-testable without a sink or a runtime, and
//! keeps the fire-and-forget discipline auditable in one place: nothing here returns
//! an error or blocks, so no diagnostic path can ever affect the pool's behavior.
//!
//! Not covered: `unbounded.signaling` (§C6) — `SupervisorEvent` (unbounded-rs rev
//! 521a356) carries no signaling state changes, only whole-attempt outcomes, so there
//! is nothing real to map; signaling failures surface via `attempt_failed` with a
//! `SignalingError::*` kind instead. Emitting it needs Freddie-signaler visibility in
//! unbounded-rs first (same follow-up family as the ice-visibility TODO below).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use spark_core::diag::span::{DiagSpan, SessionTrace};
use spark_core::diag::upload::TraceCtx;
use spark_core::diag::{self, events, DiagEvent};
use spark_sharing::{PoolEvent, SupervisorEvent};

/// Cadence for the §C6 `unbounded.pool_snapshot` event. Checked by the aggregation
/// loop on each pool event (no dedicated timer task), so an idle pool emits no
/// snapshots — the timeline events already cover a pool with nothing happening.
pub(crate) const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(60);

/// The fields diagnostics needs from a [`PoolEvent`], copied out **before** the
/// aggregator consumes the event (`Aggregator::apply_with_geo` takes it by value and
/// `PoolEvent`/`SupervisorEvent` implement neither `Clone` nor `Copy`).
pub(crate) enum EventView {
    AttemptStarted { slot: usize },
    PeerConnected { slot: usize, session_id: String },
    PeerDisconnected { slot: usize, session_id: String },
    SessionEnded { slot: usize, session_id: String },
    AttemptFailed { slot: usize, error: String },
    Stopped { slot: usize },
}

impl EventView {
    pub(crate) fn capture(ev: &PoolEvent) -> EventView {
        let slot = ev.slot;
        match &ev.event {
            SupervisorEvent::AttemptStarted { .. } => EventView::AttemptStarted { slot },
            SupervisorEvent::PeerConnected { session_id, .. } => EventView::PeerConnected {
                slot,
                session_id: session_id.clone(),
            },
            SupervisorEvent::PeerDisconnected { session_id } => EventView::PeerDisconnected {
                slot,
                session_id: session_id.clone(),
            },
            SupervisorEvent::SessionEnded { outcome, .. } => EventView::SessionEnded {
                slot,
                session_id: outcome.consumer_session_id.clone(),
            },
            SupervisorEvent::AttemptFailed { error, .. } => EventView::AttemptFailed {
                slot,
                error: error.clone(),
            },
            SupervisorEvent::Stopped { .. } => EventView::Stopped { slot },
        }
    }
}

/// One diagnostic side effect the mapper wants performed. The mapper only *describes*
/// effects; [`apply_actions`] performs them, so the mapping stays pure and testable.
pub(crate) enum DiagAction {
    Emit(DiagEvent),
    EmitError(DiagEvent),
    PushSpans(Vec<DiagSpan>),
    SetCtx { session: String, ctx: TraceCtx },
    RemoveCtx { session: String },
}

/// A session currently relaying on some slot: its trace plus the wall-clock start
/// used for `duration_ms` at disconnect.
struct LiveSession {
    session_id: String,
    trace: SessionTrace,
    started: Instant,
}

/// Per-slot instrumentation state. The supervisor runs one attempt — and therefore at
/// most one connected session — per slot at a time (attempts are strictly sequential
/// in `supervise_peer_proxy`'s loop), so a single `Option` per slot matches reality.
#[derive(Default)]
struct SlotDiag {
    /// Set at `AttemptStarted`, consumed at `PeerConnected` for `nat_traversal_ms`.
    attempt_started: Option<Instant>,
    live: Option<LiveSession>,
}

/// Instrumentation state for the whole pool, owned by the aggregation loop's stack.
#[derive(Default)]
pub(crate) struct PoolDiag {
    slots: HashMap<usize, SlotDiag>,
}

impl PoolDiag {
    fn slot(&mut self, slot: usize) -> &mut SlotDiag {
        self.slots.entry(slot).or_default()
    }

    /// Number of slots currently carrying a connected session (`slots_filled` in the
    /// §C6 `unbounded.pool_snapshot`).
    pub(crate) fn slots_filled(&self) -> u64 {
        self.slots.values().filter(|s| s.live.is_some()).count() as u64
    }
}

/// Map one pool event to diagnostic actions (§C6 timeline + §C3a spans).
///
/// `peer_region` is the country the aggregation loop already resolved for the globe
/// view (`None` when unresolved) — only meaningful for `PeerConnected`.
///
/// Pure: no I/O, no globals; the only ambient input is `Instant::now()` for phase
/// timing. Never fails — unexpected sequences (a disconnect for an unknown session, a
/// failure racing a live session) degrade to fewer or defensive actions, never to an
/// error the pool loop would have to handle.
pub(crate) fn diag_for_event(
    ev: &EventView,
    peer_region: Option<&str>,
    state: &mut PoolDiag,
) -> Vec<DiagAction> {
    let mut out = Vec::new();
    match ev {
        EventView::AttemptStarted { slot } => {
            state.slot(*slot).attempt_started = Some(Instant::now());
            out.push(DiagAction::Emit(events::unbounded_attempt_started(*slot)));
        }
        EventView::PeerConnected { slot, session_id } => {
            let s = state.slot(*slot);
            // Duplicate connect for the already-live session: the aggregator dedups
            // these for the UI; dedup here too so no second trace/event is created.
            if s.live.as_ref().is_some_and(|l| l.session_id == *session_id) {
                return out;
            }
            // Defensive: one session per slot is the supervisor contract, so a live
            // *different* session here means its end event was missed — close it out
            // cleanly rather than leaking an open trace.
            if let Some(live) = s.live.take() {
                out.extend(finish_live(live, None));
            }
            let nat_traversal_ms = s
                .attempt_started
                .take()
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);
            // The session trace starts here, not at AttemptStarted: the consumer
            // session id (the trace key) only exists once the peer connects, and a
            // failed attempt gets timeline events but needs no trace. The signaling +
            // ICE phases therefore appear as the root span's pre-relay gap (root
            // start = connect time; nat_traversal_ms carries the pre-connect timing)
            // rather than as fabricated child spans. "relay" — the long-lived data
            // phase — opens immediately.
            let mut trace = SessionTrace::new(session_id);
            trace.child_start("relay");
            // Register the trace context first so the session's log records are
            // correlated from the moment the timeline event lands (§C3a).
            out.push(DiagAction::SetCtx {
                session: session_id.clone(),
                ctx: (trace.trace_id(), trace.root_span_id()),
            });
            // selected_pair_type: the pool exposes no ICE pair info today (only the
            // remote address), so report "unknown" rather than inventing data.
            // TODO(§C6 ice-visibility): plumb the selected candidate-pair type
            // through unbounded-rs `SupervisorEvent::PeerConnected`.
            out.push(DiagAction::Emit(events::unbounded_peer_connected(
                session_id,
                nat_traversal_ms,
                "unknown",
                peer_region,
            )));
            if peer_region.is_none() {
                // An unresolved geo used to be silent (§C6 blind spot): the resolver
                // returned nothing, or the peer's remote address was unavailable.
                out.push(DiagAction::Emit(events::unbounded_geo_failed(
                    "resolver_none",
                )));
            }
            s.live = Some(LiveSession {
                session_id: session_id.clone(),
                trace,
                started: Instant::now(),
            });
        }
        EventView::PeerDisconnected { slot, session_id } => {
            out.extend(end_session(state, *slot, session_id, "disconnected"));
        }
        EventView::SessionEnded { slot, session_id } => {
            // Normally a no-op: unbounded-rs emits PeerDisconnected exactly once per
            // connected session, before SessionEnded, so the trace is already closed.
            // This arm only acts when that event was somehow missed.
            out.extend(end_session(state, *slot, session_id, "session_ended"));
        }
        EventView::AttemptFailed { slot, error } => {
            let kind = error_kind(error);
            out.push(DiagAction::EmitError(events::unbounded_attempt_failed(
                *slot, kind,
            )));
            let s = state.slot(*slot);
            s.attempt_started = None;
            // Defensive: a live trace here means the failure raced the disconnect —
            // finish it with the error kind so the span isn't orphaned.
            if let Some(live) = s.live.take() {
                out.extend(finish_live(live, Some(kind)));
            }
        }
        EventView::Stopped { slot } => {
            // Per-worker stop: each slot emits Stopped before the pool winds down.
            if let Some(s) = state.slots.remove(slot) {
                if let Some(live) = s.live {
                    out.extend(finish_live(live, None));
                }
            }
        }
    }
    out
}

/// Close a session normally (peer disconnected / session ended): emit the timeline
/// event and finish + push its trace. No-op when the slot holds no live trace for
/// this session (already closed, or never connected).
fn end_session(
    state: &mut PoolDiag,
    slot: usize,
    session_id: &str,
    reason: &str,
) -> Vec<DiagAction> {
    let Some(live) = state
        .slot(slot)
        .live
        .take_if(|l| l.session_id == session_id)
    else {
        return Vec::new();
    };
    let duration_ms = live.started.elapsed().as_millis() as u64;
    let mut out = vec![DiagAction::Emit(events::unbounded_peer_disconnected(
        session_id,
        duration_ms,
        // The pool exposes no per-session byte counters yet (PeerProxyOutcome carries
        // relay_end + relay_duration only) — 0 until unbounded-rs grows byte
        // accounting for the §C6 throughput events.
        0,
        reason,
    ))];
    out.extend(finish_live(live, None));
    out
}

/// Finish a live session's trace — closing the "relay" child cleanly and stamping any
/// error on the root span only — and return the push + ctx-removal actions.
fn finish_live(live: LiveSession, error: Option<&str>) -> Vec<DiagAction> {
    let LiveSession {
        session_id,
        mut trace,
        ..
    } = live;
    trace.child_end("relay", None);
    let spans = trace.finish(error);
    vec![
        DiagAction::PushSpans(spans),
        DiagAction::RemoveCtx {
            session: session_id,
        },
    ]
}

/// Perform the mapper's actions. Fire-and-forget by construction: `emit`/`emit_error`
/// are no-ops until a sink is installed, and a `None` span queue (diagnostics
/// disabled, or init not finished) silently drops span actions. Nothing here blocks
/// beyond the sink/queue's tight internal mutexes, and nothing returns an error.
pub(crate) fn apply_actions(actions: Vec<DiagAction>) {
    let queue = crate::diag_host::span_queue();
    for action in actions {
        match action {
            DiagAction::Emit(ev) => diag::emit(ev),
            DiagAction::EmitError(ev) => diag::emit_error(ev),
            DiagAction::PushSpans(spans) => {
                if let Some(q) = &queue {
                    q.push_spans(spans);
                }
            }
            DiagAction::SetCtx { session, ctx } => {
                if let Some(q) = &queue {
                    q.set_trace_ctx(&session, ctx);
                }
            }
            DiagAction::RemoveCtx { session } => {
                if let Some(q) = &queue {
                    q.remove_trace_ctx(&session);
                }
            }
        }
    }
}

/// Map the supervisor's *stringified* `PeerProxyError` back to a variant path
/// (`"EgressError::ConnectTimeout"`, `"PeerProxyError::NatTimeout"`, …).
///
/// The supervisor renders errors with `to_string()` before emitting `AttemptFailed`,
/// so the typed enum is gone by the time the event reaches this process; classify by
/// the stable `thiserror` display prefixes (lantern-unbounded rev 521a356) instead.
/// The variant path is the whole output — payloads are never forwarded (they can
/// carry addresses; §C5 wants variant-only even before the constructors' redaction
/// backstop). Wrapping variants (Signaling/Egress/Relay) classify one level deeper,
/// matching the §C6 error taxonomy.
pub(crate) fn error_kind(error: &str) -> &'static str {
    if let Some(rest) = error.strip_prefix("Freddie signaling failed: ") {
        return signaling_kind(rest);
    }
    if let Some(rest) = error.strip_prefix("egress tunnel failed: ") {
        return egress_kind(rest);
    }
    if error.starts_with("packet relay failed after ") {
        return if error.contains(": peer transport failed") {
            "RelayError::Peer"
        } else if error.contains(": egress transport failed") {
            "RelayError::Egress"
        } else {
            "PeerProxyError::Relay"
        };
    }
    if error.starts_with("WebRTC failed") {
        return "PeerProxyError::WebRtc";
    }
    if error.starts_with("invalid ") && error.contains(" signaling payload") {
        return "PeerProxyError::Decode";
    }
    // Order matters: "Freddie returned no …" (MissingResponse) is a prefix-sibling of
    // "Freddie returned …" (UnexpectedSignal).
    if error.starts_with("Freddie returned no ") {
        return "PeerProxyError::MissingResponse";
    }
    if error.starts_with("Freddie returned ") {
        return "PeerProxyError::UnexpectedSignal";
    }
    if error == "consumer supplied no session ID" {
        return "PeerProxyError::MissingConsumerSessionId";
    }
    if error == "consumer supplied a malformed session ID" {
        return "PeerProxyError::InvalidConsumerSessionId";
    }
    if error.starts_with("consumer supplied an invalid ICE candidate") {
        return "PeerProxyError::InvalidIceCandidate";
    }
    if error == "timed out waiting for the consumer WebRTC DataChannel" {
        return "PeerProxyError::NatTimeout";
    }
    if error.starts_with("consumer WebRTC DataChannel callback ended") {
        return "PeerProxyError::DataChannelClosed";
    }
    if error.starts_with("consumer WebRTC connection became ") {
        return "PeerProxyError::PeerConnectionEnded";
    }
    if error == "peer proxy session cancelled" {
        return "PeerProxyError::Cancelled";
    }
    "unknown"
}

fn signaling_kind(rest: &str) -> &'static str {
    if rest.starts_with("invalid Freddie endpoint") {
        "SignalingError::InvalidEndpoint"
    } else if rest.starts_with("Freddie request failed") {
        "SignalingError::Transport"
    } else if rest.starts_with("Freddie rejected protocol version") {
        "SignalingError::ProtocolVersion"
    } else if rest.starts_with("Freddie signaling recipient is no longer available") {
        "SignalingError::RecipientGone"
    } else if rest.starts_with("Freddie returned HTTP") {
        "SignalingError::Http"
    } else if rest.starts_with("invalid signaling JSON") {
        "SignalingError::Decode"
    } else {
        "PeerProxyError::Signaling"
    }
}

fn egress_kind(rest: &str) -> &'static str {
    if rest.starts_with("invalid egress WebSocket request") {
        "EgressError::Request"
    } else if rest.starts_with("invalid egress WebSocket subprotocol header") {
        "EgressError::Header"
    } else if rest.starts_with("egress WebSocket failed") {
        "EgressError::WebSocket"
    } else if rest.starts_with("timed out after ") {
        "EgressError::ConnectTimeout"
    } else if rest.starts_with("egress selected no WebSocket subprotocol") {
        "EgressError::MissingSubprotocol"
    } else if rest.starts_with("egress selected unexpected WebSocket subprotocol") {
        "EgressError::UnexpectedSubprotocol"
    } else if rest.starts_with("consumer session ID ") {
        "EgressError::InvalidConsumerSessionId"
    } else if rest.starts_with("egress sent a text message") {
        "EgressError::TextMessage"
    } else {
        "PeerProxyError::Egress"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spark_core::diag::DiagLevel;

    fn pe(slot: usize, event: SupervisorEvent) -> PoolEvent {
        PoolEvent { slot, event }
    }

    fn map(
        state: &mut PoolDiag,
        slot: usize,
        event: SupervisorEvent,
        region: Option<&str>,
    ) -> Vec<DiagAction> {
        diag_for_event(&EventView::capture(&pe(slot, event)), region, state)
    }

    /// Events emitted (either level) by a slice of actions, in order.
    fn emitted(actions: &[DiagAction]) -> Vec<&DiagEvent> {
        actions
            .iter()
            .filter_map(|a| match a {
                DiagAction::Emit(ev) | DiagAction::EmitError(ev) => Some(ev),
                _ => None,
            })
            .collect()
    }

    fn pushed_spans(actions: &[DiagAction]) -> Vec<&DiagSpan> {
        actions
            .iter()
            .filter_map(|a| match a {
                DiagAction::PushSpans(spans) => Some(spans.iter()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[test]
    fn timeline_for_connect_disconnect() {
        let mut st = PoolDiag::default();
        let a1 = map(
            &mut st,
            0,
            SupervisorEvent::AttemptStarted { attempt: 1 },
            None,
        );
        let a2 = map(
            &mut st,
            0,
            SupervisorEvent::PeerConnected {
                session_id: "s1".into(),
                remote: None,
            },
            Some("IR"),
        );
        assert_eq!(st.slots_filled(), 1);
        let a3 = map(
            &mut st,
            0,
            SupervisorEvent::PeerDisconnected {
                session_id: "s1".into(),
            },
            None,
        );
        assert_eq!(st.slots_filled(), 0);

        // Timeline kind sequence.
        let all: Vec<&DiagEvent> = [&a1, &a2, &a3]
            .into_iter()
            .flat_map(|a| emitted(a))
            .collect();
        let kinds: Vec<&str> = all.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                "unbounded.attempt_started",
                "unbounded.peer_connected",
                "unbounded.peer_disconnected",
            ]
        );

        // Session correlation on the connect/disconnect pair.
        assert_eq!(all[1].session.as_deref(), Some("s1"));
        assert_eq!(all[2].session.as_deref(), Some("s1"));

        // nat_traversal_ms present and sane.
        let nat = all[1].fields["nat_traversal_ms"].as_u64();
        assert!(nat.is_some(), "nat_traversal_ms must be a u64");

        // SetCtx (at connect) strictly before RemoveCtx (at disconnect).
        assert!(
            a2.iter()
                .any(|a| matches!(a, DiagAction::SetCtx { session, .. } if session == "s1")),
            "connect must register the trace ctx"
        );
        assert!(
            a3.iter()
                .any(|a| matches!(a, DiagAction::RemoveCtx { session } if session == "s1")),
            "disconnect must remove the trace ctx"
        );

        // Spans: root "unbounded.session" + "relay" child sharing one trace_id.
        let spans = pushed_spans(&a3);
        let root = spans
            .iter()
            .find(|s| s.name == "unbounded.session")
            .expect("root span pushed");
        let relay = spans
            .iter()
            .find(|s| s.name == "relay")
            .expect("relay child pushed");
        assert_eq!(relay.trace_id, root.trace_id);
        assert_eq!(relay.parent_span_id, Some(root.span_id));

        // duration_ms present on the disconnect event.
        assert!(all[2].fields["duration_ms"].as_u64().is_some());
        assert_eq!(all[2].fields["reason"], "disconnected");
    }

    #[test]
    fn attempt_failed_is_error_kind_only() {
        let mut st = PoolDiag::default();
        let payload =
            "egress tunnel failed: timed out after 10.5s connecting to the egress WebSocket";
        let actions = map(
            &mut st,
            1,
            SupervisorEvent::AttemptFailed {
                attempt: 3,
                error: payload.into(),
                duration: Duration::from_secs(1),
                retry_in: Duration::from_secs(2),
            },
            None,
        );
        let evs = emitted(&actions);
        assert_eq!(evs.len(), 1);
        let ev = evs[0];
        assert!(
            matches!(actions[0], DiagAction::EmitError(_)),
            "attempt_failed must ride the error fast-path"
        );
        assert_eq!(ev.level, DiagLevel::Error);
        assert_eq!(ev.kind, "unbounded.attempt_failed");
        assert_eq!(ev.fields["error_kind"], "EgressError::ConnectTimeout");
        // Variant path only — no payload text anywhere in the event.
        let line = ev.to_jsonl();
        assert!(!line.contains("10.5"), "payload leaked into event: {line}");
        assert!(
            !line.contains("connecting to"),
            "payload leaked into event: {line}"
        );
    }

    #[test]
    fn stopped_finishes_live_traces() {
        let mut st = PoolDiag::default();
        map(
            &mut st,
            0,
            SupervisorEvent::AttemptStarted { attempt: 1 },
            None,
        );
        map(
            &mut st,
            0,
            SupervisorEvent::PeerConnected {
                session_id: "s1".into(),
                remote: None,
            },
            Some("DE"),
        );
        let actions = map(
            &mut st,
            0,
            SupervisorEvent::Stopped {
                summary: spark_sharing::SupervisorSummary::default(),
            },
            None,
        );
        let spans = pushed_spans(&actions);
        assert!(
            spans.iter().any(|s| s.name == "unbounded.session"),
            "stop must push the live session's spans"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DiagAction::RemoveCtx { session } if session == "s1")),
            "stop must remove the live session's trace ctx"
        );
        assert_eq!(st.slots_filled(), 0);
    }

    #[test]
    fn no_geo_emits_geo_failed() {
        let mut st = PoolDiag::default();
        map(
            &mut st,
            0,
            SupervisorEvent::AttemptStarted { attempt: 1 },
            None,
        );
        let actions = map(
            &mut st,
            0,
            SupervisorEvent::PeerConnected {
                session_id: "s1".into(),
                remote: None,
            },
            None,
        );
        let evs = emitted(&actions);
        let connected = evs
            .iter()
            .find(|e| e.kind == "unbounded.peer_connected")
            .expect("peer_connected emitted");
        assert!(
            !connected.fields.contains_key("peer_region"),
            "unresolved geo must omit peer_region"
        );
        let geo_failed = evs
            .iter()
            .find(|e| e.kind == "unbounded.geo_failed")
            .expect("unresolved geo must emit geo_failed");
        assert_eq!(geo_failed.fields["reason"], "resolver_none");
    }

    #[test]
    fn duplicate_connect_is_deduped() {
        let mut st = PoolDiag::default();
        map(
            &mut st,
            0,
            SupervisorEvent::AttemptStarted { attempt: 1 },
            None,
        );
        let first = map(
            &mut st,
            0,
            SupervisorEvent::PeerConnected {
                session_id: "s1".into(),
                remote: None,
            },
            Some("IR"),
        );
        assert!(!emitted(&first).is_empty());
        let dup = map(
            &mut st,
            0,
            SupervisorEvent::PeerConnected {
                session_id: "s1".into(),
                remote: None,
            },
            None,
        );
        assert!(dup.is_empty(), "duplicate connect must produce no actions");
        assert_eq!(st.slots_filled(), 1);
    }

    #[test]
    fn session_ended_after_disconnect_is_noop() {
        let mut st = PoolDiag::default();
        map(
            &mut st,
            0,
            SupervisorEvent::AttemptStarted { attempt: 1 },
            None,
        );
        map(
            &mut st,
            0,
            SupervisorEvent::PeerConnected {
                session_id: "s1".into(),
                remote: None,
            },
            Some("IR"),
        );
        let disc = map(
            &mut st,
            0,
            SupervisorEvent::PeerDisconnected {
                session_id: "s1".into(),
            },
            None,
        );
        assert!(!disc.is_empty());
        // SessionEnded for the already-closed session must not double-report. (Built
        // directly as an EventView: PeerProxyOutcome isn't re-exported by
        // spark-sharing, and only the session id matters here.)
        let ended = diag_for_event(
            &EventView::SessionEnded {
                slot: 0,
                session_id: "s1".into(),
            },
            None,
            &mut st,
        );
        assert!(ended.is_empty(), "second close must produce no actions");
    }

    #[test]
    fn attempt_failed_with_live_trace_finishes_it_with_error() {
        let mut st = PoolDiag::default();
        map(
            &mut st,
            0,
            SupervisorEvent::AttemptStarted { attempt: 1 },
            None,
        );
        map(
            &mut st,
            0,
            SupervisorEvent::PeerConnected {
                session_id: "s1".into(),
                remote: None,
            },
            Some("IR"),
        );
        let actions = map(
            &mut st,
            0,
            SupervisorEvent::AttemptFailed {
                attempt: 1,
                error: "packet relay failed after 5s: peer transport failed: closed".into(),
                duration: Duration::from_secs(5),
                retry_in: Duration::from_secs(1),
            },
            None,
        );
        let spans = pushed_spans(&actions);
        let root = spans
            .iter()
            .find(|s| s.name == "unbounded.session")
            .expect("live trace must be finished on failure");
        assert_eq!(root.error.as_deref(), Some("RelayError::Peer"));
        let relay = spans
            .iter()
            .find(|s| s.name == "relay")
            .expect("relay child");
        assert!(relay.error.is_none(), "error is stamped on the root only");
        assert!(actions
            .iter()
            .any(|a| matches!(a, DiagAction::RemoveCtx { session } if session == "s1")));
        assert_eq!(st.slots_filled(), 0);
    }

    #[test]
    fn error_kind_classifies_variant_paths() {
        for (raw, kind) in [
            (
                "Freddie signaling failed: Freddie returned HTTP 503",
                "SignalingError::Http",
            ),
            (
                "Freddie signaling failed: Freddie request failed: connect refused",
                "SignalingError::Transport",
            ),
            (
                "egress tunnel failed: egress WebSocket failed: broken pipe",
                "EgressError::WebSocket",
            ),
            (
                "timed out waiting for the consumer WebRTC DataChannel",
                "PeerProxyError::NatTimeout",
            ),
            (
                "packet relay failed after 30s: egress transport failed: reset",
                "RelayError::Egress",
            ),
            (
                "Freddie returned no offer signaling response",
                "PeerProxyError::MissingResponse",
            ),
            (
                "Freddie returned Answer while Offer was required",
                "PeerProxyError::UnexpectedSignal",
            ),
            ("WebRTC failed: ice gathering", "PeerProxyError::WebRtc"),
            ("peer proxy session cancelled", "PeerProxyError::Cancelled"),
            ("something novel entirely", "unknown"),
        ] {
            assert_eq!(error_kind(raw), kind, "for {raw:?}");
        }
    }
}
