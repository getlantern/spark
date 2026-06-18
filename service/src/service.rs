//! The control-plane event loop (the "actor").
//!
//! One task owns all tunnel state and the subscriber set; connections never share that state
//! — they send an [`Envelope`] (request + reply channel) over an mpsc and await the reply.
//! This is the channels-over-locks shape from CLAUDE.md (no `Arc<Mutex<state>>`) and mirrors
//! Mullvad's daemon command loop. State transitions broadcast a [`Push`] to subscribers.

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use spark_ipc::{
    negotiate, ErrorCode, Push, Request, RequestPayload, Response, ResponsePayload, TunnelEvent,
    TunnelState, TunnelStatus, PROTOCOL_VERSION,
};

use crate::engine::{Teardown, TunnelEngine};

/// Depth of the command channel feeding the event loop.
const COMMAND_DEPTH: usize = 64;

/// A client request handed to the event loop: the request, a channel to answer it, and the
/// connection's push sender (registered as a subscriber if the request is `Subscribe`).
pub struct Envelope {
    /// The client's request.
    pub req: Request,
    /// Where the loop sends the matching response.
    pub reply: oneshot::Sender<Response>,
    /// The connection's push channel, registered on `Subscribe`.
    pub push_tx: mpsc::Sender<Push>,
}

/// Create the command channel connecting [`serve_connection`](crate::conn::serve_connection)
/// to [`run_service`].
pub fn channel() -> (mpsc::Sender<Envelope>, mpsc::Receiver<Envelope>) {
    mpsc::channel(COMMAND_DEPTH)
}

/// Run the event loop until all senders drop. Owns the tunnel state and drives `engine` on
/// connect/disconnect.
pub async fn run_service<E: TunnelEngine>(
    mut engine: E,
    mut rx: mpsc::Receiver<Envelope>,
    fail_closed: bool,
) {
    let mut state = TunnelState::Disconnected;
    let mut direct_fallback = false;
    let mut handshook = false;
    let mut subscribers: Vec<Subscriber> = Vec::new();

    // The actor owns one exit channel; `start` is handed the sender and the data-path
    // supervisor fires it if a forwarder loop returns on its own. Nothing fires it while
    // disconnected, so `exit_rx.recv()` simply pends until an unexpected exit.
    let (exit_tx, mut exit_rx) = mpsc::channel::<()>(1);

    loop {
        tokio::select! {
            maybe_env = rx.recv() => {
                let Some(Envelope { req, reply, push_tx }) = maybe_env else { break };
                let Request { req_id, payload } = req;
                let response_payload = match payload {
                    RequestPayload::Hello { client_version } => {
                        match negotiate(PROTOCOL_VERSION, client_version) {
                            Some(negotiated) => {
                                handshook = true;
                                ResponsePayload::Hello {
                                    service_version: PROTOCOL_VERSION,
                                    negotiated,
                                }
                            }
                            None => ResponsePayload::Error {
                                code: ErrorCode::UnsupportedVersion,
                                message: format!(
                                    "no common protocol version (service {PROTOCOL_VERSION}, client {client_version})"
                                ),
                            },
                        }
                    }
                    // Every other command requires a completed handshake first.
                    _ if !handshook => ResponsePayload::Error {
                        code: ErrorCode::InvalidRequest,
                        message: "Hello handshake required before commands".into(),
                    },
                    RequestPayload::Connect => {
                        // Announce the in-progress state before the (possibly slow) bring-up, so a
                        // subscribed UI can show "Connecting…" while `start` runs.
                        transition(&mut state, TunnelState::Connecting, &mut subscribers);
                        match engine.start(exit_tx.clone()).await {
                            Ok(()) => {
                                direct_fallback = false;
                                transition(&mut state, TunnelState::Connected, &mut subscribers);
                                ResponsePayload::Ack
                            }
                            Err(e) => {
                                transition(&mut state, TunnelState::Failed, &mut subscribers);
                                ResponsePayload::Error {
                                    code: ErrorCode::Internal,
                                    message: e.to_string(),
                                }
                            }
                        }
                    }
                    RequestPayload::Disconnect => {
                        // Announce the in-progress state during teardown (but not for a no-op
                        // disconnect from `Disconnected` — that would emit a spurious transition).
                        if state != TunnelState::Disconnected {
                            transition(&mut state, TunnelState::Disconnecting, &mut subscribers);
                        }
                        let _ = engine.stop(Teardown::RestoreDirect).await;
                        direct_fallback = false;
                        transition(&mut state, TunnelState::Disconnected, &mut subscribers);
                        ResponsePayload::Ack
                    }
                    RequestPayload::GetStatus => ResponsePayload::Status(TunnelStatus {
                        state,
                        direct_fallback,
                    }),
                    RequestPayload::Subscribe { events, logs } => {
                        subscribers.push(Subscriber::new(push_tx.clone(), events, logs));
                        ResponsePayload::Ack
                    }
                };

                // The client may have hung up; dropping the reply is fine.
                let _ = reply.send(Response { req_id, payload: response_payload });
            }

            // The data path died on its own while we believed the tunnel was up — the
            // kill-switch. Fail open (restore direct routing) or closed (block), loudly.
            Some(()) = exit_rx.recv() => {
                if state == TunnelState::Connected {
                    // Reclaim the dead device and settle routing per policy: fail open (restore
                    // direct) by default, or fail closed (blackhole) for a fail-closed profile.
                    let teardown = if fail_closed { Teardown::Block } else { Teardown::RestoreDirect };
                    let _ = engine.stop(teardown).await;
                    if fail_closed {
                        direct_fallback = false;
                        transition(&mut state, TunnelState::Failed, &mut subscribers);
                    } else {
                        direct_fallback = true;
                        transition(&mut state, TunnelState::Disconnected, &mut subscribers);
                    }
                    broadcast(&mut subscribers, Push::Event(TunnelEvent::FellOpenToDirect));
                    warn!(
                        fail_closed,
                        "tunnel exited unexpectedly; failing {}",
                        if fail_closed { "closed" } else { "open" }
                    );
                }
            }
        }
    }

    // The command channel closed — all control senders dropped, i.e. the daemon is shutting down
    // (e.g. a Windows-service STOP cancelled the listener). Tear the tunnel down so we don't
    // leave it up with no one driving it; restore direct routing on the way out.
    if state == TunnelState::Connected {
        let _ = engine.stop(Teardown::RestoreDirect).await;
    }
}

/// A subscribed connection's push channel, the push kinds it opted into, and overflow accounting.
struct Subscriber {
    /// The connection's push sender.
    tx: mpsc::Sender<Push>,
    /// Opted into tunnel events ([`Push::Event`]) — the `events` flag of [`RequestPayload::Subscribe`].
    events: bool,
    /// Opted into log lines ([`Push::Log`]) — the `logs` flag of [`RequestPayload::Subscribe`].
    logs: bool,
    /// Stream items dropped (channel full) since the last delivered [`Push::Dropped`] marker.
    dropped: u64,
}

impl Subscriber {
    fn new(tx: mpsc::Sender<Push>, events: bool, logs: bool) -> Self {
        Self {
            tx,
            events,
            logs,
            dropped: 0,
        }
    }

    /// Whether this subscriber opted into `push`'s kind. [`Push::Dropped`] is delivery metadata
    /// (generated per-subscriber, never broadcast), so it always counts as wanted.
    fn wants(&self, push: &Push) -> bool {
        match push {
            Push::Event(_) => self.events,
            Push::Log(_) => self.logs,
            Push::Dropped { .. } => true,
        }
    }

    /// Deliver `event`, flushing any pending drop accounting first. Returns `false` when the
    /// receiver has closed (so the caller prunes this subscriber).
    ///
    /// Delivery is non-blocking (`try_send`) so a wedged client never stalls the event loop. On
    /// a full channel the item is dropped and counted; the count rides out as a [`Push::Dropped`]
    /// once the channel drains, telling the client to re-sync via `GetStatus`.
    fn deliver(&mut self, event: &Push) -> bool {
        use mpsc::error::TrySendError;
        if self.dropped > 0 {
            match self.tx.try_send(Push::Dropped {
                count: self.dropped,
            }) {
                Ok(()) => self.dropped = 0,
                // Still backed up — fold this event into the count and try again next time.
                Err(TrySendError::Full(_)) => {
                    self.dropped = self.dropped.saturating_add(1);
                    return true;
                }
                Err(TrySendError::Closed(_)) => return false,
            }
        }
        match self.tx.try_send(event.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.dropped = self.dropped.saturating_add(1);
                true
            }
            Err(TrySendError::Closed(_)) => false,
        }
    }
}

/// Move to `new` state and notify subscribers of the change.
fn transition(state: &mut TunnelState, new: TunnelState, subscribers: &mut Vec<Subscriber>) {
    if *state == new {
        return;
    }
    *state = new;
    broadcast(subscribers, Push::Event(TunnelEvent::StateChanged(new)));
}

/// Push `event` to every subscriber that opted into its kind, pruning any whose receiver has
/// closed. A subscriber that didn't opt in keeps its slot untouched. Slow (but live) subscribers
/// keep their slot too — overflow is counted and surfaced as a later [`Push::Dropped`].
fn broadcast(subscribers: &mut Vec<Subscriber>, event: Push) {
    // Keep a subscriber unless it wanted this push AND its receiver has closed (deliver → false).
    subscribers.retain_mut(|sub| !sub.wants(&event) || sub.deliver(&event));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::FakeEngine;
    use spark_ipc::{LogLevel, LogLine};

    fn state_event() -> Push {
        Push::Event(TunnelEvent::StateChanged(TunnelState::Connected))
    }

    /// Send one request through the actor and await its response payload.
    async fn request(
        cmd: &mpsc::Sender<Envelope>,
        push_tx: &mpsc::Sender<Push>,
        payload: RequestPayload,
    ) -> ResponsePayload {
        let (reply, reply_rx) = oneshot::channel();
        cmd.send(Envelope {
            req: Request { req_id: 0, payload },
            reply,
            push_tx: push_tx.clone(),
        })
        .await
        .unwrap();
        reply_rx.await.unwrap().payload
    }

    #[tokio::test]
    async fn subscribers_get_only_their_requested_push_kinds() {
        let (etx, mut erx) = mpsc::channel::<Push>(8); // events-only
        let (ltx, mut lrx) = mpsc::channel::<Push>(8); // logs-only
        let mut subs = vec![
            Subscriber::new(etx, true, false),
            Subscriber::new(ltx, false, true),
        ];

        broadcast(&mut subs, state_event());
        broadcast(
            &mut subs,
            Push::Log(LogLine {
                level: LogLevel::Info,
                message: "hi".into(),
            }),
        );

        // The events-only subscriber got the Event and nothing else.
        assert!(matches!(erx.try_recv(), Ok(Push::Event(_))));
        assert!(erx.try_recv().is_err());
        // The logs-only subscriber got the Log and nothing else.
        assert!(matches!(lrx.try_recv(), Ok(Push::Log(_))));
        assert!(lrx.try_recv().is_err());
    }

    #[tokio::test]
    async fn connect_disconnect_emit_transitional_states() {
        let (cmd, cmd_rx) = channel();
        let handle = tokio::spawn(run_service(FakeEngine::default(), cmd_rx, false));
        let (push_tx, mut push_rx) = mpsc::channel::<Push>(16);

        request(
            &cmd,
            &push_tx,
            RequestPayload::Hello {
                client_version: PROTOCOL_VERSION,
            },
        )
        .await;
        request(
            &cmd,
            &push_tx,
            RequestPayload::Subscribe {
                events: true,
                logs: false,
            },
        )
        .await;

        assert!(matches!(
            request(&cmd, &push_tx, RequestPayload::Connect).await,
            ResponsePayload::Ack
        ));
        assert_eq!(
            push_rx.recv().await.unwrap(),
            Push::Event(TunnelEvent::StateChanged(TunnelState::Connecting))
        );
        assert_eq!(
            push_rx.recv().await.unwrap(),
            Push::Event(TunnelEvent::StateChanged(TunnelState::Connected))
        );

        assert!(matches!(
            request(&cmd, &push_tx, RequestPayload::Disconnect).await,
            ResponsePayload::Ack
        ));
        assert_eq!(
            push_rx.recv().await.unwrap(),
            Push::Event(TunnelEvent::StateChanged(TunnelState::Disconnecting))
        );
        assert_eq!(
            push_rx.recv().await.unwrap(),
            Push::Event(TunnelEvent::StateChanged(TunnelState::Disconnected))
        );

        drop(cmd);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn slow_subscriber_is_kept_and_told_how_many_it_missed() {
        // A 2-slot channel that we never drain: the first 2 events buffer, the rest overflow.
        let (tx, mut rx) = mpsc::channel::<Push>(2);
        let mut subs = vec![Subscriber::new(tx, true, true)];

        for _ in 0..5 {
            broadcast(&mut subs, state_event());
        }
        assert_eq!(
            subs.len(),
            1,
            "a slow (but live) subscriber must not be pruned"
        );

        // Two events fit; the other three were dropped and counted.
        assert!(matches!(rx.try_recv(), Ok(Push::Event(_))));
        assert!(matches!(rx.try_recv(), Ok(Push::Event(_))));

        // Draining freed the channel; the next broadcast flushes the drop marker first.
        broadcast(&mut subs, Push::Event(TunnelEvent::FellOpenToDirect));
        assert!(matches!(rx.try_recv(), Ok(Push::Dropped { count: 3 })));
        assert!(matches!(
            rx.try_recv(),
            Ok(Push::Event(TunnelEvent::FellOpenToDirect))
        ));
    }

    #[tokio::test]
    async fn closed_subscriber_is_pruned() {
        let (tx, rx) = mpsc::channel::<Push>(4);
        let mut subs = vec![Subscriber::new(tx, true, true)];
        drop(rx); // client hung up
        broadcast(&mut subs, state_event());
        assert!(subs.is_empty(), "a closed subscriber should be pruned");
    }
}
