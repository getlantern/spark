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
                    RequestPayload::Connect => match engine.start(exit_tx.clone()).await {
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
                    },
                    RequestPayload::Disconnect => {
                        let _ = engine.stop(Teardown::RestoreDirect).await;
                        direct_fallback = false;
                        transition(&mut state, TunnelState::Disconnected, &mut subscribers);
                        ResponsePayload::Ack
                    }
                    RequestPayload::GetStatus => ResponsePayload::Status(TunnelStatus {
                        state,
                        direct_fallback,
                    }),
                    RequestPayload::Subscribe { .. } => {
                        subscribers.push(Subscriber::new(push_tx.clone()));
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

/// A subscribed connection's push channel plus its overflow accounting.
struct Subscriber {
    /// The connection's push sender.
    tx: mpsc::Sender<Push>,
    /// Stream items dropped (channel full) since the last delivered [`Push::Dropped`] marker.
    dropped: u64,
}

impl Subscriber {
    fn new(tx: mpsc::Sender<Push>) -> Self {
        Self { tx, dropped: 0 }
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

/// Push `event` to every subscriber, pruning any whose receiver has closed. Slow subscribers
/// keep their slot — overflow is counted and surfaced as a later [`Push::Dropped`].
fn broadcast(subscribers: &mut Vec<Subscriber>, event: Push) {
    subscribers.retain_mut(|sub| sub.deliver(&event));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_event() -> Push {
        Push::Event(TunnelEvent::StateChanged(TunnelState::Connected))
    }

    #[tokio::test]
    async fn slow_subscriber_is_kept_and_told_how_many_it_missed() {
        // A 2-slot channel that we never drain: the first 2 events buffer, the rest overflow.
        let (tx, mut rx) = mpsc::channel::<Push>(2);
        let mut subs = vec![Subscriber::new(tx)];

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
        let mut subs = vec![Subscriber::new(tx)];
        drop(rx); // client hung up
        broadcast(&mut subs, state_event());
        assert!(subs.is_empty(), "a closed subscriber should be pruned");
    }
}
