//! The control-plane event loop (the "actor").
//!
//! One task owns all tunnel state and the subscriber set; connections never share that state
//! — they send an [`Envelope`] (request + reply channel) over an mpsc and await the reply.
//! This is the channels-over-locks shape from CLAUDE.md (no `Arc<Mutex<state>>`) and mirrors
//! Mullvad's daemon command loop. State transitions broadcast a [`Push`] to subscribers.

use tokio::sync::{mpsc, oneshot};

use spark_ipc::{
    negotiate, ErrorCode, Push, Request, RequestPayload, Response, ResponsePayload, TunnelEvent,
    TunnelState, TunnelStatus, PROTOCOL_VERSION,
};

use crate::engine::TunnelEngine;

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
pub async fn run_service<E: TunnelEngine>(mut engine: E, mut rx: mpsc::Receiver<Envelope>) {
    let mut state = TunnelState::Disconnected;
    let mut handshook = false;
    let mut subscribers: Vec<mpsc::Sender<Push>> = Vec::new();

    while let Some(Envelope {
        req,
        reply,
        push_tx,
    }) = rx.recv().await
    {
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
            RequestPayload::Connect => match engine.start().await {
                Ok(()) => {
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
                let _ = engine.stop().await;
                transition(&mut state, TunnelState::Disconnected, &mut subscribers);
                ResponsePayload::Ack
            }
            RequestPayload::GetStatus => ResponsePayload::Status(TunnelStatus {
                state,
                direct_fallback: false,
            }),
            RequestPayload::Subscribe { .. } => {
                subscribers.push(push_tx.clone());
                ResponsePayload::Ack
            }
        };

        // The client may have hung up; dropping the reply is fine.
        let _ = reply.send(Response {
            req_id,
            payload: response_payload,
        });
    }
}

/// Move to `new` state and notify subscribers. Dead subscribers (closed receivers) are
/// pruned; if a subscriber's channel is full the event is dropped (best-effort — a
/// drop-oldest + `Push::Dropped` accounting is a documented refinement).
fn transition(
    state: &mut TunnelState,
    new: TunnelState,
    subscribers: &mut Vec<mpsc::Sender<Push>>,
) {
    if *state == new {
        return;
    }
    *state = new;
    let event = Push::Event(TunnelEvent::StateChanged(new));
    subscribers.retain(|s| {
        !matches!(
            s.try_send(event.clone()),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    });
}
