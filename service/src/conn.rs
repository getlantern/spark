//! The per-connection serve loop: framed control messages ↔ the event loop.
//!
//! Reads length-delimited [`Request`] frames from the client, forwards each to the event
//! loop (awaiting the reply), and writes framed [`ServerMessage`]s back — interleaving
//! responses with `Push` stream items for a subscribed connection. The actual listener
//! (`UnixListener` accept + `SO_PEERCRED` extraction) is the privileged/live wiring; this
//! serve loop is transport-generic so it tests over an in-memory duplex.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use spark_ipc::{Push, Request, ServerMessage};

use crate::service::Envelope;

/// Depth of a connection's outbound push buffer.
const PUSH_DEPTH: usize = 64;

/// Serve one client connection until it closes or the service stops. `commands` is the event
/// loop's command sender (clone per connection).
pub async fn serve_connection<S>(stream: S, commands: mpsc::Sender<Envelope>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    // `read_frame` is not cancel-safe, so it runs in its own loop (never a `select!` branch)
    // and forwards parsed requests over a channel that the serve loop selects on.
    let (req_tx, mut req_rx) = mpsc::channel::<Request>(16);
    let reader_task = tokio::spawn(async move {
        // A read error or a clean EOF (`Ok(None)`) ends the loop.
        while let Ok(Some(req)) = spark_ipc::read_frame::<_, Request>(&mut reader).await {
            if req_tx.send(req).await.is_err() {
                break;
            }
        }
    });

    let (push_tx, mut push_rx) = mpsc::channel::<Push>(PUSH_DEPTH);

    let result = loop {
        tokio::select! {
            maybe_req = req_rx.recv() => {
                let Some(req) = maybe_req else { break Ok(()) }; // client closed / reader ended
                let (reply_tx, reply_rx) = oneshot::channel();
                let envelope = Envelope { req, reply: reply_tx, push_tx: push_tx.clone() };
                if commands.send(envelope).await.is_err() {
                    break Ok(()); // service stopped
                }
                match reply_rx.await {
                    Ok(response) => {
                        if let Err(e) =
                            spark_ipc::write_frame(&mut writer, &ServerMessage::Response(response)).await
                        {
                            break Err(e);
                        }
                    }
                    Err(_) => break Ok(()), // service dropped the reply
                }
            }
            Some(push) = push_rx.recv() => {
                if let Err(e) = spark_ipc::write_frame(&mut writer, &ServerMessage::Push(push)).await {
                    break Err(e);
                }
            }
        }
    };

    reader_task.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::FakeEngine;
    use crate::engine::Teardown;
    use crate::service::{channel, run_service};
    use spark_ipc::{
        ErrorCode, RequestPayload, Response, ResponsePayload, TunnelEvent, TunnelState,
        TunnelStatus, PROTOCOL_VERSION,
    };
    use std::sync::atomic::Ordering;
    use tokio::io::DuplexStream;

    /// Unwrap a [`ServerMessage`] expected to be a response (panic if it's a push).
    fn expect_response(msg: ServerMessage) -> Response {
        match msg {
            ServerMessage::Response(r) => r,
            ServerMessage::Push(p) => panic!("expected a response, got push {p:?}"),
        }
    }

    /// Stand up the event loop + a served connection over a duplex with the given kill-switch
    /// mode; return the client end and a handle to the fake engine (for `running` / `kill`).
    fn spin_up_with(fail_closed: bool) -> (DuplexStream, FakeEngine) {
        let (cmd_tx, cmd_rx) = channel();
        let engine = FakeEngine::default();
        let handle = engine.clone();
        tokio::spawn(run_service(engine, cmd_rx, fail_closed));
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(serve_connection(server, cmd_tx));
        (client, handle)
    }

    /// Default spin-up (fail-open), returning the client + the engine's "running" flag.
    fn spin_up() -> (DuplexStream, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let (client, engine) = spin_up_with(false);
        (client, engine.running.clone())
    }

    /// Subscribe, connect, then read server messages until the expected push arrives (skipping
    /// the interleaved `StateChanged` pushes); returns whether the tunnel ended up in direct
    /// fallback.
    async fn fail_after_unexpected_exit(fail_closed: bool) -> TunnelStatus {
        let (mut client, engine) = spin_up_with(fail_closed);
        expect_response(request(&mut client, hello(1)).await);
        expect_response(
            request(
                &mut client,
                Request {
                    req_id: 2,
                    payload: RequestPayload::Subscribe {
                        events: true,
                        logs: false,
                    },
                },
            )
            .await,
        );
        expect_response(
            request(
                &mut client,
                Request {
                    req_id: 3,
                    payload: RequestPayload::Connect,
                },
            )
            .await,
        );
        assert!(engine.running.load(Ordering::SeqCst));

        // The data path dies on its own; expect a loud FellOpenToDirect push.
        engine.kill().await;
        let mut saw_fell_open = false;
        for _ in 0..6 {
            if let ServerMessage::Push(Push::Event(TunnelEvent::FellOpenToDirect)) =
                spark_ipc::read_frame::<_, ServerMessage>(&mut client)
                    .await
                    .unwrap()
                    .unwrap()
            {
                saw_fell_open = true;
                break;
            }
        }
        assert!(
            saw_fell_open,
            "expected a FellOpenToDirect push after the tunnel died"
        );

        // The engine must have been told the matching routing decision (the active half of the
        // kill-switch): blackhole when failing closed, restore-direct when failing open.
        let expected = if fail_closed {
            Teardown::Block
        } else {
            Teardown::RestoreDirect
        };
        assert_eq!(engine.last_teardown(), Some(expected));

        match expect_response(
            request(
                &mut client,
                Request {
                    req_id: 4,
                    payload: RequestPayload::GetStatus,
                },
            )
            .await,
        )
        .payload
        {
            ResponsePayload::Status(s) => s,
            other => panic!("expected status, got {other:?}"),
        }
    }

    /// Send one request and read one server message back.
    async fn request(client: &mut DuplexStream, req: Request) -> ServerMessage {
        spark_ipc::write_frame(client, &req).await.unwrap();
        spark_ipc::read_frame::<_, ServerMessage>(client)
            .await
            .unwrap()
            .unwrap()
    }

    fn hello(req_id: u64) -> Request {
        Request {
            req_id,
            payload: RequestPayload::Hello {
                client_version: PROTOCOL_VERSION,
            },
        }
    }

    #[tokio::test]
    async fn handshake_connect_status_roundtrip() {
        let (mut client, running) = spin_up();

        let resp = expect_response(request(&mut client, hello(1)).await);
        assert_eq!(resp.req_id, 1);
        assert!(matches!(
            resp.payload,
            ResponsePayload::Hello { negotiated, .. } if negotiated == PROTOCOL_VERSION
        ));

        let resp = expect_response(
            request(
                &mut client,
                Request {
                    req_id: 2,
                    payload: RequestPayload::Connect,
                },
            )
            .await,
        );
        assert_eq!(resp.req_id, 2);
        assert!(matches!(resp.payload, ResponsePayload::Ack));
        assert!(running.load(Ordering::SeqCst), "engine should be started");

        let resp = expect_response(
            request(
                &mut client,
                Request {
                    req_id: 3,
                    payload: RequestPayload::GetStatus,
                },
            )
            .await,
        );
        assert!(matches!(
            resp.payload,
            ResponsePayload::Status(s) if s.state == TunnelState::Connected
        ));
    }

    #[tokio::test]
    async fn commands_before_handshake_are_rejected() {
        let (mut client, _) = spin_up();
        let resp = expect_response(
            request(
                &mut client,
                Request {
                    req_id: 1,
                    payload: RequestPayload::GetStatus,
                },
            )
            .await,
        );
        assert!(matches!(
            resp.payload,
            ResponsePayload::Error { code, .. } if code == ErrorCode::InvalidRequest
        ));
    }

    #[tokio::test]
    async fn incompatible_version_is_rejected() {
        let (mut client, _) = spin_up();
        let resp = expect_response(
            request(
                &mut client,
                Request {
                    req_id: 1,
                    payload: RequestPayload::Hello { client_version: 0 },
                },
            )
            .await,
        );
        assert!(matches!(
            resp.payload,
            ResponsePayload::Error { code, .. } if code == ErrorCode::UnsupportedVersion
        ));
    }

    #[tokio::test]
    async fn subscribed_client_receives_state_change_push() {
        let (mut client, _) = spin_up();
        let _ = request(&mut client, hello(1)).await;
        let _ = request(
            &mut client,
            Request {
                req_id: 2,
                payload: RequestPayload::Subscribe {
                    events: true,
                    logs: false,
                },
            },
        )
        .await;

        // Connect yields both an Ack and (because we subscribed) a StateChanged push, in some
        // order; collect two frames and assert we saw each.
        spark_ipc::write_frame(
            &mut client,
            &Request {
                req_id: 3,
                payload: RequestPayload::Connect,
            },
        )
        .await
        .unwrap();

        let mut got_ack = false;
        let mut got_push = false;
        for _ in 0..2 {
            match spark_ipc::read_frame::<_, ServerMessage>(&mut client)
                .await
                .unwrap()
                .unwrap()
            {
                ServerMessage::Response(Response {
                    req_id: 3,
                    payload: ResponsePayload::Ack,
                }) => got_ack = true,
                ServerMessage::Push(Push::Event(TunnelEvent::StateChanged(
                    TunnelState::Connected,
                ))) => got_push = true,
                other => panic!("unexpected server message: {other:?}"),
            }
        }
        assert!(got_ack && got_push, "ack={got_ack} push={got_push}");
    }

    #[tokio::test]
    async fn unexpected_exit_fails_open_loudly() {
        // Default (fail-open): a dead data path → FellOpenToDirect + status restored to
        // direct (Disconnected, direct_fallback=true).
        let status = fail_after_unexpected_exit(false).await;
        assert!(
            status.direct_fallback,
            "fail-open should report direct fallback"
        );
        assert_eq!(status.state, TunnelState::Disconnected);
    }

    #[tokio::test]
    async fn unexpected_exit_fails_closed_when_configured() {
        // Per-profile fail-closed override: same loud event, but status is Failed (blocked),
        // not direct fallback. (Active traffic blocking is the deferred platform piece.)
        let status = fail_after_unexpected_exit(true).await;
        assert!(
            !status.direct_fallback,
            "fail-closed should NOT report direct fallback"
        );
        assert_eq!(status.state, TunnelState::Failed);
    }
}
