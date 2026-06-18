//! End-to-end control test: drives the real `Backend` against a mock `spark-service` responder
//! that speaks the actual `spark-ipc` wire protocol over a unix socket. No dependency on
//! `spark-service` — the mock answers the handshake + commands directly with `read_frame`/
//! `write_frame`, so this exercises `Backend` ↔ `ipc::Client` over a real transport.

use spark_ffi::{BackendError, TunnelEvent, TunnelState};

/// `From<spark_ipc::ErrorCode>` maps service error categories to typed `BackendError`s (pure; no
/// socket needed, runs on every platform).
#[test]
fn error_codes_map_to_typed_errors() {
    use spark_ipc::ErrorCode;
    assert!(matches!(
        BackendError::from(ErrorCode::NotConnected),
        BackendError::NotConnected
    ));
    assert!(matches!(
        BackendError::from(ErrorCode::Unauthorized),
        BackendError::Unauthorized
    ));
    assert!(matches!(
        BackendError::from(ErrorCode::Internal),
        BackendError::Internal { .. }
    ));
}

#[cfg(unix)]
mod unix_e2e {
    use super::*;
    use spark_ffi::{Backend, EventListener};
    use spark_ipc::{
        read_frame, write_frame, Push, Request, RequestPayload, Response, ResponsePayload,
        ServerMessage, TunnelStatus as IpcStatus, PROTOCOL_VERSION,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A test event sink that records what it's pushed.
    struct Recorder {
        events: Arc<Mutex<Vec<TunnelEvent>>>,
    }
    impl EventListener for Recorder {
        fn on_event(&self, event: TunnelEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    /// Mock service: handshake, then `Connect`/`Disconnect`→Ack, `GetStatus`→Connected,
    /// `Subscribe`→Ack then push one `StateChanged(Connected)` event.
    async fn handle_conn(mut stream: tokio::net::UnixStream) {
        while let Ok(Some(req)) = read_frame::<_, Request>(&mut stream).await {
            let req_id = req.req_id;
            let resp = match req.payload {
                RequestPayload::Hello { .. } => ResponsePayload::Hello {
                    service_version: PROTOCOL_VERSION,
                    negotiated: PROTOCOL_VERSION,
                },
                RequestPayload::Connect | RequestPayload::Disconnect => ResponsePayload::Ack,
                RequestPayload::GetStatus => ResponsePayload::Status(IpcStatus {
                    state: spark_ipc::TunnelState::Connected,
                    direct_fallback: false,
                }),
                RequestPayload::Subscribe { .. } => ResponsePayload::Ack,
            };
            let subscribed = matches!(req.payload, RequestPayload::Subscribe { .. });
            if write_frame(
                &mut stream,
                &ServerMessage::Response(Response {
                    req_id,
                    payload: resp,
                }),
            )
            .await
            .is_err()
            {
                return;
            }
            if subscribed {
                let event = spark_ipc::TunnelEvent::StateChanged(spark_ipc::TunnelState::Connected);
                let _ = write_frame(&mut stream, &ServerMessage::Push(Push::Event(event))).await;
            }
        }
    }

    fn wait_for_first(events: &Arc<Mutex<Vec<TunnelEvent>>>) -> Option<TunnelEvent> {
        for _ in 0..200 {
            if let Some(e) = events.lock().unwrap().first().cloned() {
                return Some(e);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    #[test]
    fn control_roundtrips_over_a_real_socket() {
        let sock = std::env::temp_dir().join(format!("spk-ffi-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        // Bind here (std, no runtime) so the socket exists before `Backend` connects.
        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        // tokio requires a non-blocking fd when adopting a std listener.
        listener.set_nonblocking(true).expect("nonblocking");

        // Run the mock service on its own thread + runtime.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::UnixListener::from_std(listener).unwrap();
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(handle_conn(stream));
                }
            });
        });

        let backend = Backend::new(sock.to_string_lossy().into_owned()).expect("backend");

        backend.connect().expect("connect");
        assert_eq!(
            backend.status().expect("status").state,
            TunnelState::Connected
        );

        let events = Arc::new(Mutex::new(Vec::new()));
        backend.subscribe(Box::new(Recorder {
            events: Arc::clone(&events),
        }));
        assert_eq!(
            wait_for_first(&events),
            Some(TunnelEvent::StateChanged {
                state: TunnelState::Connected
            }),
            "subscribe must deliver the pushed event"
        );

        backend.disconnect().expect("disconnect");
        backend.unsubscribe();
        drop(backend);
        let _ = std::fs::remove_file(&sock);
    }
}
