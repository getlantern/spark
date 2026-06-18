//! End-to-end control tests: drive the real `Backend` against a mock `spark-service` responder
//! that speaks the actual `spark-ipc` wire protocol. No dependency on `spark-service` — the mock
//! answers the handshake + commands directly with `read_frame`/`write_frame`, so this exercises
//! `Backend` ↔ `ipc::Client` over a real transport (a unix-domain socket on unix, a named pipe on
//! Windows). The mock responder is generic over `AsyncRead + AsyncWrite`, so one implementation
//! serves both transports.

use spark_ffi::BackendError;

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

/// Transport-agnostic mock service + `Backend` driver, shared by the unix-socket and named-pipe
/// e2e tests below.
#[cfg(any(unix, windows))]
mod harness {
    use spark_ffi::{Backend, EventListener, TunnelEvent, TunnelState};
    use spark_ipc::{
        read_frame, write_frame, Push, Request, RequestPayload, Response, ResponsePayload,
        ServerMessage, TunnelStatus as IpcStatus, PROTOCOL_VERSION,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite};

    /// A test event sink that records what it's pushed.
    pub(crate) struct Recorder {
        pub(crate) events: Arc<Mutex<Vec<TunnelEvent>>>,
    }
    impl EventListener for Recorder {
        fn on_event(&self, event: TunnelEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    /// Mock service over any byte stream: handshake, then `Connect`/`Disconnect`→Ack,
    /// `GetStatus`→Connected, `Subscribe`→Ack then push one `StateChanged(Connected)` event. When
    /// `close_after_subscribe` is set, the connection drops right after that push — which lets the
    /// reconnect test treat each delivered event as evidence of a fresh session.
    pub(crate) async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        close_after_subscribe: bool,
    ) {
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
                if close_after_subscribe {
                    return;
                }
            }
        }
    }

    /// Poll `events` until at least `n` have arrived (or give up). Returns the count seen.
    pub(crate) async fn wait_for_count(events: &Arc<Mutex<Vec<TunnelEvent>>>, n: usize) -> usize {
        for _ in 0..400 {
            let len = events.lock().unwrap().len();
            if len >= n {
                return len;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        events.lock().unwrap().len()
    }

    /// Poll `events` until one matches `pred` (or give up). Returns whether one was seen.
    // Only the unix-only reconnect test uses this; without the gate it's dead code on Windows.
    #[cfg(unix)]
    pub(crate) async fn wait_for(
        events: &Arc<Mutex<Vec<TunnelEvent>>>,
        pred: impl Fn(&TunnelEvent) -> bool,
    ) -> bool {
        for _ in 0..400 {
            if events.lock().unwrap().iter().any(&pred) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// Drive a `Backend` bound to `endpoint` (a mock responder must already be accepting there):
    /// connect → status(Connected) → subscribe(receives the pushed event) → disconnect.
    pub(crate) async fn drive_backend(endpoint: String) {
        let backend = Backend::new(endpoint).expect("backend");

        backend.connect().await.expect("connect");
        assert_eq!(
            backend.status().await.expect("status").state,
            TunnelState::Connected
        );

        let events = Arc::new(Mutex::new(Vec::new()));
        backend.subscribe(Box::new(Recorder {
            events: Arc::clone(&events),
        }));
        assert_eq!(
            wait_for_count(&events, 1).await,
            1,
            "subscribe must deliver the pushed event"
        );
        assert_eq!(
            events.lock().unwrap()[0],
            TunnelEvent::StateChanged {
                state: TunnelState::Connected
            }
        );

        backend.disconnect().await.expect("disconnect");
        backend.unsubscribe();
        // Backend owns a tokio runtime; dropping it does a blocking worker-thread join, which
        // tokio forbids inside another runtime (here, `#[tokio::test]`'s). Foreign callers drop
        // Backend on an ordinary off-runtime thread and never hit this, so drop on a blocking
        // thread to mirror that.
        tokio::task::spawn_blocking(move || drop(backend))
            .await
            .expect("drop backend off-runtime");
    }
}

#[cfg(unix)]
mod unix_e2e {
    use super::harness;
    use spark_ffi::{Backend, TunnelEvent};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn control_roundtrips_over_a_real_socket() {
        let sock = std::env::temp_dir().join(format!("spk-ffi-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        // tokio's `bind` listens immediately and registers with this test's runtime, so the socket
        // exists before `Backend` (on its own runtime) connects.
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind");
        tokio::spawn(async move {
            // Each control op opens a fresh connection.
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(harness::handle_conn(stream, false));
            }
        });

        harness::drive_backend(sock.to_string_lossy().into_owned()).await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn subscribe_reconnects_after_the_stream_drops() {
        let sock =
            std::env::temp_dir().join(format!("spk-ffi-reconnect-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind");
        // Every accepted connection delivers one Subscribe event then closes.
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(harness::handle_conn(stream, true));
            }
        });

        let backend = Backend::new(sock.to_string_lossy().into_owned()).expect("backend");
        let events = Arc::new(Mutex::new(Vec::new()));
        backend.subscribe(Box::new(harness::Recorder {
            events: Arc::clone(&events),
        }));

        // Each session delivers one StateChanged then the mock closes; a *re*-established session
        // emits StreamReconnected first. Seeing a StreamReconnected proves the subscription
        // reconnected on its own AND surfaced the post-gap resync signal.
        let reconnected =
            harness::wait_for(&events, |e| matches!(e, TunnelEvent::StreamReconnected)).await;
        assert!(
            reconnected,
            "expected a StreamReconnected event after the stream dropped; got {:?}",
            *events.lock().unwrap()
        );
        // The first session's push still arrives as a normal StateChanged (no synthetic reconnect
        // on the initial connect).
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, TunnelEvent::StateChanged { .. })));

        backend.unsubscribe();
        tokio::task::spawn_blocking(move || drop(backend))
            .await
            .expect("drop backend off-runtime");
        let _ = std::fs::remove_file(&sock);
    }
}

#[cfg(windows)]
mod windows_e2e {
    use super::harness;
    use tokio::net::windows::named_pipe::ServerOptions;

    #[tokio::test]
    async fn control_roundtrips_over_a_named_pipe() {
        let name = format!(r"\\.\pipe\spk-ffi-{}", std::process::id());
        // The first instance must exist before the client opens it (avoids a FILE_NOT_FOUND race).
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .expect("create first pipe instance");
        let accept_name = name.clone();
        tokio::spawn(async move {
            loop {
                if server.connect().await.is_err() {
                    return;
                }
                let connected = server;
                // Pre-create the next instance so the next control op finds a free pipe.
                server = match ServerOptions::new().create(&accept_name) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                tokio::spawn(harness::handle_conn(connected, false));
            }
        });

        harness::drive_backend(name).await;
    }
}
