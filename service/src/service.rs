//! The control-plane event loop (the "actor").
//!
//! One task owns all tunnel state and the subscriber set; connections never share that state
//! — they send an [`Envelope`] (request + reply channel) over an mpsc and await the reply.
//! This is the channels-over-locks shape from CLAUDE.md (no `Arc<Mutex<state>>`) and mirrors
//! Mullvad's daemon command loop. State transitions broadcast a [`Push`] to subscribers.

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use spark_core::caps;
use spark_core::config::{Config, StackKind};
use spark_ipc::{
    negotiate, Capabilities, Details, ErrorCode, KillSwitchMode, NetStack, ProtocolVersion, Push,
    Request, RequestPayload, Response, ResponsePayload, TransportKind, TunnelEvent, TunnelState,
    TunnelStatus, PROTOCOL_VERSION,
};

use crate::engine::{Teardown, TunnelEngine};

/// Depth of the command channel feeding the event loop.
const COMMAND_DEPTH: usize = 64;

/// Static backend facts the event loop reports for the v2 read-only requests (ADR 0004): the build's
/// [`Capabilities`] plus the active config's selected transport/stack. Computed once at startup
/// (config is fixed for the daemon's lifetime); the loop overlays its live state for `GetDetails`.
#[derive(Debug, Clone, Default)]
pub struct BackendInfo {
    /// What this build supports (compiled features + platform).
    pub capabilities: Capabilities,
    /// The transport the active config selects.
    pub selected_transport: TransportKind,
    /// The netstack the active config selects.
    pub selected_stack: NetStack,
}

/// Derive the [`BackendInfo`] from the loaded config + this build's compiled [`caps`].
pub fn backend_info(config: &Config) -> BackendInfo {
    let c = caps::compiled();
    let mut transports = vec![TransportKind::Direct, TransportKind::Plain];
    if c.anytls {
        transports.push(TransportKind::Anytls);
    }
    if c.wasm_transport {
        transports.push(TransportKind::Wasm);
    }
    let mut stacks = vec![NetStack::Userspace];
    if c.system_stack {
        stacks.push(NetStack::System);
    }
    BackendInfo {
        capabilities: Capabilities {
            protocol_version: PROTOCOL_VERSION,
            build_version: env!("CARGO_PKG_VERSION").to_owned(),
            transports,
            stacks,
            platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        },
        selected_transport: selected_transport(config),
        selected_stack: netstack_of(config),
    }
}

/// Which transport the config selects (precedence mirrors `transport::from_config`: anytls > wasm >
/// plain server > direct).
pub(crate) fn selected_transport(config: &Config) -> TransportKind {
    let t = &config.transport;
    if t.anytls.is_some() {
        TransportKind::Anytls
    } else if t.wasm.is_some() {
        TransportKind::Wasm
    } else if t.server.is_some() {
        TransportKind::Plain
    } else {
        TransportKind::Direct
    }
}

/// Which netstack the config selects.
pub(crate) fn netstack_of(config: &Config) -> NetStack {
    match config.tun.stack {
        StackKind::System => NetStack::System,
        StackKind::Userspace => NetStack::Userspace,
    }
}

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
    info: BackendInfo,
) {
    let mut state = TunnelState::Disconnected;
    let mut direct_fallback = false;
    // `None` until the `Hello` handshake completes; then the negotiated protocol version (gates the
    // v2-only requests so we never answer a v1 peer with a frame it can't decode).
    let mut negotiated: Option<ProtocolVersion> = None;
    // The most recent error surfaced (for `GetDetails.last_error`); cleared on a successful connect.
    let mut last_error: Option<String> = None;
    // Stored connection profiles (ADR 0004 slice 3; in-memory for now).
    let mut profiles = crate::profiles::ProfileStore::default();
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
                            Some(neg) => {
                                negotiated = Some(neg);
                                ResponsePayload::Hello {
                                    service_version: PROTOCOL_VERSION,
                                    negotiated: neg,
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
                    _ if negotiated.is_none() => ResponsePayload::Error {
                        code: ErrorCode::InvalidRequest,
                        message: "Hello handshake required before commands".into(),
                    },
                    // v2-only requests: refuse on a v1-negotiated peer rather than send a frame it
                    // can't decode (ADR 0004 — never emit above the negotiated version).
                    RequestPayload::GetCapabilities
                    | RequestPayload::GetDetails
                    | RequestPayload::GetMetrics
                    | RequestPayload::ListProfiles
                    | RequestPayload::GetProfile { .. }
                    | RequestPayload::SetProfile { .. }
                    | RequestPayload::DeleteProfile { .. }
                    | RequestPayload::SetActiveProfile { .. }
                    | RequestPayload::ValidateProfile { .. }
                        if negotiated < Some(2) =>
                    {
                        ResponsePayload::Error {
                            code: ErrorCode::InvalidRequest,
                            message: "request requires protocol version 2".into(),
                        }
                    }
                    RequestPayload::GetCapabilities => {
                        ResponsePayload::Capabilities(info.capabilities.clone())
                    }
                    RequestPayload::GetDetails => ResponsePayload::Details(Details {
                        state,
                        direct_fallback,
                        selected_transport: info.selected_transport,
                        selected_stack: info.selected_stack,
                        module: None, // live module name/version is a later slice
                        kill_switch: if fail_closed {
                            KillSwitchMode::FailClosed
                        } else {
                            KillSwitchMode::FailOpen
                        },
                        last_error: last_error.clone(),
                    }),
                    RequestPayload::GetMetrics => {
                        let m = engine.metrics();
                        ResponsePayload::Metrics(spark_ipc::Metrics {
                            bytes_up: m.bytes_up,
                            bytes_down: m.bytes_down,
                            sessions_active: m.sessions_active,
                            sessions_total: m.sessions_total,
                        })
                    }
                    RequestPayload::ListProfiles => ResponsePayload::Profiles(profiles.list()),
                    RequestPayload::GetProfile { name } => match profiles.get_redacted(&name) {
                        Some(doc) => ResponsePayload::Profile(doc),
                        None => ResponsePayload::Error {
                            code: ErrorCode::InvalidRequest,
                            message: format!("no such profile: {name}"),
                        },
                    },
                    RequestPayload::SetProfile { name, toml } => match profiles.set(&name, &toml) {
                        Ok(()) => ResponsePayload::Ack,
                        Err(e) => ResponsePayload::Error {
                            code: ErrorCode::InvalidRequest,
                            message: e,
                        },
                    },
                    RequestPayload::DeleteProfile { name } => {
                        profiles.delete(&name);
                        ResponsePayload::Ack
                    }
                    RequestPayload::SetActiveProfile { name } => match profiles.set_active(&name) {
                        Ok(()) => ResponsePayload::Ack,
                        Err(e) => ResponsePayload::Error {
                            code: ErrorCode::InvalidRequest,
                            message: e,
                        },
                    },
                    RequestPayload::ValidateProfile { toml } => {
                        ResponsePayload::Validated(crate::profiles::validate(&toml))
                    }
                    RequestPayload::Connect => {
                        // Announce the in-progress state before the (possibly slow) bring-up, so a
                        // subscribed UI can show "Connecting…" while `start` runs.
                        transition(&mut state, TunnelState::Connecting, &mut subscribers);
                        match engine.start(exit_tx.clone()).await {
                            Ok(()) => {
                                direct_fallback = false;
                                last_error = None;
                                transition(&mut state, TunnelState::Connected, &mut subscribers);
                                ResponsePayload::Ack
                            }
                            Err(e) => {
                                let message = e.to_string();
                                last_error = Some(message.clone());
                                transition(&mut state, TunnelState::Failed, &mut subscribers);
                                ResponsePayload::Error {
                                    code: ErrorCode::Internal,
                                    message,
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
                    last_error = Some(format!(
                        "tunnel exited unexpectedly; failed {}",
                        if fail_closed { "closed" } else { "open" }
                    ));
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
        let handle = tokio::spawn(run_service(
            FakeEngine::default(),
            cmd_rx,
            false,
            BackendInfo::default(),
        ));
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
    async fn capabilities_and_details_reflect_backend_info() {
        let info = BackendInfo {
            capabilities: Capabilities {
                protocol_version: PROTOCOL_VERSION,
                build_version: "x".to_owned(),
                transports: vec![TransportKind::Direct, TransportKind::Plain],
                stacks: vec![NetStack::Userspace],
                platform: "p".to_owned(),
            },
            selected_transport: TransportKind::Plain,
            selected_stack: NetStack::Userspace,
        };
        let (cmd, cmd_rx) = channel();
        let handle = tokio::spawn(run_service(FakeEngine::default(), cmd_rx, false, info));
        let (push_tx, _rx) = mpsc::channel::<Push>(4);

        request(
            &cmd,
            &push_tx,
            RequestPayload::Hello {
                client_version: PROTOCOL_VERSION,
            },
        )
        .await;
        match request(&cmd, &push_tx, RequestPayload::GetCapabilities).await {
            ResponsePayload::Capabilities(c) => {
                assert_eq!(c.protocol_version, PROTOCOL_VERSION);
                assert_eq!(
                    c.transports,
                    vec![TransportKind::Direct, TransportKind::Plain]
                );
            }
            other => panic!("expected Capabilities, got {other:?}"),
        }
        match request(&cmd, &push_tx, RequestPayload::GetDetails).await {
            ResponsePayload::Details(d) => {
                assert_eq!(d.selected_transport, TransportKind::Plain);
                assert_eq!(d.kill_switch, KillSwitchMode::FailOpen);
            }
            other => panic!("expected Details, got {other:?}"),
        }
        // FakeEngine reports zero metrics; this just proves the GetMetrics path + mapping.
        match request(&cmd, &push_tx, RequestPayload::GetMetrics).await {
            ResponsePayload::Metrics(m) => assert_eq!(m, spark_ipc::Metrics::default()),
            other => panic!("expected Metrics, got {other:?}"),
        }
        drop(cmd);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn v2_requests_are_refused_on_a_v1_peer() {
        let (cmd, cmd_rx) = channel();
        let handle = tokio::spawn(run_service(
            FakeEngine::default(),
            cmd_rx,
            false,
            BackendInfo::default(),
        ));
        let (push_tx, _rx) = mpsc::channel::<Push>(4);
        // A v1 client negotiates v1; the v2-only requests must be refused, not answered with a
        // frame it can't decode.
        request(&cmd, &push_tx, RequestPayload::Hello { client_version: 1 }).await;
        assert!(matches!(
            request(&cmd, &push_tx, RequestPayload::GetCapabilities).await,
            ResponsePayload::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ));
        drop(cmd);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn profile_crud_through_the_actor_redacts_secrets() {
        let (cmd, cmd_rx) = channel();
        let handle = tokio::spawn(run_service(
            FakeEngine::default(),
            cmd_rx,
            false,
            BackendInfo::default(),
        ));
        let (push_tx, _rx) = mpsc::channel::<Push>(4);
        request(
            &cmd,
            &push_tx,
            RequestPayload::Hello {
                client_version: PROTOCOL_VERSION,
            },
        )
        .await;

        let toml =
            "[transport.anytls]\nserver = \"1.2.3.4:443\"\npassword = \"s3cret\"\n".to_owned();
        assert!(matches!(
            request(
                &cmd,
                &push_tx,
                RequestPayload::SetProfile {
                    name: "home".into(),
                    toml,
                },
            )
            .await,
            ResponsePayload::Ack
        ));
        match request(&cmd, &push_tx, RequestPayload::ListProfiles).await {
            ResponsePayload::Profiles(ps) => {
                assert!(ps.iter().any(|p| p.name == "home" && p.has_password));
            }
            other => panic!("expected Profiles, got {other:?}"),
        }
        match request(
            &cmd,
            &push_tx,
            RequestPayload::GetProfile {
                name: "home".into(),
            },
        )
        .await
        {
            ResponsePayload::Profile(d) => {
                assert!(!d.toml.contains("s3cret"), "the password must be redacted");
            }
            other => panic!("expected Profile, got {other:?}"),
        }
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
