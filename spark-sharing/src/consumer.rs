use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use lantern_unbounded::signaling::ConsumerSignaler;
use lantern_unbounded::{
    maintain_consumer, ConsumerConfig, ConsumerEvent, ConsumerQuicBroker, ConsumerQuicDialer,
    ConsumerQuicError, ConsumerQuicServer, ConsumerQuicStream, ConsumerSocks5Error,
    ConsumerSummary, ConsumerSupervisorConfig, Socks5Target, SyntheticPathAllocator,
    VirtualUdpSocket,
};
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "spark-transport")]
use async_trait::async_trait;
#[cfg(feature = "spark-transport")]
use spark_core::transport::{Address, Transport};
#[cfg(feature = "spark-transport")]
use spark_core::BoxedStream;

const DEFAULT_LOCAL_PORT: u16 = 443;
const DEFAULT_PATH_QUEUE_CAPACITY: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum ConsumerTlsError {
    #[error("failed to generate an ephemeral consumer certificate: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("failed to build the consumer TLS configuration: {0}")]
    Rustls(#[from] quinn::rustls::Error),
    #[error("failed to build the consumer QUIC crypto configuration: {0}")]
    QuicCrypto(String),
}

pub fn ephemeral_quic_server_config() -> Result<quinn::ServerConfig, ConsumerTlsError> {
    let identity = rcgen::generate_simple_self_signed(vec!["unbounded.invalid".into()])?;
    let key = PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der());
    let cert = CertificateDer::from(identity.cert);
    let mut crypto = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())?;
    crypto.alpn_protocols = vec![lantern_unbounded::CONSUMER_QUIC_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|error| ConsumerTlsError::QuicCrypto(error.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Configuration for the censored-user Unbounded runtime.
#[derive(Debug, Clone)]
pub struct ConsumerRuntimeConfig {
    /// QUIC server identity and transport settings presented to the Go egress.
    pub quic_server_config: quinn::ServerConfig,
    /// Synthetic address exposed by the stable virtual UDP socket.
    pub local_address: SocketAddr,
    /// Stable identifier used by replacement peers to rejoin this consumer.
    pub consumer_session_id: String,
    /// ICE STUN URLs used to discover peer-reachable candidates.
    pub stun_urls: Vec<String>,
    /// Optional application tag included in Freddie advertisements.
    pub tag: String,
    /// Number of independent peer paths advertised concurrently.
    pub concurrent_sessions: usize,
    /// Time allowed for additional ICE candidates after the first candidate.
    pub candidate_patience: Duration,
    /// Maximum time to wait for a peer DataChannel to open.
    pub nat_timeout: Duration,
    /// Delay before a failed or completed path is advertised again.
    pub retry_delay: Duration,
    /// Datagram capacity reserved for each virtual peer path.
    pub path_queue_capacity: usize,
    /// Whether local IPv6 ICE candidates may be advertised.
    pub enable_ipv6: bool,
}

impl ConsumerRuntimeConfig {
    pub fn new(
        quic_server_config: quinn::ServerConfig,
        consumer_session_id: impl Into<String>,
    ) -> Self {
        Self {
            quic_server_config,
            local_address: SocketAddr::new(Ipv4Addr::new(100, 64, 0, 1).into(), DEFAULT_LOCAL_PORT),
            consumer_session_id: consumer_session_id.into(),
            stun_urls: Vec::new(),
            tag: String::new(),
            concurrent_sessions: 5,
            candidate_patience: Duration::from_millis(500),
            nat_timeout: Duration::from_secs(5),
            retry_delay: Duration::from_secs(1),
            path_queue_capacity: DEFAULT_PATH_QUEUE_CAPACITY,
            enable_ipv6: false,
        }
    }
}

#[derive(Debug)]
pub struct ConsumerPoolEvent {
    pub slot: usize,
    pub event: ConsumerEvent,
}

#[derive(Debug)]
pub struct ConsumerRuntimeSummary {
    pub sessions: Vec<ConsumerSummary>,
}

impl ConsumerRuntimeSummary {
    pub fn attempts(&self) -> u64 {
        self.sessions.iter().map(|summary| summary.attempts).sum()
    }

    pub fn completed_paths(&self) -> u64 {
        self.sessions
            .iter()
            .map(|summary| summary.completed_paths)
            .sum()
    }

    pub fn failed_attempts(&self) -> u64 {
        self.sessions
            .iter()
            .map(|summary| summary.failed_attempts)
            .sum()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConsumerRuntimeError {
    #[error("consumer runtime task failed: {0}")]
    Join(#[from] JoinError),
    #[error("consumer QUIC broker failed: {0}")]
    Quic(#[from] ConsumerQuicError),
}

#[derive(Debug)]
pub struct ConsumerHandle {
    cancellation: CancellationToken,
    dialer: ConsumerQuicDialer,
    broker_task: Option<JoinHandle<Result<(), ConsumerQuicError>>>,
    session_task: Option<JoinHandle<Result<Vec<ConsumerSummary>, JoinError>>>,
}

impl ConsumerHandle {
    pub fn dialer(&self) -> ConsumerQuicDialer {
        self.dialer.clone()
    }

    #[cfg(feature = "spark-transport")]
    pub fn transport(&self) -> ConsumerTransport {
        ConsumerTransport {
            dialer: self.dialer.clone(),
            cancellation: self.cancellation.clone(),
        }
    }

    pub async fn dial(
        &self,
        target: impl Into<Socks5Target>,
    ) -> Result<ConsumerQuicStream, ConsumerSocks5Error> {
        let target = target.into();
        self.dialer
            .connect_socks5(&target, &self.cancellation)
            .await
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn stop(mut self) -> Result<ConsumerRuntimeSummary, ConsumerRuntimeError> {
        self.cancellation.cancel();
        let sessions = self
            .session_task
            .take()
            .expect("consumer session task is present")
            .await;
        let broker = self
            .broker_task
            .take()
            .expect("consumer broker task is present")
            .await;
        let sessions = sessions??;
        broker??;
        Ok(ConsumerRuntimeSummary { sessions })
    }
}

#[cfg(feature = "spark-transport")]
#[derive(Debug, Clone)]
pub struct ConsumerTransport {
    dialer: ConsumerQuicDialer,
    cancellation: CancellationToken,
}

#[cfg(feature = "spark-transport")]
#[async_trait]
impl Transport for ConsumerTransport {
    async fn dial(&self, target: SocketAddr) -> std::io::Result<BoxedStream> {
        self.dial_target(Socks5Target::Ip(target)).await
    }

    async fn dial_addr(&self, target: Address) -> std::io::Result<BoxedStream> {
        let target = match target {
            Address::Ip(address) => Socks5Target::Ip(address),
            Address::Domain { host, port } => Socks5Target::Domain { host, port },
        };
        self.dial_target(target).await
    }
}

/// The refusal both `UdpTransport` methods return.
///
/// `ErrorKind::Unsupported`, deliberately, NOT `Error::other`: spark's selecting pool reads
/// `Unsupported` as a statement about what a member *can carry* and moves to the next one, while any
/// other error is read as ill health and **demotes** the member. Since a capability never comes back,
/// that demotion is permanent, and the ranking it feeds is shared with TCP — so getting this wrong
/// would rank a perfectly healthy consumer last for the TCP it serves fine. This exact conflation was
/// already observed in the field with the shadowsocks members (see `select.rs`'s `dial_udp`).
#[cfg(feature = "spark-transport")]
fn unsupported_udp() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unbounded: UDP is not supported (the egress relays SOCKS5 CONNECT only)",
    )
}

/// Unbounded carries **no UDP**. The egress relays each peer session to a SOCKS5 upstream and the
/// consumer only ever issues `CONNECT` (`consumer_socks5.rs` writes CMD `0x01`; there is no UDP
/// ASSOCIATE), so there is no datagram path to offer. Spelled out on both methods rather than
/// delegated: `dial_udp_addr` has no default, and a transport must state what it can carry.
///
/// A pool member that refuses UDP is not a broken member — the selecting transport falls back for
/// UDP flows exactly as it does for a TCP dial failure.
#[cfg(feature = "spark-transport")]
#[async_trait]
impl spark_core::transport::UdpTransport for ConsumerTransport {
    async fn dial_udp_addr(
        &self,
        _target: Address,
    ) -> std::io::Result<(
        spark_core::transport::BoxedPacketSink,
        spark_core::transport::BoxedPacketSource,
    )> {
        Err(unsupported_udp())
    }

    async fn dial_udp(
        &self,
        _target: SocketAddr,
    ) -> std::io::Result<(
        spark_core::transport::BoxedPacketSink,
        spark_core::transport::BoxedPacketSource,
    )> {
        Err(unsupported_udp())
    }
}

#[cfg(feature = "spark-transport")]
impl ConsumerTransport {
    async fn dial_target(&self, target: Socks5Target) -> std::io::Result<BoxedStream> {
        self.dialer
            .connect_socks5(&target, &self.cancellation)
            .await
            .map(|stream| Box::new(stream) as BoxedStream)
            .map_err(std::io::Error::other)
    }
}

impl Drop for ConsumerHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn join_all<T>(tasks: Vec<JoinHandle<T>>) -> Result<Vec<T>, JoinError> {
    let mut values = Vec::with_capacity(tasks.len());
    let mut first_join_error = None;
    for task in tasks {
        match task.await {
            Ok(value) => values.push(value),
            Err(error) if first_join_error.is_none() => first_join_error = Some(error),
            Err(_) => {}
        }
    }
    match first_join_error {
        Some(error) => Err(error),
        None => Ok(values),
    }
}

pub fn start_consumer(
    config: ConsumerRuntimeConfig,
    signaler: Arc<dyn ConsumerSignaler>,
    events: Option<mpsc::UnboundedSender<ConsumerPoolEvent>>,
) -> Result<ConsumerHandle, ConsumerQuicError> {
    let socket = VirtualUdpSocket::new(config.local_address);
    let path_allocator = Arc::new(SyntheticPathAllocator::new());
    let server = Arc::new(ConsumerQuicServer::new(
        socket.clone(),
        config.quic_server_config,
    )?);
    let broker = ConsumerQuicBroker::new(server);
    let dialer = broker.dialer();
    let cancellation = CancellationToken::new();
    let broker_task = tokio::spawn(broker.run(cancellation.clone()));

    let mut consumer =
        ConsumerConfig::new(signaler, socket, path_allocator, config.consumer_session_id);
    consumer.stun_urls = config.stun_urls;
    consumer.tag = config.tag;
    consumer.patience = config.candidate_patience;
    consumer.nat_timeout = config.nat_timeout;
    consumer.path_queue_capacity = config.path_queue_capacity;
    consumer.enable_ipv6 = config.enable_ipv6;
    let supervisor = ConsumerSupervisorConfig {
        consumer,
        retry_delay: config.retry_delay,
    };
    let slots = config.concurrent_sessions.max(1);
    let session_cancellation = cancellation.clone();
    let session_task = tokio::spawn(async move {
        let mut tasks = Vec::with_capacity(slots);
        for slot in 0..slots {
            let supervisor = supervisor.clone();
            let cancellation = session_cancellation.clone();
            let events = events.clone();
            tasks.push(tokio::spawn(async move {
                let (slot_events, mut event_rx) = mpsc::unbounded_channel();
                let session = maintain_consumer(supervisor, cancellation, Some(slot_events));
                tokio::pin!(session);
                loop {
                    tokio::select! {
                        summary = &mut session => {
                            while let Ok(event) = event_rx.try_recv() {
                                if let Some(events) = &events {
                                    // Best-effort telemetry: a dropped receiver must NOT stop the
                                    // pool serving traffic, so a closed channel is intentionally
                                    // ignored rather than propagated.
                                    let _ = events.send(ConsumerPoolEvent { slot, event });
                                }
                            }
                            return summary;
                        }
                        event = event_rx.recv() => match event {
                            Some(event) => {
                                if let Some(events) = &events {
                                    // Best-effort telemetry: a dropped receiver must NOT stop the
                                    // pool serving traffic, so a closed channel is intentionally
                                    // ignored rather than propagated.
                                    let _ = events.send(ConsumerPoolEvent { slot, event });
                                }
                            }
                            None => return session.await,
                        }
                    }
                }
            }));
        }
        join_all(tasks).await
    });

    Ok(ConsumerHandle {
        cancellation,
        dialer,
        broker_task: Some(broker_task),
        session_task: Some(session_task),
    })
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use lantern_unbounded::signaling::{AdvertisementSource, Signaler, SignalingError};
    use lantern_unbounded::{SignalMessage, SignalMessageType};

    use super::*;

    #[tokio::test]
    async fn joins_every_slot_after_an_earlier_join_error() {
        let later_task_completed = Arc::new(AtomicBool::new(false));
        let later_task_flag = later_task_completed.clone();
        let tasks = vec![
            tokio::spawn(async { panic!("simulated consumer slot panic") }),
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                later_task_flag.store(true, Ordering::SeqCst);
            }),
        ];

        assert!(join_all(tasks).await.is_err());
        assert!(later_task_completed.load(Ordering::SeqCst));
    }

    struct PendingAdvertisements;

    #[async_trait]
    impl AdvertisementSource for PendingAdvertisements {
        async fn next(&mut self) -> Result<Option<SignalMessage>, SignalingError> {
            std::future::pending().await
        }
    }

    #[derive(Clone)]
    struct TestSignaler;

    impl fmt::Debug for TestSignaler {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("TestSignaler")
        }
    }

    #[async_trait]
    impl Signaler for TestSignaler {
        async fn exchange(
            &self,
            _send_to: &str,
            _kind: SignalMessageType,
            _payload: &str,
        ) -> Result<Option<SignalMessage>, SignalingError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl ConsumerSignaler for TestSignaler {
        async fn advertisements(&self) -> Result<Box<dyn AdvertisementSource>, SignalingError> {
            Ok(Box::new(PendingAdvertisements))
        }
    }

    fn server_config() -> quinn::ServerConfig {
        ephemeral_quic_server_config().unwrap()
    }

    #[tokio::test]
    async fn starts_all_consumer_slots_and_stops_cleanly() {
        let mut config = ConsumerRuntimeConfig::new(server_config(), "stable-session-id");
        config.concurrent_sessions = 2;
        let (events, mut event_rx) = mpsc::unbounded_channel();
        let handle = start_consumer(config, Arc::new(TestSignaler), Some(events)).unwrap();

        let mut started_slots = Vec::new();
        for _ in 0..2 {
            let event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
                .await
                .unwrap()
                .unwrap();
            started_slots.push(event.slot);
            assert!(matches!(
                event.event,
                ConsumerEvent::AttemptStarted { attempt: 1 }
            ));
        }
        started_slots.sort_unstable();
        assert_eq!(started_slots, [0, 1]);

        let summary = tokio::time::timeout(Duration::from_secs(2), handle.stop())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(summary.sessions.len(), 2);
        assert_eq!(summary.attempts(), 2);
        assert_eq!(summary.failed_attempts(), 0);
    }

    /// The refusal's *kind* is load-bearing, not cosmetic: spark's selecting pool demotes a member
    /// that returns anything but `Unsupported` from a UDP dial, permanently and for TCP too. A
    /// refactor that reached for the more idiomatic-looking `Error::other` would silently rank a
    /// healthy consumer last, with nothing failing to show it.
    #[cfg(feature = "spark-transport")]
    #[test]
    fn the_udp_refusal_is_unsupported_not_a_generic_error() {
        let e = super::unsupported_udp();
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::Unsupported,
            "the pool reads any other kind as ill health and demotes the member"
        );
    }
}
