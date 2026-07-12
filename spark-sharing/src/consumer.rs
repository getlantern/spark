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

pub struct ConsumerRuntimeConfig {
    pub quic_server_config: quinn::ServerConfig,
    pub local_address: SocketAddr,
    pub consumer_session_id: String,
    pub stun_urls: Vec<String>,
    pub tag: String,
    pub concurrent_sessions: usize,
    pub candidate_patience: Duration,
    pub nat_timeout: Duration,
    pub retry_delay: Duration,
    pub path_queue_capacity: usize,
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
        self.dialer
            .connect_socks5(&target.into(), &self.cancellation)
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
                                    let _ = events.send(ConsumerPoolEvent { slot, event });
                                }
                            }
                            return summary;
                        }
                        event = event_rx.recv() => match event {
                            Some(event) => {
                                if let Some(events) = &events {
                                    let _ = events.send(ConsumerPoolEvent { slot, event });
                                }
                            }
                            None => return session.await,
                        }
                    }
                }
            }));
        }
        let mut summaries = Vec::with_capacity(slots);
        for task in tasks {
            summaries.push(task.await?);
        }
        Ok(summaries)
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

    use async_trait::async_trait;
    use lantern_unbounded::signaling::{AdvertisementSource, Signaler, SignalingError};
    use lantern_unbounded::{SignalMessage, SignalMessageType};

    use super::*;

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
}
