//! Unprivileged lifecycle adapter for Spark connection sharing.

mod freddie;

use std::sync::Arc;
use std::time::Duration;

use lantern_unbounded::peer_proxy::PeerProxyConfig;
use lantern_unbounded::signaling::Signaler;
use lantern_unbounded::supervisor::supervise_peer_proxy_pool;
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

pub use freddie::{FreddieBuildError, FreddieSignaler};
pub use lantern_unbounded::supervisor::{
    PoolEvent, SupervisorEvent, SupervisorPoolSummary, SupervisorSummary,
};

/// Runtime settings for the peer-proxy sharing pool.
#[derive(Debug, Clone)]
pub struct SharingConfig {
    /// Infrastructure egress WebSocket URL.
    pub egress_url: String,
    /// STUN servers used to gather peer-facing ICE candidates.
    pub stun_urls: Vec<String>,
    /// Number of independent censored-user sessions to advertise concurrently.
    /// Zero is clamped to one so starting sharing always creates a usable pool.
    pub concurrent_sessions: usize,
    /// Maximum time to wait for a consumer's WebRTC DataChannel to open.
    pub nat_timeout: Duration,
    /// Initial delay after a failed or completed sharing attempt.
    pub initial_backoff: Duration,
    /// Maximum retry delay, before bounded jitter is applied.
    pub max_backoff: Duration,
    /// Relay duration after which retry backoff returns to its initial value.
    pub stable_session: Duration,
    /// Whether local IPv6 ICE candidates may be advertised.
    pub enable_ipv6: bool,
    /// Whether to randomize the DTLS ClientHello fingerprint.
    pub randomize_dtls: bool,
}

impl SharingConfig {
    fn supervisor_config(
        &self,
        signaler: Arc<dyn Signaler>,
    ) -> lantern_unbounded::supervisor::SupervisorConfig {
        lantern_unbounded::supervisor::SupervisorConfig {
            peer_proxy: PeerProxyConfig {
                signaler,
                egress_url: self.egress_url.clone(),
                stun_urls: self.stun_urls.clone(),
                nat_timeout: self.nat_timeout,
                enable_ipv6: self.enable_ipv6,
                randomize_dtls: self.randomize_dtls,
            },
            initial_backoff: self.initial_backoff,
            max_backoff: self.max_backoff,
            stable_session: self.stable_session,
        }
    }
}

/// A running connection-sharing pool owned by an unprivileged Spark frontend.
///
/// Call [`SharingHandle::stop`] during orderly shutdown. Call [`SharingHandle::cancel`]
/// when another task will await the handle later.
#[derive(Debug)]
pub struct SharingHandle {
    cancellation: CancellationToken,
    task: Option<JoinHandle<SupervisorPoolSummary>>,
}

impl SharingHandle {
    /// Requests cancellation without waiting for active WebRTC sessions to close.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Waits for the sharing pool to finish without initiating cancellation.
    pub async fn wait(mut self) -> Result<SupervisorPoolSummary, JoinError> {
        self.task.take().expect("sharing task is present").await
    }

    /// Cancels every sharing slot, waits for cleanup, and returns aggregate counters.
    pub async fn stop(mut self) -> Result<SupervisorPoolSummary, JoinError> {
        self.cancellation.cancel();
        self.task.take().expect("sharing task is present").await
    }
}

impl Drop for SharingHandle {
    fn drop(&mut self) {
        // Cooperative cancellation only — the supervisor observes the token at its await points and
        // winds down gracefully (closing WebRTC sessions + emitting `Stopped`); the runtime keeps
        // polling it after this returns. Do NOT `abort()` here: that truncates the graceful shutdown
        // (verified by `dropping_the_handle_cancels_the_pool`, which requires the `Stopped` event).
        self.cancellation.cancel();
    }
}

/// Starts an unprivileged pool of peer-proxy sharing sessions on the current Tokio runtime.
///
/// Signaling is injected so a Spark frontend can use its approved HTTP/TLS stack without
/// pulling Unbounded's standalone `reqwest` client into the application.
///
/// # Examples
///
/// ```no_run
/// # use std::{sync::Arc, time::Duration};
/// # use lantern_unbounded::signaling::Signaler;
/// # use spark_sharing::{start_sharing, SharingConfig};
/// # fn start(signaler: Arc<dyn Signaler>) {
/// let handle = start_sharing(
///     SharingConfig {
///         egress_url: "wss://egress.example/ws".into(),
///         stun_urls: vec!["stun:stun.example:3478".into()],
///         concurrent_sessions: 5,
///         nat_timeout: Duration::from_secs(10),
///         initial_backoff: Duration::from_secs(1),
///         max_backoff: Duration::from_secs(30),
///         stable_session: Duration::from_secs(30),
///         enable_ipv6: false,
///         randomize_dtls: true,
///     },
///     signaler,
///     None,
/// );
/// handle.cancel();
/// # }
/// ```
pub fn start_sharing(
    config: SharingConfig,
    signaler: Arc<dyn Signaler>,
    events: Option<mpsc::UnboundedSender<PoolEvent>>,
) -> SharingHandle {
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let slots = config.concurrent_sessions.max(1);
    let supervisor = config.supervisor_config(signaler);
    let task = tokio::spawn(async move {
        supervise_peer_proxy_pool(supervisor, slots, task_cancellation, events).await
    });
    SharingHandle {
        cancellation,
        task: Some(task),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use lantern_unbounded::signaling::SignalingError;
    use lantern_unbounded::{SignalMessage, SignalMessageType};

    use super::*;

    #[derive(Debug, Default)]
    struct TestSignaler {
        exchanges: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Signaler for TestSignaler {
        async fn exchange(
            &self,
            _send_to: &str,
            _kind: SignalMessageType,
            _payload: &str,
        ) -> Result<Option<SignalMessage>, SignalingError> {
            self.exchanges.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
    }

    fn config() -> SharingConfig {
        SharingConfig {
            egress_url: "ws://127.0.0.1:1/ws".into(),
            stun_urls: Vec::new(),
            concurrent_sessions: 1,
            nat_timeout: Duration::from_millis(10),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(1),
            stable_session: Duration::from_secs(1),
            enable_ipv6: false,
            randomize_dtls: false,
        }
    }

    #[tokio::test]
    async fn starts_emits_and_stops_the_unprivileged_pool() {
        let signaler = Arc::new(TestSignaler::default());
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let handle = start_sharing(config(), signaler.clone(), Some(events_tx));

        let first = tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
            .await
            .unwrap();
        assert!(matches!(
            first,
            Some(PoolEvent {
                slot: 0,
                event: SupervisorEvent::AttemptStarted { attempt: 1 }
            })
        ));
        let second = tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
            .await
            .unwrap();
        assert!(matches!(
            second,
            Some(PoolEvent {
                slot: 0,
                event: SupervisorEvent::AttemptFailed { attempt: 1, .. }
            })
        ));

        let summary = tokio::time::timeout(Duration::from_secs(5), handle.stop())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(summary.attempts(), 1);
        assert_eq!(summary.failed_attempts(), 1);
        assert_eq!(signaler.exchanges.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dropping_the_handle_cancels_the_pool() {
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let handle = start_sharing(config(), Arc::new(TestSignaler::default()), Some(events_tx));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
                .await
                .unwrap(),
            Some(PoolEvent {
                event: SupervisorEvent::AttemptStarted { .. },
                ..
            })
        ));

        drop(handle);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events_rx.recv().await {
                    Some(PoolEvent {
                        event: SupervisorEvent::Stopped { .. },
                        ..
                    }) => break,
                    Some(_) => {}
                    None => panic!("sharing event stream closed before the pool stopped"),
                }
            }
        })
        .await
        .expect("dropped sharing handle did not stop the pool");
    }
}
