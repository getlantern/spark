//! The `spark-core` side of the consumer: an [`UnboundedConsumer`] implementation plus
//! [`install`], which registers it into core's transport seam.
//!
//! Core cannot build the consumer itself — it would have to depend on this crate, which already
//! depends on core (see `spark_core::transport::external`'s module docs). So the dependency is
//! inverted: core declares the trait, this crate implements it, and the binary that owns the tunnel
//! calls [`install`] at bringup.
//!
//! Everything here is behind the `spark-transport` feature, so a build that only wants the
//! *volunteer* side (the Tauri plugin) never compiles the `spark-core` edge at all.

use std::sync::{Arc, Mutex};

use spark_core::config::UnboundedConsumerConfig;
use spark_core::transport::external::{set_unbounded_consumer, UnboundedConsumer};
use spark_core::transport::{Transport, UdpTransport};

use crate::consumer::{
    ephemeral_quic_server_config, start_consumer, ConsumerHandle, ConsumerRuntimeConfig,
};
use crate::freddie::FreddieSignaler;

/// Bytes of randomness behind a consumer session id. 16 bytes is the same width a UUID carries, and
/// the id's only job is to be unguessable and collision-free across the population of consumers that
/// signaling sees at once.
const SESSION_ID_BYTES: usize = 16;

/// A started consumer runtime, kept alive alongside the transport handed to the pool.
///
/// `ConsumerHandle` cancels its session pool on `Drop`, so it is deliberately held here for as long
/// as this entry is the live one. Dropping it is how a config change tears the old runtime down.
struct Running {
    /// The config this runtime was started for. Compared against the next `build` to decide reuse.
    config: UnboundedConsumerConfig,
    /// Retained for its `Drop`. Never read — the transport below is what carries flows.
    _handle: ConsumerHandle,
    tcp: Arc<dyn Transport>,
    udp: Arc<dyn UdpTransport>,
}

/// Spark's Unbounded consumer: starts (and reuses) a `spark-sharing` consumer runtime on demand.
pub struct SparkUnboundedConsumer {
    /// The live runtime, if one has been started. A `std::sync::Mutex` because `build` is called from
    /// core's synchronous pool-build path; the guard is never held across an `.await` (nothing in
    /// `build` awaits — `start_consumer` spawns and returns).
    running: Mutex<Option<Running>>,
    /// A runtime handle captured at [`install`], if there was one in scope. Used only as the
    /// fallback when `build` cannot find an ambient runtime of its own.
    ///
    /// Both halves are needed because the two hosts install from opposite contexts. `spark-service`
    /// installs from inside its runtime, so a handle is available. The Apple/Android FFI installs
    /// from a **synchronous** C-ABI/JNI entry point — `fd_tunnel::run_fd_dispatch` builds its own
    /// runtime and `block_on`s it *after* that — so there is nothing to capture there, and
    /// `Handle::current()` would panic. Resolving at `build` instead picks up whichever runtime the
    /// pool is actually being built on, which is also the right one: the consumer's tasks then die
    /// with the tunnel rather than outliving it on a runtime nobody owns.
    installed_runtime: Option<tokio::runtime::Handle>,
}

impl SparkUnboundedConsumer {
    /// Build a consumer, optionally pinned to `runtime`. Prefer [`install`], which also registers it.
    pub fn new(runtime: Option<tokio::runtime::Handle>) -> Self {
        Self {
            running: Mutex::new(None),
            installed_runtime: runtime,
        }
    }

    /// The runtime to spawn the consumer's tasks onto: whichever one this build is happening on,
    /// else the one captured at install. An error rather than a panic, because a missing runtime
    /// makes exactly one pool member unbuildable and the pool skips it like any other.
    fn runtime(&self) -> std::io::Result<tokio::runtime::Handle> {
        tokio::runtime::Handle::try_current()
            .ok()
            .or_else(|| self.installed_runtime.clone())
            .ok_or_else(|| {
                std::io::Error::other(
                    "unbounded: no tokio runtime to spawn the consumer on (install from inside one, \
                     or build on one)",
                )
            })
    }

    /// A fresh, unguessable consumer session id as lowercase hex.
    ///
    /// Peers use this to rejoin an existing consumer when a volunteer drops, so it must be stable for
    /// the life of a runtime (it is generated once per start, not per dial) and unguessable — it is
    /// the only thing naming this consumer on the signaling channel.
    fn new_session_id() -> Result<String, std::io::Error> {
        use ring::rand::SecureRandom;
        let mut raw = [0u8; SESSION_ID_BYTES];
        ring::rand::SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| std::io::Error::other("unbounded: system RNG unavailable"))?;
        Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
    }
}

impl UnboundedConsumer for SparkUnboundedConsumer {
    fn build(
        &self,
        config: &UnboundedConsumerConfig,
    ) -> std::io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
        let mut slot = self.running.lock().unwrap_or_else(|e| e.into_inner());

        // Reuse on an unchanged config. Core rebuilds the whole pool on every live config push, and
        // the config usually has not touched the `unbounded` block — restarting here would abandon
        // working peer paths and re-advertise to signaling on the refresh cadence.
        if let Some(running) = slot.as_ref() {
            if &running.config == config {
                return Ok((running.tcp.clone(), running.udp.clone()));
            }
        }

        let signaler = FreddieSignaler::new(&config.signaling_url).map_err(|e| {
            std::io::Error::other(format!("unbounded: building the signaler failed: {e}"))
        })?;
        let quic = ephemeral_quic_server_config()
            .map_err(|e| std::io::Error::other(format!("unbounded: QUIC identity failed: {e}")))?;

        let mut runtime_config = ConsumerRuntimeConfig::new(quic, Self::new_session_id()?);
        runtime_config.stun_urls = config.stun_urls.clone();
        // Zero from the wire means "unset", not "no paths": leave the runtime's own default rather
        // than clamping to a pool that could never carry a flow.
        if config.concurrent_paths > 0 {
            runtime_config.concurrent_sessions = config.concurrent_paths;
        }

        // `start_consumer` spawns its broker and session tasks, so it needs a runtime in scope. The
        // enter guard is dropped immediately after; the spawned tasks keep running on `self.runtime`.
        let runtime = self.runtime()?;
        let handle = {
            let _enter = runtime.enter();
            start_consumer(runtime_config, Arc::new(signaler), None).map_err(|e| {
                std::io::Error::other(format!("unbounded: starting the consumer failed: {e}"))
            })?
        };

        let transport = Arc::new(handle.transport());
        let tcp = transport.clone() as Arc<dyn Transport>;
        let udp = transport as Arc<dyn UdpTransport>;
        // Replacing the slot drops the previous `Running` — and with it the previous
        // `ConsumerHandle`, cancelling the runtime the superseded config started.
        *slot = Some(Running {
            config: config.clone(),
            _handle: handle,
            tcp: tcp.clone(),
            udp: udp.clone(),
        });
        Ok((tcp, udp))
    }
}

/// Register spark's Unbounded consumer with `spark-core`, so a config-delivered `unbounded` pool
/// member can be built.
///
/// Safe to call from inside a runtime or outside one: a handle in scope is captured as a fallback,
/// and otherwise the runtime is resolved when the pool is built. Call before the first transport
/// build — a member built earlier has already been skipped and is not revisited.
pub fn install() {
    set_unbounded_consumer(Some(Arc::new(SparkUnboundedConsumer::new(
        tokio::runtime::Handle::try_current().ok(),
    ))));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(signaling: &str, paths: usize) -> UnboundedConsumerConfig {
        UnboundedConsumerConfig {
            signaling_url: signaling.into(),
            stun_urls: Vec::new(),
            concurrent_paths: paths,
        }
    }

    #[test]
    fn session_ids_are_hex_and_unique() {
        let a = SparkUnboundedConsumer::new_session_id().expect("RNG available");
        let b = SparkUnboundedConsumer::new_session_id().expect("RNG available");
        assert_eq!(
            a.len(),
            SESSION_ID_BYTES * 2,
            "hex-encoded, so two chars per byte"
        );
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(
            a, b,
            "a reused id would let one consumer's peers rejoin another's session"
        );
    }

    /// Reuse is the property that keeps a config refresh from tearing down working peer paths, so it
    /// is asserted on the cache directly: a real `start_consumer` would need signaling to reach a
    /// live Freddie.
    #[tokio::test]
    async fn an_unchanged_config_reuses_the_running_transport() {
        let consumer = SparkUnboundedConsumer::new(Some(tokio::runtime::Handle::current()));
        let cfg = config("https://freddie.example/s", 5);

        // Seed the cache with a stand-in transport, then assert `build` hands back that same one
        // rather than starting a second runtime.
        let direct = Arc::new(spark_core::transport::DirectTransport::new(None));
        let handle = {
            let quic = ephemeral_quic_server_config().expect("ephemeral QUIC config");
            let signaler = FreddieSignaler::new(&cfg.signaling_url).expect("signaler");
            start_consumer(
                ConsumerRuntimeConfig::new(quic, "seed".to_string()),
                Arc::new(signaler),
                None,
            )
            .expect("the consumer starts without reaching signaling")
        };
        *consumer.running.lock().unwrap() = Some(Running {
            config: cfg.clone(),
            _handle: handle,
            tcp: direct.clone() as Arc<dyn Transport>,
            udp: direct.clone() as Arc<dyn UdpTransport>,
        });

        let (tcp, _udp) = consumer.build(&cfg).expect("an unchanged config reuses");
        assert!(
            Arc::ptr_eq(&tcp, &(direct as Arc<dyn Transport>)),
            "build() started a new runtime instead of reusing the live one"
        );
    }

    /// `install()` is called from a **synchronous** C-ABI entry point on Apple and Android
    /// (`fd_tunnel::run_fd_dispatch` builds its runtime and `block_on`s it only afterwards), so it
    /// must not require an ambient runtime. `Handle::current()` here would panic and take the tunnel
    /// start with it.
    #[test]
    fn install_outside_a_runtime_does_not_panic() {
        install();
        // And the resulting consumer reports a missing runtime as an error, not a panic, so the pool
        // skips the member instead of unwinding through FFI.
        let c = SparkUnboundedConsumer::new(None);
        // The Ok variant holds trait objects that aren't Debug, so match rather than expect_err.
        match c.build(&config("https://freddie.example/s", 5)) {
            Ok(_) => panic!("with no runtime anywhere, build must fail"),
            Err(e) => assert!(e.to_string().contains("no tokio runtime"), "{e}"),
        }
        spark_core::transport::external::set_unbounded_consumer(None);
    }

    /// A changed config must NOT reuse — otherwise a server moving the signaling endpoint would
    /// leave the client talking to the old one forever.
    #[tokio::test]
    async fn a_changed_config_does_not_reuse() {
        let consumer = SparkUnboundedConsumer::new(Some(tokio::runtime::Handle::current()));
        let direct = Arc::new(spark_core::transport::DirectTransport::new(None));
        let handle = {
            let quic = ephemeral_quic_server_config().expect("ephemeral QUIC config");
            let signaler = FreddieSignaler::new("https://old.example/s").expect("signaler");
            start_consumer(
                ConsumerRuntimeConfig::new(quic, "seed".to_string()),
                Arc::new(signaler),
                None,
            )
            .expect("the consumer starts without reaching signaling")
        };
        *consumer.running.lock().unwrap() = Some(Running {
            config: config("https://old.example/s", 5),
            _handle: handle,
            tcp: direct.clone() as Arc<dyn Transport>,
            udp: direct.clone() as Arc<dyn UdpTransport>,
        });

        let (tcp, _udp) = consumer
            .build(&config("https://new.example/s", 5))
            .expect("a new endpoint starts a fresh runtime");
        assert!(
            !Arc::ptr_eq(&tcp, &(direct as Arc<dyn Transport>)),
            "a changed signaling endpoint must start a new runtime, not reuse the old one"
        );
    }
}
