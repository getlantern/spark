//! Registration seam for a transport `core` cannot construct itself.
//!
//! Today that is exactly one thing: the **Unbounded consumer** — the censored side of the WebRTC
//! peer-proxy, which relays through a volunteer to Lantern's egress.
//!
//! It needs a seam because of a dependency cycle that cannot be broken any other way. The consumer
//! is a *data-path* transport, so by the process model (CLAUDE.md §0) it must run in whichever
//! process owns the tunnel — it cannot sit in the unprivileged app and ship packets over IPC. But
//! its implementation lives in `spark-sharing`, which already depends on *this* crate for the
//! [`Transport`] trait, so `core` cannot depend back on it. `spark-sharing` is also a separate
//! workspace on purpose: its WebRTC graph is 14 crates deep, and cargo unifies features across
//! workspace members, so as a member it would land in the size-tuned product binaries whether or
//! not anything enabled it.
//!
//! So the dependency is inverted. `core` declares the capability it wants; the binary that owns the
//! tunnel installs an implementation at startup. This is the same shape `fd_tunnel` already uses for
//! its `PoolControl` and `ConfigApplier` handles: a process-wide slot, written once at bringup, read
//! by whatever needs it later.
//!
//! With nothing installed, an `unbounded` pool member is skipped with a reason, exactly like a
//! member whose feature isn't compiled in. It never fails the pool — a build that cannot speak
//! Unbounded simply uses the rest of the servers the config assigned it.

use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use super::{Transport, UdpTransport};
use crate::config::UnboundedConsumerConfig;

/// Builds the Unbounded consumer transport. Implemented outside `core` (see the module docs) and
/// installed with [`set_unbounded_consumer`].
///
/// # Implementor contract
///
/// Two things are easy to get wrong and neither is visible from here:
///
/// - **Keep the runtime alive.** `spark-sharing`'s `ConsumerHandle` cancels its session pool on
///   `Drop`. Returning a transport while letting the handle fall out of scope yields a transport
///   whose peer paths are already being torn down. The handle must be retained for at least as long
///   as the returned transport is in use.
/// - **Reuse, don't restart.** [`build`](UnboundedConsumer::build) is called once per pool build,
///   and the pool is rebuilt on every live config push. Starting a fresh consumer pool each time
///   would abandon working peer paths and re-advertise to signaling on a config-refresh cadence.
///   Build once for a given config and hand back a clone.
pub trait UnboundedConsumer: Send + Sync {
    /// Start (or reuse) a consumer runtime for `config` and return its transport pair.
    fn build(
        &self,
        config: &UnboundedConsumerConfig,
    ) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)>;
}

/// The installed consumer builder, if the binary registered one.
///
/// One slot, like `fd_tunnel`'s pool handle: a process runs one tunnel, and the consumer is a
/// process-wide capability rather than per-tunnel state. Written at bringup, read from the pool
/// build (which can happen on a config-refresh thread), so it is behind a mutex.
fn slot() -> &'static Mutex<Option<Arc<dyn UnboundedConsumer>>> {
    static SLOT: OnceLock<Mutex<Option<Arc<dyn UnboundedConsumer>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Install the Unbounded consumer builder, replacing any previous one. Call before the first
/// transport build — a member built earlier has already been skipped and is not retroactively
/// added. `None` uninstalls (used by tests and by teardown).
///
/// Poison-tolerant: the guarded value is a single `Option` with no invariant a panicking writer
/// could have broken, and this is reachable from teardown paths where panicking would take the
/// tunnel down with it.
pub fn set_unbounded_consumer(builder: Option<Arc<dyn UnboundedConsumer>>) {
    *slot().lock().unwrap_or_else(|e| e.into_inner()) = builder;
}

/// The installed builder, or `None` if this binary never registered one.
///
/// Gated with the pool, like [`super::build_one`]: an `unbounded` spec only ever arrives as a
/// `transport.servers` member (the config server delivers it as an outbound), so without
/// `multi-server` there is no build path that could read this. [`set_unbounded_consumer`] stays
/// ungated so a caller still compiles either way.
#[cfg(feature = "multi-server")]
pub(crate) fn unbounded_consumer() -> Option<Arc<dyn UnboundedConsumer>> {
    slot().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[cfg(all(test, feature = "multi-server"))]
mod tests {
    use super::*;

    /// Serializes the tests that touch the process-wide slot. Two tests both writing it would
    /// otherwise race — one installing while the other asserts an empty slot.
    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Stub;

    impl UnboundedConsumer for Stub {
        fn build(
            &self,
            _config: &UnboundedConsumerConfig,
        ) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
            Err(io::Error::other("stub"))
        }
    }

    #[test]
    fn absent_until_installed_and_cleared_on_uninstall() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_unbounded_consumer(None);
        assert!(
            unbounded_consumer().is_none(),
            "a build that registered nothing must report nothing, not a stale slot"
        );

        set_unbounded_consumer(Some(Arc::new(Stub)));
        assert!(unbounded_consumer().is_some());

        set_unbounded_consumer(None);
        assert!(
            unbounded_consumer().is_none(),
            "uninstalling must clear the slot so teardown cannot leave a dangling builder"
        );
    }

    #[test]
    fn installing_twice_keeps_the_latest() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_unbounded_consumer(Some(Arc::new(Stub)));
        set_unbounded_consumer(Some(Arc::new(Stub)));
        assert!(unbounded_consumer().is_some());
        set_unbounded_consumer(None);
    }
}
