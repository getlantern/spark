//! `spark-core` — the process- and IPC-agnostic proxy core.
//!
//! M0 pinned the vendored netstack. M1 added the TUN data-path foundation: an async
//! [`tun`] device abstraction and a minimal zero-copy IP [`packet`] inspector. M2 added
//! the [`netstack`] bridge (TUN ↔ userspace TCP/IP stack) and a plain [`proxy`] TCP
//! forwarder. M3 built the [`transport`] tunnel client in isolation; M4 wires it in behind
//! the [`transport::Transport`] trait so the forwarder dials either directly or through a
//! tunnel. See `docs/PLAN.md`.

use tokio::io::{AsyncRead, AsyncWrite};

// Run the data path on an OS-provided TUN fd — the shared entry for Android `VpnService` and
// Apple NetworkExtension (iOS + macOS). The FFI shims (`platforms/android` JNI, `platforms/apple`
// C ABI) call into this.
pub mod caps;
pub mod config;
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
pub mod fd_tunnel;
pub mod log_bridge;
pub mod metrics;
pub mod net;
pub mod netstack;
pub mod packet;
pub mod proxy;
pub mod redact;
pub mod routing;
pub mod transport;
pub mod tun;

/// Control-plane name resolution for startup (design: docs/bootstrap-resolver-design.md). Resolves a
/// proxy `server` hostname to validated IPs via an un-poisoned Chrome-mimicry DoH race, before any
/// tunnel exists. Behind `bootstrap-dns` (pulls flint-dns/flint-dial + boring).
#[cfg(feature = "bootstrap-dns")]
pub mod bootstrap;

/// Rule-based smart-routing + ad-block: parse sing-box `.srs` rule-sets and decide per-flow
/// Direct/Proxy/Reject (design: docs/superpowers/specs/2026-07-01-spark-smart-routing-ad-block-design.md).
/// Distinct from [`routing`], which manages the OS route table. Behind `smart-routing`.
#[cfg(feature = "smart-routing")]
pub mod rules;

/// Fake-IP DNS subsystem (M4): spark answers the app's A/AAAA queries with synthetic IPs from a
/// reserved range, maps `fakeip→domain`, and recovers the domain at connect time so [`rules`] can
/// decide per-flow. Distinct from upstream/control-plane resolution ([`bootstrap`]). Behind
/// `smart-routing` (same feature as the rules engine it feeds).
#[cfg(feature = "smart-routing")]
pub mod dns;

/// Install bundled CA roots so flint's fronted TLS can verify on mobile (Android/iOS lack a
/// boring-readable system trust store). Gated to the fd-tunnel platforms: its only caller,
/// [`fd_tunnel::run_fd_dispatch`], compiles only on android/ios/macos, so declaring `ca_roots` more
/// broadly would leave the desktop no-op as dead code on linux/windows.
#[cfg(all(
    feature = "config-fetch",
    any(target_os = "android", target_os = "ios", target_os = "macos")
))]
mod ca_roots;

/// Marker for a bidirectional async byte stream. Blanket-implemented for every
/// `AsyncRead + AsyncWrite`, so a surfaced netstack flow and a dialed transport stream can
/// share one boxed type ([`BoxedStream`]).
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// An owned, boxed bidirectional stream — the currency between netstack flows
/// ([`netstack::TcpFlow`]) and transports ([`transport::Transport::dial`]).
pub type BoxedStream = Box<dyn AsyncReadWrite + Unpin + Send>;

/// Bootstrap phase: resolve every `Endpoint::Host` proxy `server` in `config` to an `Endpoint::Ip`
/// before the transport is built (design §3.3). With `bootstrap-dns` this uses the un-poisoned
/// Chrome-mimicry resolver; without it, a configured hostname is a hard error — never a silent
/// system-DNS fallback. An all-IP config is a no-op (and works with the feature off).
#[cfg(feature = "bootstrap-dns")]
pub async fn resolve_bootstrap(config: &mut config::Config) -> std::io::Result<()> {
    let resolver = bootstrap::default_resolver(config);
    bootstrap::resolve_endpoints(config, &resolver).await
}

/// See the `bootstrap-dns` variant. Without the feature, a configured hostname is rejected explicitly.
#[cfg(not(feature = "bootstrap-dns"))]
pub async fn resolve_bootstrap(config: &mut config::Config) -> std::io::Result<()> {
    if let Some(host) = config.first_unresolved_host() {
        return Err(std::io::Error::other(format!(
            "proxy server `{host}` is a hostname, which requires the bootstrap-dns feature"
        )));
    }
    Ok(())
}

#[cfg(all(test, not(feature = "bootstrap-dns")))]
mod resolve_bootstrap_tests {
    use crate::config::Config;

    #[tokio::test]
    async fn host_without_the_feature_is_an_explicit_error() {
        let mut cfg = Config::from_toml_str(
            "[transport.anytls]\nserver = \"proxy.example.com:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        let err = super::resolve_bootstrap(&mut cfg).await.unwrap_err();
        assert!(err.to_string().contains("bootstrap-dns feature"));
    }

    #[tokio::test]
    async fn all_ip_config_is_a_noop() {
        let mut cfg = Config::from_toml_str(
            "[transport.anytls]\nserver = \"1.2.3.4:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        super::resolve_bootstrap(&mut cfg)
            .await
            .expect("all-IP config resolves trivially");
    }
}
