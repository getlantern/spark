//! Un-poisoned control-plane name resolution for spark startup (design:
//! `docs/bootstrap-resolver-design.md`).
//!
//! Resolution races at two levels: an *outer* race across strategies ([`RacingResolver`] over
//! [`DohResolver`] / [`ProxyResolver`]) and an *inner* race within DoH across the resolver pool
//! (`flint_dns::resolve`). Neither a blocked strategy nor a blocked individual resolver holds up the
//! first **validated** answer.

// Import the full set the module uses by the end of Phase C. `Arc`/`Duration`/`Config`/`Endpoint`/
// `UdpTransport` are used by Tasks C2–C4; they produce harmless unused-import warnings until then
// (this task's gate is `cargo test`, where warnings don't fail; the `-D warnings` clippy gate runs at
// the end of Phase C, by which point all are used).
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::{Config, Endpoint};
use crate::transport::UdpTransport;

/// Resolves a control-plane hostname to its first **validated** address. One impl per resolution
/// strategy; [`RacingResolver`] composes several. A trait so the wiring is unit-testable with a fake.
#[async_trait]
pub trait NameResolver: Send + Sync {
    /// Resolve `host` to a `SocketAddr` on `port`, returning the first validated address.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr>;
}

/// The outer happy-eyeballs race: holds an ordered set of strategy resolvers and returns the first
/// that yields a validated answer; errors only if every strategy fails.
pub struct RacingResolver {
    strategies: Vec<Box<dyn NameResolver>>,
}

impl RacingResolver {
    /// Race the given strategies (order is informational; all start together — the field is small).
    pub fn new(strategies: Vec<Box<dyn NameResolver>>) -> Self {
        Self { strategies }
    }
}

#[async_trait]
impl NameResolver for RacingResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        match flint_dial::race_with(self.strategies.len(), |i| self.strategies[i].resolve(host, port))
            .await
        {
            Ok((_winner, addr)) => Ok(addr),
            Err(errors) => Err(io::Error::other(format!(
                "all {} resolver strategies failed for {host}: {errors:?}",
                self.strategies.len()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(io::Result<SocketAddr>);
    #[async_trait]
    impl NameResolver for Fixed {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<SocketAddr> {
            match &self.0 {
                Ok(a) => Ok(*a),
                Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    fn ok(s: &str) -> Box<dyn NameResolver> {
        Box::new(Fixed(Ok(s.parse().unwrap())))
    }
    fn fail() -> Box<dyn NameResolver> {
        Box::new(Fixed(Err(io::Error::other("decline"))))
    }

    #[tokio::test]
    async fn first_validated_wins() {
        let r = RacingResolver::new(vec![fail(), ok("1.2.3.4:443")]);
        assert_eq!(r.resolve("h", 443).await.unwrap(), "1.2.3.4:443".parse().unwrap());
    }

    #[tokio::test]
    async fn all_fail_is_an_error() {
        let r = RacingResolver::new(vec![fail(), fail()]);
        assert!(r.resolve("h", 443).await.is_err());
    }
}
