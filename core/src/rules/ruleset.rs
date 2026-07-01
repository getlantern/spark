//! Rule-set fetch, disk cache, and refresh (M6) — mirroring the config-fetch cache pattern.
//!
//! Rule-sets are cached under `<data_dir>/rulesets/<tag>.srs` (the path the tunnel's loader reads).
//! Fetching is behind the [`RuleSetFetcher`] seam so the cache/refresh/offline logic is unit-testable
//! without the network; the production fetcher does an HTTP(S) GET (M6b).
//!
//! Offline-resilience is the invariant: a fetch failure — or a download that doesn't parse — never
//! disturbs the existing cache, so the tunnel keeps using the last-known-good `.srs`. A first-ever
//! fetch that fails simply leaves no file, and the loader degrades that list to proxy-everything.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::config::RuleSetRef;

/// Subdirectory of the platform data dir where cached `.srs` files live.
const RULESETS_SUBDIR: &str = "rulesets";

/// The on-disk cache path for a rule-set `tag`: `<data_dir>/rulesets/<tag>.srs`. Must match the
/// tunnel's loader (`fd_tunnel::setup_routing_and_udp`).
pub fn cache_path(data_dir: &Path, tag: &str) -> PathBuf {
    data_dir.join(RULESETS_SUBDIR).join(format!("{tag}.srs"))
}

/// Fetches a rule-set's raw `.srs` bytes from its URL. Injected so the cache/refresh logic is testable
/// without the network; the production impl does an HTTP(S) GET (M6b).
#[async_trait::async_trait]
pub trait RuleSetFetcher: Send + Sync {
    /// Fetch the `.srs` bytes at `url`.
    async fn fetch(&self, url: &str) -> io::Result<Vec<u8>>;
}

/// Fetch one rule-set and, **only if it fetches and parses**, atomically write it to the cache.
/// Returns `Ok(true)` when the cache was updated, `Ok(false)` when the fetch or parse failed (the
/// existing cache is left intact — offline-resilient). `Err` only on a filesystem write failure.
pub async fn refresh_one(
    fetcher: &dyn RuleSetFetcher,
    data_dir: &Path,
    r: &RuleSetRef,
) -> io::Result<bool> {
    let bytes = match fetcher.fetch(&r.url).await {
        Ok(b) => b,
        Err(e) => {
            warn!(tag = %r.tag, error = %e, "ruleset: fetch failed; keeping cached .srs");
            return Ok(false);
        }
    };
    // Validate before caching so a corrupt/incomplete download never overwrites a good cache.
    if let Err(e) = super::srs::parse(&bytes) {
        warn!(tag = %r.tag, error = %e, "ruleset: downloaded .srs did not parse; keeping cache");
        return Ok(false);
    }
    write_atomic(&cache_path(data_dir, &r.tag), &bytes)?;
    info!(tag = %r.tag, bytes = bytes.len(), "ruleset: cache updated");
    Ok(true)
}

/// Refresh every rule-set best-effort (one failure never aborts the rest), returning how many caches
/// were updated. A filesystem write error on one rule-set is logged and skipped.
pub async fn refresh_all(
    fetcher: &dyn RuleSetFetcher,
    data_dir: &Path,
    rule_sets: &[RuleSetRef],
) -> usize {
    let mut updated = 0;
    for r in rule_sets {
        match refresh_one(fetcher, data_dir, r).await {
            Ok(true) => updated += 1,
            Ok(false) => {}
            Err(e) => warn!(tag = %r.tag, error = %e, "ruleset: cache write failed; skipping"),
        }
    }
    updated
}

/// Refresh loop: refresh once up front, then every `interval`, until `stop` is signalled. Mirrors the
/// config-fetch background loop; spawn it on the tunnel's runtime (M6b wires it into `fd_tunnel`).
pub async fn run_refresh_loop(
    fetcher: Arc<dyn RuleSetFetcher>,
    data_dir: PathBuf,
    rule_sets: Vec<RuleSetRef>,
    interval: Duration,
    stop: Arc<tokio::sync::Notify>,
) {
    loop {
        refresh_all(fetcher.as_ref(), &data_dir, &rule_sets).await;
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = stop.notified() => break,
        }
    }
}

/// Atomically write `bytes` to `path`: create the parent dir, write a temp file, then rename over the
/// target — so a reader never sees a half-written `.srs`.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("srs.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteAction;

    /// A fetcher returning a fixed canned result (bytes or an error) for any URL.
    struct Canned(io::Result<Vec<u8>>);

    #[async_trait::async_trait]
    impl RuleSetFetcher for Canned {
        async fn fetch(&self, _url: &str) -> io::Result<Vec<u8>> {
            match &self.0 {
                Ok(b) => Ok(b.clone()),
                Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    fn ref_for(tag: &str) -> RuleSetRef {
        RuleSetRef {
            action: RouteAction::Reject,
            tag: tag.into(),
            url: format!("https://example.test/{tag}.srs"),
        }
    }

    /// A unique temp dir per test (no `tempfile` dep; mirrors the config-fetch tests).
    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("spark-ruleset-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // The smallest valid fixture — these tests exercise the cache/refresh logic, not parsing, so use
    // the cheapest `.srs` to keep them fast (banad_v1 parses slowly in debug builds).
    fn valid_srs() -> Vec<u8> {
        std::fs::read("tests/fixtures/srs/geoip-malware.srs").expect("read fixture")
    }

    #[test]
    fn cache_path_matches_the_loader_layout() {
        let p = cache_path(Path::new("/data"), "banad");
        assert_eq!(p, Path::new("/data/rulesets/banad.srs"));
    }

    #[tokio::test]
    async fn refresh_one_writes_a_valid_ruleset() {
        let dir = tmp("write");
        let bytes = valid_srs();
        let fetcher = Canned(Ok(bytes.clone()));
        assert!(refresh_one(&fetcher, &dir, &ref_for("banad"))
            .await
            .unwrap());
        assert_eq!(std::fs::read(cache_path(&dir, "banad")).unwrap(), bytes);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn refresh_one_keeps_cache_on_fetch_error() {
        let dir = tmp("fetch-err");
        let path = cache_path(&dir, "banad");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"OLD-GOOD-CACHE").unwrap();
        let fetcher = Canned(Err(io::Error::other("offline")));
        assert!(!refresh_one(&fetcher, &dir, &ref_for("banad"))
            .await
            .unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"OLD-GOOD-CACHE");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn refresh_one_keeps_cache_on_corrupt_download() {
        let dir = tmp("corrupt");
        let path = cache_path(&dir, "banad");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"OLD-GOOD-CACHE").unwrap();
        // Bytes that don't parse as a .srs → must not overwrite the good cache.
        let fetcher = Canned(Ok(b"not a real srs file".to_vec()));
        assert!(!refresh_one(&fetcher, &dir, &ref_for("banad"))
            .await
            .unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"OLD-GOOD-CACHE");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn refresh_all_counts_only_successful_updates() {
        let dir = tmp("all");
        // Both tags fetch the same valid fixture (the Canned fetcher ignores the URL), so both update.
        let fetcher = Canned(Ok(valid_srs()));
        let n = refresh_all(&fetcher, &dir, &[ref_for("banad"), ref_for("ads")]).await;
        assert_eq!(n, 2);
        assert!(cache_path(&dir, "banad").exists());
        assert!(cache_path(&dir, "ads").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
