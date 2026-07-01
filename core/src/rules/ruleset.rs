//! Rule-set fetch, disk cache, and refresh (M6) — mirroring the config-fetch cache pattern.
//!
//! Rule-sets are cached under `<data_dir>/rulesets/<tag>.srs` (the path the tunnel's loader reads).
//! Fetching is behind the [`RuleSetFetcher`] seam so the cache/refresh/offline logic is unit-testable
//! without the network; the production impl ([`KindlingRuleSetFetcher`]) fetches **via kindling**
//! (domain-fronted, self-bootstrapping) so updates work under censorship.
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

/// The on-disk cache path for a rule-set `tag`: `<data_dir>/rulesets/<sanitized-tag>.srs`. The single
/// place tags become filenames (both the loader and the fetcher call it), so the sanitization can't be
/// bypassed.
pub fn cache_path(data_dir: &Path, tag: &str) -> PathBuf {
    data_dir
        .join(RULESETS_SUBDIR)
        .join(format!("{}.srs", sanitized_tag(tag)))
}

/// Reduce a (fetched, untrusted) rule-set tag to a filename-safe token so it can't escape the
/// rulesets dir via path traversal. Keeps `[A-Za-z0-9._-]`, maps anything else (incl. `/` and `\`) to
/// `_`, then neutralizes any residual `..`. Never empty.
fn sanitized_tag(tag: &str) -> String {
    let mut s: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("..") {
        s = s.replace("..", "_");
    }
    if s.is_empty() {
        s.push('_');
    }
    s
}

/// Fetches a rule-set's raw `.srs` bytes from its URL. Injected so the cache/refresh logic is testable
/// without the network; the production impl ([`KindlingRuleSetFetcher`]) fetches via kindling.
#[async_trait::async_trait]
pub trait RuleSetFetcher: Send + Sync {
    /// Fetch the `.srs` bytes at `url`.
    async fn fetch(&self, url: &str) -> io::Result<Vec<u8>>;
}

/// Split an `https://host[/path]` URL into `(host, path)`. Kindling fronts to `host` (443 implied) and
/// requests `path`. Errors on a non-`https` URL or an empty host.
#[cfg(feature = "config-fetch")]
fn split_https_url(url: &str) -> io::Result<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| io::Error::other(format!("ruleset url must be https: {url}")))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if host.is_empty() {
        return Err(io::Error::other(format!("ruleset url has no host: {url}")));
    }
    Ok((host.to_string(), path.to_string()))
}

/// The production [`RuleSetFetcher`]: fetch every `.srs` **via kindling**
/// (`flint_kindling::FrontedBootstrap`) — domain-fronted through CDNs, self-bootstrapping from the
/// user's own network — so rule-set updates work even where a direct fetch of the `.srs` host is
/// blocked. There is deliberately **no** direct-dial fallback (kindling is always used). Behind
/// `config-fetch` (which pulls flint-kindling); the rule-set host must be frontable (served by a CDN
/// kindling knows — CloudFront / Akamai / Aliyun).
#[cfg(feature = "config-fetch")]
pub struct KindlingRuleSetFetcher {
    seed: u64,
}

#[cfg(feature = "config-fetch")]
impl KindlingRuleSetFetcher {
    /// A fetcher whose CloudFront/Aliyun front-sampling is diversified by `seed` — per-device, from the
    /// device id (see `config::fetch::seed_from_device_id`), matching the config fetch's sampling.
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }
}

#[cfg(feature = "config-fetch")]
#[async_trait::async_trait]
impl RuleSetFetcher for KindlingRuleSetFetcher {
    async fn fetch(&self, url: &str) -> io::Result<Vec<u8>> {
        let (host, path) = split_https_url(url)?;
        let bootstrap = flint_kindling::FrontedBootstrap::new(host).with_seed(self.seed);
        let resp = bootstrap
            .request(&flint_fronted::OneshotRequest::get(path))
            .await?;
        match resp.status {
            200 | 206 => Ok(resp.body),
            other => Err(io::Error::other(format!("ruleset fetch HTTP {other}"))),
        }
    }
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

/// Refresh loop: each cycle re-fetches only the rule-sets whose cache is **stale** (missing or older
/// than `interval`), then waits `interval` — until `stop` is signalled. The staleness gate keeps a
/// warm cache from being re-downloaded via kindling on every connect. Mirrors the config-fetch
/// background loop; spawned on the tunnel's runtime by `fd_tunnel`.
pub async fn run_refresh_loop(
    fetcher: Arc<dyn RuleSetFetcher>,
    data_dir: PathBuf,
    rule_sets: Vec<RuleSetRef>,
    interval: Duration,
    stop: Arc<tokio::sync::Notify>,
) {
    loop {
        let stale: Vec<RuleSetRef> = rule_sets
            .iter()
            .filter(|r| is_stale(&cache_path(&data_dir, &r.tag), interval))
            .cloned()
            .collect();
        if !stale.is_empty() {
            let updated = refresh_all(fetcher.as_ref(), &data_dir, &stale).await;
            info!(
                updated,
                stale = stale.len(),
                "ruleset: refresh cycle complete"
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = stop.notified() => break,
        }
    }
}

/// Whether the cache at `path` is missing or older than `max_age` — i.e. worth re-fetching. A file
/// whose mtime is unreadable or in the future is treated as stale (fetch to be safe).
fn is_stale(path: &Path, max_age: Duration) -> bool {
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => mtime.elapsed().map(|age| age >= max_age).unwrap_or(true),
        Err(_) => true,
    }
}

/// Atomically write `bytes` to `path`: create the parent dir, write a temp file, then rename over the
/// target — so a reader never sees a half-written `.srs`. The temp name is unique **per write** (pid +
/// a monotonic counter), so even overlapping writes for the same tag can't share a temp path. On Unix
/// the rename atomically replaces; on Windows rename fails if the destination exists, so fall back to
/// remove-then-rename there.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("srs.tmp.{}.{}", std::process::id(), uniq));
    std::fs::write(&tmp, bytes)?;
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(path);
        std::fs::rename(&tmp, path)?;
    }
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

    #[test]
    fn cache_path_sanitizes_traversal_tags() {
        let dir = Path::new("/data");
        // A malicious fetched tag can't escape the rulesets dir.
        for tag in ["../../etc/passwd", "..", "a/b\\c", "/abs"] {
            let p = cache_path(dir, tag);
            assert!(
                p.starts_with("/data/rulesets"),
                "stays under rulesets: {p:?}"
            );
            assert!(
                !p.to_string_lossy().contains(".."),
                "no `..` survives for {tag:?}: {p:?}"
            );
        }
    }

    #[test]
    fn is_stale_flags_missing_and_old_not_fresh() {
        let dir = tmp("stale");
        let path = cache_path(&dir, "x");
        assert!(is_stale(&path, Duration::from_secs(60)), "missing → stale");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"data").unwrap();
        assert!(
            !is_stale(&path, Duration::from_secs(3600)),
            "freshly written → not stale"
        );
        assert!(
            is_stale(&path, Duration::from_secs(0)),
            "zero max-age → always stale"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "config-fetch")]
    #[test]
    fn split_https_url_parses_host_and_path() {
        assert_eq!(
            split_https_url("https://cdn.example.com/rulesets/banad.srs").unwrap(),
            (
                "cdn.example.com".to_string(),
                "/rulesets/banad.srs".to_string()
            )
        );
        // No path → root.
        assert_eq!(
            split_https_url("https://cdn.example.com").unwrap(),
            ("cdn.example.com".to_string(), "/".to_string())
        );
        // Non-https and empty-host are rejected.
        assert!(split_https_url("http://cdn.example.com/x.srs").is_err());
        assert!(split_https_url("https:///x.srs").is_err());
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
