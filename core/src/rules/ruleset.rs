//! Rule-set fetch, disk cache, and refresh (M6) — mirroring the config-fetch cache pattern.
//!
//! Rule-sets are cached under `<data_dir>/rulesets/<tag>.srs` (the path the tunnel's loader reads).
//! Fetching is behind the [`RuleSetFetcher`] seam so the cache/refresh/offline logic is unit-testable
//! without the network; the production impl ([`FrontedRuleSetFetcher`]) fetches through the embedded
//! domain-fronting config (`fronted.yaml.gz`) so updates work under censorship.
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
/// without the network; the production impl ([`FrontedRuleSetFetcher`]) fetches via the embedded
/// domain-fronting config.
#[async_trait::async_trait]
pub trait RuleSetFetcher: Send + Sync {
    /// Fetch the `.srs` bytes at `url`.
    async fn fetch(&self, url: &str) -> io::Result<Vec<u8>>;
}

/// Split an `https://host[/path]` URL into `(host, path)`. The fronted dialer fronts to `host` (443
/// implied) and requests `path`. Errors on a non-`https` URL or an empty host.
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

/// The production [`RuleSetFetcher`]: fetch every `.srs` **via the embedded fronted config** — the
/// same domain-fronting map (`config/fetch/fronted.yaml.gz`) config-fetch uses. Its `hostaliases`
/// already route the rule-set hosts (e.g. `raw.githubusercontent.com`) through Lantern's Akamai /
/// CloudFront fronting properties, so a rule-set update works even where a direct fetch of the `.srs`
/// host is blocked — and, unlike the bare front-scanner, it knows which CDN front actually reaches
/// each host (the scanner guesses generic edges with the raw host as the inner `Host`, which no CDN
/// serves for GitHub). Behind `config-fetch` (which pulls flint-fronted + the embedded map).
#[cfg(feature = "config-fetch")]
pub struct FrontedRuleSetFetcher {
    dialer: flint_fronted::FrontedTlsDialer<flint_fronted::FlintDnsResolver>,
}

#[cfg(feature = "config-fetch")]
impl FrontedRuleSetFetcher {
    /// Build a fetcher that fronts each `.srs` via the embedded fronted config. `None` only if that
    /// config fails to parse (shouldn't happen) — the caller then skips rule-set refresh and keeps any
    /// cached lists.
    pub fn new() -> Option<Self> {
        Some(Self {
            dialer: crate::config::fetch::fronted_dialer()?,
        })
    }
}

#[cfg(feature = "config-fetch")]
#[async_trait::async_trait]
impl RuleSetFetcher for FrontedRuleSetFetcher {
    async fn fetch(&self, url: &str) -> io::Result<Vec<u8>> {
        let (host, path) = split_https_url(url)?;
        // The dialer maps `host` to its fronting provider via the embedded `hostaliases`, dials a
        // decoy-SNI front, and requests `path` — so e.g. raw.githubusercontent.com reaches GitHub
        // through Lantern's Akamai/CloudFront property.
        let resp = self
            .dialer
            .request(&host, &flint_fronted::OneshotRequest::get(path))
            .await
            .map_err(io::Error::other)?;
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
/// warm cache from being re-downloaded on every connect. Mirrors the config-fetch
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
            ad_block: true,
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

    #[cfg(feature = "config-fetch")]
    #[test]
    fn fronted_fetcher_builds_from_the_embedded_config() {
        // Rule-set refresh now depends on the embedded `fronted.yaml.gz` parsing into a dialer; if it
        // ever stops parsing, refresh silently degrades to keeping stale/empty lists. Catch that here.
        assert!(
            FrontedRuleSetFetcher::new().is_some(),
            "embedded fronted config must parse so rule-set refresh has a fetcher"
        );
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
