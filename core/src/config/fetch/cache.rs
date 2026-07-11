//! On-disk last-good config cache: the raw `config_raw.json` body + a small meta sidecar
//! (`config_meta.json`: etag, last-modified, poll-interval). Each file is written atomically
//! (temp + rename); the two files are not updated as a single atomic unit (see `store`).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Sidecar metadata persisted next to the cached raw config.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheMeta {
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub poll_interval_seconds: u64,
}

fn raw_path(dir: &Path) -> PathBuf {
    dir.join("config_raw.json")
}
fn meta_path(dir: &Path) -> PathBuf {
    dir.join("config_meta.json")
}

/// Load the cached raw config body + meta, or `None` if no cache exists yet.
pub fn load(dir: &Path) -> Option<(String, CacheMeta)> {
    let raw = std::fs::read_to_string(raw_path(dir)).ok()?;
    let meta = std::fs::read_to_string(meta_path(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Some((raw, meta))
}

/// Persist the raw config body + meta into `dir` (creating it if needed). Each file is written
/// atomically (temp + rename); the two are NOT one atomic unit — a crash between writes leaves stale
/// meta, which is harmless (at worst a redundant HTTP fetch next run).
pub fn store(dir: &Path, raw: &str, meta: &CacheMeta) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_atomic(&raw_path(dir), raw.as_bytes())?;
    let meta_json = serde_json::to_vec(meta).map_err(io::Error::other)?;
    write_atomic(&meta_path(dir), &meta_json)
}

/// Monotonic per-write counter for unique temp names (see `unique_tmp_path`).
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A per-write temp path in the same dir as `path`. Unique across concurrent writers (pid + a
/// monotonic seq) so two writers sharing this cache — e.g. the tunnel process and the app's own
/// startup fetch (locations-before-VPN Phase 2a) — never write the same temp file and clobber each
/// other mid-write. A fixed `.tmp` name was safe only while a single process ever wrote the cache.
fn unique_tmp_path(path: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    path.with_file_name(format!("{name}.{pid}.{seq}.tmp"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Temp stays in the same dir as `path`, so the rename is always same-filesystem (atomic).
    // Its name is unique per writer/write so concurrent writers can't corrupt a shared temp.
    let tmp = unique_tmp_path(path);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_path_is_unique_per_write() {
        let p = Path::new("/tmp/spark-x/config_raw.json");
        let a = unique_tmp_path(p);
        let b = unique_tmp_path(p);
        assert_ne!(a, b, "two writers must not share a temp path");
        // Same dir as the target (so the rename stays same-filesystem/atomic) and derived from the
        // target's file name.
        assert_eq!(a.parent(), p.parent());
        assert!(a
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("config_raw.json.") && s.ends_with(".tmp")));
    }

    #[test]
    fn round_trips_raw_and_meta() {
        let dir = std::env::temp_dir().join(format!("spark-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load(&dir).is_none());
        let meta = CacheMeta {
            etag: Some("\"e\"".into()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".into()),
            poll_interval_seconds: 30,
        };
        store(&dir, "{\"servers\":[]}", &meta).unwrap();
        let (raw, got) = load(&dir).unwrap();
        assert_eq!(raw, "{\"servers\":[]}");
        assert_eq!(got, meta);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_overwrites_existing() {
        let dir =
            std::env::temp_dir().join(format!("spark-cache-overwrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let meta1 = CacheMeta {
            etag: Some("v1".into()),
            ..Default::default()
        };
        store(&dir, "first", &meta1).unwrap();
        let meta2 = CacheMeta {
            etag: Some("v2".into()),
            poll_interval_seconds: 60,
            ..Default::default()
        };
        store(&dir, "second", &meta2).unwrap();
        let (raw, got) = load(&dir).unwrap();
        assert_eq!(raw, "second");
        assert_eq!(got, meta2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
