//! On-disk last-good config cache: the raw `config_raw.json` body + a small meta sidecar
//! (`config_meta.json`: etag, last-modified, poll-interval). Each file is written atomically
//! (temp + rename); the two files are not updated as a single atomic unit (see `store`).

use std::io;
use std::path::{Path, PathBuf};

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

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Temp stays in the same dir as `path`, so the rename is always same-filesystem (atomic).
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
