//! macOS installed-apps catalog for desktop app-based split tunneling.
//!
//! Enumerates `*.app` bundles under `/Applications`, `/System/Applications`, and
//! `~/Applications`, and returns a JSON array of `{id, name, icon}` sorted by display name.
//!
//! `id` is the **canonical bundle root** (e.g. `/Applications/Google Chrome.app` after
//! `std::fs::canonicalize`, so symlinked bundles like Safari resolve to their real path). The
//! core matches split-tunnel flows by bundle-root *prefix* against the resolved process path —
//! this catches the helper/child processes real apps make their network connections from — so
//! the bundle root (not the main-exe path) is the match key.
//!
//! `icon` is a small PNG data-URL extracted from the bundle's `.icns` via `sips`, or `null` if
//! extraction fails. `name` is the bundle's display name.
//!
//! Info.plist parsing uses `plutil -convert json` piped into `serde_json` rather than a
//! `plist` crate (no new dependencies — CLAUDE.md). Icons use `sips` for the same reason.
//!
//! A stale-while-revalidate disk cache (`<base>/installed_apps_cache.json`) serves the
//! previous scan instantly and refreshes in a background thread, mirroring the Android
//! plugin's approach — a full plist+icon scan is slow enough to stall the picker on first paint.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

/// One catalog entry, serialized to match the TS `InstalledApp` shape
/// (`gui-tauri/src/lib/spark_backend.ts`): `{id, name, icon}`.
#[derive(Serialize, Deserialize)]
struct AppEntry {
    /// Canonical bundle-root path (e.g. `/Applications/Google Chrome.app`) — the core matches
    /// split-tunnel flows by prefix against this, so it is the split-tunnel match key.
    id: String,
    /// Display name (`CFBundleDisplayName` else `CFBundleName` else the bundle stem).
    name: String,
    /// Optional icon data-URL (`data:image/png;base64,…`); `null` if extraction failed.
    icon: Option<String>,
}

/// Name of the SWR cache file under `base`.
const CACHE_FILE: &str = "installed_apps_cache.json";

/// The directories scanned for `*.app` bundles (one level deep). `~/Applications` is
/// appended when `HOME` is set.
fn scan_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join("Applications"));
    }
    roots
}

/// Parse a bundle's `Contents/Info.plist` into an [`AppEntry`], or `None` if the bundle
/// has no `CFBundleExecutable` (skip it — nothing to attribute flows to), the plist can't
/// be read/parsed, or it's Safari (whose network can't be process-matched — see below).
fn entry_for_bundle(app: &Path) -> Option<AppEntry> {
    let info_plist = app.join("Contents/Info.plist");
    // `plutil -convert json -o - <path>` emits the plist as JSON on stdout. This handles
    // binary and XML plists uniformly without a `plist` crate.
    let output = Command::new("/usr/bin/plutil")
        .arg("-convert")
        .arg("json")
        .arg("-o")
        .arg("-")
        .arg(&info_plist)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let plist: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;

    // Skip Safari: its network traffic flows through the shared `com.apple.WebKit.Networking`
    // system process (outside any app bundle), so a per-process / bundle-prefix match can never
    // attribute Safari's flows. Offering it in the picker would be a broken promise.
    if plist.get("CFBundleIdentifier").and_then(|v| v.as_str()) == Some("com.apple.Safari") {
        return None;
    }

    // CFBundleExecutable is required — a bundle with no exe has no processes to attribute.
    let exe = plist.get("CFBundleExecutable").and_then(|v| v.as_str())?;
    if exe.is_empty() {
        return None;
    }

    // The match key is the **canonical bundle root** (resolve symlinks like Safari's Cryptexes
    // path). Fall back to the literal path if canonicalization fails so the entry isn't dropped.
    let id = std::fs::canonicalize(app)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| app.to_string_lossy().into_owned());

    // Display name: CFBundleDisplayName → CFBundleName → the bundle dir stem.
    let name = plist
        .get("CFBundleDisplayName")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            plist
                .get("CFBundleName")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(|s| s.to_owned())
        .or_else(|| app.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| id.clone());

    // Best-effort icon; never fails the whole entry.
    let icon = icon_data_url(app, &plist);

    Some(AppEntry { id, name, icon })
}

/// Resolve a bundle's `.icns` icon file. Reads `CFBundleIconFile` from the plist (appending
/// `.icns` if it has no extension); falls back to `Contents/Resources/AppIcon.icns`, then the
/// first `*.icns` under `Contents/Resources`. `None` if no icon file is found.
fn icns_path(app: &Path, plist: &serde_json::Value) -> Option<PathBuf> {
    let resources = app.join("Contents/Resources");

    if let Some(icon_file) = plist
        .get("CFBundleIconFile")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let mut name = icon_file.to_owned();
        if Path::new(&name).extension().is_none() {
            name.push_str(".icns");
        }
        let p = resources.join(&name);
        if p.is_file() {
            return Some(p);
        }
    }

    let default = resources.join("AppIcon.icns");
    if default.is_file() {
        return Some(default);
    }

    // Last resort: the first `*.icns` in Resources.
    std::fs::read_dir(&resources).ok()?.flatten().find_map(|e| {
        let p = e.path();
        (p.extension().and_then(|x| x.to_str()) == Some("icns")).then_some(p)
    })
}

/// Extract a 64×64 PNG icon for `app` and return it as a `data:image/png;base64,…` URL, or
/// `None` if any step fails (no `.icns`, `sips` error, read/encode failure). Best-effort:
/// icons are cosmetic, so a failure here never drops the app from the catalog.
fn icon_data_url(app: &Path, plist: &serde_json::Value) -> Option<String> {
    let icns = icns_path(app, plist)?;

    // Per-process/-icon temp path so concurrent extractions don't collide. `sips` writes PNG.
    let tmp = std::env::temp_dir().join(format!(
        "spark-icon-{}-{}.png",
        std::process::id(),
        NEXT_ICON.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));

    let status = Command::new("/usr/bin/sips")
        .arg("-z")
        .arg("64")
        .arg("64")
        .arg("-s")
        .arg("format")
        .arg("png")
        .arg(&icns)
        .arg("--out")
        .arg(&tmp)
        .output()
        .ok();

    let ok = status.map(|o| o.status.success()).unwrap_or(false);
    let png = if ok { std::fs::read(&tmp).ok() } else { None };
    let _ = std::fs::remove_file(&tmp); // clean up regardless of outcome

    png.map(|bytes| format!("data:image/png;base64,{}", base64_encode(&bytes)))
}

/// Monotonic counter so each icon extraction gets a unique temp filename within this process.
static NEXT_ICON: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Standard base64 encoder (RFC 4648, with padding). Implemented inline: this crate has no
/// base64 dependency and CLAUDE.md forbids adding one for a job this small.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Enumerate every `*.app` bundle under [`scan_roots`] (one level deep) and build the
/// sorted catalog. Returns the JSON array string.
fn enumerate() -> String {
    let mut entries: Vec<AppEntry> = Vec::new();
    for root in scan_roots() {
        let Ok(dir) = std::fs::read_dir(&root) else {
            continue; // root missing / unreadable → skip it
        };
        for dirent in dir.flatten() {
            let path = dirent.path();
            if path.extension().and_then(|e| e.to_str()) == Some("app") {
                if let Some(entry) = entry_for_bundle(&path) {
                    entries.push(entry);
                }
            }
        }
    }
    entries.sort_by_key(|a| a.name.to_lowercase());
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

/// Atomically write `json` to `<base>/installed_apps_cache.json` (temp file + rename), so
/// a reader never sees a half-written cache. Best-effort — errors are logged, not fatal.
fn write_cache(base: &Path, json: &str) {
    if std::fs::create_dir_all(base).is_err() {
        return;
    }
    let final_path = base.join(CACHE_FILE);
    // Per-process temp name so a concurrent refresh in another process can't clobber ours.
    let tmp_path = base.join(format!("{}.{}.tmp", CACHE_FILE, std::process::id()));
    if std::fs::write(&tmp_path, json).is_err() {
        return;
    }
    if std::fs::rename(&tmp_path, &final_path).is_err() {
        // Rename failed — drop the temp file rather than leaving it behind.
        let _ = std::fs::remove_file(&tmp_path);
    }
}

/// Return the macOS installed-apps catalog as a JSON array string of `{id, name, icon}`.
///
/// Stale-while-revalidate: if a cache exists at `<base>/installed_apps_cache.json`, return
/// it immediately and kick off a background refresh (so the next call sees fresh data).
/// On a cache miss, enumerate synchronously, persist, and return.
pub fn list_installed_apps(base: &Path) -> String {
    let cache_path = base.join(CACHE_FILE);
    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
        // Serve the cache instantly; refresh in the background for next time.
        let base = base.to_path_buf();
        std::thread::spawn(move || {
            let fresh = enumerate();
            write_cache(&base, &fresh);
        });
        return cached;
    }
    // Cache miss: enumerate synchronously so the first caller still gets a real list.
    let fresh = enumerate();
    write_cache(base, &fresh);
    fresh
}

#[cfg(test)]
mod tests {
    use super::base64_encode;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // RFC 4648 §10 test vectors — including the three padding cases (0/1/2 pad chars).
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encodes_all_byte_values() {
        // Exercises every 6-bit index (0x2b/'+' and 0x2f/'/' among them) via the full byte range.
        let all: Vec<u8> = (0u8..=255).collect();
        let encoded = base64_encode(&all);
        // 256 bytes → ceil(256/3)=86 groups → 344 chars, and it must contain both '+' and '/'.
        assert_eq!(encoded.len(), 344);
        assert!(encoded.contains('+') && encoded.contains('/'));
    }
}
