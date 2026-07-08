//! macOS installed-apps catalog for desktop app-based split tunneling.
//!
//! Enumerates `*.app` bundles under `/Applications`, `/System/Applications`, and
//! `~/Applications`, resolves each bundle's executable path (the split-tunnel match key —
//! `ProcessResolver` returns exactly this path), and returns a JSON array of
//! `{id, name, icon}` sorted by display name. `id` is the absolute executable path,
//! `name` the bundle's display name, `icon` is `null` for v1 (no `.icns` extraction yet).
//!
//! Info.plist parsing uses `plutil -convert json` piped into `serde_json` rather than a
//! `plist` crate (no new dependencies — CLAUDE.md).
//!
//! A stale-while-revalidate disk cache (`<base>/installed_apps_cache.json`) serves the
//! previous scan instantly and refreshes in a background thread, mirroring the Android
//! plugin's approach — a full plist scan is slow enough to stall the picker on first paint.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

/// One catalog entry, serialized to match the TS `InstalledApp` shape
/// (`gui-tauri/src/lib/spark_backend.ts`): `{id, name, icon}`.
#[derive(Serialize, Deserialize)]
struct AppEntry {
    /// Absolute executable path (`<app>/Contents/MacOS/<CFBundleExecutable>`) — the
    /// value the core's process resolver returns, so it is the split-tunnel match key.
    id: String,
    /// Display name (`CFBundleDisplayName` else `CFBundleName` else the bundle stem).
    name: String,
    /// Optional icon data-URL — always `null` in v1.
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
/// has no `CFBundleExecutable` (skip it — there's no process path to match on) or the
/// plist can't be read/parsed.
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

    // CFBundleExecutable is required — the exe path is the match key.
    let exe = plist.get("CFBundleExecutable").and_then(|v| v.as_str())?;
    if exe.is_empty() {
        return None;
    }
    let id = app
        .join("Contents/MacOS")
        .join(exe)
        .to_string_lossy()
        .into_owned();

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

    Some(AppEntry {
        id,
        name,
        icon: None,
    })
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
