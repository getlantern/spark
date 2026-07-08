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
//! `icon` is a small PNG data-URL: extracted from the bundle's `.icns` via `sips` when present,
//! else rendered from the app's Finder icon via AppKit's `NSWorkspace` (this covers macOS
//! system apps like Calendar and Books, whose icons live in an `Assets.car` asset catalog with
//! no standalone `.icns`), or `null` if both fail. `name` is the bundle's display name.
//!
//! Info.plist parsing uses `plutil -convert json` piped into `serde_json` rather than a
//! `plist` crate (no new dependencies — CLAUDE.md). Icons use `sips` for the same reason.
//!
//! A stale-while-revalidate disk cache (`<base>/installed_apps_cache.v<N>.json`, where `<N>` is
//! [`CACHE_VERSION`]) serves the previous scan instantly and refreshes in a background thread,
//! mirroring the Android plugin's approach — a full plist+icon scan is slow enough to stall the
//! picker on first paint. The version suffix ensures an upgraded build never serves an older
//! build's cache (which may list apps the current filter now drops).

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

/// Base name of the SWR cache file under `base`; the version suffix (see [`CACHE_VERSION`])
/// is appended so an upgraded build never reads a cache written by an older build.
const CACHE_BASENAME: &str = "installed_apps_cache";

/// Bump when the *shape* or *filtering* of catalog entries changes, so an upgraded build
/// ignores a cache written by an older build (whose entries may include apps the new filter
/// now drops — e.g. the LSUIElement/LSBackgroundOnly and Safari exclusions) instead of
/// serving that stale list once under stale-while-revalidate. Encoded into the cache filename.
///
/// v2: Safari + background/agent-bundle filtering; NSWorkspace icon fallback.
const CACHE_VERSION: u32 = 2;

/// Path of the current-version SWR cache file under `base`.
fn cache_file(base: &Path) -> PathBuf {
    base.join(format!("{CACHE_BASENAME}.v{CACHE_VERSION}.json"))
}

/// Remove cache files left by older builds (any `installed_apps_cache*.json` that isn't the
/// current version). Best-effort — keeps `base` tidy and reclaims disk after an upgrade.
/// Called only on refresh/miss paths, never on the hot read path.
fn prune_stale_caches(base: &Path) {
    let keep = cache_file(base);
    let Ok(dir) = std::fs::read_dir(base) else {
        return;
    };
    for dirent in dir.flatten() {
        let path = dirent.path();
        let is_cache = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(CACHE_BASENAME) && n.ends_with(".json"));
        if is_cache && path != keep {
            let _ = std::fs::remove_file(&path);
        }
    }
}

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

    // Skip background/agent bundles (menu-bar helpers, URL handlers, login items) — a user doesn't
    // think of these as "apps to exclude", and they clutter the picker (e.g. "… URL Handler").
    // LSUIElement / LSBackgroundOnly are the standard Info.plist markers; plutil emits them as a
    // JSON bool or (for string-valued plists) "1"/"true".
    let flag_true = |k: &str| {
        plist.get(k).is_some_and(|v| {
            v.as_bool() == Some(true) || v.as_str() == Some("1") || v.as_str() == Some("true")
        })
    };
    if flag_true("LSUIElement") || flag_true("LSBackgroundOnly") {
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

/// Best-effort 64×64 PNG icon for `app` as a `data:image/png;base64,…` URL, or `None` if every
/// strategy fails. Icons are cosmetic, so a failure here never drops the app from the catalog.
///
/// Fast path: a standalone `.icns` decoded by `sips` (covers ~all third-party apps). Fallback:
/// apps with no `.icns` — most macOS system apps (Calendar, Books, …) keep their icon in an
/// `Assets.car` asset catalog that `sips` can't read — are rendered via AppKit's `NSWorkspace`.
fn icon_data_url(app: &Path, plist: &serde_json::Value) -> Option<String> {
    if let Some(url) = icns_path(app, plist).and_then(|icns| icon_from_icns(&icns)) {
        return Some(url);
    }
    icon_via_nsworkspace(app)
}

/// Decode an `.icns` to a 64×64 PNG data-URL via `sips`. `None` on any `sips`/read failure.
fn icon_from_icns(icns: &Path) -> Option<String> {
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
        .arg(icns)
        .arg("--out")
        .arg(&tmp)
        .output()
        .ok();

    let ok = status.map(|o| o.status.success()).unwrap_or(false);
    let png = if ok { std::fs::read(&tmp).ok() } else { None };
    let _ = std::fs::remove_file(&tmp); // clean up regardless of outcome

    png.map(|bytes| format!("data:image/png;base64,{}", base64_encode(&bytes)))
}

/// Render an app's Finder icon to a 64×64 PNG data-URL via AppKit's `NSWorkspace`, for apps
/// whose icon lives in an `Assets.car` asset catalog rather than a standalone `.icns` (e.g.
/// macOS system apps like Calendar and Books). `None` on any failure.
///
/// Thread-safety: `NSWorkspace`'s icon methods and offscreen `NSImage`/`NSBitmapImageRep`
/// bitmap generation are usable from any thread (AppKit Thread Safety Summary). This matters
/// because [`enumerate`] runs off the main thread — both on the SWR background-refresh thread
/// and on the Tauri command worker that services a cache miss.
fn icon_via_nsworkspace(app: &Path) -> Option<String> {
    use objc2_app_kit::{NSBitmapImageFileType, NSBitmapImageRep, NSWorkspace};
    use objc2_foundation::{NSDictionary, NSSize, NSString};

    let path = NSString::from_str(app.to_str()?);
    let image = NSWorkspace::sharedWorkspace().iconForFile(&path);
    // Render at 64×64 to match the `sips` path and bound the data-URL size — the icon carries
    // representations up to 512×512, and `TIFFRepresentation` would otherwise emit the largest.
    image.setSize(NSSize {
        width: 64.0,
        height: 64.0,
    });
    let tiff = image.TIFFRepresentation()?;
    let bitmap = NSBitmapImageRep::imageRepWithData(&tiff)?;
    let props = NSDictionary::new();
    // SAFETY: `props` is a valid (empty) properties dictionary of the expected key/value types
    // and `NSBitmapImageFileType::PNG` is a valid storage type; the method has no further
    // preconditions. It returns an autoreleased `NSData` (or nil), handled as `Option`.
    let png =
        unsafe { bitmap.representationUsingType_properties(NSBitmapImageFileType::PNG, &props) }?;
    Some(format!(
        "data:image/png;base64,{}",
        base64_encode(&png.to_vec())
    ))
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
    let final_path = cache_file(base);
    // Per-process temp name so a concurrent refresh in another process can't clobber ours.
    let tmp_path = base.join(format!(
        "{CACHE_BASENAME}.v{CACHE_VERSION}.{}.tmp",
        std::process::id()
    ));
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
    let cache_path = cache_file(base);
    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
        // Serve the cache instantly; refresh in the background for next time.
        let base = base.to_path_buf();
        std::thread::spawn(move || {
            let fresh = enumerate();
            write_cache(&base, &fresh);
            prune_stale_caches(&base);
        });
        return cached;
    }
    // Cache miss (fresh install *or* an upgrade that bumped CACHE_VERSION): enumerate
    // synchronously so the first caller gets a real list built by the *current* filter, then
    // drop any older-version cache so it can't be served later.
    let fresh = enumerate();
    write_cache(base, &fresh);
    prune_stale_caches(base);
    fresh
}

#[cfg(test)]
mod tests {
    use super::{base64_encode, cache_file, prune_stale_caches, CACHE_BASENAME, CACHE_VERSION};
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spark-apps-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn cache_file_is_version_tagged() {
        let base = PathBuf::from("/some/base");
        let expected = format!("{CACHE_BASENAME}.v{CACHE_VERSION}.json");
        assert_eq!(
            cache_file(&base).file_name().unwrap().to_str().unwrap(),
            expected
        );
    }

    #[test]
    fn prune_removes_old_versions_keeps_current() {
        let base = tmp("prune");
        // Current-version cache + a stale older-version cache + an unrelated file.
        let current = cache_file(&base);
        let stale = base.join(format!("{CACHE_BASENAME}.v1.json"));
        let unversioned = base.join(format!("{CACHE_BASENAME}.json"));
        let unrelated = base.join("split_tunnel.json");
        for p in [&current, &stale, &unversioned, &unrelated] {
            std::fs::write(p, "[]").unwrap();
        }

        prune_stale_caches(&base);

        assert!(current.exists(), "current-version cache must be kept");
        assert!(!stale.exists(), "older-version cache must be pruned");
        assert!(
            !unversioned.exists(),
            "unversioned (legacy) cache must be pruned"
        );
        assert!(unrelated.exists(), "unrelated files must be left alone");

        let _ = std::fs::remove_dir_all(&base);
    }

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
