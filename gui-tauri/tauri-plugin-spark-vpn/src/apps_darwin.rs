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
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Guards against unbounded background refresh threads: repeated `list_installed_apps` calls (UI
/// polling / multiple windows) each hit the cache and would otherwise each spawn a full enumeration.
/// Only one SWR refresh runs at a time; concurrent cache hits skip spawning while it's in flight.
static REFRESH_INFLIGHT: AtomicBool = AtomicBool::new(false);

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
/// v3: icons come from NSWorkspace for *every* app then downscaled via sips (fixes Books's stub
///     `.icns` rendering blank, and Calendar's un-downscaled multi-MB icon bloating the cache).
/// v4: reverted v3's slow/blank NSWorkspace-TIFF→sips path — sips-on-`.icns` is primary again
///     (fast), stub `.icns` skipped, NSWorkspace+NSBitmapImageRep only for `.icns`-less apps.
/// v5: filter Spark's own bundle (`org.getlantern.spark`) from the picker.
const CACHE_VERSION: u32 = 5;

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

/// The directories scanned for `*.app` bundles (one level deep). Includes the `Utilities`
/// subfolders so nested system apps (Terminal, Activity Monitor, …) appear in the catalog.
/// `~/Applications` (and its `Utilities`) is appended when `HOME` is set.
fn scan_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/Applications/Utilities"),
        PathBuf::from("/System/Applications"),
        PathBuf::from("/System/Applications/Utilities"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let user_apps = PathBuf::from(home).join("Applications");
        roots.push(user_apps.join("Utilities"));
        roots.push(user_apps);
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

    // Skip bundles that can't or shouldn't be offered as exclusions:
    //  - Safari: its network traffic flows through the shared `com.apple.WebKit.Networking` system
    //    process (outside any app bundle), so a per-process / bundle-prefix match can never
    //    attribute Safari's flows — offering it would be a broken promise.
    //  - Spark itself: excluding our own app from its own VPN is meaningless (and confusing).
    match plist.get("CFBundleIdentifier").and_then(|v| v.as_str()) {
        Some("com.apple.Safari") | Some("org.getlantern.spark") => return None,
        _ => {}
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

/// Below this size a bundle's `.icns` is treated as a *stub*: some system apps (e.g. Books) ship
/// a ~2 KB placeholder `.icns` whose real icon lives in `Assets.car`, and `sips` would convert
/// that stub to a blank image. Under this threshold we skip the `.icns` and let NSWorkspace
/// render the true Finder icon instead. Real app icons are far larger (tens of KB to ~1 MB).
const MIN_USABLE_ICNS_BYTES: u64 = 4096;

/// Best-effort 64×64 PNG icon for `app` as a `data:image/png;base64,…` URL, or `None` if every
/// strategy fails. Icons are cosmetic, so a failure here never drops the app from the catalog.
///
/// Fast path: decode the bundle's standalone `.icns` with `sips` — quick (no giant AppKit TIFF)
/// and correct for nearly every third-party app. A *stub* `.icns` (see [`MIN_USABLE_ICNS_BYTES`])
/// is skipped so it doesn't yield a blank. Fallback: apps with no usable `.icns` — asset-catalog
/// system apps (Calendar) and stub-`.icns` apps (Books), whose real icon is in `Assets.car` — are
/// rendered via AppKit's `NSWorkspace`.
fn icon_data_url(app: &Path, plist: &serde_json::Value) -> Option<String> {
    if let Some(url) = icns_path(app, plist)
        .filter(|icns| {
            std::fs::metadata(icns)
                .map(|m| m.len() >= MIN_USABLE_ICNS_BYTES)
                .unwrap_or(false)
        })
        .and_then(|icns| sips_png_data_url(&icns))
    {
        return Some(url);
    }
    icon_via_nsworkspace(app)
}

/// Render an app's Finder icon to a 64×64 PNG data-URL via AppKit's `NSWorkspace`, for apps with
/// no usable standalone `.icns` — asset-catalog system apps (Calendar) and stub-`.icns` apps
/// (Books), whose real icon lives in `Assets.car`. `None` on any failure.
///
/// The icon is decoded with AppKit's own `NSBitmapImageRep`, **not** `sips`: `NSWorkspace`'s
/// `TIFFRepresentation` is a ~70 MB *multi-representation* image that `sips` mis-decodes into a
/// blank (and whose per-app temp-file round-trip is painfully slow), whereas `NSBitmapImageRep`
/// decodes it correctly in-process. The resulting (large, native-res) PNG is then downscaled to a
/// small 64×64 with `sips` — which *is* reliable on a single-image PNG — falling back to the
/// full-size PNG if that downscale fails. Only the handful of apps without a usable `.icns` reach
/// this path, so the extra work is bounded.
///
/// Thread-safety: `NSWorkspace`'s icon methods and offscreen `NSImage`/`NSBitmapImageRep` bitmap
/// generation are usable from any thread (AppKit Thread Safety Summary). This matters because
/// [`enumerate`] runs off the main thread — on the SWR refresh thread and the Tauri command worker.
///
/// The AppKit work is wrapped in an [`autoreleasepool`](objc2::rc::autoreleasepool): these calls
/// return autoreleased objects (the icon `NSImage`, the multi-MB `TIFFRepresentation`, the PNG
/// `NSData`), and background threads have no implicit pool — without an explicit one they would
/// accumulate across the whole app enumeration and cause large transient memory growth.
fn icon_via_nsworkspace(app: &Path) -> Option<String> {
    use objc2::rc::autoreleasepool;
    use objc2_app_kit::{NSBitmapImageFileType, NSBitmapImageRep, NSWorkspace};
    use objc2_foundation::{NSDictionary, NSString};

    // The PNG bytes are copied out of the pool (`to_vec`) before it drains, so the returned
    // `Vec`/data-URL outlives the autoreleased AppKit objects.
    let bytes = autoreleasepool(|_pool| {
        let path = NSString::from_str(app.to_str()?);
        let image = NSWorkspace::sharedWorkspace().iconForFile(&path);
        let tiff = image.TIFFRepresentation()?;
        let bitmap = NSBitmapImageRep::imageRepWithData(&tiff)?;
        let props = NSDictionary::new();
        // SAFETY: `props` is a valid (empty) properties dictionary of the expected key/value types
        // and `NSBitmapImageFileType::PNG` is a valid storage type; the method has no further
        // preconditions. It returns an autoreleased `NSData` (or nil), handled as `Option`.
        let png = unsafe {
            bitmap.representationUsingType_properties(NSBitmapImageFileType::PNG, &props)
        }?;
        Some(png.to_vec())
    })?;
    // Downscale the valid (but native-res, often >1 MB) PNG to a consistent 64×64 to keep the
    // cache small; keep the full-size PNG if `sips` fails so we never regress to no icon.
    sips_png_data_url_from_bytes(&bytes, "png")
        .or_else(|| Some(format!("data:image/png;base64,{}", base64_encode(&bytes))))
}

/// A hard-to-predict token for the per-call temp directory name: pid + a monotonic counter + a
/// wall-clock nanosecond component.
fn temp_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        NEXT_ICON.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        nanos
    )
}

/// Run `f` with a freshly-created, owner-only (0700) per-call temp **directory**, removing it (and
/// its contents) afterward. Scratch files (the `sips` source/output) go inside it, not directly in
/// the world-writable temp root — this closes the symlink/clobber race: `create_dir` (not
/// `create_dir_all`) fails if the path already exists, so a pre-created path from another local
/// user aborts the operation (returns `None`) instead of letting `sips` write through an attacker's
/// symlink. Best-effort — any fs error yields `None`, leaving the app iconless (never fatal).
fn with_temp_dir<T>(f: impl FnOnce(&Path) -> Option<T>) -> Option<T> {
    let dir = std::env::temp_dir().join(format!("spark-icons-{}", temp_nonce()));
    // Create with mode 0700 **atomically** at creation (not create-then-chmod, which leaves a
    // world-readable window and could stay 0755 if the chmod fails). `create` (not `create_all`)
    // fails if the path already exists → anti-clobber.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir).ok()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(&dir).ok()?;
    }
    let out = f(&dir);
    let _ = std::fs::remove_dir_all(&dir); // clean up regardless of outcome
    out
}

/// Run `sips` to convert on-disk `input` (`.icns`, `.tiff`, `.png`, …) into a 64×64 PNG at `out`;
/// returns the PNG bytes, or `None` on any `sips`/read failure.
fn sips_convert(input: &Path, out: &Path) -> Option<Vec<u8>> {
    let ok = Command::new("/usr/bin/sips")
        .arg("-z")
        .arg("64")
        .arg("64")
        .arg("-s")
        .arg("format")
        .arg("png")
        .arg(input)
        .arg("--out")
        .arg(out)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        std::fs::read(out).ok()
    } else {
        None
    }
}

/// Convert an on-disk image file (`.icns`, `.tiff`, …) to a 64×64 PNG data-URL via `sips`.
/// `None` on any `sips`/read failure.
fn sips_png_data_url(input: &Path) -> Option<String> {
    with_temp_dir(|dir| {
        let bytes = sips_convert(input, &dir.join("out.png"))?;
        Some(format!("data:image/png;base64,{}", base64_encode(&bytes)))
    })
}

/// Write `bytes` to a temp file with extension `ext` and convert it via `sips`, so `sips` can
/// decode an in-memory image (e.g. the `NSWorkspace` TIFF). Both scratch files live in a private
/// per-call directory that is removed afterward.
fn sips_png_data_url_from_bytes(bytes: &[u8], ext: &str) -> Option<String> {
    with_temp_dir(|dir| {
        let src = dir.join(format!("src.{ext}"));
        std::fs::write(&src, bytes).ok()?;
        let png = sips_convert(&src, &dir.join("out.png"))?;
        Some(format!("data:image/png;base64,{}", base64_encode(&png)))
    })
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
    // `sort_by_cached_key` computes each lowercase key once, not on every comparison.
    entries.sort_by_cached_key(|a| a.name.to_lowercase());
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

/// Atomically write `json` to `cache_file(base)` (`installed_apps_cache.v<N>.json`) (temp file + rename), so
/// a reader never sees a half-written cache. Best-effort — errors are logged, not fatal.
fn write_cache(base: &Path, json: &str) {
    if std::fs::create_dir_all(base).is_err() {
        return;
    }
    let final_path = cache_file(base);
    // Per-call temp name (pid + counter + nanos) so two writers — even in the same process (a
    // cache-miss racing a background refresh) — never target the same `.tmp` and clobber each other.
    let tmp_path = base.join(format!(
        "{CACHE_BASENAME}.v{CACHE_VERSION}.{}.tmp",
        temp_nonce()
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
/// Stale-while-revalidate: if a cache exists at `cache_file(base)` (`installed_apps_cache.v<N>.json`), return
/// it immediately and kick off a background refresh (so the next call sees fresh data).
/// On a cache miss, enumerate synchronously, persist, and return.
pub fn list_installed_apps(base: &Path) -> String {
    let cache_path = cache_file(base);
    // Only serve a cache file that is actually a JSON array — it's user-writable disk state, so a
    // corrupted/partial/hand-edited file would otherwise be returned verbatim and crash the
    // frontend's `JSON.parse(...) as InstalledApp[]`. An invalid cache is treated as a miss.
    let cached = std::fs::read_to_string(&cache_path)
        .ok()
        .filter(|c| serde_json::from_str::<serde_json::Value>(c).is_ok_and(|v| v.is_array()));
    if let Some(cached) = cached {
        // Serve the cache instantly; refresh in the background for next time. Only spawn if no
        // refresh is already in flight — otherwise repeated cache hits (UI polling / multiple
        // windows) would pile up unbounded threads each running a full enumeration. The spawned
        // thread clears the flag when done so the next call can refresh again.
        if REFRESH_INFLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let base = base.to_path_buf();
            std::thread::spawn(move || {
                let fresh = enumerate();
                write_cache(&base, &fresh);
                prune_stale_caches(&base);
                REFRESH_INFLIGHT.store(false, Ordering::Release);
            });
        }
        return cached;
    }
    // Cache miss (fresh install, an upgrade that bumped CACHE_VERSION, or an invalid cache file):
    // enumerate synchronously so the first caller gets a real list built by the *current* filter,
    // then drop any older-version cache so it can't be served later.
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
