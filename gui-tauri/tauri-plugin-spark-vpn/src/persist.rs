//! Durable settings persistence for the spark-vpn plugin.
//!
//! All functions take an explicit `base: &Path` (the platform-provided app config dir, e.g.
//! `~/Library/Application Support/org.getlantern.spark` on macOS) instead of resolving it
//! themselves.  The caller — `platform::control()` in `lib.rs` — resolves the dir from the
//! Tauri `AppHandle` and passes it in, so these functions are pure I/O with no Tauri coupling.
//!
//! The on-disk layout mirrors what `gui-tauri/src-tauri/src/config.rs` writes today:
//!   `<base>/split_tunnel.json`
//!   `<base>/routing_mode.txt`
//!   `<base>/ad_block.txt`
//!
//! Validation/canonicalization is byte-for-byte identical to `config.rs`.

use std::path::Path;

use serde::{Deserialize, Serialize};

// ── SplitTunnel shape ─────────────────────────────────────────────────────────

/// The split-tunnel list shape, mirroring spark-core's `SplitTunnel`
/// (core/src/split_tunnel.rs).  Used only to validate + canonicalize the on-disk
/// file on load; `#[serde(default)]` tolerates missing fields, and deserializing
/// rejects non-object JSON (`[]`, `null`, scalars).
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct SplitTunnelShape {
    enabled: bool,
    domains: Vec<String>,
    ips: Vec<String>,
}

// ── Split-tunnel persistence ──────────────────────────────────────────────────

/// Read the persisted split-tunnel list from `<base>/split_tunnel.json`.
///
/// Re-serializes to the canonical `{enabled,domains,ips}` shape, or returns the
/// disabled default `{"enabled":false,"domains":[],"ips":[]}` if the file is missing,
/// unreadable, or doesn't deserialize into that shape.
pub fn load_split_tunnel(base: &Path) -> String {
    fn default() -> String {
        "{\"enabled\":false,\"domains\":[],\"ips\":[]}".to_string()
    }
    std::fs::read_to_string(base.join("split_tunnel.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<SplitTunnelShape>(&s).ok())
        // Re-serialize the validated shape so the returned string is always canonical
        // (missing fields filled, unknown fields dropped).
        .and_then(|shape| serde_json::to_string(&shape).ok())
        .unwrap_or_else(default)
}

/// Persist the split-tunnel list to `<base>/split_tunnel.json`.
///
/// Validates + canonicalizes to the `{enabled,domains,ips}` shape first.  Returns
/// an error on invalid/wrong-shape input so a bad caller surfaces a save failure to
/// the UI rather than writing garbage that a later `load_split_tunnel` would silently
/// discard (losing the user's list).
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_split_tunnel(base: &Path, json: &str) -> crate::Result<()> {
    let shape: SplitTunnelShape = serde_json::from_str(json)
        .map_err(|e| crate::Error::Platform(format!("invalid split-tunnel JSON: {e}")))?;
    let canonical =
        serde_json::to_string(&shape).map_err(|e| crate::Error::Platform(e.to_string()))?;
    std::fs::create_dir_all(base)?;
    std::fs::write(base.join("split_tunnel.json"), canonical)?;
    Ok(())
}

// ── Routing-mode persistence ──────────────────────────────────────────────────

/// Read the persisted routing mode from `<base>/routing_mode.txt`.
///
/// Returns `"smart"` if the file is missing, unreadable, or holds anything other
/// than exactly `"smart"`/`"full"` (trimmed).
pub fn load_routing_mode(base: &Path) -> String {
    std::fs::read_to_string(base.join("routing_mode.txt"))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| s == "smart" || s == "full")
        .unwrap_or_else(|| "smart".to_string())
}

/// Persist the routing mode to `<base>/routing_mode.txt`.
///
/// Rejects any value other than `"smart"`/`"full"` (trimmed) so the UI surfaces a
/// save failure rather than writing garbage.
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_routing_mode(base: &Path, mode: &str) -> crate::Result<()> {
    let m = mode.trim();
    if m != "smart" && m != "full" {
        return Err(crate::Error::Platform(format!(
            "invalid routing mode: {mode:?} (expected \"smart\" or \"full\")"
        )));
    }
    std::fs::create_dir_all(base)?;
    std::fs::write(base.join("routing_mode.txt"), m)?;
    Ok(())
}

// ── Excluded-apps persistence (desktop app split tunneling) ───────────────────
//
// Only macOS `AppleControl` reads/writes these today; the Windows/Linux `ServiceControl` stubs the
// excluded-apps commands (the app-bypass list rides `launch_cfg`, not this persist file, on the
// service path). So they're dead code on non-macOS lib builds — `allow(dead_code)` there rather than
// deleting them, since the on-disk format is shared and the tests below exercise them on every host.

/// Read the persisted excluded-apps list from `<base>/excluded_apps.json`.
///
/// The list is a JSON array of app match keys (macOS: canonical `.app` bundle-root paths,
/// matched by prefix so in-bundle helpers match — not executable paths).  Returns the canonical
/// (re-serialized) array, or the empty-array default `"[]"` if the file is missing, unreadable,
/// or doesn't deserialize into an array of strings.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn load_excluded_apps(base: &Path) -> String {
    std::fs::read_to_string(base.join("excluded_apps.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .map(canonicalize_excluded)
        // Re-serialize the validated shape so the returned string is always a canonical array.
        .and_then(|list| serde_json::to_string(&list).ok())
        .unwrap_or_else(|| "[]".to_string())
}

/// Persist the excluded-apps list to `<base>/excluded_apps.json`.
///
/// Validates that the input is a JSON **array of strings**, canonicalizes it (trim, drop
/// blanks, dedupe while preserving first-seen order), then writes the canonical array.
/// Returns [`crate::Error::Platform`] on wrong-shape input (not an array / non-string
/// elements) so a bad caller surfaces a save failure to the UI rather than writing garbage
/// that a later `load_excluded_apps` would silently discard.
///
/// Creates `base` (and any parents) if they don't exist.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn save_excluded_apps(base: &Path, json: &str) -> crate::Result<()> {
    let list: Vec<String> = serde_json::from_str(json)
        .map_err(|e| crate::Error::Platform(format!("invalid excluded-apps JSON: {e}")))?;
    let canonical = serde_json::to_string(&canonicalize_excluded(list))
        .map_err(|e| crate::Error::Platform(e.to_string()))?;
    std::fs::create_dir_all(base)?;
    std::fs::write(base.join("excluded_apps.json"), canonical)?;
    Ok(())
}

/// Trim each entry, drop blanks, and dedupe while preserving first-seen order.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn canonicalize_excluded(list: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    list.into_iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

// ── Ad-block persistence ──────────────────────────────────────────────────────

/// Read the persisted ad-block toggle from `<base>/ad_block.txt`.
///
/// Returns `true` (ad-block on) unless the file holds `"false"` (trimmed, case-insensitive);
/// a missing/unreadable file or any other contents default to on.
pub fn load_ad_block_enabled(base: &Path) -> bool {
    std::fs::read_to_string(base.join("ad_block.txt"))
        .ok()
        // Only an explicit "false" turns ad-block off; anything else (incl. missing) stays on.
        // Compare the trimmed &str directly (no allocation) and case-insensitively.
        .map(|s| !s.trim().eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

/// Persist the ad-block toggle to `<base>/ad_block.txt` as `"true"`/`"false"`.
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_ad_block_enabled(base: &Path, enabled: bool) -> crate::Result<()> {
    std::fs::create_dir_all(base)?;
    std::fs::write(
        base.join("ad_block.txt"),
        if enabled { "true" } else { "false" },
    )?;
    Ok(())
}

// ── Unbounded (volunteer-proxy) persistence ───────────────────────────────────
//
// One file per setting, mirroring the ad-block/routing-mode scalar files: bools as
// `"true"`/`"false"`, the cumulative counter as decimal text. All five are opt-in, so a
// missing/unreadable/garbage file defaults to off (bools → false, counter → 0) — only an
// explicit `"true"` (trimmed, case-insensitive) turns a bool on.
//
// The unbounded module (`unbounded.rs`, desktop-only) consumes these. Both modules are gated
// `not(target_os = "android")`, so on the Android lib build they're unreferenced; keep the
// `allow(dead_code)` only where that applies (the private helpers below) — the public accessors
// are all used by the desktop `unbounded` commands.

/// Read the persisted `unbounded_enabled` toggle from `<base>/unbounded_enabled.txt`.
///
/// Returns `false` (off) unless the file holds exactly `"true"` (trimmed, case-insensitive);
/// a missing/unreadable file or any other contents default to off.
pub fn load_unbounded_enabled(base: &Path) -> bool {
    load_unbounded_bool(base, "unbounded_enabled.txt")
}

/// Persist the `unbounded_enabled` toggle to `<base>/unbounded_enabled.txt` as `"true"`/`"false"`.
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_unbounded_enabled(base: &Path, enabled: bool) -> crate::Result<()> {
    save_unbounded_bool(base, "unbounded_enabled.txt", enabled)
}

/// Read the persisted `unbounded_auto_enable` toggle from `<base>/unbounded_auto_enable.txt`.
///
/// Returns `false` (off) unless the file holds exactly `"true"` (trimmed, case-insensitive);
/// a missing/unreadable file or any other contents default to off.
pub fn load_unbounded_auto_enable(base: &Path) -> bool {
    load_unbounded_bool(base, "unbounded_auto_enable.txt")
}

/// Persist the `unbounded_auto_enable` toggle to `<base>/unbounded_auto_enable.txt` as
/// `"true"`/`"false"`.
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_unbounded_auto_enable(base: &Path, enabled: bool) -> crate::Result<()> {
    save_unbounded_bool(base, "unbounded_auto_enable.txt", enabled)
}

/// Read the persisted `unbounded_hidden` toggle from `<base>/unbounded_hidden.txt`.
///
/// Returns `false` (not hidden) unless the file holds exactly `"true"` (trimmed,
/// case-insensitive); a missing/unreadable file or any other contents default to not hidden.
pub fn load_unbounded_hidden(base: &Path) -> bool {
    load_unbounded_bool(base, "unbounded_hidden.txt")
}

/// Persist the `unbounded_hidden` toggle to `<base>/unbounded_hidden.txt` as `"true"`/`"false"`.
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_unbounded_hidden(base: &Path, hidden: bool) -> crate::Result<()> {
    save_unbounded_bool(base, "unbounded_hidden.txt", hidden)
}

/// Read the persisted `unbounded_welcome_seen` toggle from `<base>/unbounded_welcome_seen.txt`.
///
/// Returns `false` (welcome not yet seen) unless the file holds exactly `"true"` (trimmed,
/// case-insensitive); a missing/unreadable file or any other contents default to false.
pub fn load_unbounded_welcome_seen(base: &Path) -> bool {
    load_unbounded_bool(base, "unbounded_welcome_seen.txt")
}

/// Persist the `unbounded_welcome_seen` toggle to `<base>/unbounded_welcome_seen.txt` as
/// `"true"`/`"false"`.
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_unbounded_welcome_seen(base: &Path, seen: bool) -> crate::Result<()> {
    save_unbounded_bool(base, "unbounded_welcome_seen.txt", seen)
}

/// Read the persisted cumulative `unbounded_total_helped` counter from
/// `<base>/unbounded_total_helped.txt`.
///
/// Returns `0` if the file is missing, unreadable, or doesn't parse as a decimal `u64`.
pub fn load_unbounded_total_helped(base: &Path) -> u64 {
    std::fs::read_to_string(base.join("unbounded_total_helped.txt"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Persist the cumulative `unbounded_total_helped` counter to
/// `<base>/unbounded_total_helped.txt` as decimal text.
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_unbounded_total_helped(base: &Path, total: u64) -> crate::Result<()> {
    std::fs::create_dir_all(base)?;
    std::fs::write(base.join("unbounded_total_helped.txt"), total.to_string())?;
    Ok(())
}

// ── Diagnostics persistence ───────────────────────────────────────────────────

/// Read the persisted diagnostics toggle from `<base>/diagnostics_enabled.txt`.
///
/// Diagnostics are **OFF by default — strictly opt-in.** This revises the diag design's original
/// §C4 "default-on so the opt-out switch is load-bearing" decision: Spark's users include people in
/// surveilled jurisdictions, and an Unbounded volunteer's diagnostics describe sessions they relayed
/// for censored users, so nothing is reported until the user turns it on. Returns `true` only when
/// the file holds exactly `"true"` (trimmed, case-insensitive); missing, unreadable, truncated, and
/// garbage content all mean off — the same fail-closed shape as the Unbounded opt-ins.
pub fn load_diagnostics_enabled(base: &Path) -> bool {
    load_unbounded_bool(base, "diagnostics_enabled.txt")
}

/// Persist the diagnostics toggle to `<base>/diagnostics_enabled.txt` as
/// `"true"`/`"false"`. Takes effect on next launch (`diag_host::init` runs once).
///
/// Creates `base` (and any parents) if they don't exist.
pub fn save_diagnostics_enabled(base: &Path, enabled: bool) -> crate::Result<()> {
    std::fs::create_dir_all(base)?;
    std::fs::write(
        base.join("diagnostics_enabled.txt"),
        if enabled { "true" } else { "false" },
    )?;
    Ok(())
}

/// Read an opt-in bool setting from `<base>/<file>`: `true` only when the file holds exactly
/// `"true"` (trimmed, case-insensitive); missing/unreadable/other contents default to `false`.
fn load_unbounded_bool(base: &Path, file: &str) -> bool {
    std::fs::read_to_string(base.join(file))
        .ok()
        .map(|s| s.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Write an opt-in bool setting to `<base>/<file>` as `"true"`/`"false"`, creating `base`
/// (and any parents) if they don't exist.
fn save_unbounded_bool(base: &Path, file: &str, value: bool) -> crate::Result<()> {
    std::fs::create_dir_all(base)?;
    std::fs::write(base.join(file), if value { "true" } else { "false" })?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        // Per-process subdir so concurrent test processes / leftover state can't interfere.
        std::env::temp_dir()
            .join(format!(
                "tauri-plugin-spark-vpn-tests-{}",
                std::process::id()
            ))
            .join(name)
    }

    // (a) save_routing_mode rejects "bogus", "", "Smart" without touching the filesystem.
    #[test]
    fn routing_mode_rejects_invalid_values() {
        // Use a dir that must NOT exist after the call (no create_dir_all for rejections).
        let base = tmp("routing_mode_rejects_invalid_values");
        // Ensure it doesn't exist beforehand so we can verify nothing was written.
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            save_routing_mode(&base, "bogus").is_err(),
            "save_routing_mode must reject values other than smart/full"
        );
        assert!(
            save_routing_mode(&base, "").is_err(),
            "save_routing_mode must reject empty string"
        );
        assert!(
            save_routing_mode(&base, "Smart").is_err(),
            "save_routing_mode must reject wrong case"
        );

        // The dir must NOT have been created (validation fires before create_dir_all).
        assert!(
            !base.exists(),
            "save_routing_mode must not touch the filesystem on invalid input"
        );
    }

    // (b) round-trip: save_routing_mode(dir,"full") → load_routing_mode(dir)=="full"
    #[test]
    fn routing_mode_round_trip() {
        let base = tmp("routing_mode_round_trip");
        let _ = std::fs::remove_dir_all(&base);

        save_routing_mode(&base, "full").expect("save_routing_mode(full)");
        assert_eq!(load_routing_mode(&base), "full");

        save_routing_mode(&base, "smart").expect("save_routing_mode(smart)");
        assert_eq!(load_routing_mode(&base), "smart");
    }

    // (b') ad-block round-trip: save(false) → load()==false, save(true) → load()==true.
    #[test]
    fn ad_block_round_trip() {
        let base = tmp("ad_block_round_trip");
        let _ = std::fs::remove_dir_all(&base);

        save_ad_block_enabled(&base, false).expect("save_ad_block_enabled(false)");
        assert!(!load_ad_block_enabled(&base));

        save_ad_block_enabled(&base, true).expect("save_ad_block_enabled(true)");
        assert!(load_ad_block_enabled(&base));
    }

    // (c) split-tunnel round-trip: save a non-trivial object then load returns canonical JSON.
    #[test]
    fn split_tunnel_round_trip() {
        let base = tmp("split_tunnel_round_trip");
        let _ = std::fs::remove_dir_all(&base);

        let input = r#"{"enabled":true,"domains":["x.com"],"ips":[]}"#;
        save_split_tunnel(&base, input).expect("save_split_tunnel");
        let loaded = load_split_tunnel(&base);
        // Canonical JSON must contain the fields we wrote.
        assert!(
            loaded.contains("\"enabled\":true"),
            "loaded JSON must have enabled=true: {loaded}"
        );
        assert!(
            loaded.contains("\"x.com\""),
            "loaded JSON must preserve domain x.com: {loaded}"
        );
    }

    // (d) load_* on a missing dir returns safe defaults.
    #[test]
    fn load_returns_defaults_on_missing_dir() {
        let base = tmp("load_defaults_missing_dir");
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            load_split_tunnel(&base),
            "{\"enabled\":false,\"domains\":[],\"ips\":[]}",
            "load_split_tunnel must return safe default on missing dir"
        );
        assert_eq!(
            load_routing_mode(&base),
            "smart",
            "load_routing_mode must return smart on missing dir"
        );
        assert_eq!(
            load_excluded_apps(&base),
            "[]",
            "load_excluded_apps must return empty array on missing dir"
        );
        assert!(
            load_ad_block_enabled(&base),
            "load_ad_block_enabled must default to on (true) on missing dir"
        );
    }

    // (e) excluded-apps round-trip: save an array, load returns a canonical array with the entries.
    #[test]
    fn excluded_apps_round_trip() {
        let base = tmp("excluded_apps_round_trip");
        let _ = std::fs::remove_dir_all(&base);

        let input = r#"["/Applications/Firefox.app"]"#;
        save_excluded_apps(&base, input).expect("save_excluded_apps");
        let loaded = load_excluded_apps(&base);
        assert!(
            loaded.contains("/Applications/Firefox.app"),
            "loaded JSON must preserve the excluded `.app` bundle-root path: {loaded}"
        );
    }

    // (f) canonicalization: blanks dropped, duplicates removed, first-seen order kept.
    #[test]
    fn excluded_apps_canonicalizes() {
        let base = tmp("excluded_apps_canonicalizes");
        let _ = std::fs::remove_dir_all(&base);

        // "  b  " trims to "b"; the trailing "a"/"" are a dup and a blank.
        let input = r#"["a", "  b  ", "a", ""]"#;
        save_excluded_apps(&base, input).expect("save_excluded_apps");
        assert_eq!(
            load_excluded_apps(&base),
            r#"["a","b"]"#,
            "excluded-apps must be trimmed, deduped, and blank-stripped in first-seen order"
        );
    }

    // (g) save_excluded_apps rejects non-array / wrong-shape JSON without writing anything.
    #[test]
    fn excluded_apps_rejects_non_array() {
        let base = tmp("excluded_apps_rejects_non_array");
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            save_excluded_apps(&base, r#"{"not":"an array"}"#).is_err(),
            "save_excluded_apps must reject a JSON object"
        );
        assert!(
            save_excluded_apps(&base, r#"[1, 2, 3]"#).is_err(),
            "save_excluded_apps must reject an array of non-strings"
        );
        assert!(
            save_excluded_apps(&base, "not json").is_err(),
            "save_excluded_apps must reject invalid JSON"
        );
        assert!(
            !base.exists(),
            "save_excluded_apps must not touch the filesystem on invalid input"
        );
    }

    // (h) unbounded bool toggles all default to false (opt-in) on a missing dir.
    #[test]
    fn unbounded_bools_default_false_on_missing_dir() {
        let base = tmp("unbounded_bools_default_false");
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            !load_unbounded_enabled(&base),
            "load_unbounded_enabled must default to false (opt-in)"
        );
        assert!(
            !load_unbounded_auto_enable(&base),
            "load_unbounded_auto_enable must default to false (opt-in)"
        );
        assert!(
            !load_unbounded_hidden(&base),
            "load_unbounded_hidden must default to false"
        );
        assert!(
            !load_unbounded_welcome_seen(&base),
            "load_unbounded_welcome_seen must default to false"
        );
    }

    // (i) unbounded_total_helped counter defaults to 0 on a missing dir.
    #[test]
    fn unbounded_total_helped_defaults_zero_on_missing_dir() {
        let base = tmp("unbounded_total_helped_default");
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            load_unbounded_total_helped(&base),
            0,
            "load_unbounded_total_helped must default to 0"
        );
    }

    // (j) each unbounded bool round-trips: save(true) → load()==true, save(false) → load()==false.
    #[test]
    fn unbounded_bools_round_trip() {
        let base = tmp("unbounded_bools_round_trip");
        let _ = std::fs::remove_dir_all(&base);

        save_unbounded_enabled(&base, true).expect("save_unbounded_enabled(true)");
        assert!(load_unbounded_enabled(&base));
        save_unbounded_enabled(&base, false).expect("save_unbounded_enabled(false)");
        assert!(!load_unbounded_enabled(&base));

        save_unbounded_auto_enable(&base, true).expect("save_unbounded_auto_enable(true)");
        assert!(load_unbounded_auto_enable(&base));
        save_unbounded_auto_enable(&base, false).expect("save_unbounded_auto_enable(false)");
        assert!(!load_unbounded_auto_enable(&base));

        save_unbounded_hidden(&base, true).expect("save_unbounded_hidden(true)");
        assert!(load_unbounded_hidden(&base));
        save_unbounded_hidden(&base, false).expect("save_unbounded_hidden(false)");
        assert!(!load_unbounded_hidden(&base));

        save_unbounded_welcome_seen(&base, true).expect("save_unbounded_welcome_seen(true)");
        assert!(load_unbounded_welcome_seen(&base));
        save_unbounded_welcome_seen(&base, false).expect("save_unbounded_welcome_seen(false)");
        assert!(!load_unbounded_welcome_seen(&base));
    }

    // (k') diagnostics toggle defaults to ON (opt-out) on a missing dir, unlike the
    // opt-in unbounded bools.
    #[test]
    fn diagnostics_enabled_defaults_false_on_missing_dir() {
        let base = tmp("diagnostics_enabled_default");
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            !load_diagnostics_enabled(&base),
            "diagnostics must be strictly opt-in: default OFF on a missing dir"
        );
        // Garbage / partial content must also fail closed, never enable reporting.
        std::fs::create_dir_all(&base).expect("create base");
        for content in ["", " ", "yes", "1", "tru", "TRUE\n\u{0}"] {
            std::fs::write(base.join("diagnostics_enabled.txt"), content).expect("write");
            if content.trim().eq_ignore_ascii_case("true") {
                continue;
            }
            assert!(
                !load_diagnostics_enabled(&base),
                "{content:?} must not enable diagnostics"
            );
        }
    }

    // (k'') diagnostics toggle round-trips: save(false) → load()==false, save(true) → true.
    #[test]
    fn diagnostics_enabled_round_trip() {
        let base = tmp("diagnostics_enabled_round_trip");
        let _ = std::fs::remove_dir_all(&base);

        save_diagnostics_enabled(&base, false).expect("save_diagnostics_enabled(false)");
        assert!(!load_diagnostics_enabled(&base));

        save_diagnostics_enabled(&base, true).expect("save_diagnostics_enabled(true)");
        assert!(load_diagnostics_enabled(&base));
    }

    // (k) unbounded_total_helped round-trips a non-default u64 value.
    #[test]
    fn unbounded_total_helped_round_trip() {
        let base = tmp("unbounded_total_helped_round_trip");
        let _ = std::fs::remove_dir_all(&base);

        save_unbounded_total_helped(&base, 42).expect("save_unbounded_total_helped(42)");
        assert_eq!(load_unbounded_total_helped(&base), 42);

        save_unbounded_total_helped(&base, 0).expect("save_unbounded_total_helped(0)");
        assert_eq!(load_unbounded_total_helped(&base), 0);
    }
}
