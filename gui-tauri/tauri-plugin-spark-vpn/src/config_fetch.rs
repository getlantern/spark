//! App-side startup config fetch (desktop, Phase 2a). Runs spark-core's kindling `load_or_fetch`
//! into the app's OWN config cache dir ([`crate::desktop::app_config_cache_dir`]) — on macOS the NE
//! keeps a separate cache (the sysext sandbox blocks the user container, so they can't be shared) —
//! so the location list refreshes on every launch regardless of VPN state. Change is detected by
//! comparing the raw cache bytes before/after the fetch — cheap, exact, and independent of
//! `load_or_fetch`'s internal 304 signalling. On a change the caller emits `spark://servers`; on
//! 304/unchanged or failure it does nothing (the cached list is never clobbered).
//!
//! Android does NOT use this module: its core runs in the `:vpn` process and the fetch is triggered
//! there over IPC (Phase 2b), so this stays desktop-only (gated in `lib.rs`).

use std::path::Path;

/// True if the cached raw config changed between `before` and `after` snapshots (either may be
/// `None` when the file was absent). Used to decide whether to emit `spark://servers`.
pub(crate) fn config_changed(before: &Option<Vec<u8>>, after: &Option<Vec<u8>>) -> bool {
    before != after
}

/// The raw `config_raw.json` bytes in `dir`, or `None` if absent/unreadable.
fn snapshot(dir: &Path) -> Option<Vec<u8>> {
    std::fs::read(dir.join("config_raw.json")).ok()
}

/// Run one kindling config fetch into the app's cache `dir`. Returns `Ok(true)` if the cached
/// config changed (caller emits `spark://servers`), `Ok(false)` on 304/unchanged, and `Err` if the
/// fetch failed (caller keeps the cached list — never clobbers). `load_or_fetch` writes the cache
/// itself (cache-first + conditional); we ignore its returned `Config`/`CacheMeta` and let
/// `servers_from_cache()` re-read the file on the next `servers()` pull. Never blocks the caller's
/// critical path — run it on a detached background task.
///
/// The before/after snapshots aren't locked against a concurrent writer of the same file (another
/// app instance, or — on platforms where the dir is shared — the tunnel). That's intentional and
/// safe: the only observable effect of an interleave is a possible **false-positive** `true` (the
/// `after` bytes reflect the other writer's config, not ours), which just triggers one extra
/// `servers()` re-pull — harmless. A false negative is covered by the UI's 2–3s poll. Serializing
/// would need a cross-process lock for no correctness gain.
pub(crate) async fn fetch_into_cache(dir: &Path) -> std::io::Result<bool> {
    let before = snapshot(dir);
    let env = spark_core::config::fetch::FetchEnv::from_env();
    let _ = spark_core::config::fetch::load_or_fetch(dir, &env).await?;
    let after = snapshot(dir);
    Ok(config_changed(&before, &after))
}

/// The cached config-new body, if one has been fetched.
pub(crate) fn cached_config(dir: &Path) -> Option<String> {
    snapshot(dir).and_then(|b| String::from_utf8(b).ok())
}

/// Fetch into the app's cache, then hand the result to the running tunnel.
///
/// The app is the **only** process that fetches. `/config-new` *assigns*, so a tunnel that fetched
/// for itself would hold a second, independent assignment for the same account: the two disagree
/// about which servers exist, and the UI ends up offering a location the tunnel has no member for.
/// Forwarding the app's own bytes keeps one assignment, applied live with no reconnect.
///
/// Pushed on **every** successful fetch, not only a changed one. The push is also what tells the
/// tunnel an app is driving (it retires the daemon's own refresh loop), so waiting for the first
/// change would leave both fetching until then; and a reload with an unchanged config is cheap and
/// keeps the working proxy. Best-effort: a tunnel that is down has nothing to apply to and will read
/// this same config from the cache when it starts, so a failed push never fails the fetch.
pub(crate) async fn fetch_and_push<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    dir: &Path,
) -> std::io::Result<bool> {
    let changed = fetch_into_cache(dir).await?;
    if let Some(raw) = snapshot(dir) {
        if let Ok(raw) = String::from_utf8(raw) {
            use tauri::Manager;
            if let Some(ctl) = app.try_state::<crate::commands::Ctl>() {
                if let Err(e) = ctl.push_config(&raw) {
                    eprintln!("[spark-vpn] config push failed (cached for next connect): {e}");
                }
            }
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::config_changed;

    #[test]
    fn detects_change_and_no_change() {
        let a = Some(b"{\"servers\":[]}".to_vec());
        let b = Some(b"{\"servers\":[{\"country\":\"US\"}]}".to_vec());
        assert!(config_changed(&None, &a)); // first fetch: absent -> present
        assert!(config_changed(&a, &b)); // body changed
        assert!(!config_changed(&a, &a)); // unchanged (304)
        assert!(!config_changed(&None, &None)); // fetch failed, still nothing
    }
}
