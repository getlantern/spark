//! App-side startup config fetch (desktop, Phase 2a). Runs spark-core's kindling `load_or_fetch`
//! against the SAME shared cache dir the tunnel uses ([`crate::desktop::shared_config_cache_dir`]),
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

/// Run one kindling config fetch into the shared cache `dir`. Returns `Ok(true)` if the cached
/// config changed (caller emits `spark://servers`), `Ok(false)` on 304/unchanged, and `Err` if the
/// fetch failed (caller keeps the cached list — never clobbers). `load_or_fetch` writes the cache
/// itself (cache-first + conditional); we ignore its returned `Config`/`CacheMeta` and let Phase 1's
/// `servers_from_cache()` re-read the file on the next `servers()` pull. Never blocks the caller's
/// critical path — run it on a detached background task.
///
/// The before/after snapshots aren't locked against the tunnel process writing the same cache
/// concurrently. That's intentional and safe: the only observable effect of an interleave is a
/// possible **false-positive** `true` (the `after` bytes reflect the tunnel's write, not ours),
/// which just triggers one extra `servers()` re-pull — harmless. A false negative is covered by the
/// UI's 2–3s poll. Serializing would need a cross-process lock for no correctness gain.
pub(crate) async fn fetch_into_shared_cache(dir: &Path) -> std::io::Result<bool> {
    let before = snapshot(dir);
    let env = spark_core::config::fetch::FetchEnv::from_env();
    let _ = spark_core::config::fetch::load_or_fetch(dir, &env).await?;
    let after = snapshot(dir);
    Ok(config_changed(&before, &after))
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
