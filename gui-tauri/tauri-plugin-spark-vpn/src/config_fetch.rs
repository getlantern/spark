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

/// Whether the app owns config fetching right now.
///
/// Exactly one process may fetch at a time. While the tunnel is up the network extension owns it:
/// it self-fetches on its own schedule, and its pool is what the UI shows (`servers()` reads the
/// NE's live snapshot when connected). An app fetch layered on top produces a *second, independent*
/// assignment for the same account — the two disagree about which servers exist, and the UI ends up
/// offering a location the tunnel has no member for.
pub(crate) fn app_owns_fetching() -> bool {
    let (_, raw) = crate::desktop::ne_spike::load_first_status(std::time::Duration::from_secs(2));
    app_owns_fetching_in(crate::desktop::ne_spike::ui_state(raw))
}

/// The rule itself, split from reading the live status so it can be tested.
///
/// "connecting" is deliberately the tunnel's: control transfers at the connect *attempt*, not at
/// success, so a fetch cannot race a bringup and mint a second assignment mid-handover.
pub(crate) fn app_owns_fetching_in(state: &str) -> bool {
    matches!(state, "disconnected" | "failed")
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

#[cfg(test)]
mod tests {
    use super::config_changed;

    /// Exactly one process fetches at a time. While the tunnel is up the NE owns it — an app fetch
    /// layered on top mints a second, independent assignment for the same account, and the two
    /// disagree about which servers exist. That is what made the UI offer a location the tunnel had
    /// no member for.
    #[test]
    fn only_a_down_tunnel_leaves_fetching_to_the_app() {
        use super::app_owns_fetching_in;

        assert!(app_owns_fetching_in("disconnected"));
        // A failed session is not serving traffic and will not refresh, so the app takes over
        // rather than leaving the list frozen at whatever the NE last published.
        assert!(app_owns_fetching_in("failed"));

        assert!(!app_owns_fetching_in("connected"));
        // Control transfers at the connect ATTEMPT, not at success: a fetch racing a bringup would
        // be exactly the concurrent second assignment this rule exists to prevent.
        assert!(!app_owns_fetching_in("connecting"));
        // Anything unrecognized belongs to the tunnel — the safe direction is to not fetch, since a
        // missed refresh is recoverable and a divergent assignment is what breaks selection.
        assert!(!app_owns_fetching_in("something-new"));
    }

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
