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

/// Whether this platform's tunnel refreshes config on its own while it is up.
///
/// The one real platform difference, named once instead of forked across the rule. On Apple the
/// tunnel runs in the network extension in `lantern-api` mode and re-fetches on its own schedule.
/// On Windows and Linux the privileged service is *handed* a config — `Connect` carries none and
/// the service starts the active profile or its launch config (`service.rs`) — so it never fetches.
///
/// When this is false the app is the only fetcher and must keep fetching while connected; standing
/// down would freeze the list for the whole session and prevent nothing. Flip it here when the
/// desktop service gains its own refresh, and the rule below follows.
const TUNNEL_SELF_FETCHES: bool = cfg!(any(target_os = "macos", target_os = "ios"));

/// Whether the app owns config fetching right now.
///
/// Exactly one process may fetch at a time. Where the tunnel fetches for itself, it owns fetching
/// while it is up: its pool is what the UI shows (`servers()` reads the tunnel's live snapshot when
/// connected). An app fetch layered on top produces a *second, independent* assignment for the same
/// account — the two disagree about which servers exist, and the UI ends up offering a location the
/// tunnel has no member for.
///
/// The state is read through [`TunnelControl::status`], which reports the same vocabulary on every
/// platform (`AppleControl` maps `NEVPNStatus`, `ServiceControl` maps `TunnelState`), so this is one
/// rule everywhere rather than a per-platform one.
pub(crate) fn app_owns_fetching<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> bool {
    // Skip the status round trip where it cannot change the answer — on desktop that is an IPC
    // connect to a service which, at app start, is often not running at all.
    if !TUNNEL_SELF_FETCHES {
        return true;
    }
    match crate::commands::tunnel_state(app) {
        Some(state) => app_owns_fetching_in(&state),
        // No readable tunnel status: nothing is up to be fetching, so the app owns it. This is the
        // ordinary first-run case (no tunnel configured yet), and on Apple it is also what a status
        // read that times out reports — treating it as the tunnel's would leave a fresh install
        // never fetching at all.
        None => true,
    }
}

/// The rule itself, split from reading the live status so it can be tested.
///
/// "connecting" is deliberately the tunnel's: control transfers at the connect *attempt*, not at
/// success, so a fetch cannot race a bringup and mint a second assignment mid-handover.
pub(crate) fn app_owns_fetching_in(state: &str) -> bool {
    if !TUNNEL_SELF_FETCHES {
        return true;
    }
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

    /// Exactly one process fetches at a time. Where the tunnel fetches for itself, an app fetch
    /// layered on top mints a second, independent assignment for the same account, and the two
    /// disagree about which servers exist. That is what made the UI offer a location the tunnel had
    /// no member for.
    ///
    /// Where the tunnel does NOT fetch (Windows/Linux today), the app is the only fetcher and must
    /// keep going while connected — standing down would freeze the list for the whole session.
    #[test]
    fn only_a_down_tunnel_leaves_fetching_to_the_app() {
        use super::{app_owns_fetching_in, TUNNEL_SELF_FETCHES};

        // True on every platform: a tunnel that is down never owns fetching.
        assert!(app_owns_fetching_in("disconnected"));
        // A failed session is not serving traffic and will not refresh, so the app takes over
        // rather than leaving the list frozen at whatever the tunnel last published.
        assert!(app_owns_fetching_in("failed"));

        if TUNNEL_SELF_FETCHES {
            assert!(!app_owns_fetching_in("connected"));
            // Control transfers at the connect ATTEMPT, not at success: a fetch racing a bringup
            // would be exactly the concurrent second assignment this rule exists to prevent.
            assert!(!app_owns_fetching_in("connecting"));
            // Anything unrecognized belongs to the tunnel — the safe direction is to not fetch,
            // since a missed refresh is recoverable and a divergent assignment breaks selection.
            assert!(!app_owns_fetching_in("something-new"));
        } else {
            // Nothing else fetches here, so no state may take ownership away from the app.
            for state in ["connected", "connecting", "disconnecting", "something-new"] {
                assert!(
                    app_owns_fetching_in(state),
                    "{state} must not stop the only fetcher"
                );
            }
        }
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
