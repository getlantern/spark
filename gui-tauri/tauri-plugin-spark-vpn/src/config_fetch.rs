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
    // Advertise the TUNNEL's capabilities, not this process's. The app links spark-core without the
    // wasm host and could never run a delivered module itself — but it never tunnels either: on
    // Apple every tunnel runs in the network extension, which does have it. Deriving the set from
    // this binary's features made the app ask a different question than the NE, so the server
    // withheld delivered-module outbounds from the app and the two disagreed about which servers
    // exist — the UI offered one the tunnel had no member for, and traffic silently took another.
    //
    // Conditional, not unconditional: the module host is only in the tunnel when a production
    // module-signing key was pinned at build time, and that is true on Windows and Linux exactly as
    // it is on Apple (`tunnel_runs_delivered_modules` documents the shared build rule). Claiming it
    // on a build without one would be the same divergence pointing the other way — the server would
    // send a module-bearing outbound to a tunnel that must skip it. When it is absent we declare
    // nothing and fall back to the default set derived from this build.
    let env = spark_core::config::fetch::FetchEnv::from_env();
    let env = if spark_core::config::fetch::tunnel_runs_delivered_modules() {
        env.with_capabilities(vec![
            spark_core::config::fetch::CAPABILITY_TRANSPORT_MODULES.to_string(),
        ])
    } else {
        env
    };
    let _ = spark_core::config::fetch::load_or_fetch(dir, &env).await?;
    let after = snapshot(dir);
    Ok(config_changed(&before, &after))
}

/// The cached config-new body, if one has been fetched.
pub(crate) fn cached_config(dir: &Path) -> Option<String> {
    snapshot(dir).and_then(|b| String::from_utf8(b).ok())
}

/// Whether this platform's tunnel refreshes config on its own while it is up.
///
/// On Apple the tunnel runs in the network extension in `lantern-api` mode and re-fetches on its own
/// schedule. On Windows and Linux the privileged service is *handed* a config — `Connect` carries
/// none and the service starts the active profile or its launch config — so it never fetches, and
/// the app must keep fetching for it.
const TUNNEL_SELF_FETCHES: bool = cfg!(any(target_os = "macos", target_os = "ios"));

/// Whether the app owns config fetching right now.
///
/// Two things force this, and they point the same way:
///
/// 1. **One fetcher.** `/config-new` *assigns*, so two fetchers hold two independent assignments for
///    one account and disagree about which servers exist — the UI then offers a location the tunnel
///    has no member for.
/// 2. **The fetch must bypass the tunnel.** While the tunnel is up it carries the app's traffic too;
///    the app's sockets are not pinned to the physical interface and (on iOS) cannot be. A fetch
///    routed through the tunnel is geolocated to the *exit*, so the server assigns servers for the
///    exit's country rather than the user's — and a broken pool could never fetch its replacement.
///    The tunnel's own sockets *are* pinned (`transport.protect_interface`), so while it is up it is
///    the only party that can fetch correctly.
///
/// So the app fetches only while the tunnel is down. While it is up, the tunnel refreshes and the UI
/// reads its live pool through `servers()`. Where the tunnel does not self-fetch, the app keeps
/// fetching regardless — standing down would freeze the list and nothing else would refresh it.
pub(crate) async fn app_owns_fetching<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> bool {
    if !TUNNEL_SELF_FETCHES {
        return true;
    }
    // Off the async runtime: reading the tunnel's status blocks for seconds (see
    // `commands::tunnel_state_async`), and every caller here is inside a spawned task.
    match crate::commands::tunnel_state_async(app).await {
        Some(state) => app_owns_fetching_in(&state),
        // No readable tunnel status: nothing is up to be fetching or to route us through, so the app
        // owns it. This is the ordinary first-run case (no tunnel configured yet); treating it as the
        // tunnel's would leave a fresh install never fetching at all.
        None => true,
    }
}

/// The rule itself, split from reading the live status so it can be tested.
///
/// "connecting" is deliberately the tunnel's: control transfers at the connect *attempt*, not at
/// success, so a fetch cannot race a bringup — and by the time it landed the tunnel might already be
/// carrying it.
pub(crate) fn app_owns_fetching_in(state: &str) -> bool {
    if !TUNNEL_SELF_FETCHES {
        return true;
    }
    matches!(state, "disconnected" | "failed")
}

#[cfg(test)]
mod tests {
    use super::config_changed;

    /// Exactly one process fetches at a time, and while the tunnel is up it must be the tunnel: it
    /// carries the app's traffic, so an app fetch would be geolocated to the exit and assign servers
    /// for the wrong country — and on iOS the app cannot bypass it at all. Where the tunnel does not
    /// fetch for itself, the app must keep going or nothing refreshes the list.
    #[test]
    fn the_fetcher_is_whoever_can_reach_the_api_directly() {
        use super::{app_owns_fetching_in, TUNNEL_SELF_FETCHES};

        // True everywhere: a tunnel that is down neither fetches nor routes us.
        assert!(app_owns_fetching_in("disconnected"));
        assert!(app_owns_fetching_in("failed"));

        if TUNNEL_SELF_FETCHES {
            assert!(!app_owns_fetching_in("connected"));
            // Control transfers at the connect ATTEMPT: a fetch racing a bringup could land after
            // the tunnel is already carrying it, which is the case this rule exists to prevent.
            assert!(!app_owns_fetching_in("connecting"));
            assert!(!app_owns_fetching_in("something-new"));
        } else {
            for state in ["connected", "connecting", "disconnecting", "something-new"] {
                assert!(
                    app_owns_fetching_in(state),
                    "{state}: nothing else fetches here, so the app must not stand down"
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
