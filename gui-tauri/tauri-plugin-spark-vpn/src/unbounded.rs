//! Unbounded (volunteer-proxy) control surface for the spark-vpn plugin.
//!
//! Runs the `spark-sharing` peer-proxy pool, folds its per-slot event stream into a live view
//! via [`spark_sharing::Aggregator`], and pushes a `spark://unbounded` snapshot to the UI on every
//! change. Durable settings (enabled / auto-enable / hidden / welcome-seen) and the cumulative
//! `total_helped` counter live in `persist.rs`, keyed off the same platform-provided config dir the
//! rest of the plugin uses.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use spark_core::config::lantern::UnboundedConfig;
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use spark_sharing::{
    start_sharing, Aggregator, FreddieSignaler, GeoResolver, PoolEvent, SharingConfig,
    SharingDelta, SharingHandle, SharingStatus,
};

use crate::unbounded_diag;

/// Live handles for a running sharing pool. The `SharingHandle` is dropped (cooperative cancel) and
/// the aggregation loop `JoinHandle` is aborted on stop; the latest [`SharingStatus`] is kept so
/// `unbounded_status` can report `helpingNow`/`peers` without a live `Aggregator` on hand.
///
/// Both `Mutex`es are `std::sync::Mutex` and are only ever held in tight, non-`await` scopes.
#[derive(Default)]
pub(crate) struct UnboundedState {
    handle: Mutex<Option<SharingHandle>>,
    loop_handle: Mutex<Option<JoinHandle<()>>>,
    latest_status: Mutex<Option<SharingStatus>>,
    /// Serializes `unbounded_start`: held (async-safe) across the whole start so two concurrent
    /// callers can't both pass the "already running?" check and each spin up a pool. A `tokio`
    /// mutex (not `std`) because it is intentionally held across `.await` points.
    start_gate: tokio::sync::Mutex<()>,
}

/// Resolve the persistence base dir (the platform-provided app config dir) the same way
/// `platform::control()` does in `lib.rs`, so the unbounded settings land next to the other
/// durable settings files.
fn base_dir<R: Runtime>(app: &AppHandle<R>) -> crate::Result<PathBuf> {
    app.path()
        .app_config_dir()
        .map_err(|e| crate::Error::Platform(format!("no app config dir: {e}")))
}

/// Read + parse the Unbounded block from the app's own cached `config_raw.json` (the same cache the
/// location list reads). Returns the default (disabled) config when the cache file does not exist yet
/// (the normal pre-first-fetch state) or when it parses but carries no `unbounded`/`features.unbounded`
/// section — so a first-launch client simply reports the feature as unavailable. Other I/O errors and
/// JSON parse failures propagate as an error rather than being masked as "unavailable".
fn read_unbounded_config<R: Runtime>(app: &AppHandle<R>) -> crate::Result<UnboundedConfig> {
    let base = base_dir(app)?;
    let path = crate::desktop::app_config_cache_dir(&base).join("config_raw.json");
    match std::fs::read_to_string(&path) {
        Ok(raw) => spark_core::config::lantern::unbounded_from_config_raw_json(&raw)
            .map_err(|e| crate::Error::Platform(format!("unbounded config parse failed: {e}"))),
        // No cache yet (never fetched) is the normal pre-first-fetch state → feature unavailable.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UnboundedConfig::default()),
        Err(e) => Err(crate::Error::Io(e)),
    }
}

/// Build the sharing config + signaler for the pool from the resolved Lantern config's Unbounded
/// block (`features.unbounded` gate + the top-level `unbounded` block; see
/// [`spark_core::config::lantern::UnboundedConfig`]).
///
/// Returns the typed "unbounded not available" error — keeping `unbounded_start` refusing — when the
/// feature is gated off, the block is missing, or it lacks the endpoints needed to dial. Otherwise it
/// maps the wire fields onto a [`SharingConfig`] (egress URL + session count; STUN is left empty — the
/// config carries none today) and builds a [`FreddieSignaler`] from the signaling endpoint.
fn build_sharing_config<R: Runtime>(
    app: &AppHandle<R>,
) -> crate::Result<(SharingConfig, FreddieSignaler)> {
    let uc = read_unbounded_config(app)?;
    if !uc.is_available() {
        return Err(crate::Error::Platform("unbounded not available".into()));
    }
    let cfg = SharingConfig {
        egress_url: uc.egress_url,
        // The config doesn't carry STUN servers today; an empty list lets the consumer gather
        // host/srflx candidates without an explicit STUN server.
        stun_urls: Vec::new(),
        // `ctable_size` from the wire, clamped to a sane floor (SharingConfig::supervisor_config
        // also clamps 0 → 1, but be explicit so a missing/zero value still yields a usable pool).
        concurrent_sessions: uc.concurrent_sessions.max(1),
        nat_timeout: Duration::from_secs(10),
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(30),
        stable_session: Duration::from_secs(30),
        enable_ipv6: false,
        randomize_dtls: true,
    };
    let signaler = FreddieSignaler::new(&uc.signaling_url)
        .map_err(|e| crate::Error::Platform(format!("unbounded signaler build failed: {e}")))?;
    Ok((cfg, signaler))
}

/// Bump the running total by one for each new peer join. Pure glue, unit-tested below.
fn on_delta(total: &mut u64, delta: &SharingDelta) {
    if let SharingDelta::Joined(_) = delta {
        *total += 1;
    }
}

/// The `spark://unbounded` payload. camelCase keys are the fixed UI contract:
/// `enabled`, `helpingNow`, `totalHelped`, `peers[].sessionId`, `peers[].geo.{countryCode,lat,lon}`.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UnboundedSnapshot {
    enabled: bool,
    helping_now: usize,
    total_helped: u64,
    peers: Vec<PeerPayload>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PeerPayload {
    session_id: String,
    geo: Option<GeoPayload>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct GeoPayload {
    country_code: String,
    lat: f64,
    lon: f64,
}

/// Build a snapshot payload from a [`SharingStatus`] and the persisted total.
fn snapshot_payload(enabled: bool, status: &SharingStatus, total: u64) -> UnboundedSnapshot {
    let peers = status
        .peers
        .iter()
        .map(|p| PeerPayload {
            session_id: p.session_id.clone(),
            geo: p.geo.as_ref().map(|g| GeoPayload {
                country_code: g.country_code.clone(),
                lat: g.lat,
                lon: g.lon,
            }),
        })
        .collect();
    UnboundedSnapshot {
        enabled,
        helping_now: status.helping_now,
        total_helped: total,
        peers,
    }
}

/// Emit the `spark://unbounded` event with the current view. Mirrors how the tray emits
/// `spark://state` (`app.emit(...)` via the `Emitter` trait).
fn emit_snapshot<R: Runtime>(
    app: &AppHandle<R>,
    enabled: bool,
    status: &SharingStatus,
    total: u64,
) {
    let _ = app.emit(
        "spark://unbounded",
        snapshot_payload(enabled, status, total),
    );
    #[cfg(desktop)]
    crate::tray::refresh_unbounded_label(app, enabled, status.helping_now);
}

#[tauri::command]
pub(crate) async fn unbounded_start<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    let base = base_dir(&app)?;
    let state = app.state::<UnboundedState>();

    // Idempotent: if a pool is already running, do nothing. Without this, a double-click, repeated
    // tray toggle, or racing UI call would start a second pool and overwrite the stored handles,
    // orphaning the first pool + its aggregation task (still consuming resources / emitting).
    //
    // Hold the start gate across the whole start (build + spawn + store). `try_lock` makes a second
    // concurrent caller bail immediately instead of blocking, and — because the gate serializes
    // starts — the `handle.is_some()` check below is race-free (only one start runs at a time).
    let _gate = match state.start_gate.try_lock() {
        Ok(gate) => gate,
        Err(_) => return Ok(()),
    };
    if lock_recover(&state.handle).is_some() {
        return Ok(());
    }

    // Refuses with a typed "unbounded not available" error when the feature is gated off or the
    // resolved config lacks the endpoints to dial (see build_sharing_config).
    let (cfg, signaler) = build_sharing_config(&app)?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PoolEvent>();
    // `Arc<FreddieSignaler>` coerces to the `Arc<dyn Signaler>` that `start_sharing` expects.
    let handle = start_sharing(cfg, Arc::new(signaler), Some(tx));

    // Store the handle in a tight, non-await scope.
    *lock_recover(&state.handle) = Some(handle);

    let loop_app = app.clone();
    let loop_base = base.clone();
    let loop_handle = tauri::async_runtime::spawn(async move {
        let mut agg = Aggregator::new();
        let resolver = GeoResolver::new();
        // Seed the cumulative counter once from disk, then keep it in memory — persisting only on a
        // join. Avoids a disk read on every delta, and a poisoned lock can no longer panic the loop
        // (which would leave the pool running but the UI/tray frozen).
        let mut total = crate::persist::load_unbounded_total_helped(&loop_base);
        // §C6 diagnostics: pure per-slot mapper state + snapshot pacing, both on this
        // task's stack. Everything diag-related below is fire-and-forget (see
        // unbounded_diag::apply_actions) — no path can error out of or stall the loop.
        let mut pool_diag = unbounded_diag::PoolDiag::default();
        let mut last_snapshot = std::time::Instant::now();
        while let Some(ev) = rx.recv().await {
            // Copy the diag-relevant fields out before the aggregator consumes the event.
            let view = unbounded_diag::EventView::capture(&ev);
            let delta = agg.apply_with_geo(ev, &resolver).await;
            // peer_region rides the geo the aggregator just resolved for the globe
            // (country only — §C5); None both when unresolved and for non-join deltas.
            // Borrowed from `delta`: the borrow ends at the diag_for_event call, before
            // the `if let` below moves `delta`.
            let region = match &delta {
                Some(SharingDelta::Joined(p)) => p.geo.as_ref().map(|g| g.country_code.as_str()),
                _ => None,
            };
            unbounded_diag::apply_actions(unbounded_diag::diag_for_event(
                &view,
                region,
                &mut pool_diag,
            ));
            if let Some(delta) = delta {
                let joined = matches!(delta, SharingDelta::Joined(_));
                on_delta(&mut total, &delta);
                if joined {
                    if let Err(e) = crate::persist::save_unbounded_total_helped(&loop_base, total) {
                        // error!, not eprintln!: rides the DiagLayer's §C2a error
                        // fast-path so a persist failure is visible in diagnostics.
                        tracing::error!(
                            error = %e,
                            "unbounded: failed to persist total_helped"
                        );
                    }
                }
                let status = agg.status();
                *lock_recover(&loop_app.state::<UnboundedState>().latest_status) =
                    Some(status.clone());
                emit_snapshot(&loop_app, true, &status, total);
            }
            // ~60s §C6 pool snapshot, paced by event arrival (no extra timer task; an
            // idle pool emits none, which the timeline already makes unambiguous).
            if last_snapshot.elapsed() >= unbounded_diag::SNAPSHOT_INTERVAL {
                last_snapshot = std::time::Instant::now();
                spark_core::diag::emit(spark_core::diag::events::unbounded_pool_snapshot(
                    agg.status().helping_now as u64,
                    pool_diag.slots_filled(),
                    total,
                ));
            }
        }

        // The event stream closed without an explicit stop — i.e. the supervisor pool ended on its
        // own (a panic/crash; it otherwise retries forever). `unbounded_stop` aborts this task
        // before this runs, so reaching here means nobody called stop: reflect "off" so the UI/tray
        // don't stay stuck on "enabled" with a dead pool. (Clear the handle first so a racing start
        // sees no pool and starts cleanly.)
        let ustate = loop_app.state::<UnboundedState>();
        *lock_recover(&ustate.handle) = None;
        *lock_recover(&ustate.latest_status) = None;
        let _ = crate::persist::save_unbounded_enabled(&loop_base, false);
        emit_snapshot(&loop_app, false, &empty_status(), total);
    });

    *lock_recover(&state.loop_handle) = Some(loop_handle);

    // If persisting the enabled flag fails, the pool + aggregation task are already running; tear
    // them down before returning so we never leave Unbounded silently running behind a returned
    // error (with a persisted "disabled" state the UI would show).
    if let Err(e) = crate::persist::save_unbounded_enabled(&base, true) {
        drop(lock_recover(&state.handle).take());
        if let Some(loop_handle) = lock_recover(&state.loop_handle).take() {
            loop_handle.abort();
        }
        *lock_recover(&state.latest_status) = None;
        return Err(e);
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn unbounded_stop<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    let base = base_dir(&app)?;
    let state = app.state::<UnboundedState>();

    // Take the sharing handle out and drop it — its `Drop` does a cooperative cancel. Do NOT abort.
    // Recover from a poisoned lock (via `lock_recover`) rather than treating it as "no handle" —
    // otherwise a poison would leave the pool running while stop silently succeeds.
    let handle = lock_recover(&state.handle).take();
    drop(handle);

    // Abort + clear the aggregation loop task (the mpsc receiver ends when the sender is dropped
    // by the supervisor, but abort is deterministic and stops emits immediately).
    if let Some(loop_handle) = lock_recover(&state.loop_handle).take() {
        loop_handle.abort();
    }
    // Aborting the loop can outrun the supervisor's Stopped events, stranding live trace ctx
    // entries; retire them all to keep the SetCtx/RetireCtx pairing contract, with the same
    // grace semantics (the uploader prunes after RETIRE_GRACE, so final log lines stay
    // correlated).
    if let Some(q) = crate::diag_host::span_queue() {
        q.retire_all_ctxs();
    }
    *lock_recover(&state.latest_status) = None;

    // Emit the stopped snapshot BEFORE persisting the flag: the pool is already torn down, so the
    // UI/tray must reflect "off" even if the disk write fails (the error still propagates after).
    // No peers, nobody helping now, but keep the cumulative total.
    let total = crate::persist::load_unbounded_total_helped(&base);
    emit_snapshot(&app, false, &empty_status(), total);
    crate::persist::save_unbounded_enabled(&base, false)?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn unbounded_status<R: Runtime>(
    app: AppHandle<R>,
) -> crate::Result<serde_json::Value> {
    let base = base_dir(&app)?;
    let total = crate::persist::load_unbounded_total_helped(&base);
    let state = app.state::<UnboundedState>();

    // `enabled` reflects whether a pool is actually running (live handle), NOT the persisted flag —
    // otherwise a restart with the persisted flag left `true` (but no pool started, e.g. auto-enable
    // off) would report `enabled: true` with an empty status. Live values only while running (the
    // loop keeps `latest_status` fresh); otherwise nobody helping / no peers.
    let running = lock_recover(&state.handle).is_some();
    let status = if running {
        lock_recover(&state.latest_status)
            .clone()
            .unwrap_or_else(empty_status)
    } else {
        empty_status()
    };

    Ok(serde_json::to_value(snapshot_payload(
        running, &status, total,
    ))?)
}

/// Whether the Unbounded feature is available for this client: the server's `features.unbounded`
/// gate is on AND the resolved config carries the endpoints needed to start sharing. The UI uses
/// this to decide whether to surface the Unbounded tab/row at all. A missing/unreadable config
/// (e.g. before the first fetch) reports `false`.
#[tauri::command]
pub(crate) async fn unbounded_available<R: Runtime>(app: AppHandle<R>) -> crate::Result<bool> {
    Ok(read_unbounded_config(&app)?.is_available())
}

#[tauri::command]
pub(crate) async fn unbounded_get_settings<R: Runtime>(
    app: AppHandle<R>,
) -> crate::Result<serde_json::Value> {
    let base = base_dir(&app)?;
    Ok(serde_json::json!({
        "autoEnable": crate::persist::load_unbounded_auto_enable(&base),
        "hidden": crate::persist::load_unbounded_hidden(&base),
        "welcomeSeen": crate::persist::load_unbounded_welcome_seen(&base),
    }))
}

/// A partial update to the durable Unbounded settings. Only the provided fields are written.
///
/// A single struct arg with `#[serde(rename_all = "camelCase")]` maps the UI's camelCase keys onto
/// the persisted snake_case names explicitly — self-documenting and independent of Tauri's per-param
/// case conversion (the UI invokes with `{ settings: { autoEnable, hidden, welcomeSeen } }`).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct UnboundedSettingsPatch {
    auto_enable: Option<bool>,
    hidden: Option<bool>,
    welcome_seen: Option<bool>,
}

#[tauri::command]
pub(crate) async fn unbounded_set_settings<R: Runtime>(
    app: AppHandle<R>,
    settings: UnboundedSettingsPatch,
) -> crate::Result<()> {
    let base = base_dir(&app)?;
    if let Some(v) = settings.auto_enable {
        crate::persist::save_unbounded_auto_enable(&base, v)?;
    }
    if let Some(v) = settings.hidden {
        crate::persist::save_unbounded_hidden(&base, v)?;
    }
    if let Some(v) = settings.welcome_seen {
        crate::persist::save_unbounded_welcome_seen(&base, v)?;
    }
    Ok(())
}

/// The "nobody helping right now" view, reported whenever no pool is running.
fn empty_status() -> SharingStatus {
    SharingStatus {
        helping_now: 0,
        peers: Vec::new(),
    }
}

/// Lock a std mutex, recovering the guard if a prior holder panicked (poisoned it). The data these
/// mutexes guard is always left in a valid state, so a poison must never silently turn start/stop/
/// status into a no-op — recover and continue. Does not panic (not an `unwrap`/`expect`).
fn lock_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spark_sharing::PeerView;

    fn joined(id: &str) -> SharingDelta {
        SharingDelta::Joined(PeerView {
            session_id: id.into(),
            geo: None,
        })
    }

    #[test]
    fn total_increments_only_on_join() {
        let mut total = 0u64;
        on_delta(&mut total, &joined("a"));
        on_delta(&mut total, &joined("b"));
        on_delta(&mut total, &SharingDelta::Left("a".into()));
        assert_eq!(total, 2);
    }

    #[test]
    fn snapshot_payload_uses_camel_case_contract() {
        let status = SharingStatus {
            helping_now: 1,
            peers: vec![PeerView {
                session_id: "abc".into(),
                geo: Some(spark_sharing::Geo {
                    country_code: "IR".into(),
                    lat: 35.7,
                    lon: 51.4,
                }),
            }],
        };
        let value = serde_json::to_value(snapshot_payload(true, &status, 219)).unwrap();
        assert_eq!(value["enabled"], serde_json::json!(true));
        assert_eq!(value["helpingNow"], serde_json::json!(1));
        assert_eq!(value["totalHelped"], serde_json::json!(219));
        assert_eq!(value["peers"][0]["sessionId"], serde_json::json!("abc"));
        assert_eq!(
            value["peers"][0]["geo"]["countryCode"],
            serde_json::json!("IR")
        );
    }

    #[test]
    fn snapshot_payload_null_geo_when_absent() {
        let status = SharingStatus {
            helping_now: 1,
            peers: vec![PeerView {
                session_id: "abc".into(),
                geo: None,
            }],
        };
        let value = serde_json::to_value(snapshot_payload(true, &status, 0)).unwrap();
        assert!(value["peers"][0]["geo"].is_null());
    }
}
