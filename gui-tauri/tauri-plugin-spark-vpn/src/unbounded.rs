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
/// location list reads). Returns the default (disabled) config when the cache is absent/unreadable or
/// carries no `unbounded`/`features.unbounded` section — so a first-launch client with no config yet
/// simply reports the feature as unavailable rather than erroring.
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
    if state.handle.lock().is_ok_and(|g| g.is_some()) {
        return Ok(());
    }

    // Refuses with a typed "unbounded not available" error when the feature is gated off or the
    // resolved config lacks the endpoints to dial (see build_sharing_config).
    let (cfg, signaler) = build_sharing_config(&app)?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PoolEvent>();
    // `Arc<FreddieSignaler>` coerces to the `Arc<dyn Signaler>` that `start_sharing` expects.
    let handle = start_sharing(cfg, Arc::new(signaler), Some(tx));

    // Store the handle in a tight, non-await scope.
    if let Ok(mut guard) = state.handle.lock() {
        *guard = Some(handle);
    }

    let loop_app = app.clone();
    let loop_base = base.clone();
    let loop_handle = tauri::async_runtime::spawn(async move {
        let mut agg = Aggregator::new();
        let resolver = GeoResolver::new();
        // Seed the cumulative counter once from disk, then keep it in memory — persisting only on a
        // join. Avoids a disk read on every delta, and a poisoned lock can no longer panic the loop
        // (which would leave the pool running but the UI/tray frozen).
        let mut total = crate::persist::load_unbounded_total_helped(&loop_base);
        while let Some(ev) = rx.recv().await {
            if let Some(delta) = agg.apply_with_geo(ev, &resolver).await {
                let joined = matches!(delta, SharingDelta::Joined(_));
                on_delta(&mut total, &delta);
                if joined {
                    if let Err(e) = crate::persist::save_unbounded_total_helped(&loop_base, total) {
                        eprintln!("[spark-unbounded] failed to persist total_helped: {e}");
                    }
                }
                let status = agg.status();
                if let Ok(mut latest) = loop_app.state::<UnboundedState>().latest_status.lock() {
                    *latest = Some(status.clone());
                }
                emit_snapshot(&loop_app, true, &status, total);
            }
        }
    });

    if let Ok(mut guard) = state.loop_handle.lock() {
        *guard = Some(loop_handle);
    }

    crate::persist::save_unbounded_enabled(&base, true)?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn unbounded_stop<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    let base = base_dir(&app)?;
    let state = app.state::<UnboundedState>();

    // Take the sharing handle out and drop it — its `Drop` does a cooperative cancel. Do NOT abort.
    let handle = state.handle.lock().ok().and_then(|mut g| g.take());
    drop(handle);

    // Abort + clear the aggregation loop task (the mpsc receiver ends when the sender is dropped
    // by the supervisor, but abort is deterministic and stops emits immediately).
    if let Some(loop_handle) = state.loop_handle.lock().ok().and_then(|mut g| g.take()) {
        loop_handle.abort();
    }
    if let Ok(mut latest) = state.latest_status.lock() {
        *latest = None;
    }

    crate::persist::save_unbounded_enabled(&base, false)?;

    // Emit a stopped snapshot: no peers, nobody helped right now, but keep the cumulative total.
    let total = crate::persist::load_unbounded_total_helped(&base);
    emit_snapshot(&app, false, &empty_status(), total);
    Ok(())
}

#[tauri::command]
pub(crate) async fn unbounded_status<R: Runtime>(
    app: AppHandle<R>,
) -> crate::Result<serde_json::Value> {
    let base = base_dir(&app)?;
    let enabled = crate::persist::load_unbounded_enabled(&base);
    let total = crate::persist::load_unbounded_total_helped(&base);
    let state = app.state::<UnboundedState>();

    // Live values only while a pool is running (its loop keeps `latest_status` fresh); otherwise
    // report nobody helping / no peers.
    let running = state.handle.lock().is_ok_and(|g| g.is_some());
    let status = if running {
        state
            .latest_status
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(empty_status)
    } else {
        empty_status()
    };

    Ok(serde_json::to_value(snapshot_payload(
        enabled, &status, total,
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
