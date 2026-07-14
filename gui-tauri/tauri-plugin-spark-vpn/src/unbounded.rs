//! Unbounded (volunteer-proxy) control surface for the spark-vpn plugin.
//!
//! Runs the `spark-sharing` peer-proxy pool, folds its per-slot event stream into a live view
//! via [`spark_sharing::Aggregator`], and pushes a `spark://unbounded` snapshot to the UI on every
//! change. Durable settings (enabled / auto-enable / hidden / welcome-seen) and the cumulative
//! `total_helped` counter live in `persist.rs`, keyed off the same platform-provided config dir the
//! rest of the plugin uses.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
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
}

/// Resolve the persistence base dir (the platform-provided app config dir) the same way
/// `platform::control()` does in `lib.rs`, so the unbounded settings land next to the other
/// durable settings files.
fn base_dir<R: Runtime>(app: &AppHandle<R>) -> crate::Result<PathBuf> {
    app.path()
        .app_config_dir()
        .map_err(|e| crate::Error::Platform(format!("no app config dir: {e}")))
}

/// Build the sharing config + signaler for the pool.
///
/// The Lantern config does not yet carry an `unbounded`/sharing block (egress WS URL, Freddie
/// signaling endpoint, STUN URLs); outbounds of type `unbounded` are dropped by the config mapper
/// today. Until Phase 7 wires the real block, this gates `unbounded_start` with a typed error.
fn build_sharing_config<R: Runtime>(
    app: &AppHandle<R>,
) -> crate::Result<(SharingConfig, FreddieSignaler)> {
    // TODO(Task 7.1): read the real unbounded config block (egress URL, Freddie endpoint, STUN
    // URLs, concurrent_sessions, timeouts) from the resolved Lantern config and build the signaler
    // from it. Until then the block is absent, so refuse to start rather than dial a placeholder.
    let _ = app;
    Err(crate::Error::Platform(
        "unbounded config unavailable".into(),
    ))
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
    // Gates cleanly on the missing config block until Phase 7 (returns the typed error today).
    let (cfg, signaler) = build_sharing_config(&app)?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PoolEvent>();
    // `Arc<FreddieSignaler>` coerces to the `Arc<dyn Signaler>` that `start_sharing` expects.
    let handle = start_sharing(cfg, Arc::new(signaler), Some(tx));

    let state = app.state::<UnboundedState>();
    // Store the handle in a tight, non-await scope.
    {
        let mut guard = state.handle.lock().expect("handle lock");
        *guard = Some(handle);
    }

    let loop_app = app.clone();
    let loop_base = base.clone();
    let loop_handle = tauri::async_runtime::spawn(async move {
        let mut agg = Aggregator::new();
        let resolver = GeoResolver::new();
        while let Some(ev) = rx.recv().await {
            if let Some(delta) = agg.apply_with_geo(ev, &resolver).await {
                let mut total = crate::persist::load_unbounded_total_helped(&loop_base);
                on_delta(&mut total, &delta);
                if matches!(delta, SharingDelta::Joined(_)) {
                    if let Err(e) = crate::persist::save_unbounded_total_helped(&loop_base, total) {
                        eprintln!("[spark-unbounded] failed to persist total_helped: {e}");
                    }
                }
                let status = agg.status();
                *loop_app
                    .state::<UnboundedState>()
                    .latest_status
                    .lock()
                    .expect("status lock") = Some(status.clone());
                emit_snapshot(&loop_app, true, &status, total);
            }
        }
    });

    {
        let mut guard = state.loop_handle.lock().expect("loop lock");
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
    let handle = state.handle.lock().expect("handle lock").take();
    drop(handle);

    // Abort + clear the aggregation loop task (the mpsc receiver ends when the sender is dropped
    // by the supervisor, but abort is deterministic and stops emits immediately).
    if let Some(loop_handle) = state.loop_handle.lock().expect("loop lock").take() {
        loop_handle.abort();
    }
    *state.latest_status.lock().expect("status lock") = None;

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
    let status = if state.handle.lock().expect("handle lock").is_some() {
        state
            .latest_status
            .lock()
            .expect("status lock")
            .clone()
            .unwrap_or_else(empty_status)
    } else {
        empty_status()
    };

    Ok(serde_json::to_value(snapshot_payload(
        enabled, &status, total,
    ))?)
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

#[tauri::command]
pub(crate) async fn unbounded_set_settings<R: Runtime>(
    app: AppHandle<R>,
    auto_enable: Option<bool>,
    hidden: Option<bool>,
    welcome_seen: Option<bool>,
) -> crate::Result<()> {
    let base = base_dir(&app)?;
    if let Some(v) = auto_enable {
        crate::persist::save_unbounded_auto_enable(&base, v)?;
    }
    if let Some(v) = hidden {
        crate::persist::save_unbounded_hidden(&base, v)?;
    }
    if let Some(v) = welcome_seen {
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
