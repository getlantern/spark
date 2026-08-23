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
    SharingDelta, SharingHandle, SharingStatus, STUN_BATCH_SIZE,
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
    /// Where WE are — the far end of every arc on the globe.
    ///
    /// Resolved once per sharing session, and ONLY while sharing: asking the geo service where we
    /// are is an outbound request that reveals our address to it, so it happens because the user
    /// turned the feature on, never merely because they opened the tab.
    origin: Mutex<Option<spark_sharing::Geo>>,
    /// Serializes `unbounded_start` AND `unbounded_stop`: held (async-safe) across each so two
    /// concurrent callers can't interleave. A `tokio` mutex (not `std`) because it is intentionally
    /// held across `.await` points. Stop must take it too: it mutates the same handles and the same
    /// durable flag, so a stop overlapping a start could otherwise cancel nothing (taking the handle
    /// before start stored it) and leave the pool relaying while disk, UI and tray all read "off".
    start_gate: tokio::sync::Mutex<()>,
    /// Incremented on every start. The aggregation loop captures its value and performs its
    /// end-of-stream teardown only while still current, so a loop belonging to a previous generation
    /// can never clear the handle or state of the pool that replaced it.
    generation: std::sync::atomic::AtomicU64,
    /// Incremented by every `unbounded_stop`, under `start_gate`.
    ///
    /// `unbounded_start` awaits the network (the STUN fetch) *before* taking the gate, because holding
    /// it across that await would make a stop wait out the fetch timeout. That opens a window: a stop
    /// can run to completion while a start is still fetching, and the start would then take the gate,
    /// see no handle, and spin up a pool the user had just cancelled — sharing on after pressing stop,
    /// which for a consent-gated feature is the worst direction to fail in.
    ///
    /// So start snapshots this before the fetch and re-reads it under the gate: a change means a stop
    /// intervened, and the start abandons instead of spawning. Separate from `generation` rather than
    /// reusing it, because that one's meaning ("which pool a loop belongs to") is load-bearing for the
    /// aggregation loop's teardown and should not also encode "a stop happened".
    stop_epoch: std::sync::atomic::AtomicU64,
    /// Cached `features.unbounded` availability, refreshed whenever the config is actually read.
    ///
    /// The tray polls ~0.7 Hz and repaints on every peer event; resolving availability from disk each
    /// time meant a `config_raw.json` read plus a full deserialize of the ENTIRE config (all
    /// outbounds, rule sets, …) at that rate for the whole app lifetime — on every desktop install,
    /// including users who never enable Unbounded and clients where the server gate is off.
    available: std::sync::atomic::AtomicBool,
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
        // Filled in by the caller — it needs an `.await` and this fn is sync. An empty list here is
        // NOT benign: without STUN, ICE gathers host candidates only and cannot traverse most NATs,
        // so the donor advertises, a censored client answers, and the DataChannel never opens. That
        // is exactly why sharing carried no traffic while Lantern's donor carried it quickly.
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
    /// Our own location, once resolved. `None` until then — the globe simply omits us.
    origin: Option<GeoPayload>,
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
fn snapshot_payload(
    enabled: bool,
    status: &SharingStatus,
    total: u64,
    origin: Option<&spark_sharing::Geo>,
) -> UnboundedSnapshot {
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
        origin: origin.map(|g| GeoPayload {
            country_code: g.country_code.clone(),
            lat: g.lat,
            lon: g.lon,
        }),
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
    let origin = app
        .try_state::<UnboundedState>()
        .and_then(|s| lock_recover(&s.origin).clone());
    let _ = app.emit(
        "spark://unbounded",
        snapshot_payload(enabled, status, total, origin.as_ref()),
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
    // Hold the start gate across the whole start (build + spawn + store). A second concurrent caller
    // WAITS on the gate (`lock().await`, not `try_lock`) and then falls through to the `handle`
    // check below, which sees the pool the winner stored and returns Ok — same idempotency, but the
    // return value is honest: `Ok` always means "a pool is running", never "someone else might be
    // starting one". Because the gate serializes start and stop, that check is race-free.
    // Cheap, NON-authoritative early-out. Its only job is to avoid a pointless STUN fetch on a
    // double-click; the authoritative check is the gated one below, and only that one is race-free.
    if lock_recover(&state.handle).is_some() {
        return Ok(());
    }

    // Consent gate, enforced here rather than only in the window UI: the volunteer's connection must
    // never carry other people's traffic before they have been shown the disclosure. Checking it in
    // the command covers EVERY entry point — including the tray toggle and the startup resume, which
    // have no dialog of their own. Ahead of the STUN fetch below, so no network request is made on an
    // unconsented volunteer's behalf either.
    if !crate::persist::load_unbounded_welcome_seen(&base) {
        return Err(crate::Error::Platform(
            "unbounded consent not given (disclosure not yet acknowledged)".into(),
        ));
    }

    // Refuses with a typed "unbounded not available" error when the feature is gated off or the
    // resolved config lacks the endpoints to dial (see build_sharing_config).
    let (mut cfg, signaler) = build_sharing_config(&app)?;

    // Snapshot BEFORE the ungated network await below, and re-checked under the gate. See
    // `UnboundedState::stop_epoch`: without this, a stop that completes while we are fetching would
    // be undone by this start.
    let stop_epoch_before = state.stop_epoch.load(std::sync::atomic::Ordering::Acquire);

    // ICE STUN servers. Mirrors Lantern's donor, which takes broflake's `DefaultSTUNBatchFunc`
    // (`clientcore.NewDefaultWebRTCOptions()`, never overridden in radiance): fetch a public list and
    // pick 5 at random. Spark adds an embedded fallback broflake has no equivalent of, because the
    // remote list lives on `raw.githubusercontent.com` — a plausible casualty of the same blocking
    // this tool exists to route around, and a third-party repo besides.
    //
    // **Deliberately before `start_gate` is taken.** This awaits the network for up to the fetch
    // timeout, and holding the gate across it would make `unbounded_stop` wait out that timeout
    // before it could even begin stopping — the gate serializes start and stop. The cost is a
    // redundant fetch if two callers race past the early-out above; the loser then finds the pool
    // already running under the gate and returns Ok, so the waste is bounded and harmless.
    let (stun_urls, from_remote, why) =
        spark_sharing::stun_batch_or_embedded(STUN_BATCH_SIZE).await;
    if let Some(why) = why {
        tracing::info!(
            error = %why,
            count = stun_urls.len(),
            "unbounded: STUN list unavailable; using the embedded fallback"
        );
    } else {
        tracing::debug!(
            count = stun_urls.len(),
            from_remote,
            "unbounded: STUN servers selected"
        );
    }
    cfg.stun_urls = stun_urls;

    // NOW take the gate, for the authoritative idempotency check plus spawn + store. A second
    // concurrent caller WAITS here (`lock().await`, not `try_lock`) and then sees the pool the winner
    // stored, returning Ok — so `Ok` always means "a pool is running", never "someone else might be
    // starting one". Nothing below awaits the network, so the gate is held only over local work.
    let _gate = state.start_gate.lock().await;
    if lock_recover(&state.handle).is_some() {
        return Ok(());
    }
    // A stop landed while we were fetching, so the user's latest intent is "off". Abandon rather than
    // spawn — and report it, because returning `Ok` here would claim a pool is running when the whole
    // point is that we declined to start one.
    if state.stop_epoch.load(std::sync::atomic::Ordering::Acquire) != stop_epoch_before {
        return Err(crate::Error::Platform(
            "unbounded start superseded by a stop while preparing".into(),
        ));
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PoolEvent>();
    // `Arc<FreddieSignaler>` coerces to the `Arc<dyn Signaler>` that `start_sharing` expects.
    let handle = start_sharing(cfg, Arc::new(signaler), Some(tx));

    // Store the handle in a tight, non-await scope.
    *lock_recover(&state.handle) = Some(handle);

    // This start's generation; the loop below only tears down state while it is still current.
    let generation = state
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        + 1;

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
        // Place ourselves on the map. In its OWN task, because this is a network round trip and the
        // loop below is what keeps peer accounting, the tray label and the UI moving — a slow or dead
        // geo host must not delay the first peer join by its timeout. Nothing re-emits when it lands:
        // the Unbounded screen polls `unbounded_status` every 2s, so the globe picks it up there,
        // which costs less than duplicating the persisted-total bookkeeping out here.
        {
            let origin_app = loop_app.clone();
            // Scoped to THIS session by `stop_epoch`, the same signal `unbounded_start` uses across
            // its own pre-gate fetch. Without it a lookup still in flight when the user presses stop
            // writes the origin back AFTER stop cleared it, and `unbounded_status` then reports where
            // we are while sharing is off — contradicting the one property this lookup's placement is
            // supposed to guarantee. Re-read after every await, not just once, because there are
            // several.
            let epoch_at_start = origin_app
                .try_state::<UnboundedState>()
                .map(|st| st.stop_epoch.load(std::sync::atomic::Ordering::Acquire));
            tauri::async_runtime::spawn(async move {
                let still_this_session =
                    || match (epoch_at_start, origin_app.try_state::<UnboundedState>()) {
                        (Some(before), Some(st)) => {
                            st.stop_epoch.load(std::sync::atomic::Ordering::Acquire) == before
                        }
                        _ => false,
                    };
                let resolver = GeoResolver::new();
                // RETRY, because `resolve_own` deliberately does not cache failures — one attempt
                // would waste that and leave the volunteer off their own map for the whole session
                // after a single blip. Backed off and bounded: this is decoration, and a geo host
                // that is down should cost a handful of attempts, not a standing timer.
                for delay_secs in [0_u64, 5, 20, 60, 180] {
                    if delay_secs > 0 {
                        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                    }
                    if !still_this_session() {
                        return;
                    }
                    if let Some(geo) = resolver.resolve_own().await {
                        if !still_this_session() {
                            return;
                        }
                        if let Some(st) = origin_app.try_state::<UnboundedState>() {
                            *lock_recover(&st.origin) = Some(geo);
                        }
                        return;
                    }
                }
            });
        }
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
        //
        // Only if this loop is still the current generation: `abort()` takes effect at an await
        // point, so a stop→start can begin a new pool while this tail is mid-flight, and an
        // unguarded tail would then drop the NEW handle and contradict the start that just
        // succeeded.
        let ustate = loop_app.state::<UnboundedState>();
        if ustate.generation.load(std::sync::atomic::Ordering::SeqCst) != generation {
            return;
        }
        *lock_recover(&ustate.handle) = None;
        *lock_recover(&ustate.latest_status) = None;
        // Dropped with the session: a later start re-resolves, so moving networks between sessions
        // cannot leave us pinned where we used to be.
        *lock_recover(&ustate.origin) = None;
        // Deliberately do NOT clear the persisted `unbounded_enabled` here. That flag carries the
        // user's opt-in, so writing `false` on a pool crash silently un-enrolled a volunteer for
        // good — one transient supervisor panic and the only way back was re-toggling. Reporting
        // "off" to the UI is honest (nothing is relaying); the durable choice survives, and the
        // startup resume re-checks it (together with auto-enable + availability) next launch.
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
        *lock_recover(&state.origin) = None;
        return Err(e);
    }

    // Publish the running state immediately. Without this, nothing reported "enabled" until the first
    // peer joined — so the tray status line sat at "Unbounded: off" directly above "Disable
    // Unbounded", potentially for hours on a volunteer nobody has connected to yet.
    emit_snapshot(&app, true, &empty_status(), total_helped(&base));
    Ok(())
}

/// The persisted cumulative "people helped" counter.
fn total_helped(base: &std::path::Path) -> u64 {
    crate::persist::load_unbounded_total_helped(base)
}

#[tauri::command]
pub(crate) async fn unbounded_stop<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    let base = base_dir(&app)?;
    let state = app.state::<UnboundedState>();

    // Serialize against `unbounded_start` (see `start_gate`): the three entry points — window UI,
    // tray toggle, startup resume — share no other guard, and a stop that interleaved with a start
    // could take the handle before the start stored it, cancelling nothing and leaving the pool
    // relaying while every observable said "off".
    let _gate = state.start_gate.lock().await;

    // Announce the stop to any start currently between its snapshot and the gate (see `stop_epoch`).
    // Under the gate, so a start either reads the old value and then observes this change when it
    // acquires the gate, or reads the new one — never misses it.
    state
        .stop_epoch
        .fetch_add(1, std::sync::atomic::Ordering::Release);

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
    *lock_recover(&state.origin) = None;

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

    let origin = lock_recover(&state.origin).clone();
    Ok(serde_json::to_value(snapshot_payload(
        running,
        &status,
        total,
        origin.as_ref(),
    ))?)
}

/// Whether the Unbounded feature is available for this client: the server's `features.unbounded`
/// gate is on AND the resolved config carries the endpoints needed to start sharing. The UI uses
/// this to decide whether to surface the Unbounded tab/row at all. A missing/unreadable config
/// (e.g. before the first fetch) reports `false`.
#[tauri::command]
pub(crate) async fn unbounded_available<R: Runtime>(app: AppHandle<R>) -> crate::Result<bool> {
    let available = read_unbounded_config(&app)?.is_available();
    store_availability(&app, available);
    Ok(available)
}

/// Re-read the config and update the cached availability flag. Call this wherever the config is
/// known to have changed (startup fetch) — everything else reads the cache.
pub(crate) fn refresh_availability<R: Runtime>(app: &AppHandle<R>) -> bool {
    let available = read_unbounded_config(app)
        .map(|c| c.is_available())
        .unwrap_or(false);
    store_availability(app, available);
    available
}

fn store_availability<R: Runtime>(app: &AppHandle<R>, available: bool) {
    if let Some(state) = app.try_state::<UnboundedState>() {
        state
            .available
            .store(available, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Cached availability, for the tray (which repaints on the main thread and can't await) and any
/// other hot path. Reports `false` until the first config read — the correct pre-first-fetch answer.
pub(crate) fn unbounded_available_sync<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.try_state::<UnboundedState>()
        .map(|s| s.available.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(false)
}

/// `(pool running, peers currently helped)` from live state — lets the tray render the real status
/// line without re-deriving it from persisted flags or waiting for the next peer delta.
pub(crate) fn live_view<R: Runtime>(app: &AppHandle<R>) -> (bool, usize) {
    match app.try_state::<UnboundedState>() {
        Some(state) => {
            let running = lock_recover(&state.handle).is_some();
            let helping = lock_recover(&state.latest_status)
                .as_ref()
                .map(|s| s.helping_now)
                .unwrap_or(0);
            (running, helping)
        }
        None => (false, 0),
    }
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
        let origin = spark_sharing::Geo {
            country_code: "US".into(),
            lat: 39.74,
            lon: -104.98,
        };
        let value =
            serde_json::to_value(snapshot_payload(true, &status, 219, Some(&origin))).unwrap();
        assert_eq!(value["enabled"], serde_json::json!(true));
        assert_eq!(value["helpingNow"], serde_json::json!(1));
        assert_eq!(value["totalHelped"], serde_json::json!(219));
        assert_eq!(value["peers"][0]["sessionId"], serde_json::json!("abc"));
        assert_eq!(
            value["peers"][0]["geo"]["countryCode"],
            serde_json::json!("IR")
        );
        // The volunteer's own position, which is the far end of every arc on the globe.
        assert_eq!(value["origin"]["countryCode"], serde_json::json!("US"));
        assert_eq!(value["origin"]["lat"], serde_json::json!(39.74));
        assert_eq!(value["origin"]["lon"], serde_json::json!(-104.98));
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
        let value = serde_json::to_value(snapshot_payload(true, &status, 0, None)).unwrap();
        assert!(value["peers"][0]["geo"].is_null());
        // Null until the self lookup lands, which the globe reads as "do not draw us yet" rather
        // than pinning the volunteer at (0, 0) in the Gulf of Guinea.
        assert!(value["origin"].is_null());
    }
}
