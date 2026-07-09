//! Windows Service Control Manager (SCM) integration.
//!
//! Lets `spark-service` run as a proper Windows service: it reports RUNNING to the SCM, responds
//! to STOP/SHUTDOWN by signalling the daemon to shut down cleanly, and reports STOPPED. The
//! binary is dual-mode — [`run_as_service_if_launched_by_scm`] attaches to the SCM; if the
//! process was NOT launched by the SCM (e.g. run from a console for dev), it returns `Ok(false)`
//! so the caller falls back to running the daemon in the foreground.
//!
//! The service control handler can't reach the daemon's async tasks directly, so STOP fires a
//! oneshot that [`crate::daemon::serve_daemon`] selects on; ending its `listen` future drops the
//! command sender, which winds the event loop and the tunnel down. Reporting STOPPED only after
//! `block_on` returns keeps the SCM's view consistent with the actual teardown.
//!
//! NB: built and type-checked against the Windows target; not yet exercised under a real SCM.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::sync::oneshot;
use tracing::{error, info};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::daemon::{self, Args};

/// The service name registered with the SCM (matches the MSI / `sc create` name).
const SERVICE_NAME: &str = "spark";

/// Win32 error the dispatcher returns when the process was NOT started by the SCM
/// (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`) — our signal to fall back to foreground mode.
const NOT_LAUNCHED_BY_SCM: i32 = 1063;

/// Attach to the SCM. Returns `Ok(true)` if the process was launched by the SCM — in which case
/// this blocks until the service stops — or `Ok(false)` if it wasn't (run the daemon in the
/// foreground instead).
pub fn run_as_service_if_launched_by_scm() -> anyhow::Result<bool> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NOT_LAUNCHED_BY_SCM) => {
            Ok(false)
        }
        Err(e) => Err(anyhow::Error::new(e).context("attaching to the service control manager")),
    }
}

define_windows_service!(ffi_service_main, service_main);

/// The SCM entry point (runs on a background thread the dispatcher spawns). There's no caller to
/// return errors to, so failures are logged.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!(error = %e, "spark-service (service mode) exited with an error");
    }
}

fn run_service() -> anyhow::Result<()> {
    // SCM stop/shutdown fires this oneshot; the daemon selects on the receiver. `Option` so the
    // `FnMut` handler can `take` it (a oneshot sender fires at most once).
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut shutdown_tx = Some(shutdown_tx);

    let event_handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = shutdown_tx.take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        // Interrogate must be acknowledged; everything else we don't handle.
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("registering the service control handler")?;

    // Report START_PENDING first (the SCM contract): it opens a window to do fallible init before
    // we claim RUNNING, and the wait-hint keeps the SCM's start timeout from firing meanwhile.
    status_handle
        .set_service_status(pending(ServiceState::StartPending))
        .context("reporting START_PENDING to the SCM")?;

    // Do all fallible init BEFORE reporting RUNNING, and turn any failure into a clean
    // STOPPED-with-error. Otherwise a failure here (bad binPath args, runtime build) would leave
    // the SCM believing we're RUNNING when the process exits — it flags the service failed and can
    // trigger a restart storm. `try_parse` (not `parse`) so a bad binPath returns an error instead
    // of `process::exit`-ing, which would skip the STOPPED report entirely.
    let init = (|| -> anyhow::Result<(Args, tokio::runtime::Runtime)> {
        // The binPath arguments arrive as this process's argv, so the same `Args` parse works here.
        let args = Args::try_parse().context("parsing service arguments")?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("building the tokio runtime")?;
        Ok((args, runtime))
    })();
    let (args, runtime) = match init {
        Ok(v) => v,
        Err(e) => {
            report_stopped(&status_handle, 1);
            return Err(e);
        }
    };

    // Init succeeded → RUNNING (accepting Stop/Shutdown). The GUI client retries pipe-open for ~3s
    // (ERROR_FILE_NOT_FOUND), covering the brief gap until `serve_daemon` binds the pipe.
    status_handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ))
        .context("reporting RUNNING to the SCM")?;
    info!("spark-service running as a Windows service");

    // Isolate a panic in the daemon so we still report STOPPED (else the SCM sees the process
    // vanish while RUNNING → "service terminated unexpectedly" + recovery). No-op under
    // `panic = "abort"`; a strict improvement under unwind.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(daemon::serve_daemon(args, async move {
            let _ = shutdown_rx.await;
        }))
    }));

    // Report STOPPED regardless of how the daemon exited (clean, error, or panic), with a non-zero
    // exit code on failure so the SCM records an error rather than a normal stop.
    match result {
        Ok(inner) => {
            report_stopped(&status_handle, if inner.is_err() { 1 } else { 0 });
            inner
        }
        Err(_panic) => {
            report_stopped(&status_handle, 1);
            Err(anyhow::anyhow!("spark-service panicked"))
        }
    }
}

/// Report STOPPED with an exit code (`0` = clean, non-zero = error → the SCM records a failure).
/// Best-effort: if the SCM call itself fails there's nothing left to do but log it.
fn report_stopped(handle: &service_control_handler::ServiceStatusHandle, code: u32) {
    let exit_code = if code == 0 {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(code)
    };
    let stopped = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    if let Err(e) = handle.set_service_status(stopped) {
        error!(error = %e, "reporting STOPPED to the SCM failed");
    }
}

/// Build a `ServiceStatus` for a steady `state` accepting `controls` (RUNNING/STOPPED — no
/// pending-operation hints).
fn status(state: ServiceState, controls: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

/// Build a transient `*_PENDING` status with a checkpoint + wait-hint so the SCM waits for the
/// transition instead of timing it out. No controls are accepted while it's in flight.
fn pending(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}
