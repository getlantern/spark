//! `spark-service` — the privileged tunnel daemon.
//!
//! Owns the TUN device + the core, and serves an unprivileged client over a control channel
//! authenticated at the OS boundary: a unix-domain socket with peer-credential auth on unix, a
//! named pipe with an admin-only DACL on Windows. Run it privileged (the device + routes need
//! it); the client is `spark` in client mode.
//!
//! All the logic lives in [`spark_service::daemon`] so it's shared between the foreground entry
//! and the Windows service entry; this binary is a thin shim. On Windows, `daemon::run` runs as
//! a Service Control Manager service when launched by it, and in the foreground otherwise.

fn main() -> anyhow::Result<()> {
    spark_service::daemon::run()
}
