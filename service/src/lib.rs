//! `spark-service` — the privileged tunnel process that owns the TUN/WinTun + routes
//! and runs the core in-process, serving the unprivileged client over `spark-ipc`.
//!
//! Empty at M0 by design. The service target, per-platform IPC transport + authz,
//! supervision, and fail-open route-restore are built at M7 (see `docs/PLAN.md` and
//! `docs/process-architecture-and-ipc.md`).
