//! Process-wide panic hook (spec §C2a): a panic's `message` + `location` must reach the
//! diagnostics spool *before the process dies*, so it uploads on next launch.

use std::sync::atomic::{AtomicBool, Ordering};

use super::{emit_error, events};

/// One-shot guard: hook installed at most once per process. Without it a second
/// `install()` would chain the hook to itself and every panic would spool twice.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the diagnostics panic hook (idempotent — the second call is a no-op).
/// Chains to the previously-installed hook so default stderr reporting survives.
/// The hook writes `error.panic {message, location}` through `diag::emit_error`
/// (synchronous spool write, §C2a) BEFORE the process dies — uploaded next launch.
pub fn install() {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    // take_hook + chaining (§C2a): we replace the process hook but keep the previous one
    // (usually the default stderr reporter) and call it after spooling, so panic output
    // still reaches stderr/logs. Constraint: this closure must NEVER itself panic — a
    // panicking panic hook aborts the process before the chained hook runs. Hence plain
    // string ops only, no unwrap, and no tracing (the process is dying; emit_error's
    // synchronous file append is the only side effect we need).
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message: &str = if let Some(s) = payload.downcast_ref::<&str>() {
            s
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s
        } else {
            "panic (non-string payload)"
        };
        let location = match info.location() {
            Some(loc) => format!("{}:{}", loc.file(), loc.line()),
            None => "unknown".to_string(),
        };
        emit_error(events::error_panic(message, &location));
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Child half of `panic_hook_writes_error_to_spool`: only runs when re-invoked as a
    /// subprocess with `SPARK_DIAG_PANIC_DIR` set (a no-op in a normal suite run). It
    /// installs a real sink + the hook and panics for real — the only way to observe the
    /// hook firing on an actual panic.
    #[test]
    fn panic_child() {
        let Ok(dir) = std::env::var("SPARK_DIAG_PANIC_DIR") else {
            return;
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let sink = crate::diag::sink::DiagSink::new(std::path::Path::new(&dir), "app").unwrap();
        crate::diag::install(sink);
        // Twice: the second must be a no-op, or the hook would chain to itself and the
        // parent would see two error.panic lines.
        install();
        install();
        panic!("boom at 1.2.3.4");
    }

    #[test]
    fn panic_hook_writes_error_to_spool() {
        let dir = std::env::temp_dir().join(format!("spark-diag-panic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = std::env::current_exe().unwrap();
        // Re-run this same test binary filtered to the child test. libtest catches the
        // child's panic and reports a failed test (non-zero exit) — but the hook fires
        // before libtest's catch_unwind, so the spool line must exist either way.
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "diag::panic_hook::tests::panic_child",
                "--nocapture",
                // Explicit single-thread: one --exact test implies it today, but the
                // child calls the process-global diag::install and must stay isolated
                // if libtest defaults ever change.
                "--test-threads=1",
            ])
            .env("SPARK_DIAG_PANIC_DIR", &dir)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "child must die from the panic: {out:?}"
        );
        let spool = std::fs::read_to_string(dir.join("diagnostics.jsonl")).unwrap();
        assert_eq!(
            spool.matches("error.panic").count(),
            1,
            "exactly one error.panic (double install must not double-fire): {spool}"
        );
        assert!(
            spool.contains("[redacted-ip]"),
            "panic message must be redacted: {spool}"
        );
        assert!(
            spool.contains("panic_hook.rs"),
            "location captured: {spool}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
