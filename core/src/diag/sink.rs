//! `DiagSink` (spec §C2/§C2a): the capture/buffering stage of on-device diagnostics.
//!
//! Events enter through a lossy bounded channel (the "ring", logbus-style `try_send`)
//! and are drained by a spawned writer task into two size-capped JSONL files in the
//! sink's directory: `diagnostics.jsonl` (the spool — the upload queue a later task's
//! uploader consumes) and `diag.log` (the unconditional local backup, which never
//! leaves the device on its own). Errors take a synchronous fast-path (§C2a) so a
//! crash immediately after the error still preserves it for next-launch upload.
//!
//! I/O failures on the append paths are logged at `debug!` and swallowed: this code
//! will run beneath the tracing capture layer (a later task), so reporting its own
//! failures at a captured level (error!/warn!/info!) would re-enter the capture
//! pipeline and recurse. That WHY applies to every `tracing::debug!` in this file.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use tokio::sync::{mpsc, oneshot, Notify};

use super::{DiagEvent, DiagLevel};

/// Ring depth — sized for the DEBUG+ capture posture (§C2 wants a rich recent window;
/// logbus's 256 is for a live UI stream).
const RING_DEPTH: usize = 4096;
/// Spool hard cap (§C2: rotate `diagnostics.jsonl` at ~4 MB).
const SPOOL_CAP: u64 = 4 * 1024 * 1024;
/// Backup-log cap (§C2: rotate `diag.log` at ~5 MB).
const LOG_CAP: u64 = 5 * 1024 * 1024;

const SPOOL_NAME: &str = "diagnostics.jsonl";
const LOG_NAME: &str = "diag.log";

/// Writer-task inbox: events to append, or a flush marker. The channel is FIFO, so a
/// [`Msg::Flush`] ack proves everything queued before it has been written.
enum Msg {
    Event(DiagEvent),
    Flush(oneshot::Sender<()>),
}

/// One append-only, size-capped file with single-slot rotation (`<name>` → `<name>.1`).
/// Tracks its running length so appends never `stat`.
struct CappedFile {
    file: File,
    path: PathBuf,
    len: u64,
    cap: u64,
}

impl CappedFile {
    /// Open (append mode — the spool must survive restarts, never truncate-on-open).
    fn open(path: PathBuf, cap: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(CappedFile {
            file,
            path,
            len,
            cap,
        })
    }

    /// Append one JSONL line (newline added here), rotating first if it would pass the cap.
    fn append_line(&mut self, line: &str) {
        let add = line.len() as u64 + 1;
        // `len > 0` guard: a single line larger than the cap is written anyway rather
        // than rotating an empty file forever.
        if self.len > 0 && self.len + add > self.cap {
            self.rotate();
        }
        // One write_all for line+newline so a concurrent crash can't tear between them.
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        match self.file.write_all(buf.as_bytes()) {
            Ok(()) => self.len += add,
            Err(e) => tracing::debug!(err = %e, path = %self.path.display(), "diag: append failed"),
        }
    }

    /// Rename to `<name>.1` (replacing any existing `.1`) and start a fresh file.
    fn rotate(&mut self) {
        let mut rotated = self.path.clone().into_os_string();
        rotated.push(".1");
        if let Err(e) = fs::rename(&self.path, PathBuf::from(rotated)) {
            // Keep appending to the (oversized) current file — better than losing events.
            tracing::debug!(err = %e, path = %self.path.display(), "diag: rotate rename failed");
            return;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(f) => {
                self.file = f;
                self.len = 0;
            }
            // The old handle still points at the rotated inode, so writes keep landing
            // somewhere a tester can hand over.
            Err(e) => {
                tracing::debug!(err = %e, path = %self.path.display(), "diag: rotate reopen failed")
            }
        }
    }

    /// Re-point the handle at `path` after an external rename swapped the inode
    /// (see [`DiagSink::take_spool_batch`]); the old fd would keep appending to the
    /// unlinked file otherwise.
    fn reopen(&mut self) -> std::io::Result<()> {
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.len = self.file.metadata()?.len();
        Ok(())
    }
}

/// Both output files behind one lock: every event goes to both, and `push_error` /
/// the writer task / `take_spool_batch` must not interleave partial appends.
struct Files {
    spool: CappedFile,
    log: CappedFile,
}

impl Files {
    fn append_both(&mut self, line: &str) {
        self.spool.append_line(line);
        self.log.append_line(line);
    }
}

/// A poisoned lock means another thread panicked mid-append; the files are still
/// structurally sound (worst case one torn trailing line), so keep writing.
fn lock_files(files: &Mutex<Files>) -> MutexGuard<'_, Files> {
    files.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The diagnostics sink (§C2): lossy channel ring + spool + backup log + error fast-path.
///
/// Cheap to share (`Arc`); [`push`](DiagSink::push) is non-blocking and safe on hot paths.
/// Dropping the last `Arc` aborts the writer task.
pub struct DiagSink {
    component: &'static str,
    tx: mpsc::Sender<Msg>,
    files: Arc<Mutex<Files>>,
    /// Ring overflows not yet folded into a synthetic `diag.buffer_dropped` event.
    dropped: Arc<AtomicU64>,
    error_notify: Arc<Notify>,
    spool_path: PathBuf,
    spool_tmp: PathBuf,
    writer: tokio::task::JoinHandle<()>,
}

impl DiagSink {
    /// Create a sink writing into `dir` (created if missing) with default caps.
    ///
    /// `component` ("app"/"tunnel") overwrites `ev.component` on every event pushed
    /// through this sink. **Must be called from within a tokio runtime** — it spawns
    /// the writer task that drains the ring.
    pub fn new(dir: &Path, component: &'static str) -> std::io::Result<Arc<DiagSink>> {
        Self::with_caps(dir, component, SPOOL_CAP, LOG_CAP)
    }

    /// [`DiagSink::new`] with explicit rotation caps (bytes) for the spool and backup
    /// log — production uses the defaults; tests shrink them to exercise rotation.
    /// **Must be called from within a tokio runtime** (spawns the writer task).
    pub fn with_caps(
        dir: &Path,
        component: &'static str,
        spool_cap: u64,
        log_cap: u64,
    ) -> std::io::Result<Arc<DiagSink>> {
        fs::create_dir_all(dir)?;
        let spool_path = dir.join(SPOOL_NAME);
        let files = Arc::new(Mutex::new(Files {
            spool: CappedFile::open(spool_path.clone(), spool_cap)?,
            log: CappedFile::open(dir.join(LOG_NAME), log_cap)?,
        }));
        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, rx) = mpsc::channel(RING_DEPTH);
        // The writer holds only the shared pieces (not the Arc<DiagSink>), so dropping
        // the last sink Arc runs Drop (which aborts it) instead of leaking a cycle.
        let writer = tokio::spawn(writer_loop(rx, files.clone(), dropped.clone(), component));
        Ok(Arc::new(DiagSink {
            component,
            tx,
            files,
            dropped,
            error_notify: Arc::new(Notify::new()),
            spool_tmp: dir.join(format!("{SPOOL_NAME}.tmp")),
            spool_path,
            writer,
        }))
    }

    /// Lossy, non-blocking push into the ring (never stalls a hot path). On a full
    /// ring the event is dropped and counted; the writer folds the count into a
    /// synthetic `diag.buffer_dropped` event on its next write.
    pub fn push(&self, mut ev: DiagEvent) {
        ev.component = self.component;
        if self.tx.try_send(Msg::Event(ev)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Error fast-path (§C2a): bypasses the ring and appends synchronously to both
    /// files at call time, so a crash immediately after still preserves the event.
    /// Then signals [`DiagSink::error_notify`] for an expedited upload.
    pub fn push_error(&self, mut ev: DiagEvent) {
        ev.component = self.component;
        let line = ev.to_jsonl();
        lock_files(&self.files).append_both(&line);
        self.error_notify.notify_one();
    }

    /// Ring overflows not yet reported via a synthetic `diag.buffer_dropped` event.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Wait until the writer has processed everything queued before this call
    /// (FIFO channel + acked marker). A no-op if the writer is gone.
    pub async fn flush_writer(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(Msg::Flush(ack_tx)).await.is_ok() {
            // Err here means the writer was aborted mid-flush — nothing left to await.
            let _ = ack_rx.await;
        }
    }

    /// Take whole JSONL lines from the front of the spool, up to `max_bytes` (counting
    /// each line's newline), and rewrite the spool to hold only the remainder
    /// (temp-file + `fs::rename`, atomic-enough for a single-consumer upload queue).
    ///
    /// Returns the taken lines (without newlines). A first line larger than
    /// `max_bytes` yields an empty batch — the caller picks the budget.
    pub fn take_spool_batch(&self, max_bytes: usize) -> std::io::Result<Vec<String>> {
        // Hold the lock across read-rewrite-reopen so the writer/push_error can't
        // append between our snapshot and the rename (their lines would be lost).
        // All-sync I/O, never held across an .await.
        let mut files = lock_files(&self.files);
        let content = fs::read_to_string(&self.spool_path)?;
        let lines: Vec<&str> = content.lines().collect();
        let mut taken = Vec::new();
        let mut budget = 0usize;
        for line in &lines {
            let cost = line.len() + 1;
            if budget + cost > max_bytes {
                break;
            }
            budget += cost;
            taken.push((*line).to_string());
        }
        // Rebuild the remainder from lines (rather than slicing the raw content) so a
        // torn, newline-less final line from a crash is re-terminated on rewrite.
        let mut remainder = String::new();
        for line in &lines[taken.len()..] {
            remainder.push_str(line);
            remainder.push('\n');
        }
        fs::write(&self.spool_tmp, &remainder)?;
        fs::rename(&self.spool_tmp, &self.spool_path)?;
        // The rename swapped the spool's inode out from under the shared handle;
        // re-point it or every later append lands in the unlinked old file.
        files.spool.reopen()?;
        Ok(taken)
    }

    /// Notified once per [`DiagSink::push_error`]; a later task's uploader awaits this
    /// for the §C2a expedited (debounced) flush.
    pub fn error_notify(&self) -> Arc<Notify> {
        self.error_notify.clone()
    }
}

impl Drop for DiagSink {
    fn drop(&mut self) {
        // Dropping `tx` would end the writer's recv loop anyway, but only after it
        // drains the backlog nobody will flush_writer() again — abort() reclaims the
        // task promptly (tests and short-lived processes create many sinks). Aborts
        // land at .await points, so no append is torn mid-write.
        self.writer.abort();
    }
}

/// Drain the ring: append each event to both files, folding any accumulated overflow
/// count into a synthetic `diag.buffer_dropped` event (§C2's "dropped events" signal).
async fn writer_loop(
    mut rx: mpsc::Receiver<Msg>,
    files: Arc<Mutex<Files>>,
    dropped: Arc<AtomicU64>,
    component: &'static str,
) {
    // recv() runs with the files lock released; the lock guards only the synchronous
    // appends below and is never held across an .await.
    while let Some(msg) = rx.recv().await {
        match msg {
            Msg::Event(ev) => {
                let overflowed = dropped.swap(0, Ordering::Relaxed);
                let line = ev.to_jsonl();
                let mut files = lock_files(&files);
                files.append_both(&line);
                if overflowed > 0 {
                    let mut drop_ev =
                        DiagEvent::new(DiagLevel::Warn, component, "diag.buffer_dropped");
                    drop_ev
                        .fields
                        .insert("count".to_string(), overflowed.into());
                    files.append_both(&drop_ev.to_jsonl());
                }
            }
            Msg::Flush(ack) => {
                // FIFO channel ⇒ everything queued before this marker is on disk.
                let _ = ack.send(());
            }
        }
    }
}

/// The process-global sink, so core code can [`emit`] without threading a handle
/// everywhere (same OnceLock pattern as `logbus::LOG_TX`).
static SINK: OnceLock<Arc<DiagSink>> = OnceLock::new();

/// Install the process-global sink (logbus-style). Returns `false` if one was
/// already installed (the first install wins; the new sink is dropped).
pub fn install(sink: Arc<DiagSink>) -> bool {
    SINK.set(sink).is_ok()
}

/// [`DiagSink::push`] on the global sink; a no-op until [`install`] has run, so core
/// code can emit unconditionally (startup, tests, non-diag processes).
pub fn emit(ev: DiagEvent) {
    if let Some(sink) = SINK.get() {
        sink.push(ev);
    }
}

/// [`DiagSink::push_error`] on the global sink; a no-op until [`install`] has run.
pub fn emit_error(ev: DiagEvent) {
    if let Some(sink) = SINK.get() {
        sink.push_error(ev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique per-test scratch dir (pid + call line), cleared before use.
    fn test_dir(line: u32) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spark-diag-sink-{}-{}", std::process::id(), line));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// A test event with a deliberately wrong component: push/push_error must overwrite it.
    fn ev(i: u64) -> DiagEvent {
        let mut ev = DiagEvent::new(DiagLevel::Info, "wrong-component", "test.event");
        ev.fields.insert("i".to_string(), i.into());
        ev
    }

    fn read_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn push_reaches_spool_and_backup_log() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();
        for i in 0..3 {
            sink.push(ev(i));
        }
        sink.flush_writer().await;
        for name in [SPOOL_NAME, LOG_NAME] {
            let lines = read_lines(&dir.join(name));
            assert_eq!(lines.len(), 3, "{name}");
            for line in &lines {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(v["component"], "app", "{name}");
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn push_error_is_synchronous() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();
        let mut e = DiagEvent::new(DiagLevel::Error, "wrong-component", "error.test");
        e.insert_str("message", "boom");
        sink.push_error(e);
        // No flush, no await: the §C2a fast-path must already have hit both files.
        for name in [SPOOL_NAME, LOG_NAME] {
            let lines = read_lines(&dir.join(name));
            assert_eq!(lines.len(), 1, "{name}");
            let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
            assert_eq!(v["kind"], "error.test");
            assert_eq!(v["component"], "app");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ring_overflow_drops_and_counts() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();
        // Deterministic (not just probably-fast-enough): #[tokio::test] runs on the
        // current-thread runtime, where the spawned writer only runs at an .await
        // point — and push() never awaits, so nothing drains while this loop
        // overfills the 4096-deep channel.
        for i in 0..5000 {
            sink.push(ev(i));
        }
        assert!(sink.dropped() > 0, "channel should have overflowed");
        sink.flush_writer().await;
        let dropped_events: Vec<serde_json::Value> = read_lines(&dir.join(SPOOL_NAME))
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|v: &serde_json::Value| v["kind"] == "diag.buffer_dropped")
            .collect();
        assert!(
            !dropped_events.is_empty(),
            "no diag.buffer_dropped in spool"
        );
        assert!(dropped_events[0]["fields"]["count"].as_u64().unwrap() >= 1);
        assert_eq!(dropped_events[0]["level"], "warn");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn backup_log_rotates_at_cap() {
        let dir = test_dir(line!());
        let sink = DiagSink::with_caps(&dir, "app", 1_000_000, 1024).unwrap();
        let mut rotated = false;
        for batch in 0..100u64 {
            for i in 0..10 {
                sink.push(ev(batch * 10 + i));
            }
            sink.flush_writer().await;
            if dir.join("diag.log.1").exists() {
                rotated = true;
                break;
            }
        }
        assert!(rotated, "diag.log.1 never appeared");
        let len = fs::metadata(dir.join(LOG_NAME)).unwrap().len();
        assert!(
            len < 1024 + 200,
            "diag.log past cap + one-line slack: {len}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn take_spool_batch_and_truncate() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();
        for i in 0..10 {
            sink.push(ev(i));
        }
        sink.flush_writer().await;
        let taken = sink.take_spool_batch(usize::MAX).unwrap();
        assert_eq!(taken.len(), 10);
        assert_eq!(fs::read_to_string(dir.join(SPOOL_NAME)).unwrap(), "");

        // These appends also prove the writer's handle survived the take's rename.
        for i in 10..14 {
            sink.push(ev(i));
        }
        sink.flush_writer().await;
        let lines = read_lines(&dir.join(SPOOL_NAME));
        assert_eq!(lines.len(), 4);
        // A budget that fits exactly the first two lines (incl. newlines).
        let two = lines[0].len() + 1 + lines[1].len() + 1;
        let taken = sink.take_spool_batch(two).unwrap();
        assert_eq!(taken.len(), 2);
        assert_eq!(read_lines(&dir.join(SPOOL_NAME)).len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn spool_survives_reopen() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();
        for i in 0..2 {
            sink.push(ev(i));
        }
        sink.flush_writer().await;
        drop(sink); // Drop aborts the writer task
        let sink2 = DiagSink::new(&dir, "app").unwrap();
        let taken = sink2.take_spool_batch(usize::MAX).unwrap();
        assert_eq!(taken.len(), 2, "reopen must append, not truncate");
        let _ = fs::remove_dir_all(&dir);
    }

    // Deliberately no install-then-emit test: SINK is a process-global OnceLock, and
    // installing here would leak a sink into every other test in this process.
    #[test]
    fn global_emit_is_noop_before_install() {
        emit(DiagEvent::new(DiagLevel::Info, "app", "test.noop"));
        emit_error(DiagEvent::new(DiagLevel::Error, "app", "test.noop"));
    }
}
