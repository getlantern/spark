use std::path::PathBuf;

use crate::control::TunnelControl;
use crate::models::{ServerInfo, Status};

// ── macOS NE control (relocated verbatim from gui-tauri/src-tauri/src/lib.rs) ─

#[cfg(target_os = "macos")]
mod ne_spike {
    use objc2_network_extension::NETunnelProviderManager;

    /// Raw NEVPNStatus of a fresh manager's connection (Invalid=0, Disconnected=1,
    /// Connecting=2, Connected=3, Reasserting=4, Disconnecting=5).
    #[allow(dead_code)]
    pub fn probe_status_raw() -> isize {
        // SAFETY: NETunnelProviderManager/NEVPNConnection are plain ObjC objects;
        // `new` + the `connection`/`status` getters are side-effect-free reads.
        unsafe {
            let manager = NETunnelProviderManager::new();
            let connection = manager.connection();
            connection.status().0
        }
    }

    /// Human-readable status name for the spike's report.
    #[allow(dead_code)]
    pub fn status_name(raw: isize) -> &'static str {
        match raw {
            0 => "invalid",
            1 => "disconnected",
            2 => "connecting",
            3 => "connected",
            4 => "reasserting",
            5 => "disconnecting",
            _ => "unknown",
        }
    }

    /// U1b machinery proof: enumerate the app's saved tunnel managers via the
    /// async `loadAllFromPreferences` completion handler — the real status source
    /// (U1a's synchronous `new()` was only a bridge probe). The completion fires on
    /// the main queue, so the caller must service the main run loop; this drives it
    /// in 0.1s slices for up to ~3s. Returns (manager_count, first_status_raw);
    /// first_status_raw is -1 when there are no managers. The same completion-block
    /// pattern carries connect/disconnect (saveToPreferences/startVPNTunnel) in U1c.
    ///
    /// MUST be called on the main thread (the example's `ne_probe` does, driving the
    /// run loop itself). The Tauri app instead uses `load_first_status` from an
    /// off-main `#[tauri::command(async)]`, so its own run loop services the main-queue
    /// completion. Needs no NE entitlement — read-only.
    #[allow(dead_code)]
    pub fn load_first_status_blocking() -> (usize, isize) {
        use std::sync::mpsc::channel;

        use block2::RcBlock;
        use objc2_foundation::{NSArray, NSDate, NSDefaultRunLoopMode, NSError, NSRunLoop};

        let (tx, rx) = channel::<(usize, isize)>();
        let handler = RcBlock::new(
            move |arr: *mut NSArray<NETunnelProviderManager>, err: *mut NSError| {
                let result = if !err.is_null() {
                    // loadAll failed (entitlement/profile) — distinct sentinel so the UI
                    // surfaces "failed" instead of a silent "disconnected".
                    (0usize, -3isize)
                } else {
                    // SAFETY: `arr` is the framework-owned managers array (or null).
                    unsafe {
                        if arr.is_null() {
                            (0usize, -1isize)
                        } else {
                            let arr = &*arr;
                            let count = arr.count();
                            let status = if count > 0 {
                                arr.objectAtIndex(0).connection().status().0
                            } else {
                                -1
                            };
                            (count, status)
                        }
                    }
                };
                let _ = tx.send(result);
            },
        );

        // SAFETY: standard NE async-read API; the handler outlives the call via RcBlock.
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&handler) };

        // Drive the main run loop until the main-queue completion fires (~3s cap).
        let run_loop = NSRunLoop::currentRunLoop();
        for _ in 0..30 {
            if let Ok(v) = rx.try_recv() {
                return v;
            }
            let until = NSDate::dateWithTimeIntervalSinceNow(0.1);
            unsafe { run_loop.runMode_beforeDate(NSDefaultRunLoopMode, &until) };
        }
        rx.try_recv().unwrap_or((0, -2))
    }

    /// App-context status read: same async `loadAllFromPreferences`, but instead of
    /// driving a run loop it blocks the *calling* (worker) thread on a channel —
    /// the Tauri app's own main loop services the main-queue completion. Use this
    /// from a Tauri command (never the main thread). Returns (count, first_status).
    pub fn load_first_status(timeout: std::time::Duration) -> (usize, isize) {
        use std::sync::mpsc::channel;

        use block2::RcBlock;
        use objc2_foundation::{NSArray, NSError};

        let (tx, rx) = channel::<(usize, isize)>();
        let handler = RcBlock::new(
            move |arr: *mut NSArray<NETunnelProviderManager>, err: *mut NSError| {
                let result = if !err.is_null() {
                    // loadAll failed (entitlement/profile) — distinct sentinel so the UI
                    // surfaces "failed" instead of a silent "disconnected".
                    (0usize, -3isize)
                } else {
                    // SAFETY: `arr` is the framework-owned managers array (or null).
                    unsafe {
                        if arr.is_null() {
                            (0usize, -1isize)
                        } else {
                            let arr = &*arr;
                            let count = arr.count();
                            let status = if count > 0 {
                                arr.objectAtIndex(0).connection().status().0
                            } else {
                                -1
                            };
                            (count, status)
                        }
                    }
                };
                let _ = tx.send(result);
            },
        );
        // SAFETY: standard NE async-read API; the handler outlives the call via RcBlock.
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&handler) };
        rx.recv_timeout(timeout).unwrap_or((0, -2))
    }

    /// Map a raw NEVPNStatus to the four UI states the frontend SparkBackend uses.
    pub fn ui_state(raw: isize) -> &'static str {
        match raw {
            3 => "connected",
            2 | 4 => "connecting", // connecting / reasserting
            -2 | -3 => "failed",   // -2 = status load timed out, -3 = loadAll error
            _ => "disconnected",   // invalid / disconnected / disconnecting; -1 = no managers
        }
    }

    use std::sync::mpsc::Sender;
    use std::time::Duration;

    use block2::RcBlock;
    use dispatch2::DispatchQueue;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, ProtocolObject};
    use objc2::{define_class, msg_send, AllocAnyThread, DefinedClass};
    use objc2_foundation::{
        ns_string, NSArray, NSDictionary, NSError, NSObject, NSObjectProtocol, NSString,
    };
    use objc2_network_extension::NETunnelProviderProtocol;
    use objc2_system_extensions::{
        OSSystemExtensionManager, OSSystemExtensionProperties, OSSystemExtensionReplacementAction,
        OSSystemExtensionRequest, OSSystemExtensionRequestDelegate, OSSystemExtensionRequestResult,
    };

    fn err_str(e: *mut NSError) -> String {
        // SAFETY: caller passes a non-null framework NSError*.
        unsafe { (*e).localizedDescription().to_string() }
    }

    /// Bundle identifier of the packet-tunnel system extension embedded in the app.
    const TUNNEL_SYSEXT_ID: &str = "org.getlantern.spark.tunnel";

    /// Ivars for the activation delegate: a channel to report the terminal outcome
    /// (Ok once activated, Err on failure) back to the waiting worker thread.
    struct ActIvars {
        tx: Sender<Result<(), String>>,
    }

    define_class!(
        // SAFETY: plain NSObject subclass — no subclassing requirements, no Drop.
        #[unsafe(super(NSObject))]
        #[name = "SparkSysExtDelegate"]
        #[ivars = ActIvars]
        struct ActDelegate;

        unsafe impl NSObjectProtocol for ActDelegate {}

        // OSSystemExtensionRequestDelegate. Callbacks arrive on the queue passed to
        // the request (the main queue); they just forward the verdict on the channel.
        unsafe impl OSSystemExtensionRequestDelegate for ActDelegate {
            // An older copy of the extension exists — replace it with the one we ship.
            #[unsafe(method(request:actionForReplacingExtension:withExtension:))]
            fn action_for_replacing(
                &self,
                _request: &OSSystemExtensionRequest,
                _existing: &OSSystemExtensionProperties,
                _ext: &OSSystemExtensionProperties,
            ) -> OSSystemExtensionReplacementAction {
                OSSystemExtensionReplacementAction::Replace
            }

            // Pending user approval (System Settings → Login Items & Extensions). The
            // request stays pending until the user approves; we keep waiting.
            #[unsafe(method(requestNeedsUserApproval:))]
            fn needs_user_approval(&self, _request: &OSSystemExtensionRequest) {
                eprintln!(
                    "[spark] system extension needs approval in System Settings → \
                     General → Login Items & Extensions"
                );
            }

            #[unsafe(method(request:didFinishWithResult:))]
            fn did_finish(
                &self,
                _request: &OSSystemExtensionRequest,
                result: OSSystemExtensionRequestResult,
            ) {
                // `WillCompleteAfterReboot` means the replacement extension is only *staged*: the
                // previously-active version keeps running until a reboot, and an already-running
                // provider is never hot-swapped. Reporting Ok here is exactly what let stale versions
                // pile up as `terminated_waiting_to_uninstall_on_reboot` while `connect` ran against
                // the wrong binary (cost us a full debugging day, 2026-06-22). Surface it instead so
                // the UI can tell the user to reboot rather than silently "succeeding".
                if result == OSSystemExtensionRequestResult::WillCompleteAfterReboot {
                    let _ = self.ivars().tx.send(Err(
                        "the updated Spark network extension needs a restart to activate — quit \
                         Spark, reboot, then open Spark and tap Connect again"
                            .to_owned(),
                    ));
                    return;
                }
                let _ = self.ivars().tx.send(Ok(()));
            }

            #[unsafe(method(request:didFailWithError:))]
            fn did_fail(&self, _request: &OSSystemExtensionRequest, error: &NSError) {
                let _ = self.ivars().tx.send(Err(format!(
                    "activation failed: {}",
                    error.localizedDescription()
                )));
            }
        }
    );

    impl ActDelegate {
        fn new(tx: Sender<Result<(), String>>) -> Retained<Self> {
            let this = Self::alloc().set_ivars(ActIvars { tx });
            // SAFETY: NSObject's designated initializer.
            unsafe { msg_send![super(this), init] }
        }
    }

    /// U1b-2b-ii: ensure the embedded packet-tunnel system extension is activated,
    /// prompting the user to approve it on first run (`OSSystemExtensionRequest`).
    /// Delegate callbacks fire on the main queue, so this (worker) thread waits on a
    /// channel while the app's main run loop services them — same model as `connect`.
    /// Returns Ok once the extension is active; once approved this completes
    /// immediately on subsequent calls. Needs the `system-extension.install` +
    /// packet-tunnel entitlements (present in the signed product build).
    pub fn activate_extension() -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let delegate = ActDelegate::new(tx);
        let ident = NSString::from_str(TUNNEL_SYSEXT_ID);
        let queue = DispatchQueue::main();
        // SAFETY: standard SystemExtensions activation API; `queue` is the main queue.
        let request =
            unsafe { OSSystemExtensionRequest::activationRequestForExtension_queue(&ident, queue) };
        unsafe { request.setDelegate(Some(ProtocolObject::from_ref(&*delegate))) };
        let manager = unsafe { OSSystemExtensionManager::sharedManager() };
        unsafe { manager.submitRequest(&request) };
        // Wait for a terminal callback. `request`/`delegate` stay alive on this frame
        // for the whole window so a pending approval can still complete (dropping the
        // request cancels it). Generous timeout to let the user approve in Settings.
        let outcome = rx
            .recv_timeout(Duration::from_secs(150))
            .unwrap_or_else(|_| {
                Err(
                    "system extension approval timed out — approve Spark in System \
                 Settings → General → Login Items & Extensions, then tap Connect again"
                        .to_owned(),
                )
            });
        drop(request);
        drop(delegate);
        outcome
    }

    /// U1b-2b: bring the tunnel up. NE completion handlers fire on the main queue
    /// and NETunnelProviderManager isn't Send, so the whole load→save→reload→start
    /// chain runs inside the loadAll completion (on the main thread, via nested
    /// completion blocks); this (worker) thread just waits on a channel for the
    /// final verdict. `config` is the resolved data-path config (TOML/host:port),
    /// handed to the extension via providerConfiguration["config"].
    ///
    /// First activates the org.getlantern.spark.tunnel system extension (U1b-2b-ii,
    /// prompting approval on first run) so there's a provider to start, then runs the
    /// save/start chain. Needs the NE entitlement (present in the signed product build).
    ///
    /// The one adaptation from the app's version: instead of reading split-tunnel /
    /// routing-mode from the app's config module internally, they are passed in as
    /// already-loaded strings so the plugin's persist layer controls the values.
    pub fn connect(
        config: Option<String>,
        split_tunnel: Option<String>,
        routing_mode: Option<String>,
        app_bypass: Option<String>,
    ) -> Result<(), String> {
        // No provider can start until the extension is activated + user-approved.
        activate_extension()?;
        // Resolve the optional strings to owned values before entering the block so
        // the closure can be `Fn` (RcBlock requires Fn, not FnOnce). The original
        // app's connect read these inline from crate::config; here they are pre-loaded
        // by the caller and passed in as Option<String>.
        let split_tunnel_json = split_tunnel.unwrap_or_default();
        let routing_mode_str = routing_mode.unwrap_or_default();
        // App-bypass list (JSON array of canonical `.app` bundle-root paths — the core matches by
        // bundle-root prefix so in-bundle helpers are caught) for desktop app split tunneling,
        // delivered at start via providerConfiguration["appBypass"] (live pushes go through
        // set_excluded_apps → sendProviderMessage). Empty string when nothing is excluded.
        let app_bypass_json = app_bypass.unwrap_or_default();
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let outer = RcBlock::new(
            move |arr: *mut NSArray<NETunnelProviderManager>, e: *mut NSError| {
                // A non-null error means loadAll itself failed (entitlement / provisioning
                // / profile) — surface it instead of silently falling back to a fresh
                // manager and hitting a confusing downstream save/start timeout.
                if !e.is_null() {
                    let _ = tx.send(Err(format!(
                        "loadAllFromPreferences failed: {}",
                        err_str(e)
                    )));
                    return;
                }
                let mgr: Retained<NETunnelProviderManager> = unsafe {
                    if !arr.is_null() && (*arr).count() > 0 {
                        (*arr).objectAtIndex(0)
                    } else {
                        NETunnelProviderManager::new()
                    }
                };
                let proto = unsafe { NETunnelProviderProtocol::new() };
                unsafe {
                    proto.setProviderBundleIdentifier(Some(&NSString::from_str(TUNNEL_SYSEXT_ID)));
                    proto.setServerAddress(Some(ns_string!("Spark")));
                    // Always include splitTunnel, routingMode, and appBypass in
                    // providerConfiguration so the NE can apply the user's domain bypass list,
                    // routing mode, and app-bypass list on every connect. Also include the
                    // optional dev-override config when present. providerConfiguration is
                    // NSDictionary<NSString, AnyObject>; upcast each NSString value
                    // (NSString → NSObject → AnyObject).
                    let st_val: Retained<AnyObject> = NSString::from_str(&split_tunnel_json)
                        .into_super()
                        .into_super();
                    let rm_val: Retained<AnyObject> = NSString::from_str(&routing_mode_str)
                        .into_super()
                        .into_super();
                    let ab_val: Retained<AnyObject> = NSString::from_str(&app_bypass_json)
                        .into_super()
                        .into_super();
                    let dict = if let Some(ref c) = config {
                        let cfg_val: Retained<AnyObject> =
                            NSString::from_str(c).into_super().into_super();
                        NSDictionary::from_retained_objects(
                            &[
                                ns_string!("config"),
                                ns_string!("splitTunnel"),
                                ns_string!("routingMode"),
                                ns_string!("appBypass"),
                            ],
                            &[cfg_val, st_val, rm_val, ab_val],
                        )
                    } else {
                        NSDictionary::from_retained_objects(
                            &[
                                ns_string!("splitTunnel"),
                                ns_string!("routingMode"),
                                ns_string!("appBypass"),
                            ],
                            &[st_val, rm_val, ab_val],
                        )
                    };
                    proto.setProviderConfiguration(Some(&dict));
                    mgr.setProtocolConfiguration(Some(&proto));
                    mgr.setLocalizedDescription(Some(ns_string!("Spark")));
                    mgr.setEnabled(true);
                }
                // save → (on completion) reload → (on completion) start.
                let tx_save = tx.clone();
                let mgr_save = mgr.clone();
                let save_block = RcBlock::new(move |serr: *mut NSError| {
                    if !serr.is_null() {
                        let _ = tx_save.send(Err(format!("save failed: {}", err_str(serr))));
                        return;
                    }
                    let tx_load = tx_save.clone();
                    let mgr_start = mgr_save.clone();
                    let load_block = RcBlock::new(move |lerr: *mut NSError| {
                        if !lerr.is_null() {
                            let _ = tx_load.send(Err(format!("reload failed: {}", err_str(lerr))));
                            return;
                        }
                        let r = unsafe { mgr_start.connection().startVPNTunnelAndReturnError() }
                            .map_err(|e| format!("start failed: {e}"));
                        let _ = tx_load.send(r);
                    });
                    unsafe { mgr_save.loadFromPreferencesWithCompletionHandler(&load_block) };
                });
                unsafe { mgr.saveToPreferencesWithCompletionHandler(Some(&save_block)) };
            },
        );
        // SAFETY: NE copies the escaping completion block, so it outlives this call.
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&outer) };
        // Generous: a first-run connect can block on the interactive "add VPN
        // configurations" approval prompt (saveToPreferences), which the user may
        // take a while to accept — a short timeout would falsely report failure.
        rx.recv_timeout(Duration::from_secs(120))
            .map_err(|_| "connect timed out".to_owned())?
    }

    /// Bring the tunnel down: stop the first manager's connection (the stop call
    /// runs inside the loadAll completion, on the main thread).
    pub fn disconnect() -> Result<(), String> {
        let (tx, rx): (Sender<Result<(), String>>, _) = std::sync::mpsc::channel();
        let h = RcBlock::new(
            move |arr: *mut NSArray<NETunnelProviderManager>, e: *mut NSError| {
                let r = if !e.is_null() {
                    // loadAll failed — propagate the real cause rather than the
                    // misleading "no tunnel configured".
                    Err(format!("loadAllFromPreferences failed: {}", err_str(e)))
                } else {
                    unsafe {
                        if !arr.is_null() && (*arr).count() > 0 {
                            (*arr).objectAtIndex(0).connection().stopVPNTunnel();
                            Ok(())
                        } else {
                            Err("no tunnel configured".to_owned())
                        }
                    }
                };
                let _ = tx.send(r);
            },
        );
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&h) };
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| "disconnect timed out".to_owned())?
    }

    /// Diagnostic trace to `~/spark-ne-debug.log` — the unified log isn't readable from the headless
    /// tooling context, so this gives a file the host can read while debugging the NE channel.
    /// Off by default (no file written); set `SPARK_NE_DEBUG=1` to enable. Best-effort, append-only.
    /// The call sites are deliberately kept — this trace is what localized the `application-identifier`
    /// IPC failure (see Release.entitlements), so it earns its keep behind the flag.
    pub fn ne_debug(msg: &str) {
        if std::env::var_os("SPARK_NE_DEBUG").is_none() {
            return;
        }
        if let Some(home) = std::env::var_os("HOME") {
            use std::io::Write;
            let path = std::path::Path::new(&home).join("spark-ne-debug.log");
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{msg}");
            }
        }
    }

    /// Send a control message to the running tunnel provider via `sendProviderMessage` and return its
    /// reply (a UTF-8 JSON string). The provider's `handleAppMessage` (spark-apple) understands
    /// `{"cmd":"servers"}` and `{"cmd":"select","index":N}`. Loads the manager and resolves its
    /// `NETunnelProviderSession` **entirely on the main queue, per call** — that connection IS the
    /// running tunnel's session (there is a single tunnel configuration), so nothing has to be
    /// retained across threads. The dispatched closure captures only `message` (`String`) and the
    /// channel `Sender` (both `Send`), so the `NETunnelProviderManager`/session `Retained`s are
    /// created, used, and dropped solely on the main thread — no cross-thread `Retained`, no
    /// `unsafe impl Send`. MUST be called off the main thread (the Tauri commands are
    /// `command(async)`): the load/response handlers fire on the main queue while this worker thread
    /// waits on the channel.
    pub fn send_provider_message(message: String) -> Result<String, String> {
        // `Retained`, `RcBlock`, `NSArray`, `NSError`, `Duration`, `err_str` are in scope from the
        // module-level imports; `NSData`/`NETunnelProviderSession` are specific to this call.
        use objc2_foundation::NSData;
        use objc2_network_extension::NETunnelProviderSession;

        ne_debug(&format!("[send] start msg={message}"));
        let (tx, rx) = std::sync::mpsc::channel::<Result<String, String>>();
        // All ObjC work happens on the main queue; the closure captures only `Send` values. The
        // session is resolved fresh from `loadAllFromPreferences` here rather than reused from a
        // stored handle — which is safe now that the real fix was the `application-identifier`
        // entitlement (the earlier "reuse the started manager" workaround is no longer needed).
        DispatchQueue::main().exec_async(move || {
            let load_block = RcBlock::new(
                move |arr: *mut NSArray<NETunnelProviderManager>, e: *mut NSError| {
                    if !e.is_null() {
                        let _ = tx.send(Err(format!(
                            "loadAllFromPreferences failed: {}",
                            err_str(e)
                        )));
                        return;
                    }
                    let mgr = unsafe {
                        if !arr.is_null() && (*arr).count() > 0 {
                            (*arr).objectAtIndex(0)
                        } else {
                            let _ =
                                tx.send(Err("no active tunnel manager — connect first".to_owned()));
                            return;
                        }
                    };
                    let connection = unsafe { mgr.connection() };
                    ne_debug(&format!(
                        "[send] (main) connection status={}",
                        unsafe { connection.status() }.0
                    ));
                    let session = match connection.downcast::<NETunnelProviderSession>() {
                        Ok(s) => s,
                        Err(_) => {
                            ne_debug("[send] (main) downcast FAILED");
                            let _ = tx.send(Err(
                                "tunnel connection is not a provider session".to_owned()
                            ));
                            return;
                        }
                    };
                    let data = NSData::with_bytes(message.as_bytes());
                    let tx_resp = tx.clone();
                    let handler = RcBlock::new(move |resp: *mut NSData| {
                        // A null reply means the provider sent no response — an unrecognized command,
                        // or a control channel that isn't actually delivering. Surface it as an error
                        // rather than a silent empty-string success, so callers don't parse "" as JSON
                        // or mask a dead channel. SAFETY: `resp` is the framework reply NSData (or null).
                        if resp.is_null() {
                            let _ = tx_resp.send(Err("provider sent no response".to_owned()));
                            return;
                        }
                        let bytes = unsafe { &*resp }.to_vec();
                        let s = String::from_utf8_lossy(&bytes).into_owned();
                        let _ = tx_resp.send(Ok(s));
                    });
                    let mut err: Option<Retained<NSError>> = None;
                    // SAFETY: standard NE control API; NE copies the escaping response block.
                    let ok = unsafe {
                        session.sendProviderMessage_returnError_responseHandler(
                            &data,
                            Some(&mut err),
                            Some(&handler),
                        )
                    };
                    let errstr = err
                        .as_ref()
                        .map(|e| e.localizedDescription().to_string())
                        .unwrap_or_default();
                    ne_debug(&format!(
                        "[send] (main) sendProviderMessage ok={ok} err='{errstr}'"
                    ));
                    if !ok {
                        let msg = if errstr.is_empty() {
                            "sendProviderMessage failed".to_owned()
                        } else {
                            errstr
                        };
                        let _ = tx.send(Err(msg));
                    }
                    // On success, the response handler sends the reply.
                },
            );
            // SAFETY: NE copies the escaping completion block, so it outlives this main-queue turn.
            unsafe {
                NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&load_block)
            };
        });
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| Err("provider message timed out".to_owned()));
        ne_debug(&format!("[send] result={result:?}"));
        result
    }
}

// ── Config helpers (relocated from gui-tauri/src-tauri/src/config.rs) ─────────
// These are private to desktop.rs; not part of the plugin's public API.

/// Resolve a deliberate dev override config string, or `None` for the normal daemon-fetch path.
/// Reads `SPARK_CONFIG` (base64 TOML) → `SPARK_PROXY` (host:port) → `None`.
#[cfg(target_os = "macos")]
pub(crate) fn resolve() -> Option<String> {
    resolve_with(
        std::env::var("SPARK_CONFIG").ok(),
        std::env::var("SPARK_PROXY").ok(),
    )
}

#[cfg(target_os = "macos")]
fn resolve_with(baked: Option<String>, proxy: Option<String>) -> Option<String> {
    [baked, proxy]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
}

/// Parse the static pool list from an explicit TOML dev override (`resolve()`).
/// Empty in the normal (daemon-fetch) path — the pool is only known after the extension
/// fetches it, so the live snapshot fills the UI on connect.
#[cfg(target_os = "macos")]
fn servers_from_config() -> Vec<ServerInfo> {
    use serde::Deserialize;

    let Some(text) = resolve() else {
        return Vec::new();
    };
    #[derive(Deserialize)]
    struct Root {
        transport: Option<Transport>,
    }
    #[derive(Deserialize)]
    struct Transport {
        #[serde(default)]
        servers: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        name: Option<String>,
        country: Option<String>,
        country_code: Option<String>,
        city: Option<String>,
    }
    let root: Root = match toml::from_str(&text) {
        Ok(r) => r,
        Err(_) => return Vec::new(), // host:port / base64 / invalid → no static list
    };
    root.transport
        .map(|t| t.servers)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, e)| ServerInfo {
            index: i,
            name: e.name,
            country: e.country,
            country_code: e.country_code,
            city: e.city,
            protocol: None,
            latency_ms: None,
            healthy: false,
            is_current: false,
        })
        .collect()
}

// ── macOS: AppleControl (cross-process NE). ───────────────────────────────────

#[cfg(target_os = "macos")]
pub(crate) struct AppleControl {
    pub(crate) base: PathBuf,
}

#[cfg(target_os = "macos")]
impl TunnelControl for AppleControl {
    fn connect(&self) -> crate::Result<()> {
        let config = resolve(); // dev-override or None (daemon self-fetches)
        let split = {
            let s = crate::persist::load_split_tunnel(&self.base);
            let s = s.trim().to_owned();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        };
        let mode = {
            let m = crate::persist::load_routing_mode(&self.base);
            let m = m.trim().to_owned();
            if m.is_empty() {
                None
            } else {
                Some(m)
            }
        };
        let app_bypass = {
            let a = crate::persist::load_excluded_apps(&self.base);
            let a = a.trim().to_owned();
            if a.is_empty() {
                None
            } else {
                Some(a)
            }
        };
        ne_spike::connect(config, split, mode, app_bypass).map_err(crate::Error::Platform)
    }

    fn disconnect(&self) -> crate::Result<()> {
        ne_spike::disconnect().map_err(crate::Error::Platform)
    }

    fn status(&self) -> crate::Result<Status> {
        let (_count, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(3));
        Ok(Status {
            state: ne_spike::ui_state(raw).to_owned(),
            protocol: "AnyTLS".into(),
            fail_open: false,
        })
    }

    fn servers(&self) -> crate::Result<Vec<ServerInfo>> {
        // Static list from config first, so the screen shows the pool even before connecting.
        let mut list = servers_from_config();
        // Overlay live latency / health / current — but only when actually connected, else
        // sendProviderMessage to a down session just burns the 5s timeout on every poll.
        let (_, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(2));
        if ne_spike::ui_state(raw) == "connected" {
            if let Ok(json) = ne_spike::send_provider_message("{\"cmd\":\"servers\"}".to_owned()) {
                if let Ok(live) = serde_json::from_str::<Vec<ServerInfo>>(&json) {
                    if list.is_empty() {
                        list = live; // no static config (e.g. base64) → use the live pool outright
                    } else {
                        for l in &live {
                            if let Some(s) = list.get_mut(l.index) {
                                // Protocol is identity metadata, not a live measurement: only fill it
                                // when the snapshot knows it, so a partial snapshot can't blank an
                                // already-known subtitle.
                                if let Some(p) = &l.protocol {
                                    s.protocol = Some(p.clone());
                                }
                                s.latency_ms = l.latency_ms;
                                s.healthy = l.healthy;
                                s.is_current = l.is_current;
                            }
                        }
                    }
                }
            }
        }
        Ok(list)
    }

    fn select_server(&self, index: i32) -> crate::Result<()> {
        let resp =
            ne_spike::send_provider_message(format!("{{\"cmd\":\"select\",\"index\":{index}}}"))
                .map_err(crate::Error::Platform)?;
        let v: serde_json::Value = serde_json::from_str(&resp).map_err(crate::Error::Serde)?;
        if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) {
            Ok(())
        } else {
            Err(crate::Error::Platform(
                "server selection was not applied (no active pool?)".to_owned(),
            ))
        }
    }

    fn get_split_tunnel(&self) -> crate::Result<String> {
        Ok(crate::persist::load_split_tunnel(&self.base))
    }

    fn set_split_tunnel(&self, json: &str) -> crate::Result<()> {
        crate::persist::save_split_tunnel(&self.base, json)?;
        // Best-effort live push: only send when the tunnel is actually up.
        let (_, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(2));
        if ne_spike::ui_state(raw) == "connected" {
            let msg = serde_json::json!({"cmd": "splitTunnel", "list": json}).to_string();
            if let Err(e) = ne_spike::send_provider_message(msg) {
                ne_spike::ne_debug(&format!(
                    "split-tunnel live push failed (persisted; applies next connect): {e}"
                ));
            }
        }
        Ok(())
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        Ok(crate::persist::load_routing_mode(&self.base))
    }

    fn set_routing_mode(&self, mode: &str) -> crate::Result<()> {
        crate::persist::save_routing_mode(&self.base, mode)?;
        // Best-effort live push: only send when the tunnel is actually up.
        let (_, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(2));
        if ne_spike::ui_state(raw) == "connected" {
            let msg = serde_json::json!({"cmd": "routingMode", "mode": mode}).to_string();
            if let Err(e) = ne_spike::send_provider_message(msg) {
                ne_spike::ne_debug(&format!(
                    "routing-mode live push failed (persisted; applies next connect): {e}"
                ));
            }
        }
        Ok(())
    }

    // App split tunneling: the macOS installed-apps catalog + excluded-apps persistence, with a
    // best-effort live push to the running NE (mirroring set_split_tunnel).
    fn list_installed_apps(&self) -> crate::Result<String> {
        Ok(crate::apps_darwin::list_installed_apps(&self.base))
    }

    fn get_excluded_apps(&self) -> crate::Result<String> {
        Ok(crate::persist::load_excluded_apps(&self.base))
    }

    fn set_excluded_apps(&self, json: &str) -> crate::Result<()> {
        crate::persist::save_excluded_apps(&self.base, json)?;
        // Push the canonical (trimmed/deduped/blank-stripped) value, not the raw `json`, so a live
        // apply matches exactly what a reconnect would apply from the persisted file.
        let canonical = crate::persist::load_excluded_apps(&self.base);
        // Best-effort live push: only send when the tunnel is actually up.
        let (_, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(2));
        if ne_spike::ui_state(raw) == "connected" {
            let msg = serde_json::json!({"cmd": "appBypass", "list": canonical}).to_string();
            if let Err(e) = ne_spike::send_provider_message(msg) {
                ne_spike::ne_debug(&format!(
                    "app-bypass live push failed (persisted; applies next connect): {e}"
                ));
            }
        }
        Ok(())
    }
}

// ── Windows/Linux: ServiceControl over spark-ipc — future. ───────────────────

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
pub(crate) struct ServiceControl {
    pub(crate) base: PathBuf,
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
impl TunnelControl for ServiceControl {
    fn connect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }

    fn disconnect(&self) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }

    fn status(&self) -> crate::Result<Status> {
        Ok(Status {
            state: "disconnected".into(),
            protocol: "AnyTLS".into(),
            fail_open: false,
        })
    }

    fn servers(&self) -> crate::Result<Vec<ServerInfo>> {
        Ok(Vec::new())
    }

    fn select_server(&self, _index: i32) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }

    fn get_split_tunnel(&self) -> crate::Result<String> {
        Ok(crate::persist::load_split_tunnel(&self.base))
    }

    fn set_split_tunnel(&self, json: &str) -> crate::Result<()> {
        crate::persist::save_split_tunnel(&self.base, json)
    }

    fn get_routing_mode(&self) -> crate::Result<String> {
        Ok(crate::persist::load_routing_mode(&self.base))
    }

    fn set_routing_mode(&self, mode: &str) -> crate::Result<()> {
        crate::persist::save_routing_mode(&self.base, mode)
    }

    // App split tunneling is Android-only for now; the desktop backend lands in a later phase.
    // Reads return an empty catalog so the picker loads; the write errors (like the other
    // not-yet-implemented ServiceControl actions) rather than falsely reporting success.
    fn list_installed_apps(&self) -> crate::Result<String> {
        Ok("[]".to_string())
    }

    fn get_excluded_apps(&self) -> crate::Result<String> {
        Ok("[]".to_string())
    }

    fn set_excluded_apps(&self, _json: &str) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "desktop service: not yet implemented (spark-ipc)".into(),
        ))
    }
}
