use std::path::PathBuf;

use crate::control::TunnelControl;
use crate::models::{ServerInfo, Status};

// ── Apple (macOS + iOS) NE control (relocated verbatim from gui-tauri/src-tauri/src/lib.rs;
//    the NETunnelProviderManager path is shared, macOS additionally does system-extension activation) ─

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) mod ne_spike {
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
    #[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
    struct ActIvars {
        tx: Sender<Result<(), String>>,
    }

    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
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
    /// On macOS, first activates the org.getlantern.spark.tunnel *system extension* (U1b-2b-ii,
    /// prompting approval on first run) so there's a provider to start. On iOS the NE is a bundled
    /// app-extension — no activation step; consent is the "Allow VPN configuration" prompt raised
    /// by saveToPreferences. Then runs the save/start chain. Needs the NE entitlement (present in
    /// the signed product build).
    ///
    /// The one adaptation from the app's version: instead of reading split-tunnel /
    /// routing-mode from the app's config module internally, they are passed in as
    /// already-loaded strings so the plugin's persist layer controls the values.
    pub fn connect(
        config: Option<String>,
        split_tunnel: Option<String>,
        routing_mode: Option<String>,
        app_bypass: Option<String>,
        ad_block: bool,
        diagnostics: bool,
        identity: Option<String>,
    ) -> Result<(), String> {
        // macOS system extension must be activated + user-approved before a provider can start. iOS
        // ships the NE as a bundled app-extension — no activation; the "Allow VPN configuration"
        // consent comes from saveToPreferences during connect below.
        #[cfg(target_os = "macos")]
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
        // set_excluded_apps → sendProviderMessage). `AppleControl::connect` supplies the persisted
        // canonical array ("[]" when nothing is excluded); `unwrap_or_default()` only yields "" if a
        // caller passes `None`, which the NE reads the same as "[]" (no bypass).
        let app_bypass_json = app_bypass.unwrap_or_default();
        // providerConfiguration values are strings, so pre-format the bool as "true"/"false"
        // (the NE parses "false" → off). Owned so the closure can stay `Fn`.
        let ad_block_str = if ad_block { "true" } else { "false" }.to_owned();
        // The user's diagnostics toggle, same "true"/"false" encoding. This is the ONLY channel by
        // which their choice reaches the NE: the core's other consent gate is the SPARK_DIAGNOSTICS
        // env var, which nobody using the app can set on a system extension — so without this key
        // "declined" meant whoever launched the process. Carried in the saved VPN profile like the
        // rest, so it also governs on-demand and at-boot starts with no app running.
        let diagnostics_str = if diagnostics { "true" } else { "false" }.to_owned();
        // The app's own device + account identity, handed to the NE so it fetches config as THIS user
        // instead of registering its own. Empty when the app hasn't fetched yet (identity is minted by
        // its first config fetch): the NE then refuses to start with a clear error rather than quietly
        // creating a second account — which is what it used to do, leaving every install with two
        // Lantern users and entitlement stranded on the app's. See docs/identity-unification-design.md.
        let identity_json = identity.unwrap_or_default();
        // NOTE: we deliberately do NOT pass a dataDir to the NE. The NE self-resolves its OWN
        // app-group container; the system-extension sandbox forbids the root NE from accessing the
        // *user's* group container (EPERM → self-fetch hangs → connect times out, confirmed
        // on-device 2026-07-13). The app keeps its own separate config cache for the UI location list
        // (`app_config_cache_dir()`, fetched by the Phase 2a startup task); it is not shared with the
        // NE on macOS.
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
                    // Always include splitTunnel, routingMode, appBypass, adBlock, and diagnostics in
                    // providerConfiguration so the NE can apply the user's domain bypass list,
                    // routing mode, app-bypass list, and ad-block toggle on every connect. Also
                    // include the optional dev-override config when present. providerConfiguration
                    // is NSDictionary<NSString, AnyObject>; upcast each NSString value
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
                    let adb_val: Retained<AnyObject> =
                        NSString::from_str(&ad_block_str).into_super().into_super();
                    let diag_val: Retained<AnyObject> = NSString::from_str(&diagnostics_str)
                        .into_super()
                        .into_super();
                    let id_val: Retained<AnyObject> =
                        NSString::from_str(&identity_json).into_super().into_super();
                    let dict = if let Some(ref c) = config {
                        let cfg_val: Retained<AnyObject> =
                            NSString::from_str(c).into_super().into_super();
                        NSDictionary::from_retained_objects(
                            &[
                                ns_string!("config"),
                                ns_string!("splitTunnel"),
                                ns_string!("routingMode"),
                                ns_string!("appBypass"),
                                ns_string!("adBlock"),
                                ns_string!("diagnostics"),
                                ns_string!("identity"),
                            ],
                            &[cfg_val, st_val, rm_val, ab_val, adb_val, diag_val, id_val],
                        )
                    } else {
                        NSDictionary::from_retained_objects(
                            &[
                                ns_string!("splitTunnel"),
                                ns_string!("routingMode"),
                                ns_string!("appBypass"),
                                ns_string!("adBlock"),
                                ns_string!("diagnostics"),
                                ns_string!("identity"),
                            ],
                            &[st_val, rm_val, ab_val, adb_val, diag_val, id_val],
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
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn resolve() -> Option<String> {
    resolve_with(
        std::env::var("SPARK_CONFIG").ok(),
        std::env::var("SPARK_PROXY").ok(),
    )
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
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
#[cfg(any(target_os = "macos", target_os = "ios"))]
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
            is_pinned: false,
        })
        .collect()
}

/// The app's OWN on-disk config-cache dir: `<app_config_dir>/config` (macOS:
/// `~/Library/Application Support/org.getlantern.spark/config`) — where the app fetches + reads its
/// `config_raw.json` for the location list. `base` is the plugin's `app_config_dir()`.
///
/// Deliberately NOT the app-group container: the macOS system-extension sandbox denies the root NE
/// access to the *user's* group container (EPERM — hangs connect), so the NE cache can't be shared
/// with the app anyway; and a non-sandboxed app poking into `~/Library/Group Containers/` trips a
/// macOS "access data from other apps" TCC prompt. The app's own Application Support dir (where the
/// plugin already stores its settings) avoids both.
#[cfg(not(target_os = "android"))]
pub(crate) fn app_config_cache_dir(base: &std::path::Path) -> PathBuf {
    base.join("config")
}

/// The app's device + account identity as `{"device_id":…,"user_id":…,"pro_token":…}`, for handing to
/// the NE in `providerConfiguration["identity"]`. `None` until the app's first config fetch has minted
/// it (`device_id` is written locally, `user.json` comes from `/user-create`).
///
/// This is the *only* durable copy of identity: the NE receives it per start and persists nothing, so
/// there is no second copy that can drift. Reads the files rather than re-deriving, because
/// `fetch::device_id()` would CREATE one — and a second creator is exactly the bug being removed.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn identity_json(base: &std::path::Path) -> Option<String> {
    let dir = app_config_cache_dir(base);
    let device_id = std::fs::read_to_string(dir.join("device_id")).ok()?;
    let user = std::fs::read_to_string(dir.join("user.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&user).ok()?;
    let user_id = v.get("user_id")?.as_str()?;
    let pro_token = v.get("pro_token")?.as_str()?;
    let device_id = device_id.trim();
    if device_id.is_empty() || user_id.is_empty() || user_id == "0" || pro_token.is_empty() {
        return None; // a partial identity must not half-apply — the NE rejects it anyway
    }
    serde_json::to_string(&serde_json::json!({
        "device_id": device_id,
        "user_id": user_id,
        "pro_token": pro_token,
    }))
    .ok()
}

/// Location list read from the app's own `config_raw.json` cache, or empty if there's no cache yet
/// (never fetched) or it can't be read/parsed. Built via the core's exact `config_raw.json` → pool
/// mapping ([`spark_core::config::lantern::from_config_raw_json`]) so the pre-connect list IS the
/// pool — same members, same order, each with its protocol. (Building from the top-level geo
/// `servers[]` array instead put protocol/latency on the wrong rows: that array is ordered
/// differently from `options.outbounds`.) This is the pre-connect path only; once connected,
/// `servers()` returns the NE's live snapshot directly (no overlay).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn servers_from_cache(base: &std::path::Path) -> Vec<ServerInfo> {
    let path = app_config_cache_dir(base).join("config_raw.json");
    // Re-parse only when the file actually changed. The UI polls `servers()` every 2s and, while
    // disconnected, every one of those ticks landed here — so this read the file and ran the FULL
    // `config_raw.json` → pool mapping twice a minute forever, including its per-outbound warnings.
    // Those warnings are captured by the diag layer, so an idle app was also filling the spool (and
    // the telemetry channel, and its ingestion quota) with the same lines on a 2s cadence; that is
    // how this was noticed. A `stat` is microseconds against a parse of the whole config.
    //
    // Keyed on mtime, which preserves the original intent exactly — `config_fetch` rewrites this
    // file and expects the next `servers()` pull to see it (see its module doc).
    let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    if let Some(mtime) = mtime {
        if let Some((cached_at, list)) = servers_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            if *cached_at == mtime {
                return list.clone();
            }
        }
    }

    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        // A missing cache is the normal pre-first-fetch state — silent.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            ne_spike::ne_debug(&format!("servers_from_cache: read failed: {e}"));
            return Vec::new();
        }
    };
    let list = match spark_core::config::lantern::from_config_raw_json(&raw) {
        Ok(cfg) => servers_from_pool(&cfg),
        Err(e) => {
            ne_spike::ne_debug(&format!("servers_from_cache: parse failed: {e}"));
            Vec::new()
        }
    };
    // Store even an empty result: a config whose outbounds spark can't represent parses to nothing,
    // and re-deriving that every 2s is the case this exists to stop. An unreadable mtime skips the
    // store, so the next call simply re-parses — correctness over the optimisation.
    if let Some(mtime) = mtime {
        *servers_cache().lock().unwrap_or_else(|e| e.into_inner()) = Some((mtime, list.clone()));
    }
    list
}

/// A [`servers_from_cache`] result together with the `config_raw.json` mtime it was built from.
#[cfg(any(target_os = "macos", target_os = "ios"))]
type CachedServers = Option<(std::time::SystemTime, Vec<ServerInfo>)>;

/// Memoised [`servers_from_cache`] result, keyed on the `config_raw.json` mtime it was built from.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn servers_cache() -> &'static std::sync::Mutex<CachedServers> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<CachedServers>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(None))
}

/// Map a parsed config's server pool to the UI location list — the same members/order the live NE
/// snapshot uses (indexed by position), each with its protocol label but no live metrics yet
/// (latency/health/current fill in from the NE snapshot once connected).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn servers_from_pool(cfg: &spark_core::config::Config) -> Vec<ServerInfo> {
    cfg.transport
        .servers
        .iter()
        .enumerate()
        .map(|(i, e)| ServerInfo {
            index: i,
            name: e.name.clone(),
            country: e.country.clone(),
            country_code: e.country_code.clone(),
            city: e.city.clone(),
            protocol: Some(spark_core::transport::spec_kind(&e.spec).to_string()),
            latency_ms: None,
            healthy: false,
            is_current: false,
            is_pinned: false,
        })
        .collect()
}

// ── Apple (macOS + iOS): AppleControl (cross-process NE). ────────────────────

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) struct AppleControl {
    pub(crate) base: PathBuf,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
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
        let ad_block = crate::persist::load_ad_block_enabled(&self.base);
        // Read here (the app owns the only durable copy) and hand it down; `ne_spike` has no base dir.
        let identity = identity_json(&self.base);
        if identity.is_none() {
            tracing::warn!(
                "no app identity yet (first config fetch hasn't minted one) — the tunnel will refuse \
                 to start rather than register a second account"
            );
        }
        // The user's diagnostics choice, from the same persisted toggle the app process reads at
        // `diag_host::init`. Passing it is what makes one switch govern BOTH processes.
        let diagnostics = crate::persist::load_diagnostics_enabled(&self.base);
        ne_spike::connect(
            config,
            split,
            mode,
            app_bypass,
            ad_block,
            diagnostics,
            identity,
        )
        .map_err(crate::Error::Platform)
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
        // When connected, the NE's live snapshot is the source of truth: a COMPLETE list (geo,
        // protocol, latency, health, current) for the pool actually in use. Use it directly.
        //
        // Do NOT overlay it onto the app's own cached list by index. The app cache and the NE cache
        // are independent config-new fetches (macOS can't share them — the NE sandbox blocks the
        // user container), so their pool order can differ; overlaying by index then stamped
        // `is_current`/latency onto the wrong city (e.g. showing Tokyo as current while actually
        // connected to Toronto). Only poll the NE when connected — `sendProviderMessage` to a down
        // session burns the 5s timeout on every poll.
        let (_, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(2));
        if ne_spike::ui_state(raw) == "connected" {
            if let Ok(json) = ne_spike::send_provider_message("{\"cmd\":\"servers\"}".to_owned()) {
                if let Ok(live) = serde_json::from_str::<Vec<ServerInfo>>(&json) {
                    if !live.is_empty() {
                        return Ok(live);
                    }
                }
            }
        }
        // Not connected (or no live pool, e.g. a single-transport config): show the pre-connect list
        // from a SPARK_CONFIG dev-override, else the app's own cached `config_raw.json` (built from
        // the pool, with protocol) so the screen shows the pool before connecting.
        let mut list = servers_from_config();
        if list.is_empty() {
            list = servers_from_cache(&self.base);
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

    fn get_ad_block_enabled(&self) -> crate::Result<bool> {
        Ok(crate::persist::load_ad_block_enabled(&self.base))
    }

    fn set_ad_block_enabled(&self, enabled: bool) -> crate::Result<()> {
        crate::persist::save_ad_block_enabled(&self.base, enabled)?;
        // Best-effort live push: only send when the tunnel is actually up.
        let (_, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(2));
        if ne_spike::ui_state(raw) == "connected" {
            let msg = serde_json::json!({"cmd": "adBlock", "enabled": enabled}).to_string();
            if let Err(e) = ne_spike::send_provider_message(msg) {
                ne_spike::ne_debug(&format!(
                    "ad-block live push failed (persisted; applies next connect): {e}"
                ));
            }
        }
        Ok(())
    }

    // App split tunneling: the macOS installed-apps catalog + excluded-apps persistence, with a
    // best-effort live push to the running NE (mirroring set_split_tunnel).
    fn list_installed_apps(&self) -> crate::Result<String> {
        // apps_darwin uses AppKit (NSWorkspace) which is macOS-only. On iOS the picker
        // is not yet implemented; return an empty catalog so the command doesn't error.
        #[cfg(target_os = "macos")]
        return Ok(crate::apps_darwin::list_installed_apps(&self.base));
        #[cfg(not(target_os = "macos"))]
        Ok("[]".to_string())
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

// ── Windows/Linux: ServiceControl over spark-ipc. ────────────────────────────

#[cfg(all(
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
pub(crate) struct ServiceControl {
    pub(crate) base: PathBuf,
    ipc: crate::service_ipc::IpcClient,
}

#[cfg(all(
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
impl ServiceControl {
    pub(crate) fn new(base: PathBuf) -> Self {
        let ipc = crate::service_ipc::IpcClient::new(crate::service_ipc::default_control_addr());
        Self { base, ipc }
    }

    /// Issue `payload` (named `op` for diagnostics), returning the raw reply. Transport/timeout
    /// failures are prefixed with the operation so a pipe-open failure or timeout is attributable
    /// in logs, not just protocol mismatches.
    fn request(
        &self,
        op: &str,
        payload: spark_ipc::message::RequestPayload,
    ) -> crate::Result<spark_ipc::message::ResponsePayload> {
        self.ipc
            .request(payload)
            .map_err(|e| crate::Error::Platform(format!("{op}: {e}")))
    }

    /// Send `payload` (named `op`), expecting an `Ack`. A service-side `Error` surfaces its message
    /// verbatim (e.g. Unauthorized / NotConnected); anything else is a protocol mismatch, reported
    /// with the operation name.
    fn ack(&self, op: &str, payload: spark_ipc::message::RequestPayload) -> crate::Result<()> {
        match self.request(op, payload)? {
            spark_ipc::message::ResponsePayload::Ack => Ok(()),
            spark_ipc::message::ResponsePayload::Error { message, .. } => {
                Err(crate::Error::Platform(message))
            }
            other => Err(crate::Error::Platform(format!(
                "{op}: unexpected reply {other:?}"
            ))),
        }
    }
}

#[cfg(all(
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
impl TunnelControl for ServiceControl {
    fn connect(&self) -> crate::Result<()> {
        self.ack("connect", spark_ipc::message::RequestPayload::Connect)
    }

    fn disconnect(&self) -> crate::Result<()> {
        self.ack("disconnect", spark_ipc::message::RequestPayload::Disconnect)
    }

    fn status(&self) -> crate::Result<Status> {
        match self.request("status", spark_ipc::message::RequestPayload::GetStatus)? {
            spark_ipc::message::ResponsePayload::Status(s) => Ok(crate::service_ipc::map_status(s)),
            spark_ipc::message::ResponsePayload::Error { message, .. } => {
                Err(crate::Error::Platform(message))
            }
            other => Err(crate::Error::Platform(format!(
                "status: unexpected reply {other:?}"
            ))),
        }
    }

    fn servers(&self) -> crate::Result<Vec<ServerInfo>> {
        Ok(Vec::new())
    }

    fn select_server(&self, _index: i32) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "server selection is not supported by the desktop service yet".into(),
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

    fn get_ad_block_enabled(&self) -> crate::Result<bool> {
        Ok(crate::persist::load_ad_block_enabled(&self.base))
    }

    fn set_ad_block_enabled(&self, enabled: bool) -> crate::Result<()> {
        crate::persist::save_ad_block_enabled(&self.base, enabled)
    }

    // App split tunneling is Android-only for now; the desktop backend lands in a later phase.
    // Reads return an empty catalog so the picker loads; the write errors rather than falsely
    // reporting success.
    fn list_installed_apps(&self) -> crate::Result<String> {
        Ok("[]".to_string())
    }

    fn get_excluded_apps(&self) -> crate::Result<String> {
        Ok("[]".to_string())
    }

    fn set_excluded_apps(&self, _json: &str) -> crate::Result<()> {
        Err(crate::Error::Platform(
            "per-app split tunneling is not supported by the desktop service yet".into(),
        ))
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod servers_cache_tests {
    use super::*;

    /// A `config_raw.json` with one representable outbound, so the mapping yields a pool.
    /// `hysteria2` needs only `server`/`server_port`/`password` — the least fixture for a pool entry.
    fn config_json(port: u16) -> String {
        format!(
            r#"{{"options":{{"outbounds":[
                {{"tag":"a","type":"hysteria2","server":"1.2.3.4","server_port":{port},"password":"p"}}
            ]}}}}"#
        )
    }

    fn write_config(dir: &std::path::Path, body: &str) {
        let cache = app_config_cache_dir(dir);
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("config_raw.json"), body).unwrap();
    }

    /// The list is memoised on the file's mtime, and a genuine rewrite is picked up.
    ///
    /// Proven by **pinning the mtime across a content change**: the body changes to one with no
    /// representable outbound, but the timestamp is restored. A working memo keeps returning the
    /// old list; a broken one re-parses and returns empty. Asserting only that repeated calls agree
    /// would pass either way — the memo has to be observable, not merely plausible.
    ///
    /// Why it matters: the UI polls `servers()` every 2s and, while disconnected, every tick ran
    /// the full `config_raw.json` → pool mapping. Its per-outbound warnings are captured by the diag
    /// layer, so an idle app filled the spool — and the telemetry channel — on a 2s cadence.
    #[test]
    fn servers_are_memoised_until_the_config_file_changes() {
        let dir = std::env::temp_dir().join(format!("spark-servers-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Start from a known-empty memo: it is a process-global another test could have populated.
        *servers_cache().lock().unwrap() = None;

        let path = app_config_cache_dir(&dir).join("config_raw.json");
        write_config(&dir, &config_json(443));
        assert_eq!(
            servers_from_cache(&dir).len(),
            1,
            "the representable outbound became a pool entry"
        );
        let pinned = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Swap in a config with NOTHING representable, then restore the mtime so the memo's key is
        // unchanged. This is what makes the memo observable.
        std::fs::write(&path, r#"{"options":{"outbounds":[]}}"#).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(pinned))
            .unwrap();
        assert_eq!(
            servers_from_cache(&dir).len(),
            1,
            "unchanged mtime must serve the memo, not re-parse (the whole point)"
        );

        // A real rewrite moves the mtime, and the new — empty — pool must win over the memo.
        // The new mtime is set explicitly rather than slept for: filesystems with coarse timestamp
        // granularity (1s on HFS+ and some network mounts) would leave a short sleep's mtime
        // unchanged, so the memo would legitimately hit and this assertion would fail on a correct
        // implementation. Same mechanism as the pin above, in the opposite direction.
        std::fs::write(&path, r#"{"options":{"outbounds":[]}}"#).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new().set_modified(pinned + std::time::Duration::from_secs(2)),
            )
            .unwrap();
        assert!(
            servers_from_cache(&dir).is_empty(),
            "a changed mtime must re-parse; config_fetch rewrites this file expecting exactly that"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
