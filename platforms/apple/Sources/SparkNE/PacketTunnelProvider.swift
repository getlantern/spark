import NetworkExtension
import SparkCore // the Rust core's C ABI (libspark_apple.a via SparkCore.xcframework)
import os

/// Unified-log sink for the Rust core's `tracing` events (subsystem `org.getlantern.spark`, category
/// `core`), bridged in via `spark_set_log_callback`. Without it the core has no subscriber and the
/// whole config-fetch path is invisible on device. File scope so the C callback below can reach it
/// without capturing.
private let sparkCoreLog = Logger(subsystem: "org.getlantern.spark", category: "core")

/// C callback matching `spark_log_cb`: maps the core's severity (0=ERROR…4=TRACE) to an `os_log`
/// level and logs the message. Captures nothing, so Swift bridges it to a C function pointer. The
/// `msg` pointer is valid only for this call, so `String(cString:)` copies it synchronously. The core
/// curates these lines (no secrets — pro_token is never logged), so `.public` keeps them readable in
/// Console.app rather than redacted to `<private>`.
private func sparkCoreLogBridge(_ level: UInt8, _ msg: UnsafePointer<CChar>?) {
    guard let msg else { return }
    let text = String(cString: msg)
    switch level {
    case 0: sparkCoreLog.error("\(text, privacy: .public)")
    case 1: sparkCoreLog.warning("\(text, privacy: .public)")
    case 2: sparkCoreLog.notice("\(text, privacy: .public)")
    default: sparkCoreLog.debug("\(text, privacy: .public)")
    }
}

/// The spark Packet Tunnel Provider — **one subclass for iOS and macOS** (the OS difference is
/// confined to fd resolution). On `startTunnel` it configures a full-tunnel route, resolves the
/// `utun` fd from `packetFlow`, and hands it to the Rust core (`spark_tunnel_run`), which owns the
/// fd and runs the whole netstack — so packets never cross the FFI. `stopTunnel` signals the core.
///
/// Loop avoidance: the NE process's own upstream dials egress the real interface (they're not
/// routed back through `packetFlow`), so no per-socket protection is needed.
///
/// Logs go to the unified log under subsystem `org.getlantern.spark` — read with Console.app or
/// `log stream --predicate 'subsystem == "org.getlantern.spark"'`.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "org.getlantern.spark", category: "tunnel")
    private let mtu = 1500
    private var worker: Thread?

    // `startTunnel`'s completion, fired exactly once via `finishStart`. The readiness waiter and
    // `stopTunnel` (if a connect is cancelled mid-startup) can both race to resolve the start; the
    // lock + take-and-nil makes the NE see a single, well-ordered completion.
    private let startLock = NSLock()
    private var pendingStart: ((Error?) -> Void)?

    /// Fire `startTunnel`'s completion handler exactly once (`nil` = connected, else the start failed).
    /// Subsequent calls are no-ops, so the readiness waiter and `stopTunnel` can both call it safely.
    private func finishStart(_ error: Error?) {
        startLock.lock()
        let handler = pendingStart
        pendingStart = nil
        startLock.unlock()
        handler?(error)
    }

    /// Whether a start is still pending — i.e. `stopTunnel`/`finishStart` hasn't resolved it yet.
    /// `startTunnel`'s async stages check this and bail if the connect was cancelled mid-startup, so we
    /// don't resolve an fd or spawn a worker after teardown has begun.
    private func startPending() -> Bool {
        startLock.lock()
        defer { startLock.unlock() }
        return pendingStart != nil
    }

    override func startTunnel(
        options _: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // Bridge core tracing -> os_log before anything else, so cold-start fetch logs are captured.
        // Idempotent (the core's tracing global default is set once); safe to call on every connect.
        spark_set_log_callback(sparkCoreLogBridge)
        log.notice("startTunnel: configuring full-tunnel settings")
        startLock.lock()
        pendingStart = completionHandler
        startLock.unlock()
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()] // capture all IPv4
        settings.ipv4Settings = ipv4
        settings.mtu = NSNumber(value: mtu)
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            // `stopTunnel` may have fired before this async callback ran (connect cancelled
            // mid-startup); if so the start is already resolved — don't resolve an fd or spawn a worker.
            guard self.startPending() else {
                self.log.notice("startup cancelled before settings callback; skipping")
                return
            }
            if let error {
                self.log.error("setTunnelNetworkSettings failed: \(error.localizedDescription)")
                self.finishStart(error)
                return
            }
            guard let fd = FdResolver.resolve(packetFlow: self.packetFlow) else {
                self.log.error("could not resolve the utun fd")
                self.finishStart(NEVPNError(.configurationInvalid))
                return
            }
            // The controlling app passes the data-path config in `providerConfiguration["config"]`:
            // a bare "host:port" (plain relay) or a full TOML config (AnyTLS + shaping + gambit) as an
            // explicit override. Absent/empty → the daemon self-fetches from config-new (the default).
            // (Back-compat: the legacy `["server"]` host:port key is still honored if `["config"]`
            // is unset.)
            let provider = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
            let config = (provider?["config"] as? String) ?? (provider?["server"] as? String)
            let mode = (config?.isEmpty == false && config != "lantern-api") ? "explicit-config" : "self-fetch"
            self.log.notice("resolved fd=\(fd); starting spark_tunnel_run (mtu=\(self.mtu), mode=\(mode, privacy: .public))")

            // The app-group container path the app + extension share; the Rust core caches the
            // generated `device_id` and the fetched `config_raw.json` here. Required by self-fetch
            // mode (absent/empty config); for an explicit config it's passed through and ignored.
            let dataDir = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: "group.org.getlantern.spark")?
                .appendingPathComponent("config", isDirectory: true).path

            // `spark_tunnel_run` blocks until `spark_tunnel_stop`, so run it off the NE callback
            // thread. The core owns `fd` and closes it on stop. `withCString` keeps the C strings
            // alive for the whole blocking call (it returns only when the tunnel stops).
            let worker = Thread { [mtu = self.mtu, log = self.log, config, dataDir] in
                // Thread the optional app-group data dir through as the 4th C-ABI arg (nil if absent).
                func runNative(_ cfg: UnsafePointer<CChar>?) -> Int32 {
                    if let dataDir {
                        return dataDir.withCString { spark_tunnel_run(fd, Int32(mtu), cfg, $0) }
                    }
                    return spark_tunnel_run(fd, Int32(mtu), cfg, nil)
                }
                let rc: Int32
                if let config, !config.isEmpty {
                    rc = config.withCString { runNative($0) }
                } else {
                    rc = runNative(nil)
                }
                log.notice("spark_tunnel_run returned \(rc)")
            }
            worker.name = "spark-tunnel"
            worker.stackSize = 1 << 20

            // Re-check right before spawning: `stopTunnel` may have fired during this callback. If the
            // start was cancelled, don't spawn the worker (it would run on past teardown). Narrow
            // residual: a stop in the gap before the worker registers its stop handle is the shared
            // registry's pre-existing limitation; the stray worker dies with the extension on teardown.
            guard self.startPending() else {
                self.log.notice("startup cancelled before worker start; skipping")
                return
            }
            self.worker = worker

            // Mark connecting BEFORE starting the worker, so the readiness waiter below can't observe a
            // stale ready/down state from a prior connect; then start the (blocking) tunnel worker.
            spark_tunnel_mark_connecting()
            worker.start()

            // Gate "connected" on the data path actually servicing the fd. In `lantern-api` mode the
            // core fetches config *before* adopting the fd, so reporting up eagerly would blackhole
            // traffic on a cold start (especially offline). Wait (bounded) for the ready signal on a
            // separate thread, then complete — or fail the connection cleanly if it never comes up.
            let readyWaiter = Thread { [weak self, log = self.log] in
                let rc = spark_tunnel_wait_ready(30_000) // 30s ceiling
                if rc == 0 {
                    log.notice("tunnel data path ready; reporting connected")
                    self?.finishStart(nil)
                } else {
                    log.error("tunnel did not become ready (config unavailable?); failing connection")
                    spark_tunnel_stop()
                    self?.finishStart(NEVPNError(.connectionFailed))
                }
            }
            readyWaiter.name = "spark-ready"
            readyWaiter.start()
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.notice("stopTunnel (reason \(reason.rawValue))")
        spark_tunnel_stop()
        // If a connect was cancelled mid-startup (the readiness waiter is still blocked), resolve the
        // start as failed so it can't fire after this stop completes. No-op if already resolved.
        finishStart(NEVPNError(.connectionFailed))
        worker = nil
        completionHandler()
    }

    /// Control channel for the server-selection UI. The controlling app sends a small JSON command
    /// via `NETunnelProviderSession.sendProviderMessage(_:)`; we route it to the Rust core's pool
    /// control and reply with JSON:
    ///   `{"cmd":"servers"}`           → the pool array (see `spark_servers_json`), or `[]`.
    ///   `{"cmd":"select","index":N}`  → pin member N (N < 0 = auto); replies `{"ok":true|false}`.
    /// Unknown/malformed messages get a nil reply. (Packets still never cross the FFI — this is
    /// control-only, like the existing run/stop calls.)
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        // Diagnostic: fires before any guard, so we can tell whether NE invokes the handler at all
        // (and on which thread / with a completion handler). `.public` so values aren't redacted.
        log.notice(
            "handleAppMessage ENTER: \(messageData.count, privacy: .public)B hasCompletion=\(completionHandler != nil, privacy: .public) mainThread=\(Thread.isMainThread, privacy: .public)"
        )
        guard let completionHandler else { return }
        guard
            let obj = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
            let cmd = obj["cmd"] as? String
        else {
            log.error("handleAppMessage: unrecognized message")
            completionHandler(nil)
            return
        }
        switch cmd {
        case "servers":
            // Heap-allocated C string from Rust; copy into a Swift String, then free it.
            guard let cstr = spark_servers_json() else {
                completionHandler("[]".data(using: .utf8))
                return
            }
            let json = String(cString: cstr)
            spark_string_free(cstr)
            completionHandler(json.data(using: .utf8))
        case "select":
            // Missing / non-integer / out-of-Int32-range index → -1 (auto). `Int32(exactly:)` is
            // non-trapping, unlike `Int32.init`, which would crash the extension on a huge index from
            // a malformed app message — this handler must tolerate untrusted input.
            let index = (obj["index"] as? Int).flatMap { Int32(exactly: $0) } ?? -1
            let rc = spark_select_server(index)
            log.notice("handleAppMessage: select index=\(index) rc=\(rc)")
            completionHandler("{\"ok\":\(rc == 0)}".data(using: .utf8))
        default:
            log.error("handleAppMessage: unknown cmd \(cmd)")
            completionHandler(nil)
        }
    }
}
