import NetworkExtension
import SparkCore // the Rust core's C ABI (libspark_apple.a via SparkCore.xcframework)
import os

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

    override func startTunnel(
        options _: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        log.notice("startTunnel: configuring full-tunnel settings")
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()] // capture all IPv4
        settings.ipv4Settings = ipv4
        settings.mtu = NSNumber(value: mtu)
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                self.log.error("setTunnelNetworkSettings failed: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            guard let fd = FdResolver.resolve(packetFlow: self.packetFlow) else {
                self.log.error("could not resolve the utun fd")
                completionHandler(NEVPNError(.configurationInvalid))
                return
            }
            // The controlling app passes the data-path config in `providerConfiguration["config"]`:
            // a bare "host:port" (plain relay), or a full TOML config (AnyTLS + shaping + gambit).
            // Absent/empty → forward directly. (Back-compat: the legacy `["server"]` host:port key is
            // still honored if `["config"]` is unset.)
            let provider = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
            let config = (provider?["config"] as? String) ?? (provider?["server"] as? String)
            self.log.notice("resolved fd=\(fd); starting spark_tunnel_run (mtu=\(self.mtu), config=\(config?.isEmpty == false ? "set" : "direct"))")

            // `spark_tunnel_run` blocks until `spark_tunnel_stop`, so run it off the NE callback
            // thread. The core owns `fd` and closes it on stop. `withCString` keeps the C string
            // alive for the whole blocking call (it returns only when the tunnel stops).
            let worker = Thread { [mtu = self.mtu, log = self.log, config] in
                let rc: Int32
                if let config, !config.isEmpty {
                    rc = config.withCString { spark_tunnel_run(fd, Int32(mtu), $0) }
                } else {
                    rc = spark_tunnel_run(fd, Int32(mtu), nil)
                }
                log.notice("spark_tunnel_run returned \(rc)")
            }
            worker.name = "spark-tunnel"
            worker.stackSize = 1 << 20
            self.worker = worker
            worker.start()
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.notice("stopTunnel (reason \(reason.rawValue))")
        spark_tunnel_stop()
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
            // Missing/invalid index → -1 (auto).
            let index = (obj["index"] as? Int).map(Int32.init) ?? -1
            let rc = spark_select_server(index)
            log.notice("handleAppMessage: select index=\(index) rc=\(rc)")
            completionHandler("{\"ok\":\(rc == 0)}".data(using: .utf8))
        default:
            log.error("handleAppMessage: unknown cmd \(cmd)")
            completionHandler(nil)
        }
    }
}
