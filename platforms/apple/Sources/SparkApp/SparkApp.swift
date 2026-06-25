import NetworkExtension
import os
import SwiftUI
import SystemExtensions

/// Container app / test harness. On launch it activates the Packet Tunnel **system extension**
/// (first run prompts approval in System Settings → Privacy & Security), then installs an
/// `NETunnelProviderManager` and starts it (first run prompts the VPN consent). Logs go to the
/// unified log under subsystem `org.getlantern.spark` (read with Console.app).
@main
struct SparkApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_: Notification) {
        // Activate the system extension, then bring the tunnel up once it's installed/approved.
        SysExt.shared.onReady = { Vpn.shared.connect() }
        SysExt.shared.activate()
    }
}

struct ContentView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("spark")
            Button("Activate + Connect") { SysExt.shared.onReady = { Vpn.shared.connect() }; SysExt.shared.activate() }
            Button("Disconnect") { Vpn.shared.disconnect() }
            Button("Open Extension Settings") { SysExt.shared.openSettings() }
        }
        .padding(24)
    }
}

/// Drives system-extension activation (`OSSystemExtensionRequest`). `onReady` fires once the
/// extension is active.
final class SysExt: NSObject, OSSystemExtensionRequestDelegate {
    static let shared = SysExt()
    private let log = Logger(subsystem: "org.getlantern.spark", category: "sysext")
    private let extBundleId = "org.getlantern.spark.tunnel"
    var onReady: (() -> Void)?

    func activate() {
        log.notice("submitting system extension activation for \(self.extBundleId)")
        let req = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extBundleId, queue: .main
        )
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    func openSettings() {
        // macOS 15+ deep-links to the Network Extensions pane; older falls back to Privacy/Security.
        let urls = [
            "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point",
            "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
            "x-apple.systempreferences:com.apple.preference.security",
        ]
        for u in urls where NSWorkspace.shared.open(URL(string: u)!) { return }
    }

    // MARK: OSSystemExtensionRequestDelegate

    func request(
        _: OSSystemExtensionRequest,
        actionForReplacingExtension _: OSSystemExtensionProperties,
        withExtension _: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace // always take the bundled build during dev
    }

    func requestNeedsUserApproval(_: OSSystemExtensionRequest) {
        log.notice("system extension needs user approval (System Settings → Privacy & Security)")
        DispatchQueue.main.async { self.openSettings() }
    }

    func request(_: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        log.notice("system extension activation finished: \(result.rawValue)")
        if result == .completed { onReady?() }
    }

    func request(_: OSSystemExtensionRequest, didFailWithError error: Error) {
        let ns = error as NSError
        log.error("system extension activation failed (\(ns.domain) code=\(ns.code)): \(error.localizedDescription)")
    }
}

/// Loads/saves the tunnel config and drives start/stop via `NETunnelProviderManager`.
final class Vpn {
    static let shared = Vpn()
    private let log = Logger(subsystem: "org.getlantern.spark", category: "app")
    private let providerBundleId = "org.getlantern.spark.tunnel"

    /// Run the tunnel in `lantern-api` mode — the NE extension self-fetches its server pool from the
    /// Lantern config-new API and caches it in the app-group container. Default-on: validated on
    /// device (the fetched pool probes, ranks, and carries traffic across samizdat + hysteria2). Set
    /// `false` to fall back to the legacy direct/relay config. Pair with `SPARK_CONFIG_ENV=staging`
    /// in the extension's environment to hit staging instead of prod.
    private let useLanternApi = true

    func connect() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self else { return }
            if let error {
                self.log.error("loadAll failed: \(error.localizedDescription)")
                return
            }
            let manager = managers?.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.providerBundleId
            proto.serverAddress = "spark"
            if self.useLanternApi {
                // The NE provider reads this and runs `lantern-api` mode (self-fetch via the API).
                proto.providerConfiguration = ["config": "lantern-api"]
            }
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Spark"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error {
                    self.log.error("saveToPreferences failed: \(error.localizedDescription)")
                    return
                }
                manager.loadFromPreferences { error in
                    if let error {
                        self.log.error("reload failed: \(error.localizedDescription)")
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                        self.log.notice("startVPNTunnel requested")
                    } catch {
                        self.log.error("startVPNTunnel failed: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    func disconnect() {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            managers?.first?.connection.stopVPNTunnel()
        }
    }
}
