import NetworkExtension
import os
import SwiftUI

/// Minimal container app / test harness: installs an `NETunnelProviderManager` pointing at the
/// Packet Tunnel Provider extension and starts/stops it. The first start triggers the system's
/// one-time "allow VPN configuration" approval.
@main
struct SparkApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("spark")
            Button("Connect") { Vpn.shared.connect() }
            Button("Disconnect") { Vpn.shared.disconnect() }
        }
        .padding(24)
        .onAppear { Vpn.shared.connect() } // auto-connect for the gate
    }
}

/// Loads/saves the tunnel config and drives start/stop.
final class Vpn {
    static let shared = Vpn()
    private let log = Logger(subsystem: "org.getlantern.spark", category: "app")
    private let providerBundleId = "org.getlantern.spark.tunnel"

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
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Spark"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error {
                    self.log.error("save failed: \(error.localizedDescription)")
                    return
                }
                // Reload so the connection reference is valid after the save.
                manager.loadFromPreferences { error in
                    if let error {
                        self.log.error("reload failed: \(error.localizedDescription)")
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                        self.log.info("startVPNTunnel requested")
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
