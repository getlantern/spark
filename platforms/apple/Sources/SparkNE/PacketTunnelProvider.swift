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
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "org.getlantern.spark", category: "tunnel")
    private let mtu = 1500
    private var worker: Thread?

    override func startTunnel(
        options _: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
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
            self.log.info("tunnel up; handing fd=\(fd) to native (mtu=\(self.mtu))")

            // `spark_tunnel_run` blocks until `spark_tunnel_stop`, so run it off the NE callback
            // thread. The core owns `fd` and closes it on stop.
            let worker = Thread { [mtu = self.mtu] in
                let rc = spark_tunnel_run(fd, Int32(mtu))
                self.log.info("spark_tunnel_run returned \(rc)")
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
        log.info("stopTunnel (reason \(reason.rawValue))")
        spark_tunnel_stop()
        worker = nil
        completionHandler()
    }
}
