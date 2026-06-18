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
            // The controlling app passes the relay address in `providerConfiguration["server"]`
            // (a "host:port" IP literal) to tunnel through it; absent → forward directly.
            let server = (self.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerConfiguration?["server"] as? String
            self.log.notice("resolved fd=\(fd); starting spark_tunnel_run (mtu=\(self.mtu), server=\(server ?? "direct"))")

            // `spark_tunnel_run` blocks until `spark_tunnel_stop`, so run it off the NE callback
            // thread. The core owns `fd` and closes it on stop. `withCString` keeps the C string
            // alive for the whole blocking call (it returns only when the tunnel stops).
            let worker = Thread { [mtu = self.mtu, log = self.log, server] in
                let rc: Int32
                if let server, !server.isEmpty {
                    rc = server.withCString { spark_tunnel_run(fd, Int32(mtu), $0) }
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
}
