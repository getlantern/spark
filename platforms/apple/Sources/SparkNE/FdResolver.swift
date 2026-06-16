import Darwin
import NetworkExtension

/// Resolves the `utun` file descriptor backing an `NEPacketTunnelFlow`, so the Rust core can run
/// an fd-based packet stack (the same data path as desktop/Android) instead of the slower
/// `readPacketObjects`/`writePackets` API.
///
/// Two layers, matching WireGuard/sing-box/Mullvad/Proton/lantern:
///   1. the KVC fast path `packetFlow.value(forKeyPath: "socket.fileDescriptor")`, and
///   2. a public-symbol fd-scan fallback (the KVC keypath has gotten flaky on recent iOS) —
///      probe each open fd with `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)` and keep the one
///      whose interface name starts with `utun`.
enum FdResolver {
    // From <sys/sys_domain.h> and <net/if_utun.h>; not always surfaced by the Swift Darwin
    // overlay, so pinned here (stable kernel ABI).
    private static let sysprotoControl: Int32 = 2 // SYSPROTO_CONTROL
    private static let utunOptIfname: Int32 = 2 // UTUN_OPT_IFNAME

    /// Resolve the utun fd, or `nil` if none can be found.
    static func resolve(packetFlow: NEPacketTunnelFlow) -> Int32? {
        if let n = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? NSNumber,
           isUtun(n.int32Value) {
            return n.int32Value
        }
        for fd in Int32(0)..<1024 where isUtun(fd) {
            return fd
        }
        return nil
    }

    /// Whether `fd` is a utun control socket (its `UTUN_OPT_IFNAME` reads back as `utunN`).
    /// Non-socket / non-utun fds return an error from `getsockopt`, so they're rejected.
    private static func isUtun(_ fd: Int32) -> Bool {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var len = socklen_t(name.count)
        guard getsockopt(fd, sysprotoControl, utunOptIfname, &name, &len) == 0 else {
            return false
        }
        return String(cString: name).hasPrefix("utun")
    }
}
