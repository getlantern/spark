package org.getlantern.spark

/**
 * JNI bridge to libspark_android.so (built by cargo-ndk from the `spark-android` crate). The
 * native symbols are `Java_org_getlantern_spark_SparkBridge_*`, so this object MUST stay in
 * package `org.getlantern.spark` with this name.
 */
object SparkBridge {
    init {
        System.loadLibrary("spark_android")
    }

    /**
     * Adopt the VpnService TUN [fd] (ownership transferred) and run the tunnel with [mtu], blocking
     * the calling thread until [nativeStop]. Returns 0 on clean stop, -1 on error.
     *
     * [addr] is the tun IPv4 packed big-endian into an Int (e.g. 10.0.0.2 -> 0x0A000002); it MUST
     * equal the VpnService.Builder.addAddress(addr, prefix), and [prefix] must cover addr+1 (the
     * system stack's synthetic gateway). [systemStack]: 1 = the kernel-TCP "system" stack, 0 = the
     * userspace (smoltcp) stack.
     *
     * [config]/[dataDir] select the data path (decided in the shared core dispatch): a null/empty
     * [config] — or the "lantern-api" sentinel — self-fetches the server pool from the Lantern
     * config-new API, caching device_id + the fetched config into [dataDir] (the app files dir);
     * an "IP:port" (IP literal, not a hostname) is a plain relay; any other string is a full config
     * (TOML or config_raw.json).
     *
     * [splitTunnel] is an optional JSON bypass list. Null means no split-tunneling (all traffic
     * tunnelled). A bad/undecodable value is treated leniently — it does NOT fail the tunnel.
     *
     * [routingMode] is an optional routing mode string. Null means the default routing mode.
     * A bad/undecodable value is treated leniently — it does NOT fail the tunnel.
     */
    external fun nativeRun(
        fd: Int,
        mtu: Int,
        addr: Int,
        prefix: Int,
        systemStack: Int,
        config: String?,
        dataDir: String?,
        splitTunnel: String?,
        routingMode: String?,
        /**
         * Comma-separated OS resolver IPs from
         * `ConnectivityManager.getLinkProperties(underlying).getDnsServers()`.
         *
         * Android has no `/etc/resolv.conf`, so this is the only way the core can learn them — and
         * without them the bootstrap DNS-tunnel member, the last-resort reachability tier, refuses
         * to build and drops out of the config-fetch race. Null or empty is a working configuration:
         * the device simply gets no DNS-tunnel member.
         */
        dnsServers: String?,
    ): Int

    /** Signal a running [nativeRun] to stop. */
    external fun nativeStop()

    /** Mark the data path *connecting* before the [nativeRun] worker starts, so [nativeWaitReady]
     *  can't observe a stale ready/down state from a prior connect. Call synchronously first. */
    external fun nativeMarkConnecting()

    /** Block until the data path is servicing the fd (0), or -1 if it doesn't come up within
     *  [timeoutMs] (e.g. a cold-start self-fetch still offline) or it stops first. In self-fetch mode
     *  the core fetches config before adopting the fd, so the service gates on this and stops the VPN
     *  on -1 (falling back to direct) rather than blackholing traffic while the fetch is stuck. */
    external fun nativeWaitReady(timeoutMs: Int): Int

    /** The live server pool as a JSON array (see native `servers_json`): one object per member with
     *  index, location metadata, protocol, latencyMs, healthy, isCurrent, isPinned. "[]" when no pool
     *  is active. Safe to call any time; "[]" before connect. Nullable only for a catastrophic JVM
     *  string-allocation failure in JNI; callers should treat null as "[]". */
    external fun nativeServers(): String?

    /** Pin which pool member new flows dial: [index] >= 0 pins it, [index] < 0 = auto (fastest).
     *  Returns true if applied (false if out of range / no active pool). */
    external fun nativeSelectServer(index: Int): Boolean

    /** Update the running tunnel's split-tunnel bypass list live. Returns true if applied.
     *  The [json] format matches the core's SplitTunnel JSON schema. */
    external fun nativeSetSplitTunnel(json: String): Boolean

    /** Update the running tunnel's routing mode live. Returns true if applied.
     *  The [mode] format matches the core's RoutingMode string schema. */
    external fun nativeSetRoutingMode(mode: String): Boolean
}
