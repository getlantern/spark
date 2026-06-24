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
     * a "host:port" is a plain relay; any other string is a full config (TOML or config_raw.json).
     */
    external fun nativeRun(
        fd: Int,
        mtu: Int,
        addr: Int,
        prefix: Int,
        systemStack: Int,
        config: String?,
        dataDir: String?,
    ): Int

    /** Signal a running [nativeRun] to stop. */
    external fun nativeStop()
}
