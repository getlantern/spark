package org.getlantern.spark

import android.content.Intent
import android.net.VpnService
import android.util.Log
import kotlin.concurrent.thread

/**
 * The spark TUN provider. Builds a full-tunnel route, establishes the interface, hands its fd to
 * the native core, and runs the data path on a worker thread.
 *
 * Loop avoidance: `addDisallowedApplication(<self>)` excludes this app's own sockets from the
 * tunnel, so the in-process proxy's upstream dials bypass it (the Android analog of the desktop
 * SocketProtector). That's why the JNI bridge needs no per-socket `protect()` callback.
 */
class SparkVpnService : VpnService() {
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            return START_NOT_STICKY
        }
        // Optional explicit config (host:port / TOML / config_raw.json) from the launching Intent;
        // absent → null → the daemon self-fetches the pool from the Lantern config-new API.
        startTunnel(intent?.getStringExtra(EXTRA_CONFIG))
        return START_STICKY
    }

    private fun startTunnel(config: String?) {
        if (worker != null) return
        val builder = Builder()
            .setSession("spark")
            .setMtu(MTU)
            .addAddress(TUN_ADDR, TUN_PREFIX) // the in-tunnel client address
            .addRoute("0.0.0.0", 0) // capture all IPv4
            .addDnsServer("8.8.8.8")
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.e(TAG, "addDisallowedApplication failed", e)
        }

        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "establish() returned null (VPN not prepared / consent missing)")
            stopSelf()
            return
        }
        // Transfer fd ownership to native; it closes the fd (tearing down the interface) on stop.
        val fd = pfd.detachFd()
        // The tun IPv4 packed big-endian into an Int, matching addAddress above (native rebuilds it
        // via Ipv4Addr::from(addr as u32)).
        val addr = TUN_ADDR.split(".").fold(0) { acc, oct -> (acc shl 8) or oct.toInt() }
        // The app files dir is the self-fetch cache (device_id + the fetched config_raw.json).
        val dataDir = filesDir.absolutePath
        // The "lantern-api" sentinel is non-empty but still means self-fetch (like null/empty).
        val mode = if (config.isNullOrEmpty() || config == "lantern-api") "self-fetch" else "explicit-config"
        Log.i(TAG, "tunnel established; handing fd=$fd to native (mtu=$MTU, mode=$mode)")
        worker = thread(name = "spark-tunnel") {
            // systemStack = 0 (userspace): the cross-platform default, with no kernel-redirect/gateway
            // setup; production Android may pass 1 to use the kernel "system" stack for throughput.
            val rc = SparkBridge.nativeRun(fd, MTU, addr, TUN_PREFIX, 0, config, dataDir)
            Log.i(TAG, "nativeRun returned $rc")
        }
    }

    private fun stopTunnel() {
        SparkBridge.nativeStop()
        worker?.join(2000)
        worker = null
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "SparkVpn"
        private const val MTU = 1500
        private const val TUN_ADDR = "10.0.0.2" // the in-tunnel client address
        private const val TUN_PREFIX = 24
        const val ACTION_STOP = "org.getlantern.spark.STOP"

        /** Optional Intent string extra: an explicit config (host:port / TOML / config_raw.json).
         *  Absent → the daemon self-fetches from the Lantern config-new API. */
        const val EXTRA_CONFIG = "org.getlantern.spark.CONFIG"
    }
}
