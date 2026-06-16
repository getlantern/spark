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
        startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
        if (worker != null) return
        val builder = Builder()
            .setSession("spark")
            .setMtu(MTU)
            .addAddress("10.0.0.2", 24) // the in-tunnel client address
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
        Log.i(TAG, "tunnel established; handing fd=$fd to native (mtu=$MTU)")
        worker = thread(name = "spark-tunnel") {
            val rc = SparkBridge.nativeRun(fd, MTU)
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
        const val ACTION_STOP = "org.getlantern.spark.STOP"
    }
}
