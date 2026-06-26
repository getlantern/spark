package org.getlantern.spark

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import java.util.concurrent.atomic.AtomicInteger
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

    // Default-network reconnection state. Mobile clients roam between Wi-Fi and cellular; when the
    // default network changes the tunnel's underlying socket dies and stays dead, so we watch for
    // the change and re-establish. These vars are touched from both the service thread and the
    // ConnectivityManager callback thread; the operations are coarse and the window is tiny.
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    // Network callbacks (and the blocking restartTunnel they trigger) run on this dedicated thread,
    // never the main looper — restartTunnel's nativeStop()+join would otherwise risk an ANR.
    private var netCbThread: HandlerThread? = null
    private var currentNet: Network? = null
    private var lastConfig: String? = null // last config handed to startTunnel, reused on restart

    // Generation counter so a stale readiness thread (from a superseded connect attempt) doesn't
    // tear down the service. A restart's nativeStop() wakes the OLD readiness thread with rc=-1;
    // without this guard that stale thread would nativeStop()+stopSelf() the tunnel the restart is
    // rebuilding. @Volatile so the old readiness thread sees the bump across threads.
    // Atomic so concurrent (re)starts can't lose an increment and hand two readiness threads the
    // same generation (which would defeat the stale-thread guard).
    private val tunnelGeneration = AtomicInteger(0)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            return START_NOT_STICKY
        }
        // Optional explicit config (IP:port / TOML / config_raw.json) from the launching Intent,
        // trimmed and normalized to null when blank so the mode log + the value handed to native match
        // the core (which trims and treats "" as "no config"). Absent/blank → null → self-fetch.
        val raw = intent?.getStringExtra(EXTRA_CONFIG)?.trim()
        startTunnel(if (raw.isNullOrEmpty()) null else raw)
        return START_STICKY
    }

    /**
     * Promote the service to the foreground with an ongoing notification so Android keeps the
     * tunnel alive once the app is backgrounded (an unpromoted VpnService is killed on background).
     *
     * minSdk is 24, so the channel + `Notification.Builder(Context, channelId)` constructor (both
     * API 26+) are version-gated; on API 24/25 we fall back to the deprecated channel-less
     * `Notification.Builder(Context)`. AndroidX is not a dependency here, so this stays
     * framework-only rather than using NotificationCompat. On API 34+ we must declare the
     * foreground-service type at runtime (specialUse, matching the manifest's "vpn" subtype).
     */
    private fun startInForeground() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Spark VPN", NotificationManager.IMPORTANCE_LOW),
                )
            }
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        // An explicit MainActivity intent (never null, unlike getLaunchIntentForPackage) so tapping
        // the notification reopens the app. FLAG_IMMUTABLE is required on API 23+.
        val tap = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notif = builder
            .setContentTitle("Spark")
            // State-neutral: shown from before readiness through connected (the readiness gate can
            // still fail). Phase 2 wires this to live status.
            .setContentText("VPN running")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(tap)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    @Synchronized
    private fun startTunnel(config: String?) {
        // Already running? Leave lastConfig alone — it must reflect the config the *running* tunnel
        // was started with, so a later restart reuses the right one (not a stray second Connect tap).
        if (worker != null) return
        lastConfig = config
        // Bump the generation for this real start so the readiness thread below can detect if a later
        // (re)connect supersedes it (only the current generation may stop the service).
        val generation = tunnelGeneration.incrementAndGet()
        // Promote to foreground FIRST so the tunnel survives backgrounding (and so we satisfy the
        // platform requirement to call startForeground promptly after startForegroundService).
        startInForeground()
        val builder = Builder()
            .setSession("spark")
            .setMtu(MTU)
            .addAddress(TUN_ADDR, TUN_PREFIX) // the in-tunnel client address
            .addRoute("0.0.0.0", 0) // capture all IPv4
            .addAddress(TUN_ADDR6, TUN_PREFIX6) // in-tunnel client v6 address (ULA)
            .addRoute("::", 0) // capture all IPv6 (fail-closed if the core can't proxy v6)
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
        // Mark connecting BEFORE starting the worker so the readiness waiter below can't observe a
        // stale ready/down state from a prior connect.
        SparkBridge.nativeMarkConnecting()
        worker = thread(name = "spark-tunnel") {
            // systemStack = 0 (userspace): the cross-platform default, with no kernel-redirect/gateway
            // setup; production Android may pass 1 to use the kernel "system" stack for throughput.
            val rc = SparkBridge.nativeRun(fd, MTU, addr, TUN_PREFIX, 0, config, dataDir)
            Log.i(TAG, "nativeRun returned $rc")
        }
        // Readiness gate (the Android analog of the Apple NE's). A VpnService has no completion
        // handler — routes are live the moment establish() returns — and in self-fetch mode the core
        // fetches config BEFORE servicing the fd, so a cold-start offline/slow fetch would blackhole
        // device traffic indefinitely. Wait (bounded) for the data path to come up; if it never does,
        // stop the VPN cleanly so traffic falls back to direct rather than a black hole.
        thread(name = "spark-ready") {
            val rc = SparkBridge.nativeWaitReady(READY_TIMEOUT_MS)
            val now = tunnelGeneration.get()
            if (generation != now) {
                // A newer (re)connect superseded this attempt — don't touch the service. A restart's
                // nativeStop() wakes this stale thread with rc=-1; without this guard it would
                // nativeStop()+stopSelf() the tunnel the restart is rebuilding.
                Log.i(TAG, "stale readiness result (gen=$generation now=$now); ignoring")
                return@thread
            }
            if (rc != 0) {
                Log.e(TAG, "tunnel did not become ready (config unavailable?); stopping VPN")
                SparkBridge.nativeStop()
                stopSelf()
            } else {
                Log.i(TAG, "tunnel data path ready")
            }
        }
        // Register the default-network watcher once, on the first start. On a restart netCallback is
        // already set, so we don't stack callbacks — but this fresh startTunnel still re-established
        // the tunnel and re-promoted the foreground service above.
        if (netCallback == null) registerNetworkWatcher()
    }

    /** Human-readable description of a network for the debug logs: handle, interface, transports. */
    private fun netDesc(cm: ConnectivityManager, network: Network?): String {
        if (network == null) return "none"
        val caps = cm.getNetworkCapabilities(network)
        val iface = cm.getLinkProperties(network)?.interfaceName
        val transports = if (caps == null) {
            "?"
        } else {
            buildList {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("WIFI")
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("CELLULAR")
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("ETHERNET")
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
            }.joinToString("|").ifEmpty { "(no transports)" }
        }
        return "net=$network iface=$iface transports=$transports"
    }

    /**
     * Watch the underlying physical network and react when it actually changes (e.g. Wi-Fi →
     * cellular). NOTE: `registerDefaultNetworkCallback` reports OUR VPN as the default on API 28+
     * (so it never sees the underlying change). Lantern's fix, mirrored here: on API 31+ use
     * `registerBestMatchingNetworkCallback` with an INTERNET + NOT_RESTRICTED request (it tracks the
     * physical network); on 24..30 fall back to `registerDefaultNetworkCallback`. On a changed
     * non-VPN network we update the VPN's underlying network and restart the tunnel so new dials use
     * it. Heavily logged under tag "$TAG" / "netwatch" while we validate the path.
     */
    private fun registerNetworkWatcher() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = currentNet
                val isVpn = cm.getNetworkCapabilities(network)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                Log.i(TAG, "netwatch onAvailable: ${netDesc(cm, network)} isVpn=$isVpn prev=${netDesc(cm, prev)}")
                if (isVpn) {
                    Log.i(TAG, "netwatch: reported network is our own VPN; ignoring (not an underlying change)")
                    return
                }
                currentNet = network
                // Tell the system which physical network the VPN's sockets ride (Lantern does this).
                runCatching { setUnderlyingNetworks(arrayOf(network)) }
                    .onSuccess { Log.i(TAG, "netwatch: setUnderlyingNetworks($network) ok") }
                    .onFailure { Log.w(TAG, "netwatch: setUnderlyingNetworks failed", it) }
                if (prev == null) {
                    Log.i(TAG, "netwatch: adopted initial underlying network; no restart")
                } else if (prev != network) {
                    Log.i(TAG, "netwatch: underlying network changed ($prev -> $network); restarting tunnel")
                    restartTunnel()
                } else {
                    Log.i(TAG, "netwatch: same underlying network re-reported; no restart")
                }
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "netwatch onLost: $network (current=$currentNet)")
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                Log.i(TAG, "netwatch onCapabilitiesChanged: ${netDesc(cm, network)}")
            }
        }
        netCallback = cb
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .build()
        when {
            // 31+: registerBestMatchingNetworkCallback (handler overload) tracks the physical net.
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
                Log.i(TAG, "netwatch: registerBestMatchingNetworkCallback (API ${Build.VERSION.SDK_INT})")
                cm.registerBestMatchingNetworkCallback(request, cb, backgroundCallbackHandler())
            }
            // 26..30: registerDefaultNetworkCallback's Handler overload (added in API 26).
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O -> {
                Log.i(TAG, "netwatch: registerDefaultNetworkCallback+handler (API ${Build.VERSION.SDK_INT})")
                cm.registerDefaultNetworkCallback(cb, backgroundCallbackHandler())
            }
            // 24..25: the Handler overload doesn't exist yet. The 1-arg version delivers on
            // ConnectivityManager's own thread (not main), so restartTunnel still runs off-main.
            else -> {
                Log.i(TAG, "netwatch: registerDefaultNetworkCallback (API ${Build.VERSION.SDK_INT})")
                cm.registerDefaultNetworkCallback(cb)
            }
        }
    }

    /** A Handler on a dedicated background thread for network callbacks, so the blocking
     *  restartTunnel they trigger never runs on the main looper. Stored in [netCbThread] for cleanup. */
    private fun backgroundCallbackHandler(): Handler {
        val t = HandlerThread("spark-netwatch").apply { start() }
        netCbThread = t
        return Handler(t.looper)
    }

    /**
     * Tear down the current data path and re-establish it with the last config. Runs on the
     * ConnectivityManager callback thread; the worker is a different thread, so the bounded join
     * can't deadlock. Clearing `worker` BEFORE calling startTunnel is what lets the restart past
     * startTunnel's `if (worker != null) return` guard.
     */
    @Synchronized
    private fun restartTunnel() {
        Log.i(TAG, "restartTunnel: tearing down + re-establishing with lastConfig")
        val cfg = lastConfig
        SparkBridge.nativeStop()
        worker?.join(2000)
        worker = null
        startTunnel(cfg)
    }

    @Synchronized
    private fun stopTunnel() {
        // Stop watching the network first so an in-flight network change can't trigger a restart
        // while we're tearing down.
        netCallback?.let {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                .unregisterNetworkCallback(it)
        }
        netCallback = null
        netCbThread?.quitSafely()
        netCbThread = null
        // Reset so a later re-register treats its first onAvailable as the initial network (prev ==
        // null), not a spurious "change" from the prior run that would churn an immediate restart.
        currentNet = null
        SparkBridge.nativeStop()
        worker?.join(2000)
        worker = null
        stopForeground(STOP_FOREGROUND_REMOVE)
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
        private const val TUN_ADDR6 = "fd00::2"
        private const val TUN_PREFIX6 = 64
        private const val READY_TIMEOUT_MS = 30_000 // ceiling for cold-start self-fetch before giving up
        private const val CHANNEL_ID = "spark_vpn" // foreground-service notification channel (API 26+)
        private const val NOTIF_ID = 1 // ongoing foreground notification id
        const val ACTION_STOP = "org.getlantern.spark.STOP"

        /** Optional Intent string extra: an explicit config (IP:port / TOML / config_raw.json; the
         *  relay override is an IP literal, not a hostname). Absent → self-fetch from config-new. */
        const val EXTRA_CONFIG = "org.getlantern.spark.CONFIG"
    }
}
